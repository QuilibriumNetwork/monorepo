package time

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/utils"
)

const (
	// Default cache size for LRU
	defaultAppCacheSize = 10000
	// Maximum tree depth before pruning old frames
	maxTreeDepth = 360
)

// AppEvent represents an event in the app time reel
type AppEvent struct {
	Type    TimeReelEventType
	Frame   *protobufs.AppShardFrame
	OldHead *protobufs.AppShardFrame // For fork events
	Message string
}

func (n *AppEvent) ControlEventData() {}

// FrameNode represents a node in the frame tree
type FrameNode struct {
	Frame    *protobufs.AppShardFrame
	Parent   *FrameNode
	Children map[string]*FrameNode
	Depth    uint64
}

// PendingFrame represents a frame waiting for its parent
type PendingFrame struct {
	Frame          *protobufs.AppShardFrame
	ParentSelector []byte
	Timestamp      int64 // when it was received
}

// AppTimeReel implements a time reel for app shard FrameHeaders with tree
// structure
type AppTimeReel struct {
	logger         *zap.Logger
	address        []byte // The app shard address this reel is tracking
	proverRegistry consensus.ProverRegistry
	mu             sync.RWMutex

	// Tree structure
	root *FrameNode

	// Frame lookup - maps frame ID to node
	nodes map[string]*FrameNode

	// Frame number lookup - maps frame number to list of nodes at that height
	framesByNumber map[uint64][]*FrameNode

	// Pending frames waiting for parents - keyed by parent selector
	pendingFrames map[string][]*PendingFrame

	// Current canonical head
	head *FrameNode

	// Fork choice parameters
	forkChoiceParams Params

	// LRU cache for quick access
	cache *lru.Cache[string, *FrameNode]

	// Event channel with guaranteed delivery
	eventCh   chan AppEvent
	eventDone chan struct{} // Signals event processing complete

	// Equivocator tracking: frame number -> bit positions that equivocated
	equivocators map[uint64]map[int]bool

	// Durable frame store
	store store.ClockStore

	// Materialize side effects
	materializeFunc func(
		txn store.Transaction,
		frame *protobufs.AppShardFrame,
	) error

	// Revert side effects
	revertFunc func(
		txn store.Transaction,
		frame *protobufs.AppShardFrame,
	) error

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewAppTimeReel creates a new app time reel for a specific shard address
func NewAppTimeReel(
	logger *zap.Logger,
	address []byte,
	proverRegistry consensus.ProverRegistry,
	clockStore store.ClockStore,
) (*AppTimeReel, error) {
	cache, err := lru.New[string, *FrameNode](defaultAppCacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create LRU cache")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AppTimeReel{
		logger:           logger,
		address:          address,
		proverRegistry:   proverRegistry,
		nodes:            make(map[string]*FrameNode),
		framesByNumber:   make(map[uint64][]*FrameNode),
		pendingFrames:    make(map[string][]*PendingFrame),
		forkChoiceParams: DefaultForkChoiceParams,
		cache:            cache,
		eventCh:          make(chan AppEvent, 1000),
		eventDone:        make(chan struct{}),
		equivocators:     make(map[uint64]map[int]bool),
		materializeFunc: func(
			txn store.Transaction,
			frameNumber *protobufs.AppShardFrame,
		) error {
			return nil
		},
		revertFunc: func(
			txn store.Transaction,
			frame *protobufs.AppShardFrame,
		) error {
			return nil
		},
		store:  clockStore,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// SetMaterializeFunc sets the materialize side effects function
func (g *AppTimeReel) SetMaterializeFunc(
	materializeFunc func(
		txn store.Transaction,
		frame *protobufs.AppShardFrame,
	) error,
) {
	g.materializeFunc = materializeFunc
}

// SetRevertFunc sets the revert side effects function
func (a *AppTimeReel) SetRevertFunc(
	revertFunc func(
		txn store.Transaction,
		frame *protobufs.AppShardFrame,
	) error,
) {
	a.revertFunc = revertFunc
}

// Start starts the app time reel
func (a *AppTimeReel) Start() error {
	a.logger.Info(
		"starting app time reel",
		zap.String("address", fmt.Sprintf("%x", a.address)),
	)

	if err := a.bootstrapFromStore(); err != nil {
		return errors.Wrap(err, "start app time reel")
	}

	return nil
}

// Stop stops the app time reel
func (a *AppTimeReel) Stop() {
	a.logger.Info(
		"stopping app time reel",
		zap.String("address", fmt.Sprintf("%x", a.address)),
	)
	a.cancel()
	a.wg.Wait()
	close(a.eventCh)
	close(a.eventDone)
}

// sendEvent sends an event with guaranteed delivery
func (a *AppTimeReel) sendEvent(event AppEvent) {
	// This blocks until the event is delivered, guaranteeing order
	select {
	case a.eventCh <- event:
		a.logger.Debug(
			"sent event",
			zap.Int("type", int(event.Type)),
			zap.Uint64("frame_number", event.Frame.Header.FrameNumber),
			zap.String("id", a.ComputeFrameID(event.Frame)),
		)
	case <-a.ctx.Done():
		return
	}
}

// Insert inserts an app frame header into the tree structure
func (a *AppTimeReel) Insert(
	ctx context.Context,
	frame *protobufs.AppShardFrame,
) error {
	// Start timing
	timer := prometheus.NewTimer(frameProcessingDuration.WithLabelValues("app"))
	defer timer.ObserveDuration()

	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify frame is for our address
	if !bytes.Equal(frame.Header.Address, a.address) {
		framesProcessedTotal.WithLabelValues("app", "error").Inc()
		return errors.New("frame address does not match reel address")
	}

	frameID := a.ComputeFrameID(frame)

	// Check if frame already exists
	if _, exists := a.nodes[frameID]; exists {
		return nil
	}

	// Check for equivocation with different frames at same height
	nodesAtHeight := a.framesByNumber[frame.Header.FrameNumber]
	for _, node := range nodesAtHeight {
		if !isEqualAppFrame(node.Frame, frame) &&
			hasOverlappingAppBits(node.Frame, frame) {
			a.logger.Warn(
				"equivocation detected for app frame",
				zap.String("address", fmt.Sprintf("%x", a.address)),
				zap.Uint64("frame_number", frame.Header.FrameNumber),
			)

			// Track equivocators by bit position
			if a.equivocators[frame.Header.FrameNumber] == nil {
				a.equivocators[frame.Header.FrameNumber] = make(map[int]bool)
			}

			// Find overlapping bits and mark them as equivocators
			existingBits := node.Frame.Header.PublicKeySignatureBls48581
			newBits := frame.Header.PublicKeySignatureBls48581
			if existingBits != nil && newBits != nil {
				existingBitmask := existingBits.Bitmask
				newBitmask := newBits.Bitmask
				maxLen := len(existingBitmask)
				if len(newBitmask) > maxLen {
					maxLen = len(newBitmask)
				}

				for i := 0; i < maxLen; i++ {
					var eByte, nByte byte
					if i < len(existingBitmask) {
						eByte = existingBitmask[i]
					}
					if i < len(newBitmask) {
						nByte = newBitmask[i]
					}
					overlapping := eByte & nByte
					for bit := 0; bit < 8; bit++ {
						if overlapping&(1<<bit) != 0 {
							a.equivocators[frame.Header.FrameNumber][i*8+bit] = true
						}
					}
				}
			}

			a.sendEvent(AppEvent{
				Type:  TimeReelEventEquivocationDetected,
				Frame: frame,
				Message: fmt.Sprintf(
					"equivocation at frame %d",
					frame.Header.FrameNumber,
				),
			})

			// Record equivocation metric
			equivocationsDetected.WithLabelValues("app").Inc()

			// Continue processing, we need to handle fork choice still before the
			// trees update
		}
	}

	a.stageFrame(frame)

	// Handle genesis frame
	if frame.Header.FrameNumber == 0 {
		return a.insertGenesisFrame(frame, frameID)
	}

	// Try to find parent
	parentSelector := string(frame.Header.ParentSelector)
	parentNode := a.findNodeBySelector(frame.Header.ParentSelector)

	if parentNode == nil {
		// Parent not found, add to pending frames
		a.addPendingFrame(frame, parentSelector)
		return nil
	}

	// Verify parent selector matches
	expectedSelector := computeAppPoseidonHash(parentNode.Frame.Header.Output)
	if !bytes.Equal(expectedSelector, frame.Header.ParentSelector) {
		return errors.New("parent selector mismatch")
	}

	// Insert frame into tree
	newNode := &FrameNode{
		Frame:    frame,
		Parent:   parentNode,
		Children: make(map[string]*FrameNode),
		Depth:    parentNode.Depth + 1,
	}

	// Add to data structures
	a.nodes[frameID] = newNode
	a.framesByNumber[frame.Header.FrameNumber] = append(
		a.framesByNumber[frame.Header.FrameNumber],
		newNode,
	)
	parentNode.Children[frameID] = newNode
	a.cache.Add(frameID, newNode)

	// Process any pending frames that can now be connected
	a.processPendingFrames(frameID, newNode)

	// Evaluate fork choice if we have competing branches
	a.evaluateForkChoice(newNode)

	// Prune old frames if tree is getting too deep
	a.pruneOldFrames()

	// Prune old pending frames periodically
	a.pruneOldPendingFrames()

	// Record success
	framesProcessedTotal.WithLabelValues("app", "success").Inc()

	// Update tree metrics
	a.updateTreeMetrics()

	return nil
}

// insertGenesisFrame handles genesis frame insertion
func (a *AppTimeReel) insertGenesisFrame(
	frame *protobufs.AppShardFrame,
	frameID string,
) error {
	if a.root != nil {
		return errors.New("genesis frame already exists")
	}

	a.root = &FrameNode{
		Frame:    frame,
		Parent:   nil,
		Children: make(map[string]*FrameNode),
		Depth:    0,
	}

	a.nodes[frameID] = a.root
	a.framesByNumber[0] = []*FrameNode{a.root}
	a.head = a.root
	a.cache.Add(frameID, a.root)

	// Send new head event
	a.sendEvent(AppEvent{
		Type:  TimeReelEventNewHead,
		Frame: frame,
	})

	// Process any pending frames that can now be connected
	a.processPendingFrames(frameID, a.root)

	// Prune old frames if tree is getting too deep
	a.pruneOldFrames()

	a.persistCanonicalFrames([]*protobufs.AppShardFrame{frame})

	return nil
}

// addPendingFrame adds a frame to the pending list
func (a *AppTimeReel) addPendingFrame(
	frame *protobufs.AppShardFrame,
	parentSelector string,
) {
	pending := &PendingFrame{
		Frame:          frame,
		ParentSelector: frame.Header.ParentSelector,
		Timestamp:      frame.Header.Timestamp,
	}

	a.pendingFrames[parentSelector] = append(
		a.pendingFrames[parentSelector],
		pending,
	)

	a.logger.Debug(
		"added pending frame",
		zap.String("address", fmt.Sprintf("%x", a.address)),
		zap.Uint64("frame_number", frame.Header.FrameNumber),
		zap.String(
			"parent_selector",
			fmt.Sprintf("%x", frame.Header.ParentSelector),
		),
	)
}

// processPendingFrames processes frames that were waiting for the given parent
func (a *AppTimeReel) processPendingFrames(
	parentFrameID string,
	parentNode *FrameNode,
) {
	a.logger.Debug(
		"process pending frame",
		zap.Uint64("frame_number", parentNode.Frame.Header.FrameNumber),
		zap.String("id", parentFrameID),
	)
	parentSelector := computeAppPoseidonHash(parentNode.Frame.Header.Output)
	parentSelectorStr := string(parentSelector)

	pendingList := a.pendingFrames[parentSelectorStr]
	if len(pendingList) == 0 {
		// Remove from pending list
		delete(a.pendingFrames, parentSelectorStr)
		return
	}

	// Process each pending frame
	for _, pending := range pendingList {
		frameID := a.ComputeFrameID(pending.Frame)

		// Skip if already processed
		if _, exists := a.nodes[frameID]; exists {
			continue
		}

		// Create and insert node
		newNode := &FrameNode{
			Frame:    pending.Frame,
			Parent:   parentNode,
			Children: make(map[string]*FrameNode),
			Depth:    parentNode.Depth + 1,
		}

		a.nodes[frameID] = newNode
		a.framesByNumber[pending.Frame.Header.FrameNumber] = append(
			a.framesByNumber[pending.Frame.Header.FrameNumber], newNode)
		parentNode.Children[frameID] = newNode
		a.cache.Add(frameID, newNode)

		a.logger.Debug(
			"processed pending frame",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Uint64("frame_number", pending.Frame.Header.FrameNumber),
		)

		// Recursively process any frames waiting for this one
		a.processPendingFrames(frameID, newNode)

		// Evaluate fork choice
		a.evaluateForkChoice(newNode)
	}
}

// findNodeBySelector finds a node whose output hash matches the selector
func (a *AppTimeReel) findNodeBySelector(selector []byte) *FrameNode {
	for _, node := range a.nodes {
		expectedSelector := computeAppPoseidonHash(node.Frame.Header.Output)
		if bytes.Equal(expectedSelector, selector) {
			return node
		}
	}
	return nil
}

// evaluateForkChoice evaluates fork choice and updates head if necessary
func (a *AppTimeReel) evaluateForkChoice(newNode *FrameNode) {
	if a.head == nil {
		a.head = newNode
		a.sendHeadEvent(newNode, nil)
		return
	}

	// Find all competing branches (leaf nodes)
	leafNodes := a.findLeafNodes()
	if len(leafNodes) <= 1 {
		// No competition, check if we should update head
		if newNode.Depth > a.head.Depth {
			oldHead := a.head
			a.head = newNode
			a.persistCanonicalFrames([]*protobufs.AppShardFrame{newNode.Frame})
			a.sendHeadEvent(newNode, oldHead)
		}
		return
	}

	// Get maximum depth among leaf nodes
	maxDepth := uint64(0)
	for _, leaf := range leafNodes {
		if leaf.Depth > maxDepth {
			maxDepth = leaf.Depth
		}
	}

	// Only consider leaf nodes at maximum depth for fork choice
	var competingLeaves []*FrameNode
	for _, leaf := range leafNodes {
		if leaf.Depth == maxDepth {
			competingLeaves = append(competingLeaves, leaf)
		}
	}

	// If only one leaf at max depth, make it head
	if len(competingLeaves) == 1 {
		chosenNode := competingLeaves[0]
		if chosenNode != a.head {
			oldHead := a.head
			a.head = chosenNode

			// Check if this is a reorganization (fork)
			if oldHead != nil && !a.isAncestorNode(oldHead, chosenNode) {
				a.logger.Info(
					"reorganization detected (single leaf)",
					zap.Uint64("old_head_frame", oldHead.Frame.Header.FrameNumber),
					zap.Uint64("new_head_frame", chosenNode.Frame.Header.FrameNumber))
				// This is a fork - emit fork detected event first
				event := AppEvent{
					Type:    TimeReelEventForkDetected,
					Frame:   chosenNode.Frame,
					OldHead: oldHead.Frame,
					Message: fmt.Sprintf(
						"fork detected for address %x: old head %d (%x), new head %d (%x)",
						a.address,
						oldHead.Frame.Header.FrameNumber,
						poseidon.Sum(oldHead.Frame.Header.Output),
						chosenNode.Frame.Header.FrameNumber,
						poseidon.Sum(chosenNode.Frame.Header.Output),
					),
				}
				a.sendEvent(event)

				// Find the common ancestor
				commonAncestor, reverts := a.findCommonAncestor(oldHead, chosenNode)

				if len(reverts) != 0 {
					a.rewindFrames(reverts)
				}

				// Emit new head events for each frame in the new canonical path
				// from the frame after the common ancestor to the new head
				if commonAncestor != nil {
					a.emitReplayEvents(commonAncestor, chosenNode)
				}
			} else {
				// Regular head advance - emit single new head event
				event := AppEvent{
					Type:  TimeReelEventNewHead,
					Frame: chosenNode.Frame,
				}
				if oldHead != nil {
					event.OldHead = oldHead.Frame
				}
				a.persistCanonicalFrames([]*protobufs.AppShardFrame{chosenNode.Frame})
				a.sendEvent(event)
			}
		}
		return
	}

	// Convert competing leaf nodes to branches for fork choice
	branches := make([]Branch, 0, len(competingLeaves))
	nodeToIndex := make(map[*FrameNode]int)

	for i, leaf := range competingLeaves {
		branch := a.nodeToBranch(leaf)
		branches = append(branches, branch)
		nodeToIndex[leaf] = i
	}

	// Get current head index - find which competing leaf is the current head
	prevChoice := 0
	for i, leaf := range competingLeaves {
		if leaf == a.head {
			prevChoice = i
			break
		}
	}

	// Perform fork choice
	forkChoiceTimer := prometheus.NewTimer(
		forkChoiceDuration.WithLabelValues("app"),
	)

	for i, branch := range branches {
		if len(branch.Frames) > 0 {
			lastFrame := branch.Frames[len(branch.Frames)-1]
			a.logger.Debug(
				"fork choice branch",
				zap.Int("index", i),
				zap.String("prover", hex.EncodeToString(lastFrame.ProverAddress)),
				zap.String("distance", lastFrame.Distance.String()),
				zap.Bool("is_current_head", competingLeaves[i] == a.head),
			)
		}
	}

	chosenIndex := ForkChoice(branches, a.forkChoiceParams, prevChoice)
	chosenNode := competingLeaves[chosenIndex]
	forkChoiceTimer.ObserveDuration()

	a.logger.Debug(
		"fork choice result",
		zap.Int("chosen_index", chosenIndex),
		zap.Int("prev_choice", prevChoice),
	)

	// Record fork choice metrics
	forkChoiceEvaluations.WithLabelValues("app").Inc()
	competingBranches.WithLabelValues("app").Observe(float64(len(branches)))

	// Update head if it changed
	if chosenNode != a.head {
		oldHead := a.head
		a.head = chosenNode

		// Check if this is a reorganization (fork)
		if oldHead != nil && !a.isAncestorNode(oldHead, chosenNode) {
			a.logger.Info(
				"reorganization detected",
				zap.Uint64("old_head_frame", oldHead.Frame.Header.FrameNumber),
				zap.Uint64("new_head_frame", chosenNode.Frame.Header.FrameNumber))

			// Record reorganization metrics
			headChangesTotal.WithLabelValues("app", "reorganization").Inc()

			// Calculate reorganization depth
			commonAncestor, reverts := a.findCommonAncestor(oldHead, chosenNode)
			if commonAncestor != nil {
				depth := oldHead.Depth - commonAncestor.Depth
				reorganizationDepth.WithLabelValues("app").Observe(float64(depth))
			}

			// This is a fork - emit fork detected event first
			event := AppEvent{
				Type:    TimeReelEventForkDetected,
				Frame:   chosenNode.Frame,
				OldHead: oldHead.Frame,
				Message: fmt.Sprintf(
					"fork detected for address %x: old head %d (%x), new head %d (%x)",
					a.address,
					oldHead.Frame.Header.FrameNumber,
					poseidon.Sum(oldHead.Frame.Header.Output),
					chosenNode.Frame.Header.FrameNumber,
					poseidon.Sum(chosenNode.Frame.Header.Output),
				),
			}
			a.sendEvent(event)

			// Rewind all previous frames
			if len(reverts) != 0 {
				a.rewindFrames(reverts)
			}

			// Emit new head events for each frame in the new canonical path
			// from the frame after the common ancestor to the new head
			if commonAncestor != nil {
				a.emitReplayEvents(commonAncestor, chosenNode)
			}
		} else {
			// Regular head advance - emit single new head event
			headChangesTotal.WithLabelValues("app", "advance").Inc()

			event := AppEvent{
				Type:  TimeReelEventNewHead,
				Frame: chosenNode.Frame,
			}
			if oldHead != nil {
				event.OldHead = oldHead.Frame
			}
			a.sendEvent(event)
		}
	}
}

// findLeafNodes returns all leaf nodes (nodes with no children)
func (a *AppTimeReel) findLeafNodes() []*FrameNode {
	var leaves []*FrameNode
	for _, node := range a.nodes {
		if len(node.Children) == 0 {
			leaves = append(leaves, node)
		}
	}
	return leaves
}

// nodeToBranch converts a node and its lineage to a Branch for fork choice
func (a *AppTimeReel) nodeToBranch(node *FrameNode) Branch {
	// Build lineage from this node backwards, but limit to 360 frames
	const maxLineageDepth = 360
	var lineage []*FrameNode
	current := node
	depth := 0

	for current != nil && depth < maxLineageDepth {
		lineage = append([]*FrameNode{current}, lineage...)
		current = current.Parent
		depth++
	}

	// Convert to fork choice frames
	frames := make([]Frame, 0, len(lineage))
	for _, n := range lineage {
		frame := Frame{
			Distance:      a.computeFrameDistance(n.Frame),
			Seniority:     a.computeFrameSeniority(n.Frame),
			ProverAddress: n.Frame.Header.Prover,
		}
		frames = append(frames, frame)
	}

	return Branch{Frames: frames}
}

// computeFrameDistance computes the distance metric for fork choice
func (a *AppTimeReel) computeFrameDistance(
	frame *protobufs.AppShardFrame,
) *big.Int {
	if frame.Header.FrameNumber == 0 {
		return big.NewInt(0)
	}

	// Verify the prover was the expected one
	var parentSelector [32]byte
	copy(parentSelector[:], frame.Header.ParentSelector)

	// Get the expected prover for this frame
	expectedProver, err := a.proverRegistry.GetNextProver(
		parentSelector,
		a.address,
	)
	if err == nil {
		if bytes.Equal(expectedProver, frame.Header.Prover) {
			return big.NewInt(0)
		}

		// If the prover is not the expected one, grab the full set and calculate
		// the distance
		provers, err := a.proverRegistry.GetOrderedProvers(
			parentSelector,
			a.address,
		)
		if err == nil {
			if len(provers) > 0 && bytes.Equal(provers[0], frame.Header.Prover) {
				return big.NewInt(0)
			}
		}
	}

	// Get RMax from fork choice params
	address := new(big.Int).SetBytes(frame.Header.Prover)
	sel := new(big.Int).SetBytes(parentSelector[:])
	rawDist := utils.AbsoluteModularMinimumDistance(
		address,
		sel,
		ff.Modulus(),
	)
	distance := new(big.Int).Mul(rawDist, a.forkChoiceParams.RMax)
	distance.Quo(distance, RMaxDenom)
	return distance
}

// computeFrameSeniority computes seniority for fork choice based on number of
// signers
func (a *AppTimeReel) computeFrameSeniority(
	frame *protobufs.AppShardFrame,
) uint64 {
	// Genesis frame and frames without signatures get minimal seniority
	if frame.Header.PublicKeySignatureBls48581 == nil {
		// Use minimal seniority so genesis doesn't dominate fork choice
		return SCALE / 64 // Same as 1 signer
	}

	// Count bits excluding equivocators
	equivocatorsAtHeight := a.equivocators[frame.Header.FrameNumber]
	bitCount := 0
	bitmask := frame.Header.PublicKeySignatureBls48581.Bitmask

	for i := 0; i < len(bitmask); i++ {
		for bit := 0; bit < 8; bit++ {
			if bitmask[i]&(1<<bit) != 0 {
				// Check if this bit position equivocated
				bitPos := i*8 + bit
				if equivocatorsAtHeight == nil || !equivocatorsAtHeight[bitPos] {
					bitCount++
				} else {
					a.logger.Debug(
						"excluding equivocator from seniority",
						zap.Uint64("frame_number", frame.Header.FrameNumber),
						zap.Int("bit_position", bitPos))
				}
			}
		}
	}

	if bitCount == 0 {
		return 0 // evicted or all equivocators
	}

	// Return seniority proportional to number of signers, normalized to SCALE
	maxSigners := uint64(64)
	// Simple linear scaling: more signers = higher seniority
	// To avoid overflow, divide SCALE first
	result := (SCALE / maxSigners) * uint64(bitCount)
	return result
}

// sendHeadEvent sends a head update event
func (a *AppTimeReel) sendHeadEvent(newHead *FrameNode, oldHead *FrameNode) {
	eventType := TimeReelEventNewHead
	var message string

	if oldHead != nil && !a.isAncestorNode(oldHead, newHead) {
		eventType = TimeReelEventForkDetected
		message = fmt.Sprintf(
			"fork detected for address %x: old head %d (%x), new head %d (%x)",
			a.address,
			oldHead.Frame.Header.FrameNumber,
			poseidon.Sum(oldHead.Frame.Header.Output),
			newHead.Frame.Header.FrameNumber,
			poseidon.Sum(newHead.Frame.Header.Output),
		)
	}

	event := AppEvent{
		Type:    eventType,
		Frame:   newHead.Frame,
		Message: message,
	}
	if oldHead != nil {
		event.OldHead = oldHead.Frame
	}
	a.sendEvent(event)
}

// isAncestorNode checks if ancestor is an ancestor of descendant
func (a *AppTimeReel) isAncestorNode(ancestor, descendant *FrameNode) bool {
	current := descendant
	for current != nil {
		if current == ancestor {
			return true
		}
		current = current.Parent
	}
	return false
}

// findCommonAncestor finds the most recent common ancestor of two nodes
func (a *AppTimeReel) findCommonAncestor(
	node1, node2 *FrameNode,
) (*FrameNode, []*FrameNode) {
	// Build path from node1 to root
	path1 := make(map[*FrameNode]bool)
	current := node1
	for current != nil {
		path1[current] = true
		current = current.Parent
	}

	// Walk from node2 to root and find first common node
	current = node2
	for current != nil {
		if path1[current] {
			a.logger.Info(
				"found common ancestor",
				zap.Uint64("ancestor_frame", current.Frame.Header.FrameNumber),
				zap.Uint64("node1_frame", node1.Frame.Header.FrameNumber),
				zap.Uint64("node2_frame", node2.Frame.Header.FrameNumber))

			// Build revert path from node1 back to the common ancestor (not including it)
			prev := []*FrameNode{node1}
			walk := node1
			for walk != current {
				prev = append(prev, walk.Parent)
				walk = walk.Parent
			}
			return current, prev
		}
		current = current.Parent
	}

	a.logger.Warn(
		"no common ancestor found",
		zap.Uint64("node1_frame", node1.Frame.Header.FrameNumber),
		zap.Uint64("node2_frame", node2.Frame.Header.FrameNumber),
	)
	return nil, nil
}

// emitReplayEvents emits new head events for each frame in the path from
// commonAncestor to newHead
func (a *AppTimeReel) emitReplayEvents(commonAncestor, newHead *FrameNode) {
	// Build path from newHead back to commonAncestor
	var reversePath []*FrameNode
	current := newHead
	for current != nil && current != commonAncestor {
		reversePath = append(reversePath, current)
		current = current.Parent
	}

	// Reverse the path to get correct order (from ancestor toward new head)
	replayPath := make([]*FrameNode, len(reversePath))
	for i, node := range reversePath {
		replayPath[len(reversePath)-1-i] = node
	}

	frames := make([]*protobufs.AppShardFrame, 0, len(replayPath))
	for _, n := range replayPath {
		frames = append(frames, n.Frame)
	}
	if err := a.persistCanonicalFrames(frames); err != nil {
		a.logger.Warn(
			"failed to persist canonical replay path",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Int("replay_len", len(frames)),
			zap.Error(err),
		)
	}

	a.logger.Info(
		"emitting replay events",
		zap.Int("replay_path_length", len(replayPath)),
		zap.Uint64("common_ancestor", commonAncestor.Frame.Header.FrameNumber),
		zap.String("common_ancestor_selector", fmt.Sprintf(
			"%x",
			computeAppPoseidonHash(commonAncestor.Frame.Header.Output),
		)),
		zap.Uint64("new_head", newHead.Frame.Header.FrameNumber),
		zap.String("new_head_selector", fmt.Sprintf(
			"%x",
			computeAppPoseidonHash(newHead.Frame.Header.Output),
		)),
	)

	// Emit new head events for each frame in the replay path sequentially
	for _, node := range replayPath {
		a.logger.Info(
			"emitting replay event for frame",
			zap.Uint64("frame_number", node.Frame.Header.FrameNumber))
		event := AppEvent{
			Type:  TimeReelEventNewHead,
			Frame: node.Frame,
		}
		a.sendEvent(event)
	}
}

// rewindFrames reverts side effects for frames in the old branch being unwound
func (a *AppTimeReel) rewindFrames(revertNodes []*FrameNode) {
	if len(revertNodes) == 0 {
		return
	}

	a.logger.Info(
		"rewinding frames",
		zap.String("address", fmt.Sprintf("%x", a.address)),
		zap.Int("rewind_path_length", len(revertNodes)),
	)

	// Create a transaction for reverting side effects
	txn, err := a.store.NewTransaction(false)
	if err != nil {
		a.logger.Error(
			"failed to create transaction for rewind",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Error(err),
		)
		return
	}

	// Process each frame in the revert list (already in correct order)
	for _, node := range revertNodes {
		a.logger.Info(
			"reverting frame",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Uint64("frame_number", node.Frame.Header.FrameNumber),
		)

		// Call revert function to undo side effects
		if err := a.revertFunc(
			txn,
			node.Frame,
		); err != nil {
			txn.Abort()
			a.logger.Error(
				"failed to revert frame side effects",
				zap.String("address", fmt.Sprintf("%x", a.address)),
				zap.Uint64("frame_number", node.Frame.Header.FrameNumber),
				zap.Error(err),
			)
			return
		}
	}

	// Commit the revert transaction
	if err := txn.Commit(); err != nil {
		a.logger.Error(
			"failed to commit revert transaction",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Error(err),
		)
		return
	}

	a.logger.Info(
		"successfully rewound frames",
		zap.String("address", fmt.Sprintf("%x", a.address)),
		zap.Int("reverted_count", len(revertNodes)),
	)
}

// ComputeFrameID computes a unique ID for a frame
func (a *AppTimeReel) ComputeFrameID(frame *protobufs.AppShardFrame) string {
	// Create a unique identifier based on frame contents
	data := fmt.Sprintf("%x:%d:%d:%x:%x",
		frame.Header.Address,
		frame.Header.FrameNumber,
		frame.Header.Timestamp,
		frame.Header.Output,
		frame.Header.ParentSelector,
	)
	hash := computeAppPoseidonHash([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// GetHead returns the current head frame
func (a *AppTimeReel) GetHead() (*protobufs.AppShardFrame, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.head == nil {
		return nil, errors.New("no head frame")
	}

	return a.head.Frame, nil
}

// GetFrame retrieves a frame by frame ID
func (a *AppTimeReel) GetFrame(frameID string) (
	*protobufs.AppShardFrame,
	error,
) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check cache first
	if node, ok := a.cache.Get(frameID); ok {
		return node.Frame, nil
	}

	// Check main storage
	node, exists := a.nodes[frameID]
	if !exists {
		return nil, errors.New("frame not found")
	}

	// Add to cache
	a.cache.Add(frameID, node)
	return node.Frame, nil
}

// GetFramesByNumber retrieves all frames at a specific frame number
func (a *AppTimeReel) GetFramesByNumber(frameNumber uint64) (
	[]*protobufs.AppShardFrame,
	error,
) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	nodes := a.framesByNumber[frameNumber]
	if len(nodes) == 0 {
		return nil, errors.New("no frames found at frame number")
	}

	frames := make([]*protobufs.AppShardFrame, len(nodes))
	for i, node := range nodes {
		frames[i] = node.Frame
	}

	return frames, nil
}

// GetLineage returns the full lineage of frames from genesis to the head
func (a *AppTimeReel) GetLineage() ([]*protobufs.AppShardFrame, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.head == nil {
		return nil, errors.New("no head frame")
	}

	return a.getNodeLineage(a.head), nil
}

// GetNodeLineage returns the lineage for a specific node
func (a *AppTimeReel) GetNodeLineage(frameID string) (
	[]*protobufs.AppShardFrame,
	error,
) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	node, exists := a.nodes[frameID]
	if !exists {
		return nil, errors.New("frame not found")
	}

	return a.getNodeLineage(node), nil
}

// getNodeLineage returns the lineage from genesis to the specified node
func (a *AppTimeReel) getNodeLineage(node *FrameNode) []*protobufs.AppShardFrame {
	var lineage []*protobufs.AppShardFrame
	current := node
	for current != nil {
		lineage = append([]*protobufs.AppShardFrame{current.Frame}, lineage...)
		current = current.Parent
	}
	return lineage
}

// GetEventCh returns the event channel
func (a *AppTimeReel) GetEventCh() <-chan AppEvent {
	return a.eventCh
}

// GetAddress returns the address this reel is tracking
func (a *AppTimeReel) GetAddress() []byte {
	return a.address
}

// GetChildFrames returns all direct child frames of a given frame
func (a *AppTimeReel) GetChildFrames(frameID string) (
	[]*protobufs.AppShardFrame,
	error,
) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	node, exists := a.nodes[frameID]
	if !exists {
		return nil, errors.New("frame not found")
	}

	children := make([]*protobufs.AppShardFrame, 0, len(node.Children))
	for _, childNode := range node.Children {
		children = append(children, childNode.Frame)
	}

	return children, nil
}

// GetPendingFrames returns information about frames waiting for parents
func (a *AppTimeReel) GetPendingFrames() map[string][]*protobufs.AppShardFrame {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string][]*protobufs.AppShardFrame)
	for selector, pendingList := range a.pendingFrames {
		frames := make([]*protobufs.AppShardFrame, len(pendingList))
		for i, pending := range pendingList {
			frames[i] = pending.Frame
		}
		result[selector] = frames
	}

	return result
}

// GetBranchTips returns all leaf nodes (potential heads)
func (a *AppTimeReel) GetBranchTips() ([]*protobufs.AppShardFrame, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	leafNodes := a.findLeafNodes()
	tips := make([]*protobufs.AppShardFrame, len(leafNodes))
	for i, node := range leafNodes {
		tips[i] = node.Frame
	}

	return tips, nil
}

// SetForkChoiceParams updates the fork choice parameters
func (a *AppTimeReel) SetForkChoiceParams(params Params) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forkChoiceParams = params
}

// pruneOldFrames removes frames older than maxTreeDepth from the current head
func (a *AppTimeReel) pruneOldFrames() {
	if a.head == nil || a.head.Depth < maxTreeDepth {
		return // Not enough frames to prune
	}

	// Calculate the minimum depth to keep
	minDepthToKeep := a.head.Depth - maxTreeDepth + 1

	// Find all nodes that should be pruned (depth < minDepthToKeep)
	var nodesToPrune []*FrameNode
	for _, node := range a.nodes {
		if node.Depth < minDepthToKeep {
			nodesToPrune = append(nodesToPrune, node)
		}
	}

	if len(nodesToPrune) == 0 {
		return // Nothing to prune
	}

	// First, clear parent references from children of nodes being pruned
	// This ensures proper garbage collection
	for _, node := range nodesToPrune {
		for _, child := range node.Children {
			if child.Depth >= minDepthToKeep {
				// This child is being kept, so clear its parent reference
				child.Parent = nil
			}
		}
	}

	// Remove nodes from data structures
	for _, node := range nodesToPrune {
		frameID := a.ComputeFrameID(node.Frame)

		// Remove from nodes map
		delete(a.nodes, frameID)

		// Remove from framesByNumber
		frameNum := node.Frame.Header.FrameNumber
		if nodeList, exists := a.framesByNumber[frameNum]; exists {
			// Filter out the node to be pruned
			var filteredList []*FrameNode
			for _, n := range nodeList {
				if n != node {
					filteredList = append(filteredList, n)
				}
			}
			if len(filteredList) == 0 {
				delete(a.framesByNumber, frameNum)
			} else {
				a.framesByNumber[frameNum] = filteredList
			}
		}

		// Remove from cache
		a.cache.Remove(frameID)

		// Disconnect from parent
		if node.Parent != nil {
			delete(node.Parent.Children, frameID)
		}

		// Update root if necessary
		if a.root == node {
			// Find new root (should be one of the remaining nodes at minimum depth)
			a.root = nil
			for _, remaining := range a.nodes {
				if remaining.Depth == minDepthToKeep {
					if a.root == nil ||
						remaining.Frame.Header.FrameNumber < a.root.Frame.Header.FrameNumber {
						a.root = remaining
					}
				}
			}
			// Clear parent reference for new root
			if a.root != nil {
				a.root.Parent = nil
			}
		}
	}

	a.logger.Info(
		"pruned old frames",
		zap.String("address", fmt.Sprintf("%x", a.address)),
		zap.Int("pruned_count", len(nodesToPrune)),
		zap.Uint64("min_depth_kept", minDepthToKeep),
		zap.Uint64("head_depth", a.head.Depth))
}

// pruneOldPendingFrames removes pending frames that are too old
func (a *AppTimeReel) pruneOldPendingFrames() {
	// Prune pending frames older than 5 minutes
	const maxPendingAge = 5 * 60 * 1000 // 5 minutes in milliseconds
	currentTime := time.Now().UnixMilli()

	prunedCount := 0
	for selector, pendingList := range a.pendingFrames {
		var filteredList []*PendingFrame
		for _, pending := range pendingList {
			age := currentTime - pending.Timestamp
			if age <= maxPendingAge {
				filteredList = append(filteredList, pending)
			} else {
				prunedCount++
			}
		}

		if len(filteredList) == 0 {
			delete(a.pendingFrames, selector)
		} else {
			a.pendingFrames[selector] = filteredList
		}
	}

	if prunedCount > 0 {
		a.logger.Info(
			"pruned old pending frames",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Int("pruned_count", prunedCount),
			zap.Int("remaining_selectors", len(a.pendingFrames)))
	}
}

// GetTreeInfo returns debugging information about the tree structure
func (a *AppTimeReel) GetTreeInfo() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	info := map[string]interface{}{
		"total_nodes":    len(a.nodes),
		"pending_frames": len(a.pendingFrames),
		"max_depth":      0,
		"branch_count":   0,
		"max_tree_depth": maxTreeDepth,
		"pruning_needed": false,
	}

	if a.head != nil {
		info["head_depth"] = a.head.Depth
		info["head_frame_number"] = a.head.Frame.Header.FrameNumber
		info["pruning_needed"] = a.head.Depth >= maxTreeDepth
	}

	// Calculate max depth and branch count
	leafNodes := a.findLeafNodes()
	info["branch_count"] = len(leafNodes)

	maxDepth := uint64(0)
	minDepth := uint64(0)
	if len(a.nodes) > 0 {
		minDepth = ^uint64(0) // max value
		for _, node := range a.nodes {
			if node.Depth > maxDepth {
				maxDepth = node.Depth
			}
			if node.Depth < minDepth {
				minDepth = node.Depth
			}
		}
	}
	info["max_depth"] = maxDepth
	info["min_depth"] = minDepth
	info["tree_span"] = maxDepth - minDepth + 1

	// Count pending frames
	totalPending := 0
	for _, pendingList := range a.pendingFrames {
		totalPending += len(pendingList)
	}
	info["total_pending"] = totalPending

	return info
}

// updateTreeMetrics updates Prometheus metrics for the tree state
func (a *AppTimeReel) updateTreeMetrics() {
	// Count total nodes
	treeNodeCount.WithLabelValues("app").Set(float64(len(a.nodes)))

	// Set tree depth
	if a.head != nil {
		treeDepth.WithLabelValues("app").Set(float64(a.head.Depth))
	}

	// Count pending frames
	totalPending := 0
	for _, pendingList := range a.pendingFrames {
		totalPending += len(pendingList)
	}
	pendingFramesCount.WithLabelValues("app").Set(float64(totalPending))

	// Count unique equivocators
	uniqueEquivocators := make(map[int]bool)
	for _, equivocatorsAtHeight := range a.equivocators {
		for bitPos := range equivocatorsAtHeight {
			uniqueEquivocators[bitPos] = true
		}
	}
	equivocatorsTracked.WithLabelValues("app").Set(
		float64(len(uniqueEquivocators)),
	)
}

func (a *AppTimeReel) bootstrapFromStore() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	latest, _, err := a.store.GetLatestShardClockFrame(a.address)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // fresh DB
		}
		return errors.Wrap(err, "bootstrap from store")
	}
	latestNum := latest.Header.FrameNumber
	var start uint64
	if latestNum+1 > maxTreeDepth {
		start = latestNum - (maxTreeDepth - 1)
	} else {
		start = 0
	}

	iter, err := a.store.RangeShardClockFrames(a.address, start, latestNum)
	if err != nil {
		return errors.Wrap(err, "bootstrap from store")
	}
	defer iter.Close()

	var prev *FrameNode
	for ok := iter.First(); ok && iter.Valid(); ok = iter.Next() {
		frame, err := iter.Value()
		if err != nil {
			return errors.Wrap(err, "bootstrap from store")
		}
		frameID := a.ComputeFrameID(frame)

		node := &FrameNode{
			Frame:    frame,
			Parent:   nil,
			Children: make(map[string]*FrameNode),
			Depth:    0,
		}

		if prev != nil {
			expSel := computeAppPoseidonHash(prev.Frame.Header.Output)
			if bytes.Equal(frame.Header.ParentSelector, expSel) {
				node.Parent = prev
				node.Depth = prev.Depth + 1
				prev.Children[frameID] = node
			}
		}
		if node.Parent == nil {
			if p := a.findNodeBySelector(frame.Header.ParentSelector); p != nil {
				node.Parent = p
				node.Depth = p.Depth + 1
				p.Children[frameID] = node
			}
		}

		if a.root == nil {
			a.root = node
		}

		a.nodes[frameID] = node
		a.framesByNumber[frame.Header.FrameNumber] = append(
			a.framesByNumber[frame.Header.FrameNumber],
			node,
		)
		a.cache.Add(frameID, node)

		prev = node
		a.head = node
	}

	a.updateTreeMetrics()

	if a.head != nil {
		a.logger.Info(
			"bootstrapped app reel from store",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Uint64("loaded_to", a.head.Frame.Header.FrameNumber),
			zap.Int("loaded_count", len(a.nodes)),
		)
	}
	return nil
}

func (a *AppTimeReel) stageFrame(frame *protobufs.AppShardFrame) {
	txn, err := a.store.NewTransaction(false)
	if err != nil {
		a.logger.Warn(
			"stage frame: new txn failed",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Error(err),
		)
		return
	}
	if err := a.store.StageShardClockFrame(
		frame.Header.ParentSelector,
		frame,
		txn,
	); err != nil {
		_ = txn.Abort()
		a.logger.Warn(
			"stage frame failed",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Uint64("frame", frame.Header.FrameNumber),
			zap.Error(err),
		)
		return
	}
	if err := txn.Commit(); err != nil {
		a.logger.Warn(
			"stage frame commit failed",
			zap.String("address", fmt.Sprintf("%x", a.address)),
			zap.Uint64("frame", frame.Header.FrameNumber),
			zap.Error(err),
		)
	}
}

func (a *AppTimeReel) persistCanonicalFrames(
	frames []*protobufs.AppShardFrame,
) error {
	if len(frames) == 0 {
		return nil
	}
	txn, err := a.store.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "persist canonical frames")
	}
	for _, f := range frames {
		if err := a.materializeFunc(
			txn,
			f,
		); err != nil {
			_ = txn.Abort()
			return errors.Wrap(err, "persist canonical frames")
		}

		if err := a.store.CommitShardClockFrame(
			a.address,
			f.Header.FrameNumber,
			f.Header.ParentSelector,
			nil, // proverTries
			txn,
			false, // backfill
		); err != nil {
			_ = txn.Abort()
			return errors.Wrap(err, "persist canonical frames")
		}
	}
	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "persist canonical frames")
	}
	return nil
}
