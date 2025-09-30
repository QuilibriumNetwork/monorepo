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
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

const (
	// Default cache size for LRU
	defaultGlobalCacheSize = 10000
	// Maximum tree depth to prevent unbounded growth
	maxGlobalTreeDepth = 360
)

// TimeReelEventType represents different types of events that can occur in a
// time reel
type TimeReelEventType int

const (
	TimeReelEventNewHead TimeReelEventType = iota
	TimeReelEventForkDetected
	TimeReelEventEquivocationDetected
)

// GlobalEvent represents an event in the global time reel
type GlobalEvent struct {
	Type    TimeReelEventType
	Frame   *protobufs.GlobalFrame
	OldHead *protobufs.GlobalFrame // For fork events
	Message string
}

func (n *GlobalEvent) ControlEventData() {}

// GlobalFrameNode represents a node in the global frame tree
type GlobalFrameNode struct {
	Frame    *protobufs.GlobalFrame
	Parent   *GlobalFrameNode
	Children map[string]*GlobalFrameNode
	Depth    uint64
}

// GlobalPendingFrame represents a frame waiting for its parent
type GlobalPendingFrame struct {
	Frame          *protobufs.GlobalFrame
	ParentSelector []byte
	Timestamp      int64
}

// GlobalTimeReel implements a time reel for GlobalFrames
type GlobalTimeReel struct {
	logger         *zap.Logger
	proverRegistry consensus.ProverRegistry
	mu             sync.RWMutex

	// Tree structure
	root *GlobalFrameNode
	// Fast lookup by frame ID (output hash)
	nodes map[string]*GlobalFrameNode
	// Fast lookup by frame number
	framesByNumber map[uint64][]*GlobalFrameNode
	// Current head of canonical chain
	head *GlobalFrameNode

	// Pending frames waiting for parents
	pendingFrames map[string][]*GlobalPendingFrame

	// Fork choice parameters
	forkChoiceParams Params

	// LRU cache for frame lookups
	cache *lru.Cache[string, *GlobalFrameNode]

	// Underlying frame store
	store store.ClockStore

	// Event channel with guaranteed delivery
	eventCh   chan GlobalEvent
	eventDone chan struct{} // Signals event processing complete

	// Equivocator tracking: frame number -> bit positions that equivocated
	equivocators map[uint64]map[int]bool

	// Materialize side effects
	materializeFunc func(
		txn store.Transaction,
		frameNumber uint64,
		requests []*protobufs.MessageBundle,
	) error

	// Revert side effects
	revertFunc func(
		txn store.Transaction,
		frameNumber uint64,
		requests []*protobufs.MessageBundle,
	) error

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// Network-specific consensus toggles
	genesisFrameNumber uint64

	// Archive mode: whether to hold historic frame data
	archiveMode bool
}

// NewGlobalTimeReel creates a new global time reel
func NewGlobalTimeReel(
	logger *zap.Logger,
	proverRegistry consensus.ProverRegistry,
	clockStore store.ClockStore,
	network uint8,
	archiveMode bool,
) (*GlobalTimeReel, error) {
	cache, err := lru.New[string, *GlobalFrameNode](
		defaultGlobalCacheSize,
	)
	if err != nil {
		return nil, errors.Wrap(err, "new global time reel")
	}

	ctx, cancel := context.WithCancel(context.Background())

	genesisFrameNumber := uint64(0)

	if network == 0 {
		genesisFrameNumber = 244200
	}

	return &GlobalTimeReel{
		logger:           logger,
		proverRegistry:   proverRegistry,
		store:            clockStore,
		nodes:            make(map[string]*GlobalFrameNode),
		framesByNumber:   make(map[uint64][]*GlobalFrameNode),
		pendingFrames:    make(map[string][]*GlobalPendingFrame),
		forkChoiceParams: DefaultForkChoiceParams,
		cache:            cache,
		eventCh:          make(chan GlobalEvent, 1000),
		eventDone:        make(chan struct{}),
		equivocators:     make(map[uint64]map[int]bool),
		materializeFunc: func(
			txn store.Transaction,
			frameNumber uint64,
			requests []*protobufs.MessageBundle,
		) error {
			return nil
		},
		revertFunc: func(
			txn store.Transaction,
			frameNumber uint64,
			requests []*protobufs.MessageBundle,
		) error {
			return nil
		},
		ctx:                ctx,
		cancel:             cancel,
		genesisFrameNumber: genesisFrameNumber,
		archiveMode:        archiveMode,
	}, nil
}

// SetMaterializeFunc sets the materialize side effects function
func (g *GlobalTimeReel) SetMaterializeFunc(
	materializeFunc func(
		txn store.Transaction,
		frameNumber uint64,
		requests []*protobufs.MessageBundle,
	) error,
) {
	g.materializeFunc = materializeFunc
}

// SetRevertFunc sets the revert side effects function
func (g *GlobalTimeReel) SetRevertFunc(
	revertFunc func(
		txn store.Transaction,
		frameNumber uint64,
		requests []*protobufs.MessageBundle,
	) error,
) {
	g.revertFunc = revertFunc
}

// Start starts the global time reel
func (g *GlobalTimeReel) Start() error {
	g.logger.Info("starting global time reel")

	// Warm the in-memory tree/cache from store.
	if err := g.bootstrapFromStore(); err != nil {
		return errors.Wrap(err, "start")
	}

	return nil
}

// Stop stops the global time reel
func (g *GlobalTimeReel) Stop() {
	g.logger.Info("stopping global time reel")
	g.cancel()
	close(g.eventCh)
	close(g.eventDone)
}

// sendEvent sends an event with guaranteed delivery
func (g *GlobalTimeReel) sendEvent(event GlobalEvent) {
	// This blocks until the event is delivered, guaranteeing order
	select {
	case g.eventCh <- event:
		g.logger.Debug(
			"sent event",
			zap.Int("type", int(event.Type)),
			zap.Uint64("frame_number", event.Frame.Header.FrameNumber),
			zap.String("id", g.ComputeFrameID(event.Frame)),
		)
	case <-g.ctx.Done():
		return
	}
}

// Insert inserts a global frame header into the tree structure (non-blocking)
func (g *GlobalTimeReel) Insert(
	ctx context.Context,
	frame *protobufs.GlobalFrame,
) error {
	// Start timing
	timer := prometheus.NewTimer(
		frameProcessingDuration.WithLabelValues("global"),
	)
	defer timer.ObserveDuration()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Compute frame ID
	frameID := g.ComputeFrameID(frame)

	// Check if frame already exists with same ID
	if _, exists := g.nodes[frameID]; exists {
		return nil
	}

	// Check for equivocation with different frames at same height
	nodesAtHeight := g.framesByNumber[frame.Header.FrameNumber]
	for _, node := range nodesAtHeight {
		if !isEqualGlobalFrame(node.Frame, frame) &&
			hasOverlappingBits(node.Frame, frame) {
			g.logger.Warn(
				"equivocation detected for frame",
				zap.Uint64("frame_number", frame.Header.FrameNumber),
			)

			// Track which bits equivocated
			if g.equivocators[frame.Header.FrameNumber] == nil {
				g.equivocators[frame.Header.FrameNumber] = make(map[int]bool)
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
							g.equivocators[frame.Header.FrameNumber][i*8+bit] = true
						}
					}
				}
			}

			g.sendEvent(GlobalEvent{
				Type:  TimeReelEventEquivocationDetected,
				Frame: frame,
				Message: fmt.Sprintf(
					"equivocation at frame %d",
					frame.Header.FrameNumber,
				),
			})

			// Record equivocation metric
			equivocationsDetected.WithLabelValues("global").Inc()

			// Continue processing, we need to handle fork choice still before the
			// trees update
		}
	}

	// Handle genesis frame
	if frame.Header.FrameNumber == g.genesisFrameNumber {
		return g.insertGenesisFrame(frame, frameID)
	}

	// In non-archive mode, if we have no frames yet and this frame is recent
	// enough, accept it as a starting point
	if !g.archiveMode && g.root == nil && len(g.nodes) == 0 {
		// Accept this frame as the initial pseudo-root
		g.logger.Info(
			"non-archive mode: accepting first frame as pseudo-root",
			zap.Uint64("frame_number", frame.Header.FrameNumber),
		)
		return g.insertGenesisFrame(frame, frameID)
	}

	// Try to find parent
	parentSelector := string(frame.Header.ParentSelector)
	parentNode := g.findNodeBySelector(frame.Header.ParentSelector)

	if parentNode == nil {
		if !g.archiveMode {
			// In non-archive mode, check if we should accept this frame based on
			// frame number proximity to our current head
			if g.head != nil {
				// Check if frame is within reasonable range of our head
				if frame.Header.FrameNumber > g.head.Frame.Header.FrameNumber &&
					frame.Header.FrameNumber <= g.head.Frame.Header.FrameNumber+10 {
					// Frame is slightly ahead, add to pending
					g.addPendingFrame(frame, parentSelector)
					return nil
				} else if frame.Header.FrameNumber < g.head.Frame.Header.FrameNumber &&
					g.head.Frame.Header.FrameNumber-frame.Header.FrameNumber > maxGlobalTreeDepth {
					// Frame is too old, reject it
					g.logger.Debug(
						"rejecting old frame in non-archive mode",
						zap.Uint64("frame_number", frame.Header.FrameNumber),
						zap.Uint64("head_frame", g.head.Frame.Header.FrameNumber),
					)
					return nil
				}
			}
		}
		// Parent not found, add to pending frames
		g.addPendingFrame(frame, parentSelector)
		return nil
	}

	// Verify parent selector matches
	expectedSelector := computeGlobalPoseidonHash(parentNode.Frame.Header.Output)
	if !bytes.Equal(expectedSelector, frame.Header.ParentSelector) {
		return errors.New("parent selector mismatch")
	}

	// Insert frame into tree
	newNode := &GlobalFrameNode{
		Frame:    frame,
		Parent:   parentNode,
		Children: make(map[string]*GlobalFrameNode),
		Depth:    parentNode.Depth + 1,
	}

	// Add to data structures
	g.nodes[frameID] = newNode
	g.framesByNumber[frame.Header.FrameNumber] = append(
		g.framesByNumber[frame.Header.FrameNumber],
		newNode,
	)
	parentNode.Children[frameID] = newNode
	g.cache.Add(frameID, newNode)

	// Process any pending frames that can now be connected
	g.processPendingFrames(frameID, newNode)

	// Evaluate fork choice if we have competing branches
	g.evaluateForkChoice(newNode)

	// Prune old frames if tree is getting too deep
	g.pruneOldFrames()

	// Prune old pending frames periodically
	g.pruneOldPendingFrames()

	// Record success
	framesProcessedTotal.WithLabelValues("global", "success").Inc()

	// Update tree metrics
	g.updateTreeMetrics()

	return nil
}

// insertGenesisFrame handles genesis frame insertion or pseudo-root in non-archive mode
func (g *GlobalTimeReel) insertGenesisFrame(
	frame *protobufs.GlobalFrame,
	frameID string,
) error {
	if g.root != nil && g.archiveMode {
		// In archive mode, don't replace existing root
		return errors.New("genesis frame already exists")
	}

	if g.root != nil && !g.archiveMode {
		// In non-archive mode, check if this frame should replace the current pseudo-root
		if frame.Header.FrameNumber >= g.root.Frame.Header.FrameNumber {
			// This frame is not older than current root, don't replace
			return errors.New("frame is not older than current root")
		}
		// This frame is older, it should become the new pseudo-root
		g.logger.Info(
			"non-archive mode: replacing pseudo-root with older frame",
			zap.Uint64("old_root_frame", g.root.Frame.Header.FrameNumber),
			zap.Uint64("new_root_frame", frame.Header.FrameNumber),
		)
	}

	g.root = &GlobalFrameNode{
		Frame:    frame,
		Parent:   nil,
		Children: make(map[string]*GlobalFrameNode),
		Depth:    0,
	}

	g.nodes[frameID] = g.root
	g.framesByNumber[frame.Header.FrameNumber] = []*GlobalFrameNode{g.root}
	g.head = g.root
	g.cache.Add(frameID, g.root)

	// Persist canonical genesis.
	if err := g.persistCanonicalFrames(
		[]*protobufs.GlobalFrame{frame},
	); err != nil {
		return errors.Wrap(err, "insert genesis frame")
	}

	// Send new head event
	g.sendEvent(GlobalEvent{
		Type:  TimeReelEventNewHead,
		Frame: frame,
	})

	// Process any pending frames that can now be connected
	g.processPendingFrames(frameID, g.root)

	// Prune old frames if tree is getting too deep
	g.pruneOldFrames()

	return nil
}

// addPendingFrame adds a frame to the pending list
func (g *GlobalTimeReel) addPendingFrame(
	frame *protobufs.GlobalFrame,
	parentSelector string,
) {
	pending := &GlobalPendingFrame{
		Frame:          frame,
		ParentSelector: frame.Header.ParentSelector,
		Timestamp:      frame.Header.Timestamp,
	}

	g.pendingFrames[parentSelector] = append(
		g.pendingFrames[parentSelector],
		pending,
	)

	g.logger.Debug(
		"added pending frame",
		zap.Uint64("frame_number", frame.Header.FrameNumber),
		zap.String(
			"parent_selector",
			fmt.Sprintf("%x", frame.Header.ParentSelector),
		),
	)
}

// processPendingFrames processes frames that were waiting for the given parent
func (g *GlobalTimeReel) processPendingFrames(
	parentFrameID string,
	parentNode *GlobalFrameNode,
) {
	g.logger.Debug(
		"process pending frame",
		zap.Uint64("frame_number", parentNode.Frame.Header.FrameNumber),
		zap.String("id", parentFrameID),
	)
	parentSelector := computeGlobalPoseidonHash(parentNode.Frame.Header.Output)
	parentSelectorStr := string(parentSelector)

	pendingList := g.pendingFrames[parentSelectorStr]
	if len(pendingList) == 0 {
		return
	}

	// Remove from pending list
	delete(g.pendingFrames, parentSelectorStr)

	// Process each pending frame
	for _, pending := range pendingList {
		frameID := g.ComputeFrameID(pending.Frame)

		// Skip if already processed
		if _, exists := g.nodes[frameID]; exists {
			continue
		}

		// Create and insert node
		newNode := &GlobalFrameNode{
			Frame:    pending.Frame,
			Parent:   parentNode,
			Children: make(map[string]*GlobalFrameNode),
			Depth:    parentNode.Depth + 1,
		}

		g.nodes[frameID] = newNode
		g.framesByNumber[pending.Frame.Header.FrameNumber] = append(
			g.framesByNumber[pending.Frame.Header.FrameNumber], newNode)
		parentNode.Children[frameID] = newNode
		g.cache.Add(frameID, newNode)

		g.logger.Debug(
			"processed pending frame",
			zap.Uint64("frame_number", pending.Frame.Header.FrameNumber),
			zap.String("id", frameID),
			zap.String("parent_id", parentFrameID),
		)

		// Recursively process any frames waiting for this one
		g.processPendingFrames(frameID, newNode)

		// Evaluate fork choice
		g.evaluateForkChoice(newNode)
	}
}

// findNodeBySelector finds a node whose output hash matches the selector
func (g *GlobalTimeReel) findNodeBySelector(selector []byte) *GlobalFrameNode {
	for _, node := range g.nodes {
		expectedSelector := computeGlobalPoseidonHash(node.Frame.Header.Output)
		if bytes.Equal(expectedSelector, selector) {
			return node
		}
	}
	return nil
}

// evaluateForkChoice evaluates fork choice and updates head if necessary
func (g *GlobalTimeReel) evaluateForkChoice(newNode *GlobalFrameNode) {
	if g.head == nil {
		g.head = newNode
		g.sendHeadEvent(newNode, nil)
		return
	}

	// Find all competing branches (leaf nodes)
	leafNodes := g.findLeafNodes()
	if len(leafNodes) <= 1 {
		// No competition, check if we should update head
		if newNode.Depth > g.head.Depth {
			oldHead := g.head
			g.head = newNode

			g.persistCanonicalFrames([]*protobufs.GlobalFrame{newNode.Frame})

			g.sendHeadEvent(newNode, oldHead)
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
	var competingLeaves []*GlobalFrameNode
	for _, leaf := range leafNodes {
		if leaf.Depth == maxDepth {
			competingLeaves = append(competingLeaves, leaf)
		}
	}

	// If only one leaf at max depth, make it head
	if len(competingLeaves) == 1 {
		chosenNode := competingLeaves[0]
		if chosenNode != g.head {
			oldHead := g.head
			g.head = chosenNode

			// Check if this is a reorganization (fork)
			if oldHead != nil && !g.isAncestorNode(oldHead, chosenNode) {
				g.logger.Info(
					"reorganization detected (single leaf)",
					zap.Uint64("old_head_frame", oldHead.Frame.Header.FrameNumber),
					zap.Uint64("new_head_frame", chosenNode.Frame.Header.FrameNumber))
				// This is a fork - emit fork detected event first
				event := GlobalEvent{
					Type:    TimeReelEventForkDetected,
					Frame:   chosenNode.Frame,
					OldHead: oldHead.Frame,
					Message: fmt.Sprintf(
						"fork detected: old head %d (%x), new head %d (%x)",
						oldHead.Frame.Header.FrameNumber,
						poseidon.Sum(oldHead.Frame.Header.Output),
						chosenNode.Frame.Header.FrameNumber,
						poseidon.Sum(chosenNode.Frame.Header.Output),
					),
				}
				g.sendEvent(event)

				// Find the common ancestor
				commonAncestor, reverts := g.findCommonAncestor(oldHead, chosenNode)

				if len(reverts) != 0 {
					g.rewindFrames(reverts)
				}

				// Emit new head events for each frame in the new canonical path
				// from the frame after the common ancestor to the new head
				if commonAncestor != nil {
					g.emitReplayEvents(commonAncestor, chosenNode)
				}
			} else {
				// Regular head advance - emit single new head event
				headChangesTotal.WithLabelValues("global", "advance").Inc()

				g.persistCanonicalFrames([]*protobufs.GlobalFrame{newNode.Frame})

				event := GlobalEvent{
					Type:  TimeReelEventNewHead,
					Frame: chosenNode.Frame,
				}
				if oldHead != nil {
					event.OldHead = oldHead.Frame
				}
				g.sendEvent(event)
			}
		}
		return
	}

	// Convert competing leaf nodes to branches for fork choice
	branches := make([]Branch, 0, len(competingLeaves))
	nodeToIndex := make(map[*GlobalFrameNode]int)

	for i, leaf := range competingLeaves {
		branch := g.nodeToBranch(leaf)
		branches = append(branches, branch)
		nodeToIndex[leaf] = i
		g.logger.Debug(
			"competing leaf",
			zap.Int("index", i),
			zap.Uint64("frame_number", leaf.Frame.Header.FrameNumber),
		)
	}

	// Get current head index - find which competing leaf is the current head
	prevChoice := 0
	for i, leaf := range competingLeaves {
		if leaf == g.head {
			prevChoice = i
			break
		}
	}

	// Perform fork choice
	forkChoiceTimer := prometheus.NewTimer(
		forkChoiceDuration.WithLabelValues("global"),
	)

	// Debug: log branch information
	for i, branch := range branches {
		if len(branch.Frames) > 0 {
			lastFrame := branch.Frames[len(branch.Frames)-1]
			g.logger.Debug(
				"fork choice branch",
				zap.Int("index", i),
				zap.String("prover", hex.EncodeToString(lastFrame.ProverAddress)),
				zap.String("distance", lastFrame.Distance.String()),
				zap.Bool("is_current_head", competingLeaves[i] == g.head))
		}
	}

	chosenIndex := ForkChoice(branches, g.forkChoiceParams, prevChoice)
	chosenNode := competingLeaves[chosenIndex]
	forkChoiceTimer.ObserveDuration()

	g.logger.Debug(
		"fork choice result",
		zap.Int("chosen_index", chosenIndex),
		zap.Int("prev_choice", prevChoice),
	)

	// Record fork choice metrics
	forkChoiceEvaluations.WithLabelValues("global").Inc()
	competingBranches.WithLabelValues("global").Observe(float64(len(branches)))

	// Update head if it changed
	if chosenNode != g.head {
		oldHead := g.head
		g.head = chosenNode

		// Check if this is a reorganization (fork)
		if oldHead != nil && !g.isAncestorNode(oldHead, chosenNode) {
			g.logger.Info(
				"reorganization detected",
				zap.Uint64("old_head_frame", oldHead.Frame.Header.FrameNumber),
				zap.Uint64("new_head_frame", chosenNode.Frame.Header.FrameNumber))

			// Record reorganization metrics
			headChangesTotal.WithLabelValues("global", "reorganization").Inc()

			// Calculate reorganization depth
			commonAncestor, reverts := g.findCommonAncestor(oldHead, chosenNode)
			if commonAncestor != nil {
				depth := oldHead.Depth - commonAncestor.Depth
				reorganizationDepth.WithLabelValues("global").Observe(float64(depth))
			}

			// This is a fork - emit fork detected event first
			event := GlobalEvent{
				Type:    TimeReelEventForkDetected,
				Frame:   chosenNode.Frame,
				OldHead: oldHead.Frame,
				Message: fmt.Sprintf(
					"fork detected: old head %d (%x), new head %d (%x)",
					oldHead.Frame.Header.FrameNumber,
					poseidon.Sum(oldHead.Frame.Header.Output),
					chosenNode.Frame.Header.FrameNumber,
					poseidon.Sum(chosenNode.Frame.Header.Output),
				),
			}
			g.sendEvent(event)

			// Rewind all previous frames
			if len(reverts) != 0 {
				g.rewindFrames(reverts)
			}

			// Emit new head events for each frame in the new canonical path
			// from the frame after the common ancestor to the new head
			if commonAncestor != nil {
				g.emitReplayEvents(commonAncestor, chosenNode)
			}
		} else {
			// Regular head advance - emit single new head event
			event := GlobalEvent{
				Type:  TimeReelEventNewHead,
				Frame: chosenNode.Frame,
			}
			if oldHead != nil {
				event.OldHead = oldHead.Frame
			}
			g.sendEvent(event)
		}
	}
}

// findLeafNodes returns all leaf nodes (nodes with no children)
func (g *GlobalTimeReel) findLeafNodes() []*GlobalFrameNode {
	var leaves []*GlobalFrameNode
	for _, node := range g.nodes {
		if len(node.Children) == 0 {
			leaves = append(leaves, node)
		}
	}
	return leaves
}

// nodeToBranch converts a node and its lineage to a Branch for fork choice
func (g *GlobalTimeReel) nodeToBranch(node *GlobalFrameNode) Branch {
	// Build lineage from this node backwards, but limit to maxGlobalTreeDepth
	// frames
	var lineage []*GlobalFrameNode
	current := node
	depth := 0

	for current != nil && depth < maxGlobalTreeDepth {
		lineage = append([]*GlobalFrameNode{current}, lineage...)
		current = current.Parent
		depth++
	}

	// Convert to fork choice frames
	frames := make([]Frame, 0, len(lineage))
	for _, n := range lineage {
		// Use frame output as prover address for uniqueness. Global frames have no
		// assigned prover as they should mutually agree.
		proverAddr := n.Frame.Header.Output
		if len(proverAddr) > 32 {
			proverAddr = proverAddr[:32]
		}

		// Only frames with signatures should have signature-based seniority
		// Genesis and frames without signatures get default seniority
		seniority := g.computeFrameSeniority(n.Frame)

		g.logger.Debug(
			"frame seniority in branch",
			zap.Uint64("frame_number", n.Frame.Header.FrameNumber),
			zap.Uint64("seniority", seniority),
		)

		frame := Frame{
			Distance:      big.NewInt(0),
			Seniority:     seniority,
			ProverAddress: proverAddr,
		}
		frames = append(frames, frame)
	}

	return Branch{Frames: frames}
}

// computeFrameSeniority computes seniority for fork choice based on number of
// signers, excluding equivocators
func (g *GlobalTimeReel) computeFrameSeniority(
	frame *protobufs.GlobalFrame,
) uint64 {
	// Genesis frame and frames without signatures get minimal seniority
	if frame.Header.PublicKeySignatureBls48581 == nil {
		// Use minimal seniority so genesis doesn't dominate fork choice
		return SCALE / 64 // Same as 1 signer
	}

	// Count bits excluding equivocators
	equivocatorsAtHeight := g.equivocators[frame.Header.FrameNumber]
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
					g.logger.Debug(
						"excluding equivocator from seniority",
						zap.Uint64("frame_number", frame.Header.FrameNumber),
						zap.Int("bit_position", bitPos),
					)
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
func (g *GlobalTimeReel) sendHeadEvent(
	newHead *GlobalFrameNode,
	oldHead *GlobalFrameNode,
) {
	eventType := TimeReelEventNewHead
	var message string

	if oldHead != nil && !g.isAncestorNode(oldHead, newHead) {
		eventType = TimeReelEventForkDetected
		message = fmt.Sprintf(
			"fork detected: old head %d (%x), new head %d (%x)",
			oldHead.Frame.Header.FrameNumber,
			poseidon.Sum(oldHead.Frame.Header.Output),
			newHead.Frame.Header.FrameNumber,
			poseidon.Sum(newHead.Frame.Header.Output),
		)
	}

	event := GlobalEvent{
		Type:    eventType,
		Frame:   newHead.Frame,
		Message: message,
	}
	if oldHead != nil {
		event.OldHead = oldHead.Frame
	}
	g.sendEvent(event)
}

// isAncestorNode checks if ancestor is an ancestor of descendant
func (g *GlobalTimeReel) isAncestorNode(
	ancestor, descendant *GlobalFrameNode,
) bool {
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
func (g *GlobalTimeReel) findCommonAncestor(
	node1, node2 *GlobalFrameNode,
) (*GlobalFrameNode, []*GlobalFrameNode) {
	// Build path from node1 to root
	path1 := make(map[*GlobalFrameNode]bool)
	current := node1
	for current != nil {
		path1[current] = true
		current = current.Parent
	}

	// Walk from node2 to root and find first common node
	current = node2
	for current != nil {
		if path1[current] {
			g.logger.Info(
				"found common ancestor",
				zap.Uint64("ancestor_frame", current.Frame.Header.FrameNumber),
				zap.Uint64("node1_frame", node1.Frame.Header.FrameNumber),
				zap.Uint64("node2_frame", node2.Frame.Header.FrameNumber))
			prev := []*GlobalFrameNode{node1}
			walk := node1
			for walk != current {
				prev = append(prev, walk.Parent)
				walk = walk.Parent
			}
			return current, prev
		}
		current = current.Parent
	}

	g.logger.Warn(
		"no common ancestor found",
		zap.Uint64("node1_frame", node1.Frame.Header.FrameNumber),
		zap.Uint64("node2_frame", node2.Frame.Header.FrameNumber),
	)
	return nil, nil
}

// emitReplayEvents emits new head events for each frame in the path from
// commonAncestor to newHead
func (g *GlobalTimeReel) emitReplayEvents(
	commonAncestor, newHead *GlobalFrameNode,
) {
	// Build path from newHead back to commonAncestor
	var reversePath []*GlobalFrameNode
	current := newHead
	for current != nil && current != commonAncestor {
		reversePath = append(reversePath, current)
		current = current.Parent
	}

	// Reverse the path to get correct order (from ancestor toward new head)
	replayPath := make([]*GlobalFrameNode, len(reversePath))
	for i, node := range reversePath {
		replayPath[len(reversePath)-1-i] = node
	}

	// Persist the canonical replay path in order.
	frames := make([]*protobufs.GlobalFrame, 0, len(replayPath))
	for _, n := range replayPath {
		frames = append(frames, n.Frame)
	}
	if err := g.persistCanonicalFrames(frames); err != nil {
		g.logger.Warn(
			"failed to persist canonical replay path",
			zap.Error(err),
			zap.Int("replay_len", len(frames)),
		)
	}

	g.logger.Info(
		"emitting replay events",
		zap.Int("replay_path_length", len(replayPath)),
		zap.String("common_ancestor", fmt.Sprintf(
			"frame_%d",
			commonAncestor.Frame.Header.FrameNumber,
		)),
		zap.String("common_ancestor_selector", fmt.Sprintf(
			"%x",
			computeGlobalPoseidonHash(commonAncestor.Frame.Header.Output),
		)),
		zap.String("new_head", fmt.Sprintf(
			"frame_%d",
			newHead.Frame.Header.FrameNumber,
		)),
		zap.String("new_head_selector", fmt.Sprintf(
			"%x",
			computeGlobalPoseidonHash(newHead.Frame.Header.Output),
		)),
	)

	// Emit new head events for each frame in the replay path sequentially
	for _, node := range replayPath {
		g.logger.Info(
			"emitting replay event for frame",
			zap.Uint64("frame_number", node.Frame.Header.FrameNumber))
		event := GlobalEvent{
			Type:  TimeReelEventNewHead,
			Frame: node.Frame,
		}
		g.sendEvent(event)
	}
}

// rewindFrames reverts side effects for frames in the old branch being unwound
func (g *GlobalTimeReel) rewindFrames(revertNodes []*GlobalFrameNode) {
	if len(revertNodes) == 0 {
		return
	}

	g.logger.Info(
		"rewinding frames",
		zap.Int("rewind_path_length", len(revertNodes)),
	)

	// Create a transaction for reverting side effects
	txn, err := g.store.NewTransaction(false)
	if err != nil {
		g.logger.Error(
			"failed to create transaction for rewind",
			zap.Error(err),
		)
		return
	}

	// Process each frame in the revert list (already in correct order)
	for _, node := range revertNodes {
		if node.Frame.Header.FrameNumber == 244200 {
			continue
		}

		g.logger.Info(
			"reverting frame",
			zap.Uint64("frame_number", node.Frame.Header.FrameNumber),
		)

		// Call revert function to undo side effects
		if err := g.revertFunc(
			txn,
			node.Frame.Header.FrameNumber,
			node.Frame.Requests,
		); err != nil {
			txn.Abort()
			g.logger.Error(
				"failed to revert frame side effects",
				zap.Uint64("frame_number", node.Frame.Header.FrameNumber),
				zap.Error(err),
			)
			return
		}
	}

	// Commit the revert transaction
	if err := txn.Commit(); err != nil {
		g.logger.Error(
			"failed to commit revert transaction",
			zap.Error(err),
		)
		return
	}

	g.logger.Info(
		"successfully rewound frames",
		zap.Int("reverted_count", len(revertNodes)),
	)
}

// ComputeFrameID computes a unique ID for a frame
func (g *GlobalTimeReel) ComputeFrameID(
	frame *protobufs.GlobalFrame,
) string {
	// Create a unique identifier based on frame contents
	data := fmt.Sprintf("%d:%d:%x:%x",
		frame.Header.FrameNumber,
		frame.Header.Timestamp,
		frame.Header.Output,
		frame.Header.ParentSelector,
	)
	hash := computeGlobalPoseidonHash([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// GetHead returns the current head frame
func (g *GlobalTimeReel) GetHead() (*protobufs.GlobalFrame, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.head == nil {
		return nil, errors.New("no head frame")
	}

	return g.head.Frame, nil
}

// GetFrame retrieves a frame by frame ID
func (g *GlobalTimeReel) GetFrame(frameID string) (
	*protobufs.GlobalFrame,
	error,
) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check cache first
	if node, ok := g.cache.Get(frameID); ok {
		return node.Frame, nil
	}

	// Check main storage
	node, exists := g.nodes[frameID]
	if !exists {
		return nil, errors.New("frame not found")
	}

	// Add to cache
	g.cache.Add(frameID, node)
	return node.Frame, nil
}

// GetFramesByNumber retrieves all frames at a specific frame number
func (g *GlobalTimeReel) GetFramesByNumber(frameNumber uint64) (
	[]*protobufs.GlobalFrame,
	error,
) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := g.framesByNumber[frameNumber]
	if len(nodes) == 0 {
		return nil, errors.New("no frames found at frame number")
	}

	frames := make([]*protobufs.GlobalFrame, len(nodes))
	for i, node := range nodes {
		frames[i] = node.Frame
	}

	return frames, nil
}

// GetLineage returns the full lineage of frames from genesis to the head
func (g *GlobalTimeReel) GetLineage() ([]*protobufs.GlobalFrame, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.head == nil {
		return nil, errors.New("no head frame")
	}

	return g.getNodeLineage(g.head), nil
}

// GetNodeLineage returns the lineage for a specific node
func (g *GlobalTimeReel) GetNodeLineage(frameID string) (
	[]*protobufs.GlobalFrame,
	error,
) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, exists := g.nodes[frameID]
	if !exists {
		return nil, errors.New("frame not found")
	}

	return g.getNodeLineage(node), nil
}

// getNodeLineage returns the lineage from genesis to the specified node
func (g *GlobalTimeReel) getNodeLineage(
	node *GlobalFrameNode,
) []*protobufs.GlobalFrame {
	var lineage []*protobufs.GlobalFrame
	current := node
	for current != nil {
		lineage = append([]*protobufs.GlobalFrame{current.Frame}, lineage...)
		current = current.Parent
	}
	return lineage
}

// GetEventCh returns the event channel
func (g *GlobalTimeReel) GetEventCh() <-chan GlobalEvent {
	return g.eventCh
}

// GetChildFrames returns all known child frames of a given parent frame
func (g *GlobalTimeReel) GetChildFrames(parentFrameID string) (
	[]*protobufs.GlobalFrame,
	error,
) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	parent, exists := g.nodes[parentFrameID]
	if !exists {
		return nil, errors.New("parent frame not found")
	}

	children := make([]*protobufs.GlobalFrame, 0, len(parent.Children))
	for _, child := range parent.Children {
		children = append(children, child.Frame)
	}

	return children, nil
}

// GetPendingFrames returns information about frames waiting for parents
func (
	g *GlobalTimeReel,
) GetPendingFrames() map[string][]*protobufs.GlobalFrame {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make(map[string][]*protobufs.GlobalFrame)
	for selector, pendingList := range g.pendingFrames {
		frames := make([]*protobufs.GlobalFrame, len(pendingList))
		for i, pending := range pendingList {
			frames[i] = pending.Frame
		}
		result[selector] = frames
	}

	return result
}

// GetBranchTips returns all leaf nodes (potential heads)
func (g *GlobalTimeReel) GetBranchTips() (
	[]*protobufs.GlobalFrame,
	error,
) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	leafNodes := g.findLeafNodes()
	tips := make([]*protobufs.GlobalFrame, len(leafNodes))
	for i, node := range leafNodes {
		tips[i] = node.Frame
	}

	return tips, nil
}

// SetForkChoiceParams updates the fork choice parameters
func (g *GlobalTimeReel) SetForkChoiceParams(params Params) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forkChoiceParams = params
}

// pruneOldFrames removes frames older than maxGlobalTreeDepth from the in-memory
// cache to prevent unbounded memory growth. The store handles its own pruning
// based on archive mode.
func (g *GlobalTimeReel) pruneOldFrames() {
	if g.head == nil || g.head.Depth < maxGlobalTreeDepth {
		return // Not enough frames to prune
	}

	// Calculate the minimum depth to keep
	minDepthToKeep := g.head.Depth - maxGlobalTreeDepth + 1

	// Find all nodes that should be pruned (depth < minDepthToKeep)
	var nodesToPrune []*GlobalFrameNode
	for _, node := range g.nodes {
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
		frameID := g.ComputeFrameID(node.Frame)

		// Remove from nodes map
		delete(g.nodes, frameID)

		// Remove from framesByNumber
		frameNum := node.Frame.Header.FrameNumber
		if nodeList, exists := g.framesByNumber[frameNum]; exists {
			// Filter out the node to be pruned
			var filteredList []*GlobalFrameNode
			for _, n := range nodeList {
				if n != node {
					filteredList = append(filteredList, n)
				}
			}
			if len(filteredList) == 0 {
				delete(g.framesByNumber, frameNum)
			} else {
				g.framesByNumber[frameNum] = filteredList
			}
		}

		// Remove from cache
		g.cache.Remove(frameID)

		// Disconnect from parent
		if node.Parent != nil {
			delete(node.Parent.Children, frameID)
		}

		// Update root if necessary
		if g.root == node {
			// Find new root (should be one of the remaining nodes at minimum depth)
			g.root = nil
			for _, remaining := range g.nodes {
				if remaining.Depth == minDepthToKeep {
					if g.root == nil ||
						remaining.Frame.Header.FrameNumber <
							g.root.Frame.Header.FrameNumber {
						g.root = remaining
					}
				}
			}
			// Clear parent reference for new root
			if g.root != nil {
				g.root.Parent = nil
			}
		}
	}

	g.logger.Info(
		"pruned old frames",
		zap.Int("pruned_count", len(nodesToPrune)),
		zap.Uint64("min_depth_kept", minDepthToKeep),
		zap.Uint64("head_depth", g.head.Depth))
}

// pruneOldPendingFrames removes pending frames that are too old
func (g *GlobalTimeReel) pruneOldPendingFrames() {
	// Prune pending frames older than 5 minutes
	const maxPendingAge = 5 * 60 * 1000 // 5 minutes in milliseconds
	currentTime := time.Now().UnixMilli()

	prunedCount := 0
	for selector, pendingList := range g.pendingFrames {
		var filteredList []*GlobalPendingFrame
		for _, pending := range pendingList {
			age := currentTime - pending.Timestamp
			if age <= maxPendingAge {
				filteredList = append(filteredList, pending)
			} else {
				prunedCount++
			}
		}

		if len(filteredList) == 0 {
			delete(g.pendingFrames, selector)
		} else {
			g.pendingFrames[selector] = filteredList
		}
	}

	if prunedCount > 0 {
		g.logger.Info(
			"pruned old pending frames",
			zap.Int("pruned_count", prunedCount),
			zap.Int("remaining_selectors", len(g.pendingFrames)))
	}
}

// GetTreeInfo returns debugging information about the tree structure
func (g *GlobalTimeReel) GetTreeInfo() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()

	info := map[string]interface{}{
		"total_nodes":    len(g.nodes),
		"pending_frames": len(g.pendingFrames),
		"max_depth":      0,
		"branch_count":   0,
		"max_tree_depth": maxTreeDepth,
		"pruning_needed": false,
	}

	if g.head != nil {
		info["head_depth"] = g.head.Depth
		info["head_frame_number"] = g.head.Frame.Header.FrameNumber
		info["pruning_needed"] = g.head.Depth >= maxTreeDepth
	}

	// Calculate max depth and branch count
	leafNodes := g.findLeafNodes()
	info["branch_count"] = len(leafNodes)

	maxDepth := uint64(0)
	minDepth := uint64(0)
	if len(g.nodes) > 0 {
		minDepth = ^uint64(0) // max value
		for _, node := range g.nodes {
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
	for _, pendingList := range g.pendingFrames {
		totalPending += len(pendingList)
	}
	info["total_pending"] = totalPending

	return info
}

// updateTreeMetrics updates Prometheus metrics for the tree state
func (g *GlobalTimeReel) updateTreeMetrics() {
	// Count total nodes
	treeNodeCount.WithLabelValues("global").Set(float64(len(g.nodes)))

	// Set tree depth
	if g.head != nil {
		treeDepth.WithLabelValues("global").Set(float64(g.head.Depth))
	}

	// Count pending frames
	totalPending := 0
	for _, pendingList := range g.pendingFrames {
		totalPending += len(pendingList)
	}
	pendingFramesCount.WithLabelValues("global").Set(float64(totalPending))

	// Count unique equivocators
	uniqueEquivocators := make(map[int]bool)
	for _, equivocatorsAtHeight := range g.equivocators {
		for bitPos := range equivocatorsAtHeight {
			uniqueEquivocators[bitPos] = true
		}
	}
	equivocatorsTracked.WithLabelValues("global").Set(
		float64(len(uniqueEquivocators)),
	)
}

// bootstrapFromStore loads up to the last maxGlobalTreeDepth canonical frames
// from durable storage and fills the in-memory structures and cache.
func (g *GlobalTimeReel) bootstrapFromStore() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	latest, err := g.store.GetLatestGlobalClockFrame()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Fresh DB — nothing to load.
			return nil
		}
		return errors.Wrap(err, "bootstrap from store")
	}
	latestNum := latest.Header.FrameNumber

	var start uint64
	if !g.archiveMode && latestNum+1 > maxGlobalTreeDepth {
		// Non-archive mode: only load last 360 frames
		start = latestNum - (maxGlobalTreeDepth - 1)
	} else {
		// Archive mode or insufficient frames: load all available
		start = g.genesisFrameNumber
	}

	iter, err := g.store.RangeGlobalClockFrames(start, latestNum)
	if err != nil {
		return errors.Wrap(err, "bootstrap from store")
	}
	defer iter.Close()

	var prev *GlobalFrameNode

	for ok := iter.First(); ok && iter.Valid(); ok = iter.Next() {
		frame, err := iter.Value()
		if err != nil {
			return errors.Wrap(err, "bootstrap from store")
		}
		frameID := g.ComputeFrameID(frame)

		// Create node; parent will be prev if selector matches, else try find by
		// selector.
		node := &GlobalFrameNode{
			Frame:    frame,
			Parent:   nil,
			Children: make(map[string]*GlobalFrameNode),
			Depth:    0,
		}

		// Try to link to known parent (best effort; first loaded frame may lack
		// parent in memory).
		if prev != nil {
			// Fast path: if this frame points to prev's output, link.
			expSel := computeGlobalPoseidonHash(prev.Frame.Header.Output)
			if bytes.Equal(frame.Header.ParentSelector, expSel) {
				node.Parent = prev
				node.Depth = prev.Depth + 1
				prev.Children[frameID] = node
			}
		}
		if node.Parent == nil {
			// Slow path: search existing nodes by selector (rare on linear history).
			if p := g.findNodeBySelector(frame.Header.ParentSelector); p != nil {
				node.Parent = p
				node.Depth = p.Depth + 1
				p.Children[frameID] = node
			} else if !g.archiveMode && frame.Header.FrameNumber == start {
				// Non-archive mode: first frame loaded may not have parent in DB.
				// Treat it as a pseudo-root with depth 0.
				node.Depth = 0
				g.logger.Info(
					"non-archive mode: treating first loaded frame as pseudo-root",
					zap.Uint64("frame_number", frame.Header.FrameNumber),
				)
			}
		}

		if g.root == nil || (!g.archiveMode && frame.Header.FrameNumber == start) {
			// Set root to first loaded frame (actual genesis or pseudo-root in non-archive mode)
			g.root = node
		}

		g.nodes[frameID] = node
		g.framesByNumber[frame.Header.FrameNumber] = append(
			g.framesByNumber[frame.Header.FrameNumber],
			node,
		)
		g.cache.Add(frameID, node)

		prev = node
		g.head = node
	}

	// Warm up the tree metrics
	g.updateTreeMetrics()

	if g.head != nil {
		g.logger.Info(
			"bootstrapped time reel from store",
			zap.Uint64("loaded_from_frame", start),
			zap.Uint64("loaded_to_frame", g.head.Frame.Header.FrameNumber),
			zap.Int("loaded_count", len(g.nodes)),
			zap.Bool("archive_mode", g.archiveMode),
		)

		if !g.archiveMode && g.root != nil {
			g.logger.Info(
				"non-archive mode: accepting last 360 frames as valid chain",
				zap.Uint64("pseudo_root_frame", g.root.Frame.Header.FrameNumber),
				zap.Uint64("head_frame", g.head.Frame.Header.FrameNumber),
			)
		}
	}

	return nil
}

// persistCanonicalFrames writes a contiguous set of canonical frames to the
// store in one txn. In non-archive mode, it also prunes old frames from the store.
func (g *GlobalTimeReel) persistCanonicalFrames(
	frames []*protobufs.GlobalFrame,
) error {
	if len(frames) == 0 {
		return nil
	}

	txn, err := g.store.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "persist canonical frames")
	}

	for _, f := range frames {
		if err := g.materializeFunc(
			txn,
			f.Header.FrameNumber,
			f.Requests,
		); err != nil {
			_ = txn.Abort()
			return errors.Wrap(err, "persist canonical frames")
		}
		if err := g.store.PutGlobalClockFrame(f, txn); err != nil {
			_ = txn.Abort()
			return errors.Wrap(err, "persist canonical frames")
		}
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "persist canonical frames")
	}

	// In non-archive mode, prune frames older than maxGlobalTreeDepth from store
	if !g.archiveMode && g.head != nil {
		// Calculate the oldest frame we want to keep
		if g.head.Frame.Header.FrameNumber > maxGlobalTreeDepth {
			oldestToKeep := g.head.Frame.Header.FrameNumber - maxGlobalTreeDepth + 1
			err := g.store.DeleteGlobalClockFrameRange(0, oldestToKeep)
			if err != nil {
				g.logger.Error("unable to delete frame range", zap.Error(err))
			}
		}
	}

	return nil
}
