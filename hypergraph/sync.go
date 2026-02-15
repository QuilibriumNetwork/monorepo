package hypergraph

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/peer"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// HyperStream is the gRPC method that handles synchronization.
func (hg *HypergraphCRDT) HyperStream(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) (err error) {
	requestCtx := stream.Context()
	ctx, shutdownCancel := hg.contextWithShutdown(requestCtx)
	defer shutdownCancel()

	// Apply session-level timeout only if we have a shutdown context
	// (i.e., in production, not in tests without shutdown context)
	if hg.shutdownCtx != nil {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, maxSyncSessionDuration)
		defer timeoutCancel()
	}

	sessionLogger := hg.logger
	sessionStart := time.Now()
	defer func() {
		sessionLogger.Info(
			"hyperstream session finished",
			zap.Duration("session_duration", time.Since(sessionStart)),
			zap.Error(err),
		)
	}()

	identifyStart := time.Now()
	peerId, err := hg.authenticationProvider.Identify(requestCtx)
	if err != nil {
		return errors.Wrap(err, "hyper stream")
	}
	sessionLogger = sessionLogger.With(zap.String("peer_id", peerId.String()))
	sessionLogger.Debug(
		"identified peer",
		zap.Duration("duration", time.Since(identifyStart)),
	)

	peerKey := peerId.String()
	if addr := peerIPFromContext(requestCtx); addr != "" {
		sessionLogger = sessionLogger.With(zap.String("peer_ip", addr))
	}
	if !hg.syncController.TryEstablishSyncSession(peerKey) {
		return errors.New("peer already syncing")
	}
	defer func() {
		hg.syncController.EndSyncSession(peerKey)
	}()

	// Start idle timeout monitor (only if shutdownCtx is available, i.e., in production)
	if hg.shutdownCtx != nil {
		idleCtx, idleCancel := context.WithCancel(ctx)
		defer idleCancel()
		go hg.monitorSyncSessionIdle(idleCtx, peerKey, sessionLogger, shutdownCancel)
	}

	syncStart := time.Now()
	err = hg.syncTreeServer(ctx, stream, sessionLogger)
	sessionLogger.Info(
		"syncTreeServer completed",
		zap.Duration("sync_duration", time.Since(syncStart)),
		zap.Error(err),
	)

	hg.syncController.SetStatus(peerKey, &hypergraph.SyncInfo{
		Unreachable: false,
		LastSynced:  time.Now(),
	})

	return err
}

// monitorSyncSessionIdle periodically checks if the sync session has become idle
// and cancels the context if so.
func (hg *HypergraphCRDT) monitorSyncSessionIdle(
	ctx context.Context,
	peerKey string,
	logger *zap.Logger,
	cancelFunc context.CancelFunc,
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hg.syncController.IsSessionStale(peerKey, maxSyncSessionDuration, syncIdleTimeout) {
				logger.Warn(
					"sync session idle timeout - forcing termination",
					zap.String("peer_id", peerKey),
					zap.Duration("session_duration", hg.syncController.SessionDuration(peerKey)),
				)
				cancelFunc()
				return
			}
		}
	}
}

// Sync performs the tree diff and synchronization from the client side.
// The caller (e.g. the client) must initiate the diff from its root.
// After that, both sides exchange queries, branch info, and leaf updates until
// their local trees are synchronized.
//
// If expectedRoot is provided, the server will attempt to use a snapshot with
// a matching commit root. This allows the client to sync against a specific
// known state rather than whatever the server's current state happens to be.
func (hg *HypergraphCRDT) Sync(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
) (root []byte, err error) {
	const localSyncKey = "local-sync"
	if !hg.syncController.TryEstablishSyncSession(localSyncKey) {
		return nil, errors.New("local sync already in progress")
	}
	defer func() {
		hg.syncController.EndSyncSession(localSyncKey)
	}()

	hg.mu.Lock()
	defer hg.mu.Unlock()

	syncStart := time.Now()
	shardKeyHex := hex.EncodeToString(slices.Concat(shardKey.L1[:], shardKey.L2[:]))
	hg.logger.Info(
		"sync started",
		zap.String("shard_key", shardKeyHex),
		zap.Int("phase_set", int(phaseSet)),
	)
	defer func() {
		hg.logger.Info(
			"sync finished",
			zap.String("shard_key", shardKeyHex),
			zap.Duration("duration", time.Since(syncStart)),
			zap.Error(err),
		)
	}()

	var set hypergraph.IdSet
	switch phaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		set = hg.getVertexAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		set = hg.getVertexRemovesSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		set = hg.getHyperedgeAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		set = hg.getHyperedgeRemovesSet(shardKey)
	default:
		return nil, errors.New("unsupported phase set")
	}

	path := hg.getCoveredPrefix()

	// Commit tree state through a transaction before sending initial query
	initTxn, err := hg.store.NewTransaction(false)
	if err != nil {
		return nil, err
	}
	initCommitment := set.GetTree().Commit(initTxn, false)
	if err := initTxn.Commit(); err != nil {
		initTxn.Abort()
		return nil, err
	}

	// Send initial query for path
	sendStart := time.Now()
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				ShardKey:        slices.Concat(shardKey.L1[:], shardKey.L2[:]),
				PhaseSet:        phaseSet,
				Path:            toInt32Slice(path),
				Commitment:      initCommitment,
				IncludeLeafData: false,
				ExpectedRoot:    expectedRoot,
			},
		},
	}); err != nil {
		return nil, err
	}
	hg.logger.Debug(
		"sent initialization message",
		zap.String("shard_key", shardKeyHex),
		zap.Duration("duration", time.Since(sendStart)),
	)

	// hg.logger.Debug("server waiting for initial query")
	recvStart := time.Now()
	msg, err := stream.Recv()
	if err != nil {
		hg.logger.Info("initial recv failed", zap.Error(err))
		return nil, err
	}
	hg.logger.Debug(
		"received initialization response",
		zap.String("shard_key", shardKeyHex),
		zap.Duration("duration", time.Since(recvStart)),
	)
	response := msg.GetResponse()
	if response == nil {
		return nil, errors.New(
			"server did not send valid initialization response message",
		)
	}

	branchInfoStart := time.Now()
	branchInfo, err := getBranchInfoFromTree(
		hg.logger,
		set.GetTree(),
		toInt32Slice(path),
	)
	if err != nil {
		return nil, err
	}
	hg.logger.Debug(
		"constructed branch info",
		zap.String("shard_key", shardKeyHex),
		zap.Duration("duration", time.Since(branchInfoStart)),
	)

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	responseSendStart := time.Now()
	if err := stream.Send(resp); err != nil {
		return nil, err
	}
	hg.logger.Debug(
		"sent initial branch info",
		zap.String("shard_key", shardKeyHex),
		zap.Duration("duration", time.Since(responseSendStart)),
	)

	ctx, cancel := context.WithCancel(stream.Context())

	incomingQueriesIn, incomingQueriesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonQuery](
			cancel,
			"client incoming",
		)
	incomingResponsesIn, incomingResponsesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonResponse](
			cancel,
			"client incoming",
		)
	incomingLeavesIn, incomingLeavesOut :=
		UnboundedChan[*protobufs.HypergraphComparison](
			cancel,
			"client incoming",
		)

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				// hg.logger.Debug("stream closed by sender")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				// hg.logger.Debug("error from stream", zap.Error(err))
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if msg == nil {
				continue
			}
			switch m := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_LeafData:
				incomingLeavesIn <- msg
			case *protobufs.HypergraphComparison_Metadata:
				incomingLeavesIn <- msg
			case *protobufs.HypergraphComparison_Query:
				incomingQueriesIn <- m.Query
			case *protobufs.HypergraphComparison_Response:
				incomingResponsesIn <- m.Response
			}
		}
	}()

	manager := &streamManager{
		ctx:             ctx,
		cancel:          cancel,
		logger:          hg.logger,
		stream:          stream,
		hypergraphStore: hg.store,
		localTree:       set.GetTree(),
		localSet:        set,
		lastSent:        time.Now(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := manager.walk(
			branchInfo.Path,
			branchInfo,
			response,
			incomingLeavesOut,
			incomingQueriesOut,
			incomingResponsesOut,
			true,
			false,
			shardKey,
			phaseSet,
		)
		if err != nil {
			hg.logger.Debug("error while syncing", zap.Error(err))
		}
	}()

	wg.Wait()

	finalTxn, err := hg.store.NewTransaction(false)
	if err != nil {
		return nil, err
	}
	root = set.GetTree().Commit(finalTxn, false)
	if err := finalTxn.Commit(); err != nil {
		finalTxn.Abort()
		return nil, err
	}
	hg.logger.Info(
		"hypergraph root commit",
		zap.String("root", hex.EncodeToString(root)),
	)

	return root, nil
}

func (hg *HypergraphCRDT) GetChildrenForPath(
	ctx context.Context,
	request *protobufs.GetChildrenForPathRequest,
) (*protobufs.GetChildrenForPathResponse, error) {
	if len(request.ShardKey) != 35 {
		return nil, errors.New("invalid shard key")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(request.ShardKey[:3]),
		L2: [32]byte(request.ShardKey[3:]),
	}

	var set hypergraph.IdSet
	switch request.PhaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		set = hg.getVertexAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		set = hg.getVertexRemovesSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		set = hg.getHyperedgeAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		set = hg.getHyperedgeRemovesSet(shardKey)
	}

	path := []int{}
	for _, p := range request.Path {
		path = append(path, int(p))
	}

	segments, err := getSegments(
		set.GetTree(),
		path,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get children for path")
	}

	response := &protobufs.GetChildrenForPathResponse{
		PathSegments: []*protobufs.TreePathSegments{},
	}

	for _, segment := range segments {
		pathSegments := &protobufs.TreePathSegments{}
		for i, seg := range segment {
			if seg == nil {
				continue
			}
			switch t := seg.(type) {
			case *tries.LazyVectorCommitmentBranchNode:
				pathSegments.Segments = append(
					pathSegments.Segments,
					&protobufs.TreePathSegment{
						Index: uint32(i),
						Segment: &protobufs.TreePathSegment_Branch{
							Branch: &protobufs.TreePathBranch{
								Prefix:        toUint32Slice(t.Prefix),
								Commitment:    t.Commitment,
								Size:          t.Size.Bytes(),
								LeafCount:     uint64(t.LeafCount),
								LongestBranch: uint32(t.LongestBranch),
								FullPrefix:    toUint32Slice(t.FullPrefix),
							},
						},
					},
				)
			case *tries.LazyVectorCommitmentLeafNode:
				var data []byte
				tree, err := hg.store.LoadVertexTree(t.Key)
				if err == nil {
					data, err = tries.SerializeNonLazyTree(tree)
					if err != nil {
						return nil, errors.Wrap(err, "get children for path")
					}
				}
				pathSegments.Segments = append(
					pathSegments.Segments,
					&protobufs.TreePathSegment{
						Index: uint32(i),
						Segment: &protobufs.TreePathSegment_Leaf{
							Leaf: &protobufs.TreePathLeaf{
								Key:        t.Key,
								Value:      data,
								HashTarget: t.HashTarget,
								Commitment: t.Commitment,
								Size:       t.Size.Bytes(),
							},
						},
					},
				)
			}
		}

		response.PathSegments = append(response.PathSegments, pathSegments)
	}

	return response, nil
}

func toUint32Slice(s []int) []uint32 {
	o := []uint32{}
	for _, p := range s {
		o = append(o, uint32(p))
	}
	return o
}

func toInt32Slice(s []int) []int32 {
	o := []int32{}
	for _, p := range s {
		o = append(o, int32(p))
	}
	return o
}

func toIntSlice(s []int32) []int {
	o := []int{}
	for _, p := range s {
		o = append(o, int(p))
	}
	return o
}

func isPrefix(prefix []int, path []int) bool {
	if len(prefix) > len(path) {
		return false
	}

	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}

	return true
}

func getChildSegments(
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	node *tries.LazyVectorCommitmentBranchNode,
	path []int,
) ([64]tries.LazyVectorCommitmentNode, int) {
	nodes := [64]tries.LazyVectorCommitmentNode{}
	index := 0
	for i, child := range node.Children {
		if child == nil {
			var err error
			prefix := slices.Concat(node.FullPrefix, []int{i})
			child, err = node.Store.GetNodeByPath(
				setType,
				phaseType,
				shardKey,
				prefix,
			)
			if err != nil && !strings.Contains(err.Error(), "item not found") {
				return nodes, 0
			}

			if isPrefix(prefix, path) {
				index = i
			}
		}

		if child != nil {
			nodes[i] = child
		}
	}

	return nodes, index
}

func getSegments(tree *tries.LazyVectorCommitmentTree, path []int) (
	[][64]tries.LazyVectorCommitmentNode,
	error,
) {
	segments := [][64]tries.LazyVectorCommitmentNode{
		{tree.Root},
	}

	node := tree.Root
	for node != nil {
		switch t := node.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			segment, index := getChildSegments(
				tree.SetType,
				tree.PhaseType,
				tree.ShardKey,
				t,
				path,
			)
			segments = append(segments, segment)
			node = segment[index]
		case *tries.LazyVectorCommitmentLeafNode:
			node = nil
		}
	}

	return segments, nil
}

type streamManager struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *zap.Logger
	stream          hypergraph.HyperStream
	hypergraphStore tries.TreeBackingStore
	localTree       *tries.LazyVectorCommitmentTree
	localSet        hypergraph.IdSet
	lastSent        time.Time
	snapshot        *snapshotHandle
}

// updateActivity updates the last activity timestamp for the stream.
func (s *streamManager) updateActivity() {
	s.lastSent = time.Now()
}

const (
	leafAckMinTimeout    = 30 * time.Second
	leafAckMaxTimeout    = 10 * time.Minute
	leafAckPerLeafBudget = 20 * time.Millisecond // Generous budget for tree building overhead

	// Session-level timeouts
	maxSyncSessionDuration = 30 * time.Minute // Maximum total time for a sync session
	syncIdleTimeout        = 10 * time.Minute // Maximum time without activity before session is killed

	// Operation-level timeouts
	syncOperationTimeout = 2 * time.Minute // Timeout for individual sync operations (queries, responses)
)

func leafAckTimeout(count uint64) time.Duration {
	// Calculate timeout with per-leaf budget plus a base overhead
	baseOverhead := 30 * time.Second
	timeout := baseOverhead + time.Duration(count)*leafAckPerLeafBudget

	if timeout < leafAckMinTimeout {
		return leafAckMinTimeout
	}
	if timeout > leafAckMaxTimeout {
		return leafAckMaxTimeout
	}
	return timeout
}

// isTimeoutError checks if an error is a timeout-related error that should abort the sync.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "timed out") ||
		strings.Contains(errMsg, "context deadline exceeded") ||
		strings.Contains(errMsg, "context canceled")
}

// sendLeafData builds a LeafData message (with the full leaf data) for the
// node at the given path in the local tree and sends it over the stream.
func (s *streamManager) sendLeafData(
	path []int32,
	incomingLeaves <-chan *protobufs.HypergraphComparison,
) (err error) {
	start := time.Now()
	pathHex := hex.EncodeToString(packPath(path))
	var count uint64
	s.logger.Debug("send leaf data start", zap.String("path", pathHex))
	defer func() {
		s.logger.Debug(
			"send leaf data finished",
			zap.String("path", pathHex),
			zap.Uint64("leaves_sent", count),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
	}()
	send := func(leaf *tries.LazyVectorCommitmentLeafNode) error {
		update := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}
		data, err := s.getSerializedLeaf(leaf.Key)
		if err != nil {
			return errors.Wrap(err, "send leaf data")
		}
		if len(data) != 0 {
			update.UnderlyingData = data
		}
		msg := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_LeafData{
				LeafData: update,
			},
		}

		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		err = s.stream.Send(msg)
		if err != nil {
			return errors.Wrap(err, "send leaf data")
		}

		s.updateActivity()
		return nil
	}

	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}

	intPath := []int{}
	for _, i := range path {
		intPath = append(intPath, int(i))
	}

	node, err := s.localTree.GetByPath(intPath)
	if err != nil {
		s.logger.Error("could not get by path", zap.Error(err))
		if err := s.stream.Send(&protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Metadata{
				Metadata: &protobufs.HypersyncMetadata{Leaves: 0},
			},
		}); err != nil {
			return err
		}
		// Wait for ack even when sending 0 leaves
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case msg, ok := <-incomingLeaves:
			if !ok {
				return errors.New("channel closed")
			}
			if meta := msg.GetMetadata(); meta == nil || meta.Leaves != 0 {
				return errors.New("unexpected ack for 0 leaves")
			}
		case <-time.After(leafAckTimeout(0)):
			return errors.New("timeout waiting for ack")
		}
		return nil
	}

	if node == nil {
		s.logger.Warn(
			"SERVER: node is nil at path, sending 0 leaves",
			zap.String("path", pathHex),
			zap.Bool("tree_nil", s.localTree == nil),
			zap.Bool("root_nil", s.localTree != nil && s.localTree.Root == nil),
		)
		if err := s.stream.Send(&protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Metadata{
				Metadata: &protobufs.HypersyncMetadata{Leaves: 0},
			},
		}); err != nil {
			return err
		}
		// Wait for ack even when sending 0 leaves
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case msg, ok := <-incomingLeaves:
			if !ok {
				return errors.New("channel closed")
			}
			if meta := msg.GetMetadata(); meta == nil || meta.Leaves != 0 {
				return errors.New("unexpected ack for 0 leaves")
			}
		case <-time.After(leafAckTimeout(0)):
			return errors.New("timeout waiting for ack")
		}
		return nil
	}

	leaf, ok := node.(*tries.LazyVectorCommitmentLeafNode)
	count = uint64(0)

	// Debug: log the node type
	s.logger.Info(
		"SERVER: node type at path",
		zap.String("path", pathHex),
		zap.Bool("is_leaf", ok),
		zap.String("node_type", fmt.Sprintf("%T", node)),
	)

	if !ok {
		children := tries.GetAllLeaves(
			s.localTree.SetType,
			s.localTree.PhaseType,
			s.localTree.ShardKey,
			node,
		)
		for _, child := range children {
			if child == nil {
				continue
			}
			count++
		}
		s.logger.Info(
			"SERVER: sending metadata with leaf count (branch)",
			zap.String("path", pathHex),
			zap.Uint64("leaf_count", count),
			zap.Int("children_slice_len", len(children)),
		)
		if err := s.stream.Send(&protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Metadata{
				Metadata: &protobufs.HypersyncMetadata{Leaves: count},
			},
		}); err != nil {
			return err
		}
		for _, child := range children {
			if child == nil {
				continue
			}

			if err := send(child); err != nil {
				return err
			}
		}
	} else {
		count = 1
		s.logger.Info(
			"SERVER: root is a single leaf, sending 1 leaf",
			zap.String("path", pathHex),
			zap.String("leaf_key", hex.EncodeToString(leaf.Key)),
		)
		if err := s.stream.Send(&protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Metadata{
				Metadata: &protobufs.HypersyncMetadata{Leaves: count},
			},
		}); err != nil {
			return err
		}
		if err := send(leaf); err != nil {
			return err
		}
	}

	timeoutTimer := time.NewTimer(leafAckTimeout(count))
	defer timeoutTimer.Stop()

	select {
	case <-s.ctx.Done():
		return errors.Wrap(
			errors.New("context canceled"),
			"send leaf data",
		)
	case msg, ok := <-incomingLeaves:
		if !ok {
			return errors.Wrap(
				errors.New("channel closed"),
				"send leaf data",
			)
		}

		switch msg.Payload.(type) {
		case *protobufs.HypergraphComparison_Metadata:
			expectedLeaves := msg.GetMetadata().Leaves
			if expectedLeaves != count {
				return errors.Wrap(
					errors.New("did not match"),
					"send leaf data",
				)
			}
			return nil
		}

		return errors.Wrap(
			errors.New("invalid message"),
			"send leaf data",
		)
	case <-timeoutTimer.C:
		return errors.Wrap(
			errors.New("timed out"),
			"send leaf data",
		)
	}
}

func (s *streamManager) getSerializedLeaf(key []byte) ([]byte, error) {
	if s.snapshot != nil {
		if data, ok := s.snapshot.getLeafData(key); ok {
			return data, nil
		}
		if s.snapshot.isLeafMiss(key) {
			return nil, nil
		}
	}

	type rawVertexLoader interface {
		LoadVertexTreeRaw(id []byte) ([]byte, error)
	}

	if loader, ok := s.hypergraphStore.(rawVertexLoader); ok {
		data, err := loader.LoadVertexTreeRaw(key)
		if err != nil {
			if s.snapshot != nil {
				s.snapshot.markLeafMiss(key)
			}
			return nil, nil
		}
		if len(data) != 0 {
			if s.snapshot != nil {
				s.snapshot.storeLeafData(key, data)
			}
			return data, nil
		}
	}

	tree, err := s.hypergraphStore.LoadVertexTree(key)
	if err != nil {
		if s.snapshot != nil {
			s.snapshot.markLeafMiss(key)
		}
		return nil, nil
	}
	data, err := tries.SerializeNonLazyTree(tree)
	if err != nil {
		return nil, err
	}

	if s.snapshot != nil {
		s.snapshot.storeLeafData(key, data)
	}
	return data, nil
}

func (s *streamManager) getBranchInfo(
	path []int32,
) (*protobufs.HypergraphComparisonResponse, error) {
	if s.snapshot != nil {
		if resp, ok := s.snapshot.getBranchInfo(path); ok {
			return resp, nil
		}
	}

	resp, err := getBranchInfoFromTree(s.logger, s.localTree, path)
	if err != nil {
		return nil, err
	}

	if s.snapshot != nil {
		s.snapshot.storeBranchInfo(path, resp)
	}

	return resp, nil
}

// getNodeAtPath traverses the tree along the provided nibble path. It returns
// the node found (or nil if not found). The depth argument is used for internal
// recursion.
func getNodeAtPath(
	logger *zap.Logger,
	setType string,
	phaseType string,
	shardKey tries.ShardKey,
	node tries.LazyVectorCommitmentNode,
	path []int32,
	depth int,
) tries.LazyVectorCommitmentNode {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		return node
	}

	switch n := node.(type) {
	case *tries.LazyVectorCommitmentLeafNode:
		return node
	case *tries.LazyVectorCommitmentBranchNode:
		// Check that the branch's prefix matches the beginning of the query path.
		if len(path) < len(n.Prefix) {
			return nil
		}

		for i, nib := range n.Prefix {
			if int32(nib) != path[i] {
				return nil
			}
		}

		// Remove the prefix portion from the path.
		remainder := path[len(n.Prefix):]
		if len(remainder) == 0 {
			return node
		}

		// The first element of the remainder selects the child.
		childIndex := remainder[0]
		if int(childIndex) < 0 || int(childIndex) >= len(n.Children) {
			return nil
		}

		child, err := n.Store.GetNodeByPath(
			setType,
			phaseType,
			shardKey,
			slices.Concat(n.FullPrefix, []int{int(childIndex)}),
		)
		if err != nil && !strings.Contains(err.Error(), "item not found") {
			return nil
		}

		if child == nil {
			return nil
		}

		return getNodeAtPath(
			logger,
			setType,
			phaseType,
			shardKey,
			child,
			remainder[1:],
			depth+len(n.Prefix)+1,
		)
	}
	return nil
}

// getBranchInfoFromTree looks up the node at the given path in the local tree,
// computes its commitment, and (if it is a branch) collects its immediate
// children's commitments.
func getBranchInfoFromTree(
	logger *zap.Logger,
	tree *tries.LazyVectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	node := getNodeAtPath(
		logger,
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		tree.Root,
		path,
		0,
	)
	if node == nil {
		return &protobufs.HypergraphComparisonResponse{
			Path:       path, // buildutils:allow-slice-alias this assignment is ephemeral
			Commitment: []byte{},
			IsRoot:     len(path) == 0,
		}, nil
	}

	intpath := []int{}
	for _, p := range path {
		intpath = append(intpath, int(p))
	}

	node = ensureCommittedNode(logger, tree, intpath, node)

	branchInfo := &protobufs.HypergraphComparisonResponse{
		Path:   path, // buildutils:allow-slice-alias this assignment is ephemeral
		IsRoot: len(path) == 0,
	}

	if branch, ok := node.(*tries.LazyVectorCommitmentBranchNode); ok {
		branchInfo.Commitment = branch.Commitment
		if len(branch.Commitment) == 0 {
			return nil, errors.New("invalid commitment")
		}

		for _, p := range branch.Prefix {
			branchInfo.Path = append(branchInfo.Path, int32(p))
		}
		for i := 0; i < len(branch.Children); i++ {
			child := branch.Children[i]
			if child == nil {
				var err error
				child, err = branch.Store.GetNodeByPath(
					tree.SetType,
					tree.PhaseType,
					tree.ShardKey,
					slices.Concat(branch.FullPrefix, []int{i}),
				)
				if err != nil && !strings.Contains(err.Error(), "item not found") {
					return nil, err
				}
			}

			childPath := slices.Concat(branch.FullPrefix, []int{i})
			child = ensureCommittedNode(logger, tree, childPath, child)

			if child != nil {
				var childCommit []byte
				if childB, ok := child.(*tries.LazyVectorCommitmentBranchNode); ok {
					childCommit = childB.Commitment
				} else if childL, ok := child.(*tries.LazyVectorCommitmentLeafNode); ok {
					childCommit = childL.Commitment
				}

				if len(childCommit) == 0 {
					return nil, errors.New("invalid commitment")
				}
				branchInfo.Children = append(
					branchInfo.Children,
					&protobufs.BranchChild{
						Index:      int32(i),
						Commitment: childCommit,
					},
				)
			}
		}
	} else if leaf, ok := node.(*tries.LazyVectorCommitmentLeafNode); ok {
		branchInfo.Commitment = leaf.Commitment
		if len(branchInfo.Commitment) == 0 {
			return nil, errors.New("invalid commitment")
		}
	}
	return branchInfo, nil
}

func ensureCommittedNode(
	logger *zap.Logger,
	tree *tries.LazyVectorCommitmentTree,
	path []int,
	node tries.LazyVectorCommitmentNode,
) tries.LazyVectorCommitmentNode {
	if node == nil {
		return nil
	}

	hasCommit := func(commitment []byte) bool {
		return len(commitment) != 0
	}

	switch n := node.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		if hasCommit(n.Commitment) {
			return node
		}
	case *tries.LazyVectorCommitmentLeafNode:
		if hasCommit(n.Commitment) {
			return node
		}
	default:
		return node
	}

	reloaded, err := tree.Store.GetNodeByPath(
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		path,
	)
	if err != nil && !strings.Contains(err.Error(), "item not found") {
		return nil
	}
	if reloaded != nil {
		return reloaded
	}

	return node
}

// isLeaf infers whether a HypergraphComparisonResponse message represents a
// leaf node.
func isLeaf(info *protobufs.HypergraphComparisonResponse) bool {
	return len(info.Children) == 0
}

func (s *streamManager) queryNext(
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	path []int32,
) (
	resp *protobufs.HypergraphComparisonResponse,
	err error,
) {
	start := time.Now()
	pathHex := hex.EncodeToString(packPath(path))
	s.logger.Debug("query next start", zap.String("path", pathHex))
	defer func() {
		s.logger.Debug(
			"query next finished",
			zap.String("path", pathHex),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
	}()
	if err := s.stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				Path:            path, // buildutils:allow-slice-alias this assignment is ephemeral
				IncludeLeafData: true,
			},
		},
	}); err != nil {
		return nil, err
	}

	s.updateActivity()

	select {
	case <-s.ctx.Done():
		return nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query",
		)
	case r, ok := <-incomingResponses:
		if !ok {
			return nil, errors.Wrap(
				errors.New("channel closed"),
				"handle query",
			)
		}
		s.updateActivity()
		resp = r
		return resp, nil
	case <-time.After(syncOperationTimeout):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query",
		)
	}
}

func (s *streamManager) handleLeafData(
	incomingLeaves <-chan *protobufs.HypergraphComparison,
) (err error) {
	start := time.Now()
	var expectedLeaves uint64
	s.logger.Debug("handle leaf data start")
	defer func() {
		s.logger.Debug(
			"handle leaf data finished",
			zap.Uint64("leaves_expected", expectedLeaves),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
	}()
	select {
	case <-s.ctx.Done():
		return errors.Wrap(
			errors.New("context canceled"),
			"handle leaf data",
		)
	case msg, ok := <-incomingLeaves:
		if !ok {
			return errors.Wrap(
				errors.New("channel closed"),
				"handle leaf data",
			)
		}

		switch msg.Payload.(type) {
		case *protobufs.HypergraphComparison_LeafData:
			return errors.Wrap(
				errors.New("invalid message"),
				"handle leaf data",
			)
		case *protobufs.HypergraphComparison_Metadata:
			expectedLeaves = msg.GetMetadata().Leaves
		}
	case <-time.After(syncOperationTimeout):
		return errors.Wrap(
			errors.New("timed out"),
			"handle leaf data",
		)
	}

	// s.logger.Info("expecting leaves", zap.Uint64("count", expectedLeaves))

	var txn tries.TreeBackingStoreTransaction
	for i := uint64(0); i < expectedLeaves; i++ {
		if i%100 == 0 {
			if txn != nil {
				if err := txn.Commit(); err != nil {
					return errors.Wrap(
						err,
						"handle leaf data",
					)
				}
			}
			txn, err = s.hypergraphStore.NewTransaction(false)
			if err != nil {
				return errors.Wrap(
					err,
					"handle leaf data",
				)
			}
		}
		select {
		case <-s.ctx.Done():
			return errors.Wrap(
				errors.New("context canceled"),
				"handle leaf data",
			)
		case msg, ok := <-incomingLeaves:
			if !ok {
				return errors.Wrap(
					errors.New("channel closed"),
					"handle leaf data",
				)
			}

			var remoteUpdate *protobufs.LeafData
			switch msg.Payload.(type) {
			case *protobufs.HypergraphComparison_Metadata:
				return errors.Wrap(
					errors.New("invalid message"),
					"handle leaf data",
				)
			case *protobufs.HypergraphComparison_LeafData:
				remoteUpdate = msg.GetLeafData()
			}

			// s.logger.Info(
			// 	"received leaf data",
			// 	zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
			// )

			theirs := AtomFromBytes(remoteUpdate.Value)
			if err := s.persistLeafTree(txn, remoteUpdate); err != nil {
				txn.Abort()
				return err
			}

			err := s.localSet.Add(txn, theirs)
			if err != nil {
				s.logger.Error("error while saving", zap.Error(err))
				return errors.Wrap(
					err,
					"handle leaf data",
				)
			}
		case <-time.After(syncOperationTimeout):
			return errors.Wrap(
				errors.New("timed out"),
				"handle leaf data",
			)
		}
	}

	if txn != nil {
		if err := txn.Commit(); err != nil {
			return errors.Wrap(
				err,
				"handle leaf data",
			)
		}
	}

	if err := s.stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Metadata{
			Metadata: &protobufs.HypersyncMetadata{Leaves: expectedLeaves},
		},
	}); err != nil {
		return err
	}

	return nil
}

func (s *streamManager) persistLeafTree(
	txn tries.TreeBackingStoreTransaction,
	update *protobufs.LeafData,
) error {
	if len(update.UnderlyingData) == 0 {
		return nil
	}

	tree, err := tries.DeserializeNonLazyTree(update.UnderlyingData)
	if err != nil {
		s.logger.Error("server returned invalid tree", zap.Error(err))
		return err
	}

	if s.requiresTreeValidation() {
		if err := s.localSet.ValidateTree(
			update.Key,
			update.Value,
			tree,
		); err != nil {
			s.logger.Error("server returned invalid tree", zap.Error(err))
			return err
		}
	}

	return s.hypergraphStore.SaveVertexTree(txn, update.Key, tree)
}

func (s *streamManager) requiresTreeValidation() bool {
	if typed, ok := s.localSet.(*idSet); ok {
		return typed.validator != nil
	}
	return false
}

func (s *streamManager) handleQueryNext(
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	path []int32,
) (
	branch *protobufs.HypergraphComparisonResponse,
	err error,
) {
	start := time.Now()
	pathHex := hex.EncodeToString(packPath(path))
	s.logger.Debug("handle query next start", zap.String("path", pathHex))
	defer func() {
		s.logger.Debug(
			"handle query next finished",
			zap.String("path", pathHex),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
	}()
	select {
	case <-s.ctx.Done():
		return nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query next",
		)
	case query, ok := <-incomingQueries:
		if !ok {
			return nil, errors.Wrap(
				errors.New("channel closed"),
				"handle query next",
			)
		}

		if slices.Compare(query.Path, path) != 0 {
			return nil, errors.Wrap(
				errors.New("invalid query received"),
				"handle query next",
			)
		}

		branchInfo, berr := s.getBranchInfo(path)
		if berr != nil {
			return nil, errors.Wrap(berr, "handle query next")
		}

		resp := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Response{
				Response: branchInfo,
			},
		}

		if err := s.stream.Send(resp); err != nil {
			return nil, errors.Wrap(err, "handle query next")
		}

		s.updateActivity()
		branch = branchInfo
		return branch, nil
	case <-time.After(syncOperationTimeout):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query next",
		)
	}
}

func (s *streamManager) descendIndex(
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	path []int32,
) (
	local *protobufs.HypergraphComparisonResponse,
	remote *protobufs.HypergraphComparisonResponse,
	err error,
) {
	start := time.Now()
	pathHex := hex.EncodeToString(packPath(path))
	s.logger.Debug("descend index start", zap.String("path", pathHex))
	defer func() {
		s.logger.Debug(
			"descend index finished",
			zap.String("path", pathHex),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err),
		)
	}()
	branchInfo, err := s.getBranchInfo(path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := s.stream.Send(resp); err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	s.updateActivity()

	select {
	case <-s.ctx.Done():
		return nil, nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query next",
		)
	case r, ok := <-incomingResponses:
		if !ok {
			return nil, nil, errors.Wrap(
				errors.New("channel closed"),
				"descend index",
			)
		}

		// Both sides independently extend the path based on their tree's branch
		// prefixes. We only need to verify that the server's response path starts
		// with the original query path - the extensions may differ.
		if len(r.Path) < len(path) || slices.Compare(r.Path[:len(path)], path) != 0 {
			return nil, nil, errors.Wrap(
				fmt.Errorf(
					"invalid path received: %v, expected prefix: %v",
					r.Path,
					path,
				),
				"descend index",
			)
		}

		s.updateActivity()
		local = branchInfo
		remote = r
		return local, remote, nil
	case <-time.After(syncOperationTimeout):
		return nil, nil, errors.Wrap(
			errors.New("timed out"),
			"descend index",
		)
	}
}

func packPath(path []int32) []byte {
	b := []byte{}
	for _, p := range path {
		b = append(b, byte(p))
	}
	return b
}

func (s *streamManager) walk(
	path []int32,
	lnode, rnode *protobufs.HypergraphComparisonResponse,
	incomingLeaves <-chan *protobufs.HypergraphComparison,
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	init bool,
	isServer bool,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}

	// pathString := zap.String("path", hex.EncodeToString(packPath(path)))

	if bytes.Equal(lnode.Commitment, rnode.Commitment) {
		// s.logger.Debug(
		// 	"commitments match",
		// 	pathString,
		// 	zap.String("commitment", hex.EncodeToString(lnode.Commitment)),
		// )
		return nil
	}

	if isLeaf(lnode) && isLeaf(rnode) && !init {
		// Both are leaves with differing commitments - need to sync
		// Server sends its leaf, client prunes local and receives server's leaf
		if isServer {
			err := s.sendLeafData(
				path,
				incomingLeaves,
			)
			return errors.Wrap(err, "walk")
		} else {
			// Merge remote data with local, pruning only what server doesn't have
			err := s.handleLeafData(incomingLeaves)
			return errors.Wrap(err, "walk")
		}
	}

	if isLeaf(rnode) || isLeaf(lnode) {
		// s.logger.Debug("leaf/branch mismatch at path", pathString)
		if isServer {
			err := s.sendLeafData(
				path,
				incomingLeaves,
			)
			return errors.Wrap(err, "walk")
		} else {
			// Merge remote data with local, pruning only what server doesn't have
			err := s.handleLeafData(incomingLeaves)
			return errors.Wrap(err, "walk")
		}
	}

	lpref := lnode.Path
	rpref := rnode.Path
	if len(lpref) != len(rpref) {
		// s.logger.Debug(
		// 	"prefix length mismatch",
		// 	zap.Int("local_prefix", len(lpref)),
		// 	zap.Int("remote_prefix", len(rpref)),
		// 	pathString,
		// )
		if len(lpref) > len(rpref) {
			// s.logger.Debug("local prefix longer, traversing remote to path", pathString)
			traverse := lpref[len(rpref):]
			rtrav := rnode
			traversePath := append([]int32{}, rpref...)
			for _, nibble := range traverse {
				// s.logger.Debug("attempting remote traversal step")
				preTraversal := append([]int32{}, traversePath...)
				found := false
				for _, child := range rtrav.Children {
					if child.Index == nibble {
						// s.logger.Debug("sending query")
						traversePath = append(traversePath, child.Index)
						var err error
						rtrav, err = s.queryNext(
							incomingResponses,
							traversePath,
						)
						if err != nil {
							s.logger.Error("query failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}
						found = true
					} else {
						// Remote has a child that's not on local's traversal path
						missingPath := append(append([]int32{}, preTraversal...), child.Index)
						if isServer {
							// Server has extra data - send it to client
							if err := s.sendLeafData(
								missingPath,
								incomingLeaves,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
						} else {
							err := s.handleLeafData(incomingLeaves)
							if err != nil {
								return errors.Wrap(err, "walk")
							}
						}
					}
				}

				// If no child matched or queryNext returned nil, remote doesn't
				// have the path that local has
				if !found || rtrav == nil {
					// s.logger.Debug("traversal could not reach path")
					if isServer {
						err := s.sendLeafData(
							lpref,
							incomingLeaves,
						)
						return errors.Wrap(err, "walk")
					} else {
						err := s.handleLeafData(incomingLeaves)
						return errors.Wrap(err, "walk")
					}
				}
			}
			// s.logger.Debug("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				lnode,
				rtrav,
				incomingLeaves,
				incomingQueries,
				incomingResponses,
				false,
				isServer,
				shardKey,
				phaseSet,
			)
		} else {
			// s.logger.Debug("remote prefix longer, traversing local to path", pathString)
			traverse := rpref[len(lpref):]
			ltrav := lnode
			traversedPath := append([]int32{}, lnode.Path...)

			for _, nibble := range traverse {
				// s.logger.Debug("attempting local traversal step")
				preTraversal := append([]int32{}, traversedPath...)
				found := false
				for _, child := range ltrav.Children {
					if child.Index == nibble {
						traversedPath = append(traversedPath, nibble)
						var err error
						// s.logger.Debug("expecting query")
						ltrav, err = s.handleQueryNext(
							incomingQueries,
							traversedPath,
						)
						if err != nil {
							s.logger.Error("expect failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}

						if ltrav == nil {
							// s.logger.Debug("traversal could not reach path")
							if isServer {
								err := s.sendLeafData(
									preTraversal,
									incomingLeaves,
								)
								return errors.Wrap(err, "walk")
							} else {
								// Merge server data with local at preTraversal path
								err := s.handleLeafData(incomingLeaves)
								return errors.Wrap(err, "walk")
							}
						}
						found = true
					} else {
						// Local has a child that's not on remote's traversal path
						missingPath := append(append([]int32{}, preTraversal...), child.Index)
						if isServer {
							// Server has extra data - send it to client
							if err := s.sendLeafData(
								missingPath,
								incomingLeaves,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
						} else {
							err := s.handleLeafData(incomingLeaves)
							if err != nil {
								return errors.Wrap(err, "walk")
							}
						}
					}
				}

				// If no child matched the nibble, local doesn't have the path
				// that remote expects - receive remote's data
				if !found {
					if isServer {
						err := s.sendLeafData(
							preTraversal,
							incomingLeaves,
						)
						return errors.Wrap(err, "walk")
					} else {
						err := s.handleLeafData(incomingLeaves)
						return errors.Wrap(err, "walk")
					}
				}
			}
			// s.logger.Debug("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				ltrav,
				rnode,
				incomingLeaves,
				incomingQueries,
				incomingResponses,
				false,
				isServer,
				shardKey,
				phaseSet,
			)
		}
	} else {
		if slices.Compare(lpref, rpref) == 0 {
			// s.logger.Debug("prefixes match, diffing children")
			for i := int32(0); i < 64; i++ {
				// s.logger.Debug("checking branch", zap.Int32("branch", i))
				var lchild *protobufs.BranchChild = nil
				for _, lc := range lnode.Children {
					if lc.Index == i {
						// s.logger.Debug("local instance found", zap.Int32("branch", i))

						lchild = lc
						break
					}
				}
				var rchild *protobufs.BranchChild = nil
				for _, rc := range rnode.Children {
					if rc.Index == i {
						// s.logger.Debug("remote instance found", zap.Int32("branch", i))

						rchild = rc
						break
					}
				}
				if (lchild != nil && rchild == nil) ||
					(lchild == nil && rchild != nil) {
					// s.logger.Info("branch divergence", pathString)
					if lchild != nil {
						// Local has a child that remote doesn't have
						if isServer {
							nextPath := append(
								append([]int32{}, lpref...),
								lchild.Index,
							)
							// Server has data client doesn't - send it
							if err := s.sendLeafData(
								nextPath,
								incomingLeaves,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
						}
						// Client has data server doesn't
						// Skip - pruning happens after sync completes
					}
					if rchild != nil {
						if !isServer {
							err := s.handleLeafData(incomingLeaves)
							if err != nil {
								return errors.Wrap(err, "walk")
							}
						}
					}
				} else {
					if lchild != nil {
						nextPath := append(
							append([]int32{}, lpref...),
							lchild.Index,
						)
						lc, rc, err := s.descendIndex(
							incomingResponses,
							nextPath,
						)
						if err != nil {
							// If this is a timeout or context error, abort the sync entirely
							// rather than trying to continue with leaf data exchange
							if isTimeoutError(err) {
								s.logger.Warn(
									"branch descension timeout - aborting sync",
									zap.Error(err),
									zap.String("path", hex.EncodeToString(packPath(nextPath))),
								)
								return errors.Wrap(err, "walk: branch descension timeout")
							}
							s.logger.Info("incomplete branch descension", zap.Error(err))
							if isServer {
								if err := s.sendLeafData(
									nextPath,
									incomingLeaves,
								); err != nil {
									return errors.Wrap(err, "walk")
								}
							} else {
								err := s.handleLeafData(incomingLeaves)
								if err != nil {
									return errors.Wrap(err, "walk")
								}
							}
							continue
						}

						if err = s.walk(
							nextPath,
							lc,
							rc,
							incomingLeaves,
							incomingQueries,
							incomingResponses,
							false,
							isServer,
							shardKey,
							phaseSet,
						); err != nil {
							return errors.Wrap(err, "walk")
						}
					}
				}
			}
		} else {
			// s.logger.Debug("prefix mismatch on both sides", pathString)
			if isServer {
				if err := s.sendLeafData(
					path,
					incomingLeaves,
				); err != nil {
					return errors.Wrap(err, "walk")
				}
			} else {
				// Merge server data with local, pruning only what server doesn't have
				err := s.handleLeafData(incomingLeaves)
				if err != nil {
					return errors.Wrap(err, "walk")
				}
			}
		}
	}

	return nil
}

// syncTreeServer implements the diff and sync logic on the
// server side. It sends the local root info, then processes incoming messages,
// and queues further queries as differences are detected.
func (hg *HypergraphCRDT) syncTreeServer(
	ctx context.Context,
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
	sessionLogger *zap.Logger,
) error {
	logger := sessionLogger
	if logger == nil {
		logger = hg.logger
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	query := msg.GetQuery()
	if query == nil {
		return errors.New("client did not send valid initialization message")
	}

	logger.Info("received initialization message")

	if len(query.ShardKey) != 35 {
		return errors.New("invalid shard key")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(query.ShardKey[:3]),
		L2: [32]byte(query.ShardKey[3:]),
	}

	snapshotStart := time.Now()
	handle := hg.snapshotMgr.acquire(shardKey, query.ExpectedRoot)
	if handle == nil {
		return errors.New("hypergraph shard snapshot unavailable")
	}
	defer hg.snapshotMgr.release(handle)
	logger.Debug(
		"snapshot acquisition complete",
		zap.Duration("duration", time.Since(snapshotStart)),
	)

	snapshotRoot := handle.Root()
	if len(snapshotRoot) != 0 {
		logger.Info(
			"syncing with snapshot",
			zap.String("root", hex.EncodeToString(snapshotRoot)),
		)
	} else {
		logger.Info("syncing with snapshot", zap.String("root", ""))
	}

	snapshotStore := handle.Store()

	idSet := hg.snapshotPhaseSet(shardKey, query.PhaseSet, snapshotStore)
	if idSet == nil {
		return errors.New("unsupported phase set")
	}

	branchInfo, err := getBranchInfoFromTree(
		logger,
		idSet.GetTree(),
		query.Path,
	)
	if err != nil {
		return err
	}

	// hg.logger.Debug(
	// 	"returning branch info",
	// 	zap.String("commitment", hex.EncodeToString(branchInfo.Commitment)),
	// 	zap.Int("children", len(branchInfo.Children)),
	// 	zap.Int("path", len(branchInfo.Path)),
	// )

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	msg, err = stream.Recv()
	if err != nil {
		return err
	}
	response := msg.GetResponse()
	if response == nil {
		return errors.New(
			"client did not send valid initialization response message",
		)
	}

	ctx, cancel := context.WithCancel(ctx)

	incomingQueriesIn, incomingQueriesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonQuery](
			cancel,
			"server incoming",
		)
	incomingResponsesIn, incomingResponsesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonResponse](
			cancel,
			"server incoming",
		)
	incomingLeavesIn, incomingLeavesOut :=
		UnboundedChan[*protobufs.HypergraphComparison](
			cancel,
			"server incoming",
		)

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				logger.Info("server stream recv eof")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				logger.Info("server stream recv error", zap.Error(err))
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if msg == nil {
				continue
			}
			switch m := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_LeafData:
				logger.Warn("received leaf from client, terminating")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			case *protobufs.HypergraphComparison_Metadata:
				incomingLeavesIn <- msg
			case *protobufs.HypergraphComparison_Query:
				incomingQueriesIn <- m.Query
			case *protobufs.HypergraphComparison_Response:
				incomingResponsesIn <- m.Response
			}
		}
	}()

	manager := &streamManager{
		ctx:             ctx,
		cancel:          cancel,
		logger:          logger,
		stream:          stream,
		hypergraphStore: snapshotStore,
		localTree:       idSet.GetTree(),
		localSet:        idSet,
		lastSent:        time.Now(),
		snapshot:        handle,
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := manager.walk(
			branchInfo.Path,
			branchInfo,
			response,
			incomingLeavesOut,
			incomingQueriesOut,
			incomingResponsesOut,
			true,
			true,
			shardKey,
			query.PhaseSet,
		)
		if err != nil {
			logger.Error("error while syncing", zap.Error(err))
		}
	}()

	wg.Wait()

	return nil
}

func UnboundedChan[T any](
	cancel context.CancelFunc,
	purpose string,
) (chan<- T, <-chan T) {
	in := make(chan T)
	out := make(chan T)
	go func() {
		var queue []T
		for {
			var active chan T
			var next T
			if len(queue) > 0 {
				active = out
				next = queue[0]
			}
			select {
			case msg, ok := <-in:
				if !ok {
					cancel()
					close(out)
					return
				}

				queue = append(queue, msg)
			case active <- next:
				queue = queue[1:]
			}
		}
	}()
	return in, out
}

func peerIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
