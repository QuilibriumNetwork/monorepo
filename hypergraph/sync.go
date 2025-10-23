package hypergraph

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// HyperStream is the gRPC method that handles synchronization.
func (hg *HypergraphCRDT) HyperStream(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	if !hg.syncController.TryEstablishSyncSession() {
		return errors.New("unavailable")
	}

	hg.mu.RLock()
	defer hg.mu.RUnlock()
	defer hg.syncController.EndSyncSession()

	peerId, err := hg.authenticationProvider.Identify(stream.Context())
	if err != nil {
		return errors.Wrap(err, "hyper stream")
	}

	status, ok := hg.syncController.SyncStatus[peerId.String()]
	if ok && time.Since(status.LastSynced) < 10*time.Second {
		return errors.New("peer too recently synced")
	}

	err = hg.syncTreeServer(stream)

	hg.syncController.SyncStatus[peerId.String()] = &hypergraph.SyncInfo{
		Unreachable: false,
		LastSynced:  time.Now(),
	}

	return err
}

// Sync performs the tree diff and synchronization from the client side.
// The caller (e.g. the client) must initiate the diff from its root.
// After that, both sides exchange queries, branch info, and leaf updates until
// their local trees are synchronized.
func (hg *HypergraphCRDT) Sync(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
) error {
	if !hg.syncController.TryEstablishSyncSession() {
		return errors.New("unavailable")
	}

	hg.mu.RLock()
	defer hg.mu.RUnlock()
	defer hg.syncController.EndSyncSession()

	hg.logger.Info(
		"sending initialization message",
		zap.String(
			"shard_key",
			hex.EncodeToString(slices.Concat(shardKey.L1[:], shardKey.L2[:])),
		),
		zap.Int("phase_set", int(phaseSet)),
	)

	// Get the appropriate id set
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
	}

	path := hg.coveredPrefix

	// Send initial query for path
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				ShardKey:        slices.Concat(shardKey.L1[:], shardKey.L2[:]),
				PhaseSet:        phaseSet,
				Path:            toInt32Slice(path),
				Commitment:      set.GetTree().Commit(false),
				IncludeLeafData: false,
			},
		},
	}); err != nil {
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	response := msg.GetResponse()
	if response == nil {
		return errors.New(
			"server did not send valid initialization response message",
		)
	}

	branchInfo, err := getBranchInfoFromTree(
		hg.logger,
		set.GetTree(),
		toInt32Slice(path),
	)
	if err != nil {
		return err
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

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
				hg.logger.Debug("stream closed by sender")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				hg.logger.Debug("error from stream", zap.Error(err))
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

	wg := sync.WaitGroup{}
	wg.Add(1)

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
		)
		if err != nil {
			hg.logger.Error("error while syncing", zap.Error(err))
		}
	}()

	wg.Wait()

	hg.logger.Info(
		"hypergraph root commit",
		zap.String("root", hex.EncodeToString(set.GetTree().Commit(false))),
	)

	return nil
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
				panic(err)
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
}

// sendLeafData builds a LeafData message (with the full leaf data) for the
// node at the given path in the local tree and sends it over the stream.
func (s *streamManager) sendLeafData(
	path []int32,
	incomingLeaves <-chan *protobufs.HypergraphComparison,
) error {
	send := func(leaf *tries.LazyVectorCommitmentLeafNode) error {
		update := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}
		tree, err := s.hypergraphStore.LoadVertexTree(leaf.Key)
		if err == nil {
			b, err := tries.SerializeNonLazyTree(tree)
			if err != nil {
				return errors.Wrap(err, "send leaf data")
			}
			update.UnderlyingData = b
		}
		msg := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_LeafData{
				LeafData: update,
			},
		}

		s.logger.Info(
			"sending leaf data",
			zap.String("key", hex.EncodeToString(leaf.Key)),
		)

		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		err = s.stream.Send(msg)
		if err != nil {
			return errors.Wrap(err, "send leaf data")
		}

		s.lastSent = time.Now()
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
		return nil
	}

	if node == nil {
		s.logger.Info("no node, sending 0 leaves")
		if err := s.stream.Send(&protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Metadata{
				Metadata: &protobufs.HypersyncMetadata{Leaves: 0},
			},
		}); err != nil {
			return err
		}
		return nil
	}

	leaf, ok := node.(*tries.LazyVectorCommitmentLeafNode)
	count := uint64(0)
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
		s.logger.Info("sending set of leaves", zap.Uint64("leaf_count", count))
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
		s.logger.Info("sending one leaf", zap.Uint64("leaf_count", count))
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
	case <-time.After(30 * time.Second):
		return errors.Wrap(
			errors.New("timed out"),
			"send leaf data",
		)
	}
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
			logger.Panic("failed to get node by path", zap.Error(err))
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
			Path:       path,
			Commitment: []byte{},
			IsRoot:     len(path) == 0,
		}, nil
	}

	intpath := []int{}
	for _, p := range path {
		intpath = append(intpath, int(p))
	}
	commitment := node.Commit(
		tree.InclusionProver,
		nil,
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		intpath,
		false,
	)
	branchInfo := &protobufs.HypergraphComparisonResponse{
		Path:       path,
		Commitment: commitment,
		IsRoot:     len(path) == 0,
	}

	if branch, ok := node.(*tries.LazyVectorCommitmentBranchNode); ok {
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
					logger.Panic("failed to get node by path", zap.Error(err))
				}
			}
			if child != nil {
				childCommit := child.Commit(
					tree.InclusionProver,
					nil,
					tree.SetType,
					tree.PhaseType,
					tree.ShardKey,
					slices.Concat(branch.FullPrefix, []int{i}),
					false,
				)
				branchInfo.Children = append(
					branchInfo.Children,
					&protobufs.BranchChild{
						Index:      int32(i),
						Commitment: childCommit,
					},
				)
			}
		}
	}
	return branchInfo, nil
}

// isLeaf infers whether a HypergraphComparisonResponse message represents a
// leaf node.
func isLeaf(info *protobufs.HypergraphComparisonResponse) bool {
	return len(info.Children) == 0
}

func queryNext(
	ctx context.Context,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream hypergraph.HyperStream,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				Path:            path,
				IncludeLeafData: true,
			},
		},
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query",
		)
	case resp, ok := <-incomingResponses:
		if !ok {
			return nil, errors.Wrap(
				errors.New("channel closed"),
				"handle query",
			)
		}
		return resp, nil
	case <-time.After(30 * time.Second):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query",
		)
	}
}

func (s *streamManager) handleLeafData(
	ctx context.Context,
	incomingLeaves <-chan *protobufs.HypergraphComparison,
) error {
	expectedLeaves := uint64(0)
	select {
	case <-ctx.Done():
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
	case <-time.After(30 * time.Second):
		return errors.Wrap(
			errors.New("timed out"),
			"handle leaf data",
		)
	}

	s.logger.Info("expecting leaves", zap.Uint64("count", expectedLeaves))

	var txn tries.TreeBackingStoreTransaction
	var err error
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
		case <-ctx.Done():
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

			s.logger.Info(
				"received leaf data",
				zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
			)

			theirs := AtomFromBytes(remoteUpdate.Value)
			if len(remoteUpdate.UnderlyingData) != 0 {
				tree, err := tries.DeserializeNonLazyTree(remoteUpdate.UnderlyingData)
				if err != nil {
					s.logger.Error("server returned invalid tree", zap.Error(err))
					txn.Abort()
					return err
				}

				err = s.localSet.ValidateTree(
					remoteUpdate.Key,
					remoteUpdate.Value,
					tree,
				)
				if err != nil {
					s.logger.Error("server returned invalid tree", zap.Error(err))
					txn.Abort()
					return err
				}

				err = s.hypergraphStore.SaveVertexTree(txn, remoteUpdate.Key, tree)
				if err != nil {
					txn.Abort()
					return err
				}
			}

			err := s.localSet.Add(txn, theirs)
			if err != nil {
				s.logger.Error("error while saving", zap.Error(err))
				return errors.Wrap(
					err,
					"handle leaf data",
				)
			}
		case <-time.After(30 * time.Second):
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

func handleQueryNext(
	logger *zap.Logger,
	ctx context.Context,
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	stream hypergraph.HyperStream,
	localTree *tries.LazyVectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	select {
	case <-ctx.Done():
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

		branchInfo, err := getBranchInfoFromTree(logger, localTree, path)
		if err != nil {
			return nil, errors.Wrap(err, "handle query next")
		}

		resp := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Response{
				Response: branchInfo,
			},
		}

		if err := stream.Send(resp); err != nil {
			return nil, errors.Wrap(err, "handle query next")
		}

		return branchInfo, nil
	case <-time.After(30 * time.Second):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query next",
		)
	}
}

func descendIndex(
	logger *zap.Logger,
	ctx context.Context,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream hypergraph.HyperStream,
	localTree *tries.LazyVectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	branchInfo, err := getBranchInfoFromTree(logger, localTree, path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	select {
	case <-ctx.Done():
		return nil, nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query next",
		)
	case resp, ok := <-incomingResponses:
		if !ok {
			return nil, nil, errors.Wrap(
				errors.New("channel closed"),
				"descend index",
			)
		}

		if slices.Compare(branchInfo.Path, resp.Path) != 0 {
			return nil, nil, errors.Wrap(
				fmt.Errorf(
					"invalid path received: %v, expected: %v",
					resp.Path,
					branchInfo.Path,
				),
				"descend index",
			)
		}

		return branchInfo, resp, nil
	case <-time.After(30 * time.Second):
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
) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	default:
	}

	pathString := zap.String("path", hex.EncodeToString(packPath(path)))

	if bytes.Equal(lnode.Commitment, rnode.Commitment) {
		s.logger.Info(
			"commitments match",
			pathString,
			zap.String("commitment", hex.EncodeToString(lnode.Commitment)),
		)
		return nil
	}

	if isLeaf(lnode) && isLeaf(rnode) && !init {
		return nil
	}

	if isLeaf(rnode) || isLeaf(lnode) {
		s.logger.Info("leaf/branch mismatch at path", pathString)
		if isServer {
			err := s.sendLeafData(
				path,
				incomingLeaves,
			)
			return errors.Wrap(err, "walk")
		} else {
			err := s.handleLeafData(s.ctx, incomingLeaves)
			return errors.Wrap(err, "walk")
		}
	}

	lpref := lnode.Path
	rpref := rnode.Path
	if len(lpref) != len(rpref) {
		s.logger.Info(
			"prefix length mismatch",
			zap.Int("local_prefix", len(lpref)),
			zap.Int("remote_prefix", len(rpref)),
			pathString,
		)
		if len(lpref) > len(rpref) {
			s.logger.Info("local prefix longer, traversing remote to path", pathString)
			traverse := lpref[len(rpref)-1:]
			rtrav := rnode
			traversePath := append([]int32{}, rpref...)
			for _, nibble := range traverse {
				s.logger.Info("attempting remote traversal step")
				for _, child := range rtrav.Children {
					if child.Index == nibble {
						s.logger.Info("sending query")
						traversePath = append(traversePath, child.Index)
						var err error
						rtrav, err = queryNext(
							s.ctx,
							incomingResponses,
							s.stream,
							traversePath,
						)
						if err != nil {
							s.logger.Error("query failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}

						break
					}
				}

				if rtrav == nil {
					s.logger.Info("traversal could not reach path")
					if isServer {
						err := s.sendLeafData(
							lpref,
							incomingLeaves,
						)
						return errors.Wrap(err, "walk")
					} else {
						err := s.handleLeafData(s.ctx, incomingLeaves)
						return errors.Wrap(err, "walk")
					}
				}
			}
			s.logger.Info("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				lnode,
				rtrav,
				incomingLeaves,
				incomingQueries,
				incomingResponses,
				false,
				isServer,
			)
		} else {
			s.logger.Info("remote prefix longer, traversing local to path", pathString)
			traverse := rpref[len(lpref)-1:]
			ltrav := lnode
			traversedPath := append([]int32{}, lnode.Path...)

			for _, nibble := range traverse {
				s.logger.Info("attempting local traversal step")
				preTraversal := append([]int32{}, traversedPath...)
				for _, child := range ltrav.Children {
					if child.Index == nibble {
						traversedPath = append(traversedPath, nibble)
						var err error
						s.logger.Info("expecting query")
						ltrav, err = handleQueryNext(
							s.logger,
							s.ctx,
							incomingQueries,
							s.stream,
							s.localTree,
							traversedPath,
						)
						if err != nil {
							s.logger.Error("expect failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}

						if ltrav == nil {
							s.logger.Info("traversal could not reach path")
							if isServer {
								err := s.sendLeafData(
									preTraversal,
									incomingLeaves,
								)
								return errors.Wrap(err, "walk")
							} else {
								err := s.handleLeafData(s.ctx, incomingLeaves)
								return errors.Wrap(err, "walk")
							}
						}
					} else {
						s.logger.Info(
							"known missing branch",
							zap.String(
								"path",
								hex.EncodeToString(
									packPath(
										append(append([]int32{}, preTraversal...), child.Index),
									),
								),
							),
						)
						if isServer {
							if err := s.sendLeafData(
								append(append([]int32{}, preTraversal...), child.Index),
								incomingLeaves,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
						} else {
							err := s.handleLeafData(s.ctx, incomingLeaves)
							if err != nil {
								return errors.Wrap(err, "walk")
							}
						}
					}
				}
			}
			s.logger.Info("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				ltrav,
				rnode,
				incomingLeaves,
				incomingQueries,
				incomingResponses,
				false,
				isServer,
			)
		}
	} else {
		if slices.Compare(lpref, rpref) == 0 {
			s.logger.Debug("prefixes match, diffing children")
			for i := int32(0); i < 64; i++ {
				s.logger.Debug("checking branch", zap.Int32("branch", i))
				var lchild *protobufs.BranchChild = nil
				for _, lc := range lnode.Children {
					if lc.Index == i {
						s.logger.Debug("local instance found", zap.Int32("branch", i))

						lchild = lc
						break
					}
				}
				var rchild *protobufs.BranchChild = nil
				for _, rc := range rnode.Children {
					if rc.Index == i {
						s.logger.Debug("remote instance found", zap.Int32("branch", i))

						rchild = rc
						break
					}
				}
				if (lchild != nil && rchild == nil) ||
					(lchild == nil && rchild != nil) {
					s.logger.Info("branch divergence", pathString)
					if lchild != nil {
						nextPath := append(
							append([]int32{}, lpref...),
							lchild.Index,
						)
						if isServer {
							if err := s.sendLeafData(
								nextPath,
								incomingLeaves,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
						}
					}
					if rchild != nil {
						if !isServer {
							err := s.handleLeafData(s.ctx, incomingLeaves)
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
						lc, rc, err := descendIndex(
							s.logger,
							s.ctx,
							incomingResponses,
							s.stream,
							s.localTree,
							nextPath,
						)
						if err != nil {
							s.logger.Info("incomplete branch descension", zap.Error(err))
							if isServer {
								if err := s.sendLeafData(
									nextPath,
									incomingLeaves,
								); err != nil {
									return errors.Wrap(err, "walk")
								}
							} else {
								err := s.handleLeafData(s.ctx, incomingLeaves)
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
						); err != nil {
							return errors.Wrap(err, "walk")
						}
					}
				}
			}
		} else {
			s.logger.Info("prefix mismatch on both sides", pathString)
			if isServer {
				if err := s.sendLeafData(
					path,
					incomingLeaves,
				); err != nil {
					return errors.Wrap(err, "walk")
				}
			} else {
				err := s.handleLeafData(s.ctx, incomingLeaves)
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
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	query := msg.GetQuery()
	if query == nil {
		return errors.New("client did not send valid initialization message")
	}

	hg.logger.Info("received initialization message")

	if len(query.ShardKey) != 35 {
		return errors.New("invalid shard key")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(query.ShardKey[:3]),
		L2: [32]byte(query.ShardKey[3:]),
	}

	// Get the appropriate id set
	var idSet hypergraph.IdSet
	switch query.PhaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		idSet = hg.getVertexAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		idSet = hg.getVertexRemovesSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		idSet = hg.getHyperedgeAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		idSet = hg.getHyperedgeRemovesSet(shardKey)
	}

	branchInfo, err := getBranchInfoFromTree(
		hg.logger,
		idSet.GetTree(),
		query.Path,
	)
	if err != nil {
		return err
	}

	hg.logger.Debug(
		"returning branch info",
		zap.String("commitment", hex.EncodeToString(branchInfo.Commitment)),
		zap.Int("children", len(branchInfo.Children)),
		zap.Int("path", len(branchInfo.Path)),
	)

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

	ctx, cancel := context.WithCancel(stream.Context())

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
				hg.logger.Info("received disconnect")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				return
			}
			if err != nil {
				hg.logger.Info("received error", zap.Error(err))
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				return
			}
			if msg == nil {
				continue
			}
			switch m := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_LeafData:
				hg.logger.Warn("received leaf from client, terminating")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
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

	wg := sync.WaitGroup{}
	wg.Add(1)

	manager := &streamManager{
		ctx:             ctx,
		cancel:          cancel,
		logger:          hg.logger,
		stream:          stream,
		hypergraphStore: hg.store,
		localTree:       idSet.GetTree(),
		lastSent:        time.Now(),
	}
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
		)
		if err != nil {
			hg.logger.Error("error while syncing", zap.Error(err))
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
