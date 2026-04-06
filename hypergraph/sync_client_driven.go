package hypergraph

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// syncSession holds the state for a PerformSync session.
type syncSession struct {
	shardKey tries.ShardKey
	phaseSet protobufs.HypergraphPhaseSet
	snapshot *snapshotHandle
	idSet    hypergraph.IdSet
	store    tries.TreeBackingStore
}

// isGlobalProverShard returns true if this is the global prover registry shard
// (L1={0,0,0}, L2=0xff*32). Used to enable detailed logging for prover sync
// without adding noise from other shard syncs.
func isGlobalProverShard(shardKey tries.ShardKey) bool {
	if shardKey.L1 != [3]byte{0, 0, 0} {
		return false
	}
	for _, b := range shardKey.L2 {
		if b != 0xff {
			return false
		}
	}
	return true
}

// isGlobalProverShardBytes checks the same for concatenated byte slice (35 bytes).
func isGlobalProverShardBytes(shardKeyBytes []byte) bool {
	if len(shardKeyBytes) != 35 {
		return false
	}
	for i := 0; i < 3; i++ {
		if shardKeyBytes[i] != 0x00 {
			return false
		}
	}
	for i := 3; i < 35; i++ {
		if shardKeyBytes[i] != 0xff {
			return false
		}
	}
	return true
}


// PerformSync implements the server side of the client-driven sync protocol.
// The client sends GetBranch and GetLeaves requests, and the server responds
// with the requested data. This is simpler than HyperStream because there's
// no need for both sides to walk in lockstep.
//
// The server uses a snapshot to ensure consistent reads throughout the session.
func (hg *HypergraphCRDT) PerformSync(
	stream protobufs.HypergraphComparisonService_PerformSyncServer,
) error {
	ctx, shutdownCancel := hg.contextWithShutdown(stream.Context())
	defer shutdownCancel()

	logger := hg.logger.With(zap.String("method", "PerformSync"))
	sessionStart := time.Now()

	// Session state - initialized on first request
	var session *syncSession
	defer func() {
		if session != nil {
			logger.Info("sync session closed",
				zap.Duration("duration", time.Since(sessionStart)),
			)
			if session.snapshot != nil {
				hg.snapshotMgr.release(session.snapshot)
			}
		}
	}()

	// Process requests until stream closes
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "receive request")
		}

		var resp *protobufs.HypergraphSyncResponse

		switch r := req.Request.(type) {
		case *protobufs.HypergraphSyncQuery_GetBranch:
			// Initialize session on first request
			if session == nil {
				session, err = hg.initSyncSession(
					r.GetBranch.ShardKey,
					r.GetBranch.PhaseSet,
					r.GetBranch.ExpectedRoot,
					logger,
				)
				if err != nil {
					return errors.Wrap(err, "init sync session")
				}
			}
			resp, err = hg.handleGetBranch(ctx, r.GetBranch, session, logger)
		case *protobufs.HypergraphSyncQuery_GetLeaves:
			// Initialize session on first request
			if session == nil {
				session, err = hg.initSyncSession(
					r.GetLeaves.ShardKey,
					r.GetLeaves.PhaseSet,
					r.GetLeaves.ExpectedRoot,
					logger,
				)
				if err != nil {
					return errors.Wrap(err, "init sync session")
				}
			}
			resp, err = hg.handleGetLeaves(ctx, r.GetLeaves, session, logger)
		default:
			resp = &protobufs.HypergraphSyncResponse{
				Response: &protobufs.HypergraphSyncResponse_Error{
					Error: &protobufs.HypergraphSyncError{
						Code:    protobufs.HypergraphSyncErrorCode_HYPERGRAPH_SYNC_ERROR_UNKNOWN,
						Message: "unknown request type",
					},
				},
			}
		}

		if err != nil {
			logger.Error("error handling request", zap.Error(err))
			resp = &protobufs.HypergraphSyncResponse{
				Response: &protobufs.HypergraphSyncResponse_Error{
					Error: &protobufs.HypergraphSyncError{
						Code:    protobufs.HypergraphSyncErrorCode_HYPERGRAPH_SYNC_ERROR_INTERNAL,
						Message: err.Error(),
					},
				},
			}
		}

		if err := stream.Send(resp); err != nil {
			return errors.Wrap(err, "send response")
		}
	}
}

// initSyncSession initializes a sync session with a snapshot for consistent reads.
func (hg *HypergraphCRDT) initSyncSession(
	shardKeyBytes []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
	logger *zap.Logger,
) (*syncSession, error) {
	if len(shardKeyBytes) != 35 {
		return nil, errors.New("shard key must be 35 bytes")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(shardKeyBytes[:3]),
		L2: [32]byte(shardKeyBytes[3:]),
	}

	// Acquire a snapshot for consistent reads throughout the session.
	// If expectedRoot is provided, we try to find a snapshot matching that root.
	snapshot := hg.snapshotMgr.acquire(shardKey, expectedRoot)
	if snapshot == nil {
		return nil, errors.New("failed to acquire snapshot")
	}

	snapshotStore := snapshot.Store()
	idSet := hg.snapshotPhaseSet(shardKey, phaseSet, snapshotStore)
	if idSet == nil {
		hg.snapshotMgr.release(snapshot)
		return nil, errors.New("unsupported phase set")
	}

	logger.Info("sync session started",
		zap.String("shard", hex.EncodeToString(shardKeyBytes)),
		zap.String("phase", phaseSet.String()),
	)

	return &syncSession{
		shardKey: shardKey,
		phaseSet: phaseSet,
		snapshot: snapshot,
		idSet:    idSet,
		store:    snapshotStore,
	}, nil
}

func (hg *HypergraphCRDT) handleGetBranch(
	ctx context.Context,
	req *protobufs.HypergraphSyncGetBranchRequest,
	session *syncSession,
	logger *zap.Logger,
) (*protobufs.HypergraphSyncResponse, error) {
	tree := session.idSet.GetTree()
	if tree == nil || tree.Root == nil {
		return &protobufs.HypergraphSyncResponse{
			Response: &protobufs.HypergraphSyncResponse_Branch{
				Branch: &protobufs.HypergraphSyncBranchResponse{
					FullPath:   req.Path,
					Commitment: nil,
					Children:   nil,
					IsLeaf:     true,
					LeafCount:  0,
				},
			},
		}, nil
	}

	path := toIntSlice(req.Path)

	node := getNodeAtPath(
		logger,
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		tree.Root,
		toInt32Slice(path),
		0,
	)

	if node == nil {
		return &protobufs.HypergraphSyncResponse{
			Response: &protobufs.HypergraphSyncResponse_Error{
				Error: &protobufs.HypergraphSyncError{
					Code:    protobufs.HypergraphSyncErrorCode_HYPERGRAPH_SYNC_ERROR_NODE_NOT_FOUND,
					Message: "node not found at path",
					Path:    req.Path,
				},
			},
		}, nil
	}

	resp := &protobufs.HypergraphSyncBranchResponse{}

	// Ensure commitment is computed first
	node = ensureCommittedNode(logger, tree, path, node)

	switch n := node.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		resp.FullPath = toInt32Slice(n.FullPrefix)
		resp.Commitment = n.Commitment
		resp.IsLeaf = false
		resp.LeafCount = uint64(n.LeafCount)

		// Collect children
		for i := 0; i < 64; i++ {
			child := n.Children[i]
			if child == nil {
				var err error
				child, err = n.Store.GetNodeByPath(
					tree.SetType,
					tree.PhaseType,
					tree.ShardKey,
					slices.Concat(n.FullPrefix, []int{i}),
				)
				if err != nil && !strings.Contains(err.Error(), "item not found") {
					continue
				}
			}

			if child != nil {
				childPath := slices.Concat(n.FullPrefix, []int{i})
				child = ensureCommittedNode(logger, tree, childPath, child)

				var childCommit []byte
				switch c := child.(type) {
				case *tries.LazyVectorCommitmentBranchNode:
					childCommit = c.Commitment
				case *tries.LazyVectorCommitmentLeafNode:
					childCommit = c.Commitment
				}

				if len(childCommit) > 0 {
					resp.Children = append(resp.Children, &protobufs.HypergraphSyncChildInfo{
						Index:      int32(i),
						Commitment: childCommit,
					})
				}
			}
		}

	case *tries.LazyVectorCommitmentLeafNode:
		resp.FullPath = req.Path // Leaves don't have FullPrefix, use requested path
		resp.Commitment = n.Commitment
		resp.IsLeaf = true
		resp.LeafCount = 1
	}

	return &protobufs.HypergraphSyncResponse{
		Response: &protobufs.HypergraphSyncResponse_Branch{
			Branch: resp,
		},
	}, nil
}

func (hg *HypergraphCRDT) handleGetLeaves(
	ctx context.Context,
	req *protobufs.HypergraphSyncGetLeavesRequest,
	session *syncSession,
	logger *zap.Logger,
) (*protobufs.HypergraphSyncResponse, error) {
	tree := session.idSet.GetTree()
	if tree == nil || tree.Root == nil {
		return &protobufs.HypergraphSyncResponse{
			Response: &protobufs.HypergraphSyncResponse_Leaves{
				Leaves: &protobufs.HypergraphSyncLeavesResponse{
					Path:        req.Path,
					Leaves:      nil,
					TotalLeaves: 0,
				},
			},
		}, nil
	}

	path := toIntSlice(req.Path)

	node := getNodeAtPath(
		logger,
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		tree.Root,
		toInt32Slice(path),
		0,
	)

	if node == nil {
		return &protobufs.HypergraphSyncResponse{
			Response: &protobufs.HypergraphSyncResponse_Error{
				Error: &protobufs.HypergraphSyncError{
					Code:    protobufs.HypergraphSyncErrorCode_HYPERGRAPH_SYNC_ERROR_NODE_NOT_FOUND,
					Message: "node not found at path",
					Path:    req.Path,
				},
			},
		}, nil
	}

	// Get all leaves under this node
	allLeaves := tries.GetAllLeaves(
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		node,
	)

	// Apply pagination
	maxLeaves := int(req.MaxLeaves)
	if maxLeaves == 0 {
		maxLeaves = 1000 // Default batch size
	}

	startIdx := 0
	if len(req.ContinuationToken) > 0 {
		// Simple continuation: token is the start index as hex
		idx, err := parseContToken(req.ContinuationToken)
		if err == nil {
			startIdx = idx
		}
	}

	var leaves []*protobufs.LeafData
	var totalNonNil uint64

	for i, leaf := range allLeaves {
		if leaf == nil {
			continue
		}
		totalNonNil++

		if int(totalNonNil) <= startIdx {
			continue
		}

		if len(leaves) >= maxLeaves {
			break
		}

		leafData := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}

		vtree, err := session.store.LoadVertexTree(leaf.Key)
		if err == nil && vtree != nil {
			data, err := tries.SerializeNonLazyTree(vtree)
			if err == nil {
				leafData.UnderlyingData = data
			}
		}

		leaves = append(leaves, leafData)
		_ = i // suppress unused warning
	}

	resp := &protobufs.HypergraphSyncLeavesResponse{
		Path:        req.Path,
		Leaves:      leaves,
		TotalLeaves: totalNonNil,
	}

	// Set continuation token if more leaves remain
	if startIdx+len(leaves) < int(totalNonNil) {
		resp.ContinuationToken = makeContToken(startIdx + len(leaves))
	}

	return &protobufs.HypergraphSyncResponse{
		Response: &protobufs.HypergraphSyncResponse_Leaves{
			Leaves: resp,
		},
	}, nil
}

func (hg *HypergraphCRDT) getPhaseSet(
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
) hypergraph.IdSet {
	switch phaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		return hg.getVertexAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		return hg.getVertexRemovesSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		return hg.getHyperedgeAddsSet(shardKey)
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		return hg.getHyperedgeRemovesSet(shardKey)
	default:
		return nil
	}
}

func parseContToken(token []byte) (int, error) {
	if len(token) == 0 {
		return 0, nil
	}
	// Token is hex-encoded 4 bytes (big-endian int32)
	decoded, err := hex.DecodeString(string(token))
	if err != nil {
		return 0, err
	}
	if len(decoded) != 4 {
		return 0, errors.New("invalid continuation token length")
	}
	idx := int(decoded[0])<<24 | int(decoded[1])<<16 | int(decoded[2])<<8 | int(decoded[3])
	return idx, nil
}

func makeContToken(idx int) []byte {
	return []byte(hex.EncodeToString([]byte{byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx)}))
}

// SyncFrom performs a client-driven sync from the given server stream.
// It navigates to the covered prefix (if any), then recursively syncs
// differing subtrees. If expectedRoot is provided, the server will attempt
// to sync from a snapshot matching that root commitment.
// Returns the new root commitment after sync completes.
func (hg *HypergraphCRDT) SyncFrom(
	stream protobufs.HypergraphComparisonService_PerformSyncClient,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
) ([]byte, error) {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	isGlobalProver := isGlobalProverShard(shardKey)

	logger := hg.logger.With(
		zap.String("method", "SyncFrom"),
		zap.String("shard", hex.EncodeToString(slices.Concat(shardKey.L1[:], shardKey.L2[:]))),
	)
	if len(expectedRoot) > 0 {
		logger = logger.With(zap.String("expectedRoot", hex.EncodeToString(expectedRoot)))
	}

	syncStart := time.Now()
	defer func() {
		logger.Debug("SyncFrom completed", zap.Duration("duration", time.Since(syncStart)))
	}()

	set := hg.getPhaseSet(shardKey, phaseSet)
	if set == nil {
		return nil, errors.New("unsupported phase set")
	}

	// For global prover sync, capture pre-sync state to detect changes
	var preSyncRoot []byte
	if isGlobalProver {
		preSyncRoot = set.GetTree().Commit(nil, false)
	}

	shardKeyBytes := slices.Concat(shardKey.L1[:], shardKey.L2[:])
	coveredPrefix := hg.getCoveredPrefix()

	// Step 1: Navigate to sync point
	syncPoint, err := hg.navigateToSyncPoint(stream, shardKeyBytes, phaseSet, coveredPrefix, expectedRoot, logger)
	if err != nil {
		return nil, errors.Wrap(err, "navigate to sync point")
	}

	if syncPoint == nil || len(syncPoint.Commitment) == 0 {
		if isGlobalProver {
			logger.Warn("global prover sync: server has no data at sync point",
				zap.Bool("syncPoint_nil", syncPoint == nil),
			)
		} else {
			logger.Debug("server has no data at sync point")
		}
		// Return current root even if no data was synced
		root := set.GetTree().Commit(nil, false)
		return root, nil
	}

	if isGlobalProver {
		logger.Info("global prover sync: server returned sync point",
			zap.String("server_commitment", hex.EncodeToString(syncPoint.Commitment)),
			zap.String("local_root", hex.EncodeToString(preSyncRoot)),
			zap.Int("server_children", len(syncPoint.Children)),
			zap.Bool("server_is_leaf", syncPoint.IsLeaf),
		)
	}

	// Step 2: Sync the subtree
	err = hg.syncSubtree(stream, shardKeyBytes, phaseSet, expectedRoot, syncPoint, set, logger)
	if err != nil {
		return nil, errors.Wrap(err, "sync subtree")
	}

	// Step 3: Recompute commitment so future syncs see updated state
	root := set.GetTree().Commit(nil, false)

	// For global prover, only log if sync didn't converge (the interesting case)
	if isGlobalProver && !bytes.Equal(root, expectedRoot) {
		logger.Warn(
			"global prover sync did not converge",
			zap.String("phase", phaseSet.String()),
			zap.String("pre_sync_root", hex.EncodeToString(preSyncRoot)),
			zap.String("post_sync_root", hex.EncodeToString(root)),
			zap.String("expected_root", hex.EncodeToString(expectedRoot)),
			zap.Bool("root_changed", !bytes.Equal(preSyncRoot, root)),
		)
	}

	return root, nil
}

func (hg *HypergraphCRDT) navigateToSyncPoint(
	stream protobufs.HypergraphComparisonService_PerformSyncClient,
	shardKey []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	coveredPrefix []int,
	expectedRoot []byte,
	logger *zap.Logger,
) (*protobufs.HypergraphSyncBranchResponse, error) {
	path := []int32{}

	for {
		// Query server for branch at current path
		err := stream.Send(&protobufs.HypergraphSyncQuery{
			Request: &protobufs.HypergraphSyncQuery_GetBranch{
				GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
					ShardKey:     shardKey,
					PhaseSet:     phaseSet,
					Path:         path,
					ExpectedRoot: expectedRoot,
				},
			},
		})
		if err != nil {
			return nil, errors.Wrap(err, "send GetBranch request")
		}

		resp, err := stream.Recv()
		if err != nil {
			return nil, errors.Wrap(err, "receive GetBranch response")
		}

		if errResp := resp.GetError(); errResp != nil {
			if errResp.Code == protobufs.HypergraphSyncErrorCode_HYPERGRAPH_SYNC_ERROR_NODE_NOT_FOUND {
				// Server doesn't have this path - nothing to sync
				return nil, nil
			}
			return nil, errors.Errorf("server error: %s", errResp.Message)
		}

		branch := resp.GetBranch()
		if branch == nil {
			return nil, errors.New("unexpected response type")
		}

		logger.Debug("navigating",
			zap.String("path", hex.EncodeToString(packPath(path))),
			zap.String("fullPath", hex.EncodeToString(packPath(branch.FullPath))),
			zap.Int("coveredPrefixLen", len(coveredPrefix)),
		)

		// If no covered prefix, root is the sync point
		if len(coveredPrefix) == 0 {
			return branch, nil
		}

		// Check if server's full path reaches or passes our covered prefix
		serverPath := toIntSlice(branch.FullPath)
		if isPrefixOrEqual(coveredPrefix, serverPath) {
			return branch, nil
		}

		// Need to navigate deeper - find next child to descend into
		if len(serverPath) >= len(coveredPrefix) {
			// Server path is longer but doesn't match our prefix
			// This means server has data outside our coverage
			return branch, nil
		}

		// Server path is shorter - we need to go deeper
		nextNibble := coveredPrefix[len(serverPath)]

		// Check if server has a child at this index
		found := false
		for _, child := range branch.Children {
			if int(child.Index) == nextNibble {
				found = true
				break
			}
		}

		if !found {
			// Server doesn't have the path we need
			logger.Debug("server missing path to covered prefix",
				zap.Int("nextNibble", nextNibble),
			)
			return nil, nil
		}

		// Descend to next level
		path = append(branch.FullPath, int32(nextNibble))
	}
}

func (hg *HypergraphCRDT) syncSubtree(
	stream protobufs.HypergraphComparisonService_PerformSyncClient,
	shardKey []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
	serverBranch *protobufs.HypergraphSyncBranchResponse,
	localSet hypergraph.IdSet,
	logger *zap.Logger,
) error {
	tree := localSet.GetTree()

	// Get local node at same path
	var localCommitment []byte
	var localNode tries.LazyVectorCommitmentNode
	if tree != nil && tree.Root != nil {
		path := toIntSlice(serverBranch.FullPath)
		localNode = getNodeAtPath(
			logger,
			tree.SetType,
			tree.PhaseType,
			tree.ShardKey,
			tree.Root,
			serverBranch.FullPath,
			0,
		)
		if localNode != nil {
			localNode = ensureCommittedNode(logger, tree, path, localNode)
			switch n := localNode.(type) {
			case *tries.LazyVectorCommitmentBranchNode:
				localCommitment = n.Commitment
			case *tries.LazyVectorCommitmentLeafNode:
				localCommitment = n.Commitment
			}
		}
	}

	// If commitments match, subtrees are identical
	if bytes.Equal(localCommitment, serverBranch.Commitment) {
		return nil
	}

	// Log divergence for global prover sync
	isGlobalProver := isGlobalProverShardBytes(shardKey)
	var localNodeType string
	var localFullPrefix []int
	switch n := localNode.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		localNodeType = "branch"
		localFullPrefix = n.FullPrefix
	case *tries.LazyVectorCommitmentLeafNode:
		localNodeType = "leaf"
	case nil:
		localNodeType = "nil"
	default:
		localNodeType = "unknown"
	}

	// Check for path prefix mismatch
	serverFullPath := toIntSlice(serverBranch.FullPath)
	pathMismatch := !slices.Equal(localFullPrefix, serverFullPath)

	if isGlobalProver {
		logger.Info("global prover sync: commitment divergence",
			zap.String("phase", phaseSet.String()),
			zap.String("server_path", hex.EncodeToString(packPath(serverBranch.FullPath))),
			zap.String("local_path", hex.EncodeToString(packPath(toInt32Slice(localFullPrefix)))),
			zap.Bool("path_mismatch", pathMismatch),
			zap.Int("path_depth", len(serverBranch.FullPath)),
			zap.String("local_commitment", hex.EncodeToString(localCommitment)),
			zap.String("server_commitment", hex.EncodeToString(serverBranch.Commitment)),
			zap.Bool("local_has_data", localNode != nil),
			zap.String("local_node_type", localNodeType),
			zap.Int("server_children", len(serverBranch.Children)),
			zap.Bool("server_is_leaf", serverBranch.IsLeaf),
		)
	}

	// If server node is a leaf or has no children, fetch all leaves
	if serverBranch.IsLeaf || len(serverBranch.Children) == 0 {
		return hg.fetchAndIntegrateLeaves(stream, shardKey, phaseSet, expectedRoot, serverBranch.FullPath, localSet, logger)
	}

	// If we have NO local data at this path, fetch all leaves directly.
	// This avoids N round trips for N children when we need all of them anyway.
	if localNode == nil {
		return hg.fetchAndIntegrateLeaves(stream, shardKey, phaseSet, expectedRoot, serverBranch.FullPath, localSet, logger)
	}

	// Structural mismatch: local is a leaf but server is a branch with children.
	// We can't compare children because local has none - fetch all server leaves.
	if _, isLeaf := localNode.(*tries.LazyVectorCommitmentLeafNode); isLeaf {
		if isGlobalProver {
			logger.Info("global prover sync: structural mismatch - local leaf vs server branch, fetching leaves",
				zap.Int("path_depth", len(serverBranch.FullPath)),
				zap.Int("server_children", len(serverBranch.Children)),
			)
		}
		return hg.fetchAndIntegrateLeaves(stream, shardKey, phaseSet, expectedRoot, serverBranch.FullPath, localSet, logger)
	}

	// Compare children and recurse
	localChildren := make(map[int32][]byte)
	if tree != nil && tree.Root != nil {
		path := toIntSlice(serverBranch.FullPath)
		if branch, ok := localNode.(*tries.LazyVectorCommitmentBranchNode); ok {
			for i := 0; i < 64; i++ {
				child := branch.Children[i]
				if child == nil {
					child, _ = branch.Store.GetNodeByPath(
						tree.SetType,
						tree.PhaseType,
						tree.ShardKey,
						slices.Concat(path, []int{i}),
					)
				}
				if child != nil {
					childPath := slices.Concat(path, []int{i})
					child = ensureCommittedNode(logger, tree, childPath, child)
					switch c := child.(type) {
					case *tries.LazyVectorCommitmentBranchNode:
						localChildren[int32(i)] = c.Commitment
					case *tries.LazyVectorCommitmentLeafNode:
						localChildren[int32(i)] = c.Commitment
					}
				}
			}
		}
	}

	if isGlobalProver {
		logger.Info("global prover sync: comparing children",
			zap.Int("path_depth", len(serverBranch.FullPath)),
			zap.Int("local_children_count", len(localChildren)),
			zap.Int("server_children_count", len(serverBranch.Children)),
		)
	}

	childrenMatched := 0
	childrenToSync := 0
	for _, serverChild := range serverBranch.Children {
		localChildCommit := localChildren[serverChild.Index]

		// Both nil/empty means we have no data on either side - skip
		// But if server has a commitment and we don't (or vice versa), we need to sync
		localEmpty := len(localChildCommit) == 0
		serverEmpty := len(serverChild.Commitment) == 0

		if localEmpty && serverEmpty {
			// Neither side has data, skip
			childrenMatched++
			continue
		}

		if bytes.Equal(localChildCommit, serverChild.Commitment) {
			// Child matches, skip
			childrenMatched++
			continue
		}
		childrenToSync++

		// Need to sync this child
		childPath := append(slices.Clone(serverBranch.FullPath), serverChild.Index)

		// Query for child branch
		err := stream.Send(&protobufs.HypergraphSyncQuery{
			Request: &protobufs.HypergraphSyncQuery_GetBranch{
				GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
					ShardKey:     shardKey,
					PhaseSet:     phaseSet,
					Path:         childPath,
					ExpectedRoot: expectedRoot,
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "send GetBranch for child")
		}

		resp, err := stream.Recv()
		if err != nil {
			return errors.Wrap(err, "receive GetBranch response for child")
		}

		if errResp := resp.GetError(); errResp != nil {
			logger.Warn("error getting child branch",
				zap.String("error", errResp.Message),
				zap.String("path", hex.EncodeToString(packPath(childPath))),
			)
			continue
		}

		childBranch := resp.GetBranch()
		if childBranch == nil {
			continue
		}

		// Recurse
		if err := hg.syncSubtree(stream, shardKey, phaseSet, expectedRoot, childBranch, localSet, logger); err != nil {
			return err
		}
	}

	if isGlobalProver {
		logger.Info("global prover sync: children comparison complete",
			zap.Int("path_depth", len(serverBranch.FullPath)),
			zap.Int("matched", childrenMatched),
			zap.Int("synced", childrenToSync),
		)
	}

	// If parent diverged but ALL children matched, we have an inconsistent state.
	// The parent commitment should be deterministic from children, so this indicates
	// corruption or staleness. Force fetch all leaves to resolve.
	if childrenToSync == 0 && len(serverBranch.Children) > 0 {
		if isGlobalProver {
			logger.Warn("global prover sync: parent diverged but all children matched - forcing leaf fetch",
				zap.Int("path_depth", len(serverBranch.FullPath)),
				zap.Int("children_count", len(serverBranch.Children)),
			)
		}
		return hg.fetchAndIntegrateLeaves(stream, shardKey, phaseSet, expectedRoot, serverBranch.FullPath, localSet, logger)
	}

	return nil
}

func (hg *HypergraphCRDT) fetchAndIntegrateLeaves(
	stream protobufs.HypergraphComparisonService_PerformSyncClient,
	shardKey []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
	path []int32,
	localSet hypergraph.IdSet,
	logger *zap.Logger,
) error {
	isGlobalProver := isGlobalProverShardBytes(shardKey)
	if isGlobalProver {
		logger.Info("global prover sync: fetching leaves",
			zap.String("path", hex.EncodeToString(packPath(path))),
			zap.Int("path_depth", len(path)),
		)
	} else {
		logger.Debug("fetching leaves",
			zap.String("path", hex.EncodeToString(packPath(path))),
		)
	}

	var continuationToken []byte
	totalFetched := 0

	for {
		err := stream.Send(&protobufs.HypergraphSyncQuery{
			Request: &protobufs.HypergraphSyncQuery_GetLeaves{
				GetLeaves: &protobufs.HypergraphSyncGetLeavesRequest{
					ShardKey:          shardKey,
					PhaseSet:          phaseSet,
					Path:              path,
					MaxLeaves:         1000,
					ContinuationToken: continuationToken,
					ExpectedRoot:      expectedRoot,
				},
			},
		})
		if err != nil {
			return errors.Wrap(err, "send GetLeaves request")
		}

		resp, err := stream.Recv()
		if err != nil {
			return errors.Wrap(err, "receive GetLeaves response")
		}

		if errResp := resp.GetError(); errResp != nil {
			return errors.Errorf("server error: %s", errResp.Message)
		}

		leavesResp := resp.GetLeaves()
		if leavesResp == nil {
			return errors.New("unexpected response type")
		}

		// Integrate leaves into local tree
		txn, err := hg.store.NewTransaction(false)
		if err != nil {
			return errors.Wrap(err, "create transaction")
		}

		for _, leaf := range leavesResp.Leaves {
			atom := AtomFromBytes(leaf.Value)

			// Persist underlying tree if present
			if len(leaf.UnderlyingData) > 0 {
				vtree, err := tries.DeserializeNonLazyTree(leaf.UnderlyingData)
				if err == nil {
					if err := hg.store.SaveVertexTree(txn, leaf.Key, vtree); err != nil {
						logger.Warn("failed to save vertex tree", zap.Error(err))
					}
				}
			}

			if err := localSet.Add(txn, atom); err != nil {
				txn.Abort()
				return errors.Wrap(err, "add leaf to local set")
			}
		}

		if err := txn.Commit(); err != nil {
			return errors.Wrap(err, "commit transaction")
		}

		totalFetched += len(leavesResp.Leaves)

		logger.Debug("fetched leaves batch",
			zap.String("path", hex.EncodeToString(packPath(path))),
			zap.Int("count", len(leavesResp.Leaves)),
			zap.Int("totalFetched", totalFetched),
			zap.Uint64("totalAvailable", leavesResp.TotalLeaves),
		)

		// Check if more leaves remain
		if len(leavesResp.ContinuationToken) == 0 {
			break
		}
		continuationToken = leavesResp.ContinuationToken
	}

	if isGlobalProver {
		logger.Info("global prover sync: leaves integrated",
			zap.String("path", hex.EncodeToString(packPath(path))),
			zap.Int("total_fetched", totalFetched),
		)
	}

	return nil
}

func isPrefixOrEqual(prefix, path []int) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i, v := range prefix {
		if path[i] != v {
			return false
		}
	}
	return true
}
