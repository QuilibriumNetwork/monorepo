package rpc

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

type Synchronizer interface {
	Start(*zap.Logger, store.KVDB)
	Stop()
}

type StandaloneHypersyncServer struct {
	listenAddr multiaddr.Multiaddr
	dbConfig   *config.DBConfig
	grpcServer *gogrpc.Server
	quit       chan struct{}
}

type StandaloneHypersyncClient struct {
	serverAddr multiaddr.Multiaddr
	dbConfig   *config.DBConfig
	done       chan os.Signal
}

func NewStandaloneHypersyncServer(
	dbConfig *config.DBConfig,
	strictSyncServer string,
) Synchronizer {
	listenAddr, err := multiaddr.NewMultiaddr(strictSyncServer)
	if err != nil {
		utils.GetLogger().Panic("failed to parse listen address", zap.Error(err))
	}

	return &StandaloneHypersyncServer{
		dbConfig:   dbConfig,
		listenAddr: listenAddr,
		quit:       make(chan struct{}),
	}
}

func NewStandaloneHypersyncClient(
	dbConfig *config.DBConfig,
	strictSyncClient string,
	done chan os.Signal,
) Synchronizer {
	serverAddr, err := multiaddr.NewMultiaddr(strictSyncClient)
	if err != nil {
		utils.GetLogger().Panic("failed to parse server address", zap.Error(err))
	}

	return &StandaloneHypersyncClient{
		dbConfig:   dbConfig,
		serverAddr: serverAddr,
		done:       done,
	}
}

func (s *StandaloneHypersyncServer) Start(
	logger *zap.Logger,
	db store.KVDB,
) {
	lis, err := mn.Listen(s.listenAddr)
	if err != nil {
		logger.Panic("failed to listen", zap.Error(err))
	}

	s.grpcServer = grpc.NewServer(
		gogrpc.MaxRecvMsgSize(600*1024*1024),
		gogrpc.MaxSendMsgSize(600*1024*1024),
	)

	hypergraphStore := store.NewPebbleHypergraphStore(s.dbConfig, db, logger)
	hypergraph, err := hypergraphStore.LoadHypergraph()
	if err != nil {
		logger.Panic("failed to load hypergraph", zap.Error(err))
	}

	logger.Info("calculating existing hypergraph root commit")

	roots := hypergraph.Commit()
	logger.Info(
		"existing hypergraph root commit",
		zap.String("root", hex.EncodeToString(roots[0])),
	)

	totalCoins := 0

	coinStore := store.NewPebbleCoinStore(db, logger)

	iter, err := coinStore.RangeCoins(
		[]byte{0x00},
		[]byte{0xff},
	)
	if err != nil {
		logger.Panic("failed to range coins", zap.Error(err))
	}

	for iter.First(); iter.Valid(); iter.Next() {
		totalCoins++
	}
	iter.Close()

	server := NewHypergraphComparisonServer(
		logger,
		hypergraphStore,
		hypergraph,
		NewSyncController(),
		totalCoins,
		true,
	)
	protobufs.RegisterHypergraphComparisonServiceServer(
		s.grpcServer,
		server,
	)

	go func() {
		if err := s.grpcServer.Serve(mn.NetListener(lis)); err != nil {
			logger.Error("serve error", zap.Error(err))
		}
	}()
	<-s.quit
}

func (s *StandaloneHypersyncServer) Stop() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.grpcServer.GracefulStop()
	}()
	wg.Wait()
	s.quit <- struct{}{}
}

func (s *StandaloneHypersyncClient) Start(
	logger *zap.Logger,
	db store.KVDB,
) {
	hypergraphStore := store.NewPebbleHypergraphStore(s.dbConfig, db, logger)
	hypergraph, err := hypergraphStore.LoadHypergraph()
	if err != nil {
		logger.Panic("failed to load hypergraph", zap.Error(err))
	}

	logger.Info("calculating existing hypergraph root commit")

	roots := hypergraph.Commit()
	logger.Info(
		"existing hypergraph root commit",
		zap.String("root", hex.EncodeToString(roots[0])),
	)

	totalCoins := 0

	coinStore := store.NewPebbleCoinStore(db, logger)

	iter, err := coinStore.RangeCoins(
		[]byte{0x00},
		[]byte{0xff},
	)
	if err != nil {
		logger.Panic("failed to range coins", zap.Error(err))
	}

	for iter.First(); iter.Valid(); iter.Next() {
		totalCoins++
	}
	iter.Close()

	sets := hypergraph.GetVertexAdds()
	for key, set := range sets {
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelDial()

		_, addr, err := mn.DialArgs(s.serverAddr)
		if err != nil {
			logger.Panic("failed to parse server address", zap.Error(err))
		}
		credentials := insecure.NewCredentials()

		cc, err := gogrpc.DialContext(
			dialCtx,
			addr,
			gogrpc.WithTransportCredentials(
				credentials,
			),
			gogrpc.WithDefaultCallOptions(
				gogrpc.MaxCallSendMsgSize(600*1024*1024),
				gogrpc.MaxCallRecvMsgSize(600*1024*1024),
			),
		)
		if err != nil {
			logger.Panic("failed to dial server", zap.Error(err))
		}

		client := protobufs.NewHypergraphComparisonServiceClient(cc)

		stream, err := client.HyperStream(context.Background())
		if err != nil {
			logger.Error("could not open stream", zap.Error(err))
			return
		}

		err = SyncTreeBidirectionally(
			stream,
			logger,
			append(append([]byte{}, key.L1[:]...), key.L2[:]...),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			hypergraphStore,
			hypergraph,
			set,
			NewSyncController(),
			totalCoins,
			false,
		)

		if err != nil {
			logger.Error("error while synchronizing", zap.Error(err))
		}
		if err := cc.Close(); err != nil {
			logger.Error("error while closing connection", zap.Error(err))
		}
		break
	}

	roots = hypergraph.Commit()
	logger.Info(
		"hypergraph root commit",
		zap.String("root", hex.EncodeToString(roots[0])),
	)

	s.done <- syscall.SIGINT
}

func (s *StandaloneHypersyncClient) Stop() {
}

type SyncController struct {
	isSyncing  atomic.Bool
	SyncStatus map[string]*SyncInfo
}

func (s *SyncController) TryEstablishSyncSession() bool {
	return !s.isSyncing.Swap(true)
}

func (s *SyncController) EndSyncSession() {
	s.isSyncing.Store(false)
}

type SyncInfo struct {
	Unreachable bool
	LastSynced  time.Time
}

func NewSyncController() *SyncController {
	return &SyncController{
		isSyncing:  atomic.Bool{},
		SyncStatus: map[string]*SyncInfo{},
	}
}

// hypergraphComparisonServer implements the bidirectional sync service.
type hypergraphComparisonServer struct {
	protobufs.UnimplementedHypergraphComparisonServiceServer
	isDetachedServer     bool
	logger               *zap.Logger
	localHypergraphStore store.HypergraphStore
	localHypergraph      *hypergraph.Hypergraph
	syncController       *SyncController
	debugTotalCoins      int
}

func NewHypergraphComparisonServer(
	logger *zap.Logger,
	hypergraphStore store.HypergraphStore,
	hypergraph *hypergraph.Hypergraph,
	syncController *SyncController,
	debugTotalCoins int,
	isDetachedServer bool,
) *hypergraphComparisonServer {
	return &hypergraphComparisonServer{
		isDetachedServer:     isDetachedServer,
		logger:               logger,
		localHypergraphStore: hypergraphStore,
		localHypergraph:      hypergraph,
		syncController:       syncController,
		debugTotalCoins:      debugTotalCoins,
	}
}

type streamManager struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *zap.Logger
	stream          HyperStream
	hypergraphStore store.HypergraphStore
	localTree       *crypto.LazyVectorCommitmentTree
	lastSent        time.Time
}

// sendLeafData builds a LeafData message (with the full leaf data) for the
// node at the given path in the local tree and sends it over the stream.
func (s *streamManager) sendLeafData(
	path []int32,
	metadataOnly bool,
) error {
	send := func(leaf *crypto.LazyVectorCommitmentLeafNode) error {
		update := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}
		if !metadataOnly {
			tree, err := s.hypergraphStore.LoadVertexTree(leaf.Key)
			if err == nil {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				if err := enc.Encode(tree); err != nil {
					return errors.Wrap(err, "send leaf data")
				}
				update.UnderlyingData = buf.Bytes()
			}
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

		err := s.stream.Send(msg)
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

	node := getNodeAtPath(
		s.localTree.SetType,
		s.localTree.PhaseType,
		s.localTree.ShardKey,
		s.localTree.Root,
		path,
		0,
	)
	leaf, ok := node.(*crypto.LazyVectorCommitmentLeafNode)
	if !ok {
		children := crypto.GetAllLeaves(
			s.localTree.SetType,
			s.localTree.PhaseType,
			s.localTree.ShardKey,
			node,
		)
		s.logger.Info("sending set of leaves", zap.Int("leaf_count", len(children)))
		for _, child := range children {
			if child == nil {
				continue
			}

			if err := send(child); err != nil {
				return err
			}
		}

		return nil
	}

	return send(leaf)
}

// getNodeAtPath traverses the tree along the provided nibble path. It returns
// the node found (or nil if not found). The depth argument is used for internal
// recursion.
func getNodeAtPath(
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	node crypto.LazyVectorCommitmentNode,
	path []int32,
	depth int,
) crypto.LazyVectorCommitmentNode {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		return node
	}

	switch n := node.(type) {
	case *crypto.LazyVectorCommitmentLeafNode:
		return node
	case *crypto.LazyVectorCommitmentBranchNode:
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
			utils.GetLogger().Panic("failed to get node by path", zap.Error(err))
		}

		if child == nil {
			return nil
		}

		return getNodeAtPath(
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
	tree *crypto.LazyVectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	node := getNodeAtPath(
		tree.SetType,
		tree.PhaseType,
		tree.ShardKey,
		tree.Root,
		path,
		0,
	)
	if node == nil {
		return nil, fmt.Errorf("node not found at path %v", path)
	}

	intpath := []int{}
	for _, p := range path {
		intpath = append(intpath, int(p))
	}
	commitment := node.Commit(
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

	if branch, ok := node.(*crypto.LazyVectorCommitmentBranchNode); ok {
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
					utils.GetLogger().Panic("failed to get node by path", zap.Error(err))
				}
			}
			if child != nil {
				childCommit := child.Commit(
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
	stream HyperStream,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				Path:            path,
				IncludeLeafData: false,
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

func handleQueryNext(
	ctx context.Context,
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	stream HyperStream,
	localTree *crypto.LazyVectorCommitmentTree,
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

		branchInfo, err := getBranchInfoFromTree(localTree, path)
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
	ctx context.Context,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream HyperStream,
	localTree *crypto.LazyVectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	branchInfo, err := getBranchInfoFromTree(localTree, path)
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

type HyperStream interface {
	Send(*protobufs.HypergraphComparison) error
	Recv() (*protobufs.HypergraphComparison, error)
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
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	metadataOnly bool,
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

	if isLeaf(lnode) && isLeaf(rnode) {
		if !bytes.Equal(lnode.Commitment, rnode.Commitment) {
			// conditional is a kludge, m5 only
			if bytes.Compare(lnode.Commitment, rnode.Commitment) < 0 {
				s.logger.Info("leaves mismatch commitments, sending", pathString)
				s.sendLeafData(
					path,
					metadataOnly,
				)
			} else {
				s.logger.Info("leaves mismatch commitments, receiving", pathString)
			}
		}
		return nil
	}

	if isLeaf(rnode) || isLeaf(lnode) {
		s.logger.Info("leaf/branch mismatch at path", pathString)
		err := s.sendLeafData(
			path,
			metadataOnly,
		)
		return errors.Wrap(err, "walk")
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
					s.logger.Info("traversal could not reach path, sending leaf data")
					err := s.sendLeafData(
						path,
						metadataOnly,
					)
					return errors.Wrap(err, "walk")
				}
			}
			s.logger.Info("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				lnode,
				rtrav,
				incomingQueries,
				incomingResponses,
				metadataOnly,
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
							s.logger.Info("traversal could not reach path, sending leaf data")
							if err := s.sendLeafData(
								path,
								metadataOnly,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
							return nil
						}
					} else {
						s.logger.Info(
							"sending leaves of known missing branch",
							zap.String(
								"path",
								hex.EncodeToString(
									packPath(
										append(append([]int32{}, preTraversal...), child.Index),
									),
								),
							),
						)
						if err := s.sendLeafData(
							append(append([]int32{}, preTraversal...), child.Index),
							metadataOnly,
						); err != nil {
							return errors.Wrap(err, "walk")
						}
					}
				}
			}
			s.logger.Info("traversal completed, performing walk", pathString)
			return s.walk(
				path,
				ltrav,
				rnode,
				incomingQueries,
				incomingResponses,
				metadataOnly,
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
					if err := s.sendLeafData(
						path,
						metadataOnly,
					); err != nil {
						return errors.Wrap(err, "walk")
					}
				} else {
					if lchild != nil {
						nextPath := append(
							append([]int32{}, lpref...),
							lchild.Index,
						)
						lc, rc, err := descendIndex(
							s.ctx,
							incomingResponses,
							s.stream,
							s.localTree,
							nextPath,
						)
						if err != nil {
							s.logger.Info("incomplete branch descension, sending leaves")
							if err := s.sendLeafData(
								nextPath,
								metadataOnly,
							); err != nil {
								return errors.Wrap(err, "walk")
							}
							continue
						}

						if err = s.walk(
							nextPath,
							lc,
							rc,
							incomingQueries,
							incomingResponses,
							metadataOnly,
						); err != nil {
							return errors.Wrap(err, "walk")
						}
					}
				}
			}
		} else {
			s.logger.Info("prefix mismatch on both sides", pathString)
			if err := s.sendLeafData(
				path,
				metadataOnly,
			); err != nil {
				return errors.Wrap(err, "walk")
			}
		}
	}

	return nil
}

// syncTreeBidirectionallyServer implements the diff and sync logic on the
// server side. It sends the local root info, then processes incoming messages,
// and queues further queries as differences are detected.
func syncTreeBidirectionallyServer(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
	logger *zap.Logger,
	localHypergraphStore store.HypergraphStore,
	localHypergraph *hypergraph.Hypergraph,
	metadataOnly bool,
	debugTotalCoins int,
) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	query := msg.GetQuery()
	if query == nil {
		return errors.New("client did not send valid initialization message")
	}

	logger.Info("received initialization message")

	// Get the appropriate phase set
	var phaseSet map[crypto.ShardKey]*hypergraph.IdSet
	switch query.PhaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		phaseSet = localHypergraph.GetVertexAdds()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		phaseSet = localHypergraph.GetVertexRemoves()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		phaseSet = localHypergraph.GetHyperedgeAdds()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		phaseSet = localHypergraph.GetHyperedgeRemoves()
	}

	if len(query.ShardKey) != 35 {
		return errors.New("invalid shard key")
	}

	shardKey := crypto.ShardKey{
		L1: [3]byte(query.ShardKey[:3]),
		L2: [32]byte(query.ShardKey[3:]),
	}

	idSet, ok := phaseSet[shardKey]
	if !ok {
		return errors.New("server does not have phase set")
	}

	branchInfo, err := getBranchInfoFromTree(idSet.GetTree(), []int32{})
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
		UnboundedChan[*protobufs.LeafData](
			cancel,
			"server incoming",
		)

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				logger.Info("received disconnect")
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				logger.Info("received error", zap.Error(err))
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
				incomingLeavesIn <- m.LeafData
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
		logger:          logger,
		stream:          stream,
		hypergraphStore: localHypergraphStore,
		localTree:       idSet.GetTree(),
		lastSent:        time.Now(),
	}
	go func() {
		defer wg.Done()
		err := manager.walk(
			[]int32{},
			branchInfo,
			response,
			incomingQueriesOut,
			incomingResponsesOut,
			metadataOnly,
		)
		if err != nil {
			logger.Error("error while syncing", zap.Error(err))
		}
	}()

	lastReceived := time.Now()

outer:
	for {
		select {
		case remoteUpdate, ok := <-incomingLeavesOut:
			if !ok {
				break outer
			}

			logger.Info(
				"received leaf data",
				zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
			)

			theirs := hypergraph.AtomFromBytes(remoteUpdate.Value)

			if len(remoteUpdate.UnderlyingData) != 0 {
				txn, err := localHypergraphStore.NewTransaction(false)
				if err != nil {
					return err
				}

				tree := &crypto.VectorCommitmentTree{}
				var b bytes.Buffer
				b.Write(remoteUpdate.UnderlyingData)

				dec := gob.NewDecoder(&b)
				if err := dec.Decode(tree); err != nil {
					txn.Abort()
					return err
				}

				err = localHypergraphStore.SaveVertexTree(txn, remoteUpdate.Key, tree)
				if err != nil {
					txn.Abort()
					return err
				}

				if err = txn.Commit(); err != nil {
					txn.Abort()
					return err
				}
			}

			err := idSet.Add(nil, theirs)
			if err != nil {
				logger.Error("error while saving", zap.Error(err))
				break outer
			}

			lastReceived = time.Now()
		case <-time.After(30 * time.Second):
			if time.Since(lastReceived) > 30*time.Second &&
				time.Since(manager.lastSent) > 30*time.Second {
				break outer
			}
		}
	}

	wg.Wait()

	roots := localHypergraph.Commit()
	logger.Info(
		"hypergraph root commit",
		zap.String("root", hex.EncodeToString(roots[0])),
	)

	total, _ := idSet.GetTree().GetMetadata()
	logger.Info(
		"current progress, ready to resume connections",
		zap.Float32("percentage", float32(total*100)/float32(debugTotalCoins)),
	)
	return nil
}

// HyperStream is the gRPC method that handles bidirectional synchronization.
func (s *hypergraphComparisonServer) HyperStream(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	if !s.syncController.TryEstablishSyncSession() {
		return errors.New("unavailable")
	}
	defer s.syncController.EndSyncSession()

	var peerId peer.ID
	var ok bool
	if !s.isDetachedServer {
		peerId, ok = grpc.PeerIDFromContext(stream.Context())
		if !ok {
			return errors.New("could not identify peer")
		}

		status, ok := s.syncController.SyncStatus[peerId.String()]
		if ok && time.Since(status.LastSynced) < 30*time.Minute {
			return errors.New("peer too recently synced")
		}
	}

	err := syncTreeBidirectionallyServer(
		stream,
		s.logger,
		s.localHypergraphStore,
		s.localHypergraph,
		false,
		s.debugTotalCoins,
	)

	if !s.isDetachedServer {
		s.syncController.SyncStatus[peerId.String()] = &SyncInfo{
			Unreachable: false,
			LastSynced:  time.Now(),
		}
	}

	return err
}

// SyncTreeBidirectionally performs the tree diff and synchronization.
// The caller (e.g. the client) must initiate the diff from its root.
// After that, both sides exchange queries, branch info, and leaf updates until
// their local trees are synchronized.
func SyncTreeBidirectionally(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	logger *zap.Logger,
	shardKey []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	hypergraphStore store.HypergraphStore,
	localHypergraph *hypergraph.Hypergraph,
	set *hypergraph.IdSet,
	syncController *SyncController,
	debugTotalCoins int,
	metadataOnly bool,
) error {
	logger.Info(
		"sending initialization message",
		zap.String("shard_key", hex.EncodeToString(shardKey)),
		zap.Int("phase_set", int(phaseSet)),
	)

	// Send initial query for root path
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				ShardKey:        shardKey,
				PhaseSet:        phaseSet,
				Path:            []int32{},
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

	branchInfo, err := getBranchInfoFromTree(set.GetTree(), []int32{})
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
		UnboundedChan[*protobufs.LeafData](
			cancel,
			"client incoming",
		)

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				cancel()
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
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
				incomingLeavesIn <- m.LeafData
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
		logger:          logger,
		stream:          stream,
		hypergraphStore: hypergraphStore,
		localTree:       set.GetTree(),
		lastSent:        time.Now(),
	}

	go func() {
		defer wg.Done()
		err := manager.walk(
			[]int32{},
			branchInfo,
			response,
			incomingQueriesOut,
			incomingResponsesOut,
			metadataOnly,
		)
		if err != nil {
			logger.Error("error while syncing", zap.Error(err))
		}
	}()

	lastReceived := time.Now()

outer:
	for {
		select {
		case remoteUpdate, ok := <-incomingLeavesOut:
			if !ok {
				break outer
			}

			logger.Info(
				"received leaf data",
				zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
			)

			theirs := hypergraph.AtomFromBytes(remoteUpdate.Value)

			if len(remoteUpdate.UnderlyingData) != 0 {
				txn, err := hypergraphStore.NewTransaction(false)
				if err != nil {
					return err
				}

				tree := &crypto.VectorCommitmentTree{}
				var b bytes.Buffer
				b.Write(remoteUpdate.UnderlyingData)

				dec := gob.NewDecoder(&b)
				if err := dec.Decode(tree); err != nil {
					txn.Abort()
					return err
				}

				err = hypergraphStore.SaveVertexTree(txn, remoteUpdate.Key, tree)
				if err != nil {
					txn.Abort()
					return err
				}

				if err = txn.Commit(); err != nil {
					txn.Abort()
					return err
				}
			}

			err := set.Add(nil, theirs)
			if err != nil {
				logger.Error("error while saving", zap.Error(err))
				break outer
			}

			lastReceived = time.Now()
		case <-time.After(30 * time.Second):
			if time.Since(lastReceived) > 30*time.Second &&
				time.Since(manager.lastSent) > 30*time.Second {
				break outer
			}
		}
	}

	wg.Wait()

	total, _ := set.GetTree().GetMetadata()
	logger.Info(
		"current progress",
		zap.Float32("percentage", float32(total*100)/float32(debugTotalCoins)),
	)
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
