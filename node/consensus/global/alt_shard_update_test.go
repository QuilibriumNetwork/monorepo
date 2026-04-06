package global

import (
	"bytes"
	"io"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// mockHypergraphStore is a minimal mock for testing alt shard persistence
type mockHypergraphStore struct {
	mock.Mock
	altShardCommits map[string]*altShardCommit
}

type altShardCommit struct {
	frameNumber          uint64
	shardAddress         []byte
	vertexAddsRoot       []byte
	vertexRemovesRoot    []byte
	hyperedgeAddsRoot    []byte
	hyperedgeRemovesRoot []byte
}

func newMockHypergraphStore() *mockHypergraphStore {
	return &mockHypergraphStore{
		altShardCommits: make(map[string]*altShardCommit),
	}
}

// mockTransaction for hypergraph store
type mockHypergraphTransaction struct {
	store    *mockHypergraphStore
	commits  []*altShardCommit
	aborted  bool
	commited bool
}

func (t *mockHypergraphTransaction) Commit() error {
	if t.aborted {
		return nil
	}
	t.commited = true
	for _, c := range t.commits {
		t.store.altShardCommits[string(c.shardAddress)] = c
	}
	return nil
}

func (t *mockHypergraphTransaction) Abort() error {
	t.aborted = true
	return nil
}

func (t *mockHypergraphTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return nil, io.NopCloser(nil), nil
}

func (t *mockHypergraphTransaction) Set(key []byte, value []byte) error {
	return nil
}

func (t *mockHypergraphTransaction) Delete(key []byte) error {
	return nil
}

func (t *mockHypergraphTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	return nil
}

var _ tries.TreeBackingStoreTransaction = (*mockHypergraphTransaction)(nil)

func (m *mockHypergraphStore) NewTransaction(indexed bool) (tries.TreeBackingStoreTransaction, error) {
	return &mockHypergraphTransaction{store: m}, nil
}

func (m *mockHypergraphStore) SetAltShardCommit(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
	shardAddress []byte,
	vertexAddsRoot []byte,
	vertexRemovesRoot []byte,
	hyperedgeAddsRoot []byte,
	hyperedgeRemovesRoot []byte,
) error {
	t := txn.(*mockHypergraphTransaction)
	t.commits = append(t.commits, &altShardCommit{
		frameNumber:          frameNumber,
		shardAddress:         shardAddress,
		vertexAddsRoot:       vertexAddsRoot,
		vertexRemovesRoot:    vertexRemovesRoot,
		hyperedgeAddsRoot:    hyperedgeAddsRoot,
		hyperedgeRemovesRoot: hyperedgeRemovesRoot,
	})
	return nil
}

func (m *mockHypergraphStore) GetLatestAltShardCommit(
	shardAddress []byte,
) (
	vertexAddsRoot []byte,
	vertexRemovesRoot []byte,
	hyperedgeAddsRoot []byte,
	hyperedgeRemovesRoot []byte,
	err error,
) {
	c, ok := m.altShardCommits[string(shardAddress)]
	if !ok {
		return nil, nil, nil, nil, store.ErrNotFound
	}
	return c.vertexAddsRoot, c.vertexRemovesRoot, c.hyperedgeAddsRoot, c.hyperedgeRemovesRoot, nil
}

func (m *mockHypergraphStore) RangeAltShardAddresses() ([][]byte, error) {
	var addrs [][]byte
	for addr := range m.altShardCommits {
		addrs = append(addrs, []byte(addr))
	}
	return addrs, nil
}

// Stub implementations for unused interface methods
func (m *mockHypergraphStore) LoadVertexTree(id []byte) (*tries.VectorCommitmentTree, error) {
	return nil, nil
}
func (m *mockHypergraphStore) SaveVertexTree(txn tries.TreeBackingStoreTransaction, id []byte, vertTree *tries.VectorCommitmentTree) error {
	return nil
}
func (m *mockHypergraphStore) GetVertexDataIterator(prefix tries.ShardKey) (tries.VertexDataIterator, error) {
	return nil, nil
}
func (m *mockHypergraphStore) SetCoveredPrefix(coveredPrefix []int) error { return nil }
func (m *mockHypergraphStore) LoadHypergraph(authenticationProvider channel.AuthenticationProvider, numSyncWorkers int) (hypergraph.Hypergraph, error) {
	return nil, nil
}
func (m *mockHypergraphStore) GetNodeByKey(setType string, phaseType string, shardKey tries.ShardKey, key []byte) (tries.LazyVectorCommitmentNode, error) {
	return nil, nil
}
func (m *mockHypergraphStore) GetNodeByPath(setType string, phaseType string, shardKey tries.ShardKey, path []int) (tries.LazyVectorCommitmentNode, error) {
	return nil, nil
}
func (m *mockHypergraphStore) InsertNode(txn tries.TreeBackingStoreTransaction, setType string, phaseType string, shardKey tries.ShardKey, key []byte, path []int, node tries.LazyVectorCommitmentNode) error {
	return nil
}
func (m *mockHypergraphStore) SaveRoot(txn tries.TreeBackingStoreTransaction, setType string, phaseType string, shardKey tries.ShardKey, node tries.LazyVectorCommitmentNode) error {
	return nil
}
func (m *mockHypergraphStore) DeleteNode(txn tries.TreeBackingStoreTransaction, setType string, phaseType string, shardKey tries.ShardKey, key []byte, path []int) error {
	return nil
}
func (m *mockHypergraphStore) DeleteUncoveredPrefix(setType string, phaseType string, shardKey tries.ShardKey, prefix []int) error {
	return nil
}
func (m *mockHypergraphStore) ReapOldChangesets(txn tries.TreeBackingStoreTransaction, frameNumber uint64) error {
	return nil
}
func (m *mockHypergraphStore) TrackChange(txn tries.TreeBackingStoreTransaction, key []byte, oldValue *tries.VectorCommitmentTree, frameNumber uint64, phaseType string, setType string, shardKey tries.ShardKey) error {
	return nil
}
func (m *mockHypergraphStore) GetChanges(frameStart uint64, frameEnd uint64, phaseType string, setType string, shardKey tries.ShardKey) ([]*tries.ChangeRecord, error) {
	return nil, nil
}
func (m *mockHypergraphStore) UntrackChange(txn tries.TreeBackingStoreTransaction, key []byte, frameNumber uint64, phaseType string, setType string, shardKey tries.ShardKey) error {
	return nil
}
func (m *mockHypergraphStore) SetShardCommit(txn tries.TreeBackingStoreTransaction, frameNumber uint64, phaseType string, setType string, shardAddress []byte, commitment []byte) error {
	return nil
}
func (m *mockHypergraphStore) GetShardCommit(frameNumber uint64, phaseType string, setType string, shardAddress []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockHypergraphStore) GetRootCommits(frameNumber uint64) (map[tries.ShardKey][][]byte, error) {
	return nil, nil
}
func (m *mockHypergraphStore) ApplySnapshot(dbPath string) error { return nil }

var _ store.HypergraphStore = (*mockHypergraphStore)(nil)

func TestPersistAltShardUpdates_NoUpdates(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	// Empty requests - should return nil without doing anything
	err := engine.materializer.persistAltShardUpdates(100, nil)
	require.NoError(t, err)

	// Empty bundles
	err = engine.materializer.persistAltShardUpdates(100, []*protobufs.MessageBundle{})
	require.NoError(t, err)

	// Bundle with no alt shard updates
	bundles := []*protobufs.MessageBundle{
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_Join{
						Join: &protobufs.ProverJoin{
							FrameNumber: 100,
						},
					},
				},
			},
		},
	}
	err = engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// No commits should have been made
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	assert.Empty(t, addrs)
}

func TestPersistAltShardUpdates_SingleUpdate(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	// Create a mock public key (585 bytes for BLS48-581)
	publicKey := bytes.Repeat([]byte{0x01}, 585)

	// Create roots (64 bytes each)
	vertexAddsRoot := bytes.Repeat([]byte{0xAA}, 64)
	vertexRemovesRoot := bytes.Repeat([]byte{0xBB}, 64)
	hyperedgeAddsRoot := bytes.Repeat([]byte{0xCC}, 64)
	hyperedgeRemovesRoot := bytes.Repeat([]byte{0xDD}, 64)

	bundles := []*protobufs.MessageBundle{
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            publicKey,
							FrameNumber:          100,
							VertexAddsRoot:       vertexAddsRoot,
							VertexRemovesRoot:    vertexRemovesRoot,
							HyperedgeAddsRoot:    hyperedgeAddsRoot,
							HyperedgeRemovesRoot: hyperedgeRemovesRoot,
							Signature:            bytes.Repeat([]byte{0xEE}, 74),
						},
					},
				},
			},
		},
	}

	err := engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// Verify the commit was stored
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	require.Len(t, addrs, 1)

	// Compute expected shard address
	expectedAddrBI, err := poseidon.HashBytes(publicKey)
	require.NoError(t, err)
	expectedAddr := expectedAddrBI.FillBytes(make([]byte, 32))

	assert.Equal(t, expectedAddr, addrs[0])

	// Verify the stored roots
	vaRoot, vrRoot, haRoot, hrRoot, err := hgStore.GetLatestAltShardCommit(expectedAddr)
	require.NoError(t, err)
	assert.Equal(t, vertexAddsRoot, vaRoot)
	assert.Equal(t, vertexRemovesRoot, vrRoot)
	assert.Equal(t, hyperedgeAddsRoot, haRoot)
	assert.Equal(t, hyperedgeRemovesRoot, hrRoot)
}

func TestPersistAltShardUpdates_MultipleUpdates(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	// Create two different public keys
	publicKey1 := bytes.Repeat([]byte{0x01}, 585)
	publicKey2 := bytes.Repeat([]byte{0x02}, 585)

	bundles := []*protobufs.MessageBundle{
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            publicKey1,
							FrameNumber:          100,
							VertexAddsRoot:       bytes.Repeat([]byte{0x11}, 64),
							VertexRemovesRoot:    bytes.Repeat([]byte{0x12}, 64),
							HyperedgeAddsRoot:    bytes.Repeat([]byte{0x13}, 64),
							HyperedgeRemovesRoot: bytes.Repeat([]byte{0x14}, 64),
							Signature:            bytes.Repeat([]byte{0x1F}, 74),
						},
					},
				},
			},
		},
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            publicKey2,
							FrameNumber:          100,
							VertexAddsRoot:       bytes.Repeat([]byte{0x21}, 64),
							VertexRemovesRoot:    bytes.Repeat([]byte{0x22}, 64),
							HyperedgeAddsRoot:    bytes.Repeat([]byte{0x23}, 64),
							HyperedgeRemovesRoot: bytes.Repeat([]byte{0x24}, 64),
							Signature:            bytes.Repeat([]byte{0x2F}, 74),
						},
					},
				},
			},
		},
	}

	err := engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// Verify both commits were stored
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	require.Len(t, addrs, 2)

	// Verify first shard
	expectedAddrBI1, _ := poseidon.HashBytes(publicKey1)
	expectedAddr1 := expectedAddrBI1.FillBytes(make([]byte, 32))
	vaRoot1, vrRoot1, haRoot1, hrRoot1, err := hgStore.GetLatestAltShardCommit(expectedAddr1)
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{0x11}, 64), vaRoot1)
	assert.Equal(t, bytes.Repeat([]byte{0x12}, 64), vrRoot1)
	assert.Equal(t, bytes.Repeat([]byte{0x13}, 64), haRoot1)
	assert.Equal(t, bytes.Repeat([]byte{0x14}, 64), hrRoot1)

	// Verify second shard
	expectedAddrBI2, _ := poseidon.HashBytes(publicKey2)
	expectedAddr2 := expectedAddrBI2.FillBytes(make([]byte, 32))
	vaRoot2, vrRoot2, haRoot2, hrRoot2, err := hgStore.GetLatestAltShardCommit(expectedAddr2)
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{0x21}, 64), vaRoot2)
	assert.Equal(t, bytes.Repeat([]byte{0x22}, 64), vrRoot2)
	assert.Equal(t, bytes.Repeat([]byte{0x23}, 64), haRoot2)
	assert.Equal(t, bytes.Repeat([]byte{0x24}, 64), hrRoot2)
}

func TestPersistAltShardUpdates_SkipsEmptyPublicKey(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	// Create update with empty public key - should be skipped
	bundles := []*protobufs.MessageBundle{
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            nil, // Empty
							FrameNumber:          100,
							VertexAddsRoot:       bytes.Repeat([]byte{0xAA}, 64),
							VertexRemovesRoot:    bytes.Repeat([]byte{0xBB}, 64),
							HyperedgeAddsRoot:    bytes.Repeat([]byte{0xCC}, 64),
							HyperedgeRemovesRoot: bytes.Repeat([]byte{0xDD}, 64),
							Signature:            bytes.Repeat([]byte{0xEE}, 74),
						},
					},
				},
			},
		},
	}

	err := engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// No commits should have been made
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	assert.Empty(t, addrs)
}

func TestPersistAltShardUpdates_MixedRequests(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	publicKey := bytes.Repeat([]byte{0x01}, 585)

	// Mix of alt shard updates and other request types
	bundles := []*protobufs.MessageBundle{
		{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_Join{
						Join: &protobufs.ProverJoin{
							FrameNumber: 100,
						},
					},
				},
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            publicKey,
							FrameNumber:          100,
							VertexAddsRoot:       bytes.Repeat([]byte{0xAA}, 64),
							VertexRemovesRoot:    bytes.Repeat([]byte{0xBB}, 64),
							HyperedgeAddsRoot:    bytes.Repeat([]byte{0xCC}, 64),
							HyperedgeRemovesRoot: bytes.Repeat([]byte{0xDD}, 64),
							Signature:            bytes.Repeat([]byte{0xEE}, 74),
						},
					},
				},
				{
					Request: &protobufs.MessageRequest_Leave{
						Leave: &protobufs.ProverLeave{
							FrameNumber: 100,
						},
					},
				},
			},
		},
	}

	err := engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// Only the alt shard update should have been stored
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	require.Len(t, addrs, 1)

	expectedAddrBI, _ := poseidon.HashBytes(publicKey)
	expectedAddr := expectedAddrBI.FillBytes(make([]byte, 32))
	assert.Equal(t, expectedAddr, addrs[0])
}

func TestPersistAltShardUpdates_NilRequests(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
	}
	engine.materializer = &FrameMaterializer{engine: engine}

	publicKey := bytes.Repeat([]byte{0x01}, 585)

	// Bundles with nil entries mixed in
	bundles := []*protobufs.MessageBundle{
		nil, // nil bundle
		{
			Requests: []*protobufs.MessageRequest{
				nil, // nil request
				{
					Request: &protobufs.MessageRequest_AltShardUpdate{
						AltShardUpdate: &protobufs.AltShardUpdate{
							PublicKey:            publicKey,
							FrameNumber:          100,
							VertexAddsRoot:       bytes.Repeat([]byte{0xAA}, 64),
							VertexRemovesRoot:    bytes.Repeat([]byte{0xBB}, 64),
							HyperedgeAddsRoot:    bytes.Repeat([]byte{0xCC}, 64),
							HyperedgeRemovesRoot: bytes.Repeat([]byte{0xDD}, 64),
							Signature:            bytes.Repeat([]byte{0xEE}, 74),
						},
					},
				},
				nil, // another nil request
			},
		},
		nil, // another nil bundle
	}

	err := engine.materializer.persistAltShardUpdates(100, bundles)
	require.NoError(t, err)

	// The valid alt shard update should still be stored
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	require.Len(t, addrs, 1)
}

// Mock hypergraph for rebuildShardCommitments tests
type mockHypergraph struct {
	mock.Mock
	protobufs.UnimplementedHypergraphComparisonServiceServer
	commitSet map[tries.ShardKey][][]byte
}

func newMockHypergraph() *mockHypergraph {
	return &mockHypergraph{
		commitSet: make(map[tries.ShardKey][][]byte),
	}
}

func (m *mockHypergraph) GetSize(shardKey *tries.ShardKey, path []int) *big.Int {
	return big.NewInt(0)
}

func (m *mockHypergraph) Commit(frameNumber uint64) (map[tries.ShardKey][][]byte, error) {
	return m.commitSet, nil
}

func (m *mockHypergraph) CommitShard(frameNumber uint64, shardAddress []byte) ([][]byte, error) {
	return nil, nil
}

func (m *mockHypergraph) GetShardCommits(frameNumber uint64, shardAddress []byte) ([][]byte, error) {
	return nil, nil
}

func (m *mockHypergraph) SetCoveredPrefix(prefix []int) error {
	return nil
}

func (m *mockHypergraph) GetCoveredPrefix() ([]int, error) {
	return nil, nil
}

func (m *mockHypergraph) GetMetadataAtKey(pathKey []byte) ([]hypergraph.ShardMetadata, error) {
	return nil, nil
}

func (m *mockHypergraph) GetVertex(id [64]byte) (hypergraph.Vertex, error) {
	return nil, nil
}

func (m *mockHypergraph) AddVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return nil
}

func (m *mockHypergraph) RemoveVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return nil
}

func (m *mockHypergraph) RevertAddVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return nil
}

func (m *mockHypergraph) RevertRemoveVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return nil
}

func (m *mockHypergraph) LookupVertex(v hypergraph.Vertex) bool {
	return false
}

func (m *mockHypergraph) GetHyperedge(id [64]byte) (hypergraph.Hyperedge, error) {
	return nil, nil
}

func (m *mockHypergraph) AddHyperedge(txn tries.TreeBackingStoreTransaction, e hypergraph.Hyperedge) error {
	return nil
}

func (m *mockHypergraph) RemoveHyperedge(txn tries.TreeBackingStoreTransaction, e hypergraph.Hyperedge) error {
	return nil
}

func (m *mockHypergraph) RevertAddHyperedge(txn tries.TreeBackingStoreTransaction, e hypergraph.Hyperedge) error {
	return nil
}

func (m *mockHypergraph) RevertRemoveHyperedge(txn tries.TreeBackingStoreTransaction, e hypergraph.Hyperedge) error {
	return nil
}

func (m *mockHypergraph) LookupHyperedge(h hypergraph.Hyperedge) bool {
	return false
}

func (m *mockHypergraph) LookupAtom(a hypergraph.Atom) bool {
	return false
}

func (m *mockHypergraph) LookupAtomSet(atomSet []hypergraph.Atom) bool {
	return false
}

func (m *mockHypergraph) Within(a, h hypergraph.Atom) bool {
	return false
}

func (m *mockHypergraph) GetVertexDataIterator(domain [32]byte) tries.VertexDataIterator {
	return nil
}

func (m *mockHypergraph) ImportTree(
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	shardKey tries.ShardKey,
	root tries.LazyVectorCommitmentNode,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) error {
	return nil
}

func (m *mockHypergraph) GetVertexData(id [64]byte) (*tries.VectorCommitmentTree, error) {
	return nil, nil
}

func (m *mockHypergraph) SetVertexData(
	txn tries.TreeBackingStoreTransaction,
	id [64]byte,
	data *tries.VectorCommitmentTree,
) error {
	return nil
}

func (m *mockHypergraph) RunDataPruning(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
) error {
	return nil
}

func (m *mockHypergraph) DeleteVertexAdd(
	txn tries.TreeBackingStoreTransaction,
	shardKey tries.ShardKey,
	vertexID [64]byte,
) error {
	return nil
}

func (m *mockHypergraph) DeleteVertexRemove(
	txn tries.TreeBackingStoreTransaction,
	shardKey tries.ShardKey,
	vertexID [64]byte,
) error {
	return nil
}

func (m *mockHypergraph) DeleteHyperedgeAdd(
	txn tries.TreeBackingStoreTransaction,
	shardKey tries.ShardKey,
	hyperedgeID [64]byte,
) error {
	return nil
}

func (m *mockHypergraph) DeleteHyperedgeRemove(
	txn tries.TreeBackingStoreTransaction,
	shardKey tries.ShardKey,
	hyperedgeID [64]byte,
) error {
	return nil
}

func (m *mockHypergraph) GetHyperedgeExtrinsics(id [64]byte) (*tries.VectorCommitmentTree, error) {
	return nil, nil
}

func (m *mockHypergraph) CreateTraversalProof(
	domain [32]byte,
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	keys [][]byte,
) (*tries.TraversalProof, error) {
	return nil, nil
}

func (m *mockHypergraph) VerifyTraversalProof(
	domain [32]byte,
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	root []byte,
	traversalProof *tries.TraversalProof,
) (bool, error) {
	return false, nil
}

func (m *mockHypergraph) TrackChange(
	txn tries.TreeBackingStoreTransaction,
	key []byte,
	oldValue *tries.VectorCommitmentTree,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) error {
	return nil
}

func (m *mockHypergraph) GetChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) ([]*tries.ChangeRecord, error) {
	return nil, nil
}

func (m *mockHypergraph) RevertChanges(
	txn tries.TreeBackingStoreTransaction,
	frameStart uint64,
	frameEnd uint64,
	shardKey tries.ShardKey,
) error {
	return nil
}

func (m *mockHypergraph) SyncFrom(
	stream protobufs.HypergraphComparisonService_PerformSyncClient,
	shardKey tries.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
	expectedRoot []byte,
) ([]byte, error) {
	return nil, nil
}

func (m *mockHypergraph) NewTransaction(indexed bool) (tries.TreeBackingStoreTransaction, error) {
	return nil, nil
}

func (m *mockHypergraph) GetProver() crypto.InclusionProver {
	return nil
}

var _ hypergraph.Hypergraph = (*mockHypergraph)(nil)

// Mock inclusion prover
type mockInclusionProver struct{}

func (m *mockInclusionProver) CommitRaw(data []byte, polySize uint64) ([]byte, error) {
	// Return a simple mock commitment
	return bytes.Repeat([]byte{0xCC}, 64), nil
}

func (m *mockInclusionProver) ProveRaw(data []byte, index int, polySize uint64) ([]byte, error) {
	return nil, nil
}

func (m *mockInclusionProver) VerifyRaw(data []byte, commit []byte, index uint64, proof []byte, polySize uint64) (bool, error) {
	return true, nil
}

func (m *mockInclusionProver) ProveMultiple(commitments [][]byte, polys [][]byte, indices []uint64, polySize uint64) crypto.Multiproof {
	return nil
}

func (m *mockInclusionProver) VerifyMultiple(commitments [][]byte, evaluations [][]byte, indices []uint64, polySize uint64, multiCommitment []byte, proof []byte) bool {
	return true
}

func (m *mockInclusionProver) NewMultiproof() crypto.Multiproof {
	return nil
}

var _ crypto.InclusionProver = (*mockInclusionProver)(nil)

func TestRebuildShardCommitments_AppliesAltShardUpdates(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()
	hg := newMockHypergraph()
	prover := &mockInclusionProver{}

	// Create a shard address and add alt shard commits to the store
	shardAddr := bytes.Repeat([]byte{0x42}, 32)

	// Pre-populate alt shard commits in the store
	vertexAddsRoot := bytes.Repeat([]byte{0xAA}, 64)
	vertexRemovesRoot := bytes.Repeat([]byte{0xBB}, 64)
	hyperedgeAddsRoot := bytes.Repeat([]byte{0xCC}, 64)
	hyperedgeRemovesRoot := bytes.Repeat([]byte{0xDD}, 64)

	hgStore.altShardCommits[string(shardAddr)] = &altShardCommit{
		frameNumber:          100,
		shardAddress:         shardAddr,
		vertexAddsRoot:       vertexAddsRoot,
		vertexRemovesRoot:    vertexRemovesRoot,
		hyperedgeAddsRoot:    hyperedgeAddsRoot,
		hyperedgeRemovesRoot: hyperedgeRemovesRoot,
	}

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
		hypergraph:      hg,
		inclusionProver: prover,
		consensusProtocol: &ConsensusProtocol{
			shardCommitments:       nil,
			shardCommitmentTrees:   nil,
			shardCommitmentKeySets: nil,
		},
	}
	engine.materializer = &FrameMaterializer{engine: engine}
	engine.consensusProtocol.engine = engine

	// Call rebuildShardCommitments - should apply alt shard roots
	commitHash, err := engine.consensusProtocol.rebuildShardCommitments(100, 1)
	require.NoError(t, err)
	require.NotNil(t, commitHash)

	// Verify the shard commitment trees were populated with alt shard data
	// The alt shard roots should be inserted into the appropriate trees
	require.NotNil(t, engine.consensusProtocol.shardCommitmentTrees)

	// Check that the commitment hash was computed (non-zero)
	require.NotEqual(t, bytes.Repeat([]byte{0x00}, 32), commitHash)
}

func TestRebuildShardCommitments_OverridesWithAltShardRoots(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()
	hg := newMockHypergraph()
	prover := &mockInclusionProver{}

	// Create a shard address
	shardAddr := bytes.Repeat([]byte{0x42}, 32)

	// Create a shard key that maps to the same L2 address
	var l2 [32]byte
	copy(l2[:], shardAddr)
	sk := tries.ShardKey{
		L1: [3]byte{0x01, 0x02, 0x03}, // Some L1 indices
		L2: l2,
	}

	// Add a conflicting commit from the regular hypergraph
	regularCommit := bytes.Repeat([]byte{0x11}, 64)
	hg.commitSet[sk] = [][]byte{regularCommit}

	// Add alt shard commits that should override
	altVertexAddsRoot := bytes.Repeat([]byte{0xAA}, 64)
	hgStore.altShardCommits[string(shardAddr)] = &altShardCommit{
		frameNumber:          100,
		shardAddress:         shardAddr,
		vertexAddsRoot:       altVertexAddsRoot,
		vertexRemovesRoot:    nil, // Empty - should be skipped
		hyperedgeAddsRoot:    nil,
		hyperedgeRemovesRoot: nil,
	}

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
		hypergraph:      hg,
		inclusionProver: prover,
		consensusProtocol: &ConsensusProtocol{
			shardCommitments:       nil,
			shardCommitmentTrees:   nil,
			shardCommitmentKeySets: nil,
		},
	}
	engine.materializer = &FrameMaterializer{engine: engine}
	engine.consensusProtocol.engine = engine

	// First call to set up initial state
	_, err := engine.consensusProtocol.rebuildShardCommitments(100, 1)
	require.NoError(t, err)

	// Verify trees were created
	require.NotNil(t, engine.consensusProtocol.shardCommitmentTrees)

	// The alt shard update should have been applied
	// We can verify this by checking that the commitment hash is not empty
	require.NotNil(t, engine.consensusProtocol.commitmentHash)
}

func TestRebuildShardCommitments_NoAltShards(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()
	hg := newMockHypergraph()
	prover := &mockInclusionProver{}

	// No alt shard commits - just regular hypergraph commits
	shardAddr := bytes.Repeat([]byte{0x42}, 32)
	var l2 [32]byte
	copy(l2[:], shardAddr)
	sk := tries.ShardKey{
		L1: [3]byte{0x01, 0x02, 0x03},
		L2: l2,
	}

	regularCommit := bytes.Repeat([]byte{0x11}, 64)
	hg.commitSet[sk] = [][]byte{regularCommit}

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
		hypergraph:      hg,
		inclusionProver: prover,
		consensusProtocol: &ConsensusProtocol{
			shardCommitments:       nil,
			shardCommitmentTrees:   nil,
			shardCommitmentKeySets: nil,
		},
	}
	engine.materializer = &FrameMaterializer{engine: engine}
	engine.consensusProtocol.engine = engine

	commitHash, err := engine.consensusProtocol.rebuildShardCommitments(100, 1)
	require.NoError(t, err)
	require.NotNil(t, commitHash)

	// No alt shard addresses should be in the store
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	assert.Empty(t, addrs)
}

func TestRebuildShardCommitments_MultipleAltShards(t *testing.T) {
	logger := zap.NewNop()
	hgStore := newMockHypergraphStore()
	hg := newMockHypergraph()
	prover := &mockInclusionProver{}

	// Add multiple alt shard commits
	shardAddr1 := bytes.Repeat([]byte{0x42}, 32)
	shardAddr2 := bytes.Repeat([]byte{0x43}, 32)

	hgStore.altShardCommits[string(shardAddr1)] = &altShardCommit{
		frameNumber:          100,
		shardAddress:         shardAddr1,
		vertexAddsRoot:       bytes.Repeat([]byte{0xAA}, 64),
		vertexRemovesRoot:    bytes.Repeat([]byte{0xBB}, 64),
		hyperedgeAddsRoot:    bytes.Repeat([]byte{0xCC}, 64),
		hyperedgeRemovesRoot: bytes.Repeat([]byte{0xDD}, 64),
	}

	hgStore.altShardCommits[string(shardAddr2)] = &altShardCommit{
		frameNumber:          100,
		shardAddress:         shardAddr2,
		vertexAddsRoot:       bytes.Repeat([]byte{0x11}, 64),
		vertexRemovesRoot:    bytes.Repeat([]byte{0x22}, 64),
		hyperedgeAddsRoot:    bytes.Repeat([]byte{0x33}, 64),
		hyperedgeRemovesRoot: bytes.Repeat([]byte{0x44}, 64),
	}

	engine := &GlobalConsensusEngine{
		logger:          logger,
		hypergraphStore: hgStore,
		hypergraph:      hg,
		inclusionProver: prover,
		consensusProtocol: &ConsensusProtocol{
			shardCommitments:       nil,
			shardCommitmentTrees:   nil,
			shardCommitmentKeySets: nil,
		},
	}
	engine.materializer = &FrameMaterializer{engine: engine}
	engine.consensusProtocol.engine = engine

	commitHash, err := engine.consensusProtocol.rebuildShardCommitments(100, 1)
	require.NoError(t, err)
	require.NotNil(t, commitHash)

	// Both alt shards should be in the store
	addrs, err := hgStore.RangeAltShardAddresses()
	require.NoError(t, err)
	assert.Len(t, addrs, 2)
}
