package hypergraph

import (
	"context"
	"crypto/sha512"
	"math/big"

	"github.com/pkg/errors"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

var errNotSupported = errors.New("not supported in remote mode")

// RemoteHypergraph implements the hypergraph.Hypergraph interface by proxying
// operations to a remote node via gRPC. Only the methods needed by
// Transaction.Prove() are implemented; all others return errNotSupported.
type RemoteHypergraph struct {
	protobufs.UnimplementedHypergraphComparisonServiceServer
	client          protobufs.NodeServiceClient
	inclusionProver crypto.InclusionProver
	domain          [32]byte
}

func NewRemoteHypergraph(
	client protobufs.NodeServiceClient,
	inclusionProver crypto.InclusionProver,
	domain [32]byte,
) *RemoteHypergraph {
	return &RemoteHypergraph{
		client:          client,
		inclusionProver: inclusionProver,
		domain:          domain,
	}
}

// GetVertex checks if a vertex exists by trying to fetch its data.
func (r *RemoteHypergraph) GetVertex(id [64]byte) (hypergraph.Vertex, error) {
	resp, err := r.client.GetVertexData(
		context.Background(),
		&protobufs.GetVertexDataRequest{Address: id[:]},
	)
	if err != nil {
		return nil, errors.Wrap(err, "get vertex")
	}
	if len(resp.Entries) == 0 {
		return nil, errors.New("vertex not found")
	}
	return &remoteVertex{id: id}, nil
}

// LookupVertex checks if a vertex exists and hasn't been removed.
func (r *RemoteHypergraph) LookupVertex(v hypergraph.Vertex) bool {
	id := v.GetID()
	_, err := r.client.GetVertexData(
		context.Background(),
		&protobufs.GetVertexDataRequest{Address: id[:]},
	)
	return err == nil
}

// GetVertexData fetches vertex data via RPC and reconstructs the tree locally.
func (r *RemoteHypergraph) GetVertexData(
	id [64]byte,
) (*tries.VectorCommitmentTree, error) {
	resp, err := r.client.GetVertexData(
		context.Background(),
		&protobufs.GetVertexDataRequest{Address: id[:]},
	)
	if err != nil {
		return nil, errors.Wrap(err, "get vertex data")
	}

	tree := &tries.VectorCommitmentTree{}
	for _, entry := range resp.Entries {
		tree.Insert(entry.Key, entry.Value, nil, big.NewInt(int64(len(entry.Value))))
	}
	tree.Commit(r.inclusionProver, false)

	return tree, nil
}

// CreateTraversalProof delegates to the node's RPC and deserializes the result.
func (r *RemoteHypergraph) CreateTraversalProof(
	domain [32]byte,
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	keys [][]byte,
) (*tries.TraversalProof, error) {
	resp, err := r.client.CreateTraversalProof(
		context.Background(),
		&protobufs.CreateTraversalProofRequest{
			Domain:    domain[:],
			AtomType:  string(atomType),
			PhaseType: string(phaseType),
			Keys:      keys,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "create traversal proof")
	}

	proof := &tries.TraversalProof{}
	if err := proof.FromBytes(resp.Proof, r.inclusionProver); err != nil {
		return nil, errors.Wrap(err, "deserialize traversal proof")
	}

	return proof, nil
}

// GetProver returns the inclusion prover used for cryptographic operations.
func (r *RemoteHypergraph) GetProver() crypto.InclusionProver {
	return r.inclusionProver
}

// --- Unsupported methods ---

func (r *RemoteHypergraph) GetSize(shardKey *tries.ShardKey, path []int) *big.Int {
	return big.NewInt(0)
}

func (r *RemoteHypergraph) Commit(frameNumber uint64) (map[tries.ShardKey][][]byte, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) CommitShard(frameNumber uint64, shardAddress []byte) ([][]byte, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) GetShardCommits(frameNumber uint64, shardAddress []byte) ([][]byte, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) SetCoveredPrefix(prefix []int) error {
	return errNotSupported
}

func (r *RemoteHypergraph) GetCoveredPrefix() ([]int, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) GetMetadataAtKey(pathKey []byte) ([]hypergraph.ShardMetadata, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) AddVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RemoveVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RevertAddVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RevertRemoveVertex(txn tries.TreeBackingStoreTransaction, v hypergraph.Vertex) error {
	return errNotSupported
}

func (r *RemoteHypergraph) GetHyperedge(id [64]byte) (hypergraph.Hyperedge, error) {
	tree, err := r.GetHyperedgeExtrinsics(id)
	if err != nil {
		return nil, errors.Wrap(err, "get hyperedge")
	}
	return &remoteHyperedge{id: id, extTree: tree}, nil
}

func (r *RemoteHypergraph) AddHyperedge(txn tries.TreeBackingStoreTransaction, h hypergraph.Hyperedge) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RemoveHyperedge(txn tries.TreeBackingStoreTransaction, h hypergraph.Hyperedge) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RevertAddHyperedge(txn tries.TreeBackingStoreTransaction, h hypergraph.Hyperedge) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RevertRemoveHyperedge(txn tries.TreeBackingStoreTransaction, h hypergraph.Hyperedge) error {
	return errNotSupported
}

func (r *RemoteHypergraph) LookupHyperedge(h hypergraph.Hyperedge) bool {
	id := h.GetID()
	_, err := r.client.GetHyperedgeData(
		context.Background(),
		&protobufs.GetHyperedgeDataRequest{Address: id[:]},
	)
	return err == nil
}

func (r *RemoteHypergraph) LookupAtom(a hypergraph.Atom) bool {
	return false
}

func (r *RemoteHypergraph) LookupAtomSet(atomSet []hypergraph.Atom) bool {
	return false
}

func (r *RemoteHypergraph) Within(a, h hypergraph.Atom) bool {
	return false
}

func (r *RemoteHypergraph) GetVertexDataIterator(domain [32]byte) tries.VertexDataIterator {
	return nil
}

func (r *RemoteHypergraph) ImportTree(
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	shardKey tries.ShardKey,
	root tries.LazyVectorCommitmentNode,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) error {
	return errNotSupported
}

func (r *RemoteHypergraph) SetVertexData(txn tries.TreeBackingStoreTransaction, id [64]byte, data *tries.VectorCommitmentTree) error {
	return errNotSupported
}

func (r *RemoteHypergraph) RunDataPruning(txn tries.TreeBackingStoreTransaction, frameNumber uint64) error {
	return errNotSupported
}

func (r *RemoteHypergraph) DeleteVertexAdd(txn tries.TreeBackingStoreTransaction, shardKey tries.ShardKey, vertexID [64]byte) error {
	return errNotSupported
}

func (r *RemoteHypergraph) DeleteVertexRemove(txn tries.TreeBackingStoreTransaction, shardKey tries.ShardKey, vertexID [64]byte) error {
	return errNotSupported
}

func (r *RemoteHypergraph) DeleteHyperedgeAdd(txn tries.TreeBackingStoreTransaction, shardKey tries.ShardKey, hyperedgeID [64]byte) error {
	return errNotSupported
}

func (r *RemoteHypergraph) DeleteHyperedgeRemove(txn tries.TreeBackingStoreTransaction, shardKey tries.ShardKey, hyperedgeID [64]byte) error {
	return errNotSupported
}

func (r *RemoteHypergraph) GetHyperedgeExtrinsics(id [64]byte) (*tries.VectorCommitmentTree, error) {
	resp, err := r.client.GetHyperedgeData(
		context.Background(),
		&protobufs.GetHyperedgeDataRequest{Address: id[:]},
	)
	if err != nil {
		return nil, errors.Wrap(err, "get hyperedge extrinsics")
	}

	tree := &tries.VectorCommitmentTree{}
	for _, entry := range resp.Entries {
		tree.Insert(entry.Key, entry.Value, nil, big.NewInt(int64(len(entry.Value))))
	}
	tree.Commit(r.inclusionProver, false)

	return tree, nil
}

func (r *RemoteHypergraph) VerifyTraversalProof(domain [32]byte, atomType hypergraph.AtomType, phaseType hypergraph.PhaseType, root []byte, traversalProof *tries.TraversalProof) (bool, error) {
	return false, errNotSupported
}

func (r *RemoteHypergraph) TrackChange(txn tries.TreeBackingStoreTransaction, key []byte, oldValue *tries.VectorCommitmentTree, frameNumber uint64, phaseType string, setType string, shardKey tries.ShardKey) error {
	return errNotSupported
}

func (r *RemoteHypergraph) GetChanges(frameStart uint64, frameEnd uint64, phaseType string, setType string, shardKey tries.ShardKey) ([]*tries.ChangeRecord, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) RevertChanges(txn tries.TreeBackingStoreTransaction, frameStart uint64, frameEnd uint64, shardKey tries.ShardKey) error {
	return errNotSupported
}

func (r *RemoteHypergraph) SyncFrom(stream protobufs.HypergraphComparisonService_PerformSyncClient, shardKey tries.ShardKey, phaseSet protobufs.HypergraphPhaseSet, expectedRoot []byte) ([]byte, error) {
	return nil, errNotSupported
}

func (r *RemoteHypergraph) NewTransaction(indexed bool) (tries.TreeBackingStoreTransaction, error) {
	store := tries.NewMemoryTreeBackingStore()
	return store.NewTransaction(indexed)
}

// remoteVertex is a minimal Vertex implementation for remote query results.
type remoteVertex struct {
	id [64]byte
}

func (v *remoteVertex) GetID() [64]byte                    { return v.id }
func (v *remoteVertex) GetAtomType() hypergraph.AtomType   { return hypergraph.VertexAtomType }
func (v *remoteVertex) GetAppAddress() [32]byte            { return [32]byte(v.id[:32]) }
func (v *remoteVertex) GetDataAddress() [32]byte           { return [32]byte(v.id[32:]) }
func (v *remoteVertex) ToBytes() []byte                    { return v.id[:] }
func (v *remoteVertex) GetSize() *big.Int                  { return big.NewInt(0) }
func (v *remoteVertex) Commit(prover crypto.InclusionProver) []byte {
	h := sha512.New()
	h.Write(v.id[:])
	return h.Sum(nil)
}

// remoteHyperedge is a minimal Hyperedge implementation for remote query results.
type remoteHyperedge struct {
	id      [64]byte
	extTree *tries.VectorCommitmentTree
}

func (he *remoteHyperedge) GetID() [64]byte                  { return he.id }
func (he *remoteHyperedge) GetAtomType() hypergraph.AtomType { return hypergraph.HyperedgeAtomType }
func (he *remoteHyperedge) GetAppAddress() [32]byte          { return [32]byte(he.id[:32]) }
func (he *remoteHyperedge) GetDataAddress() [32]byte         { return [32]byte(he.id[32:]) }
func (he *remoteHyperedge) ToBytes() []byte                  { return he.id[:] }
func (he *remoteHyperedge) GetSize() *big.Int {
	if he.extTree == nil {
		return big.NewInt(0)
	}
	leaves, _ := he.extTree.GetMetadata()
	return big.NewInt(int64(leaves))
}
func (he *remoteHyperedge) AddExtrinsic(a hypergraph.Atom) {
	if he.extTree == nil {
		he.extTree = &tries.VectorCommitmentTree{}
	}
	id := a.GetID()
	he.extTree.Insert(id[:], a.ToBytes(), nil, a.GetSize())
}
func (he *remoteHyperedge) RemoveExtrinsic(a hypergraph.Atom) {
	if he.extTree != nil {
		id := a.GetID()
		he.extTree.Delete(id[:])
	}
}
func (he *remoteHyperedge) Commit(prover crypto.InclusionProver) []byte {
	if he.extTree == nil {
		return nil
	}
	return he.extTree.Commit(prover, false)
}
func (he *remoteHyperedge) GetExtrinsicTree() *tries.VectorCommitmentTree {
	return he.extTree
}
