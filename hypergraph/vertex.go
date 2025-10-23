package hypergraph

import (
	"math/big"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

type vertex struct {
	appAddress  [32]byte
	dataAddress [32]byte
	commitment  []byte
	size        *big.Int
}

var _ hypergraph.Vertex = (*vertex)(nil)

// NewVertex creates a new vertex with the specified parameters.
func NewVertex(
	appAddress [32]byte,
	dataAddress [32]byte,
	commitment []byte,
	size *big.Int,
) hypergraph.Vertex {
	return &vertex{
		appAddress,
		dataAddress,
		commitment,
		size,
	}
}

func (v *vertex) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], v.appAddress[:])
	copy(id[32:64], v.dataAddress[:])
	return id
}

func (v *vertex) GetSize() *big.Int {
	return v.size
}

func (v *vertex) GetAtomType() hypergraph.AtomType {
	return hypergraph.VertexAtomType
}

func (v *vertex) GetAppAddress() [32]byte {
	return v.appAddress
}

func (v *vertex) GetDataAddress() [32]byte {
	return v.dataAddress
}

func (v *vertex) ToBytes() []byte {
	return append(
		append(
			append(
				append(
					[]byte{0x00},
					v.appAddress[:]...,
				),
				v.dataAddress[:]...,
			),
			v.commitment[:]...,
		),
		v.size.FillBytes(make([]byte, 32))...,
	)
}

func (v *vertex) Commit(prover crypto.InclusionProver) []byte {
	return v.commitment
}

// GetVertex retrieves a vertex by its ID. Returns ErrRemoved if the vertex has
// been removed, or an error if not found.
func (hg *HypergraphCRDT) GetVertex(id [64]byte) (hypergraph.Vertex, error) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	timer := prometheus.NewTimer(GetDuration.WithLabelValues("vertex"))
	defer timer.ObserveDuration()

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	addSet, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	if removeSet.Has(id) {
		GetVertexTotal.WithLabelValues("removed").Inc()
		ErrorsTotal.WithLabelValues("get_vertex", "removed").Inc()
		return nil, errors.Wrap(hypergraph.ErrRemoved, "get vertex")
	}

	value, err := addSet.GetTree().Get(id[:])
	if err != nil {
		GetVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_vertex", "not_found").Inc()
		return nil, errors.Wrap(err, "get vertex")
	}

	atom := AtomFromBytes(value)
	if atom == nil {
		GetVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_vertex", "invalid_atom").Inc()
		return nil, errors.Wrap(hypergraph.ErrInvalidAtomType, "get vertex")
	}

	vertex, ok := atom.(*vertex)
	if !ok {
		GetVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_vertex", "invalid_atom").Inc()
		return nil, errors.Wrap(hypergraph.ErrInvalidAtomType, "get vertex")
	}

	GetVertexTotal.WithLabelValues("success").Inc()
	return vertex, nil
}

// AddVertex adds a vertex to the hypergraph. The vertex is added to the
// appropriate shard based on its ID.
func (hg *HypergraphCRDT) AddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hypergraph.Vertex,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	return hg.addVertex(txn, v)
}

func (hg *HypergraphCRDT) addVertex(
	txn tries.TreeBackingStoreTransaction,
	v hypergraph.Vertex,
) error {
	timer := prometheus.NewTimer(AddVertexDuration)
	defer timer.ObserveDuration()
	shardAddr := hypergraph.GetShardKey(v)
	addSet, _ := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)

	err := addSet.Add(txn, v)
	if err != nil {
		AddVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("add_vertex", "add_error").Inc()
		return errors.Wrap(err, "add vertex")
	}

	hg.size.Add(hg.size, v.GetSize())
	AddVertexTotal.WithLabelValues("success").Inc()
	return nil
}

// RevertAddVertex undoes the addition of a vertex. This is used for rolling
// back failed transactions.
func (hg *HypergraphCRDT) RevertAddVertex(
	txn tries.TreeBackingStoreTransaction,
	v hypergraph.Vertex,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	shardAddr := hypergraph.GetShardKey(v)
	addSet, _ := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	if !addSet.Has(v.GetID()) {
		RevertAddVertexTotal.WithLabelValues("success").Inc()
		return nil
	}

	err := addSet.Delete(txn, v)
	if err != nil {
		RevertAddVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("revert_add_vertex", "delete_error").Inc()
		return errors.Wrap(err, "revert add vertex")
	}

	hg.size.Sub(hg.size, v.GetSize())
	RevertAddVertexTotal.WithLabelValues("success").Inc()
	return nil
}

// RemoveVertex removes a vertex from the hypergraph. In CRDT semantics, this
// adds the vertex to the remove set. If the vertex doesn't exist, it's added to
// both sets for future conflict resolution.
func (hg *HypergraphCRDT) RemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hypergraph.Vertex,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	timer := prometheus.NewTimer(RemoveVertexDuration)
	defer timer.ObserveDuration()

	shardKey := hypergraph.GetShardKey(v)
	if !hg.lookupVertex(v) {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.vertexAdds,
			hg.vertexRemoves,
			hypergraph.VertexAtomType,
			hg.getCoveredPrefix(),
		)
		if err := addSet.Add(txn, v); err != nil {
			RemoveVertexTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("remove_vertex", "add_error").Inc()
			return errors.Wrap(err, "remove vertex")
		}
		if err := removeSet.Add(txn, v); err != nil {
			RemoveVertexTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("remove_vertex", "remove_error").Inc()
			return errors.Wrap(err, "remove vertex")
		}
		RemoveVertexTotal.WithLabelValues("success").Inc()
		return nil
	}

	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	err := removeSet.Add(txn, v)
	if err != nil {
		RemoveVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("remove_vertex", "remove_error").Inc()
		return err
	}
	hg.size.Sub(hg.size, v.GetSize())
	RemoveVertexTotal.WithLabelValues("success").Inc()
	return nil
}

// RevertRemoveVertex undoes the removal of a vertex. This removes the vertex
// from the remove set, effectively un-deleting it.
func (hg *HypergraphCRDT) RevertRemoveVertex(
	txn tries.TreeBackingStoreTransaction,
	v hypergraph.Vertex,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	shardKey := hypergraph.GetShardKey(v)
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	err := removeSet.Delete(txn, v)
	if err != nil {
		RevertRemoveVertexTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("revert_remove_vertex", "delete_error").Inc()
		return err
	}
	hg.size.Add(hg.size, v.GetSize())
	RevertRemoveVertexTotal.WithLabelValues("success").Inc()
	return nil
}

// LookupVertex checks if a vertex exists in the hypergraph. Returns true if the
// vertex is in the add set and not in the remove set.
func (hg *HypergraphCRDT) LookupVertex(v hypergraph.Vertex) bool {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	return hg.lookupVertex(v)
}

func (hg *HypergraphCRDT) lookupVertex(v hypergraph.Vertex) bool {
	timer := prometheus.NewTimer(LookupDuration.WithLabelValues("vertex"))
	defer timer.ObserveDuration()

	shardAddr := hypergraph.GetShardKey(v)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	id := v.GetID()
	found := addSet.Has(id) && !removeSet.Has(id)
	LookupVertexTotal.WithLabelValues(boolToString(found)).Inc()
	return found
}
