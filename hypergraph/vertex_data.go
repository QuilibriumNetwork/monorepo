package hypergraph

import (
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

func (hg *HypergraphCRDT) GetVertexDataIterator(
	domain [32]byte,
) tries.VertexDataIterator {
	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(domain[:], 256, 3)),
		L2: [32]byte(append([]byte{}, domain[:]...)),
	}
	iter, err := hg.store.GetVertexDataIterator(shardKey)
	if err != nil {
		// Return a no-op iterator on error
		return &noOpVertexDataIterator{}
	}
	return iter
}

// GetVertexData retrieves the data tree associated with a vertex. Returns
// ErrRemoved if the vertex has been removed.
func (hg *HypergraphCRDT) GetVertexData(id [64]byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	timer := prometheus.NewTimer(GetDuration.WithLabelValues("vertex_data"))
	defer timer.ObserveDuration()

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}

	// We need to verify it hasn't been removed, because vertex data reaping is
	// not instantaneous
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.getCoveredPrefix(),
	)
	if removeSet.Has(id) {
		GetVertexDataTotal.WithLabelValues("removed").Inc()
		ErrorsTotal.WithLabelValues("get_vertex_data", "removed").Inc()
		return nil, errors.Wrap(hypergraph.ErrRemoved, "get vertex data")
	}

	tree, err := hg.store.LoadVertexTree(id[:])
	if err != nil {
		GetVertexDataTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_vertex_data", "load_error").Inc()
		return nil, err
	}

	GetVertexDataTotal.WithLabelValues("success").Inc()
	return tree, nil
}

// SetVertexData associates a data tree with a vertex. The data is stored
// separately from the vertex atom itself.
func (hg *HypergraphCRDT) SetVertexData(
	txn tries.TreeBackingStoreTransaction,
	id [64]byte,
	data *tries.VectorCommitmentTree,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	err := hg.store.SaveVertexTree(txn, id[:], data)
	if err != nil {
		VertexDataSetTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("set_vertex_data", "save_error").Inc()
		return err
	}
	VertexDataSetTotal.WithLabelValues("success").Inc()
	return nil
}

// RunDataPruning removes changesets up to the frame number given This should be
// called periodically to clean up tombstoned data.
func (hg *HypergraphCRDT) RunDataPruning(
	txn tries.TreeBackingStoreTransaction,
	frameNumber uint64,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	timer := prometheus.NewTimer(VertexDataPruningDuration)
	defer timer.ObserveDuration()

	err := hg.store.ReapOldChangesets(txn, frameNumber)
	if err != nil {
		VertexDataPruningTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("prune_vertex_data", "reap_error").Inc()
		return err
	}
	VertexDataPruningTotal.WithLabelValues("success").Inc()
	return nil
}

// noOpVertexDataIterator is a no-op implementation of VertexDataIterator
// used when an error occurs creating the real iterator
type noOpVertexDataIterator struct{}

func (n *noOpVertexDataIterator) Key() []byte {
	return nil
}

func (n *noOpVertexDataIterator) First() bool {
	return false
}

func (n *noOpVertexDataIterator) Next() bool {
	return false
}

func (n *noOpVertexDataIterator) Prev() bool {
	return false
}

func (n *noOpVertexDataIterator) Valid() bool {
	return false
}

func (n *noOpVertexDataIterator) Value() *tries.VectorCommitmentTree {
	return nil
}

func (n *noOpVertexDataIterator) Close() error {
	return nil
}

func (n *noOpVertexDataIterator) Last() bool {
	return false
}
