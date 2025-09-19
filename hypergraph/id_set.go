package hypergraph

import (
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// GetVertexAdds returns the map of vertex addition sets by shard key.
func (
	hg *HypergraphCRDT,
) GetVertexAdds() map[tries.ShardKey]*hypergraph.IdSet {
	return hg.vertexAdds
}

// GetVertexRemoves returns the map of vertex removal sets by shard key.
func (
	hg *HypergraphCRDT,
) GetVertexRemoves() map[tries.ShardKey]*hypergraph.IdSet {
	return hg.vertexRemoves
}

// GetHyperedgeAdds returns the map of hyperedge addition sets by shard key.
func (
	hg *HypergraphCRDT,
) GetHyperedgeAdds() map[tries.ShardKey]*hypergraph.IdSet {
	return hg.hyperedgeAdds
}

// GetHyperedgeRemoves returns the map of hyperedge removal sets by shard key.
func (
	hg *HypergraphCRDT,
) GetHyperedgeRemoves() map[tries.ShardKey]*hypergraph.IdSet {
	return hg.hyperedgeRemoves
}

// getOrCreateIdSet returns the add and remove sets for the given shard. If the
// sets don't exist, they are created with the appropriate parameters.
func (hg *HypergraphCRDT) getOrCreateIdSet(
	shardAddr tries.ShardKey,
	addMap map[tries.ShardKey]*hypergraph.IdSet,
	removeMap map[tries.ShardKey]*hypergraph.IdSet,
	atomType hypergraph.AtomType,
) (*hypergraph.IdSet, *hypergraph.IdSet) {
	if _, ok := addMap[shardAddr]; !ok {
		addMap[shardAddr] = hypergraph.NewIdSet(
			atomType,
			hypergraph.AddsPhaseType,
			shardAddr,
			hg.store,
			hg.prover,
			nil,
		)
	}
	if _, ok := removeMap[shardAddr]; !ok {
		removeMap[shardAddr] = hypergraph.NewIdSet(
			atomType,
			hypergraph.RemovesPhaseType,
			shardAddr,
			hg.store,
			hg.prover,
			nil,
		)
	}
	return addMap[shardAddr], removeMap[shardAddr]
}
