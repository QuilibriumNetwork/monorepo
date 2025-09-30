package hypergraph

import (
	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// Commit calculates the hierarchical vector commitments of each set and returns
// the roots of all sets.
func (hg *HypergraphCRDT) Commit() map[tries.ShardKey][][]byte {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	timer := prometheus.NewTimer(CommitDuration)
	defer timer.ObserveDuration()

	commits := map[tries.ShardKey][][]byte{}

	ensureSet := func(shardKey tries.ShardKey) {
		if _, ok := commits[shardKey]; !ok {
			commits[shardKey] = make([][]byte, 4)
			commits[shardKey][0] = make([]byte, 64)
			commits[shardKey][1] = make([]byte, 64)
			commits[shardKey][2] = make([]byte, 64)
			commits[shardKey][3] = make([]byte, 64)
		}
	}

	for shardKey, vertexAdds := range hg.vertexAdds {
		root := vertexAdds.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][0] = root
	}
	for shardKey, vertexRemoves := range hg.vertexRemoves {
		root := vertexRemoves.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][1] = root
	}
	for shardKey, hyperedgeAdds := range hg.hyperedgeAdds {
		root := hyperedgeAdds.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][2] = root
	}
	for shardKey, hyperedgeRemoves := range hg.hyperedgeRemoves {
		root := hyperedgeRemoves.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][3] = root
	}

	// Update metrics
	CommitTotal.WithLabelValues("success").Inc()

	// Update shard count gauges
	VertexAddsShards.Set(float64(len(hg.vertexAdds)))
	VertexRemovesShards.Set(float64(len(hg.vertexRemoves)))
	HyperedgeAddsShards.Set(float64(len(hg.hyperedgeAdds)))
	HyperedgeRemovesShards.Set(float64(len(hg.hyperedgeRemoves)))

	// Update size gauge
	if hg.size != nil {
		size, _ := hg.size.Float64()
		SizeTotal.Set(size)
	}

	return commits
}

// CreateTraversalProofs generates proofs for multiple keys in a shard. The
// domain determines the shard, and proofs are created for the specified atom
// type and phase type (adds or removes).
func (hg *HypergraphCRDT) CreateTraversalProof(
	domain [32]byte,
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	keys [][]byte,
) (*tries.TraversalProof, error) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	timer := prometheus.NewTimer(TraversalProofDuration.WithLabelValues("create"))
	defer timer.ObserveDuration()

	TraversalProofKeysPerRequest.Observe(float64(len(keys)))

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(domain[:], 256, 3)),
		L2: domain,
	}

	var addSet hypergraph.IdSet
	var removeSet hypergraph.IdSet
	if atomType == hypergraph.VertexAtomType {
		addSet, removeSet = hg.getOrCreateIdSet(
			shardKey,
			hg.vertexAdds,
			hg.vertexRemoves,
			atomType,
			hg.getCoveredPrefix(),
		)
	} else {
		addSet, removeSet = hg.getOrCreateIdSet(
			shardKey,
			hg.hyperedgeAdds,
			hg.hyperedgeRemoves,
			atomType,
			hg.getCoveredPrefix(),
		)
	}

	var proof *tries.TraversalProof
	if phaseType == hypergraph.AddsPhaseType {
		proof = addSet.GetTree().ProveMultiple(
			hg.prover,
			keys,
		)
	} else {
		proof = removeSet.GetTree().ProveMultiple(
			hg.prover,
			keys,
		)
	}

	TraversalProofCreateTotal.WithLabelValues(
		string(atomType),
		string(phaseType),
	).Inc()
	return proof, nil
}

// VerifyTraversalProofs verifies a set of traversal proofs for a shard. Returns
// true if all proofs are valid, false otherwise.
func (hg *HypergraphCRDT) VerifyTraversalProof(
	domain [32]byte,
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	traversalProof *tries.TraversalProof,
) (bool, error) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	timer := prometheus.NewTimer(TraversalProofDuration.WithLabelValues("verify"))
	defer timer.ObserveDuration()

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(domain[:], 256, 3)),
		L2: domain,
	}

	var addSet hypergraph.IdSet
	var removeSet hypergraph.IdSet
	if atomType == hypergraph.VertexAtomType {
		addSet, removeSet = hg.getOrCreateIdSet(
			shardKey,
			hg.vertexAdds,
			hg.vertexRemoves,
			atomType,
			hg.getCoveredPrefix(),
		)
	} else {
		addSet, removeSet = hg.getOrCreateIdSet(
			shardKey,
			hg.hyperedgeAdds,
			hg.hyperedgeRemoves,
			atomType,
			hg.getCoveredPrefix(),
		)
	}

	valid := true
	if phaseType == hypergraph.AddsPhaseType {
		if !addSet.GetTree().Verify(traversalProof) {
			valid = false
		}
	} else {
		if !removeSet.GetTree().Verify(traversalProof) {
			valid = false
		}
	}

	TraversalProofVerifyTotal.WithLabelValues(
		string(atomType),
		string(phaseType),
		boolToString(valid),
	).Inc()
	return valid, nil
}
