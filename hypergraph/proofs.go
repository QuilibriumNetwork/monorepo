package hypergraph

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// Commit calculates the hierarchical vector commitments of each set and returns
// the roots of all sets.
func (hg *HypergraphCRDT) Commit(
	frameNumber uint64,
) (map[tries.ShardKey][][]byte, error) {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	timer := prometheus.NewTimer(CommitDuration)
	defer timer.ObserveDuration()

	commits, err := hg.store.GetRootCommits(frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "commit")
	}

	ensureSet := func(shardKey tries.ShardKey) {
		if _, ok := commits[shardKey]; !ok {
			commits[shardKey] = make([][]byte, 4)
			commits[shardKey][0] = make([]byte, 64)
			commits[shardKey][1] = make([]byte, 64)
			commits[shardKey][2] = make([]byte, 64)
			commits[shardKey][3] = make([]byte, 64)
		}
	}

	txn, err := hg.store.NewTransaction(false)
	if err != nil {
		return nil, errors.Wrap(err, "commit shard")
	}

	touched := map[tries.ShardKey][]bool{}

	for shardKey, vertexAdds := range hg.vertexAdds {
		if r, ok := commits[shardKey]; ok && len(r[0]) != 64 {
			continue
		}
		root := vertexAdds.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][0] = root

		err = hg.store.SetShardCommit(
			txn,
			frameNumber,
			"adds",
			"vertex",
			shardKey.L2[:],
			root,
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "commit shard")
		}

		touched[shardKey] = make([]bool, 4)
		touched[shardKey][0] = true
	}

	for shardKey, vertexRemoves := range hg.vertexRemoves {
		if r, ok := commits[shardKey]; ok && len(r[1]) != 64 {
			continue
		}
		root := vertexRemoves.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][1] = root

		err = hg.store.SetShardCommit(
			txn,
			frameNumber,
			"removes",
			"vertex",
			shardKey.L2[:],
			root,
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "commit shard")
		}

		if _, ok := touched[shardKey]; !ok {
			touched[shardKey] = make([]bool, 4)
		}
		touched[shardKey][1] = true
	}

	for shardKey, hyperedgeAdds := range hg.hyperedgeAdds {
		if r, ok := commits[shardKey]; ok && len(r[2]) != 64 {
			continue
		}
		root := hyperedgeAdds.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][2] = root

		err = hg.store.SetShardCommit(
			txn,
			frameNumber,
			"adds",
			"hyperedge",
			shardKey.L2[:],
			root,
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "commit shard")
		}

		if _, ok := touched[shardKey]; !ok {
			touched[shardKey] = make([]bool, 4)
		}
		touched[shardKey][2] = true
	}

	for shardKey, hyperedgeRemoves := range hg.hyperedgeRemoves {
		if r, ok := commits[shardKey]; ok && len(r[3]) != 64 {
			continue
		}
		root := hyperedgeRemoves.GetTree().Commit(false)
		ensureSet(shardKey)
		commits[shardKey][3] = root

		err = hg.store.SetShardCommit(
			txn,
			frameNumber,
			"removes",
			"hyperedge",
			shardKey.L2[:],
			root,
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "commit shard")
		}

		if _, ok := touched[shardKey]; !ok {
			touched[shardKey] = make([]bool, 4)
		}
		touched[shardKey][3] = true
	}

	for shardKey, touchSet := range touched {
		if !touchSet[0] {
			err = hg.store.SetShardCommit(
				txn,
				frameNumber,
				"adds",
				"vertex",
				shardKey.L2[:],
				make([]byte, 64),
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "commit shard")
			}
		}
		if !touchSet[1] {
			err = hg.store.SetShardCommit(
				txn,
				frameNumber,
				"removes",
				"vertex",
				shardKey.L2[:],
				make([]byte, 64),
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "commit shard")
			}
		}
		if !touchSet[2] {
			err = hg.store.SetShardCommit(
				txn,
				frameNumber,
				"adds",
				"hyperedge",
				shardKey.L2[:],
				make([]byte, 64),
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "commit shard")
			}
		}
		if !touchSet[3] {
			err = hg.store.SetShardCommit(
				txn,
				frameNumber,
				"removes",
				"hyperedge",
				shardKey.L2[:],
				make([]byte, 64),
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "commit shard")
			}
		}
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
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

	return commits, nil
}

// Commit calculates the sub-scoped vector commitments of each phase set and
// returns the roots of each.
func (hg *HypergraphCRDT) CommitShard(
	frameNumber uint64,
	shardAddress []byte,
) ([][]byte, error) {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	if len(shardAddress) < 32 {
		return nil, errors.Wrap(errors.New("invalid shard address"), "commit shard")
	}

	l1 := up2p.GetBloomFilterIndices(shardAddress[:32], 256, 3)
	shardKey := tries.ShardKey{
		L1: [3]byte(l1),
		L2: [32]byte(shardAddress[:32]),
	}

	vertexAddSet, vertexRemoveSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		"vertex",
		hg.getCoveredPrefix(),
	)
	vertexAddTree := vertexAddSet.GetTree()
	vertexAddTree.Commit(false)
	vertexRemoveTree := vertexRemoveSet.GetTree()
	vertexRemoveTree.Commit(false)

	path := tries.GetFullPath(shardAddress[:32])
	for _, p := range shardAddress[32:] {
		path = append(path, int(p))
	}

	vertexAddNode, err := vertexAddTree.GetByPath(path)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, errors.Wrap(err, "commit shard")
	}

	vertexRemoveNode, err := vertexRemoveTree.GetByPath(path)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, errors.Wrap(err, "commit shard")
	}

	hyperedgeAddSet, hyperedgeRemoveSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		"hyperedge",
		hg.getCoveredPrefix(),
	)
	hyperedgeAddTree := hyperedgeAddSet.GetTree()
	hyperedgeAddTree.Commit(false)
	hyperedgeRemoveTree := hyperedgeRemoveSet.GetTree()
	hyperedgeRemoveTree.Commit(false)

	hyperedgeAddNode, err := vertexAddTree.GetByPath(path)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, errors.Wrap(err, "commit shard")
	}

	hyperedgeRemoveNode, err := vertexRemoveTree.GetByPath(path)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, errors.Wrap(err, "commit shard")
	}

	txn, err := hg.store.NewTransaction(false)
	if err != nil {
		return nil, errors.Wrap(err, "commit shard")
	}

	vertexAddCommit := make([]byte, 64)
	if vertexAddNode != nil {
		switch n := vertexAddNode.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			vertexAddCommit = n.Commitment
		case *tries.LazyVectorCommitmentLeafNode:
			vertexAddCommit = n.Commitment
		}
	}

	vertexRemoveCommit := make([]byte, 64)
	if vertexRemoveNode != nil {
		switch n := vertexRemoveNode.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			vertexRemoveCommit = n.Commitment
		case *tries.LazyVectorCommitmentLeafNode:
			vertexRemoveCommit = n.Commitment
		}
	}

	hyperedgeAddCommit := make([]byte, 64)
	if hyperedgeAddNode != nil {
		switch n := hyperedgeAddNode.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			hyperedgeAddCommit = n.Commitment
		case *tries.LazyVectorCommitmentLeafNode:
			hyperedgeAddCommit = n.Commitment
		}
	}

	hyperedgeRemoveCommit := make([]byte, 64)
	if hyperedgeRemoveNode != nil {
		switch n := hyperedgeRemoveNode.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			hyperedgeRemoveCommit = n.Commitment
		case *tries.LazyVectorCommitmentLeafNode:
			hyperedgeRemoveCommit = n.Commitment
		}
	}

	err = hg.store.SetShardCommit(
		txn,
		frameNumber,
		"adds",
		"vertex",
		shardAddress,
		vertexAddCommit,
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
	}

	err = hg.store.SetShardCommit(
		txn,
		frameNumber,
		"removes",
		"vertex",
		shardAddress,
		vertexRemoveCommit,
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
	}

	err = hg.store.SetShardCommit(
		txn,
		frameNumber,
		"adds",
		"hyperedge",
		shardAddress,
		hyperedgeAddCommit,
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
	}

	err = hg.store.SetShardCommit(
		txn,
		frameNumber,
		"removes",
		"hyperedge",
		shardAddress,
		hyperedgeRemoveCommit,
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
	}

	if err := txn.Commit(); err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "commit shard")
	}

	return [][]byte{
		vertexAddCommit,
		vertexRemoveCommit,
		hyperedgeAddCommit,
		hyperedgeRemoveCommit,
	}, nil
}

// GetShardCommits retries the sub-scoped vector commitments of each phase set
// and returns the commitments of each at the tree level of the shard address.
// If this does not already exist, returns an error.
func (hg *HypergraphCRDT) GetShardCommits(
	frameNumber uint64,
	shardAddress []byte,
) ([][]byte, error) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	vertexAddsCommit, err := hg.store.GetShardCommit(
		frameNumber,
		"adds",
		"vertex",
		shardAddress,
	)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(
				err,
				fmt.Sprintf("shard address: (va) %x", shardAddress),
			),
			"get shard commits",
		)
	}

	vertexRemovesCommit, err := hg.store.GetShardCommit(
		frameNumber,
		"removes",
		"vertex",
		shardAddress,
	)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(
				err,
				fmt.Sprintf("shard address: (vr) %x", shardAddress),
			),
			"get shard commits",
		)
	}

	hyperedgeAddsCommit, err := hg.store.GetShardCommit(
		frameNumber,
		"adds",
		"hyperedge",
		shardAddress,
	)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(
				err,
				fmt.Sprintf("shard address: (ha) %x", shardAddress),
			),
			"get shard commits",
		)
	}

	hyperedgeRemovesCommit, err := hg.store.GetShardCommit(
		frameNumber,
		"removes",
		"hyperedge",
		shardAddress,
	)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(
				err,
				fmt.Sprintf("shard address: (he) %x", shardAddress),
			),
			"get shard commits",
		)
	}

	return [][]byte{
		vertexAddsCommit,
		vertexRemovesCommit,
		hyperedgeAddsCommit,
		hyperedgeRemovesCommit,
	}, nil
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
	root []byte,
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

	var valid bool
	var err error
	if phaseType == hypergraph.AddsPhaseType {
		valid, err = addSet.GetTree().Verify(root, traversalProof)
	} else {
		valid, err = removeSet.GetTree().Verify(root, traversalProof)
	}

	TraversalProofVerifyTotal.WithLabelValues(
		string(atomType),
		string(phaseType),
		boolToString(valid),
	).Inc()
	return valid, err
}
