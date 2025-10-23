package hypergraph

import (
	"math/big"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// HypergraphCRDT implements a CRDT-based 2P2P-Hypergraph. It maintains separate
// sets for additions and removals of vertices and hyperedges, allowing for
// conflict-free merging in distributed systems.
//
// The underlying trees have their own locks, but are atomic – the lock is taken
// on single mutations and reads. While the IdSet exposes the trees for methods
// where direct access is critical, like hypersync, do _not_ expect you will
// be safe using the tree directly.
type HypergraphCRDT struct {
	protobufs.UnsafeHypergraphComparisonServiceServer

	logger *zap.Logger
	// size tracks the total size of the hypergraph (adds - removes)
	size *big.Int
	// vertexAdds maps shard keys to sets of added vertices
	vertexAdds map[tries.ShardKey]hypergraph.IdSet
	// vertexRemoves maps shard keys to sets of removed vertices
	vertexRemoves map[tries.ShardKey]hypergraph.IdSet
	// hyperedgeAdds maps shard keys to sets of added hyperedges
	hyperedgeAdds map[tries.ShardKey]hypergraph.IdSet
	// hyperedgeRemoves maps shard keys to sets of removed hyperedges
	hyperedgeRemoves map[tries.ShardKey]hypergraph.IdSet
	// store provides persistence for the hypergraph data
	store tries.TreeBackingStore
	// prover generates cryptographic inclusion proofs
	prover crypto.InclusionProver
	// the limited prefix of paths we will accept data insertions for
	coveredPrefix []int

	// handles locking scenarios for transactions
	syncController *hypergraph.SyncController
	mu             sync.RWMutex

	// provides context-driven info for client identification
	authenticationProvider channel.AuthenticationProvider
}

var _ hypergraph.Hypergraph = (*HypergraphCRDT)(nil)
var _ protobufs.HypergraphComparisonServiceServer = (*HypergraphCRDT)(nil)

// NewHypergraph creates a new CRDT-based hypergraph. The store provides
// persistence and the prover operates over the underlying vector commitment
// trees backing the sets.
func NewHypergraph(
	logger *zap.Logger,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
	coveredPrefix []int,
	authenticationProvider channel.AuthenticationProvider,
) *HypergraphCRDT {
	return &HypergraphCRDT{
		logger:                 logger,
		size:                   big.NewInt(0),
		vertexAdds:             make(map[tries.ShardKey]hypergraph.IdSet),
		vertexRemoves:          make(map[tries.ShardKey]hypergraph.IdSet),
		hyperedgeAdds:          make(map[tries.ShardKey]hypergraph.IdSet),
		hyperedgeRemoves:       make(map[tries.ShardKey]hypergraph.IdSet),
		store:                  store,
		prover:                 prover,
		coveredPrefix:          coveredPrefix,
		authenticationProvider: authenticationProvider,
		syncController:         hypergraph.NewSyncController(),
	}
}

// NewTransaction creates a new transaction for atomic operations.
func (hg *HypergraphCRDT) NewTransaction(indexed bool) (
	tries.TreeBackingStoreTransaction,
	error,
) {
	timer := prometheus.NewTimer(
		TransactionDuration.WithLabelValues(boolToString(indexed)),
	)
	defer timer.ObserveDuration()

	txn, err := hg.store.NewTransaction(indexed)
	if err != nil {
		TransactionTotal.WithLabelValues(boolToString(indexed), "error").Inc()
		return nil, err
	}

	TransactionTotal.WithLabelValues(boolToString(indexed), "success").Inc()
	return txn, nil
}

// GetProver returns the inclusion prover used by this hypergraph.
func (hg *HypergraphCRDT) GetProver() crypto.InclusionProver {
	return hg.prover
}

// ImportTree imports an existing commitment tree into the hypergraph. This is
// used to load pre-existing hypergraph data from persistent storage. The
// atomType and phaseType determine which set the tree is imported into.
func (hg *HypergraphCRDT) ImportTree(
	atomType hypergraph.AtomType,
	phaseType hypergraph.PhaseType,
	shardKey tries.ShardKey,
	root tries.LazyVectorCommitmentNode,
	store tries.TreeBackingStore,
	prover crypto.InclusionProver,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	timer := prometheus.NewTimer(ImportTreeDuration)
	defer timer.ObserveDuration()

	set := NewIdSet(
		atomType,
		phaseType,
		shardKey,
		store,
		prover,
		root,
		hg.getCoveredPrefix(),
	)

	treeSize := set.GetSize()
	size, _ := treeSize.Float64()
	ImportTreeSize.Observe(size)

	switch atomType {
	case hypergraph.VertexAtomType:
		switch phaseType {
		case hypergraph.AddsPhaseType:
			hg.size.Add(hg.size, treeSize)
			hg.vertexAdds[shardKey] = set
		case hypergraph.RemovesPhaseType:
			hg.size.Sub(hg.size, treeSize)
			hg.vertexRemoves[shardKey] = set
		}
	case hypergraph.HyperedgeAtomType:
		switch phaseType {
		case hypergraph.AddsPhaseType:
			hg.size.Add(hg.size, treeSize)
			hg.hyperedgeAdds[shardKey] = set
		case hypergraph.RemovesPhaseType:
			hg.size.Sub(hg.size, treeSize)
			hg.hyperedgeRemoves[shardKey] = set
		}
	}

	ImportTreeTotal.WithLabelValues(
		string(atomType),
		string(phaseType),
		"success",
	).Inc()
	return nil
}

// GetSize returns the current total size of the hypergraph. The size is
// calculated as the sum of all added atoms' data minus removed atoms (note:
// removed meaning removed from a set, not the atoms in remove sets).
func (hg *HypergraphCRDT) GetSize(
	shardKey *tries.ShardKey,
	path []int,
) *big.Int {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	if shardKey == nil {
		sk := tries.ShardKey{
			L1: [3]byte{0, 0, 0},
			L2: [32]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
		}
		vas := hg.getVertexAddsSet(sk)
		has := hg.getHyperedgeAddsSet(sk)
		vrs := hg.getVertexRemovesSet(sk)
		hrs := hg.getHyperedgeRemovesSet(sk)
		size := new(big.Int).Set(hg.size)
		size = size.Sub(
			size,
			new(big.Int).Add(
				new(big.Int).Add(vas.GetSize(), has.GetSize()),
				new(big.Int).Add(vrs.GetSize(), hrs.GetSize()),
			),
		)

		return size
	}

	vas := hg.getVertexAddsSet(*shardKey)
	has := hg.getHyperedgeAddsSet(*shardKey)
	vrs := hg.getVertexRemovesSet(*shardKey)
	hrs := hg.getHyperedgeRemovesSet(*shardKey)

	if len(path) == 0 {
		return new(big.Int).Add(
			new(big.Int).Add(vas.GetSize(), has.GetSize()),
			new(big.Int).Add(vrs.GetSize(), hrs.GetSize()),
		)
	} else {
		sum := big.NewInt(0)
		n, _ := vas.GetTree().GetByPath(path)

		if n != nil {
			sum = sum.Add(sum, n.GetSize())
		}

		o, _ := has.GetTree().GetByPath(path)

		if o != nil {
			sum = sum.Add(sum, o.GetSize())
		}

		p, _ := vrs.GetTree().GetByPath(path)

		if p != nil {
			sum = sum.Add(sum, o.GetSize())
		}

		q, _ := hrs.GetTree().GetByPath(path)
		if q != nil {
			sum = sum.Add(sum, o.GetSize())
		}

		return sum
	}
}

// TrackChange marks a change for historical notation
func (hg *HypergraphCRDT) TrackChange(
	txn tries.TreeBackingStoreTransaction,
	key []byte,
	oldValue *tries.VectorCommitmentTree,
	frameNumber uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	return hg.store.TrackChange(
		txn,
		key,
		oldValue,
		frameNumber,
		phaseType,
		setType,
		shardKey,
	)
}

// GetChanges returns the series of changes between frames, in reverse
// chronological order.
func (hg *HypergraphCRDT) GetChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) ([]*tries.ChangeRecord, error) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	return hg.getChanges(
		frameStart,
		frameEnd,
		phaseType,
		setType,
		shardKey,
	)
}

func (hg *HypergraphCRDT) getChanges(
	frameStart uint64,
	frameEnd uint64,
	phaseType string,
	setType string,
	shardKey tries.ShardKey,
) ([]*tries.ChangeRecord, error) {
	return hg.store.GetChanges(
		frameStart,
		frameEnd,
		phaseType,
		setType,
		shardKey,
	)
}

// RevertChanges reverts the series of changes between frames, in reverse
// chronological order.
func (hg *HypergraphCRDT) RevertChanges(
	txn tries.TreeBackingStoreTransaction,
	frameStart uint64,
	frameEnd uint64,
	shardKey tries.ShardKey,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	// Genesis cannot be reverted
	if frameStart == 0 {
		frameStart = 1
	}

	// Get all changes for the frame range
	vertexAdds, err := hg.getChanges(
		frameStart,
		frameEnd,
		string(hypergraph.AddsPhaseType),
		string(hypergraph.VertexAtomType),
		shardKey,
	)
	if err != nil {
		return errors.Wrap(err, "revert changes")
	}

	vertexRemoves, err := hg.getChanges(
		frameStart,
		frameEnd,
		string(hypergraph.RemovesPhaseType),
		string(hypergraph.VertexAtomType),
		shardKey,
	)
	if err != nil {
		return errors.Wrap(err, "revert changes")
	}

	hyperedgeAdds, err := hg.getChanges(
		frameStart,
		frameEnd,
		string(hypergraph.AddsPhaseType),
		string(hypergraph.HyperedgeAtomType),
		shardKey,
	)
	if err != nil {
		return errors.Wrap(err, "revert changes")
	}

	hyperedgeRemoves, err := hg.getChanges(
		frameStart,
		frameEnd,
		string(hypergraph.RemovesPhaseType),
		string(hypergraph.HyperedgeAtomType),
		shardKey,
	)
	if err != nil {
		return errors.Wrap(err, "revert changes")
	}

	// Create maps indexed by frame number for efficient lookup
	vertexAddsMap := make(map[uint64][]*tries.ChangeRecord)
	vertexRemovesMap := make(map[uint64][]*tries.ChangeRecord)
	hyperedgeAddsMap := make(map[uint64][]*tries.ChangeRecord)
	hyperedgeRemovesMap := make(map[uint64][]*tries.ChangeRecord)

	for _, change := range vertexAdds {
		change := change
		vertexAddsMap[change.Frame] = append(vertexAddsMap[change.Frame], change)
	}

	for _, change := range vertexRemoves {
		change := change
		vertexRemovesMap[change.Frame] = append(
			vertexRemovesMap[change.Frame],
			change,
		)
	}

	for _, change := range hyperedgeAdds {
		change := change
		hyperedgeAddsMap[change.Frame] = append(
			hyperedgeAddsMap[change.Frame],
			change,
		)
	}

	for _, change := range hyperedgeRemoves {
		change := change
		hyperedgeRemovesMap[change.Frame] = append(
			hyperedgeRemovesMap[change.Frame],
			change,
		)
	}

	// Process frames in descending order
	for frame := frameEnd; frame >= frameStart; frame-- {
		// Revert hyperedge removes for this frame
		if hrs, ok := hyperedgeRemovesMap[frame]; ok {
			for _, change := range hrs {
				// Remove from the hyperedge removes tree
				err = hg.hyperedgeRemoves[shardKey].GetTree().Delete(txn, change.Key)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}

				// Clean up change record
				err = hg.store.UntrackChange(
					txn,
					change.Key,
					frame,
					string(hypergraph.RemovesPhaseType),
					string(hypergraph.HyperedgeAtomType),
					shardKey,
				)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}
			}
		}

		// Revert vertex removes for this frame
		if vrs, ok := vertexRemovesMap[frame]; ok {
			for _, change := range vrs {
				// Remove from the vertex removes tree
				err = hg.vertexRemoves[shardKey].GetTree().Delete(txn, change.Key)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}

				// Clean up change record
				err = hg.store.UntrackChange(
					txn,
					change.Key,
					frame,
					string(hypergraph.RemovesPhaseType),
					string(hypergraph.VertexAtomType),
					shardKey,
				)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}
			}
		}

		// Revert hyperedge adds for this frame
		if has, ok := hyperedgeAddsMap[frame]; ok {
			for _, change := range has {
				// Restore the previous hyperedge extrinsic value
				if change.OldValue != nil {
					// Update the hyperedge adds tree with the old value
					err = hg.addHyperedge(txn, &hyperedge{
						appAddress:  [32]byte(change.Key[:32]),
						dataAddress: [32]byte(change.Key[32:]),
						extTree:     change.OldValue,
					})
					if err != nil {
						return errors.Wrap(err, "revert changes")
					}
				} else {
					// If nil, this was the first add
					err = hg.hyperedgeAdds[shardKey].GetTree().Delete(txn, change.Key)
					if err != nil {
						return errors.Wrap(err, "revert changes")
					}
				}

				// Clean up change record
				err = hg.store.UntrackChange(
					txn,
					change.Key,
					frame,
					string(hypergraph.AddsPhaseType),
					string(hypergraph.HyperedgeAtomType),
					shardKey,
				)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}
			}
		}

		// Revert vertex adds for this frame
		if vas, ok := vertexAddsMap[frame]; ok {
			for _, change := range vas {
				// Restore the previous vertex value
				if change.OldValue != nil {
					// Update the vertex adds with the old value
					err = hg.addVertex(txn, NewVertex(
						[32]byte(change.Key[:32]),
						[32]byte(change.Key[32:]),
						change.OldValue.Commit(hg.GetProver(), false),
						change.OldValue.GetSize(),
					))
					if err != nil {
						return errors.Wrap(err, "revert changes")
					}
				} else {
					// If nil, this was the first add
					err = hg.vertexAdds[shardKey].GetTree().Delete(txn, change.Key)
					if err != nil {
						return errors.Wrap(err, "revert changes")
					}
				}

				// Clean up change record
				err = hg.store.UntrackChange(
					txn,
					change.Key,
					frame,
					string(hypergraph.AddsPhaseType),
					string(hypergraph.VertexAtomType),
					shardKey,
				)
				if err != nil {
					return errors.Wrap(err, "revert changes")
				}
			}
		}
	}

	return nil
}

// GetMetadataAtKey is a fast path to retrieve metadata information used for
// consensus, avoiding unnecessary recomputation for lookups.
func (hg *HypergraphCRDT) GetMetadataAtKey(pathKey []byte) (
	[]hypergraph.ShardMetadata,
	error,
) {
	hg.mu.Lock()
	defer hg.mu.Unlock()
	if len(pathKey) < 32 {
		return nil, errors.Wrap(
			hypergraph.ErrInvalidLocation,
			"get metadata at key",
		)
	}

	l1 := up2p.GetBloomFilterIndices(pathKey[:32], 256, 3)
	shardKey := tries.ShardKey{
		L1: [3]byte(l1),
		L2: [32]byte(pathKey[:32]),
	}
	vertexAdds, vertexRemoves := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		hypergraph.VertexAtomType,
		hg.coveredPrefix,
	)
	hyperedgeAdds, hyperedgeRemoves := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.coveredPrefix,
	)

	metadata := []hypergraph.ShardMetadata{}
	ipath := tries.GetFullPath(pathKey[:32])
	path := []int{}
	for _, p := range ipath {
		path = append(path, int(p))
	}
	for _, p := range pathKey[32:] {
		path = append(path, int(p))
	}

	for _, set := range []hypergraph.IdSet{
		vertexAdds,
		vertexRemoves,
		hyperedgeAdds,
		hyperedgeRemoves,
	} {
		node, err := set.GetTree().Store.GetNodeByPath(
			set.GetTree().SetType,
			set.GetTree().PhaseType,
			shardKey,
			path,
		)
		if err != nil {
			metadata = append(metadata, hypergraph.ShardMetadata{
				Commitment: make([]byte, 64),
				LeafCount:  0,
				Size:       0,
			})
			continue
		}
		if node != nil {
			switch t := node.(type) {
			case *tries.LazyVectorCommitmentBranchNode:
				metadata = append(metadata, hypergraph.ShardMetadata{
					Commitment: t.Commitment,
					LeafCount:  uint64(t.LeafCount),
					Size:       t.Size.Uint64(),
				})
			case *tries.LazyVectorCommitmentLeafNode:
				metadata = append(metadata, hypergraph.ShardMetadata{
					Commitment: t.Commitment,
					LeafCount:  1,
					Size:       t.Size.Uint64(),
				})
			}
		} else {
			metadata = append(metadata, hypergraph.ShardMetadata{
				Commitment: make([]byte, 64),
				LeafCount:  0,
				Size:       0,
			})
		}
	}

	return metadata, nil
}

// boolToString converts a boolean to string for Prometheus labels.
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
