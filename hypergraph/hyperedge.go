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

type hyperedge struct {
	appAddress  [32]byte
	dataAddress [32]byte
	extTree     *tries.VectorCommitmentTree
}

var _ hypergraph.Hyperedge = (*hyperedge)(nil)

// NewHyperedge creates a new hyperedge with the specified addresses. The
// hyperedge is initialized with an empty extrinsic tree.
func NewHyperedge(
	appAddress [32]byte,
	dataAddress [32]byte,
) hypergraph.Hyperedge {
	return &hyperedge{
		appAddress:  appAddress,
		dataAddress: dataAddress,
		extTree:     &tries.VectorCommitmentTree{},
	}
}

func (h *hyperedge) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], h.appAddress[:])
	copy(id[32:], h.dataAddress[:])
	return id
}

func (h *hyperedge) GetSize() *big.Int {
	leaves, _ := h.extTree.GetMetadata()
	return big.NewInt(int64(leaves))
}

func (h *hyperedge) GetAtomType() hypergraph.AtomType {
	return hypergraph.HyperedgeAtomType
}

func (h *hyperedge) GetAppAddress() [32]byte {
	return h.appAddress
}

func (h *hyperedge) GetDataAddress() [32]byte {
	return h.dataAddress
}

func (h *hyperedge) ToBytes() []byte {
	b, err := tries.SerializeNonLazyTree(h.extTree)
	if err != nil {
		return nil
	}
	return append(
		append(
			append(
				[]byte{0x01},
				h.appAddress[:]...,
			),
			h.dataAddress[:]...,
		),
		b...,
	)
}

func (h *hyperedge) GetExtrinsicTree() *tries.VectorCommitmentTree {
	return h.extTree
}

func (h *hyperedge) AddExtrinsic(a hypergraph.Atom) {
	id := a.GetID()
	h.extTree.Insert(id[:], a.ToBytes(), nil, a.GetSize())
}

func (h *hyperedge) RemoveExtrinsic(a hypergraph.Atom) {
	id := a.GetID()
	h.extTree.Delete(id[:])
}

func (h *hyperedge) Commit(prover crypto.InclusionProver) []byte {
	return h.extTree.Commit(prover, false)
}

// GetHyperedgeExtrinsics retrieves the extrinsics tree of a hyperedge. The
// extrinsics tree contains references to all atoms within the hyperedge.
func (hg *HypergraphCRDT) GetHyperedgeExtrinsics(id [64]byte) (
	*tries.VectorCommitmentTree,
	error,
) {
	he, err := hg.GetHyperedge(id)
	if err != nil {
		return nil, errors.Wrap(err, "get hyperedge extrinsics")
	}

	return he.(*hyperedge).extTree, nil
}

// GetHyperedge retrieves a hyperedge by its ID. Returns ErrRemoved if the
// hyperedge has been removed, or an error if not found.
func (hg *HypergraphCRDT) GetHyperedge(id [64]byte) (
	hypergraph.Hyperedge,
	error,
) {
	hg.mu.RLock()
	defer hg.mu.RUnlock()

	return hg.getHyperedge(id)
}

func (hg *HypergraphCRDT) getHyperedge(id [64]byte) (
	hypergraph.Hyperedge,
	error,
) {
	timer := prometheus.NewTimer(GetDuration.WithLabelValues("hyperedge"))
	defer timer.ObserveDuration()

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	addSet, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)
	if removeSet.Has(id) {
		GetHyperedgeTotal.WithLabelValues("removed").Inc()
		ErrorsTotal.WithLabelValues("get_hyperedge", "removed").Inc()
		return nil, errors.Wrap(hypergraph.ErrRemoved, "get hyperedge")
	}

	n, err := addSet.GetTree().Store.GetNodeByKey(
		addSet.GetTree().SetType,
		addSet.GetTree().PhaseType,
		addSet.GetTree().ShardKey,
		id[:],
	)
	if err != nil {
		GetHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_hyperedge", "not_found").Inc()
		return nil, errors.Wrap(err, "get hyperedge")
	}

	leaf, ok := n.(*tries.LazyVectorCommitmentLeafNode)
	if !ok {
		GetHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_hyperedge", "invalid_location").Inc()
		return nil, errors.Wrap(hypergraph.ErrInvalidLocation, "get hyperedge")
	}

	atom := AtomFromBytes(leaf.Value)
	if atom == nil {
		GetHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_hyperedge", "invalid_atom").Inc()
		return nil, errors.Wrap(hypergraph.ErrInvalidAtomType, "get hyperedge")
	}

	hyperedge, ok := atom.(*hyperedge)
	if !ok {
		GetHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("get_hyperedge", "invalid_atom").Inc()
		return nil, errors.Wrap(hypergraph.ErrInvalidAtomType, "get hyperedge")
	}

	GetHyperedgeTotal.WithLabelValues("success").Inc()
	return hyperedge, nil
}

// AddHyperedge adds a hyperedge to the hypergraph. If the hyperedge has been
// previously removed, it will not be re-added.
func (hg *HypergraphCRDT) AddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	h hypergraph.Hyperedge,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	return hg.addHyperedge(txn, h)
}

func (hg *HypergraphCRDT) addHyperedge(
	txn tries.TreeBackingStoreTransaction,
	h hypergraph.Hyperedge,
) error {
	timer := prometheus.NewTimer(AddHyperedgeDuration)
	defer timer.ObserveDuration()

	shardAddr := hypergraph.GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)
	id := h.GetID()
	if !removeSet.Has(id) {
		err := addSet.Add(txn, h)
		if err != nil {
			AddHyperedgeTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("add_hyperedge", "add_error").Inc()
			return errors.Wrap(err, "add hyperedge")
		}
		hg.size.Add(hg.size, h.GetSize())
		AddHyperedgeTotal.WithLabelValues("success").Inc()
		return nil
	}
	AddHyperedgeTotal.WithLabelValues("success").Inc()
	return nil
}

// RevertAddHyperedge undoes the addition of a hyperedge. This is used for
// rolling back failed transactions.
func (hg *HypergraphCRDT) RevertAddHyperedge(
	txn tries.TreeBackingStoreTransaction,
	h hypergraph.Hyperedge,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	shardAddr := hypergraph.GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)

	id := h.GetID()
	if !addSet.Has(id) {
		RevertAddHyperedgeTotal.WithLabelValues("success").Inc()
		return nil
	}

	if !removeSet.Has(id) {
		err := addSet.Delete(txn, h)
		if err != nil {
			RevertAddHyperedgeTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("revert_add_hyperedge", "delete_error").Inc()
			return errors.Wrap(err, "revert add hyperedge")
		}
		hg.size.Sub(hg.size, h.GetSize())
	}
	RevertAddHyperedgeTotal.WithLabelValues("success").Inc()
	return nil
}

// RemoveHyperedge removes a hyperedge from the hypergraph. In CRDT semantics,
// this adds the hyperedge to the remove set. If the hyperedge doesn't exist,
// it's added to both sets for future conflict resolution.
func (hg *HypergraphCRDT) RemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	h hypergraph.Hyperedge,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	timer := prometheus.NewTimer(RemoveHyperedgeDuration)
	defer timer.ObserveDuration()

	shardKey := hypergraph.GetShardKey(h)
	wasPresent := hg.lookupHyperedge(h.(*hyperedge))
	if !wasPresent {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.hyperedgeAdds,
			hg.hyperedgeRemoves,
			hypergraph.HyperedgeAtomType,
			hg.getCoveredPrefix(),
		)
		if err := addSet.Add(txn, h); err != nil {
			RemoveHyperedgeTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("remove_hyperedge", "add_error").Inc()
			return errors.Wrap(err, "remove hyperedge")
		}

		if err := removeSet.Add(txn, h); err != nil {
			RemoveHyperedgeTotal.WithLabelValues("error").Inc()
			ErrorsTotal.WithLabelValues("remove_hyperedge", "remove_error").Inc()
			return errors.Wrap(err, "remove hyperedge")
		}
		RemoveHyperedgeTotal.WithLabelValues("success").Inc()
		return nil
	}

	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)
	err := removeSet.Add(txn, h)
	if err != nil {
		RemoveHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("remove_hyperedge", "remove_error").Inc()
		return err
	}
	hg.size.Sub(hg.size, h.GetSize())
	RemoveHyperedgeTotal.WithLabelValues("success").Inc()
	return nil
}

// RevertRemoveHyperedge undoes the removal of a hyperedge. This removes the
// hyperedge from the remove set, effectively un-deleting it.
func (hg *HypergraphCRDT) RevertRemoveHyperedge(
	txn tries.TreeBackingStoreTransaction,
	h hypergraph.Hyperedge,
) error {
	hg.mu.Lock()
	defer hg.mu.Unlock()

	shardKey := hypergraph.GetShardKey(h)
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)

	err := removeSet.Delete(txn, h)
	if err != nil {
		RevertRemoveHyperedgeTotal.WithLabelValues("error").Inc()
		ErrorsTotal.WithLabelValues("revert_remove_hyperedge", "delete_error").Inc()
		return err
	}
	hg.size.Add(hg.size, h.GetSize())
	RevertRemoveHyperedgeTotal.WithLabelValues("success").Inc()
	return nil
}

// LookupHyperedge checks if a hyperedge exists in the hypergraph. Returns true
// if the hyperedge is in the add set and not in the remove set.
func (hg *HypergraphCRDT) LookupHyperedge(h hypergraph.Hyperedge) bool {
	hg.mu.RLock()
	defer hg.mu.RUnlock()
	return hg.lookupHyperedge(h)
}

func (hg *HypergraphCRDT) lookupHyperedge(h hypergraph.Hyperedge) bool {
	timer := prometheus.NewTimer(LookupDuration.WithLabelValues("hyperedge"))
	defer timer.ObserveDuration()

	shardAddr := hypergraph.GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		hypergraph.HyperedgeAtomType,
		hg.getCoveredPrefix(),
	)
	id := h.GetID()
	found := addSet.Has(id) && !removeSet.Has(id)
	LookupHyperedgeTotal.WithLabelValues(boolToString(found)).Inc()
	return found
}

// Within checks if atom a is contained within hyperedge h. Returns true if a is
// in the extrinsics tree of h or if a equals h. Also recursively checks nested
// hyperedges.
func (hg *HypergraphCRDT) Within(a, h hypergraph.Atom) bool {
	timer := prometheus.NewTimer(WithinOperationDuration)
	defer timer.ObserveDuration()
	WithinOperationTotal.Inc()

	if he, ok := h.(*hyperedge); ok {
		addr := a.GetID()
		if _, err := he.extTree.Get(addr[:]); err == nil || a.GetID() == h.GetID() {
			return true
		}
		for _, extrinsic := range tries.GetAllPreloadedLeaves(he.extTree.Root) {
			value := AtomFromBytes(extrinsic.Value)
			if value == nil {
				return false
			}
			if nestedHe, ok := value.(*hyperedge); ok {
				if hg.LookupHyperedge(nestedHe) && hg.Within(a, nestedHe) {
					return true
				}
			}
		}
	}

	return false
}
