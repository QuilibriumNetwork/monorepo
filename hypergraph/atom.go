package hypergraph

import (
	"math/big"

	"github.com/prometheus/client_golang/prometheus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// AtomFromBytes deserializes an atom from its byte representation.
// The first byte indicates the type: 0x00 for vertex, anything else for
// hyperedge. Returns nil if the data is invalid.
func AtomFromBytes(data []byte) hypergraph.Atom {
	if len(data) == 0 {
		return nil
	}

	if data[0] == 0x00 {
		// Vertex format: [type(1)][appAddr(32)][dataAddr(32)]
		//                [commitment(var)][size(32)]
		if len(data) < 161 {
			return nil
		}

		return &vertex{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			commitment:  data[65 : len(data)-32],
			size:        new(big.Int).SetBytes(data[len(data)-32:]),
		}
	} else {
		// Hyperedge format: [type(1)][appAddr(32)][dataAddr(32)]
		//                   [tree(var)]
		if len(data) < 65 {
			return nil
		}
		tree, err := tries.DeserializeNonLazyTree(data[65:])
		if err != nil {
			return nil
		}

		// Validate all leaves in the tree
		leaves := tries.GetAllPreloadedLeaves(tree.Root)
		for _, leaf := range leaves {
			if len(leaf.Key) != 64 {
				return nil
			}

			a := AtomFromBytes(leaf.Value)
			if a == nil {
				return nil
			}

			if leaf.Size == nil || leaf.Size.Cmp(a.GetSize()) != 0 {
				return nil
			}
		}

		return &hyperedge{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			extTree:     tree,
		}
	}
}

// LookupAtom checks if an atom (vertex or hyperedge) exists in the hypergraph.
// Dispatches to LookupVertex or LookupHyperedge based on the atom type.
func (hg *HypergraphCRDT) LookupAtom(a hypergraph.Atom) bool {
	timer := prometheus.NewTimer(LookupDuration.WithLabelValues("atom"))
	defer timer.ObserveDuration()

	var atomType string
	var found bool

	switch v := a.(type) {
	case *vertex:
		atomType = "vertex"
		found = hg.LookupVertex(v)
	case *hyperedge:
		atomType = "hyperedge"
		found = hg.LookupHyperedge(v)
	default:
		atomType = "unknown"
		found = false
	}

	LookupAtomTotal.WithLabelValues(atomType, boolToString(found)).Inc()
	return found
}

// LookupAtomSet checks if all atoms in a set exist in the hypergraph. Returns
// true only if all atoms are present.
func (hg *HypergraphCRDT) LookupAtomSet(atomSet []hypergraph.Atom) bool {
	for _, atom := range atomSet {
		if !hg.LookupAtom(atom) {
			return false
		}
	}
	return true
}
