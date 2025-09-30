package global

import (
	"bytes"

	"github.com/pkg/errors"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// UpdateAggregateProverStatus updates the prover status based on the aggregate
// status of all allocations
func UpdateAggregateProverStatus(
	hg *hgstate.HypergraphState,
	proverAddress []byte,
	frameNumber uint64,
	proverTree *tries.VectorCommitmentTree,
	rdfMultiprover *schema.RDFMultiprover,
) error {
	// Get the hyperedge to check all allocations
	hyperedgeAddress := [64]byte{}
	copy(hyperedgeAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(hyperedgeAddress[32:], proverAddress)

	hyperedge, err := hg.Get(
		hyperedgeAddress[:32],
		hyperedgeAddress[32:],
		hgstate.HyperedgeAddsDiscriminator,
	)
	if err != nil || hyperedge == nil {
		// No hyperedge means no allocations, prover should be left (4)
		return rdfMultiprover.Set(
			GLOBAL_RDF_SCHEMA,
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			"prover:Prover",
			"Status",
			[]byte{4},
			proverTree,
		)
	}

	// Check all allocations to determine aggregate status
	hasActive := false
	hasJoining := false
	hasLeaving := false
	hasPaused := false

	// Get all vertices from the hyperedge
	he, ok := hyperedge.(hypergraph.Hyperedge)
	if !ok {
		return errors.Wrap(
			errors.New("invalid object returned for hyperedge"),
			"update aggregate prover status",
		)
	}

	vertices := tries.GetAllPreloadedLeaves(he.GetExtrinsicTree().Root)
	if err == nil && len(vertices) > 0 {
		for _, vertex := range vertices {
			allocationFullAddress := vertex.Key

			if !bytes.Equal(
				allocationFullAddress[:32],
				intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			) {
				return errors.Wrap(
					errors.New("hyperedge includes non prover allocation vertex"),
					"update aggregate prover status",
				)
			}

			// Get allocation vertex
			allocationTree, err := hg.Get(
				allocationFullAddress[:32],
				allocationFullAddress[32:],
				hgstate.VertexAddsDiscriminator,
			)
			if err != nil || allocationTree == nil {
				continue
			}
			var tree *tries.VectorCommitmentTree
			var ok bool
			tree, ok = allocationTree.(*tries.VectorCommitmentTree)
			if !ok || tree == nil {
				return errors.Wrap(
					errors.New("invalid object returned for vertex"),
					"update aggregate prover status",
				)
			}

			// Check allocation status
			allocStatusBytes, err := rdfMultiprover.Get(
				GLOBAL_RDF_SCHEMA,
				"allocation:ProverAllocation",
				"Status",
				tree,
			)
			if err == nil && len(allocStatusBytes) > 0 {
				switch allocStatusBytes[0] {
				case 0:
					hasJoining = true
				case 1:
					hasActive = true
				case 2:
					hasPaused = true
				case 3:
					hasLeaving = true
					// case 4 (left) is ignored for aggregate calculation
				}
			}
		}
	}

	// Determine aggregate prover status based on allocation statuses
	// Priority order: active > joining > leaving > paused > left
	var newProverStatus byte
	if hasActive {
		newProverStatus = 1 // Active if any allocation is active or some are paused
	} else if hasJoining {
		newProverStatus = 0 // Joining if any allocation is joining
	} else if hasLeaving {
		newProverStatus = 3 // Leaving if any allocation is leaving
	} else if hasPaused {
		newProverStatus = 2 // Paused if all allocations are paused
	} else {
		newProverStatus = 4 // Left if all allocations are left
	}

	// Update prover status
	err = rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Status",
		[]byte{newProverStatus},
		proverTree,
	)
	if err != nil {
		return errors.Wrap(err, "update aggregate prover status")
	}

	var prior *tries.VectorCommitmentTree
	existingRecord, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		proverAddress,
		hgstate.VertexAddsDiscriminator,
	)
	if err != nil {
		prior = existingRecord.(*tries.VectorCommitmentTree)
	}

	// Update prover vertex
	proverVertex := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(proverAddress),
		frameNumber,
		prior,
		proverTree,
	)

	err = hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		proverAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		proverVertex,
	)
	if err != nil {
		return errors.Wrap(err, "update aggregate prover status")
	}

	return nil
}
