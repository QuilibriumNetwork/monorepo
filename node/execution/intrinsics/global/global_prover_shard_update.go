package global

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"slices"
	"sort"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

const (
	ringGroupSize      = 8
	defaultShardLeaves = 1
	rewardUnits        = 8_000_000_000
)

type ProverShardUpdate struct {
	FrameHeader *protobufs.FrameHeader

	// Private dependencies
	keyManager     keys.KeyManager
	hypergraph     hypergraph.Hypergraph
	rdfMultiprover *schema.RDFMultiprover
	frameProver    crypto.FrameProver
	rewardIssuance consensus.RewardIssuance
	proverRegistry consensus.ProverRegistry
	blsConstructor crypto.BlsConstructor
}

func NewProverShardUpdate(
	frameHeader *protobufs.FrameHeader,
	keyManager keys.KeyManager,
	hypergraph hypergraph.Hypergraph,
	rdfMultiprover *schema.RDFMultiprover,
	frameProver crypto.FrameProver,
	rewardIssuance consensus.RewardIssuance,
	proverRegistry consensus.ProverRegistry,
	blsConstructor crypto.BlsConstructor,
) (*ProverShardUpdate, error) {
	return &ProverShardUpdate{
		FrameHeader:    frameHeader,
		keyManager:     keyManager,
		hypergraph:     hypergraph,
		rdfMultiprover: rdfMultiprover,
		frameProver:    frameProver,
		rewardIssuance: rewardIssuance,
		proverRegistry: proverRegistry,
		blsConstructor: blsConstructor,
	}, nil
}

func (p *ProverShardUpdate) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

func (p *ProverShardUpdate) Prove(uint64) error {
	// This intrinsic is applied post-consensus confirmation and self contains
	// a proof
	return nil
}

func (p *ProverShardUpdate) Verify(frameNumber uint64) (bool, error) {
	_, err := p.buildContext()
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if frameNumber != p.FrameHeader.FrameNumber+1 {
		return false, errors.Wrap(errors.New("invalid update"), "verify")
	}

	_, err = p.frameProver.VerifyFrameHeader(p.FrameHeader, p.blsConstructor)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	return true, nil
}

func (p *ProverShardUpdate) GetReadAddresses(uint64) ([][]byte, error) {
	return nil, nil
}

func (p *ProverShardUpdate) GetWriteAddresses(uint64) ([][]byte, error) {
	ctx, err := p.buildContext()
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	addressSet := map[string][]byte{}
	for _, idx := range ctx.participantIndices {
		prover := ctx.activeProvers[idx]

		rewardKey, err := p.rewardAddress(prover.Address)
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}
		rewardAddr := compositeAddress(
			intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			rewardKey,
		)
		addressSet[string(rewardAddr)] = rewardAddr

		allocationAddr, err := p.allocationAddress(prover, p.FrameHeader.Address)
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}
		addressSet[string(allocationAddr[:])] = allocationAddr[:]
	}

	addresses := make([][]byte, 0, len(addressSet))
	for _, addr := range addressSet {
		addresses = append(addresses, slices.Clone(addr))
	}
	return addresses, nil
}

func (p *ProverShardUpdate) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hg, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid state type for shard update"),
			"materialize",
		)
	}

	ctx, err := p.buildContext()
	if err != nil {
		return nil, err
	}

	worldSize := p.hypergraph.GetSize(nil, nil).Uint64()
	rewardsPerRing := make(map[uint8]*big.Int, len(ctx.participantsByRing))

	for ring, participants := range ctx.participantsByRing {
		alloc := map[string]*consensus.ProverAllocation{
			string(p.FrameHeader.Address): {
				Ring:      ring,
				Shards:    ctx.shardCount,
				StateSize: ctx.stateSize,
			},
		}
		outputs, err := p.rewardIssuance.Calculate(
			uint64(p.FrameHeader.Difficulty),
			worldSize,
			rewardUnits,
			[]map[string]*consensus.ProverAllocation{alloc},
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
		if len(outputs) != 1 {
			return nil, errors.Wrap(
				errors.New("unexpected reward issuance output size"),
				"materialize",
			)
		}
		if len(participants) == 0 {
			continue
		}

		share := new(big.Int).Set(outputs[0])
		share.Div(share, big.NewInt(int64(len(participants))))
		rewardsPerRing[ring] = share
	}

	for ring, participants := range ctx.participantsByRing {
		share := rewardsPerRing[ring]
		for _, idx := range participants {
			prover := ctx.activeProvers[idx]
			if err := p.applyReward(
				hg,
				frameNumber,
				prover,
				p.FrameHeader.Address,
				share,
			); err != nil {
				return nil, errors.Wrap(err, "materalize")
			}

			if err := p.updateAllocationActivity(
				hg,
				frameNumber,
				prover,
				p.FrameHeader.Address,
			); err != nil {
				return nil, errors.Wrap(err, "materalize")
			}
		}
	}

	return state, nil
}

type shardUpdateContext struct {
	activeProvers       []*consensus.ProverInfo
	participantIndices  []int
	participantsByRing  map[uint8][]int
	ringByProverAddress map[string]uint8
	stateSize           uint64
	shardCount          uint64
}

func (p *ProverShardUpdate) buildContext() (*shardUpdateContext, error) {
	if p.frameProver == nil {
		return nil, errors.New("frame prover dependency missing")
	}
	if p.rewardIssuance == nil {
		return nil, errors.New("reward issuance dependency missing")
	}
	if p.proverRegistry == nil {
		return nil, errors.New("prover registry dependency missing")
	}
	if p.blsConstructor == nil {
		return nil, errors.New("bls constructor dependency missing")
	}
	if p.hypergraph == nil {
		return nil, errors.New("hypergraph dependency missing")
	}
	if p.rdfMultiprover == nil {
		return nil, errors.New("rdf multiprover dependency missing")
	}
	if len(p.FrameHeader.Address) < 32 {
		return nil, errors.New("filter length insufficient")
	}
	if p.FrameHeader == nil {
		return nil, errors.New("frame header is nil")
	}
	if len(p.FrameHeader.Address) == 0 {
		return nil, errors.New("frame header missing address")
	}

	setIndices, err := p.frameProver.VerifyFrameHeader(
		p.FrameHeader,
		p.blsConstructor,
	)
	if err != nil {
		return nil, errors.Wrap(err, "verify frame header")
	}
	if len(setIndices) == 0 {
		return nil, errors.New("frame header signature bitmask empty")
	}

	activeProvers, err := p.proverRegistry.GetActiveProvers(p.FrameHeader.Address)
	if err != nil {
		return nil, errors.Wrap(err, "get active provers")
	}
	if len(activeProvers) == 0 {
		return nil, errors.New("no active provers for shard")
	}

	participantsSet := map[int]struct{}{}
	for _, idx := range setIndices {
		if int(idx) >= len(activeProvers) {
			return nil, errors.New("bitmask index exceeds active prover count")
		}
		participantsSet[int(idx)] = struct{}{}
	}

	if len(participantsSet)*3 < len(activeProvers)*2 {
		return nil, errors.New("insufficient prover participation (< 2/3)")
	}

	participantIndices := make([]int, 0, len(participantsSet))
	for idx := range participantsSet {
		participantIndices = append(participantIndices, idx)
	}
	sort.Ints(participantIndices)

	ringByAddress, err := p.computeRingAssignments(activeProvers)
	if err != nil {
		return nil, err
	}

	participantsByRing := make(map[uint8][]int)
	for _, idx := range participantIndices {
		prover := activeProvers[idx]
		ring := ringByAddress[string(prover.Address)]
		participantsByRing[ring] = append(participantsByRing[ring], idx)
	}

	metadata, err := p.hypergraph.GetMetadataAtKey(p.FrameHeader.Address)
	if err != nil {
		return nil, errors.Wrap(err, "get hypergraph metadata")
	}
	if len(metadata) == 0 {
		return nil, errors.New("missing hypergraph metadata for shard")
	}

	stateSize := metadata[0].Size
	shardCount := metadata[0].LeafCount
	if shardCount == 0 {
		shardCount = defaultShardLeaves
	}

	return &shardUpdateContext{
		activeProvers:       activeProvers,
		participantIndices:  participantIndices,
		participantsByRing:  participantsByRing,
		ringByProverAddress: ringByAddress,
		stateSize:           stateSize,
		shardCount:          shardCount,
	}, nil
}

func (p *ProverShardUpdate) computeRingAssignments(
	activeProvers []*consensus.ProverInfo,
) (map[string]uint8, error) {
	type candidate struct {
		index      int
		joinFrame  uint64
		seniority  uint64
		address    []byte
		confirmSet bool
	}

	candidates := make([]candidate, len(activeProvers))
	for i, prover := range activeProvers {
		allocation, err := allocationForFilter(prover, p.FrameHeader.Address)
		if err != nil {
			return nil, err
		}

		joinFrame := allocation.JoinFrameNumber
		if joinFrame == 0 && allocation.JoinConfirmFrameNumber != 0 {
			joinFrame = allocation.JoinConfirmFrameNumber
		}

		candidates[i] = candidate{
			index:      i,
			joinFrame:  joinFrame,
			seniority:  prover.Seniority,
			address:    prover.Address,
			confirmSet: allocation.JoinConfirmFrameNumber != 0,
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].joinFrame != candidates[j].joinFrame {
			return candidates[i].joinFrame < candidates[j].joinFrame
		}
		if candidates[i].seniority != candidates[j].seniority {
			return candidates[i].seniority > candidates[j].seniority
		}
		return bytes.Compare(candidates[i].address, candidates[j].address) < 0
	})

	ringAssignments := make(map[string]uint8, len(candidates))
	for rank, candidate := range candidates {
		ring := uint8(math.Floor(float64(rank) / ringGroupSize))
		ringAssignments[string(candidate.address)] = ring
	}

	return ringAssignments, nil
}

func (p *ProverShardUpdate) applyReward(
	hg *hgstate.HypergraphState,
	frameNumber uint64,
	prover *consensus.ProverInfo,
	filter []byte,
	share *big.Int,
) error {
	if share == nil || share.Sign() == 0 {
		// Nothing to distribute for this prover
		return nil
	}

	rewardAddress, err := p.rewardAddress(prover.Address)
	if err != nil {
		return errors.Wrap(err, "derive reward address")
	}

	priorVertex, _ := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		rewardAddress,
		hgstate.VertexAddsDiscriminator,
	)

	var priorTree *tries.VectorCommitmentTree
	if priorVertex != nil {
		existing, ok := priorVertex.(*tries.VectorCommitmentTree)
		if !ok {
			return errors.New("invalid reward vertex type")
		}
		priorTree = existing
	}

	updateVertex, _ := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		rewardAddress,
		hgstate.VertexAddsDiscriminator,
	)

	var updateTree *tries.VectorCommitmentTree
	if updateVertex != nil {
		existing, ok := updateVertex.(*tries.VectorCommitmentTree)
		if !ok {
			return errors.New("invalid reward vertex type")
		}
		updateTree = existing
	}

	var rewardTree *tries.VectorCommitmentTree
	if priorTree != nil {
		rewardTree = updateTree
	} else {
		rewardTree = &tries.VectorCommitmentTree{}
	}

	currentBalanceBytes, err := p.rdfMultiprover.Get(
		GLOBAL_RDF_SCHEMA,
		"reward:ProverReward",
		"Balance",
		priorTree,
	)
	if err != nil {
		return errors.Wrap(err, "get reward balance")
	}

	currentBalance := new(big.Int).SetBytes(currentBalanceBytes)
	currentBalance.Add(currentBalance, share)

	balanceBytes := make([]byte, 32)
	currentBalance.FillBytes(balanceBytes)

	if err := p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"reward:ProverReward",
		"Balance",
		balanceBytes,
		rewardTree,
	); err != nil {
		return errors.Wrap(err, "set reward balance")
	}

	vertex := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		[32]byte(rewardAddress),
		frameNumber,
		priorTree,
		rewardTree,
	)

	if err := hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		rewardAddress,
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		vertex,
	); err != nil {
		return errors.Wrap(err, "set reward vertex")
	}

	return nil
}

func (p *ProverShardUpdate) updateAllocationActivity(
	hg *hgstate.HypergraphState,
	frameNumber uint64,
	prover *consensus.ProverInfo,
	filter []byte,
) error {
	allocationAddr, err := p.allocationAddress(prover, filter)
	if err != nil {
		return err
	}

	priorVertex, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddr[:],
		hgstate.VertexAddsDiscriminator,
	)

	var priorTree *tries.VectorCommitmentTree
	if priorVertex != nil {
		existing, ok := priorVertex.(*tries.VectorCommitmentTree)
		if !ok {
			return errors.New("invalid allocation vertex type")
		}
		priorTree = existing
	}

	updateVertex, err := hg.Get(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddr[:],
		hgstate.VertexAddsDiscriminator,
	)

	var allocationTree *tries.VectorCommitmentTree
	if priorTree != nil {
		allocationTree = updateVertex.(*tries.VectorCommitmentTree)
	} else {
		allocationTree = &tries.VectorCommitmentTree{}
	}

	frameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameBytes, frameNumber)

	if err := p.rdfMultiprover.Set(
		GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LastActiveFrameNumber",
		frameBytes,
		allocationTree,
	); err != nil {
		return errors.Wrap(err, "set allocation activity frame")
	}

	vertex := hg.NewVertexAddMaterializedState(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS,
		allocationAddr,
		frameNumber,
		priorTree,
		allocationTree,
	)

	if err := hg.Set(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		allocationAddr[:],
		hgstate.VertexAddsDiscriminator,
		frameNumber,
		vertex,
	); err != nil {
		return errors.Wrap(err, "set allocation vertex")
	}

	return nil
}

func (p *ProverShardUpdate) rewardAddress(
	proverAddress []byte,
) ([]byte, error) {
	hash, err := poseidon.HashBytes(
		slices.Concat(token.QUIL_TOKEN_ADDRESS[:], proverAddress),
	)
	if err != nil {
		return nil, err
	}
	return hash.FillBytes(make([]byte, 32)), nil
}

func (p *ProverShardUpdate) allocationAddress(
	prover *consensus.ProverInfo,
	filter []byte,
) ([32]byte, error) {
	allocation := [32]byte{}
	hashInput := slices.Concat(
		[]byte("PROVER_ALLOCATION"),
		prover.PublicKey,
		filter,
	)
	hash, err := poseidon.HashBytes(hashInput)
	if err != nil {
		return allocation, errors.Wrap(err, "hash allocation address")
	}
	copy(allocation[:], hash.FillBytes(make([]byte, 32)))
	return allocation, nil
}

func allocationForFilter(
	prover *consensus.ProverInfo,
	filter []byte,
) (consensus.ProverAllocationInfo, error) {
	for _, allocation := range prover.Allocations {
		if bytes.Equal(allocation.ConfirmationFilter, filter) {
			return allocation, nil
		}
	}
	return consensus.ProverAllocationInfo{},
		errors.New("allocation not found for prover")
}

func compositeAddress(domain []byte, address []byte) []byte {
	full := make([]byte, 64)
	copy(full[:32], domain)
	copy(full[32:], address)
	return full
}
