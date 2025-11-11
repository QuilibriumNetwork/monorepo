package app

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

type ConsensusWeightedIdentity struct {
	prover *tconsensus.ProverInfo
}

// Identity implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) Identity() models.Identity {
	return models.Identity(c.prover.Address)
}

// PublicKey implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) PublicKey() []byte {
	return c.prover.PublicKey
}

// Weight implements models.WeightedIdentity.
func (c *ConsensusWeightedIdentity) Weight() uint64 {
	return c.prover.Seniority
}

// IdentitiesByRank implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) IdentitiesByRank(
	rank uint64,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return nil, errors.Wrap(err, "identities by rank")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentitiesByState implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) IdentitiesByState(
	stateID models.Identity,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return nil, errors.Wrap(err, "identities by state")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentityByRank implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) IdentityByRank(
	rank uint64,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return nil, errors.Wrap(err, "identity by rank")
	}

	var found *tconsensus.ProverInfo
	for _, p := range proverInfo {
		if bytes.Equal(p.Address, []byte(participantID)) {
			found = p
			break
		}
	}

	if found == nil {
		return nil, errors.Wrap(errors.New("prover not found"), "identity by rank")
	}

	return internalProverToWeightedIdentity(found), nil
}

// IdentityByState implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) IdentityByState(
	stateID models.Identity,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return nil, errors.Wrap(err, "identity by state")
	}

	var found *tconsensus.ProverInfo
	for _, p := range proverInfo {
		if bytes.Equal(p.Address, []byte(participantID)) {
			found = p
			break
		}
	}

	if found == nil {
		return nil, errors.Wrap(errors.New("prover not found"), "identity by state")
	}

	return internalProverToWeightedIdentity(found), nil
}

// LeaderForRank implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) LeaderForRank(
	rank uint64,
) (models.Identity, error) {
	lineage, err := e.appTimeReel.GetLineage()
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	var found *protobufs.AppShardFrame
	for _, l := range lineage {
		if l.GetRank() == (rank - 1) {
			found = l
			break
		}
	}

	var selector models.Identity
	if found == nil {
		selector = models.Identity(make([]byte, 32))
	} else {
		selector = found.Identity()
	}

	inputBI, err := poseidon.HashBytes(slices.Concat(
		[]byte(selector),
		binary.BigEndian.AppendUint64(nil, rank),
	))
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	input := inputBI.FillBytes(make([]byte, 32))
	prover, err := e.proverRegistry.GetNextProver(
		[32]byte(input),
		e.appAddress,
	)
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	return models.Identity(prover), nil
}

// QuorumThresholdForRank implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) QuorumThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return 0, errors.Wrap(err, "quorum threshold for rank")
	}

	total := uint64(0)
	for _, p := range proverInfo {
		total += p.Seniority
	}

	return (total * 2) / 3, nil
}

// Self implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) Self() models.Identity {
	return e.getPeerID().Identity()
}

// TimeoutThresholdForRank implements consensus.DynamicCommittee.
func (e *AppConsensusEngine) TimeoutThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(e.appAddress)
	if err != nil {
		return 0, errors.Wrap(err, "timeout threshold for rank")
	}

	leader, err := e.LeaderForRank(rank)
	if err != nil {
		return 0, errors.Wrap(err, "timeout threshold for rank")
	}

	total := uint64(0)
	// 2/3 majority doesn't quite work in this scenario, because if the timing out
	// prover has a high enough seniority it could get things stuck where no
	// timeout can occur
	for _, p := range proverInfo {
		if !bytes.Equal(p.Address, []byte(leader)) {
			total += p.Seniority
		}
	}

	return (total * 2) / 3, nil
}

func internalProversToWeightedIdentity(
	provers []*tconsensus.ProverInfo,
) []models.WeightedIdentity {
	wis := []models.WeightedIdentity{}
	for _, p := range provers {
		wis = append(wis, internalProverToWeightedIdentity(p))
	}

	return wis
}

func internalProverToWeightedIdentity(
	prover *tconsensus.ProverInfo,
) models.WeightedIdentity {
	return &ConsensusWeightedIdentity{prover}
}
