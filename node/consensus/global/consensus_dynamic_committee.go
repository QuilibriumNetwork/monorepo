package global

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
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
func (e *GlobalConsensusEngine) IdentitiesByRank(
	rank uint64,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identities by rank")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentitiesByState implements consensus.DynamicCommittee.
func (e *GlobalConsensusEngine) IdentitiesByState(
	stateID models.Identity,
) ([]models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return nil, errors.Wrap(err, "identities by state")
	}

	return internalProversToWeightedIdentity(proverInfo), nil
}

// IdentityByRank implements consensus.DynamicCommittee.
func (e *GlobalConsensusEngine) IdentityByRank(
	rank uint64,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
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
func (e *GlobalConsensusEngine) IdentityByState(
	stateID models.Identity,
	participantID models.Identity,
) (models.WeightedIdentity, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
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
func (e *GlobalConsensusEngine) LeaderForRank(
	rank uint64,
) (models.Identity, error) {
	// TODO(2.2): revisit this
	inputBI, err := poseidon.HashBytes(slices.Concat(
		binary.BigEndian.AppendUint64(nil, rank),
	))
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	proverSet, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return "", errors.Wrap(err, "leader for rank")
	}

	inputBI.Mod(inputBI, big.NewInt(int64(len(proverSet))))
	index := inputBI.Int64()
	return models.Identity(proverSet[int(index)].Address), nil
}

// QuorumThresholdForRank implements consensus.DynamicCommittee.
func (e *GlobalConsensusEngine) QuorumThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return 0, errors.Wrap(err, "quorum threshold for rank")
	}

	total := uint64(0)
	for _, p := range proverInfo {
		total += p.Seniority
	}

	return (total * 4) / 6, nil
}

// Self implements consensus.DynamicCommittee.
func (e *GlobalConsensusEngine) Self() models.Identity {
	return e.getPeerID().Identity()
}

// TimeoutThresholdForRank implements consensus.DynamicCommittee.
func (e *GlobalConsensusEngine) TimeoutThresholdForRank(
	rank uint64,
) (uint64, error) {
	proverInfo, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return 0, errors.Wrap(err, "quorum threshold for rank")
	}

	total := uint64(0)
	for _, p := range proverInfo {
		total += p.Seniority
	}

	return (total * 4) / 6, nil
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
