package notifications

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// NoopConsumer is an implementation of the notifications consumer that
// doesn't do anything.
type NoopConsumer[StateT models.Unique, VoteT models.Unique] struct {
	NoopProposalViolationConsumer[StateT, VoteT]
	NoopFinalizationConsumer[StateT]
	NoopParticipantConsumer[StateT, VoteT]
	NoopCommunicatorConsumer[StateT, VoteT]
}

var _ consensus.Consumer[*nilUnique, *nilUnique] = (*NoopConsumer[*nilUnique, *nilUnique])(nil)

func NewNoopConsumer[
	StateT models.Unique,
	VoteT models.Unique,
]() *NoopConsumer[StateT, VoteT] {
	nc := &NoopConsumer[StateT, VoteT]{}
	return nc
}

// no-op implementation of consensus.Consumer(but not nested interfaces)

type NoopParticipantConsumer[StateT models.Unique, VoteT models.Unique] struct{}

func (*NoopParticipantConsumer[StateT, VoteT]) OnEventProcessed() {}

func (*NoopParticipantConsumer[StateT, VoteT]) OnStart(uint64) {}

func (*NoopParticipantConsumer[StateT, VoteT]) OnReceiveProposal(uint64, *models.SignedProposal[StateT, VoteT]) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnReceiveQuorumCertificate(uint64, models.QuorumCertificate) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnReceiveTimeoutCertificate(uint64, models.TimeoutCertificate) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnPartialTimeoutCertificate(uint64, *consensus.PartialTimeoutCertificateCreated) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnLocalTimeout(uint64) {}

func (*NoopParticipantConsumer[StateT, VoteT]) OnRankChange(uint64, uint64) {}

func (*NoopParticipantConsumer[StateT, VoteT]) OnQuorumCertificateTriggeredRankChange(uint64, uint64, models.QuorumCertificate) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnTimeoutCertificateTriggeredRankChange(uint64, uint64, models.TimeoutCertificate) {
}

func (*NoopParticipantConsumer[StateT, VoteT]) OnStartingTimeout(time.Time, time.Time) {}

func (*NoopParticipantConsumer[StateT, VoteT]) OnCurrentRankDetails(uint64, uint64, models.Identity) {
}

// no-op implementation of consensus.FinalizationConsumer

type NoopFinalizationConsumer[StateT models.Unique] struct{}

var _ consensus.FinalizationConsumer[*nilUnique] = (*NoopFinalizationConsumer[*nilUnique])(nil)

func (*NoopFinalizationConsumer[StateT]) OnStateIncorporated(*models.State[StateT]) {}

func (*NoopFinalizationConsumer[StateT]) OnFinalizedState(*models.State[StateT]) {}

// no-op implementation of consensus.TimeoutCollectorConsumer

type NoopTimeoutCollectorConsumer[VoteT models.Unique] struct{}

var _ consensus.TimeoutCollectorConsumer[*nilUnique] = (*NoopTimeoutCollectorConsumer[*nilUnique])(nil)

func (*NoopTimeoutCollectorConsumer[VoteT]) OnTimeoutCertificateConstructedFromTimeouts(models.TimeoutCertificate) {
}

func (*NoopTimeoutCollectorConsumer[VoteT]) OnPartialTimeoutCertificateCreated(uint64, models.QuorumCertificate, models.TimeoutCertificate) {
}

func (*NoopTimeoutCollectorConsumer[VoteT]) OnNewQuorumCertificateDiscovered(models.QuorumCertificate) {
}

func (*NoopTimeoutCollectorConsumer[VoteT]) OnNewTimeoutCertificateDiscovered(models.TimeoutCertificate) {
}

func (*NoopTimeoutCollectorConsumer[VoteT]) OnTimeoutProcessed(*models.TimeoutState[VoteT]) {}

// no-op implementation of consensus.CommunicatorConsumer

type NoopCommunicatorConsumer[StateT models.Unique, VoteT models.Unique] struct{}

var _ consensus.CommunicatorConsumer[*nilUnique, *nilUnique] = (*NoopCommunicatorConsumer[*nilUnique, *nilUnique])(nil)

func (*NoopCommunicatorConsumer[StateT, VoteT]) OnOwnVote(*VoteT, models.Identity) {}

func (*NoopCommunicatorConsumer[StateT, VoteT]) OnOwnTimeout(*models.TimeoutState[VoteT]) {}

func (*NoopCommunicatorConsumer[StateT, VoteT]) OnOwnProposal(*models.SignedProposal[StateT, VoteT], time.Time) {
}

// no-op implementation of consensus.VoteCollectorConsumer

type NoopVoteCollectorConsumer[VoteT models.Unique] struct{}

var _ consensus.VoteCollectorConsumer[*nilUnique] = (*NoopVoteCollectorConsumer[*nilUnique])(nil)

func (*NoopVoteCollectorConsumer[VoteT]) OnQuorumCertificateConstructedFromVotes(models.QuorumCertificate) {
}

func (*NoopVoteCollectorConsumer[VoteT]) OnVoteProcessed(*VoteT) {}

// no-op implementation of consensus.ProposalViolationConsumer

type NoopProposalViolationConsumer[StateT models.Unique, VoteT models.Unique] struct{}

var _ consensus.ProposalViolationConsumer[*nilUnique, *nilUnique] = (*NoopProposalViolationConsumer[*nilUnique, *nilUnique])(nil)

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnInvalidStateDetected(*models.InvalidProposalError[StateT, VoteT]) {
}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnDoubleProposeDetected(*models.State[StateT], *models.State[StateT]) {
}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnDoubleVotingDetected(*VoteT, *VoteT) {}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnInvalidVoteDetected(models.InvalidVoteError[VoteT]) {
}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnVoteForInvalidStateDetected(*VoteT, *models.SignedProposal[StateT, VoteT]) {
}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnDoubleTimeoutDetected(*models.TimeoutState[VoteT], *models.TimeoutState[VoteT]) {
}

func (*NoopProposalViolationConsumer[StateT, VoteT]) OnInvalidTimeoutDetected(models.InvalidTimeoutError[VoteT]) {
}

// Type used to satisfy generic arguments in compiler time type assertion check
type nilUnique struct{}

// GetSignature implements models.Unique.
func (n *nilUnique) GetSignature() []byte {
	panic("unimplemented")
}

// GetTimestamp implements models.Unique.
func (n *nilUnique) GetTimestamp() uint64 {
	panic("unimplemented")
}

// Source implements models.Unique.
func (n *nilUnique) Source() models.Identity {
	panic("unimplemented")
}

// Clone implements models.Unique.
func (n *nilUnique) Clone() models.Unique {
	panic("unimplemented")
}

// GetRank implements models.Unique.
func (n *nilUnique) GetRank() uint64 {
	panic("unimplemented")
}

// Identity implements models.Unique.
func (n *nilUnique) Identity() models.Identity {
	panic("unimplemented")
}

var _ models.Unique = (*nilUnique)(nil)
