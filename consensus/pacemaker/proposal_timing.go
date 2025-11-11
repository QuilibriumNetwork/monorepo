package pacemaker

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// StaticProposalDurationProvider is a consensus.ProposalDurationProvider which
// provides a static ProposalDuration. The constant dur represents the time to
// produce and broadcast the proposal (ProposalDuration), NOT the time for the
// entire rank (RankDuration).
type StaticProposalDurationProvider struct {
	dur time.Duration
}

var _ consensus.ProposalDurationProvider = (*StaticProposalDurationProvider)(nil)

func NewStaticProposalDurationProvider(
	dur time.Duration,
) StaticProposalDurationProvider {
	return StaticProposalDurationProvider{dur: dur}
}

func (p StaticProposalDurationProvider) TargetPublicationTime(
	_ uint64,
	timeRankEntered time.Time,
	_ models.Identity,
) time.Time {
	return timeRankEntered.Add(p.dur)
}

func NoProposalDelay() StaticProposalDurationProvider {
	return NewStaticProposalDurationProvider(0)
}
