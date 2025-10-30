package pacemaker

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type Pacemaker[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
] struct {
	ctx                      context.Context
	started                  bool
	proposalDurationProvider consensus.ProposalDurationProvider
	notifier                 consensus.Consumer[StateT, VoteT]
	store                    consensus.ConsensusStore[VoteT]
	backoffTimer             *consensus.BackoffTimer
	traceLogger              consensus.TraceLogger
	livenessState            *models.LivenessState
}

func NewPacemaker[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
	CollectedT models.Unique,
](
	initialParameters func() *models.LivenessState,
	proposalDurationProvider consensus.ProposalDurationProvider,
	notifier consensus.Consumer[StateT, VoteT],
	store consensus.ConsensusStore[VoteT],
	traceLogger consensus.TraceLogger,
) (*Pacemaker[StateT, VoteT, PeerIDT, CollectedT], error) {
	livenessState, err := store.GetLivenessState()
	if err != nil {
		livenessState = initialParameters()
	}

	return &Pacemaker[StateT, VoteT, PeerIDT, CollectedT]{
		proposalDurationProvider: proposalDurationProvider,
		notifier:                 notifier,
		store:                    store,
		traceLogger:              traceLogger,
		livenessState:            livenessState,
		backoffTimer:             consensus.NewBackoffTimer(),
		started:                  false,
	}, nil
}

// CurrentRank implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) CurrentRank() uint64 {
	return p.livenessState.CurrentRank
}

// LatestQuorumCertificate implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) LatestQuorumCertificate() models.QuorumCertificate {
	return p.livenessState.LatestQuorumCertificate
}

// PriorRankTimeoutCertificate implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) PriorRankTimeoutCertificate() models.TimeoutCertificate {
	return p.livenessState.PriorRankTimeoutCertificate
}

func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) newRankAndTimeout(
	currentRank uint64,
	newRank uint64,
) (*models.NextRank, error) {
	p.notifier.OnRankChange(currentRank, newRank)
	start, end := p.backoffTimer.Start(p.ctx)
	p.notifier.OnStartingTimeout(start, end)

	return &models.NextRank{
		Rank:  newRank,
		Start: start,
		End:   end,
	}, nil
}

// ReceiveQuorumCertificate implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveQuorumCertificate(
	quorumCertificate models.QuorumCertificate,
) (*models.NextRank, error) {
	currentRank := p.livenessState.CurrentRank
	newRank, err := p.processQuorumCertificate(quorumCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "receive quorum certificate")
	}

	p.backoffTimer.ReceiveSuccess()
	p.notifier.OnQuorumCertificateTriggeredRankChange(
		currentRank,
		newRank,
		quorumCertificate,
	)

	return p.newRankAndTimeout(currentRank, newRank)
}

func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) processQuorumCertificate(
	quorumCertificate models.QuorumCertificate,
) (uint64, error) {
	currentRank := p.livenessState.CurrentRank
	if quorumCertificate.GetRank() < currentRank {
		if p.livenessState.LatestQuorumCertificate.GetRank() >=
			quorumCertificate.GetRank() {
			return currentRank, nil
		}

		p.livenessState.LatestQuorumCertificate = quorumCertificate
		err := p.store.PutLivenessState(p.livenessState)
		if err != nil {
			return currentRank, errors.Wrap(err, "process quorum certificate")
		}

		return currentRank, nil
	}

	newRank := quorumCertificate.GetRank() + 1
	p.livenessState.CurrentRank = newRank
	p.livenessState.LatestQuorumCertificate = quorumCertificate
	p.livenessState.PriorRankTimeoutCertificate = nil
	err := p.store.PutLivenessState(p.livenessState)
	if err != nil {
		return 0, errors.Wrap(err, "process quorum certificate")
	}

	return newRank, nil
}

// ReceiveTimeoutCertificate implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) ReceiveTimeoutCertificate(
	timeoutCertificate models.TimeoutCertificate,
) (*models.NextRank, error) {
	currentRank := p.livenessState.CurrentRank
	newRank, err := p.processTimeoutCertificate(timeoutCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "receive timeout certificate")
	}
	if newRank <= currentRank {
		return nil, nil
	}

	p.backoffTimer.ReceiveTimeout()
	p.notifier.OnTimeoutCertificateTriggeredRankChange(
		currentRank,
		newRank,
		timeoutCertificate,
	)

	return p.newRankAndTimeout(currentRank, newRank)
}

func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) processTimeoutCertificate(
	timeoutCertificate models.TimeoutCertificate,
) (uint64, error) {
	currentRank := p.livenessState.CurrentRank
	if timeoutCertificate == nil {
		return currentRank, nil
	}

	if timeoutCertificate.GetRank() < currentRank {
		if p.livenessState.LatestQuorumCertificate.GetRank() >=
			timeoutCertificate.GetLatestQuorumCert().GetRank() {
			return currentRank, nil
		}

		p.livenessState.LatestQuorumCertificate = timeoutCertificate.
			GetLatestQuorumCert()
		err := p.store.PutLivenessState(p.livenessState)
		if err != nil {
			return currentRank, errors.Wrap(err, "process timeout certificate")
		}

		return currentRank, nil
	}

	newRank := timeoutCertificate.GetRank() + 1
	p.livenessState.CurrentRank = newRank
	p.livenessState.LatestQuorumCertificate = timeoutCertificate.
		GetLatestQuorumCert()
	p.livenessState.PriorRankTimeoutCertificate = timeoutCertificate
	err := p.store.PutLivenessState(p.livenessState)
	if err != nil {
		return 0, errors.Wrap(err, "process timeout certificate")
	}

	return newRank, nil
}

// TimeoutCh implements consensus.PacemakerProvider.
func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) TimeoutCh() <-chan time.Time {
	return p.backoffTimer.TimeoutCh()
}

func (p *Pacemaker[
	StateT,
	VoteT,
	PeerIDT,
	CollectedT,
]) Start(ctx context.Context) error {
	if p.started {
		return nil
	}
	p.started = true
	p.ctx = ctx
	start, end := p.backoffTimer.Start(ctx)
	p.notifier.OnStartingTimeout(start, end)
	return nil
}

func (p *Pacemaker[StateT, VoteT, PeerIDT, CollectedT]) TargetPublicationTime(
	proposalRank uint64,
	timeRankEntered time.Time,
	parentStateId models.Identity,
) time.Time {
	return p.proposalDurationProvider.TargetPublicationTime(
		proposalRank,
		timeRankEntered,
		parentStateId,
	)
}

var _ consensus.Pacemaker = (*Pacemaker[
	*nilUnique,
	*nilUnique,
	*nilUnique,
	*nilUnique,
])(nil)

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
