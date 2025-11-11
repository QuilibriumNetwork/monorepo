package pacemaker

import (
	"context"
	"fmt"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
	"source.quilibrium.com/quilibrium/monorepo/consensus/tracker"
)

// Pacemaker implements consensus.Pacemaker
// Conceptually, we use the Pacemaker algorithm first proposed in [1]
// (specifically Jolteon) and described in more detail in [2] (aka DiemBFT v4).
// [1] https://arxiv.org/abs/2106.10362
// [2] https://developers.diem.com/papers/diem-consensus-state-machine-replication-in-the-diem-statechain/2021-08-17.pdf
//
// To enter a new rank `r`, the Pacemaker must observe a valid QC or TC for rank
// `r-1`. The Pacemaker also controls when a node should locally time out for a
// given rank. Locally timing a rank does not cause a rank change.
// A local timeout for a rank `r` causes a node to:
//   - never produce a vote for any proposal with rank ≤ `r`, after the timeout
//   - produce and broadcast a timeout object, which can form a part of the TC
//     for the timed out rank
//
// Not concurrency safe.
type Pacemaker[StateT models.Unique, VoteT models.Unique] struct {
	consensus.ProposalDurationProvider

	ctx            context.Context
	tracer         consensus.TraceLogger
	timeoutControl *timeout.Controller
	notifier       consensus.ParticipantConsumer[StateT, VoteT]
	rankTracker    rankTracker[StateT, VoteT]
	started        bool
}

var _ consensus.Pacemaker = (*Pacemaker[*nilUnique, *nilUnique])(nil)
var _ consensus.ProposalDurationProvider = (*Pacemaker[*nilUnique, *nilUnique])(nil)

// New creates a new Pacemaker instance
//   - startRank is the rank for the pacemaker to start with.
//   - timeoutController controls the timeout trigger.
//   - notifier provides callbacks for pacemaker events.
//
// Expected error conditions:
// * models.ConfigurationError if initial LivenessState is invalid
func NewPacemaker[StateT models.Unique, VoteT models.Unique](
	filter []byte,
	timeoutController *timeout.Controller,
	proposalDurationProvider consensus.ProposalDurationProvider,
	notifier consensus.Consumer[StateT, VoteT],
	store consensus.ConsensusStore[VoteT],
	tracer consensus.TraceLogger,
	recovery ...recoveryInformation[StateT, VoteT],
) (*Pacemaker[StateT, VoteT], error) {
	vt, err := newRankTracker[StateT, VoteT](filter, store)
	if err != nil {
		return nil, fmt.Errorf("initializing rank tracker failed: %w", err)
	}

	pm := &Pacemaker[StateT, VoteT]{
		ProposalDurationProvider: proposalDurationProvider,
		timeoutControl:           timeoutController,
		notifier:                 notifier,
		rankTracker:              vt,
		tracer:                   tracer,
		started:                  false,
	}
	for _, recoveryAction := range recovery {
		err = recoveryAction(pm)
		if err != nil {
			return nil, fmt.Errorf("ingesting recovery information failed: %w", err)
		}
	}
	return pm, nil
}

// CurrentRank returns the current rank
func (p *Pacemaker[StateT, VoteT]) CurrentRank() uint64 {
	return p.rankTracker.CurrentRank()
}

// LatestQuorumCertificate returns QC with the highest rank discovered by
// Pacemaker.
func (
	p *Pacemaker[StateT, VoteT],
) LatestQuorumCertificate() models.QuorumCertificate {
	return p.rankTracker.LatestQuorumCertificate()
}

// PriorRankTimeoutCertificate returns TC for last rank, this will be nil only
// if the current rank was entered with a QC.
func (
	p *Pacemaker[StateT, VoteT],
) PriorRankTimeoutCertificate() models.TimeoutCertificate {
	return p.rankTracker.PriorRankTimeoutCertificate()
}

// TimeoutCh returns the timeout channel for current active timeout.
// Note the returned timeout channel returns only one timeout, which is the
// current timeout. To get the timeout for the next timeout, you need to call
// TimeoutCh() again.
func (p *Pacemaker[StateT, VoteT]) TimeoutCh() <-chan time.Time {
	return p.timeoutControl.Channel()
}

// ReceiveQuorumCertificate notifies the pacemaker with a new QC, which might
// allow pacemaker to fast-forward its rank. In contrast to
// `ReceiveTimeoutCertificate`, this function does _not_ handle `nil` inputs.
// No errors are expected, any error should be treated as exception.
func (p *Pacemaker[StateT, VoteT]) ReceiveQuorumCertificate(
	qc models.QuorumCertificate,
) (*models.NextRank, error) {
	initialRank := p.CurrentRank()
	resultingRank, err := p.rankTracker.ReceiveQuorumCertificate(qc)
	if err != nil {
		return nil, fmt.Errorf(
			"unexpected exception in rankTracker while processing QC for rank %d: %w",
			qc.GetRank(),
			err,
		)
	}
	if resultingRank <= initialRank {
		return nil, nil
	}

	// QC triggered rank change:
	p.timeoutControl.OnProgressBeforeTimeout()
	p.notifier.OnQuorumCertificateTriggeredRankChange(
		initialRank,
		resultingRank,
		qc,
	)

	p.notifier.OnRankChange(initialRank, resultingRank)
	timerInfo := p.timeoutControl.StartTimeout(p.ctx, resultingRank)
	p.notifier.OnStartingTimeout(
		timerInfo.StartTime,
		timerInfo.StartTime.Add(timerInfo.Duration),
	)

	return &models.NextRank{
		Rank:  timerInfo.Rank,
		Start: timerInfo.StartTime,
		End:   timerInfo.StartTime.Add(timerInfo.Duration),
	}, nil
}

// ReceiveTimeoutCertificate notifies the Pacemaker of a new timeout
// certificate, which may allow Pacemaker to fast-forward its current rank. A
// nil TC is an expected valid input, so that callers may pass in e.g.
// `Proposal.PriorRankTimeoutCertificate`, which may or may not have a value.
// No errors are expected, any error should be treated as exception
func (p *Pacemaker[StateT, VoteT]) ReceiveTimeoutCertificate(
	tc models.TimeoutCertificate,
) (*models.NextRank, error) {
	initialRank := p.CurrentRank()
	resultingRank, err := p.rankTracker.ReceiveTimeoutCertificate(tc)
	if err != nil {
		return nil, fmt.Errorf(
			"unexpected exception in rankTracker while processing TC for rank %d: %w",
			tc.GetRank(),
			err,
		)
	}
	p.tracer.Trace(
		"pacemaker receive tc",
		consensus.Uint64Param("resulting_rank", resultingRank),
		consensus.Uint64Param("initial_rank", initialRank),
	)
	if resultingRank <= initialRank {
		return nil, nil
	}

	// TC triggered rank change:
	p.timeoutControl.OnTimeout()
	p.notifier.OnTimeoutCertificateTriggeredRankChange(
		initialRank,
		resultingRank,
		tc,
	)

	p.notifier.OnRankChange(initialRank, resultingRank)
	timerInfo := p.timeoutControl.StartTimeout(p.ctx, resultingRank)
	p.notifier.OnStartingTimeout(
		timerInfo.StartTime,
		timerInfo.StartTime.Add(timerInfo.Duration),
	)

	return &models.NextRank{
		Rank:  timerInfo.Rank,
		Start: timerInfo.StartTime,
		End:   timerInfo.StartTime.Add(timerInfo.Duration),
	}, nil
}

// Start starts the pacemaker by starting the initial timer for the current
// rank. Start should only be called once - subsequent calls are a no-op.
// CAUTION: Pacemaker is not concurrency safe. The Start method must
// be executed by the same goroutine that also calls the other business logic
// methods, or concurrency safety has to be implemented externally.
func (p *Pacemaker[StateT, VoteT]) Start(ctx context.Context) {
	if p.started {
		return
	}
	p.started = true
	p.ctx = ctx
	timerInfo := p.timeoutControl.StartTimeout(ctx, p.CurrentRank())
	p.notifier.OnStartingTimeout(
		timerInfo.StartTime,
		timerInfo.StartTime.Add(timerInfo.Duration),
	)
}

/* ------------------------------------ recovery parameters for Pacemaker ------------------------------------ */

// recoveryInformation provides optional information to the Pacemaker during its
// construction to ingest additional information that was potentially lost
// during a crash or reboot. Following the "information-driven" approach, we
// consider potentially older or redundant information as consistent with our
// already-present knowledge, i.e. as a no-op.
type recoveryInformation[
	StateT models.Unique,
	VoteT models.Unique,
] func(p *Pacemaker[StateT, VoteT]) error

// WithQCs informs the Pacemaker about the given QCs. Old and nil QCs are
// accepted (no-op).
func WithQCs[
	StateT models.Unique,
	VoteT models.Unique,
](qcs ...models.QuorumCertificate) recoveryInformation[StateT, VoteT] {
	// To avoid excessive database writes during initialization, we pre-filter the
	// newest QC here and only hand that one to the rankTracker. For recovery, we
	// allow the special case of nil QCs, because the genesis state has no QC.
	tracker := tracker.NewNewestQCTracker()
	for _, qc := range qcs {
		if qc == nil {
			continue // no-op
		}
		tracker.Track(&qc)
	}
	newestQC := tracker.NewestQC()
	if newestQC == nil {
		return func(p *Pacemaker[StateT, VoteT]) error { return nil } // no-op
	}

	return func(p *Pacemaker[StateT, VoteT]) error {
		_, err := p.rankTracker.ReceiveQuorumCertificate(*newestQC)
		return err
	}
}

// WithTCs informs the Pacemaker about the given TCs. Old and nil TCs are
// accepted (no-op).
func WithTCs[
	StateT models.Unique,
	VoteT models.Unique,
](tcs ...models.TimeoutCertificate) recoveryInformation[StateT, VoteT] {
	qcTracker := tracker.NewNewestQCTracker()
	tcTracker := tracker.NewNewestTCTracker()
	for _, tc := range tcs {
		if tc == nil {
			continue // no-op
		}
		tcTracker.Track(&tc)
		qc := tc.GetLatestQuorumCert()
		qcTracker.Track(&qc)
	}
	newestTC := tcTracker.NewestTC()
	newestQC := qcTracker.NewestQC()
	if newestTC == nil { // shortcut if no TCs provided
		return func(p *Pacemaker[StateT, VoteT]) error { return nil } // no-op
	}

	return func(p *Pacemaker[StateT, VoteT]) error {
		_, err := p.rankTracker.ReceiveTimeoutCertificate(*newestTC) // allows nil inputs
		if err != nil {
			return fmt.Errorf(
				"rankTracker failed to process newest TC provided in constructor: %w",
				err,
			)
		}
		_, err = p.rankTracker.ReceiveQuorumCertificate(*newestQC) // should never be nil, because a valid TC always contain a QC
		if err != nil {
			return fmt.Errorf(
				"rankTracker failed to process newest QC extracted from the TCs provided in constructor: %w",
				err,
			)
		}
		return nil
	}
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
