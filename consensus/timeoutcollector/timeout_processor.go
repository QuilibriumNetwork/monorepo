package timeoutcollector

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/tracker"
)

// accumulatedWeightTracker tracks one-time event of reaching required weight
// Uses atomic flag to guarantee concurrency safety.
type accumulatedWeightTracker struct {
	minRequiredWeight uint64
	done              atomic.Bool
}

func (t *accumulatedWeightTracker) Done() bool {
	return t.done.Load()
}

// Track returns true if `weight` reaches or exceeds `minRequiredWeight` for the
// _first time_. All subsequent calls of `Track` (with any value) return false.
func (t *accumulatedWeightTracker) Track(weight uint64) bool {
	if weight < t.minRequiredWeight {
		return false
	}
	return t.done.CompareAndSwap(false, true)
}

// TimeoutProcessor implements the consensus.TimeoutProcessor interface. It
// processes timeout states broadcast by other replicas of the consensus
// committee. TimeoutProcessor collects TSs for one rank, eventually when enough
// timeout states are contributed TimeoutProcessor will create a timeout
// certificate which can be used to advance round. Concurrency safe.
type TimeoutProcessor[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
] struct {
	tracer           consensus.TraceLogger
	rank             uint64
	validator        consensus.Validator[StateT, VoteT]
	committee        consensus.Replicas
	sigAggregator    consensus.TimeoutSignatureAggregator
	notifier         consensus.TimeoutCollectorConsumer[VoteT]
	voting           consensus.VotingProvider[StateT, VoteT, PeerIDT]
	partialTCTracker accumulatedWeightTracker
	tcTracker        accumulatedWeightTracker
	newestQCTracker  *tracker.NewestQCTracker
}

var _ consensus.TimeoutProcessor[*nilUnique] = (*TimeoutProcessor[*nilUnique, *nilUnique, *nilUnique])(nil)

// NewTimeoutProcessor creates new instance of TimeoutProcessor
// Returns the following expected errors for invalid inputs:
//   - models.ErrRankUnknown if no rank containing the given rank is known
//
// All other errors should be treated as exceptions.
func NewTimeoutProcessor[
	StateT models.Unique,
	VoteT models.Unique,
	PeerIDT models.Unique,
](
	tracer consensus.TraceLogger,
	committee consensus.Replicas,
	validator consensus.Validator[StateT, VoteT],
	sigAggregator consensus.TimeoutSignatureAggregator,
	notifier consensus.TimeoutCollectorConsumer[VoteT],
	voting consensus.VotingProvider[StateT, VoteT, PeerIDT],
) (*TimeoutProcessor[StateT, VoteT, PeerIDT], error) {
	rank := sigAggregator.Rank()
	qcThreshold, err := committee.QuorumThresholdForRank(rank)
	if err != nil {
		return nil, fmt.Errorf(
			"could not retrieve QC weight threshold for rank %d: %w",
			rank,
			err,
		)
	}
	timeoutThreshold, err := committee.TimeoutThresholdForRank(rank)
	if err != nil {
		return nil, fmt.Errorf(
			"could not retrieve timeout weight threshold for rank %d: %w",
			rank,
			err,
		)
	}
	return &TimeoutProcessor[StateT, VoteT, PeerIDT]{
		tracer:    tracer,
		rank:      rank,
		committee: committee,
		validator: validator,
		notifier:  notifier,
		partialTCTracker: accumulatedWeightTracker{
			minRequiredWeight: timeoutThreshold,
			done:              *atomic.NewBool(false),
		},
		tcTracker: accumulatedWeightTracker{
			minRequiredWeight: qcThreshold,
			done:              *atomic.NewBool(false),
		},
		sigAggregator:   sigAggregator,
		newestQCTracker: tracker.NewNewestQCTracker(),
		voting:          voting,
	}, nil
}

// Process performs processing of timeout state in concurrent safe way. This
// function is implemented to be called by multiple goroutines at the same time.
// Design of this function is event driven, as soon as we collect enough weight
// to create a TC or a partial TC we will immediately do so and submit it
// via callback for further processing.
// Expected error returns during normal operations:
//   - ErrTimeoutForIncompatibleRank - submitted timeout for incompatible rank
//   - models.InvalidTimeoutError - submitted invalid timeout(invalid structure
//     or invalid signature)
//   - models.DuplicatedSignerError if a timeout from the same signer was
//     previously already added. It does _not necessarily_ imply that the
//     timeout is invalid or the sender is equivocating.
//
// All other errors should be treated as exceptions.
func (p *TimeoutProcessor[StateT, VoteT, PeerIDT]) Process(
	timeout *models.TimeoutState[VoteT],
) error {
	if p.rank != timeout.Rank {
		p.tracer.Trace(
			"received incompatible timeout",
			consensus.Uint64Param("processor_rank", p.rank),
			consensus.Uint64Param("timeout_rank", timeout.Rank),
			consensus.IdentityParam("timeout_voter", (*timeout.Vote).Identity()),
		)
		return fmt.Errorf(
			"received incompatible timeout, expected %d got %d: %w",
			p.rank,
			timeout.Rank,
			ErrTimeoutForIncompatibleRank,
		)
	}

	if p.tcTracker.Done() {
		return nil
	}

	err := p.validateTimeout(timeout)
	if err != nil {
		p.tracer.Error(
			"timeout validation failed",
			err,
			consensus.Uint64Param("processor_rank", p.rank),
			consensus.Uint64Param("timeout_rank", timeout.Rank),
			consensus.IdentityParam("timeout_voter", (*timeout.Vote).Identity()),
		)
		return fmt.Errorf("validating timeout failed: %w", err)
	}
	if p.tcTracker.Done() {
		return nil
	}

	// CAUTION: for correctness it is critical that we update the
	// `newestQCTracker` first, _before_ we add the TO's signature to
	// `sigAggregator`. Reasoning:
	//  * For a valid TC, we require that the TC includes a QC with
	//    rank ≥ max{TC.LatestQuorumCertificateRanks}.
	//  * The `LatestQuorumCertificateRanks` is maintained by `sigAggregator`.
	//  * Hence, for any rank `v ∈ LatestQuorumCertificateRanks` that
	//    `sigAggregator` knows, a QC  with equal or larger rank is known to
	//    `newestQCTracker`. This is guaranteed if and only if `newestQCTracker`
	//     is updated first.
	p.newestQCTracker.Track(&timeout.LatestQuorumCertificate)

	totalWeight, err := p.sigAggregator.VerifyAndAdd(
		(*timeout.Vote).Identity(),
		(*timeout.Vote).GetSignature(),
		timeout.LatestQuorumCertificate.GetRank(),
	)
	if err != nil {
		p.tracer.Error(
			"timeout signature could not be added",
			err,
			consensus.Uint64Param("processor_rank", p.rank),
			consensus.Uint64Param("timeout_rank", timeout.Rank),
			consensus.IdentityParam("timeout_voter", (*timeout.Vote).Identity()),
		)
		if models.IsInvalidSignerError(err) {
			return models.NewInvalidTimeoutErrorf(
				timeout,
				"invalid signer for timeout: %w",
				err,
			)
		}
		if errors.Is(err, models.ErrInvalidSignature) {
			return models.NewInvalidTimeoutErrorf(
				timeout,
				"timeout is from valid signer but has cryptographically invalid signature: %w",
				err,
			)
		}
		// models.DuplicatedSignerError is an expected error and just bubbled up the
		// call stack. It does _not necessarily_ imply that the timeout is invalid
		// or the sender is equivocating.
		return fmt.Errorf("adding signature to aggregator failed: %w", err)
	}
	p.tracer.Trace(fmt.Sprintf(
		"processed timeout, total weight=(%d), required=(%d)",
		totalWeight,
		p.tcTracker.minRequiredWeight,
	))

	if p.partialTCTracker.Track(totalWeight) {
		qc := p.newestQCTracker.NewestQC()
		p.notifier.OnPartialTimeoutCertificateCreated(
			p.rank,
			*qc,
			timeout.PriorRankTimeoutCertificate,
		)
	}

	// Checking of conditions for building TC are satisfied when willBuildTC is
	// true. At this point, we have enough signatures to build a TC. Another
	// routine might just be at this point. To avoid duplicate work, Track returns
	// true only once.
	willBuildTC := p.tcTracker.Track(totalWeight)
	if !willBuildTC {
		// either we do not have enough timeouts to build a TC, or another thread
		// has already passed this gate and created a TC
		return nil
	}

	tc, err := p.buildTC()
	if err != nil {
		return fmt.Errorf("internal error constructing TC: %w", err)
	}
	p.notifier.OnTimeoutCertificateConstructedFromTimeouts(*tc)
	p.tracer.Trace(
		"timeout constructed from timeouts",
		consensus.Uint64Param("rank", (*tc).GetRank()),
	)
	return nil
}

// validateTimeout performs validation of timeout state, verifies if timeout is
// correctly structured and included QC and TC is correctly structured and
// signed. ATTENTION: this function does _not_ check whether the TO's `SignerID`
// is an authorized node nor if the signature is valid. These checks happen in
// signature aggregator. Expected error returns during normal operations:
// * models.InvalidTimeoutError - submitted invalid timeout
// All other errors should be treated as exceptions.
func (p *TimeoutProcessor[StateT, VoteT, PeerIDT]) validateTimeout(
	timeout *models.TimeoutState[VoteT],
) error {
	// 1. check if it's correctly structured
	// (a) Every TO must contain a QC
	if timeout.LatestQuorumCertificate == nil {
		return models.NewInvalidTimeoutErrorf(timeout, "TimeoutState without QC is invalid")
	}

	if timeout.Rank <= timeout.LatestQuorumCertificate.GetRank() {
		return models.NewInvalidTimeoutErrorf(
			timeout,
			"TO's QC %d cannot be newer than the TO's rank %d",
			timeout.LatestQuorumCertificate.GetRank(),
			timeout.Rank,
		)
	}

	// (b) If a TC is included, the TC must be for the past round, no matter
	//     whether a QC for the last round is also included. In some edge cases, a
	//     node might observe _both_ QC and TC for the previous round, in which
	//     case it can include both.
	if timeout.PriorRankTimeoutCertificate != nil {
		if timeout.Rank != timeout.PriorRankTimeoutCertificate.GetRank()+1 {
			return models.NewInvalidTimeoutErrorf(
				timeout,
				"invalid TC for non-previous rank, expected rank %d, got rank %d",
				timeout.Rank-1,
				timeout.PriorRankTimeoutCertificate.GetRank(),
			)
		}
		if timeout.LatestQuorumCertificate.GetRank() <
			timeout.PriorRankTimeoutCertificate.GetLatestQuorumCert().GetRank() {
			return models.NewInvalidTimeoutErrorf(
				timeout,
				"timeout.LatestQuorumCertificate is older (rank=%d) than the QC in timeout.PriorRankTimeoutCertificate (rank=%d)",
				timeout.LatestQuorumCertificate.GetRank(),
				timeout.PriorRankTimeoutCertificate.GetLatestQuorumCert().GetRank(),
			)
		}
	}
	// (c) The TO must contain a proof that sender legitimately entered
	//     timeout.Rank. Transitioning to round timeout.Rank is possible either by
	//     observing a QC or a TC for the previous round. If no QC is included, we
	//     require a TC to be present, which by check (1b) must be for the
	//     previous round.
	lastRankSuccessful := timeout.Rank ==
		timeout.LatestQuorumCertificate.GetRank()+1
	if !lastRankSuccessful {
		// The TO's sender did _not_ observe a QC for round timeout.Rank-1. Hence,
		// it should include a TC for the previous round. Otherwise, the TO is
		// invalid.
		if timeout.PriorRankTimeoutCertificate == nil {
			return models.NewInvalidTimeoutErrorf(timeout, "timeout must include TC")
		}
	}

	// 2. Check if QC is valid
	err := p.validator.ValidateQuorumCertificate(timeout.LatestQuorumCertificate)
	if err != nil {
		if models.IsInvalidQuorumCertificateError(err) {
			return models.NewInvalidTimeoutErrorf(
				timeout,
				"included QC is invalid: %w",
				err,
			)
		}
		if errors.Is(err, models.ErrRankUnknown) {
			// We require each replica to be bootstrapped with a QC pointing to a
			// finalized state. Therefore, we should know the Rank for any QC.Rank
			// and TC.Rank we encounter. Receiving a `models.ErrRankUnknown` is
			// conceptually impossible, i.e. a symptom of an internal bug or invalid
			// bootstrapping information.
			return fmt.Errorf(
				"no Rank information available for QC that was included in TO; symptom of internal bug or invalid bootstrapping information: %s",
				err.Error(),
			)
		}
		return fmt.Errorf("unexpected error when validating QC: %w", err)
	}

	// 3. If TC is included, it must be valid
	if timeout.PriorRankTimeoutCertificate != nil {
		err = p.validator.ValidateTimeoutCertificate(
			timeout.PriorRankTimeoutCertificate,
		)
		if err != nil {
			if models.IsInvalidTimeoutCertificateError(err) {
				return models.NewInvalidTimeoutErrorf(
					timeout,
					"included TC is invalid: %w",
					err,
				)
			}
			if errors.Is(err, models.ErrRankUnknown) {
				// We require each replica to be bootstrapped with a QC pointing to a
				// finalized state. Therefore, we should know the Rank for any QC.Rank
				// and TC.Rank we encounter. Receiving a `models.ErrRankUnknown` is
				// conceptually impossible, i.e. a symptom of an internal bug or invalid
				// bootstrapping information.
				return fmt.Errorf(
					"no Rank information availalbe for TC that was included in TO; symptom of internal bug or invalid bootstrapping information: %s",
					err.Error(),
				)
			}
			return fmt.Errorf("unexpected error when validating TC: %w", err)
		}
	}
	return nil

}

// buildTC performs aggregation of signatures when we have collected enough
// weight for building TC. This function is run only once by single worker.
// Any error should be treated as exception.
func (p *TimeoutProcessor[StateT, VoteT, PeerIDT]) buildTC() (
	*models.TimeoutCertificate,
	error,
) {
	signersData, aggregatedSig, err := p.sigAggregator.Aggregate()
	if err != nil {
		return nil, fmt.Errorf(
			"could not aggregate multi message signature: %w",
			err,
		)
	}

	// Note that `newestQC` can have a larger rank than any of the ranks included
	// in `newestQCRanks`. This is because for a TO currently being processes
	// following two operations are executed in separate steps:
	// * updating the `newestQCTracker` with the QC from the TO
	// * adding the TO's signature to `sigAggregator`
	// Therefore, races are possible, where the `newestQCTracker` already knows of
	// a QC with larger rank than the data stored in `sigAggregator`.
	newestQC := p.newestQCTracker.NewestQC()
	tc, err := p.voting.FinalizeTimeout(
		context.TODO(),
		p.rank,
		*newestQC,
		signersData,
		aggregatedSig,
	)
	if err != nil {
		return nil, fmt.Errorf("could not construct timeout certificate: %w", err)
	}

	return &tc, nil
}

// signerIndicesFromIdentities encodes identities into signer indices.
// Any error should be treated as exception.
func (p *TimeoutProcessor[StateT, VoteT, PeerIDT]) signerIndicesFromIdentities(
	signerIDs []models.WeightedIdentity,
) ([]byte, error) {
	allIdentities, err := p.committee.IdentitiesByRank(p.rank)
	if err != nil {
		return nil, fmt.Errorf(
			"could not retrieve identities for rank %d: %w",
			p.rank,
			err,
		)
	}

	signerSet := map[models.Identity]struct{}{}
	for _, signerID := range signerIDs {
		signerSet[signerID.Identity()] = struct{}{}
	}

	signerIndices := make([]byte, (len(allIdentities)+7)/8)
	for i, member := range allIdentities {
		if _, ok := signerSet[member.Identity()]; ok {
			signerIndices[i/8] |= 1 << (i % 8)
		}
	}

	return signerIndices, nil
}
