package notifications

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// LogConsumer is an implementation of the notifications consumer that logs a
// message for each event.
type LogConsumer[StateT models.Unique, VoteT models.Unique] struct {
	log consensus.TraceLogger
}

var _ consensus.Consumer[*nilUnique, *nilUnique] = (*LogConsumer[*nilUnique, *nilUnique])(nil)
var _ consensus.TimeoutAggregationConsumer[*nilUnique] = (*LogConsumer[*nilUnique, *nilUnique])(nil)
var _ consensus.VoteAggregationConsumer[*nilUnique, *nilUnique] = (*LogConsumer[*nilUnique, *nilUnique])(nil)

func NewLogConsumer[StateT models.Unique, VoteT models.Unique](
	log consensus.TraceLogger,
) *LogConsumer[StateT, VoteT] {
	lc := &LogConsumer[StateT, VoteT]{
		log: log,
	}
	return lc
}

func (lc *LogConsumer[StateT, VoteT]) OnEventProcessed() {
	lc.log.Trace("event processed")
}

func (lc *LogConsumer[StateT, VoteT]) OnStart(currentRank uint64) {
	lc.log.With(
		consensus.Uint64Param("cur_rank", currentRank),
	).Trace("starting event handler")
}

func (lc *LogConsumer[StateT, VoteT]) OnStateIncorporated(
	state *models.State[StateT],
) {
	lc.logBasicStateData(lc.log, state).
		Trace("state incorporated")
}

func (lc *LogConsumer[StateT, VoteT]) OnFinalizedState(
	state *models.State[StateT],
) {
	lc.logBasicStateData(lc.log, state).Trace("state finalized")
}

func (lc *LogConsumer[StateT, VoteT]) OnInvalidStateDetected(
	err *models.InvalidProposalError[StateT, VoteT],
) {
	invalidState := err.InvalidProposal.State
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.IdentityParam(
			"origin_id",
			err.InvalidProposal.Proposal.State.ProposerID,
		),
		consensus.Uint64Param("state_rank", invalidState.Rank),
		consensus.IdentityParam("proposer_id", invalidState.ProposerID),
		consensus.IdentityParam("state_id", invalidState.Identifier),
		consensus.Uint64Param(
			"qc_state_rank",
			invalidState.ParentQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam(
			"qc_state_id",
			invalidState.ParentQuorumCertificate.Identity(),
		),
	).Error("invalid state detected", err)
}

func (lc *LogConsumer[StateT, VoteT]) OnDoubleProposeDetected(
	state *models.State[StateT],
	alt *models.State[StateT],
) {
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.Uint64Param("state_rank", state.Rank),
		consensus.IdentityParam("state_id", state.Identifier),
		consensus.IdentityParam("alt_id", (*alt.State).Identity()),
		consensus.IdentityParam("proposer_id", state.ProposerID),
	).Trace("double proposal detected")
}

func (lc *LogConsumer[StateT, VoteT]) OnReceiveProposal(
	currentRank uint64,
	proposal *models.SignedProposal[StateT, VoteT],
) {
	logger := lc.logBasicStateData(lc.log, proposal.State).With(
		consensus.Uint64Param("cur_rank", currentRank),
	)
	lastRankTC := proposal.PreviousRankTimeoutCertificate
	if lastRankTC != nil {
		logger = logger.With(
			consensus.Uint64Param("last_rank_tc_rank", lastRankTC.GetRank()),
			consensus.Uint64Param(
				"last_rank_tc_newest_qc_rank",
				lastRankTC.GetLatestQuorumCert().GetRank(),
			),
			consensus.IdentityParam(
				"last_rank_tc_newest_qc_state_id",
				lastRankTC.GetLatestQuorumCert().Identity(),
			),
		)
	}

	logger.Trace("processing proposal")
}

func (lc *LogConsumer[StateT, VoteT]) OnReceiveQuorumCertificate(
	currentRank uint64,
	qc models.QuorumCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("cur_rank", currentRank),
		consensus.Uint64Param("qc_rank", qc.GetRank()),
		consensus.IdentityParam("qc_state_id", qc.Identity()),
	).Trace("processing QC")
}

func (lc *LogConsumer[StateT, VoteT]) OnReceiveTimeoutCertificate(
	currentRank uint64,
	tc models.TimeoutCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("cur_rank", currentRank),
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param("newest_qc_rank", tc.GetLatestQuorumCert().GetRank()),
		consensus.IdentityParam(
			"newest_qc_state_id",
			tc.GetLatestQuorumCert().Identity(),
		),
	).Trace("processing TC")
}

func (lc *LogConsumer[StateT, VoteT]) OnPartialTimeoutCertificate(
	currentRank uint64,
	partialTc *consensus.PartialTimeoutCertificateCreated,
) {
	logger := lc.log.With(
		consensus.Uint64Param("cur_rank", currentRank),
		consensus.Uint64Param("rank", partialTc.Rank),
		consensus.Uint64Param(
			"qc_rank",
			partialTc.NewestQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam(
			"qc_state_id",
			partialTc.NewestQuorumCertificate.Identity(),
		),
	)
	lastRankTC := partialTc.PriorRankTimeoutCertificate
	if lastRankTC != nil {
		logger = logger.With(
			consensus.Uint64Param("last_rank_tc_rank", lastRankTC.GetRank()),
			consensus.Uint64Param(
				"last_rank_tc_newest_qc_rank",
				lastRankTC.GetLatestQuorumCert().GetRank(),
			),
			consensus.IdentityParam(
				"last_rank_tc_newest_qc_state_id",
				lastRankTC.GetLatestQuorumCert().Identity(),
			),
		)
	}

	logger.Trace("processing partial TC")
}

func (lc *LogConsumer[StateT, VoteT]) OnLocalTimeout(currentRank uint64) {
	lc.log.With(
		consensus.Uint64Param("cur_rank", currentRank),
	).Trace("processing local timeout")
}

func (lc *LogConsumer[StateT, VoteT]) OnRankChange(oldRank, newRank uint64) {
	lc.log.With(
		consensus.Uint64Param("old_rank", oldRank),
		consensus.Uint64Param("new_rank", newRank),
	).Trace("entered new rank")
}

func (lc *LogConsumer[StateT, VoteT]) OnQuorumCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	qc models.QuorumCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("qc_rank", qc.GetRank()),
		consensus.IdentityParam("qc_state_id", qc.Identity()),
		consensus.Uint64Param("old_rank", oldRank),
		consensus.Uint64Param("new_rank", newRank),
	).Trace("QC triggered rank change")
}

func (lc *LogConsumer[StateT, VoteT]) OnTimeoutCertificateTriggeredRankChange(
	oldRank uint64,
	newRank uint64,
	tc models.TimeoutCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param(
			"tc_newest_qc_rank",
			tc.GetLatestQuorumCert().GetRank(),
		),
		consensus.Uint64Param("new_rank", newRank),
		consensus.Uint64Param("old_rank", oldRank),
	).Trace("TC triggered rank change")
}

func (lc *LogConsumer[StateT, VoteT]) OnStartingTimeout(
	startTime time.Time,
	endTime time.Time,
) {
	lc.log.With(
		consensus.TimeParam("timeout_start", startTime),
		consensus.TimeParam("timeout_cutoff", endTime),
	).Trace("timeout started")
}

func (lc *LogConsumer[StateT, VoteT]) OnVoteProcessed(vote *VoteT) {
	lc.log.With(
		consensus.IdentityParam("state_id", (*vote).Source()),
		consensus.Uint64Param("state_rank", (*vote).GetRank()),
		consensus.IdentityParam("recipient_id", (*vote).Identity()),
	).Trace("processed valid HotStuff vote")
}

func (lc *LogConsumer[StateT, VoteT]) OnTimeoutProcessed(
	timeout *models.TimeoutState[VoteT],
) {
	logger := lc.log.With(
		consensus.Uint64Param("timeout_rank", timeout.Rank),
		consensus.Uint64Param(
			"timeout_newest_qc_rank",
			timeout.LatestQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam("timeout_vote_id", (*timeout.Vote).Identity()),
		consensus.Uint64Param("timeout_tick", timeout.TimeoutTick),
	)
	if timeout.PriorRankTimeoutCertificate != nil {
		logger = logger.With(
			consensus.Uint64Param(
				"timeout_last_tc_rank",
				timeout.PriorRankTimeoutCertificate.GetRank(),
			),
		)
	}
	logger.Trace("processed valid timeout object")
}

func (lc *LogConsumer[StateT, VoteT]) OnCurrentRankDetails(
	currentRank, finalizedRank uint64,
	currentLeader models.Identity,
) {
	lc.log.With(
		consensus.Uint64Param("rank", currentRank),
		consensus.Uint64Param("finalized_rank", finalizedRank),
		consensus.IdentityParam("current_leader", currentLeader),
	).Trace("current rank details")
}

func (lc *LogConsumer[StateT, VoteT]) OnDoubleVotingDetected(
	vote *VoteT,
	alt *VoteT,
) {
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.Uint64Param("vote_rank", (*vote).GetRank()),
		consensus.IdentityParam("voted_state_id", (*vote).Source()),
		consensus.IdentityParam("alt_id", (*vote).Source()),
		consensus.IdentityParam("voter_id", (*vote).Identity()),
	).Trace("double vote detected")
}

func (lc *LogConsumer[StateT, VoteT]) OnInvalidVoteDetected(
	err models.InvalidVoteError[VoteT],
) {
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.Uint64Param("vote_rank", (*err.Vote).GetRank()),
		consensus.IdentityParam("voted_state_id", (*err.Vote).Source()),
		consensus.IdentityParam("voter_id", (*err.Vote).Identity()),
	).Error("invalid vote detected", err)
}

func (lc *LogConsumer[StateT, VoteT]) OnVoteForInvalidStateDetected(
	vote *VoteT,
	proposal *models.SignedProposal[StateT, VoteT],
) {
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.Uint64Param("vote_rank", (*vote).GetRank()),
		consensus.IdentityParam("voted_state_id", (*vote).Source()),
		consensus.IdentityParam("voter_id", (*vote).Identity()),
		consensus.IdentityParam("proposer_id", proposal.State.ProposerID),
	).Trace("vote for invalid proposal detected")
}

func (lc *LogConsumer[StateT, VoteT]) OnDoubleTimeoutDetected(
	timeout *models.TimeoutState[VoteT],
	alt *models.TimeoutState[VoteT],
) {
	lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.IdentityParam("timeout_signer_id", (*timeout.Vote).Identity()),
		consensus.Uint64Param("timeout_rank", timeout.Rank),
		consensus.Uint64Param(
			"timeout_newest_qc_rank",
			timeout.LatestQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam("alt_signer_id", (*alt.Vote).Identity()),
		consensus.Uint64Param("alt_rank", alt.Rank),
		consensus.Uint64Param(
			"alt_newest_qc_rank",
			alt.LatestQuorumCertificate.GetRank(),
		),
	).Trace("double timeout detected")
}

func (lc *LogConsumer[StateT, VoteT]) OnInvalidTimeoutDetected(
	err models.InvalidTimeoutError[VoteT],
) {
	timeout := err.Timeout
	logger := lc.log.With(
		consensus.StringParam("suspicious", "true"),
		consensus.Uint64Param("timeout_rank", timeout.Rank),
		consensus.Uint64Param(
			"timeout_newest_qc_rank",
			timeout.LatestQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam("timeout_vote_id", (*timeout.Vote).Identity()),
		consensus.Uint64Param("timeout_tick", timeout.TimeoutTick),
	)
	if timeout.PriorRankTimeoutCertificate != nil {
		logger = logger.With(
			consensus.Uint64Param(
				"timeout_last_tc_rank",
				timeout.PriorRankTimeoutCertificate.GetRank(),
			),
		)
	}
	logger.Error("invalid timeout detected", err)
}

func (lc *LogConsumer[StateT, VoteT]) logBasicStateData(
	logger consensus.TraceLogger,
	state *models.State[StateT],
) consensus.TraceLogger {
	return logger.With(
		consensus.Uint64Param("state_rank", state.Rank),
		consensus.IdentityParam("state_id", state.Identifier),
		consensus.IdentityParam("proposer_id", state.ProposerID),
		consensus.Uint64Param("qc_rank", state.ParentQuorumCertificate.GetRank()),
		consensus.IdentityParam(
			"qc_state_id",
			state.ParentQuorumCertificate.Identity(),
		),
	)
}

func (
	lc *LogConsumer[StateT, VoteT],
) OnTimeoutCertificateConstructedFromTimeouts(
	tc models.TimeoutCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param("newest_qc_rank", tc.GetLatestQuorumCert().GetRank()),
		consensus.IdentityParam(
			"newest_qc_state_id",
			tc.GetLatestQuorumCert().Identity(),
		),
	).Trace("TC constructed")
}

func (lc *LogConsumer[StateT, VoteT]) OnPartialTimeoutCertificateCreated(
	rank uint64,
	newestQC models.QuorumCertificate,
	lastRankTC models.TimeoutCertificate,
) {
	has := "false"
	if lastRankTC != nil {
		has = "true"
	}
	lc.log.With(
		consensus.Uint64Param("rank", rank),
		consensus.Uint64Param("newest_qc_rank", newestQC.GetRank()),
		consensus.IdentityParam("newest_qc_state_id", newestQC.Identity()),
		consensus.StringParam("has_last_rank_tc", has),
	).Trace("partial TC constructed")
}

func (lc *LogConsumer[StateT, VoteT]) OnNewQuorumCertificateDiscovered(
	qc models.QuorumCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("qc_rank", qc.GetRank()),
		consensus.IdentityParam("qc_state_id", qc.Identity()),
	).Trace("new QC discovered")
}

func (lc *LogConsumer[StateT, VoteT]) OnNewTimeoutCertificateDiscovered(
	tc models.TimeoutCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("tc_rank", tc.GetRank()),
		consensus.Uint64Param("newest_qc_rank", tc.GetLatestQuorumCert().GetRank()),
		consensus.IdentityParam(
			"newest_qc_state_id",
			tc.GetLatestQuorumCert().Identity(),
		),
	).Trace("new TC discovered")
}

func (lc *LogConsumer[StateT, VoteT]) OnOwnVote(
	vote *VoteT,
	recipientID models.Identity,
) {
	lc.log.With(
		consensus.IdentityParam("state_id", (*vote).Source()),
		consensus.Uint64Param("state_rank", (*vote).GetRank()),
		consensus.IdentityParam("recipient_id", recipientID),
	).Trace("publishing HotStuff vote")
}

func (lc *LogConsumer[StateT, VoteT]) OnOwnTimeout(
	timeout *models.TimeoutState[VoteT],
) {
	logger := lc.log.With(
		consensus.Uint64Param("timeout_rank", timeout.Rank),
		consensus.Uint64Param(
			"timeout_newest_qc_rank",
			timeout.LatestQuorumCertificate.GetRank(),
		),
		consensus.IdentityParam("timeout_vote_id", (*timeout.Vote).Identity()),
		consensus.Uint64Param("timeout_tick", timeout.TimeoutTick),
	)
	if timeout.PriorRankTimeoutCertificate != nil {
		logger = logger.With(
			consensus.Uint64Param(
				"timeout_last_tc_rank",
				timeout.PriorRankTimeoutCertificate.GetRank(),
			),
		)
	}
	logger.Trace("publishing HotStuff timeout object")
}

func (lc *LogConsumer[StateT, VoteT]) OnOwnProposal(
	proposal *models.SignedProposal[StateT, VoteT],
	targetPublicationTime time.Time,
) {
	header := proposal.Proposal
	lc.log.With(
		consensus.Uint64Param(
			"state_frame",
			header.State.ParentQuorumCertificate.GetFrameNumber()+1,
		),
		consensus.Uint64Param("state_rank", header.State.Rank),
		consensus.IdentityParam("state_id", header.State.Identifier),
		consensus.IdentityParam(
			"parent_qc_id",
			header.State.ParentQuorumCertificate.Identity(),
		),
		consensus.TimeParam(
			"timestamp",
			time.UnixMilli(int64(header.State.Timestamp)),
		),
		consensus.TimeParam("target_publication_time", targetPublicationTime),
	).Trace("publishing HotStuff state proposal")
}

func (lc *LogConsumer[StateT, VoteT]) OnQuorumCertificateConstructedFromVotes(
	qc models.QuorumCertificate,
) {
	lc.log.With(
		consensus.Uint64Param("rank", qc.GetRank()),
		consensus.IdentityParam("state_id", qc.Identity()),
	).Trace("QC constructed from votes")
}
