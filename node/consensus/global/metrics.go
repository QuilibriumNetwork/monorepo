package global

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "global_consensus"
)

var (
	// Frame processing metrics
	framesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frames_processed_total",
			Help:      "Total number of frames processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	frameProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_processing_duration_seconds",
			Help:      "Time taken to process a global frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Frame processing metrics
	shardFramesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_frames_processed_total",
			Help:      "Total number of shard frames processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	shardFrameProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_frame_processing_duration_seconds",
			Help:      "Time taken to process a shard frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Frame validation metrics
	frameValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_validation_total",
			Help:      "Total number of global frame validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	frameValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_validation_duration_seconds",
			Help:      "Time taken to validate a global frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard frame validation metrics
	shardFrameValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_frame_validation_total",
			Help:      "Total number of shard frame validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	shardFrameValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_frame_validation_duration_seconds",
			Help:      "Time taken to validate a shard frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global liveness check processing metrics
	livenessCheckProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_processed_total",
			Help:      "Total number of global liveness checks processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	livenessCheckProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_processing_duration_seconds",
			Help:      "Time taken to process a global liveness check",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global liveness check validation metrics
	livenessCheckValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_validation_total",
			Help:      "Total number of global liveness check validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	livenessCheckValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_validation_duration_seconds",
			Help:      "Time taken to validate a global liveness check",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard liveness check processing metrics
	shardLivenessCheckProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_liveness_check_processed_total",
			Help:      "Total number of shard liveness checks processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	shardLivenessCheckProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_liveness_check_processing_duration_seconds",
			Help:      "Time taken to process a shard liveness check",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard liveness check validation metrics
	shardLivenessCheckValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_liveness_check_validation_total",
			Help:      "Total number of shard liveness check validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	shardLivenessCheckValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_liveness_check_validation_duration_seconds",
			Help:      "Time taken to validate a shard liveness check",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global vote processing metrics
	voteProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_processed_total",
			Help:      "Total number of global votes processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	voteProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_processing_duration_seconds",
			Help:      "Time taken to process a global vote",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global vote validation metrics
	voteValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_validation_total",
			Help:      "Total number of global vote validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	voteValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_validation_duration_seconds",
			Help:      "Time taken to validate a global vote",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard vote processing metrics
	shardVoteProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_vote_processed_total",
			Help:      "Total number of shard votes processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	shardVoteProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_vote_processing_duration_seconds",
			Help:      "Time taken to process a shard vote",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard vote validation metrics
	shardVoteValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_vote_validation_total",
			Help:      "Total number of shard vote validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	shardVoteValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_vote_validation_duration_seconds",
			Help:      "Time taken to validate a shard vote",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global confirmation processing metrics
	confirmationProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_processed_total",
			Help:      "Total number of global confirmations processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	confirmationProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_processing_duration_seconds",
			Help:      "Time taken to process a global confirmation",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global confirmation validation metrics
	confirmationValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_validation_total",
			Help:      "Total number of global confirmation validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	confirmationValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_validation_duration_seconds",
			Help:      "Time taken to validate a global confirmation",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard confirmation processing metrics
	shardConfirmationProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_confirmation_processed_total",
			Help:      "Total number of shard confirmations processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	shardConfirmationProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_confirmation_processing_duration_seconds",
			Help:      "Time taken to process a shard confirmation",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard confirmation validation metrics
	shardConfirmationValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_confirmation_validation_total",
			Help:      "Total number of shard confirmation validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	shardConfirmationValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_confirmation_validation_duration_seconds",
			Help:      "Time taken to validate a shard confirmation",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global proposal processing metrics
	proposalProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_processed_total",
			Help:      "Total number of global proposals processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	proposalProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_processing_duration_seconds",
			Help:      "Time taken to process a global proposal",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Global proposal validation metrics
	proposalValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_validation_total",
			Help:      "Total number of global proposal validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	proposalValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_validation_duration_seconds",
			Help:      "Time taken to validate a global proposal",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard proposal processing metrics
	shardProposalProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_proposal_processed_total",
			Help:      "Total number of shard proposals processed by the global consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	shardProposalProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_proposal_processing_duration_seconds",
			Help:      "Time taken to process a shard proposal",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard proposal validation metrics
	shardProposalValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_proposal_validation_total",
			Help:      "Total number of shard proposal validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	shardProposalValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_proposal_validation_duration_seconds",
			Help:      "Time taken to validate a shard proposal",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Frame proving metrics
	frameProvingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_proving_total",
			Help:      "Total number of global frame proving attempts",
		},
		[]string{"status"}, // status: "success", "error", "skipped"
	)

	frameProvingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_proving_duration_seconds",
			Help:      "Time taken to prove a global frame",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60}, // Up to 1 minute
		},
	)

	// Frame publishing metrics
	framePublishingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_publishing_total",
			Help:      "Total number of global frame publishing attempts",
		},
		[]string{"status"}, // status: "success", "error"
	)

	framePublishingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_publishing_duration_seconds",
			Help:      "Time taken to publish a global frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Shard commitment metrics
	shardCommitmentsCollected = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_commitments_collected",
			Help:      "Current number of shard commitments collected",
		},
	)

	shardCommitmentCollectionDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "shard_commitment_collection_duration_seconds",
			Help:      "Time taken to collect shard commitments",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Executor metrics
	executorsRegistered = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "executors_registered",
			Help:      "Current number of registered executors",
		},
	)

	executorRegistrationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "executor_registration_total",
			Help:      "Total number of executor registrations",
		},
		[]string{"action"}, // action: "register", "unregister"
	)

	// Sync status metrics
	syncStatusCheck = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "sync_status_check_total",
			Help:      "Total number of sync status checks",
		},
		[]string{"result"}, // result: "synced", "syncing"
	)

	// Engine state metrics
	engineState = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "engine_state",
			Help:      "Current state of the global consensus engine (0=stopped, 1=starting, 2=loading, 3=collecting, 4=proving, 5=publishing, 6=verifying, 7=stopping)",
		},
	)

	// Difficulty metrics
	currentDifficulty = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "current_difficulty",
			Help:      "Current difficulty value for the global consensus",
		},
	)

	// Time since last proven frame
	timeSinceLastProvenFrame = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "time_since_last_proven_frame_seconds",
			Help:      "Time in seconds since the last global frame was proven",
		},
	)

	// Current frame metrics
	currentFrameNumber = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "current_frame_number",
			Help:      "Current global frame number being processed",
		},
	)

	// Prover key lookup metrics
	proverKeyLookupTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "prover_key_lookup_total",
			Help:      "Total number of prover key lookups",
		},
		[]string{"result"}, // result: "found", "not_found", "error"
	)

	// Global coordination metrics
	globalCoordinationTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_coordination_total",
			Help:      "Total number of global coordination cycles",
		},
	)

	globalCoordinationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_coordination_duration_seconds",
			Help:      "Time taken for global coordination",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// State summary metrics
	stateSummariesAggregated = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "state_summaries_aggregated",
			Help:      "Number of shard state summaries aggregated in last coordination",
		},
	)
)
