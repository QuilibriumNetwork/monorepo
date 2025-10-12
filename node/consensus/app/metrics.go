package app

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "app_consensus"
)

var (
	// Frame processing metrics
	framesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frames_processed_total",
			Help:      "Total number of frames processed by the app consensus engine",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "invalid"
	)

	frameProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_processing_duration_seconds",
			Help:      "Time taken to process a frame",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Frame validation metrics
	frameValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_validation_total",
			Help:      "Total number of frame validations",
		},
		[]string{"app_address", "result"}, // result: "accept", "reject", "ignore"
	)

	frameValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_validation_duration_seconds",
			Help:      "Time taken to validate a frame",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Frame proving metrics
	frameProvingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_proving_total",
			Help:      "Total number of frame proving attempts",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "skipped"
	)

	frameProvingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_proving_duration_seconds",
			Help:      "Time taken to prove a frame",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60}, // Up to 1 minute
		},
		[]string{"app_address"},
	)

	// Frame publishing metrics
	framePublishingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_publishing_total",
			Help:      "Total number of frame publishing attempts",
		},
		[]string{"app_address", "status"}, // status: "success", "error"
	)

	framePublishingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_publishing_duration_seconds",
			Help:      "Time taken to publish a frame",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard liveness check processing metrics
	livenessCheckProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_processed_total",
			Help:      "Total number of shard liveness checks processed by the app consensus engine",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "invalid"
	)

	livenessCheckProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_processing_duration_seconds",
			Help:      "Time taken to process a shard liveness check",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard liveness check validation metrics
	livenessCheckValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_validation_total",
			Help:      "Total number of shard liveness check validations",
		},
		[]string{"app_address", "result"}, // result: "accept", "reject", "ignore"
	)

	livenessCheckValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "liveness_check_validation_duration_seconds",
			Help:      "Time taken to validate a shard liveness check",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard vote processing metrics
	voteProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_processed_total",
			Help:      "Total number of shard votes processed by the app consensus engine",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "invalid"
	)

	voteProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_processing_duration_seconds",
			Help:      "Time taken to process a shard vote",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard vote validation metrics
	voteValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_validation_total",
			Help:      "Total number of shard vote validations",
		},
		[]string{"app_address", "result"}, // result: "accept", "reject", "ignore"
	)

	voteValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vote_validation_duration_seconds",
			Help:      "Time taken to validate a shard vote",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard confirmation processing metrics
	confirmationProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_processed_total",
			Help:      "Total number of shard confirmations processed by the app consensus engine",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "invalid"
	)

	confirmationProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_processing_duration_seconds",
			Help:      "Time taken to process a shard confirmation",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard confirmation validation metrics
	confirmationValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_validation_total",
			Help:      "Total number of shard confirmation validations",
		},
		[]string{"app_address", "result"}, // result: "accept", "reject", "ignore"
	)

	confirmationValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "confirmation_validation_duration_seconds",
			Help:      "Time taken to validate a shard confirmation",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard proposal processing metrics
	proposalProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_processed_total",
			Help:      "Total number of shard proposals processed by the app consensus engine",
		},
		[]string{"app_address", "status"}, // status: "success", "error", "invalid"
	)

	proposalProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_processing_duration_seconds",
			Help:      "Time taken to process a shard proposal",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Shard proposal validation metrics
	proposalValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_validation_total",
			Help:      "Total number of shard proposal validations",
		},
		[]string{"app_address", "result"}, // result: "accept", "reject", "ignore"
	)

	proposalValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "proposal_validation_duration_seconds",
			Help:      "Time taken to validate a shard proposal",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"app_address"},
	)

	// Global frame processing metrics
	globalFramesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_frames_processed_total",
			Help:      "Total number of frames processed by the app consensus engine",
		},
		[]string{"status"}, // status: "success", "error", "invalid"
	)

	globalFrameProcessingDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_frame_processing_duration_seconds",
			Help:      "Time taken to process a global frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Frame validation metrics
	globalFrameValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_frame_validation_total",
			Help:      "Total number of global frame validations",
		},
		[]string{"result"}, // result: "accept", "reject", "ignore"
	)

	globalFrameValidationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "global_frame_validation_duration_seconds",
			Help:      "Time taken to validate a global frame",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Transaction collection metrics
	transactionsCollectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "transactions_collected_total",
			Help:      "Total number of transactions collected",
		},
		[]string{"app_address"},
	)

	pendingMessagesCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "pending_messages_count",
			Help:      "Current number of pending messages",
		},
		[]string{"app_address"},
	)

	// Executor metrics
	executorsRegistered = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "executors_registered",
			Help:      "Current number of registered executors",
		},
		[]string{"app_address"},
	)

	executorRegistrationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "executor_registration_total",
			Help:      "Total number of executor registrations",
		},
		[]string{"app_address", "action"}, // action: "register", "unregister"
	)

	// Sync status metrics
	syncStatusCheck = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "sync_status_check_total",
			Help:      "Total number of sync status checks",
		},
		[]string{"app_address", "result"}, // result: "synced", "syncing"
	)

	// Engine state metrics
	engineState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "engine_state",
			Help:      "Current state of the app consensus engine (0=stopped, 1=starting, 2=loading, 3=collecting, 4=proving, 5=publishing, 6=verifying, 7=stopping)",
		},
		[]string{"app_address"},
	)

	// Difficulty metrics
	currentDifficulty = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "current_difficulty",
			Help:      "Current difficulty value for the app consensus",
		},
		[]string{"app_address"},
	)

	// Time since last proven frame
	timeSinceLastProvenFrame = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "time_since_last_proven_frame_seconds",
			Help:      "Time in seconds since the last frame was proven",
		},
		[]string{"app_address"},
	)

	// Current frame metrics
	currentFrameNumber = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "current_frame_number",
			Help:      "Current frame number being processed",
		},
		[]string{"app_address"},
	)

	// Prover key lookup metrics
	proverKeyLookupTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "prover_key_lookup_total",
			Help:      "Total number of prover key lookups",
		},
		// result: "found", "not_found", "error"
		[]string{"app_address", "result"},
	)
)
