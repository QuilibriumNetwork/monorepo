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
