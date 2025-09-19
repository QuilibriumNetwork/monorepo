package time

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "time_reel"
)

var (
	// Frame processing metrics
	framesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frames_processed_total",
			Help:      "Total number of frames processed by the time reel",
		},
		// reel_type: "global" or "app", status: "success" or "error"
		[]string{"reel_type", "status"},
	)

	frameProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "frame_processing_duration_seconds",
			Help:      "Time taken to process a frame",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"reel_type"},
	)

	// Equivocation metrics
	equivocationsDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "equivocations_detected_total",
			Help:      "Total number of equivocations detected",
		},
		[]string{"reel_type"},
	)

	equivocatorsTracked = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "equivocators_tracked",
			Help:      "Current number of equivocators being tracked",
		},
		[]string{"reel_type"},
	)

	// Head change metrics
	headChangesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "head_changes_total",
			Help:      "Total number of head changes",
		},
		// change_type: "advance" or "reorganization"
		[]string{"reel_type", "change_type"},
	)

	reorganizationDepth = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "reorganization_depth",
			Help:      "Depth of reorganizations (number of frames rolled back)",
			Buckets:   []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
		[]string{"reel_type"},
	)

	// Tree metrics
	treeDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "tree_depth",
			Help:      "Current depth of the time reel tree",
		},
		[]string{"reel_type"},
	)

	treeNodeCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "tree_node_count",
			Help:      "Current number of nodes in the time reel tree",
		},
		[]string{"reel_type"},
	)

	pendingFramesCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "pending_frames_count",
			Help:      "Current number of frames waiting for their parent",
		},
		[]string{"reel_type"},
	)

	// Fork choice metrics
	forkChoiceEvaluations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fork_choice_evaluations_total",
			Help:      "Total number of fork choice evaluations",
		},
		[]string{"reel_type"},
	)

	forkChoiceDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fork_choice_duration_seconds",
			Help:      "Time taken to evaluate fork choice",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"reel_type"},
	)

	competingBranches = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "competing_branches_count",
			Help:      "Number of competing branches during fork choice evaluation",
			Buckets:   []float64{1, 2, 3, 5, 10, 20, 50},
		},
		[]string{"reel_type"},
	)
)
