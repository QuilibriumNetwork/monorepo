package intrinsics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "intrinsics"
)

var (
	// Materialize operation metrics
	MaterializeDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "materialize_duration_seconds",
			Help:      "Time taken to materialize intrinsic state",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"intrinsic_type"}, // compute, global, hypergraph, token
	)

	MaterializeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "materialize_total",
			Help:      "Total number of materialize operations",
		},
		[]string{"intrinsic_type", "status"}, // status: success, error
	)

	// Validate operation metrics
	ValidateDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "validate_duration_seconds",
			Help:      "Time taken to validate an intrinsic step",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"intrinsic_type"}, // intrinsic type only for overall timing
	)

	ValidateTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "validate_total",
			Help:      "Total number of successful validate operations",
		},
		[]string{"intrinsic_type", "operation"},
	)

	ValidateErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "validate_errors_total",
			Help:      "Total number of failed validate operations",
		},
		[]string{"intrinsic_type", "operation"},
	)

	// InvokeStep operation metrics
	InvokeStepDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "invoke_step_duration_seconds",
			Help:      "Time taken to execute an intrinsic step",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"intrinsic_type"}, // intrinsic type only for overall timing
	)

	InvokeStepTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "invoke_step_total",
			Help:      "Total number of successful invoke step operations",
		},
		[]string{"intrinsic_type", "operation"},
	)

	InvokeStepErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "invoke_step_errors_total",
			Help:      "Total number of failed invoke step operations",
		},
		[]string{"intrinsic_type", "operation"},
	)

	// Commit operation metrics
	CommitDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "commit_duration_seconds",
			Help:      "Time taken to commit intrinsic state",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"intrinsic_type"},
	)

	CommitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "commit_total",
			Help:      "Total number of successful commit operations",
		},
		[]string{"intrinsic_type"},
	)

	CommitErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "commit_errors_total",
			Help:      "Total number of failed commit operations",
		},
		[]string{"intrinsic_type"},
	)

	// Operation-specific duration metrics
	OperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "operation_duration_seconds",
			Help:      "Time taken for specific operations within InvokeStep",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"intrinsic_type", "operation"},
	)

	// State size metrics
	StateSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "state_size_bytes",
			Help:      "Current size of intrinsic state in bytes",
		},
		[]string{"intrinsic_type"},
	)

	// Operation-specific metrics
	OperationCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "operation_count_total",
			Help:      "Total count of specific operations by type",
		},
		[]string{"intrinsic_type", "operation"},
	)
)
