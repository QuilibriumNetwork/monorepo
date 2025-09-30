package manager

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Execution engine metrics
	executionRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "quilibrium",
			Subsystem: "execution_manager",
			Name:      "requests_total",
			Help:      "Total number of execution requests processed",
		},
		[]string{"engine", "status"}, // engine: global/compute/token/hypergraph, status: success/error
	)

	executionRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "quilibrium",
			Subsystem: "execution_manager",
			Name:      "request_duration_seconds",
			Help:      "Duration of execution request processing",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"engine"}, // engine: global/compute/token/hypergraph
	)
)