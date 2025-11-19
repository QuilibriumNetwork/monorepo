package worker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Worker manager metrics
	workerOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "operations_total",
			Help:      "Total number of worker operations",
		},
		// operation: register/allocate/deallocate, status: success/error
		[]string{"operation", "status"},
	)

	activeWorkersGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "active_workers",
			Help:      "Number of currently active workers",
		},
	)

	allocatedWorkersGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "allocated_workers",
			Help:      "Number of currently allocated workers",
		},
	)

	totalStorageGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "total_storage_bytes",
			Help:      "Total storage capacity across all workers",
		},
	)

	workerOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "operation_duration_seconds",
			Help:      "Duration of worker operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"}, // operation: register/allocate/deallocate/lookup
	)

	availableStorageGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "quilibrium",
			Subsystem: "worker_manager",
			Name:      "available_storage_bytes",
			Help:      "Aggregated available storage (bytes) across workers as estimated by the manager",
		},
	)
)
