package sync

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "sync"
)

var (
	// Sync status metrics
	syncStatusCheck = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "sync_status_check_total",
			Help:      "Total number of sync status checks",
		},
		[]string{"filter", "result"}, // result: "synced", "syncing"
	)
)
