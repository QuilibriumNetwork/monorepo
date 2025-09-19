package events

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "event_distributor"
)

var (
	// Event processing metrics
	eventsProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "events_processed_total",
			Help:      "Total number of events processed by the distributor",
		},
		// distributor_type: "global" or "app", event_type: see getEventTypeString
		[]string{"distributor_type", "event_type"},
	)

	eventProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "event_processing_duration_seconds",
			Help:      "Time taken to process and broadcast an event",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"distributor_type"},
	)

	// Subscriber metrics
	subscribersCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "subscribers_count",
			Help:      "Current number of active subscribers",
		},
		[]string{"distributor_type"},
	)

	subscriptionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "subscriptions_total",
			Help:      "Total number of subscriptions created",
		},
		[]string{"distributor_type"},
	)

	unsubscriptionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "unsubscriptions_total",
			Help:      "Total number of unsubscriptions",
		},
		[]string{"distributor_type"},
	)

	// Broadcast metrics
	broadcastsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "broadcasts_total",
			Help:      "Total number of event broadcasts",
		},
		[]string{"distributor_type", "event_type"},
	)

	broadcastDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "broadcast_duration_seconds",
			Help:      "Time taken to broadcast an event to all subscribers",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"distributor_type"},
	)

	// Lifecycle metrics
	distributorStartsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "starts_total",
			Help:      "Total number of distributor starts",
		},
		[]string{"distributor_type"},
	)

	distributorStopsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "stops_total",
			Help:      "Total number of distributor stops",
		},
		[]string{"distributor_type"},
	)

	distributorUptime = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "uptime_seconds",
			Help:      "Time since the distributor was started",
		},
		[]string{"distributor_type"},
	)
)

// Helper function to get event type string for metrics
func getEventTypeString(eventType consensus.ControlEventType) string {
	switch eventType {
	case consensus.ControlEventGlobalNewHead:
		return "global_new_head"
	case consensus.ControlEventGlobalFork:
		return "global_fork"
	case consensus.ControlEventGlobalEquivocation:
		return "global_equivocation"
	case consensus.ControlEventAppNewHead:
		return "app_new_head"
	case consensus.ControlEventAppFork:
		return "app_fork"
	case consensus.ControlEventAppEquivocation:
		return "app_equivocation"
	case consensus.ControlEventStart:
		return "start"
	case consensus.ControlEventStop:
		return "stop"
	case consensus.ControlEventHalt:
		return "halt"
	case consensus.ControlEventResume:
		return "resume"
	default:
		return "unknown"
	}
}
