package fees

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "dynamic_fees"
)

var (
	// Fee vote tracking metrics
	feeVotesAdded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fee_votes_added_total",
			Help:      "Total number of fee votes added to the sliding window",
		},
		[]string{"filter"},
	)

	feeVotesDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fee_votes_dropped_total",
			Help:      "Total number of fee votes dropped from the sliding window",
		},
		[]string{"filter"},
	)

	// Current state metrics
	currentFeeMultiplier = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "current_fee_multiplier",
			Help:      "Current calculated fee multiplier based on sliding window average",
		},
		[]string{"filter"},
	)

	slidingWindowSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "sliding_window_size",
			Help:      "Current number of votes in the sliding window",
		},
		[]string{"filter"},
	)

	// Vote distribution metrics
	feeVoteDistribution = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fee_vote_distribution",
			Help:      "Distribution of fee multiplier votes",
			// Buckets for fee multipliers
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128},
		},
		[]string{"filter"},
	)

	// Calculation metrics
	feeCalculationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "fee_calculation_duration_seconds",
			Help:      "Time taken to calculate the average fee multiplier",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"filter"},
	)

	// Memory management metrics
	filtersTracked = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "filters_tracked",
			Help:      "Number of filters currently being tracked",
		},
	)

	filtersPruned = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "filters_pruned_total",
			Help:      "Total number of filter entries pruned due to inactivity",
		},
	)
)
