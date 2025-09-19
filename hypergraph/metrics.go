package hypergraph

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	metricsNamespace = "quilibrium"
	subsystem        = "hypergraph"
)

var (
	// Core CRDT Operation Metrics
	AddVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "add_vertex_total",
			Help:      "Total number of add vertex operations",
		},
		[]string{"status"}, // success, error
	)

	RemoveVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "remove_vertex_total",
			Help:      "Total number of remove vertex operations",
		},
		[]string{"status"},
	)

	AddHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "add_hyperedge_total",
			Help:      "Total number of add hyperedge operations",
		},
		[]string{"status"},
	)

	RemoveHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "remove_hyperedge_total",
			Help:      "Total number of remove hyperedge operations",
		},
		[]string{"status"},
	)

	// Operation duration metrics
	AddVertexDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "add_vertex_duration_seconds",
			Help:      "Time taken to add a vertex",
			Buckets:   prometheus.DefBuckets,
		},
	)

	RemoveVertexDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "remove_vertex_duration_seconds",
			Help:      "Time taken to remove a vertex",
			Buckets:   prometheus.DefBuckets,
		},
	)

	AddHyperedgeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "add_hyperedge_duration_seconds",
			Help:      "Time taken to add a hyperedge",
			Buckets:   prometheus.DefBuckets,
		},
	)

	RemoveHyperedgeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "remove_hyperedge_duration_seconds",
			Help:      "Time taken to remove a hyperedge",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Revert operation metrics
	RevertAddVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "revert_add_vertex_total",
			Help:      "Total number of revert add vertex operations",
		},
		[]string{"status"},
	)

	RevertRemoveVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "revert_remove_vertex_total",
			Help:      "Total number of revert remove vertex operations",
		},
		[]string{"status"},
	)

	RevertAddHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "revert_add_hyperedge_total",
			Help:      "Total number of revert add hyperedge operations",
		},
		[]string{"status"},
	)

	RevertRemoveHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "revert_remove_hyperedge_total",
			Help:      "Total number of revert remove hyperedge operations",
		},
		[]string{"status"},
	)

	// Lookup/Query metrics
	LookupVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "lookup_vertex_total",
			Help:      "Total number of vertex lookups",
		},
		[]string{"found"}, // true, false
	)

	LookupHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "lookup_hyperedge_total",
			Help:      "Total number of hyperedge lookups",
		},
		[]string{"found"},
	)

	LookupAtomTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "lookup_atom_total",
			Help:      "Total number of atom lookups",
		},
		[]string{"type", "found"}, // type: vertex, hyperedge
	)

	LookupDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "lookup_duration_seconds",
			Help:      "Time taken for lookup operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"}, // vertex, hyperedge, atom
	)

	// Get operations (more expensive than lookups)
	GetVertexTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "get_vertex_total",
			Help:      "Total number of get vertex operations",
		},
		[]string{"status"}, // success, error, removed
	)

	GetHyperedgeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "get_hyperedge_total",
			Help:      "Total number of get hyperedge operations",
		},
		[]string{"status"},
	)

	GetVertexDataTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "get_vertex_data_total",
			Help:      "Total number of get vertex data operations",
		},
		[]string{"status"},
	)

	GetDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "get_duration_seconds",
			Help:      "Time taken for get operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"}, // vertex, hyperedge, vertex_data
	)

	// Transaction metrics
	TransactionTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "transaction_total",
			Help:      "Total number of transactions",
		},
		[]string{"indexed", "status"}, // indexed: true/false, status: success/error
	)

	TransactionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "transaction_duration_seconds",
			Help:      "Time taken to create transactions",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"indexed"},
	)

	CommitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "commit_total",
			Help:      "Total number of commit operations",
		},
		[]string{"status"},
	)

	CommitDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "commit_duration_seconds",
			Help:      "Time taken to commit",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Size and state metrics
	SizeTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "size_total",
			Help:      "Current total size of the hypergraph",
		},
	)

	VertexAddsShards = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_adds_shards",
			Help:      "Number of vertex add shards",
		},
	)

	VertexRemovesShards = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_removes_shards",
			Help:      "Number of vertex remove shards",
		},
	)

	HyperedgeAddsShards = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "hyperedge_adds_shards",
			Help:      "Number of hyperedge add shards",
		},
	)

	HyperedgeRemovesShards = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "hyperedge_removes_shards",
			Help:      "Number of hyperedge remove shards",
		},
	)

	// Proof generation/verification metrics
	TraversalProofCreateTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "traversal_proof_create_total",
			Help:      "Total number of traversal proof creations",
		},
		[]string{"atom_type", "phase_type"}, // atom_type: vertex/hyperedge, phase_type: adds/removes
	)

	TraversalProofVerifyTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "traversal_proof_verify_total",
			Help:      "Total number of traversal proof verifications",
		},
		[]string{"atom_type", "phase_type", "valid"}, // valid: true/false
	)

	TraversalProofDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "traversal_proof_duration_seconds",
			Help:      "Time taken for traversal proof operations",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"}, // create, verify
	)

	TraversalProofKeysPerRequest = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "traversal_proof_keys_per_request",
			Help:      "Number of keys per traversal proof request",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 10), // 1 to 512
		},
	)

	// Data management metrics
	VertexDataSetTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_data_set_total",
			Help:      "Total number of vertex data set operations",
		},
		[]string{"status"},
	)

	VertexDataTombstoneTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_data_tombstone_total",
			Help:      "Total number of vertex data tombstone operations",
		},
		[]string{"status"},
	)

	VertexDataUndoTombstoneTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_data_undo_tombstone_total",
			Help:      "Total number of vertex data undo tombstone operations",
		},
		[]string{"status"},
	)

	VertexDataPruningTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_data_pruning_total",
			Help:      "Total number of vertex data pruning operations",
		},
		[]string{"status"},
	)

	VertexDataPruningDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "vertex_data_pruning_duration_seconds",
			Help:      "Time taken to prune vertex data",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Import/Export metrics
	ImportTreeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "import_tree_total",
			Help:      "Total number of tree imports",
		},
		[]string{"atom_type", "phase_type", "status"},
	)

	ImportTreeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "import_tree_duration_seconds",
			Help:      "Time taken to import trees",
			Buckets:   prometheus.DefBuckets,
		},
	)

	ImportTreeSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "import_tree_size",
			Help:      "Size of imported trees",
			Buckets:   prometheus.ExponentialBuckets(1, 100, 10), // 1 to 10EB
		},
	)

	// Error metrics
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "errors_total",
			Help:      "Total number of errors by operation and type",
		},
		[]string{"operation", "error_type"},
	)

	// Within operation metrics (can be expensive)
	WithinOperationTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "within_operation_total",
			Help:      "Total number of Within operations",
		},
	)

	WithinOperationDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: subsystem,
			Name:      "within_operation_duration_seconds",
			Help:      "Time taken for Within operations",
			Buckets:   prometheus.DefBuckets,
		},
	)
)
