package observability

import (
	"encoding/base64"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

const blossomSubNamespace = "blossomsub"

var binaryEncoding = base64.RawStdEncoding

type blossomSubRawTracer struct {
	addPeerTotal              *prometheus.CounterVec
	removePeerTotal           prometheus.Counter
	joinTotal                 *prometheus.CounterVec
	leaveTotal                *prometheus.CounterVec
	graftTotal                *prometheus.CounterVec
	pruneTotal                *prometheus.CounterVec
	validateMessageTotal      *prometheus.CounterVec
	deliverMessageTotal       *prometheus.CounterVec
	rejectMessageTotal        *prometheus.CounterVec
	duplicateMessageTotal     *prometheus.CounterVec
	throttlePeerTotal         prometheus.Counter
	recvRPCTotal              prometheus.Counter
	sendRPCTotal              prometheus.Counter
	dropRPCTotal              prometheus.Counter
	undeliverableMessageTotal *prometheus.CounterVec
	iHaveMessageHistogram     *prometheus.HistogramVec
	iWantMessageHistogram     *prometheus.HistogramVec
	iDontWantMessageHistogram *prometheus.HistogramVec
}

func (b *blossomSubRawTracer) observeControl(control *pb.ControlMessage, direction string) {
	labels := []string{direction}
	for _, iHave := range control.GetIhave() {
		labels := append(labels, binaryEncoding.EncodeToString(iHave.GetBitmask()))
		b.iHaveMessageHistogram.WithLabelValues(labels...).Observe(float64(len(iHave.GetMessageIDs())))
	}
	for _, iWant := range control.GetIwant() {
		b.iWantMessageHistogram.WithLabelValues(labels...).Observe(float64(len(iWant.GetMessageIDs())))
	}
	for _, iDontWant := range control.GetIdontwant() {
		b.iDontWantMessageHistogram.WithLabelValues(labels...).Observe(float64(len(iDontWant.GetMessageIDs())))
	}
}

var _ blossomsub.RawTracer = (*blossomSubRawTracer)(nil)

// AddPeer implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) AddPeer(p peer.ID, proto protocol.ID) {
	b.addPeerTotal.WithLabelValues(string(proto)).Inc()
}

// RemovePeer implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) RemovePeer(p peer.ID) {
	b.removePeerTotal.Inc()
}

// Join implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) Join(bitmask []byte) {
	b.joinTotal.WithLabelValues(binaryEncoding.EncodeToString(bitmask)).Inc()
}

// Leave implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) Leave(bitmask []byte) {
	b.leaveTotal.WithLabelValues(binaryEncoding.EncodeToString(bitmask)).Inc()
}

// Graft implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) Graft(p peer.ID, bitmask []byte) {
	b.graftTotal.WithLabelValues(binaryEncoding.EncodeToString(bitmask)).Inc()
}

// Prune implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) Prune(p peer.ID, bitmask []byte) {
	b.pruneTotal.WithLabelValues(binaryEncoding.EncodeToString(bitmask)).Inc()
}

// ValidateMessage implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) ValidateMessage(msg *blossomsub.Message) {
	b.validateMessageTotal.WithLabelValues(binaryEncoding.EncodeToString(msg.GetBitmask())).Inc()
}

// SignMessage implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) DeliverMessage(msg *blossomsub.Message) {
	b.deliverMessageTotal.WithLabelValues(binaryEncoding.EncodeToString(msg.GetBitmask())).Inc()
}

// RejectMessage implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) RejectMessage(msg *blossomsub.Message, reason string) {
	b.rejectMessageTotal.WithLabelValues(binaryEncoding.EncodeToString(msg.GetBitmask()), reason).Inc()
}

// DuplicateMessage implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) DuplicateMessage(msg *blossomsub.Message) {
	b.duplicateMessageTotal.WithLabelValues(binaryEncoding.EncodeToString(msg.GetBitmask())).Inc()
}

// ThrottlePeer implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) ThrottlePeer(p peer.ID) {
	b.throttlePeerTotal.Inc()
}

// RecvRPC implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) RecvRPC(rpc *blossomsub.RPC) {
	b.recvRPCTotal.Inc()
	b.observeControl(rpc.GetControl(), "recv")
}

// SendRPC implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) SendRPC(rpc *blossomsub.RPC, p peer.ID) {
	b.sendRPCTotal.Inc()
	b.observeControl(rpc.GetControl(), "send")
}

// DropRPC implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) DropRPC(rpc *blossomsub.RPC, p peer.ID) {
	b.dropRPCTotal.Inc()
	b.observeControl(rpc.GetControl(), "drop")
}

// UndeliverableMessage implements blossomsub.RawTracer.
func (b *blossomSubRawTracer) UndeliverableMessage(msg *blossomsub.Message) {
	b.undeliverableMessageTotal.WithLabelValues(binaryEncoding.EncodeToString(msg.GetBitmask())).Inc()
}

var _ prometheus.Collector = (*blossomSubRawTracer)(nil)

// Describe implements prometheus.Collector.
func (b *blossomSubRawTracer) Describe(ch chan<- *prometheus.Desc) {
	b.addPeerTotal.Describe(ch)
	b.removePeerTotal.Describe(ch)
	b.joinTotal.Describe(ch)
	b.leaveTotal.Describe(ch)
	b.graftTotal.Describe(ch)
	b.pruneTotal.Describe(ch)
	b.validateMessageTotal.Describe(ch)
	b.deliverMessageTotal.Describe(ch)
	b.rejectMessageTotal.Describe(ch)
	b.duplicateMessageTotal.Describe(ch)
	b.throttlePeerTotal.Describe(ch)
	b.recvRPCTotal.Describe(ch)
	b.sendRPCTotal.Describe(ch)
	b.dropRPCTotal.Describe(ch)
	b.undeliverableMessageTotal.Describe(ch)
	b.iHaveMessageHistogram.Describe(ch)
	b.iWantMessageHistogram.Describe(ch)
	b.iDontWantMessageHistogram.Describe(ch)
}

// Collect implements prometheus.Collector.
func (b *blossomSubRawTracer) Collect(ch chan<- prometheus.Metric) {
	b.addPeerTotal.Collect(ch)
	b.removePeerTotal.Collect(ch)
	b.joinTotal.Collect(ch)
	b.leaveTotal.Collect(ch)
	b.graftTotal.Collect(ch)
	b.pruneTotal.Collect(ch)
	b.validateMessageTotal.Collect(ch)
	b.deliverMessageTotal.Collect(ch)
	b.rejectMessageTotal.Collect(ch)
	b.duplicateMessageTotal.Collect(ch)
	b.throttlePeerTotal.Collect(ch)
	b.recvRPCTotal.Collect(ch)
	b.sendRPCTotal.Collect(ch)
	b.dropRPCTotal.Collect(ch)
	b.undeliverableMessageTotal.Collect(ch)
	b.iHaveMessageHistogram.Collect(ch)
	b.iWantMessageHistogram.Collect(ch)
	b.iDontWantMessageHistogram.Collect(ch)
}

type BlossomSubRawTracer interface {
	blossomsub.RawTracer
	prometheus.Collector
}

func NewBlossomSubRawTracer() BlossomSubRawTracer {
	b := &blossomSubRawTracer{
		addPeerTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "add_peer_total",
				Help:      "Total number of peers added to the mesh.",
			},
			[]string{"protocol"},
		),
		removePeerTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "remove_peer_total",
				Help:      "Total number of peers removed from the mesh.",
			},
		),
		joinTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "join_total",
				Help:      "Total number of joins to the mesh.",
			},
			[]string{"bitmask"},
		),
		leaveTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "leave_total",
				Help:      "Total number of leaves from the mesh.",
			},
			[]string{"bitmask"},
		),
		graftTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "graft_total",
				Help:      "Total number of grafts.",
			},
			[]string{"bitmask"},
		),
		pruneTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "prune_total",
				Help:      "Total number of prunes.",
			},
			[]string{"bitmask"},
		),
		validateMessageTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "validate_message_total",
				Help:      "Total number of messages validated.",
			},
			[]string{"bitmask"},
		),
		deliverMessageTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "deliver_message_total",
				Help:      "Total number of messages delivered.",
			},
			[]string{"bitmask"},
		),
		rejectMessageTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "reject_message_total",
				Help:      "Total number of messages rejected.",
			},
			[]string{"bitmask", "reason"},
		),
		duplicateMessageTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "duplicate_message_total",
				Help:      "Total number of messages duplicated.",
			},
			[]string{"bitmask"},
		),
		throttlePeerTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "throttle_peer_total",
				Help:      "Total number of peers throttled.",
			},
		),
		recvRPCTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "recv_rpc_total",
				Help:      "Total number of RPCs received.",
			},
		),
		sendRPCTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "send_rpc_total",
				Help:      "Total number of RPCs sent.",
			},
		),
		dropRPCTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "drop_rpc_total",
				Help:      "Total number of RPCs dropped.",
			},
		),
		undeliverableMessageTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: blossomSubNamespace,
				Name:      "undeliverable_message_total",
				Help:      "Total number of messages undeliverable.",
			},
			[]string{"bitmask"},
		),
		iHaveMessageHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: blossomSubNamespace,
				Name:      "ihave_messages",
				Help:      "Histogram of the number of messages in an IHave message.",
				Buckets:   prometheus.ExponentialBuckets(1, 2, 14),
			},
			[]string{"direction", "bitmask"},
		),
		iWantMessageHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: blossomSubNamespace,
				Name:      "iwant_messages",
				Help:      "Histogram of the number of messages in an IWant message.",
				Buckets:   prometheus.ExponentialBuckets(1, 2, 14),
			},
			[]string{"direction"},
		),
		iDontWantMessageHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: blossomSubNamespace,
				Name:      "idontwant_messages",
				Help:      "Histogram of the number of messages in an IDontWant message.",
				Buckets:   prometheus.ExponentialBuckets(1, 2, 14),
			},
			[]string{"direction"},
		),
	}
	return b
}

var globalBlossomSubRawTracer = NewBlossomSubRawTracer()

func init() {
	prometheus.MustRegister(globalBlossomSubRawTracer)
}

func WithPrometheusRawTracer() blossomsub.Option {
	return blossomsub.WithRawTracer(globalBlossomSubRawTracer)
}
