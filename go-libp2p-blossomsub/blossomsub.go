package blossomsub

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sort"
	"time"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/record"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
)

const (
	// BlossomSubID_v2 is the protocol ID for version 2.0.0 of the BlossomSub protocol.
	BlossomSubID_v2 = protocol.ID("/blossomsub/2.0.0")

	// BlossomSubID_v21 is the protocol ID for version 2.1.0 of the BlossomSub protocol.
	BlossomSubID_v21 = protocol.ID("/blossomsub/2.1.0")
)

// Defines the default BlossomSub parameters.
var (
	BlossomSubD                                = 8
	BlossomSubDlo                              = 6
	BlossomSubDhi                              = 12
	BlossomSubDscore                           = 4
	BlossomSubDout                             = 2
	BlossomSubHistoryLength                    = 9
	BlossomSubHistoryGossip                    = 6
	BlossomSubDlazy                            = 6
	BlossomSubGossipFactor                     = 0.25
	BlossomSubGossipRetransmission             = 3
	BlossomSubBitmaskWidth                     = 256
	BlossomSubHeartbeatInitialDelay            = 100 * time.Millisecond
	BlossomSubHeartbeatInterval                = 700 * time.Millisecond
	BlossomSubFanoutTTL                        = 60 * time.Second
	BlossomSubPrunePeers                       = 16
	BlossomSubPruneBackoff                     = time.Minute
	BlossomSubUnsubscribeBackoff               = 10 * time.Second
	BlossomSubConnectors                       = 8
	BlossomSubMaxPendingConnections            = 128
	BlossomSubConnectionTimeout                = 30 * time.Second
	BlossomSubDirectConnectTicks        uint64 = 300
	BlossomSubDirectConnectInitialDelay        = time.Second
	BlossomSubOpportunisticGraftTicks   uint64 = 60
	BlossomSubOpportunisticGraftPeers          = 2
	BlossomSubGraftFloodThreshold              = 10 * time.Second
	BlossomSubMaxIHaveLength                   = 5000
	BlossomSubMaxIHaveMessages                 = 10
	BlossomSubMaxIDontWantMessages             = 5000
	BlossomSubIWantFollowupTime                = 3 * time.Second
	BlossomSubIDontWantMessageThreshold        = 1024 // 1KB
	BlossomSubIDontWantMessageTTL              = 60   // 60 heartbeats / 42 seconds
)

// BlossomSubParams defines all the BlossomSub specific parameters.
type BlossomSubParams struct {
	// overlay parameters.

	// D sets the optimal degree for a BlossomSub bitmask mesh. For example, if D == 6,
	// each peer will want to have about six peers in their mesh for each bitmask they're subscribed to.
	// D should be set somewhere between Dlo and Dhi.
	D int

	// Dlo sets the lower bound on the number of peers we keep in a BlossomSub bitmask mesh.
	// If we have fewer than Dlo peers, we will attempt to graft some more into the mesh at
	// the next heartbeat.
	Dlo int

	// Dhi sets the upper bound on the number of peers we keep in a BlossomSub bitmask mesh.
	// If we have more than Dhi peers, we will select some to prune from the mesh at the next heartbeat.
	Dhi int

	// Dscore affects how peers are selected when pruning a mesh due to over subscription.
	// At least Dscore of the retained peers will be high-scoring, while the remainder are
	// chosen randomly.
	Dscore int

	// Dout sets the quota for the number of outbound connections to maintain in a bitmask mesh.
	// When the mesh is pruned due to over subscription, we make sure that we have outbound connections
	// to at least Dout of the survivor peers. This prevents sybil attackers from overwhelming
	// our mesh with incoming connections.
	//
	// Dout must be set below Dlo, and must not exceed D / 2.
	Dout int

	// BitmaskWidth sets the size of the bitmask for subscriptions.
	BitmaskWidth int

	// gossip parameters

	// HistoryLength controls the size of the message cache used for gossip.
	// The message cache will remember messages for HistoryLength heartbeats.
	HistoryLength int

	// HistoryGossip controls how many cached message ids we will advertise in
	// IHAVE gossip messages. When asked for our seen message IDs, we will return
	// only those from the most recent HistoryGossip heartbeats. The slack between
	// HistoryGossip and HistoryLength allows us to avoid advertising messages
	// that will be expired by the time they're requested.
	//
	// HistoryGossip must be less than or equal to HistoryLength to
	// avoid a runtime panic.
	HistoryGossip int

	// Dlazy affects how many peers we will emit gossip to at each heartbeat.
	// We will send gossip to at least Dlazy peers outside our mesh. The actual
	// number may be more, depending on GossipFactor and how many peers we're
	// connected to.
	Dlazy int

	// GossipFactor affects how many peers we will emit gossip to at each heartbeat.
	// We will send gossip to GossipFactor * (total number of non-mesh peers), or
	// Dlazy, whichever is greater.
	GossipFactor float64

	// GossipRetransmission controls how many times we will allow a peer to request
	// the same message id through IWANT gossip before we start ignoring them. This is designed
	// to prevent peers from spamming us with requests and wasting our resources.
	GossipRetransmission int

	// heartbeat interval

	// HeartbeatInitialDelay is the short delay before the heartbeat timer begins
	// after the router is initialized.
	HeartbeatInitialDelay time.Duration

	// HeartbeatInterval controls the time between heartbeats.
	HeartbeatInterval time.Duration

	// SlowHeartbeatWarning is the duration threshold for heartbeat processing before emitting
	// a warning; this would be indicative of an overloaded peer.
	SlowHeartbeatWarning float64

	// FanoutTTL controls how long we keep track of the fanout state. If it's been
	// FanoutTTL since we've published to a bitmask that we're not subscribed to,
	// we'll delete the fanout map for that bitmask.
	FanoutTTL time.Duration

	// PrunePeers controls the number of peers to include in prune Peer eXchange.
	// When we prune a peer that's eligible for PX (has a good score, etc), we will try to
	// send them signed peer records for up to PrunePeers other peers that we
	// know of.
	PrunePeers int

	// PruneBackoff controls the backoff time for pruned peers. This is how long
	// a peer must wait before attempting to graft into our mesh again after being pruned.
	// When pruning a peer, we send them our value of PruneBackoff so they know
	// the minimum time to wait. Peers running older versions may not send a backoff time,
	// so if we receive a prune message without one, we will wait at least PruneBackoff
	// before attempting to re-graft.
	PruneBackoff time.Duration

	// UnsubscribeBackoff controls the backoff time to use when unsuscribing
	// from a bitmask. A peer should not resubscribe to this bitmask before this
	// duration.
	UnsubscribeBackoff time.Duration

	// Connectors controls the number of active connection attempts for peers obtained through PX.
	Connectors int

	// MaxPendingConnections sets the maximum number of pending connections for peers attempted through px.
	MaxPendingConnections int

	// ConnectionTimeout controls the timeout for connection attempts.
	ConnectionTimeout time.Duration

	// DirectConnectTicks is the number of heartbeat ticks for attempting to reconnect direct peers
	// that are not currently connected.
	DirectConnectTicks uint64

	// DirectConnectInitialDelay is the initial delay before opening connections to direct peers
	DirectConnectInitialDelay time.Duration

	// OpportunisticGraftTicks is the number of heartbeat ticks for attempting to improve the mesh
	// with opportunistic grafting. Every OpportunisticGraftTicks we will attempt to select some
	// high-scoring mesh peers to replace lower-scoring ones, if the median score of our mesh peers falls
	// below a threshold (see https://godoc.org/source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub#PeerScoreThresholds).
	OpportunisticGraftTicks uint64

	// OpportunisticGraftPeers is the number of peers to opportunistically graft.
	OpportunisticGraftPeers int

	// If a GRAFT comes before GraftFloodThreshold has elapsed since the last PRUNE,
	// then there is an extra score penalty applied to the peer through P7.
	GraftFloodThreshold time.Duration

	// MaxIHaveLength is the maximum number of messages to include in an IHAVE message.
	// Also controls the maximum number of IHAVE ids we will accept and request with IWANT from a
	// peer within a heartbeat, to protect from IHAVE floods. You should adjust this value from the
	// default if your system is pushing more than 5000 messages in HistoryGossip heartbeats;
	// with the defaults this is 1666 messages/s.
	MaxIHaveLength int

	// MaxIHaveMessages is the maximum number of IHAVE messages to accept from a peer within a heartbeat.
	MaxIHaveMessages int

	// MaxIDontWantMessages is the maximum number of IDONTWANT messages to accept from a peer within a heartbeat.
	MaxIDontWantMessages int

	// Time to wait for a message requested through IWANT following an IHAVE advertisement.
	// If the message is not received within this window, a broken promise is declared and
	// the router may apply bahavioural penalties.
	IWantFollowupTime time.Duration

	// IDONTWANT is only sent for messages larger than the threshold. This should be greater than
	// D_high * the size of the message id. Otherwise, the attacker can do the amplication attack by sending
	// small messages while the receiver replies back with larger IDONTWANT messages.
	IDontWantMessageThreshold int

	// IDONTWANT is cleared when it's older than the TTL.
	IDontWantMessageTTL int
}

// NewBlossomSub returns a new PubSub object using the default BlossomSubRouter as the router.
func NewBlossomSub(ctx context.Context, h host.Host, opts ...Option) (*PubSub, error) {
	rt := DefaultBlossomSubRouter(h)
	opts = append(opts, WithRawTracer(rt.tagTracer))
	return NewBlossomSubWithRouter(ctx, h, rt, opts...)
}

// NewBlossomSubWithRouter returns a new PubSub object using the given router.
func NewBlossomSubWithRouter(ctx context.Context, h host.Host, rt PubSubRouter, opts ...Option) (*PubSub, error) {
	return NewPubSub(ctx, h, rt, opts...)
}

// NewBlossomSubRouter returns a new BlossomSubRouter with custom parameters.
func NewBlossomSubRouter(h host.Host, params BlossomSubParams, network uint8) *BlossomSubRouter {
	protos, feature := BlossomSubDefaultProtocols, BlossomSubDefaultFeatures
	if network != 0 {
		protos = append(protos[:0:0], BlossomSubDefaultProtocols...)
		for i, p := range protos {
			protos[i] = protocol.ID(fmt.Sprintf("%s-network-%d", p, network))
		}
		feature = func(f BlossomSubFeature, proto protocol.ID) bool {
			switch f {
			case BlossomSubFeatureMesh:
				return proto == protos[0] || proto == protos[1]
			case BlossomSubFeaturePX:
				return proto == protos[0] || proto == protos[1]
			case BlossomSubFeatureIdontwant:
				return proto == protos[0]
			default:
				return false
			}
		}
	}

	return &BlossomSubRouter{
		peers:        make(map[peer.ID]protocol.ID),
		mesh:         make(map[string]map[peer.ID]struct{}),
		fanout:       make(map[string]map[peer.ID]struct{}),
		lastpub:      make(map[string]int64),
		gossip:       make(map[peer.ID][]*pb.ControlIHave),
		control:      make(map[peer.ID]*pb.ControlMessage),
		cab:          pstoremem.NewAddrBook(),
		backoff:      make(map[string]map[peer.ID]time.Time),
		peerhave:     make(map[peer.ID]int),
		peerdontwant: make(map[peer.ID]int),
		unwanted:     make(map[peer.ID]map[string]int),
		iasked:       make(map[peer.ID]int),
		outbound:     make(map[peer.ID]bool),
		connect:      make(chan connectInfo, params.MaxPendingConnections),
		mcache:       NewMessageCache(params.HistoryGossip, params.HistoryLength),
		protos:       protos,
		feature:      feature,
		tagTracer:    newTagTracer(h.ConnManager()),
		params:       params,
		network:      network,
	}
}

// DefaultBlossomSubRouter returns a new BlossomSubRouter with default parameters.
func DefaultBlossomSubRouter(h host.Host) *BlossomSubRouter {
	params := DefaultBlossomSubParams()
	return &BlossomSubRouter{
		peers:        make(map[peer.ID]protocol.ID),
		mesh:         make(map[string]map[peer.ID]struct{}),
		fanout:       make(map[string]map[peer.ID]struct{}),
		lastpub:      make(map[string]int64),
		gossip:       make(map[peer.ID][]*pb.ControlIHave),
		control:      make(map[peer.ID]*pb.ControlMessage),
		backoff:      make(map[string]map[peer.ID]time.Time),
		peerhave:     make(map[peer.ID]int),
		peerdontwant: make(map[peer.ID]int),
		unwanted:     make(map[peer.ID]map[string]int),
		iasked:       make(map[peer.ID]int),
		outbound:     make(map[peer.ID]bool),
		connect:      make(chan connectInfo, params.MaxPendingConnections),
		cab:          pstoremem.NewAddrBook(),
		mcache:       NewMessageCache(params.HistoryGossip, params.HistoryLength),
		protos:       BlossomSubDefaultProtocols,
		feature:      BlossomSubDefaultFeatures,
		tagTracer:    newTagTracer(h.ConnManager()),
		params:       params,
	}
}

// DefaultBlossomSubParams returns the default blossom sub parameters
// as a config.
func DefaultBlossomSubParams() BlossomSubParams {
	return BlossomSubParams{
		D:                         BlossomSubD,
		Dlo:                       BlossomSubDlo,
		Dhi:                       BlossomSubDhi,
		Dscore:                    BlossomSubDscore,
		Dout:                      BlossomSubDout,
		HistoryLength:             BlossomSubHistoryLength,
		HistoryGossip:             BlossomSubHistoryGossip,
		Dlazy:                     BlossomSubDlazy,
		GossipFactor:              BlossomSubGossipFactor,
		GossipRetransmission:      BlossomSubGossipRetransmission,
		HeartbeatInitialDelay:     BlossomSubHeartbeatInitialDelay,
		HeartbeatInterval:         BlossomSubHeartbeatInterval,
		FanoutTTL:                 BlossomSubFanoutTTL,
		PrunePeers:                BlossomSubPrunePeers,
		PruneBackoff:              BlossomSubPruneBackoff,
		UnsubscribeBackoff:        BlossomSubUnsubscribeBackoff,
		Connectors:                BlossomSubConnectors,
		MaxPendingConnections:     BlossomSubMaxPendingConnections,
		ConnectionTimeout:         BlossomSubConnectionTimeout,
		DirectConnectTicks:        BlossomSubDirectConnectTicks,
		DirectConnectInitialDelay: BlossomSubDirectConnectInitialDelay,
		OpportunisticGraftTicks:   BlossomSubOpportunisticGraftTicks,
		OpportunisticGraftPeers:   BlossomSubOpportunisticGraftPeers,
		GraftFloodThreshold:       BlossomSubGraftFloodThreshold,
		MaxIHaveLength:            BlossomSubMaxIHaveLength,
		MaxIHaveMessages:          BlossomSubMaxIHaveMessages,
		MaxIDontWantMessages:      BlossomSubMaxIDontWantMessages,
		IWantFollowupTime:         BlossomSubIWantFollowupTime,
		IDontWantMessageThreshold: BlossomSubIDontWantMessageThreshold,
		IDontWantMessageTTL:       BlossomSubIDontWantMessageTTL,
		SlowHeartbeatWarning:      0.1,
	}
}

// WithPeerScore is a BlossomSub router option that enables peer scoring.
func WithPeerScore(params *PeerScoreParams, thresholds *PeerScoreThresholds) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		// sanity check: validate the score parameters
		err := params.validate()
		if err != nil {
			return err
		}

		// sanity check: validate the threshold values
		err = thresholds.validate()
		if err != nil {
			return err
		}

		bs.score = newPeerScore(params)
		bs.gossipThreshold = thresholds.GossipThreshold
		bs.publishThreshold = thresholds.PublishThreshold
		bs.graylistThreshold = thresholds.GraylistThreshold
		bs.acceptPXThreshold = thresholds.AcceptPXThreshold
		bs.opportunisticGraftThreshold = thresholds.OpportunisticGraftThreshold

		bs.gossipTracer = newGossipTracer()

		// hook the tracer
		if ps.tracer != nil {
			ps.tracer.raw = append(ps.tracer.raw, bs.score, bs.gossipTracer)
		} else {
			ps.tracer = &pubsubTracer{
				raw:   []RawTracer{bs.score, bs.gossipTracer},
				pid:   ps.host.ID(),
				idGen: ps.idGen,
			}
		}

		return nil
	}
}

// WithFloodPublish is a BlossomSub router option that enables flood publishing.
// When this is enabled, published messages are forwarded to all peers with score >=
// to publishThreshold
func WithFloodPublish(floodPublish bool) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		bs.floodPublish = floodPublish

		return nil
	}
}

// WithPeerExchange is a BlossomSub router option that enables Peer eXchange on PRUNE.
// This should generally be enabled in bootstrappers and well connected/trusted nodes
// used for bootstrapping.
func WithPeerExchange(doPX bool) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		bs.doPX = doPX

		return nil
	}
}

// WithDirectPeers is a BlossomSub router option that specifies peers with direct
// peering agreements. These peers are connected outside of the mesh, with all (valid)
// message unconditionally forwarded to them. The router will maintain open connections
// to these peers. Note that the peering agreement should be reciprocal with direct peers
// symmetrically configured at both ends.
func WithDirectPeers(pis []peer.AddrInfo) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		direct := make(map[peer.ID]struct{})
		for _, pi := range pis {
			direct[pi.ID] = struct{}{}
			ps.host.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
		}

		bs.direct = direct

		if bs.tagTracer != nil {
			bs.tagTracer.direct = direct
		}

		return nil
	}
}

// WithDirectConnectTicks is a BlossomSub router option that sets the number of
// heartbeat ticks between attempting to reconnect direct peers that are not
// currently connected. A "tick" is based on the heartbeat interval, which is
// 1s by default. The default value for direct connect ticks is 300.
func WithDirectConnectTicks(t uint64) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}
		bs.params.DirectConnectTicks = t
		return nil
	}
}

// WithBlossomSubParams is a blossom sub router option that allows a custom
// config to be set when instantiating the BlossomSub router.
func WithBlossomSubParams(cfg BlossomSubParams) Option {
	return func(ps *PubSub) error {
		bs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}
		// Overwrite current config and associated variables in the router.
		bs.params = cfg
		bs.connect = make(chan connectInfo, cfg.MaxPendingConnections)
		bs.mcache = NewMessageCache(cfg.HistoryGossip, cfg.HistoryLength)

		return nil
	}
}

// BlossomSubRouter is a router that implements the BlossomSub protocol.
// For each bitmask we have joined, we maintain an overlay through which
// messages flow; this is the mesh map.
// For each bitmask we publish to without joining, we maintain a list of peers
// to use for injecting our messages in the overlay with stable routes; this
// is the fanout map. Fanout peer lists are expired if we don't publish any
// messages to their bitmask for BlossomSubFanoutTTL.
type BlossomSubRouter struct {
	p            *PubSub
	peers        map[peer.ID]protocol.ID          // peer protocols
	direct       map[peer.ID]struct{}             // direct peers
	mesh         map[string]map[peer.ID]struct{}  // bitmask meshes
	fanout       map[string]map[peer.ID]struct{}  // bitmask fanout
	lastpub      map[string]int64                 // last publish time for fanout bitmasks
	gossip       map[peer.ID][]*pb.ControlIHave   // pending gossip
	control      map[peer.ID]*pb.ControlMessage   // pending control messages
	peerhave     map[peer.ID]int                  // number of IHAVEs received from peer in the last heartbeat
	peerdontwant map[peer.ID]int                  // number of IDONTWANTs received from peer in the last heartbeat
	unwanted     map[peer.ID]map[string]int       // TTL of the message ids peers don't want
	iasked       map[peer.ID]int                  // number of messages we have asked from peer in the last heartbeat
	outbound     map[peer.ID]bool                 // connection direction cache, marks peers with outbound connections
	backoff      map[string]map[peer.ID]time.Time // prune backoff
	connect      chan connectInfo                 // px connection requests
	cab          peerstore.AddrBook
	network      uint8

	protos  []protocol.ID
	feature BlossomSubFeatureTest

	mcache       *MessageCache
	tracer       *pubsubTracer
	score        *peerScore
	gossipTracer *gossipTracer
	tagTracer    *tagTracer
	gate         *peerGater

	// config for BlossomSub parameters
	params BlossomSubParams

	// whether PX is enabled; this should be enabled in bootstrappers and other well connected/trusted
	// nodes.
	doPX bool

	// threshold for accepting PX from a peer; this should be positive and limited to scores
	// attainable by bootstrappers and trusted nodes
	acceptPXThreshold float64

	// threshold for peer score to emit/accept gossip
	// If the peer score is below this threshold, we won't emit or accept gossip from the peer.
	// When there is no score, this value is 0.
	gossipThreshold float64

	// flood publish score threshold; we only publish to peers with score >= to the threshold
	// when using flood publishing or the peer is a fanout or floodsub peer.
	publishThreshold float64

	// threshold for peer score before we graylist the peer and silently ignore its RPCs
	graylistThreshold float64

	// threshold for median peer score before triggering opportunistic grafting
	opportunisticGraftThreshold float64

	// whether to use flood publishing
	floodPublish bool

	// number of heartbeats since the beginning of time; this allows us to amortize some resource
	// clean up -- eg backoff clean up.
	heartbeatTicks uint64
}

type connectInfo struct {
	p   peer.ID
	spr *record.Envelope
}

func (bs *BlossomSubRouter) Protocols() []protocol.ID {
	return bs.protos
}

func (bs *BlossomSubRouter) Attach(p *PubSub) {
	bs.p = p
	bs.tracer = p.tracer

	// start the scoring
	bs.score.Start(bs)

	// and the gossip tracing
	bs.gossipTracer.Start(bs)

	// and the tracer for connmgr tags
	bs.tagTracer.Start(bs)

	// start using the same msg ID function as PubSub for caching messages.
	bs.mcache.SetMsgIdFn(p.idGen.ID)

	// start the heartbeat
	go bs.heartbeatTimer()

	// start the PX connectors
	for i := 0; i < bs.params.Connectors; i++ {
		go bs.connector()
	}

	// Manage our address book from events emitted by libp2p
	go bs.manageAddrBook()

	// connect to direct peers
	if len(bs.direct) > 0 {
		go func() {
			if bs.params.DirectConnectInitialDelay > 0 {
				time.Sleep(bs.params.DirectConnectInitialDelay)
			}
			for p := range bs.direct {
				bs.connect <- connectInfo{p: p}
			}
		}()
	}
}

func (bs *BlossomSubRouter) manageAddrBook() {
	sub, err := bs.p.host.EventBus().Subscribe([]interface{}{
		&event.EvtPeerIdentificationCompleted{},
		&event.EvtPeerConnectednessChanged{},
	})
	if err != nil {
		log.Errorf("failed to subscribe to peer identification events: %v", err)
		return
	}

	for {
		select {
		case <-bs.p.ctx.Done():
			cabCloser, ok := bs.cab.(io.Closer)
			if ok {
				errClose := cabCloser.Close()
				if errClose != nil {
					log.Warnf("failed to close addr book: %v", errClose)
				}
			}
			sub.Close()
			return
		case ev := <-sub.Out():
			switch ev := ev.(type) {
			case event.EvtPeerIdentificationCompleted:
				if ev.SignedPeerRecord != nil {
					cab, ok := peerstore.GetCertifiedAddrBook(bs.cab)
					if ok {
						ttl := peerstore.RecentlyConnectedAddrTTL
						if bs.p.host.Network().Connectedness(ev.Peer) == network.Connected {
							ttl = peerstore.ConnectedAddrTTL
						}
						_, err := cab.ConsumePeerRecord(ev.SignedPeerRecord, ttl)
						if err != nil {
							log.Warnf("failed to consume signed peer record: %v", err)
						}
					}
				}
			case event.EvtPeerConnectednessChanged:
				if ev.Connectedness != network.Connected {
					bs.cab.UpdateAddrs(ev.Peer, peerstore.ConnectedAddrTTL, peerstore.RecentlyConnectedAddrTTL)
				}
			}
		}
	}
}

func (bs *BlossomSubRouter) AddPeer(p peer.ID, proto protocol.ID) {
	log.Debugf("PEERUP: Add new peer %s using %s", p, proto)
	bs.tracer.AddPeer(p, proto)
	bs.peers[p] = proto

	// track the connection direction
	outbound := false
	conns := bs.p.host.Network().ConnsToPeer(p)
loop:
	for _, c := range conns {
		stat := c.Stat()

		if stat.Limited {
			continue
		}

		if stat.Direction == network.DirOutbound {
			// only count the connection if it has a pubsub stream
			for _, s := range c.GetStreams() {
				if s.Protocol() == proto {
					outbound = true
					break loop
				}
			}
		}
	}
	bs.outbound[p] = outbound
}

func (bs *BlossomSubRouter) RemovePeer(p peer.ID) {
	log.Debugf("PEERDOWN: Remove disconnected peer %s", p)
	for bitmask, peers := range bs.mesh {
		if _, ok := peers[p]; !ok {
			continue
		}
		log.Debugf("PEERDOWN: Pruning peer %s from bitmask %s", p, bitmask)
		bs.tracer.Prune(p, []byte(bitmask))
	}
	bs.tracer.RemovePeer(p)
	delete(bs.peers, p)
	for _, peers := range bs.mesh {
		delete(peers, p)
	}
	for _, peers := range bs.fanout {
		delete(peers, p)
	}
	delete(bs.gossip, p)
	delete(bs.control, p)
	delete(bs.outbound, p)
	delete(bs.unwanted, p)
}

func (bs *BlossomSubRouter) EnoughPeers(bitmask []byte, suggested int) bool {
	tmap, ok := bs.p.bitmasks[string(bitmask)]
	if !ok {
		return false
	}

	fsPeers, bsPeers := 0, 0
	// floodsub peers
	for p := range tmap {
		if !bs.feature(BlossomSubFeatureMesh, bs.peers[p]) {
			fsPeers++
		}
	}

	// BlossomSub peers
	bsPeers = len(bs.mesh[string(bitmask)])

	if suggested == 0 {
		suggested = bs.params.Dlo
	}

	if fsPeers+bsPeers >= suggested || bsPeers >= bs.params.Dhi {
		return true
	}

	return false
}

func (bs *BlossomSubRouter) PeerScore(p peer.ID) float64 {
	return bs.score.Score(p)
}

func (bs *BlossomSubRouter) AcceptFrom(p peer.ID) AcceptStatus {
	_, direct := bs.direct[p]
	if direct {
		return AcceptAll
	}

	if bs.score.Score(p) < bs.graylistThreshold {
		return AcceptNone
	}

	return bs.gate.AcceptFrom(p)
}

// PreValidation sends the IDONTWANT control messages to all the mesh
// peers. They need to be sent right before the validation because they
// should be seen by the peers as soon as possible.
func (bs *BlossomSubRouter) PreValidation(msgs []*Message) {
	slicedMessages := make(map[string][]*Message, len(msgs))
	for _, msg := range msgs {
		if len(msg.GetData()) < bs.params.IDontWantMessageThreshold {
			continue
		}
		for _, bitmask := range SliceBitmask(msg.GetBitmask()) {
			bitmask := string(bitmask)
			slicedMessages[bitmask] = append(slicedMessages[bitmask], msg)
		}
	}
	toSend := make(map[peer.ID]map[*Message]struct{}, len(slicedMessages))
	for bitmask, msgs := range slicedMessages {
		// send IDONTWANT to all the mesh peers
		for p := range bs.mesh[bitmask] {
			// send to only peers that support IDONTWANT
			if !bs.feature(BlossomSubFeatureIdontwant, bs.peers[p]) {
				continue
			}
			for _, msg := range msgs {
				if msg.ReceivedFrom == p {
					continue
				}
				if toSend[p] == nil {
					toSend[p] = make(map[*Message]struct{}, len(msgs))
				}
				toSend[p][msg] = struct{}{}
			}
		}
	}
	for p, msgs := range toSend {
		mids := make([][]byte, 0, len(msgs))
		for msg := range msgs {
			mids = append(mids, bs.p.idGen.ID(msg))
		}
		// shuffle the messages got from the RPC envelope
		shuffleBytes(mids)
		idontwant := []*pb.ControlIDontWant{{MessageIDs: mids}}
		out := rpcWithControl(nil, nil, nil, nil, nil, idontwant)
		bs.sendRPC(p, out, true)
	}
}

func (bs *BlossomSubRouter) HandleRPC(rpc *RPC) {
	ctl := rpc.GetControl()
	if ctl == nil {
		return
	}

	iwant := bs.handleIHave(rpc.from, ctl)
	ihave := bs.handleIWant(rpc.from, ctl)
	prune := bs.handleGraft(rpc.from, ctl)
	bs.handlePrune(rpc.from, ctl)
	bs.handleIDontWant(rpc.from, ctl)

	if len(iwant) == 0 && len(ihave) == 0 && len(prune) == 0 {
		return
	}

	out := rpcWithControl(ihave, nil, iwant, nil, prune, nil)
	bs.sendRPC(rpc.from, out, false)
}

func (bs *BlossomSubRouter) handleIHave(p peer.ID, ctl *pb.ControlMessage) []*pb.ControlIWant {
	// we ignore IHAVE gossip from any peer whose score is below the gossip threshold
	score := bs.score.Score(p)
	if score < bs.gossipThreshold {
		log.Debugf("IHAVE: ignoring peer %s with score below threshold [score = %f]", p, score)
		return nil
	}

	// IHAVE flood protection
	bs.peerhave[p]++
	if bs.peerhave[p] > bs.params.MaxIHaveMessages {
		log.Debugf("IHAVE: peer %s has advertised too many times (%d) within this heartbeat interval; ignoring", p, bs.peerhave[p])
		return nil
	}

	if bs.iasked[p] >= bs.params.MaxIHaveLength {
		log.Debugf("IHAVE: peer %s has already advertised too many messages (%d); ignoring", p, bs.iasked[p])
		return nil
	}

	iwant := make(map[string]struct{})
	for _, ihave := range ctl.GetIhave() {
		bitmask := ihave.GetBitmask()
		_, ok := bs.mesh[string(bitmask)]
		if !ok {
			continue
		}

		if !bs.p.peerFilter(p, bitmask) {
			continue
		}

	checkIwantMsgsLoop:
		for msgIdx, mid := range ihave.GetMessageIDs() {
			// prevent remote peer from sending too many msg_ids on a single IHAVE message
			if msgIdx >= bs.params.MaxIHaveLength {
				log.Debugf("IHAVE: peer %s has sent IHAVE on bitmask %s with too many messages (%d); ignoring remaining msgs", p, bitmask, len(ihave.MessageIDs))
				break checkIwantMsgsLoop
			}

			if bs.p.seenMessage(mid) {
				continue
			}
			iwant[string(mid)] = struct{}{}
		}
	}

	if len(iwant) == 0 {
		return nil
	}

	iask := len(iwant)
	if iask+bs.iasked[p] > bs.params.MaxIHaveLength {
		iask = bs.params.MaxIHaveLength - bs.iasked[p]
	}

	log.Debugf("IHAVE: Asking for %d out of %d messages from %s", iask, len(iwant), p)

	iwantlst := make([][]byte, 0, len(iwant))
	for mid := range iwant {
		iwantlst = append(iwantlst, []byte(mid))
	}

	// truncate to the messages we are actually asking for and update the iasked counter
	iwantlst = iwantlst[:iask]
	bs.iasked[p] += iask

	bs.gossipTracer.AddPromise(p, iwantlst)

	return []*pb.ControlIWant{{MessageIDs: iwantlst}}
}

func (bs *BlossomSubRouter) handleIWant(p peer.ID, ctl *pb.ControlMessage) []*pb.Message {
	// we don't respond to IWANT requests from any peer whose score is below the gossip threshold
	score := bs.score.Score(p)
	if score < bs.gossipThreshold {
		log.Debugf("IWANT: ignoring peer %s with score below threshold [score = %f]", p, score)
		return nil
	}

	ihave := make(map[string]*pb.Message)
	for _, iwant := range ctl.GetIwant() {
		for _, mid := range iwant.GetMessageIDs() {
			msg, count, ok := bs.mcache.GetForPeer(mid, p)
			if !ok {
				continue
			}

			if !bs.p.peerFilter(p, msg.GetBitmask()) {
				continue
			}

			if count > bs.params.GossipRetransmission {
				log.Debugf("IWANT: Peer %s has asked for message %s too many times; ignoring request", p, mid)
				continue
			}

			ihave[string(mid)] = msg.Message
		}
	}

	if len(ihave) == 0 {
		return nil
	}

	log.Debugf("IWANT: Sending %d messages to %s", len(ihave), p)

	msgs := make([]*pb.Message, 0, len(ihave))
	for _, msg := range ihave {
		if peer.ID(msg.GetFrom()) == p {
			continue
		}
		mid := bs.p.idGen.RawID(msg)
		if _, ok := bs.unwanted[p][string(mid)]; ok {
			continue
		}
		msgs = append(msgs, msg)
	}

	return msgs
}

func (bs *BlossomSubRouter) handleGraft(p peer.ID, ctl *pb.ControlMessage) []*pb.ControlPrune {
	var prune [][]byte

	doPX := bs.doPX
	score := bs.score.Score(p)
	now := time.Now()

	for _, graft := range ctl.GetGraft() {
		bitmask := graft.GetBitmask()

		if !bs.p.peerFilter(p, bitmask) {
			continue
		}

		peers, ok := bs.mesh[string(bitmask)]
		if !ok {
			// don't do PX when there is an unknown bitmask to avoid leaking our peers
			doPX = false
			// spam hardening: ignore GRAFTs for unknown bitmasks
			continue
		}

		// check if it is already in the mesh; if so do nothing (we might have concurrent grafting)
		_, inMesh := peers[p]
		if inMesh {
			continue
		}

		// we don't GRAFT to/from direct peers; complain loudly if this happens
		_, direct := bs.direct[p]
		if direct {
			log.Warnf("GRAFT: ignoring request from direct peer %s", p)
			// this is possibly a bug from non-reciprocal configuration; send a PRUNE
			prune = append(prune, bitmask)
			// but don't PX
			doPX = false
			continue
		}

		// make sure we are not backing off that peer
		expire, backoff := bs.backoff[string(bitmask)][p]
		if backoff && now.Before(expire) {
			log.Debugf("GRAFT: ignoring backed off peer %s", p)
			// add behavioural penalty
			bs.score.AddPenalty(p, 1)
			// no PX
			doPX = false
			// check the flood cutoff -- is the GRAFT coming too fast?
			floodCutoff := expire.Add(bs.params.GraftFloodThreshold - bs.params.PruneBackoff)
			if now.Before(floodCutoff) {
				// extra penalty
				bs.score.AddPenalty(p, 1)
			}
			// refresh the backoff
			bs.addBackoff(p, bitmask, false)
			prune = append(prune, bitmask)
			continue
		}

		// check the score
		if score < 0 {
			// we don't GRAFT peers with negative score
			log.Debugf("GRAFT: ignoring peer %s with negative score [score = %f, bitmask = %s]", p, score, bitmask)
			// we do send them PRUNE however, because it's a matter of protocol correctness
			prune = append(prune, bitmask)
			// but we won't PX to them
			doPX = false
			// add/refresh backoff so that we don't reGRAFT too early even if the score decays back up
			bs.addBackoff(p, bitmask, false)
			continue
		}

		// check the number of mesh peers; if it is at (or over) Dhi, we only accept grafts
		// from peers with outbound connections; this is a defensive check to restrict potential
		// mesh takeover attacks combined with love bombing
		if len(peers) >= bs.params.Dhi && !bs.outbound[p] {
			prune = append(prune, bitmask)
			bs.addBackoff(p, bitmask, false)
			continue
		}

		log.Debugf("GRAFT: add mesh link from %s in %s", p, bitmask)
		bs.tracer.Graft(p, bitmask)
		peers[p] = struct{}{}
	}

	if len(prune) == 0 {
		return nil
	}

	cprune := make([]*pb.ControlPrune, 0, len(prune))
	for _, bitmask := range prune {
		cprune = append(cprune, bs.makePrune(p, bitmask, doPX, false))
	}

	return cprune
}

func (bs *BlossomSubRouter) handlePrune(p peer.ID, ctl *pb.ControlMessage) {
	score := bs.score.Score(p)

	for _, prune := range ctl.GetPrune() {
		bitmask := prune.GetBitmask()
		peers, ok := bs.mesh[string(bitmask)]
		if !ok {
			continue
		}

		if _, inMesh := peers[p]; inMesh {
			log.Debugf("PRUNE: Remove mesh link to %s in %s", p, bitmask)
			bs.tracer.Prune(p, bitmask)
			delete(peers, p)
		}

		// is there a backoff specified by the peer? if so obey it.
		backoff := prune.GetBackoff()
		if backoff > 0 {
			bs.doAddBackoff(p, bitmask, time.Duration(backoff)*time.Second)
		} else {
			bs.addBackoff(p, bitmask, false)
		}

		px := prune.GetPeers()
		if len(px) > 0 {
			// we ignore PX from peers with insufficient score
			if score < bs.acceptPXThreshold {
				log.Debugf("PRUNE: ignoring PX from peer %s with insufficient score [score = %f, bitmask = %s]", p, score, bitmask)
				continue
			}

			bs.pxConnect(px)
		}
	}
}

func (bs *BlossomSubRouter) handleIDontWant(p peer.ID, ctl *pb.ControlMessage) {
	if bs.unwanted[p] == nil {
		bs.unwanted[p] = make(map[string]int)
	}

	// IDONTWANT flood protection
	if bs.peerdontwant[p] >= bs.params.MaxIDontWantMessages {
		log.Debugf("IDONWANT: peer %s has advertised too many times (%d) within this heartbeat interval; ignoring", p, bs.peerdontwant[p])
		return
	}
	bs.peerdontwant[p]++

	// Remember all the unwanted message ids
	for _, idontwant := range ctl.GetIdontwant() {
		for _, mid := range idontwant.GetMessageIDs() {
			bs.unwanted[p][string(mid)] = bs.params.IDontWantMessageTTL
		}
	}
}

func (bs *BlossomSubRouter) addBackoff(p peer.ID, bitmask []byte, isUnsubscribe bool) {
	backoff := bs.params.PruneBackoff
	if isUnsubscribe {
		backoff = bs.params.UnsubscribeBackoff
	}
	bs.doAddBackoff(p, bitmask, backoff)
}

func (bs *BlossomSubRouter) doAddBackoff(p peer.ID, bitmask []byte, interval time.Duration) {
	backoff, ok := bs.backoff[string(bitmask)]
	if !ok {
		backoff = make(map[peer.ID]time.Time)
		bs.backoff[string(bitmask)] = backoff
	}
	expire := time.Now().Add(interval)
	if backoff[p].Before(expire) {
		backoff[p] = expire
	}
}

func (bs *BlossomSubRouter) pxConnect(peers []*pb.PeerInfo) {
	if len(peers) > bs.params.PrunePeers {
		shufflePeerInfo(peers)
		peers = peers[:bs.params.PrunePeers]
	}

	toconnect := make([]connectInfo, 0, len(peers))

	for _, pi := range peers {
		p := peer.ID(pi.PeerID)

		_, connected := bs.peers[p]
		if connected {
			continue
		}

		var spr *record.Envelope
		if pi.SignedPeerRecord != nil {
			// the peer sent us a signed record; ensure that it is valid
			envelope, r, err := record.ConsumeEnvelope(pi.SignedPeerRecord, peer.PeerRecordEnvelopeDomain)
			if err != nil {
				log.Warnf("error unmarshalling peer record obtained through px: %s", err)
				continue
			}
			rec, ok := r.(*peer.PeerRecord)
			if !ok {
				log.Warnf("bogus peer record obtained through px: envelope payload is not PeerRecord")
				continue
			}
			if rec.PeerID != p {
				log.Warnf("bogus peer record obtained through px: peer ID %s doesn't match expected peer %s", rec.PeerID, p)
				continue
			}
			spr = envelope
		}

		toconnect = append(toconnect, connectInfo{p, spr})
	}

	if len(toconnect) == 0 {
		return
	}

	for _, ci := range toconnect {
		select {
		case bs.connect <- ci:
		default:
			log.Debugf("ignoring peer connection attempt; too many pending connections")
		}
	}
}

func (bs *BlossomSubRouter) connector() {
	for {
		select {
		case ci := <-bs.connect:
			if bs.p.host.Network().Connectedness(ci.p) == network.Connected {
				continue
			}

			log.Debugf("connecting to %s", ci.p)
			cab, ok := peerstore.GetCertifiedAddrBook(bs.cab)
			if ok && ci.spr != nil {
				_, err := cab.ConsumePeerRecord(ci.spr, peerstore.TempAddrTTL)
				if err != nil {
					log.Debugf("error processing peer record: %s", err)
				}
			}

			ctx, cancel := context.WithTimeout(bs.p.ctx, bs.params.ConnectionTimeout)
			err := bs.p.host.Connect(ctx, peer.AddrInfo{ID: ci.p, Addrs: bs.cab.Addrs(ci.p)})
			cancel()
			if err != nil {
				log.Debugf("error connecting to %s: %s", ci.p, err)
			}

		case <-bs.p.ctx.Done():
			return
		}
	}
}

func (bs *BlossomSubRouter) Publish(msg *Message) {
	bs.mcache.Put(msg)

	from := msg.ReceivedFrom
	bitmask := msg.GetBitmask()
	originalSender := peer.ID(msg.GetFrom())
	mid := string(bs.p.idGen.ID(msg))

	var toSendAll []map[peer.ID]struct{}
	for _, bitmask := range SliceBitmask(bitmask) {
		tosend := make(map[peer.ID]struct{})

		// any peers in the bitmask?
		tmap, ok := bs.p.bitmasks[string(bitmask)]
		if !ok {
			return
		}

		if bs.floodPublish && from == bs.p.host.ID() {
			for p := range tmap {
				_, direct := bs.direct[p]
				if direct || bs.score.Score(p) >= bs.publishThreshold {
					tosend[p] = struct{}{}
				}
			}
		} else {
			// direct peers
			for p := range bs.direct {
				_, inBitmask := tmap[p]
				if inBitmask {
					tosend[p] = struct{}{}
				}
			}

			// floodsub peers
			for p := range tmap {
				if !bs.feature(BlossomSubFeatureMesh, bs.peers[p]) && bs.score.Score(p) >= bs.publishThreshold {
					tosend[p] = struct{}{}
				}
			}

			// BlossomSub peers
			gmap, ok := bs.mesh[string(bitmask)]
			if !ok {
				// we are not in the mesh for bitmask, use fanout peers
				gmap, ok = bs.fanout[string(bitmask)]
				if !ok || len(gmap) == 0 {
					// we don't have any, pick some with score above the publish threshold
					peers := bs.getPeers(bitmask, bs.params.D, func(p peer.ID) bool {
						_, direct := bs.direct[p]
						return !direct && bs.score.Score(p) >= bs.publishThreshold
					})

					if len(peers) > 0 {
						gmap = peerListToMap(peers)
						bs.fanout[string(bitmask)] = gmap
					}
				}
				bs.lastpub[string(bitmask)] = time.Now().UnixNano()
			}

			for p := range gmap {
				tosend[p] = struct{}{}
			}
		}

		delete(tosend, from)
		delete(tosend, originalSender)
		for p := range tosend {
			if _, ok := bs.unwanted[p][mid]; ok {
				delete(tosend, p)
			}
		}

		if len(tosend) > 0 {
			toSendAll = append(toSendAll, tosend)
		}
	}

	if len(toSendAll) == 0 {
		return
	}
	toSend := toSendAll[rand.Intn(len(toSendAll))]

	out := rpcWithMessages(msg.Message)
	for pid := range toSend {
		bs.sendRPC(pid, out, false)
	}
}

func (bs *BlossomSubRouter) Join(bitmask []byte) {
	gmap, ok := bs.mesh[string(bitmask)]
	if ok {
		return
	}

	log.Debugf("JOIN %s", bitmask)
	bs.tracer.Join(bitmask)

	gmap, ok = bs.fanout[string(bitmask)]
	if ok {
		backoff := bs.backoff[string(bitmask)]
		// these peers have a score above the publish threshold, which may be negative
		// so drop the ones with a negative score
		for p := range gmap {
			_, doBackOff := backoff[p]
			if bs.score.Score(p) < 0 || doBackOff {
				delete(gmap, p)
			}
		}

		if len(gmap) < bs.params.D {
			// we need more peers; eager, as this would get fixed in the next heartbeat
			more := bs.getPeers(bitmask, bs.params.D-len(gmap), func(p peer.ID) bool {
				// filter our current peers, direct peers, peers we are backing off, and
				// peers with negative scores
				_, inMesh := gmap[p]
				_, direct := bs.direct[p]
				_, doBackOff := backoff[p]
				return !inMesh && !direct && !doBackOff && bs.score.Score(p) >= 0
			})
			for _, p := range more {
				gmap[p] = struct{}{}
			}
		}

		bs.mesh[string(bitmask)] = gmap
		delete(bs.fanout, string(bitmask))
		delete(bs.lastpub, string(bitmask))
	} else {
		backoff := bs.backoff[string(bitmask)]
		peers := bs.getPeers(bitmask, bs.params.D, func(p peer.ID) bool {
			// filter direct peers, peers we are backing off and peers with negative score
			_, direct := bs.direct[p]
			_, doBackOff := backoff[p]
			return !direct && !doBackOff && bs.score.Score(p) >= 0
		})
		gmap = peerListToMap(peers)
		bs.mesh[string(bitmask)] = gmap
	}

	for p := range gmap {
		log.Debugf("JOIN: Add mesh link to %s in %s", p, bitmask)
		bs.tracer.Graft(p, bitmask)
		bs.sendGraft(p, bitmask)
	}
}

func (bs *BlossomSubRouter) Leave(bitmask []byte) {
	gmap, ok := bs.mesh[string(bitmask)]
	if !ok {
		return
	}

	log.Debugf("LEAVE %s", bitmask)
	bs.tracer.Leave(bitmask)

	delete(bs.mesh, string(bitmask))

	for p := range gmap {
		log.Debugf("LEAVE: Remove mesh link to %s in %s", p, bitmask)
		bs.tracer.Prune(p, bitmask)
		bs.sendPrune(p, bitmask, true)
		// Add a backoff to this peer to prevent us from eagerly
		// re-grafting this peer into our mesh if we rejoin this
		// bitmask before the backoff period ends.
		bs.addBackoff(p, bitmask, true)
	}
}

func (bs *BlossomSubRouter) sendGraft(p peer.ID, bitmask []byte) {
	graft := []*pb.ControlGraft{{Bitmask: bitmask}}
	out := rpcWithControl(nil, nil, nil, graft, nil, nil)
	bs.sendRPC(p, out, false)
}

func (bs *BlossomSubRouter) sendPrune(p peer.ID, bitmask []byte, isUnsubscribe bool) {
	prune := []*pb.ControlPrune{bs.makePrune(p, bitmask, bs.doPX, isUnsubscribe)}
	out := rpcWithControl(nil, nil, nil, nil, prune, nil)
	bs.sendRPC(p, out, false)
}

func (bs *BlossomSubRouter) sendRPC(p peer.ID, out *RPC, fast bool) {
	// do we own the RPC?
	own := false

	// piggyback control message retries
	ctl, ok := bs.control[p]
	if ok {
		out = copyRPC(out)
		own = true
		bs.piggybackControl(p, out, ctl)
		delete(bs.control, p)
	}

	// piggyback gossip
	ihave, ok := bs.gossip[p]
	if ok {
		if !own {
			out = copyRPC(out)
			own = true
		}
		bs.piggybackGossip(p, out, ihave)
		delete(bs.gossip, p)
	}

	bs.p.peerMx.RLock()
	mch, ok := bs.p.peers[p]
	bs.p.peerMx.RUnlock()

	if !ok {
		return
	}

	// If we're below the max message size, go ahead and send
	if out.Size() < bs.p.softMaxMessageSize {
		bs.doSendRPC(out, p, mch, fast)
		return
	}

	outCopy := copyRPC(out)
	// Potentially split the RPC into multiple RPCs that are below the max message size
	outRPCs := appendOrMergeRPC(nil, bs.p.softMaxMessageSize, outCopy)
	for _, rpc := range outRPCs {
		if rpc.Size() > bs.p.hardMaxMessageSize {
			// This should only happen if a single message/control is above the maxMessageSize.
			bs.doDropRPC(out, p, fmt.Sprintf("Dropping oversized RPC. Size: %d, limit: %d. (Over by %d bytes)", rpc.Size(), bs.p.hardMaxMessageSize, rpc.Size()-bs.p.hardMaxMessageSize))
			continue
		}
		bs.doSendRPC(rpc, p, mch, fast)
	}
}

func (bs *BlossomSubRouter) doDropRPC(rpc *RPC, p peer.ID, reason string) {
	log.Debugf("dropping message to peer %s: %s", p, reason)
	bs.tracer.DropRPC(rpc, p)
	// push control messages that need to be retried
	ctl := rpc.GetControl()
	if ctl != nil {
		bs.pushControl(p, ctl)
	}
}

func (bs *BlossomSubRouter) doSendRPC(rpc *RPC, p peer.ID, q *rpcQueue, fast bool) {
	if err := q.TryPush(bs.p.ctx, rpc, fast); err != nil {
		bs.doDropRPC(rpc, p, "queue full")
		return
	}
	bs.tracer.SendRPC(rpc, p)
}

// appendOrMergeRPC appends the given RPCs to the slice, merging them if possible.
// If any elem is too large to fit in a single RPC, it will be split into multiple RPCs.
// If an RPC is too large and can't be split further (e.g. Message data is
// bigger than the RPC limit), then it will be returned as an oversized RPC.
// The caller should filter out oversized RPCs.
func appendOrMergeRPC(slice []*RPC, limit int, elems ...*RPC) []*RPC {
	if len(elems) == 0 {
		return slice
	}

	if len(slice) == 0 && len(elems) == 1 && elems[0].Size() < limit {
		// Fast path: no merging needed and only one element
		return append(slice, elems[0])
	}

	out := slice
	if len(out) == 0 {
		out = append(out, &RPC{RPC: &pb.RPC{}})
		out[0].from = elems[0].from
	}

	for _, elem := range elems {
		lastRPC := out[len(out)-1]

		// Merge/Append publish messages
		// TODO: Never merge messages. The current behavior is the same as the
		// old behavior. In the future let's not merge messages. Since,
		// it may increase message latency.
		for _, msg := range elem.GetPublish() {
			if lastRPC.Publish = append(lastRPC.Publish, msg); lastRPC.Size() > limit {
				lastRPC.Publish = lastRPC.Publish[:len(lastRPC.Publish)-1]
				lastRPC = &RPC{RPC: &pb.RPC{}, from: elem.from}
				lastRPC.Publish = append(lastRPC.Publish, msg)
				out = append(out, lastRPC)
			}
		}

		// Merge/Append Subscriptions
		for _, sub := range elem.GetSubscriptions() {
			if lastRPC.Subscriptions = append(lastRPC.Subscriptions, sub); lastRPC.Size() > limit {
				lastRPC.Subscriptions = lastRPC.Subscriptions[:len(lastRPC.Subscriptions)-1]
				lastRPC = &RPC{RPC: &pb.RPC{}, from: elem.from}
				lastRPC.Subscriptions = append(lastRPC.Subscriptions, sub)
				out = append(out, lastRPC)
			}
		}

		// Merge/Append Control messages
		if ctl := elem.GetControl(); ctl != nil {
			if lastRPC.Control == nil {
				lastRPC.Control = &pb.ControlMessage{}
				if lastRPC.Size() > limit {
					lastRPC.Control = nil
					lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{}}, from: elem.from}
					out = append(out, lastRPC)
				}
			}

			for _, graft := range ctl.GetGraft() {
				if lastRPC.Control.Graft = append(lastRPC.Control.Graft, graft); lastRPC.Size() > limit {
					lastRPC.Control.Graft = lastRPC.Control.Graft[:len(lastRPC.Control.Graft)-1]
					lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{}}, from: elem.from}
					lastRPC.Control.Graft = append(lastRPC.Control.Graft, graft)
					out = append(out, lastRPC)
				}
			}

			for _, prune := range ctl.GetPrune() {
				if lastRPC.Control.Prune = append(lastRPC.Control.Prune, prune); lastRPC.Size() > limit {
					lastRPC.Control.Prune = lastRPC.Control.Prune[:len(lastRPC.Control.Prune)-1]
					lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{}}, from: elem.from}
					lastRPC.Control.Prune = append(lastRPC.Control.Prune, prune)
					out = append(out, lastRPC)
				}
			}

			for _, iwant := range ctl.GetIwant() {
				if len(lastRPC.Control.Iwant) == 0 {
					// Initialize with a single IWANT.
					// For IWANTs we don't need more than a single one,
					// since there are no bitmask IDs here.
					newIWant := &pb.ControlIWant{}
					if lastRPC.Control.Iwant = append(lastRPC.Control.Iwant, newIWant); lastRPC.Size() > limit {
						lastRPC.Control.Iwant = lastRPC.Control.Iwant[:len(lastRPC.Control.Iwant)-1]
						lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{
							Iwant: []*pb.ControlIWant{newIWant},
						}}, from: elem.from}
						out = append(out, lastRPC)
					}
				}
				for _, msgID := range iwant.GetMessageIDs() {
					if lastRPC.Control.Iwant[0].MessageIDs = append(lastRPC.Control.Iwant[0].MessageIDs, msgID); lastRPC.Size() > limit {
						lastRPC.Control.Iwant[0].MessageIDs = lastRPC.Control.Iwant[0].MessageIDs[:len(lastRPC.Control.Iwant[0].MessageIDs)-1]
						lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{
							Iwant: []*pb.ControlIWant{{MessageIDs: [][]byte{msgID}}},
						}}, from: elem.from}
						out = append(out, lastRPC)
					}
				}
			}

			for _, ihave := range ctl.GetIhave() {
				if len(lastRPC.Control.Ihave) == 0 ||
					!bytes.Equal(lastRPC.Control.Ihave[len(lastRPC.Control.Ihave)-1].Bitmask, ihave.Bitmask) {
					// Start a new IHAVE if we are referencing a new bitmask ID
					newIhave := &pb.ControlIHave{Bitmask: ihave.Bitmask}
					if lastRPC.Control.Ihave = append(lastRPC.Control.Ihave, newIhave); lastRPC.Size() > limit {
						lastRPC.Control.Ihave = lastRPC.Control.Ihave[:len(lastRPC.Control.Ihave)-1]
						lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{
							Ihave: []*pb.ControlIHave{newIhave},
						}}, from: elem.from}
						out = append(out, lastRPC)
					}
				}
				for _, msgID := range ihave.GetMessageIDs() {
					lastIHave := lastRPC.Control.Ihave[len(lastRPC.Control.Ihave)-1]
					if lastIHave.MessageIDs = append(lastIHave.MessageIDs, msgID); lastRPC.Size() > limit {
						lastIHave.MessageIDs = lastIHave.MessageIDs[:len(lastIHave.MessageIDs)-1]
						lastRPC = &RPC{RPC: &pb.RPC{Control: &pb.ControlMessage{
							Ihave: []*pb.ControlIHave{{Bitmask: ihave.Bitmask, MessageIDs: [][]byte{msgID}}},
						}}, from: elem.from}
						out = append(out, lastRPC)
					}
				}
			}
		}
	}

	return out
}

func (bs *BlossomSubRouter) heartbeatTimer() {
	time.Sleep(bs.params.HeartbeatInitialDelay)
	select {
	case bs.p.eval <- bs.heartbeat:
	case <-bs.p.ctx.Done():
		return
	}

	ticker := time.NewTicker(bs.params.HeartbeatInterval)

	for {
		select {
		case <-ticker.C:
			select {
			case bs.p.eval <- bs.heartbeat:
			case <-bs.p.ctx.Done():
				ticker.Stop()
				return
			}
		case <-bs.p.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

func (bs *BlossomSubRouter) heartbeat() {
	start := time.Now()

	bs.heartbeatTicks++

	tograft := make(map[peer.ID][][]byte)
	toprune := make(map[peer.ID][][]byte)
	noPX := make(map[peer.ID]bool)

	// clean up expired backoffs
	bs.clearBackoff()

	// clean up iasked counters
	bs.clearIHaveCounters()

	// clean up IDONTWANT counters
	bs.clearIDontWantCounters()

	// apply IWANT request penalties
	bs.applyIwantPenalties()

	// ensure direct peers are connected
	bs.directConnect()

	// cache scores throughout the heartbeat
	scores := make(map[peer.ID]float64)
	score := func(p peer.ID) float64 {
		s, ok := scores[p]
		if !ok {
			s = bs.score.Score(p)
			scores[p] = s
		}
		return s
	}

	// maintain the mesh for bitmasks we have joined
	for bitmask, peers := range bs.mesh {
		bitmask := []byte(bitmask)
		prunePeer := func(p peer.ID) {
			bs.tracer.Prune(p, bitmask)
			delete(peers, p)
			bs.addBackoff(p, bitmask, false)
			bitmasks := toprune[p]
			toprune[p] = append(bitmasks, bitmask)
		}

		graftPeer := func(p peer.ID) {
			log.Debugf("HEARTBEAT: Add mesh link to %s in %s", p, bitmask)
			bs.tracer.Graft(p, bitmask)
			peers[p] = struct{}{}
			bitmasks := tograft[p]
			tograft[p] = append(bitmasks, bitmask)
		}

		// drop all peers with negative score, without PX
		for p := range peers {
			if score(p) < 0 {
				log.Debugf("HEARTBEAT: Prune peer %s with negative score [score = %f, bitmask = %s]", p, score(p), bitmask)
				prunePeer(p)
				noPX[p] = true
			}
		}

		// do we have enough peers?
		if l := len(peers); l < bs.params.Dlo {
			backoff := bs.backoff[string(bitmask)]
			ineed := bs.params.D - l
			plst := bs.getPeers(bitmask, ineed, func(p peer.ID) bool {
				// filter our current and direct peers, peers we are backing off, and peers with negative score
				_, inMesh := peers[p]
				_, doBackoff := backoff[p]
				_, direct := bs.direct[p]
				return !inMesh && !doBackoff && !direct && score(p) >= 0
			})

			for _, p := range plst {
				graftPeer(p)
			}
		}

		// do we have too many peers?
		if len(peers) > bs.params.Dhi {
			plst := peerMapToList(peers)

			// sort by score (but shuffle first for the case we don't use the score)
			shufflePeers(plst)
			sort.Slice(plst, func(i, j int) bool {
				return score(plst[i]) > score(plst[j])
			})

			// We keep the first D_score peers by score and the remaining up to D randomly
			// under the constraint that we keep D_out peers in the mesh (if we have that many)
			if len(plst) > bs.params.Dscore {
				shufflePeers(plst[bs.params.Dscore:])
			}

			// count the outbound peers we are keeping
			outbound := 0
			for _, p := range plst[:bs.params.D] {
				if bs.outbound[p] {
					outbound++
				}
			}

			// if it's less than D_out, bubble up some outbound peers from the random selection
			if outbound < bs.params.Dout {
				rotate := func(i int) {
					// rotate the plst to the right and put the ith peer in the front
					p := plst[i]
					for j := i; j > 0; j-- {
						plst[j] = plst[j-1]
					}
					plst[0] = p
				}

				// first bubble up all outbound peers already in the selection to the front
				if outbound > 0 {
					ihave := outbound
					for i := 1; i < bs.params.D && ihave > 0; i++ {
						p := plst[i]
						if bs.outbound[p] {
							rotate(i)
							ihave--
						}
					}
				}

				// now bubble up enough outbound peers outside the selection to the front
				ineed := bs.params.Dout - outbound
				for i := bs.params.D; i < len(plst) && ineed > 0; i++ {
					p := plst[i]
					if bs.outbound[p] {
						rotate(i)
						ineed--
					}
				}
			}

			// prune the excess peers
			for _, p := range plst[bs.params.D:] {
				log.Debugf("HEARTBEAT: Remove mesh link to %s in %s", p, bitmask)
				prunePeer(p)
			}
		}

		// do we have enough outboud peers?
		if len(peers) >= bs.params.Dlo {
			// count the outbound peers we have
			outbound := 0
			for p := range peers {
				if bs.outbound[p] {
					outbound++
				}
			}

			// if it's less than D_out, select some peers with outbound connections and graft them
			if outbound < bs.params.Dout {
				ineed := bs.params.Dout - outbound
				backoff := bs.backoff[string(bitmask)]
				plst := bs.getPeers(bitmask, ineed, func(p peer.ID) bool {
					// filter our current and direct peers, peers we are backing off, and peers with negative score
					_, inMesh := peers[p]
					_, doBackoff := backoff[p]
					_, direct := bs.direct[p]
					return !inMesh && !doBackoff && !direct && bs.outbound[p] && score(p) >= 0
				})

				for _, p := range plst {
					graftPeer(p)
				}
			}
		}

		// should we try to improve the mesh with opportunistic grafting?
		if bs.heartbeatTicks%bs.params.OpportunisticGraftTicks == 0 && len(peers) > 1 {
			// Opportunistic grafting works as follows: we check the median score of peers in the
			// mesh; if this score is below the opportunisticGraftThreshold, we select a few peers at
			// random with score over the median.
			// The intention is to (slowly) improve an underperforming mesh by introducing good
			// scoring peers that may have been gossiping at us. This allows us to get out of sticky
			// situations where we are stuck with poor peers and also recover from churn of good peers.

			// now compute the median peer score in the mesh
			plst := peerMapToList(peers)
			sort.Slice(plst, func(i, j int) bool {
				return score(plst[i]) < score(plst[j])
			})
			medianIndex := len(peers) / 2
			medianScore := scores[plst[medianIndex]]

			// if the median score is below the threshold, select a better peer (if any) and GRAFT
			if medianScore < bs.opportunisticGraftThreshold {
				backoff := bs.backoff[string(bitmask)]
				plst = bs.getPeers(bitmask, bs.params.OpportunisticGraftPeers, func(p peer.ID) bool {
					_, inMesh := peers[p]
					_, doBackoff := backoff[p]
					_, direct := bs.direct[p]
					return !inMesh && !doBackoff && !direct && score(p) > medianScore
				})

				for _, p := range plst {
					log.Debugf("HEARTBEAT: Opportunistically graft peer %s on bitmask %x", p, bitmask)
					graftPeer(p)
				}
			}
		}

		// 2nd arg are mesh peers excluded from gossip. We already push
		// messages to them, so its redundant to gossip IHAVEs.
		bs.emitGossip(bitmask, peers)

		if bs.params.SlowHeartbeatWarning > 0 {
			slowWarning := time.Duration(bs.params.SlowHeartbeatWarning * float64(bs.params.HeartbeatInterval))
			if dt := time.Since(start); dt > slowWarning {
				log.Warnw("slow heartbeat", "took", dt)
			}
		}
	}

	// expire fanout for bitmasks we haven't published to in a while
	now := time.Now().UnixNano()
	for bitmask, lastpub := range bs.lastpub {
		if lastpub+int64(bs.params.FanoutTTL) < now {
			delete(bs.fanout, bitmask)
			delete(bs.lastpub, bitmask)
		}
	}

	// maintain our fanout for bitmasks we are publishing but we have not joined
	for bitmask, peers := range bs.fanout {
		bitmask := []byte(bitmask)
		// check whether our peers are still in the bitmask and have a score above the publish threshold
		for p := range peers {
			_, ok := bs.p.bitmasks[string(bitmask)][p]
			if !ok || score(p) < bs.publishThreshold {
				delete(peers, p)
			}
		}

		// do we need more peers?
		if len(peers) < bs.params.D {
			ineed := bs.params.D - len(peers)
			plst := bs.getPeers(bitmask, ineed, func(p peer.ID) bool {
				// filter our current and direct peers and peers with score above the publish threshold
				_, inFanout := peers[p]
				_, direct := bs.direct[p]
				return !inFanout && !direct && score(p) >= bs.publishThreshold
			})

			for _, p := range plst {
				peers[p] = struct{}{}
			}
		}

		// 2nd arg are fanout peers excluded from gossip. We already push
		// messages to them, so its redundant to gossip IHAVEs.
		bs.emitGossip(bitmask, peers)
	}

	// send coalesced GRAFT/PRUNE messages (will piggyback gossip)
	bs.sendGraftPrune(tograft, toprune, noPX)

	// flush all pending gossip that wasn't piggybacked above
	bs.flush()

	// advance the message history window
	bs.mcache.Shift()
}

func (bs *BlossomSubRouter) clearIHaveCounters() {
	clear(bs.peerhave)
	clear(bs.iasked)
}

func (bs *BlossomSubRouter) clearIDontWantCounters() {
	clear(bs.peerdontwant)

	// decrement TTLs of all the IDONTWANTs and delete it from the cache when it reaches zero
	for _, mids := range bs.unwanted {
		for mid := range mids {
			mids[mid]--
			if mids[mid] == 0 {
				delete(mids, mid)
			}
		}
	}
}

func (bs *BlossomSubRouter) applyIwantPenalties() {
	for p, count := range bs.gossipTracer.GetBrokenPromises() {
		log.Infof("peer %s didn't follow up in %d IWANT requests; adding penalty", p, count)
		bs.score.AddPenalty(p, count)
	}
}

func (bs *BlossomSubRouter) clearBackoff() {
	// we only clear once every 15 ticks to avoid iterating over the map(s) too much
	if bs.heartbeatTicks%15 != 0 {
		return
	}

	now := time.Now()
	for bitmask, backoff := range bs.backoff {
		for p, expire := range backoff {
			// add some slack time to the expiration
			// https://github.com/libp2p/specs/pull/289
			if expire.Add(2 * BlossomSubHeartbeatInterval).Before(now) {
				delete(backoff, p)
			}
		}
		if len(backoff) == 0 {
			delete(bs.backoff, bitmask)
		}
	}
}

func (bs *BlossomSubRouter) directConnect() {
	// we donly do this every some ticks to allow pending connections to complete and account
	// for restarts/downtime
	if bs.heartbeatTicks%bs.params.DirectConnectTicks != 0 {
		return
	}

	var toconnect []peer.ID
	for p := range bs.direct {
		_, connected := bs.peers[p]
		if !connected {
			toconnect = append(toconnect, p)
		}
	}

	if len(toconnect) > 0 {
		go func() {
			for _, p := range toconnect {
				bs.connect <- connectInfo{p: p}
			}
		}()
	}
}

func (bs *BlossomSubRouter) sendGraftPrune(tograft, toprune map[peer.ID][][]byte, noPX map[peer.ID]bool) {
	for p, bitmasks := range tograft {
		graft := make([]*pb.ControlGraft, 0, len(bitmasks))
		for _, bitmask := range bitmasks {
			// copy bitmask []byte here since
			// the reference to the string
			// bitmask here changes with every
			// iteration of the slice.
			copiedID := bitmask
			graft = append(graft, &pb.ControlGraft{Bitmask: copiedID})
		}

		var prune []*pb.ControlPrune
		pruning, ok := toprune[p]
		if ok {
			delete(toprune, p)
			prune = make([]*pb.ControlPrune, 0, len(pruning))
			for _, bitmask := range pruning {
				prune = append(prune, bs.makePrune(p, bitmask, bs.doPX && !noPX[p], false))
			}
		}

		out := rpcWithControl(nil, nil, nil, graft, prune, nil)
		bs.sendRPC(p, out, false)
	}

	for p, bitmasks := range toprune {
		prune := make([]*pb.ControlPrune, 0, len(bitmasks))
		for _, bitmask := range bitmasks {
			prune = append(prune, bs.makePrune(p, bitmask, bs.doPX && !noPX[p], false))
		}

		out := rpcWithControl(nil, nil, nil, nil, prune, nil)
		bs.sendRPC(p, out, false)
	}
}

// emitGossip emits IHAVE gossip advertising items in the message cache window
// of this bitmask.
func (bs *BlossomSubRouter) emitGossip(bitmask []byte, exclude map[peer.ID]struct{}) {
	mids := bs.mcache.GetGossipIDs(bitmask)
	if len(mids) == 0 {
		return
	}

	// shuffle to emit in random order
	shuffleBytes(mids)

	// if we are emitting more than BlossomSubMaxIHaveLength mids, truncate the list
	if len(mids) > bs.params.MaxIHaveLength {
		// we do the truncation (with shuffling) per peer below
		log.Debugf("too many messages for gossip; will truncate IHAVE list (%d messages)", len(mids))
	}

	// Send gossip to GossipFactor peers above threshold, with a minimum of D_lazy.
	// First we collect the peers above gossipThreshold that are not in the exclude set
	// and then randomly select from that set.
	// We also exclude direct peers, as there is no reason to emit gossip to them.
	peers := make([]peer.ID, 0, len(bs.p.bitmasks[string(bitmask)]))
	for p := range bs.p.bitmasks[string(bitmask)] {
		_, inExclude := exclude[p]
		_, direct := bs.direct[p]
		if !inExclude && !direct && bs.feature(BlossomSubFeatureMesh, bs.peers[p]) && bs.score.Score(p) >= bs.gossipThreshold {
			peers = append(peers, p)
		}
	}

	target := bs.params.Dlazy
	factor := int(bs.params.GossipFactor * float64(len(peers)))
	target = max(target, factor)

	if target > len(peers) {
		target = len(peers)
	} else {
		shufflePeers(peers)
	}
	peers = peers[:target]

	// Emit the IHAVE gossip to the selected peers.
	for _, p := range peers {
		peerMids := mids
		if len(mids) > bs.params.MaxIHaveLength {
			// we do this per peer so that we emit a different set for each peer.
			// we have enough redundancy in the system that this will significantly increase the message
			// coverage when we do truncate.
			peerMids = make([][]byte, bs.params.MaxIHaveLength)
			shuffleBytes(mids)
			copy(peerMids, mids)
		}
		bs.enqueueGossip(p, &pb.ControlIHave{Bitmask: bitmask, MessageIDs: peerMids})
	}
}

func (bs *BlossomSubRouter) flush() {
	// send gossip first, which will also piggyback pending control
	for p, ihave := range bs.gossip {
		delete(bs.gossip, p)
		out := rpcWithControl(nil, ihave, nil, nil, nil, nil)
		bs.sendRPC(p, out, false)
	}

	// send the remaining control messages that wasn't merged with gossip
	for p, ctl := range bs.control {
		delete(bs.control, p)
		out := rpcWithControl(nil, nil, nil, ctl.Graft, ctl.Prune, nil)
		bs.sendRPC(p, out, false)
	}
}

func (bs *BlossomSubRouter) enqueueGossip(p peer.ID, ihave *pb.ControlIHave) {
	gossip := bs.gossip[p]
	gossip = append(gossip, ihave)
	bs.gossip[p] = gossip
}

func (bs *BlossomSubRouter) piggybackGossip(p peer.ID, out *RPC, ihave []*pb.ControlIHave) {
	ctl := out.GetControl()
	if ctl == nil {
		ctl = &pb.ControlMessage{}
		out.Control = ctl
	}

	ctl.Ihave = ihave
}

func (bs *BlossomSubRouter) pushControl(p peer.ID, ctl *pb.ControlMessage) {
	// remove IHAVE/IWANT from control message, gossip is not retried
	ctl.Ihave = nil
	ctl.Iwant = nil
	if ctl.Graft != nil || ctl.Prune != nil {
		bs.control[p] = ctl
	}
}

func (bs *BlossomSubRouter) piggybackControl(p peer.ID, out *RPC, ctl *pb.ControlMessage) {
	// check control message for staleness first
	var tograft []*pb.ControlGraft
	var toprune []*pb.ControlPrune

	for _, graft := range ctl.GetGraft() {
		bitmask := graft.GetBitmask()
		peers, ok := bs.mesh[string(bitmask)]
		if !ok {
			continue
		}
		_, ok = peers[p]
		if ok {
			tograft = append(tograft, graft)
		}
	}

	for _, prune := range ctl.GetPrune() {
		bitmask := prune.GetBitmask()
		peers, ok := bs.mesh[string(bitmask)]
		if !ok {
			toprune = append(toprune, prune)
			continue
		}
		_, ok = peers[p]
		if !ok {
			toprune = append(toprune, prune)
		}
	}

	if len(tograft) == 0 && len(toprune) == 0 {
		return
	}

	xctl := out.Control
	if xctl == nil {
		xctl = &pb.ControlMessage{}
		out.Control = xctl
	}

	if len(tograft) > 0 {
		xctl.Graft = append(xctl.Graft, tograft...)
	}
	if len(toprune) > 0 {
		xctl.Prune = append(xctl.Prune, toprune...)
	}
}

func (bs *BlossomSubRouter) makePrune(p peer.ID, bitmask []byte, doPX bool, isUnsubscribe bool) *pb.ControlPrune {
	if !bs.feature(BlossomSubFeaturePX, bs.peers[p]) {
		// BlossomSub v1.0 -- no peer exchange, the peer won't be able to parse it anyway
		return &pb.ControlPrune{Bitmask: bitmask}
	}

	backoff := uint64(bs.params.PruneBackoff / time.Second)
	if isUnsubscribe {
		backoff = uint64(bs.params.UnsubscribeBackoff / time.Second)
	}

	var px []*pb.PeerInfo
	if doPX {
		// select peers for Peer eXchange
		peers := bs.getPeers(bitmask, bs.params.PrunePeers, func(xp peer.ID) bool {
			return p != xp && bs.score.Score(xp) >= 0
		})

		cab, ok := peerstore.GetCertifiedAddrBook(bs.p.host.Peerstore())
		px = make([]*pb.PeerInfo, 0, len(peers))
		for _, p := range peers {
			// see if we have a signed peer record to send back; if we don't, just send
			// the peer ID and let the pruned peer find them in the DHT -- we can't trust
			// unsigned address records through px anyway.
			var recordBytes []byte
			if ok {
				spr := cab.GetPeerRecord(p)
				var err error
				if spr != nil {
					recordBytes, err = spr.Marshal()
					if err != nil {
						log.Warnf("error marshaling signed peer record for %s: %s", p, err)
					}
				}
			}
			px = append(px, &pb.PeerInfo{PeerID: []byte(p), SignedPeerRecord: recordBytes})
		}
	}

	return &pb.ControlPrune{Bitmask: bitmask, Peers: px, Backoff: backoff}
}

func (bs *BlossomSubRouter) getPeers(bitmask []byte, count int, filter func(peer.ID) bool) []peer.ID {
	bitmaskSlices := SliceBitmask(bitmask)

	set := []peer.ID{}
	for _, slice := range bitmaskSlices {
		tmap, ok := bs.p.bitmasks[string(slice)]
		if !ok {
			return nil
		}

		peers := make([]peer.ID, 0, len(tmap))
		for p := range tmap {
			if bs.feature(BlossomSubFeatureMesh, bs.peers[p]) && filter(p) && bs.p.peerFilter(p, slice) {
				peers = append(peers, p)
			}
		}

		if len(set) == 0 {
			set = peers
		} else {
			newSet := []peer.ID{}
			for _, p := range peers {
				if slices.Contains(set, p) {
					newSet = append(newSet, p)
				}
			}

			if len(newSet) == 0 {
				return nil
			}

			set = newSet
		}
	}

	shufflePeers(set)

	if count > 0 && len(set) > count {
		set = set[:count]
	}

	return set
}

// WithDefaultTagTracer returns the tag tracer of the BlossomSubRouter as a PubSub option.
// This is useful for cases where the BlossomSubRouter is instantiated externally, and is
// injected into the BlossomSub constructor as a dependency. This allows the tag tracer to be
// also injected into the BlossomSub constructor as a PubSub option dependency.
func (bs *BlossomSubRouter) WithDefaultTagTracer() Option {
	return WithRawTracer(bs.tagTracer)
}

func peerListToMap(peers []peer.ID) map[peer.ID]struct{} {
	pmap := make(map[peer.ID]struct{})
	for _, p := range peers {
		pmap[p] = struct{}{}
	}
	return pmap
}

func peerMapToList(peers map[peer.ID]struct{}) []peer.ID {
	plst := make([]peer.ID, 0, len(peers))
	for p := range peers {
		plst = append(plst, p)
	}
	return plst
}

func shufflePeers(peers []peer.ID) {
	for i := range peers {
		j := rand.Intn(i + 1)
		peers[i], peers[j] = peers[j], peers[i]
	}
}

func shufflePeerInfo(peers []*pb.PeerInfo) {
	for i := range peers {
		j := rand.Intn(i + 1)
		peers[i], peers[j] = peers[j], peers[i]
	}
}

func shuffleBytes(lst [][]byte) {
	for i := range lst {
		j := rand.Intn(i + 1)
		lst[i], lst[j] = lst[j], lst[i]
	}
}
