package blossomsub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/timecache"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	logging "github.com/ipfs/go-log/v2"
)

// DefaultSoftMaxMessageSize is 1 MiB.
const DefaultSoftMaxMessageSize = 1 << 20

// DefaultHardMaxMessageSize is 20 MB.
const DefaultHardMaxMessageSize = 10 << 21

// DefaultPeerOutboundQueueSize is the default size of the outbound message channel that we maintain for each peer.
const DefaultPeerOutboundQueueSize = 128

var (
	// TimeCacheDuration specifies how long a message ID will be remembered as seen.
	// Use WithSeenMessagesTTL to configure this per pubsub instance, instead of overriding the global default.
	TimeCacheDuration = 1 * time.Hour

	// TimeCacheStrategy specifies which type of lookup/cleanup strategy is used by the seen messages cache.
	// Use WithSeenMessagesStrategy to configure this per pubsub instance, instead of overriding the global default.
	TimeCacheStrategy = timecache.Strategy_FirstSeen

	// ErrSubscriptionCancelled may be returned when a subscription Next() is called after the
	// subscription has been cancelled.
	ErrSubscriptionCancelled = errors.New("subscription cancelled")
)

var log = logging.Logger("pubsub")

type ProtocolMatchFn = func(protocol.ID) func(protocol.ID) bool

// PubSub is the implementation of the pubsub system.
type PubSub struct {
	// atomic counter for seqnos
	// NOTE: Must be declared at the top of the struct as we perform atomic
	// operations on this field.
	//
	// See: https://golang.org/pkg/sync/atomic/#pkg-note-BUG
	counter uint64

	host host.Host

	rt PubSubRouter

	val *validation

	disc *discover

	tracer *pubsubTracer

	peerFilter PeerFilter

	// softMaxMessageSize is the maximum size of a single message fragment that
	// we will attempt to send.
	softMaxMessageSize int
	// hardMaxMessageSize is the maximum size of a single message fragment that
	// we will accept.
	hardMaxMessageSize int

	// size of the outbound message channel that we maintain for each peer
	peerOutboundQueueSize int

	// incoming messages from other peers
	incoming chan *RPC

	// addSub is a control channel for us to add and remove subscriptions
	addSub chan *addSubReq

	// addRelay is a control channel for us to add and remove relays
	addRelay chan *addRelayReq

	// rmRelay is a relay cancellation channel
	rmRelay chan string

	// get list of bitmasks we are subscribed to
	getBitmasks chan *bitmaskReq

	// get chan of peers we are connected to
	getPeers chan *listPeerReq

	// send subscription here to cancel it
	cancelCh chan *Subscription

	// addSub is a channel for us to add a bitmask
	addBitmask chan *addBitmaskReq

	// removeBitmask is a bitmask cancellation channel
	rmBitmask chan *rmBitmaskReq

	// a notification channel for new peer connections accumulated
	newPeers       chan struct{}
	newPeersPrioLk sync.RWMutex
	newPeersMx     sync.Mutex
	newPeersPend   map[peer.ID]struct{}

	// a notification channel for new outoging peer streams
	newPeerStream chan network.Stream

	// a notification channel for errors opening new peer streams
	newPeerError chan peer.ID

	// a notification channel for when our peers die
	peerDead       chan struct{}
	peerDeadPrioLk sync.RWMutex
	peerDeadMx     sync.Mutex
	peerDeadPend   map[peer.ID]struct{}
	// backoff for retrying new connections to dead peers
	deadPeerBackoff *backoff

	// The set of bitmasks we are subscribed to
	mySubs map[string]map[*Subscription]struct{}

	// The set of bitmasks we are relaying for
	myRelays map[string]int

	// The set of bitmasks we are interested in
	myBitmasks map[string]*Bitmask

	// bitmasks tracks which bitmasks each of our peers are subscribed to
	bitmasks map[string]map[peer.ID]struct{}

	// sendMsg handles messages that have been validated
	sendMsg chan *Message

	// addVal handles validator registration requests
	addVal chan *addValReq

	// rmVal handles validator unregistration requests
	rmVal chan *rmValReq

	// eval thunk in event loop
	eval chan func()

	// peer blacklist
	blacklist     Blacklist
	blacklistPeer chan peer.ID

	peerMx sync.RWMutex
	peers  map[peer.ID]*rpcQueue

	inboundStreamsMx sync.Mutex
	inboundStreams   map[peer.ID]network.Stream

	seenMessages    timecache.TimeCache
	seenMsgTTL      time.Duration
	seenMsgStrategy timecache.Strategy

	// generator used to compute the ID for a message
	idGen *msgIDGenerator

	// key for signing messages; nil when signing is disabled
	signKey crypto.PrivKey
	// source ID for signed messages; corresponds to signKey, empty when signing is disabled.
	// If empty, the author and seq-nr are completely omitted from the messages.
	signID peer.ID
	// strict mode rejects all unsigned messages prior to validation
	signPolicy MessageSignaturePolicy

	// filter for tracking subscriptions in bitmasks of interest; if nil, then we track all subscriptions
	subFilter SubscriptionFilter

	// protoMatchFunc is a matching function for protocol selection.
	protoMatchFunc ProtocolMatchFn

	ctx context.Context

	// appSpecificRpcInspector is an auxiliary that may be set by the application to inspect incoming RPCs prior to
	// processing them. The inspector is invoked on an accepted RPC right prior to handling it.
	// The return value of the inspector function is an error indicating whether the RPC should be processed or not.
	// If the error is nil, the RPC is processed as usual. If the error is non-nil, the RPC is dropped.
	appSpecificRpcInspector func(peer.ID, *RPC) error
}

// PubSubRouter is the message router component of PubSub.
type PubSubRouter interface {
	// Protocols returns the list of protocols supported by the router.
	Protocols() []protocol.ID
	// Attach is invoked by the PubSub constructor to attach the router to a
	// freshly initialized PubSub instance.
	Attach(*PubSub)
	// PeerScore returns the internal scoring basis for a given peer. This method should not be
	// externally exposed to remote callers.
	PeerScore(peer.ID) float64
	// AddPeer notifies the router that a new peer has been connected.
	AddPeer(peer.ID, protocol.ID)
	// RemovePeer notifies the router that a peer has been disconnected.
	RemovePeer(peer.ID)
	// EnoughPeers returns whether the router needs more peers before it's ready to publish new records.
	// Suggested (if greater than 0) is a suggested number of peers that the router should need.
	EnoughPeers(bitmask []byte, suggested int) bool
	// AcceptFrom is invoked on any RPC envelope before pushing it to the validation pipeline
	// or processing control information.
	// Allows routers with internal scoring to vet peers before committing any processing resources
	// to the message and implement an effective graylist and react to validation queue overload.
	AcceptFrom(peer.ID) AcceptStatus
	// PreValidation is invoked on messages in the RPC envelope right before pushing it to
	// the validation pipeline
	PreValidation([]*Message)
	// HandleRPC is invoked to process control messages in the RPC envelope.
	// It is invoked after subscriptions and payload messages have been processed.
	HandleRPC(*RPC)
	// Publish is invoked to forward a new message that has been validated.
	Publish(*Message)
	// Join notifies the router that we want to receive and forward messages in a bitmask.
	// It is invoked after the subscription announcement.
	Join(bitmask []byte)
	// Leave notifies the router that we are no longer interested in a bitmask.
	// It is invoked after the unsubscription announcement.
	Leave(bitmask []byte)
}

type AcceptStatus int

const (
	// AcceptNone signals to drop the incoming RPC
	AcceptNone AcceptStatus = iota
	// AcceptControl signals to accept the incoming RPC only for control message processing by
	// the router. Included payload messages will _not_ be pushed to the validation queue.
	AcceptControl
	// AcceptAll signals to accept the incoming RPC for full processing
	AcceptAll
)

type Message struct {
	*pb.Message
	ID            []byte
	ReceivedFrom  peer.ID
	ValidatorData interface{}
	Local         bool
}

func (m *Message) GetFrom() peer.ID {
	return peer.ID(m.Message.GetFrom())
}

type RPC struct {
	*pb.RPC

	// unexported on purpose, not sending this over the wire
	from peer.ID
}

type Option func(*PubSub) error

// NewPubSub returns a new PubSub management object.
func NewPubSub(ctx context.Context, h host.Host, rt PubSubRouter, opts ...Option) (*PubSub, error) {
	ps := &PubSub{
		host:                  h,
		ctx:                   ctx,
		rt:                    rt,
		val:                   newValidation(),
		peerFilter:            DefaultPeerFilter,
		disc:                  &discover{},
		softMaxMessageSize:    DefaultSoftMaxMessageSize,
		hardMaxMessageSize:    DefaultHardMaxMessageSize,
		peerOutboundQueueSize: DefaultPeerOutboundQueueSize,
		signID:                h.ID(),
		signKey:               nil,
		signPolicy:            LaxSign,
		incoming:              make(chan *RPC, 32),
		newPeers:              make(chan struct{}, 1),
		newPeersPend:          make(map[peer.ID]struct{}),
		newPeerStream:         make(chan network.Stream),
		newPeerError:          make(chan peer.ID),
		peerDead:              make(chan struct{}, 1),
		peerDeadPend:          make(map[peer.ID]struct{}),
		deadPeerBackoff:       newBackoff(ctx, 1000, BackoffCleanupInterval, MaxBackoffAttempts),
		cancelCh:              make(chan *Subscription),
		getPeers:              make(chan *listPeerReq),
		addSub:                make(chan *addSubReq),
		addRelay:              make(chan *addRelayReq),
		rmRelay:               make(chan string),
		addBitmask:            make(chan *addBitmaskReq),
		rmBitmask:             make(chan *rmBitmaskReq),
		getBitmasks:           make(chan *bitmaskReq),
		sendMsg:               make(chan *Message, 32),
		addVal:                make(chan *addValReq),
		rmVal:                 make(chan *rmValReq),
		eval:                  make(chan func()),
		myBitmasks:            make(map[string]*Bitmask),
		mySubs:                make(map[string]map[*Subscription]struct{}),
		myRelays:              make(map[string]int),
		bitmasks:              make(map[string]map[peer.ID]struct{}),
		peers:                 make(map[peer.ID]*rpcQueue),
		inboundStreams:        make(map[peer.ID]network.Stream),
		blacklist:             NewMapBlacklist(),
		blacklistPeer:         make(chan peer.ID),
		seenMsgTTL:            TimeCacheDuration,
		seenMsgStrategy:       TimeCacheStrategy,
		idGen:                 newMsgIdGenerator(),
		counter:               uint64(time.Now().UnixNano()),
	}

	for _, opt := range opts {
		err := opt(ps)
		if err != nil {
			return nil, err
		}
	}

	if ps.signPolicy.mustSign() {
		if ps.signID == "" {
			return nil, fmt.Errorf("strict signature usage enabled but message author was disabled")
		}
		ps.signKey = ps.host.Peerstore().PrivKey(ps.signID)
		if ps.signKey == nil {
			return nil, fmt.Errorf("can't sign for peer %s: no private key", ps.signID)
		}
	}

	ps.seenMessages = timecache.NewTimeCacheWithStrategy(ps.seenMsgStrategy, ps.seenMsgTTL)

	if err := ps.disc.Start(ps); err != nil {
		return nil, err
	}

	rt.Attach(ps)

	for _, id := range rt.Protocols() {
		if ps.protoMatchFunc != nil {
			h.SetStreamHandlerMatch(id, ps.protoMatchFunc(id), ps.handleNewStream)
		} else {
			h.SetStreamHandler(id, ps.handleNewStream)
		}
	}

	go ps.watchForNewPeers(ctx)

	ps.val.Start(ps)

	go ps.processLoop(ctx)

	return ps, nil
}

// MsgIdFunction returns a unique ID for the passed Message, and PubSub can be customized to use any
// implementation of this function by configuring it with the Option from WithMessageIdFn.
type MsgIdFunction func(pmsg *pb.Message) []byte

// WithMessageIdFn is an option to customize the way a message ID is computed for a pubsub message.
// The default ID function is DefaultMsgIdFn (concatenate source and seq nr.),
// but it can be customized to e.g. the hash of the message.
func WithMessageIdFn(fn MsgIdFunction) Option {
	return func(p *PubSub) error {
		p.idGen.Default = fn
		return nil
	}
}

// PeerFilter is used to filter pubsub peers. It should return true for peers that are accepted for
// a given bitmask. PubSub can be customized to use any implementation of this function by configuring
// it with the Option from WithPeerFilter.
type PeerFilter func(pid peer.ID, bitmask []byte) bool

// WithPeerFilter is an option to set a filter for pubsub peers.
// The default peer filter is DefaultPeerFilter (which always returns true), but it can be customized
// to any custom implementation.
func WithPeerFilter(filter PeerFilter) Option {
	return func(p *PubSub) error {
		p.peerFilter = filter
		return nil
	}
}

// WithPeerOutboundQueueSize is an option to set the buffer size for outbound messages to a peer
// We start dropping messages to a peer if the outbound queue if full
func WithPeerOutboundQueueSize(size int) Option {
	return func(p *PubSub) error {
		if size <= 0 {
			return errors.New("outbound queue size must always be positive")
		}
		p.peerOutboundQueueSize = size
		return nil
	}
}

// WithMessageSignaturePolicy sets the mode of operation for producing and verifying message signatures.
func WithMessageSignaturePolicy(policy MessageSignaturePolicy) Option {
	return func(p *PubSub) error {
		p.signPolicy = policy
		return nil
	}
}

// WithMessageSigning enables or disables message signing (enabled by default).
// Deprecated: signature verification without message signing,
// or message signing without verification, are not recommended.
func WithMessageSigning(enabled bool) Option {
	return func(p *PubSub) error {
		if enabled {
			p.signPolicy |= msgSigning
		} else {
			p.signPolicy &^= msgSigning
		}
		return nil
	}
}

// WithMessageAuthor sets the author for outbound messages to the given peer ID
// (defaults to the host's ID). If message signing is enabled, the private key
// must be available in the host's peerstore.
func WithMessageAuthor(author peer.ID) Option {
	return func(p *PubSub) error {
		author := author
		if author == "" {
			author = p.host.ID()
		}
		p.signID = author
		return nil
	}
}

// WithNoAuthor omits the author and seq-number data of messages, and disables the use of signatures.
// Not recommended to use with the default message ID function, see WithMessageIdFn.
func WithNoAuthor() Option {
	return func(p *PubSub) error {
		p.signID = ""
		p.signPolicy &^= msgSigning
		return nil
	}
}

// WithStrictSignatureVerification is an option to enable or disable strict message signing.
// When enabled (which is the default), unsigned messages will be discarded.
// Deprecated: signature verification without message signing,
// or message signing without verification, are not recommended.
func WithStrictSignatureVerification(required bool) Option {
	return func(p *PubSub) error {
		if required {
			p.signPolicy |= msgVerification
		} else {
			p.signPolicy &^= msgVerification
		}
		return nil
	}
}

// WithBlacklist provides an implementation of the blacklist; the default is a
// MapBlacklist
func WithBlacklist(b Blacklist) Option {
	return func(p *PubSub) error {
		p.blacklist = b
		return nil
	}
}

// WithDiscovery provides a discovery mechanism used to bootstrap and provide peers into PubSub
func WithDiscovery(d discovery.Discovery, opts ...DiscoverOpt) Option {
	return func(p *PubSub) error {
		discoverOpts := defaultDiscoverOptions()
		for _, opt := range opts {
			err := opt(discoverOpts)
			if err != nil {
				return err
			}
		}

		p.disc.discovery = &pubSubDiscovery{Discovery: d, opts: discoverOpts.opts}
		p.disc.options = discoverOpts
		return nil
	}
}

// WithEventTracer provides a tracer for the pubsub system
func WithEventTracer(tracer EventTracer) Option {
	return func(p *PubSub) error {
		if p.tracer != nil {
			p.tracer.tracer = tracer
		} else {
			p.tracer = &pubsubTracer{tracer: tracer, pid: p.host.ID(), idGen: p.idGen}
		}
		return nil
	}
}

// WithRawTracer adds a raw tracer to the pubsub system.
// Multiple tracers can be added using multiple invocations of the option.
func WithRawTracer(tracer RawTracer) Option {
	return func(p *PubSub) error {
		if p.tracer != nil {
			p.tracer.raw = append(p.tracer.raw, tracer)
		} else {
			p.tracer = &pubsubTracer{raw: []RawTracer{tracer}, pid: p.host.ID(), idGen: p.idGen}
		}
		return nil
	}
}

// WithMaxMessageSize sets the global maximum message size for pubsub wire
// messages. The default value is 1MiB (DefaultMaxMessageSize).
//
// Observe the following warnings when setting this option.
//
// WARNING #1: Make sure to change the default protocol prefixes for BlossomSub
// (BlossomSubID). This avoids accidentally joining the public default network,
// which uses the default max message size, and therefore will cause messages to
// be dropped.
//
// WARNING #2: Reducing the default max message limit is fine, if you are
// certain that your application messages will not exceed the new limit.
// However, be wary of increasing the limit, as pubsub networks are naturally
// write-amplifying, i.e. for every message we receive, we send D copies of the
// message to our peers. If those messages are large, the bandwidth requirements
// will grow linearly. Note that propagation is sent on the uplink, which
// traditionally is more constrained than the downlink. Instead, consider
// out-of-band retrieval for large messages, by sending a CID (Content-ID) or
// another type of locator, such that messages can be fetched on-demand, rather
// than being pushed proactively. Under this design, you'd use the pubsub layer
// as a signalling system, rather than a data delivery system.
func WithMaxMessageSize(softMaxMessageSize, hardMaxMessageSize int) Option {
	return func(ps *PubSub) error {
		ps.softMaxMessageSize = softMaxMessageSize
		ps.hardMaxMessageSize = hardMaxMessageSize
		return nil
	}
}

// WithProtocolMatchFn sets a custom matching function for protocol selection to
// be used by the protocol handler on the Host's Mux. Should be combined with
// WithBlossomSubProtocols feature function for checking if certain protocol features
// are supported
func WithProtocolMatchFn(m ProtocolMatchFn) Option {
	return func(ps *PubSub) error {
		ps.protoMatchFunc = m
		return nil
	}
}

// WithSeenMessagesTTL configures when a previously seen message ID can be forgotten about
func WithSeenMessagesTTL(ttl time.Duration) Option {
	return func(ps *PubSub) error {
		ps.seenMsgTTL = ttl
		return nil
	}
}

// WithSeenMessagesStrategy configures which type of lookup/cleanup strategy is used by the seen messages cache
func WithSeenMessagesStrategy(strategy timecache.Strategy) Option {
	return func(ps *PubSub) error {
		ps.seenMsgStrategy = strategy
		return nil
	}
}

// WithAppSpecificRpcInspector sets a hook that inspect incomings RPCs prior to
// processing them.  The inspector is invoked on an accepted RPC just before it
// is handled.  If inspector's error is nil, the RPC is handled. Otherwise, it
// is dropped.
func WithAppSpecificRpcInspector(inspector func(peer.ID, *RPC) error) Option {
	return func(ps *PubSub) error {
		ps.appSpecificRpcInspector = inspector
		return nil
	}
}

// processLoop handles all inputs arriving on the channels
func (p *PubSub) processLoop(ctx context.Context) {
	defer func() {
		// Clean up go routines.
		for _, q := range p.peers {
			_ = q.Close()
		}
		p.peers = nil
		p.bitmasks = nil
		p.seenMessages.Done()
	}()

	for {
		select {
		case <-p.newPeers:
			p.handlePendingPeers()

		case s := <-p.newPeerStream:
			pid := s.Conn().RemotePeer()

			p.peerMx.RLock()
			q, ok := p.peers[pid]
			p.peerMx.RUnlock()
			if !ok {
				log.Warn("new stream for unknown peer: ", pid)
				s.Reset()
				continue
			}

			if p.blacklist.Contains(pid) {
				log.Warn("closing stream for blacklisted peer: ", pid)
				_ = q.Close()
				p.peerMx.Lock()
				delete(p.peers, pid)
				p.peerMx.Unlock()
				s.Reset()
				continue
			}

			p.rt.AddPeer(pid, s.Protocol())

		case pid := <-p.newPeerError:
			delete(p.peers, pid)

		case <-p.peerDead:
			p.handleDeadPeers()

		case treq := <-p.getBitmasks:
			var out []string
			for t := range p.mySubs {
				out = append(out, t)
			}
			treq.resp <- out
		case bitmask := <-p.addBitmask:
			p.handleAddBitmask(bitmask)
		case bitmask := <-p.rmBitmask:
			p.handleRemoveBitmask(bitmask)
		case sub := <-p.cancelCh:
			p.handleRemoveSubscription(sub)
		case sub := <-p.addSub:
			p.handleAddSubscription(sub)
		case relay := <-p.addRelay:
			p.handleAddRelay(relay)
		case bitmask := <-p.rmRelay:
			p.handleRemoveRelay([]byte(bitmask))
		case preq := <-p.getPeers:
			peers := p.getPeersInBitmask(preq.bitmask)

			if len(peers) == 0 {
				preq.resp <- nil
			} else {
				preq.resp <- peers
			}
		case rpc := <-p.incoming:
			p.handleIncomingRPC(rpc)

		case msg := <-p.sendMsg:
			p.publishMessage(msg)

		case req := <-p.addVal:
			p.val.AddValidator(req)

		case req := <-p.rmVal:
			p.val.RemoveValidator(req)

		case thunk := <-p.eval:
			thunk()

		case pid := <-p.blacklistPeer:
			log.Infof("Blacklisting peer %s", pid)
			p.blacklist.Add(pid)

			p.peerMx.RLock()
			q, ok := p.peers[pid]
			p.peerMx.RUnlock()
			if ok {
				_ = q.Close()
				p.peerMx.Lock()
				delete(p.peers, pid)
				p.peerMx.Unlock()
				for t, tmap := range p.bitmasks {
					if _, ok := tmap[pid]; ok {
						delete(tmap, pid)
						p.notifyLeave([]byte(t), pid)
					}
				}
				p.rt.RemovePeer(pid)
			}

		case <-ctx.Done():
			log.Info("pubsub processloop shutting down")
			return
		}
	}
}

func (p *PubSub) getPeersInBitmask(bitmask []byte) []peer.ID {
	bitmaskSlices := SliceBitmask(bitmask)
	var peers []peer.ID
peerloop:
	for _, slice := range bitmaskSlices {
		tmap, ok := p.bitmasks[string(slice)]
		if !ok {
			peers = []peer.ID{}
			break peerloop
		}

		var peerset []peer.ID
		for p := range p.peers {
			_, ok := tmap[p]
			if !ok {
				continue
			}
			peerset = append(peerset, p)
		}

		if len(peers) == 0 {
			peers = peerset
		} else {
			var update []peer.ID
			for _, p := range peers {
				if slices.Contains(peerset, p) {
					update = append(update, p)
				}
			}

			peers = update

			if len(update) == 0 {
				break peerloop
			}
		}
	}

	return peers
}

func (p *PubSub) handlePendingPeers() {
	p.newPeersPrioLk.Lock()

	if len(p.newPeersPend) == 0 {
		p.newPeersPrioLk.Unlock()
		return
	}

	newPeers := p.newPeersPend
	p.newPeersPend = make(map[peer.ID]struct{})
	p.newPeersPrioLk.Unlock()

	for pid := range newPeers {
		if p.host.Network().Connectedness(pid) != network.Connected {
			continue
		}

		p.peerMx.RLock()
		_, ok := p.peers[pid]
		p.peerMx.RUnlock()
		if ok {
			log.Debug("already have connection to peer: ", pid)
			continue
		}

		if p.blacklist.Contains(pid) {
			log.Warn("ignoring connection from blacklisted peer: ", pid)
			continue
		}

		q := newRPCQueue(p.peerOutboundQueueSize, p.peerOutboundQueueSize)
		if err := q.Push(p.ctx, p.getHelloPacket(), true); err != nil {
			log.Debug("error sending hello packet to new peer: ", err)
			_ = q.Close()
			continue
		}
		go p.handleNewPeer(p.ctx, pid, q)

		p.peerMx.Lock()
		p.peers[pid] = q
		p.peerMx.Unlock()
	}
}

func (p *PubSub) handleDeadPeers() {
	p.peerDeadPrioLk.Lock()

	if len(p.peerDeadPend) == 0 {
		p.peerDeadPrioLk.Unlock()
		return
	}

	deadPeers := p.peerDeadPend
	p.peerDeadPend = make(map[peer.ID]struct{})
	p.peerDeadPrioLk.Unlock()

	for pid := range deadPeers {
		p.peerMx.RLock()
		q, ok := p.peers[pid]
		p.peerMx.RUnlock()
		if !ok {
			continue
		}

		_ = q.Close()
		p.peerMx.Lock()
		delete(p.peers, pid)
		p.peerMx.Unlock()

		for t, tmap := range p.bitmasks {
			if _, ok := tmap[pid]; ok {
				delete(tmap, pid)
				p.notifyLeave([]byte(t), pid)
			}
		}

		p.rt.RemovePeer(pid)

		if p.host.Network().Connectedness(pid) == network.Connected {
			backoffDelay, err := p.deadPeerBackoff.updateAndGet(pid)
			if err != nil {
				log.Debug(err)
				continue
			}

			// still connected, must be a duplicate connection being closed.
			// we respawn the writer as we need to ensure there is a stream active
			log.Debugf("peer declared dead but still connected; respawning writer: %s", pid)
			q := newRPCQueue(p.peerOutboundQueueSize, p.peerOutboundQueueSize)
			if err := q.Push(p.ctx, p.getHelloPacket(), true); err != nil {
				log.Debug("error sending hello packet to new peer: ", err)
				_ = q.Close()
				continue
			}

			p.peerMx.Lock()
			p.peers[pid] = q
			p.peerMx.Unlock()
			go p.handleNewPeerWithBackoff(p.ctx, pid, backoffDelay, q)
		}
	}
}

// handleAddBitmask adds a tracker for a particular bitmask.
// Only called from processLoop.
func (p *PubSub) handleAddBitmask(req *addBitmaskReq) {
	bitmask := req.bitmask
	bitmaskID := bitmask.bitmask

	t, ok := p.myBitmasks[string(bitmaskID)]
	if ok {
		req.resp <- t
		return
	}

	p.myBitmasks[string(bitmaskID)] = bitmask
	req.resp <- bitmask
}

// handleRemoveBitmask removes Bitmask tracker from bookkeeping.
// Only called from processLoop.
func (p *PubSub) handleRemoveBitmask(req *rmBitmaskReq) {
	bitmask := p.myBitmasks[string(req.bitmask.bitmask)]

	if bitmask == nil {
		req.resp <- nil
		return
	}

	if len(bitmask.evtHandlers) == 0 &&
		len(p.mySubs[string(req.bitmask.bitmask)]) == 0 &&
		p.myRelays[string(req.bitmask.bitmask)] == 0 {
		delete(p.myBitmasks, string(bitmask.bitmask))
		req.resp <- nil
		return
	}

	req.resp <- fmt.Errorf("cannot close bitmask: outstanding event handlers or subscriptions")
}

// handleRemoveSubscription removes Subscription sub from bookeeping.
// If this was the last subscription and no more relays exist for a given bitmask,
// it will also announce that this node is not subscribing to this bitmask anymore.
// Only called from processLoop.
func (p *PubSub) handleRemoveSubscription(sub *Subscription) {
	subs := p.mySubs[string(sub.bitmask)]

	if subs == nil {
		return
	}

	sub.err = ErrSubscriptionCancelled
	sub.close()
	delete(subs, sub)

	if len(subs) == 0 {
		delete(p.mySubs, string(sub.bitmask))

		// stop announcing only if there are no more subs and relays
		if p.myRelays[string(sub.bitmask)] == 0 {
			p.disc.StopAdvertise(sub.bitmask)
			p.announce(sub.bitmask, false)
			p.rt.Leave(sub.bitmask)
		}
	}
}

// handleAddSubscription adds a Subscription for a particular bitmask. If it is
// the first subscription and no relays exist so far for the bitmask, it will
// announce that this node subscribes to the bitmask.
// Only called from processLoop.
func (p *PubSub) handleAddSubscription(req *addSubReq) {
	sub := req.sub
	subs := p.mySubs[string(sub.bitmask)]

	// announce we want this bitmask if neither subs nor relays exist so far
	if len(subs) == 0 && p.myRelays[string(sub.bitmask)] == 0 {
		p.disc.Advertise(sub.bitmask)
		p.announce(sub.bitmask, true)
		p.rt.Join(sub.bitmask)
	}

	// make new if not there
	if subs == nil {
		p.mySubs[string(sub.bitmask)] = make(map[*Subscription]struct{})
	}

	sub.cancelCh = p.cancelCh

	p.mySubs[string(sub.bitmask)][sub] = struct{}{}

	req.resp <- sub
}

// handleAddRelay adds a relay for a particular bitmask. If it is
// the first relay and no subscriptions exist so far for the bitmask , it will
// announce that this node relays for the bitmask.
// Only called from processLoop.
func (p *PubSub) handleAddRelay(req *addRelayReq) {
	bitmask := req.bitmask

	p.myRelays[string(bitmask)]++

	// announce we want this bitmask if neither relays nor subs exist so far
	if p.myRelays[string(bitmask)] == 1 && len(p.mySubs[string(bitmask)]) == 0 {
		p.disc.Advertise(bitmask)
		p.announce(bitmask, true)
		p.rt.Join(bitmask)
	}

	// flag used to prevent calling cancel function multiple times
	isCancelled := false

	relayCancelFunc := func() {
		if isCancelled {
			return
		}

		select {
		case p.rmRelay <- string(bitmask):
			isCancelled = true
		case <-p.ctx.Done():
		}
	}

	req.resp <- relayCancelFunc
}

// handleRemoveRelay removes one relay reference from bookkeeping.
// If this was the last relay reference and no more subscriptions exist
// for a given bitmask, it will also announce that this node is not relaying
// for this bitmask anymore.
// Only called from processLoop.
func (p *PubSub) handleRemoveRelay(bitmask []byte) {
	if p.myRelays[string(bitmask)] == 0 {
		return
	}

	p.myRelays[string(bitmask)]--

	if p.myRelays[string(bitmask)] == 0 {
		delete(p.myRelays, string(bitmask))

		// stop announcing only if there are no more relays and subs
		if len(p.mySubs[string(bitmask)]) == 0 {
			p.disc.StopAdvertise(bitmask)
			p.announce(bitmask, false)
			p.rt.Leave(bitmask)
		}
	}
}

// announce announces whether or not this node is interested in a given bitmask
// Only called from processLoop.
func (p *PubSub) announce(bitmask []byte, sub bool) {
	subopt := &pb.RPC_SubOpts{
		Bitmask:   bitmask,
		Subscribe: sub,
	}

	out := rpcWithSubs(subopt)
	for pid, q := range p.peers {
		if err := q.TryPush(p.ctx, out, false); err != nil {
			log.Infof("Can't send announce message to peer %s: queue full; scheduling retry", pid)
			p.tracer.DropRPC(out, pid)
			go p.announceRetry(pid, bitmask, sub)
			continue
		}
		p.tracer.SendRPC(out, pid)
	}
}

func (p *PubSub) announceRetry(pid peer.ID, bitmask []byte, sub bool) {
	time.Sleep(time.Duration(1+rand.Intn(1000)) * time.Millisecond)

	retry := func() {
		_, okSubs := p.mySubs[string(bitmask)]
		_, okRelays := p.myRelays[string(bitmask)]

		ok := okSubs || okRelays

		if (ok && sub) || (!ok && !sub) {
			p.doAnnounceRetry(pid, bitmask, sub)
		}
	}

	select {
	case p.eval <- retry:
	case <-p.ctx.Done():
	}
}

func (p *PubSub) doAnnounceRetry(pid peer.ID, bitmask []byte, sub bool) {
	p.peerMx.RLock()
	q, ok := p.peers[pid]
	p.peerMx.RUnlock()
	if !ok {
		return
	}

	subopt := &pb.RPC_SubOpts{
		Bitmask:   bitmask,
		Subscribe: sub,
	}

	out := rpcWithSubs(subopt)
	if err := q.TryPush(p.ctx, out, false); err != nil {
		log.Infof("Can't send announce message to peer %s: queue full; scheduling retry", pid)
		p.tracer.DropRPC(out, pid)
		go p.announceRetry(pid, bitmask, sub)
		return
	}
	p.tracer.SendRPC(out, pid)
}

// notifySubs sends a given message to all corresponding subscribers.
// Only called from processLoop.
func (p *PubSub) notifySubs(msg *Message) {
	bitmask := msg.GetBitmask()
	slices := SliceBitmask(bitmask)
	// o := rand.Intn(len(slices))
	subs := p.mySubs[string(slices[0])]
	for f := range subs {
		select {
		case f.ch <- msg:
		default:
			p.tracer.UndeliverableMessage(msg)
			log.Infof("Can't deliver message to subscription for bitmask %x; subscriber too slow", bitmask)
		}
	}
}

// seenMessage returns whether we already saw this message before
func (p *PubSub) seenMessage(id []byte) bool {
	return p.seenMessages.Has(string(id))
}

// markSeen marks a message as seen such that seenMessage returns `true' for the given id
// returns true if the message was freshly marked
func (p *PubSub) markSeen(id []byte) bool {
	return p.seenMessages.Add(string(id))
}

// subscribedToMessage returns whether we are subscribed to one of the bitmasks
// of a given message
func (p *PubSub) subscribedToMsg(msg *pb.Message) bool {
	if len(p.mySubs) == 0 {
		return false
	}

	bitmask := msg.GetBitmask()
	slices := SliceBitmask(bitmask)
	for _, slice := range slices {
		_, ok := p.mySubs[string(slice)]
		if !ok {
			return false
		}
	}

	return true
}

// canRelayMsg returns whether we are able to relay for one of the bitmasks
// of a given message
func (p *PubSub) canRelayMsg(msg *pb.Message) bool {
	if len(p.myRelays) == 0 {
		return false
	}

	bitmask := msg.GetBitmask()
	slices := SliceBitmask(bitmask)
	for _, slice := range slices {
		relays := p.myRelays[string(slice)]
		if relays > 0 {
			return true
		}
	}

	return false
}

func (p *PubSub) notifyLeave(bitmask []byte, pid peer.ID) {
	if t, ok := p.myBitmasks[string(bitmask)]; ok {
		t.sendNotification(PeerEvent{PeerLeave, pid})
	}
}

func (p *PubSub) handleIncomingRPC(rpc *RPC) {
	// pass the rpc through app specific validation (if any available).
	if p.appSpecificRpcInspector != nil {
		// check if the RPC is allowed by the external inspector
		if err := p.appSpecificRpcInspector(rpc.from, rpc); err != nil {
			log.Debugf("application-specific inspection failed, rejecting incoming rpc: %s", err)
			return // reject the RPC
		}
	}

	p.tracer.RecvRPC(rpc)

	subs := rpc.GetSubscriptions()
	if len(subs) != 0 && p.subFilter != nil {
		var err error
		subs, err = p.subFilter.FilterIncomingSubscriptions(rpc.from, subs)
		if err != nil {
			log.Debugf("subscription filter error: %s; ignoring RPC\n", err)
			return
		}
	}

	for _, subopt := range subs {
		t := subopt.GetBitmask()
		if !p.peerFilter(rpc.from, subopt.Bitmask) {
			continue
		}

		if subopt.GetSubscribe() {
			tmap, ok := p.bitmasks[string(t)]
			if !ok {
				tmap = make(map[peer.ID]struct{})
				p.bitmasks[string(t)] = tmap
			}

			if _, ok = tmap[rpc.from]; !ok {
				tmap[rpc.from] = struct{}{}
				if bitmask, ok := p.myBitmasks[string(t)]; ok {
					peer := rpc.from
					bitmask.sendNotification(PeerEvent{PeerJoin, peer})
				}
			}
		} else {
			tmap, ok := p.bitmasks[string(t)]
			if !ok {
				continue
			}

			if _, ok := tmap[rpc.from]; ok {
				delete(tmap, rpc.from)
				p.notifyLeave(t, rpc.from)
			}
		}
	}

	// ask the router to vet the peer before commiting any processing resources
	switch p.rt.AcceptFrom(rpc.from) {
	case AcceptNone:
		log.Debugf("received RPC from router graylisted peer %s; dropping RPC", rpc.from)
		return

	case AcceptControl:
		if len(rpc.GetPublish()) > 0 {
			log.Debugf("peer %s was throttled by router; ignoring %d payload messages", rpc.from, len(rpc.GetPublish()))
		}
		p.tracer.ThrottlePeer(rpc.from)

	case AcceptAll:
		var toPush []*Message
		for _, pmsg := range rpc.GetPublish() {
			if !(p.subscribedToMsg(pmsg) || p.canRelayMsg(pmsg)) {
				log.Debug("received message in bitmask we didn't subscribe to; ignoring message")
				continue
			}

			msg := &Message{pmsg, []byte{}, rpc.from, nil, false}
			if p.shouldPush(msg) {
				toPush = append(toPush, msg)
			}
		}
		p.rt.PreValidation(toPush)
		for _, msg := range toPush {
			p.pushMsg(msg)
		}
	}

	p.rt.HandleRPC(rpc)
}

// DefaultMsgIdFn returns a unique ID of the passed Message
func DefaultMsgIdFn(pmsg *pb.Message) []byte {
	h := sha256.New()
	h.Write(pmsg.Data)
	return h.Sum([]byte{0x01})
}

// DefaultPeerFilter accepts all peers on all bitmasks
func DefaultPeerFilter(pid peer.ID, bitmask []byte) bool {
	return true
}

// shouldPush filters a message before validating and pushing it
// It returns true if the message can be further validated and pushed
func (p *PubSub) shouldPush(msg *Message) bool {
	src := msg.ReceivedFrom
	// reject messages from blacklisted peers
	if p.blacklist.Contains(src) {
		log.Debugf("dropping message from blacklisted peer %s", src)
		p.tracer.RejectMessage(msg, RejectBlacklstedPeer)
		return false
	}

	// even if they are forwarded by good peers
	if p.blacklist.Contains(msg.GetFrom()) {
		log.Debugf("dropping message from blacklisted source %s", src)
		p.tracer.RejectMessage(msg, RejectBlacklistedSource)
		return false
	}

	err := p.checkSigningPolicy(msg)
	if err != nil {
		log.Debugf("dropping message from %s: %s", src, err)
		return false
	}

	// reject messages claiming to be from ourselves but not locally published
	self := p.host.ID()
	if peer.ID(msg.GetFrom()) == self && src != self {
		log.Debugf("dropping message claiming to be from self but forwarded from %s", src)
		p.tracer.RejectMessage(msg, RejectSelfOrigin)
		return false
	}

	// have we already seen and validated this message?
	id := p.idGen.ID(msg)
	if p.seenMessage(id) {
		p.tracer.DuplicateMessage(msg)
		return false
	}

	return true
}

// pushMsg pushes a message performing validation as necessary
func (p *PubSub) pushMsg(msg *Message) {
	src := msg.ReceivedFrom
	id := p.idGen.ID(msg)

	if !p.val.Push(src, msg) {
		return
	}

	if p.markSeen(id) {
		p.publishMessage(msg)
	}
}

func (p *PubSub) checkSigningPolicy(msg *Message) error {
	// reject unsigned messages when strict before we even process the id
	if p.signPolicy.mustVerify() {
		if p.signPolicy.mustSign() {
			if msg.Signature == nil {
				p.tracer.RejectMessage(msg, RejectMissingSignature)
				return ValidationError{Reason: RejectMissingSignature}
			}
			// Actual signature verification happens in the validation pipeline,
			// after checking if the message was already seen or not,
			// to avoid unnecessary signature verification processing-cost.
		} else {
			if msg.Signature != nil {
				p.tracer.RejectMessage(msg, RejectUnexpectedSignature)
				return ValidationError{Reason: RejectUnexpectedSignature}
			}
			// If we are expecting signed messages, and not authoring messages,
			// then do no accept seq numbers, from data, or key data.
			// The default msgID function still relies on Seqno and From,
			// but is not used if we are not authoring messages ourselves.
			if p.signID == "" {
				if msg.Seqno != nil || msg.From != nil || msg.Key != nil {
					p.tracer.RejectMessage(msg, RejectUnexpectedAuthInfo)
					return ValidationError{Reason: RejectUnexpectedAuthInfo}
				}
			}
		}
	}

	return nil
}

func (p *PubSub) publishMessage(msg *Message) {
	p.tracer.DeliverMessage(msg)
	p.notifySubs(msg)
	if !msg.Local {
		p.rt.Publish(msg)
	}
}

type addBitmaskReq struct {
	bitmask *Bitmask
	resp    chan *Bitmask
}

type rmBitmaskReq struct {
	bitmask *Bitmask
	resp    chan error
}

type BitmaskOptions struct{}

type BitmaskOpt func(t *Bitmask) error

// WithBitmaskMessageIdFn sets custom MsgIdFunction for a Bitmask, enabling bitmasks to have own msg id generation rules.
func WithBitmaskMessageIdFn(msgId MsgIdFunction) BitmaskOpt {
	return func(t *Bitmask) error {
		t.p.idGen.Set(t.bitmask, msgId)
		return nil
	}
}

func (p *PubSub) PeerScore(pr peer.ID) float64 {
	return p.rt.PeerScore(pr)
}

// Join joins the bitmasks and returns a set of Bitmask handles. Only one Bitmask
// handle should exist per bit, and Join will error if all the Bitmask handles already exist.
func (p *PubSub) Join(bitmask []byte, opts ...BitmaskOpt) ([]*Bitmask, error) {
	ts, news, errs := p.tryJoin(bitmask, opts...)
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	if !slices.Contains(news, true) {
		return nil, fmt.Errorf("bitmask already exists")
	}

	return ts, nil
}

// tryJoin is an internal function that tries to join a bitmask
// Returns the bitmask if it can be created or found
// Returns true if the bitmask was newly created, false otherwise
// Can be removed once pubsub.Publish() and pubsub.Subscribe() are removed
func (p *PubSub) tryJoin(bitmask []byte, opts ...BitmaskOpt) ([]*Bitmask, []bool, []error) {
	if p.subFilter != nil && !p.subFilter.CanSubscribe(bitmask) {
		return nil, nil, []error{fmt.Errorf("bitmask is not allowed by the subscription filter")}
	}

	sliced := SliceBitmask(bitmask)
	var bitmasks []*Bitmask
	var newBitmasks []bool
	var errors []error

loop:
	for _, slice := range sliced {
		slice := slice

		t := &Bitmask{
			p:           p,
			bitmask:     slice,
			evtHandlers: make(map[*BitmaskEventHandler]struct{}),
		}

		for _, opt := range opts {
			err := opt(t)
			if err != nil {
				errors = append(errors, err)
				continue loop
			}
		}

		resp := make(chan *Bitmask, 1)
		select {
		case t.p.addBitmask <- &addBitmaskReq{
			bitmask: t,
			resp:    resp,
		}:
		case <-t.p.ctx.Done():
			errors = append(errors, t.p.ctx.Err())
			continue loop
		}
		returnedBitmask := <-resp

		if returnedBitmask != t {
			bitmasks = append(bitmasks, returnedBitmask)
			newBitmasks = append(newBitmasks, false)
		} else {
			bitmasks = append(bitmasks, t)
			newBitmasks = append(newBitmasks, true)
		}
	}

	return bitmasks, newBitmasks, errors
}

type addSubReq struct {
	sub  *Subscription
	resp chan *Subscription
}

type SubOpt func(sub *Subscription) error

// Subscribe returns a new Subscription for the given bitmask.
// Note that subscription is not an instantaneous operation. It may take some time
// before the subscription is processed by the pubsub main loop and propagated to our peers.
//
// Deprecated: use pubsub.Join() and bitmask.Subscribe() instead
func (p *PubSub) Subscribe(bitmask []byte, opts ...SubOpt) ([]*Subscription, error) {
	// ignore whether the bitmask was newly created or not, since either way we have a valid bitmask to work with
	bitmaskHandles, _, errs := p.tryJoin(bitmask)
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	var subs []*Subscription
	for _, handle := range bitmaskHandles {
		sub, err := handle.Subscribe(opts...)
		if err != nil {
			return nil, err
		}

		subs = append(subs, sub)
	}

	return subs, nil
}

// WithBufferSize is a Subscribe option to customize the size of the subscribe output buffer.
// The default length is 128 but it can be configured to avoid dropping messages if the consumer is not reading fast
// enough.
func WithBufferSize(size int) SubOpt {
	return func(sub *Subscription) error {
		sub.ch = make(chan *Message, size)
		return nil
	}
}

type bitmaskReq struct {
	resp chan []string
}

// GetBitmasks returns the bitmasks this node is subscribed to.
func (p *PubSub) GetBitmasks() []string {
	out := make(chan []string, 1)
	select {
	case p.getBitmasks <- &bitmaskReq{resp: out}:
	case <-p.ctx.Done():
		return nil
	}
	return <-out
}

func (p *PubSub) Publish(ctx context.Context, bitmask []byte, data []byte, opts ...PubOpt) error {
	slices := SliceBitmask(bitmask)
	o := rand.Intn(len(slices))
	b, _, errs := p.tryJoin(slices[o])
	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	return b[0].Publish(ctx, bitmask, data, opts...)
}

func (p *PubSub) nextSeqno() []byte {
	seqno := make([]byte, 8)
	counter := atomic.AddUint64(&p.counter, 1)
	binary.BigEndian.PutUint64(seqno, counter)
	return seqno
}

type listPeerReq struct {
	resp    chan []peer.ID
	bitmask []byte
}

// ListPeers returns a list of peers we are connected to in the given bitmask.
func (p *PubSub) ListPeers(bitmask []byte) []peer.ID {
	out := make(chan []peer.ID)
	select {
	case p.getPeers <- &listPeerReq{
		resp:    out,
		bitmask: bitmask,
	}:
	case <-p.ctx.Done():
		return nil
	}
	return <-out
}

// BlacklistPeer blacklists a peer; all messages from this peer will be unconditionally dropped.
func (p *PubSub) BlacklistPeer(pid peer.ID) {
	select {
	case p.blacklistPeer <- pid:
	case <-p.ctx.Done():
	}
}

// RegisterBitmaskValidator registers a validator for bitmask.
// By default validators are asynchronous, which means they will run in a separate goroutine.
// The number of active goroutines is controlled by global and per bitmask validator
// throttles; if it exceeds the throttle threshold, messages will be dropped.
func (p *PubSub) RegisterBitmaskValidator(bitmask []byte, val interface{}, opts ...ValidatorOpt) error {
	addVal := &addValReq{
		bitmask:  bitmask,
		validate: val,
		resp:     make(chan error, 1),
	}

	for _, opt := range opts {
		err := opt(addVal)
		if err != nil {
			return err
		}
	}

	select {
	case p.addVal <- addVal:
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
	return <-addVal.resp
}

// UnregisterBitmaskValidator removes a validator from a bitmask.
// Returns an error if there was no validator registered with the bitmask.
func (p *PubSub) UnregisterBitmaskValidator(bitmask []byte) error {
	rmVal := &rmValReq{
		bitmask: bitmask,
		resp:    make(chan error, 1),
	}

	select {
	case p.rmVal <- rmVal:
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
	return <-rmVal.resp
}

type RelayCancelFunc func()

type addRelayReq struct {
	bitmask []byte
	resp    chan RelayCancelFunc
}

func SliceBitmask(bitmask []byte) [][]byte {
	sliced := [][]byte{}
	if bytes.Equal(bitmask, make([]byte, len(bitmask))) {
		sliced = append(sliced, bitmask)
	} else {
		for i, b := range bitmask {
			if b == 0 {
				continue
			}

			// fast: one bit in byte
			if b&(b-1) == 0 {
				slice := make([]byte, len(bitmask))
				slice[i] = b
				sliced = append(sliced, slice)
				continue
			}

			for j := 7; j >= 0; j-- {
				if (b>>j)&1 == 1 {
					slice := make([]byte, len(bitmask))
					slice[i] = 1 << j
					sliced = append(sliced, slice)
				}
			}
		}
	}

	return sliced
}
