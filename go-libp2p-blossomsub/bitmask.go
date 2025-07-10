package blossomsub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"

	"github.com/libp2p/go-libp2p/core/peer"
)

// DefaultSubscriptionQueueSize is the default size of the subscription queue.
const DefaultSubscriptionQueueSize = 16384

// ErrBitmaskClosed is returned if a Bitmask is utilized after it has been closed
var ErrBitmaskClosed = errors.New("this bitmask is closed, try opening a new one")

// ErrNilSignKey is returned if a nil private key was provided
var ErrNilSignKey = errors.New("nil sign key")

// ErrEmptyPeerID is returned if an empty peer ID was provided
var ErrEmptyPeerID = errors.New("empty peer ID")

// Bitmask is the handle for a pubsub bitmask
type Bitmask struct {
	p       *PubSub
	bitmask []byte

	evtHandlerMux sync.RWMutex
	evtHandlers   map[*BitmaskEventHandler]struct{}

	mux    sync.RWMutex
	closed bool
}

// String returns the bitmask associated with t
func (t *Bitmask) Bitmask() []byte {
	return t.bitmask
}

// SetScoreParams sets the bitmask score parameters if the pubsub router supports peer
// scoring
func (t *Bitmask) SetScoreParams(p *BitmaskScoreParams) error {
	err := p.validate()
	if err != nil {
		return fmt.Errorf("invalid bitmask score parameters: %w", err)
	}

	t.mux.Lock()

	if t.closed {
		t.mux.Unlock()
		return ErrBitmaskClosed
	}

	result := make(chan error, 1)
	update := func() {
		bs, ok := t.p.rt.(*BlossomSubRouter)
		if !ok {
			result <- fmt.Errorf("pubsub router is not BlossomSub")
			return
		}

		if bs.score == nil {
			result <- fmt.Errorf("peer scoring is not enabled in router")
			return
		}

		err := bs.score.SetBitmaskScoreParams(t.bitmask, p)
		result <- err
	}

	select {
	case t.p.eval <- update:
		err = <-result
		t.mux.Unlock()
		return err

	case <-t.p.ctx.Done():
		t.mux.Unlock()
		return t.p.ctx.Err()
	}
}

// EventHandler creates a handle for bitmask specific events
// Multiple event handlers may be created and will operate independently of each other
func (t *Bitmask) EventHandler(opts ...BitmaskEventHandlerOpt) (*BitmaskEventHandler, error) {
	t.mux.RLock()
	if t.closed {
		t.mux.RUnlock()
		return nil, ErrBitmaskClosed
	}

	h := &BitmaskEventHandler{
		bitmask: t,
		err:     nil,

		evtLog:   make(map[peer.ID]EventType),
		evtLogCh: make(chan struct{}, 1),
	}

	for _, opt := range opts {
		err := opt(h)
		if err != nil {
			t.mux.RUnlock()
			return nil, err
		}
	}

	done := make(chan struct{}, 1)

	select {
	case t.p.eval <- func() {
		tmap := t.p.bitmasks[string(t.bitmask)]
		for p := range tmap {
			h.evtLog[p] = PeerJoin
		}

		t.evtHandlerMux.Lock()
		t.evtHandlers[h] = struct{}{}
		t.evtHandlerMux.Unlock()
		done <- struct{}{}
	}:
	case <-t.p.ctx.Done():
		t.mux.RUnlock()
		return nil, t.p.ctx.Err()
	}

	<-done
	t.mux.RUnlock()
	return h, nil
}

func (t *Bitmask) sendNotification(evt PeerEvent) {
	t.evtHandlerMux.RLock()

	for h := range t.evtHandlers {
		h.sendNotification(evt)
	}

	t.evtHandlerMux.RUnlock()
}

// Subscribe returns a new Subscription for the bitmask.
// Note that subscription is not an instantaneous operation. It may take some time
// before the subscription is processed by the pubsub main loop and propagated to our peers.
func (t *Bitmask) Subscribe(opts ...SubOpt) (*Subscription, error) {
	t.mux.RLock()

	if t.closed {
		t.mux.RUnlock()
		return nil, ErrBitmaskClosed
	}

	sub := &Subscription{
		bitmask: t.bitmask,
		ctx:     t.p.ctx,
	}

	for _, opt := range opts {
		err := opt(sub)
		if err != nil {
			t.mux.RUnlock()
			return nil, err
		}
	}

	if sub.ch == nil {
		sub.ch = make(chan *Message, DefaultSubscriptionQueueSize)
	}

	out := make(chan *Subscription, 1)

	t.p.disc.Discover(sub.bitmask)

	select {
	case t.p.addSub <- &addSubReq{
		sub:  sub,
		resp: out,
	}:
	case <-t.p.ctx.Done():
		t.mux.RUnlock()
		return nil, t.p.ctx.Err()
	}

	subOut := <-out
	t.mux.RUnlock()
	return subOut, nil
}

// Relay enables message relaying for the bitmask and returns a reference
// cancel function. Subsequent calls increase the reference counter.
// To completely disable the relay, all references must be cancelled.
func (t *Bitmask) Relay() (RelayCancelFunc, error) {
	t.mux.RLock()

	if t.closed {
		t.mux.RUnlock()
		return nil, ErrBitmaskClosed
	}

	out := make(chan RelayCancelFunc, 1)

	t.p.disc.Discover(t.bitmask)

	select {
	case t.p.addRelay <- &addRelayReq{
		bitmask: t.bitmask,
		resp:    out,
	}:
	case <-t.p.ctx.Done():
		t.mux.RUnlock()
		return nil, t.p.ctx.Err()
	}

	cancelFunc := <-out
	t.mux.RUnlock()
	return cancelFunc, nil
}

// RouterReady is a function that decides if a router is ready to publish
type RouterReady func(rt PubSubRouter, bitmask []byte) (bool, error)

// ProvideKey is a function that provides a private key and its associated peer ID when publishing a new message
type ProvideKey func() (crypto.PrivKey, peer.ID)

type PublishOptions struct {
	ready     RouterReady
	customKey ProvideKey
	local     bool
}

type PubOpt func(pub *PublishOptions) error

// Publish publishes data to bitmask.
func (t *Bitmask) Publish(ctx context.Context, bitmask []byte, data []byte, opts ...PubOpt) error {
	t.mux.RLock()

	if t.closed {
		t.mux.RUnlock()
		return ErrBitmaskClosed
	}

	pid := t.p.signID
	key := t.p.signKey

	pub := &PublishOptions{}
	for _, opt := range opts {
		err := opt(pub)
		if err != nil {
			t.mux.RUnlock()
			return err
		}
	}

	if pub.customKey != nil && !pub.local {
		key, pid = pub.customKey()
		if key == nil {
			t.mux.RUnlock()
			return ErrNilSignKey
		}
		if len(pid) == 0 {
			t.mux.RUnlock()
			return ErrEmptyPeerID
		}
	}

	m := &pb.Message{
		Data:    data,
		Bitmask: bitmask,
		From:    nil,
		Seqno:   nil,
	}
	if pid != "" {
		m.From = []byte(pid)
		m.Seqno = t.p.nextSeqno()
	}
	if key != nil {
		m.From = []byte(pid)
		err := signMessage(pid, key, m)
		if err != nil {
			t.mux.RUnlock()
			return err
		}
	}

	if pub.ready != nil {
		if t.p.disc.discovery != nil {
			t.p.disc.Bootstrap(ctx, t.bitmask, pub.ready)
		} else {
			// TODO: we could likely do better than polling every 200ms.
			// For example, block this goroutine on a channel,
			// and check again whenever events tell us that the number of
			// peers has increased.
			var ticker *time.Ticker
		readyLoop:
			for {
				// Check if ready for publishing.
				// Similar to what disc.Bootstrap does.
				res := make(chan bool, 1)
				select {
				case t.p.eval <- func() {
					done, _ := pub.ready(t.p.rt, t.bitmask)
					res <- done
				}:
					if <-res {
						if ticker != nil {
							ticker.Stop()
						}
						break readyLoop
					}
				case <-t.p.ctx.Done():
					if ticker != nil {
						ticker.Stop()
					}
					t.mux.RUnlock()
					return t.p.ctx.Err()
				case <-ctx.Done():
					if ticker != nil {
						ticker.Stop()
					}
					t.mux.RUnlock()
					return ctx.Err()
				}
				if ticker == nil {
					ticker = time.NewTicker(200 * time.Millisecond)
				}

				select {
				case <-ticker.C:
				case <-ctx.Done():
					ticker.Stop()
					t.mux.RUnlock()
					return fmt.Errorf("router is not ready: %w", ctx.Err())
				}
			}
		}
	}

	err := t.p.val.PushLocal(&Message{m, nil, t.p.host.ID(), nil, pub.local})

	t.mux.RUnlock()
	return err
}

// WithReadiness returns a publishing option for only publishing when the router is ready.
// This option is not useful unless PubSub is also using WithDiscovery
func WithReadiness(ready RouterReady) PubOpt {
	return func(pub *PublishOptions) error {
		pub.ready = ready
		return nil
	}
}

// WithLocalPublication returns a publishing option to notify in-process subscribers only.
// It prevents message publication to mesh peers.
// Useful in edge cases where the msg needs to be only delivered to the in-process subscribers,
// e.g. not to spam the network with outdated msgs.
// Should not be used specifically for in-process pubsubing.
func WithLocalPublication(local bool) PubOpt {
	return func(pub *PublishOptions) error {
		pub.local = local
		return nil
	}
}

// WithSecretKeyAndPeerId returns a publishing option for providing a custom private key and its corresponding peer ID
// This option is useful when we want to send messages from "virtual", never-connectable peers in the network
func WithSecretKeyAndPeerId(key crypto.PrivKey, pid peer.ID) PubOpt {
	return func(pub *PublishOptions) error {
		pub.customKey = func() (crypto.PrivKey, peer.ID) {
			return key, pid
		}

		return nil
	}
}

// Close closes down the bitmask. Will return an error unless there are no active event handlers or subscriptions.
// Does not error if the bitmask is already closed.
func (t *Bitmask) Close() error {
	t.mux.Lock()

	if t.closed {
		t.mux.Unlock()
		return nil
	}

	req := &rmBitmaskReq{t, make(chan error, 1)}

	select {
	case t.p.rmBitmask <- req:
	case <-t.p.ctx.Done():
		t.mux.Unlock()
		return t.p.ctx.Err()
	}

	err := <-req.resp

	if err == nil {
		t.closed = true
	}

	t.mux.Unlock()
	return err
}

// ListPeers returns a list of peers we are connected to in the given bitmask.
func (t *Bitmask) ListPeers() []peer.ID {
	t.mux.RLock()

	if t.closed {
		t.mux.RUnlock()
		return []peer.ID{}
	}

	l := t.p.ListPeers(t.bitmask)
	t.mux.RUnlock()
	return l
}

type EventType int

const (
	PeerJoin EventType = iota
	PeerLeave
)

// BitmaskEventHandler is used to manage bitmask specific events. No Subscription is required to receive events.
type BitmaskEventHandler struct {
	bitmask *Bitmask
	err     error

	evtLogMx sync.Mutex
	evtLog   map[peer.ID]EventType
	evtLogCh chan struct{}
}

type BitmaskEventHandlerOpt func(t *BitmaskEventHandler) error

type PeerEvent struct {
	Type EventType
	Peer peer.ID
}

// Cancel closes the bitmask event handler
func (t *BitmaskEventHandler) Cancel() {
	bitmask := t.bitmask
	t.err = fmt.Errorf("bitmask event handler cancelled by calling handler.Cancel()")

	bitmask.evtHandlerMux.Lock()
	delete(bitmask.evtHandlers, t)
	t.bitmask.evtHandlerMux.Unlock()
}

func (t *BitmaskEventHandler) sendNotification(evt PeerEvent) {
	t.evtLogMx.Lock()
	t.addToEventLog(evt)
	t.evtLogMx.Unlock()
}

// addToEventLog assumes a lock has been taken to protect the event log
func (t *BitmaskEventHandler) addToEventLog(evt PeerEvent) {
	e, ok := t.evtLog[evt.Peer]
	if !ok {
		t.evtLog[evt.Peer] = evt.Type
		// send signal that an event has been added to the event log
		select {
		case t.evtLogCh <- struct{}{}:
		default:
		}
	} else if e != evt.Type {
		delete(t.evtLog, evt.Peer)
	}
}

// pullFromEventLog assumes a lock has been taken to protect the event log
func (t *BitmaskEventHandler) pullFromEventLog() (PeerEvent, bool) {
	for k, v := range t.evtLog {
		evt := PeerEvent{Peer: k, Type: v}
		delete(t.evtLog, k)
		return evt, true
	}
	return PeerEvent{}, false
}

// NextPeerEvent returns the next event regarding subscribed peers
// Guarantees: Peer Join and Peer Leave events for a given peer will fire in order.
// Unless a peer both Joins and Leaves before NextPeerEvent emits either event
// all events will eventually be received from NextPeerEvent.
func (t *BitmaskEventHandler) NextPeerEvent(ctx context.Context) (PeerEvent, error) {
	for {
		t.evtLogMx.Lock()
		evt, ok := t.pullFromEventLog()
		if ok {
			// make sure an event log signal is available if there are events in the event log
			if len(t.evtLog) > 0 {
				select {
				case t.evtLogCh <- struct{}{}:
				default:
				}
			}
			t.evtLogMx.Unlock()
			return evt, nil
		}
		t.evtLogMx.Unlock()

		select {
		case <-t.evtLogCh:
			continue
		case <-ctx.Done():
			return PeerEvent{}, ctx.Err()
		}
	}
}
