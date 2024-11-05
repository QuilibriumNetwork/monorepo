package internal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"go.uber.org/zap"
)

// PeerConnector is a connector to peers.
type PeerConnector interface {
	// Connect connects to peers.
	Connect(context.Context) error
}

type peerConnector struct {
	ctx         context.Context
	logger      *zap.Logger
	host        host.Host
	idService   identify.IDService
	connectCh   chan (chan<- struct{})
	minPeers    int
	parallelism int
	source      PeerSource
}

// Connect implements PeerConnector.
func (pc *peerConnector) Connect(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-pc.ctx.Done():
		return pc.ctx.Err()
	case pc.connectCh <- done:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-pc.ctx.Done():
		return pc.ctx.Err()
	case <-done:
		return nil
	}
}

func (pc *peerConnector) connectToPeer(
	ctx context.Context,
	logger *zap.Logger,
	p peer.AddrInfo,
	wg *sync.WaitGroup,
	duplicate, success, failure *uint32,
	inflight <-chan struct{},
) {
	defer func() {
		select {
		case <-ctx.Done():
		case <-inflight:
		}
	}()
	defer wg.Done()

	if p.ID == pc.host.ID() ||
		pc.host.Network().Connectedness(p.ID) == network.Connected ||
		pc.host.Network().Connectedness(p.ID) == network.Limited {
		logger.Debug("peer already connected")
		atomic.AddUint32(duplicate, 1)
		return
	}

	pc.host.Peerstore().AddAddrs(p.ID, p.Addrs, peerstore.AddressTTL)

	conn, err := pc.host.Network().DialPeer(ctx, p.ID)
	if err != nil {
		logger.Debug("error while connecting to dht peer", zap.Error(err))
		atomic.AddUint32(failure, 1)
		return
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(identify.Timeout / 2):
		logger.Debug("identifying peer timed out")
		atomic.AddUint32(failure, 1)
		_ = conn.Close()
	case <-pc.idService.IdentifyWait(conn):
		logger.Debug("connected to peer")
		atomic.AddUint32(success, 1)
	}
}

func (pc *peerConnector) connectToPeers(
	ctx context.Context,
	ch <-chan peer.AddrInfo,
	duplicate, success, failure *uint32,
) {
	var inflight chan struct{} = make(chan struct{}, pc.parallelism)
	var wg sync.WaitGroup
	defer wg.Wait()
	for p := range ch {
		logger := pc.logger.With(zap.String("peer_id", p.ID.String()))
		logger.Debug("received peer")

		if atomic.LoadUint32(success) >= uint32(pc.minPeers) {
			logger.Debug("reached max findings")
			return
		}

		select {
		case <-ctx.Done():
			return
		case inflight <- struct{}{}:
		}
		wg.Add(1)
		go pc.connectToPeer(
			ctx,
			logger,
			p,
			&wg,
			duplicate,
			success,
			failure,
			inflight,
		)
	}
}

func (pc *peerConnector) connect() {
	logger := pc.logger

	logger.Info("initiating peer connections")
	var success, failure, duplicate uint32
	defer func() {
		logger.Info(
			"completed peer connections",
			zap.Uint32("success", success),
			zap.Uint32("failure", failure),
			zap.Uint32("duplicate", duplicate),
		)
	}()
	ctx, cancel := context.WithCancel(pc.ctx)
	defer cancel()

	peerChan, err := pc.source.Peers(ctx)
	if err != nil {
		logger.Error("could not find peers", zap.Error(err))
		return
	}

	pc.connectToPeers(
		ctx,
		peerChan,
		&duplicate,
		&success,
		&failure,
	)
}

func (pc *peerConnector) run() {
	for {
		select {
		case <-pc.ctx.Done():
			return
		case done := <-pc.connectCh:
			pc.connect()
			close(done)
		}
	}
}

// NewPeerConnector creates a new peer connector.
func NewPeerConnector(
	ctx context.Context,
	logger *zap.Logger,
	host host.Host,
	idService identify.IDService,
	minPeers, parallelism int,
	source PeerSource,
) PeerConnector {
	pc := &peerConnector{
		ctx:         ctx,
		logger:      logger,
		host:        host,
		idService:   idService,
		connectCh:   make(chan (chan<- struct{})),
		minPeers:    minPeers,
		parallelism: parallelism,
		source:      source,
	}
	go pc.run()
	return pc
}

type chainedPeerConnector struct {
	ctx        context.Context
	connectors []PeerConnector
	connectCh  chan (chan<- struct{})
}

// Connect implements PeerConnector.
func (cpc *chainedPeerConnector) Connect(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cpc.ctx.Done():
		return cpc.ctx.Err()
	case cpc.connectCh <- done:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cpc.ctx.Done():
		return cpc.ctx.Err()
	case <-done:
		return nil
	}
}

func (cpc *chainedPeerConnector) run() {
	for {
		select {
		case <-cpc.ctx.Done():
			return
		case done := <-cpc.connectCh:
			for _, pc := range cpc.connectors {
				_ = pc.Connect(cpc.ctx)
			}
			close(done)
		}
	}
}

// NewChainedPeerConnector creates a new chained peer connector.
func NewChainedPeerConnector(ctx context.Context, connectors ...PeerConnector) PeerConnector {
	cpc := &chainedPeerConnector{
		ctx:        ctx,
		connectors: connectors,
		connectCh:  make(chan (chan<- struct{})),
	}
	go cpc.run()
	return cpc
}

type conditionalPeerConnector struct {
	ctx       context.Context
	condition PeerConnectorCondition
	connector PeerConnector
	connectCh chan (chan<- struct{})
}

func (cpc *conditionalPeerConnector) run() {
	for {
		select {
		case <-cpc.ctx.Done():
			return
		case done := <-cpc.connectCh:
			if cpc.condition.Should() {
				_ = cpc.connector.Connect(cpc.ctx)
			}
			close(done)
		}
	}
}

// Connect implements PeerConnector.
func (cpc *conditionalPeerConnector) Connect(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cpc.ctx.Done():
		return cpc.ctx.Err()
	case cpc.connectCh <- done:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cpc.ctx.Done():
		return cpc.ctx.Err()
	case <-done:
		return nil
	}
}

// NewConditionalPeerConnector creates a new conditional peer connector.
func NewConditionalPeerConnector(
	ctx context.Context,
	condition PeerConnectorCondition,
	connector PeerConnector,
) PeerConnector {
	cpc := &conditionalPeerConnector{
		ctx:       ctx,
		condition: condition,
		connector: connector,
		connectCh: make(chan (chan<- struct{})),
	}
	go cpc.run()
	return cpc
}
