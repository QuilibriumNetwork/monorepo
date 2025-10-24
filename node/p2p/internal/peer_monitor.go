package internal

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"go.uber.org/zap"
)

type peerMonitor struct {
	ps           *ping.PingService
	h            host.Host
	timeout      time.Duration
	period       time.Duration
	attempts     int
	direct       []peer.AddrInfo
	directPeriod time.Duration
}

func (pm *peerMonitor) pingOnce(
	ctx context.Context,
	logger *zap.Logger,
	peer peer.ID,
) bool {
	pingCtx, cancel := context.WithTimeout(ctx, pm.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-pingCtx.Done():
		return false
	case res := <-pm.ps.Ping(pingCtx, peer):
		if res.Error != nil {
			logger.Debug("ping error", zap.Error(res.Error))
			return false
		}
	}
	return true
}

func (pm *peerMonitor) ping(
	ctx context.Context,
	logger *zap.Logger,
	wg *sync.WaitGroup,
	peer peer.ID,
) {
	defer wg.Done()
	for i := 0; i < pm.attempts; i++ {
		pm.pingOnce(ctx, logger, peer)
	}
}

func (pm *peerMonitor) run(ctx context.Context, logger *zap.Logger) {
	var (
		pingTicker    = time.NewTicker(pm.period)
		directTicker  *time.Ticker
		directChannel <-chan time.Time
	)
	defer pingTicker.Stop()

	if len(pm.direct) > 0 && pm.directPeriod > 0 {
		directTicker = time.NewTicker(pm.directPeriod)
		directChannel = directTicker.C
		defer directTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			pm.pingConnectedPeers(ctx, logger)
		case <-directChannel:
			pm.ensureDirectPeers(ctx, logger)
		}
	}
}

func (pm *peerMonitor) pingConnectedPeers(
	ctx context.Context,
	logger *zap.Logger,
) {
	peers := pm.h.Network().Peers()
	wg := &sync.WaitGroup{}
	for _, id := range peers {
		slogger := logger.With(zap.String("peer_id", id.String()))
		wg.Add(1)
		go pm.ping(ctx, slogger, wg, id)
	}
	wg.Wait()
}

func (pm *peerMonitor) ensureDirectPeers(
	ctx context.Context,
	logger *zap.Logger,
) {
	for _, info := range pm.direct {
		if info.ID == pm.h.ID() {
			continue
		}

		slogger := logger.With(zap.String("peer_id", info.ID.String()))
		pm.h.Peerstore().AddAddrs(
			info.ID,
			info.Addrs,
			peerstore.PermanentAddrTTL,
		)

		if pm.h.Network().Connectedness(info.ID) == network.Connected {
			continue
		}

		connectCtx, cancel := context.WithTimeout(ctx, pm.timeout)
		err := pm.h.Connect(connectCtx, info)
		cancel()
		if err != nil {
			slogger.Debug("failed to connect to direct peer", zap.Error(err))
			continue
		}
		slogger.Info("connected to direct peer")
	}
}

// MonitorPeers periodically looks up the peers connected to the host and pings
// them repeatedly to ensure they are still reachable. If the peer is not
// reachable after the attempts, the connections to the peer are closed.
func MonitorPeers(
	ctx context.Context,
	logger *zap.Logger,
	h host.Host,
	timeout, period time.Duration,
	attempts int,
	directPeers []peer.AddrInfo,
) {
	ps := ping.NewPingService(h)
	pm := &peerMonitor{
		ps:           ps,
		h:            h,
		timeout:      timeout,
		period:       period,
		attempts:     attempts,
		direct:       directPeers,
		directPeriod: 10 * time.Second,
	}

	go pm.run(ctx, logger)
}
