package internal

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"go.uber.org/zap"
)

type peerMonitor struct {
	h        host.Host
	timeout  time.Duration
	period   time.Duration
	attempts int
}

func (pm *peerMonitor) pingOnce(ctx context.Context, logger *zap.Logger, id peer.ID) bool {
	pingCtx, cancel := context.WithTimeout(ctx, pm.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-pingCtx.Done():
		logger.Debug("ping timeout")
		return false
	case res := <-ping.Ping(pingCtx, pm.h, id):
		if res.Error != nil {
			logger.Debug("ping error", zap.Error(res.Error))
			return false
		}
		logger.Debug("ping success", zap.Duration("rtt", res.RTT))
	}
	return true
}

func (pm *peerMonitor) ping(ctx context.Context, logger *zap.Logger, wg *sync.WaitGroup, id peer.ID) {
	defer wg.Done()
	var conns []network.Conn
	for i := 0; i < pm.attempts; i++ {
		// There are no fine grained semantics in libp2p that would allow us to 'ping via
		// a specific connection'. We can only ping a peer, which will attempt to open a stream via a connection.
		// As such, we save a snapshot of the connections that were potentially in use before
		// the ping, and close them if the ping fails. If new connections occur between the snapshot
		// and the ping, they will not be closed, and will be pinged in the next iteration.
		conns = pm.h.Network().ConnsToPeer(id)
		if pm.pingOnce(ctx, logger, id) {
			return
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (pm *peerMonitor) run(ctx context.Context, logger *zap.Logger) {
	// Do not allow the pings to dial new connections. Adding new peers is a separate
	// process and should not be done during the ping process.
	ctx = network.WithNoDial(ctx, "monitor peers")
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(pm.period):
			// This is once again a snapshot of the connected peers at the time of the ping. If new peers
			// are added between the snapshot and the ping, they will be pinged in the next iteration.
			peers := pm.h.Network().Peers()
			logger.Debug("pinging connected peers", zap.Int("peer_count", len(peers)))
			wg := &sync.WaitGroup{}
			for _, id := range peers {
				logger := logger.With(zap.String("peer_id", id.String()))
				wg.Add(1)
				go pm.ping(ctx, logger, wg, id)
			}
			wg.Wait()
			logger.Debug("pinged connected peers")
		}
	}
}

// MonitorPeers periodically looks up the peers connected to the host and pings them
// repeatedly to ensure they are still reachable. If the peer is not reachable after
// the attempts, the connections to the peer are closed.
func MonitorPeers(
	ctx context.Context, logger *zap.Logger, h host.Host, timeout, period time.Duration, attempts int,
) {
	pm := &peerMonitor{
		h:        h,
		timeout:  timeout,
		period:   period,
		attempts: attempts,
	}
	go pm.run(ctx, logger)
}
