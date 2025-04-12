package internal

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"go.uber.org/zap"
)

type peerMonitor struct {
	h        host.Host
	timeout  time.Duration
	period   time.Duration
	attempts int
}

func (pm *peerMonitor) pingOnce(ctx context.Context, logger *zap.Logger, conn network.Conn) bool {
	pingCtx, cancel := context.WithTimeout(ctx, pm.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
	case <-pingCtx.Done():
		logger.Debug("ping timeout")
		return false
	case res := <-ping.PingConn(pingCtx, pm.h.Peerstore(), conn):
		if res.Error != nil {
			logger.Debug("ping error", zap.Error(res.Error))
			return false
		}
		logger.Debug("ping success", zap.Duration("rtt", res.RTT))
	}
	return true
}

func (pm *peerMonitor) ping(ctx context.Context, logger *zap.Logger, wg *sync.WaitGroup, conn network.Conn) {
	defer wg.Done()
	for i := 0; i < pm.attempts; i++ {
		if pm.pingOnce(ctx, logger, conn) {
			return
		}
		if conn.IsClosed() {
			return
		}
	}
	_ = conn.Close()
}

func (pm *peerMonitor) run(ctx context.Context, logger *zap.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(pm.period):
			peers := pm.h.Network().Peers()
			logger.Debug("pinging connected peers", zap.Int("peer_count", len(peers)))
			wg := &sync.WaitGroup{}
			for _, id := range peers {
				slogger := logger.With(zap.String("peer_id", id.String()))
				for _, conn := range pm.h.Network().ConnsToPeer(id) {
					sslogger := slogger.With(zap.String("connection_id", conn.ID()))
					wg.Add(1)
					go pm.ping(ctx, sslogger, wg, conn)
				}
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
