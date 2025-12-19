package app

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/datarpc"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type DataWorkerNode struct {
	logger         *zap.Logger
	config         *config.Config
	dataProofStore store.DataProofStore
	clockStore     store.ClockStore
	coinStore      store.TokenStore
	keyManager     keys.KeyManager
	pebble         store.KVDB
	coreId         uint
	ipcServer      *datarpc.DataWorkerIPCServer
	frameProver    crypto.FrameProver
	globalTimeReel *consensustime.GlobalTimeReel
	parentProcess  int
	rpcMultiaddr   string
	quit           chan struct{}
	stopOnce       sync.Once
}

func newDataWorkerNode(
	logger *zap.Logger,
	config *config.Config,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.TokenStore,
	keyManager keys.KeyManager,
	pebble store.KVDB,
	frameProver crypto.FrameProver,
	ipcServer *datarpc.DataWorkerIPCServer,
	globalTimeReel *consensustime.GlobalTimeReel,
	coreId uint,
	parentProcess int,
	rpcMultiaddr string,
) (*DataWorkerNode, error) {
	logger = logger.With(zap.String("process", fmt.Sprintf("worker %d", coreId)))
	return &DataWorkerNode{
		logger:         logger,
		config:         config,
		dataProofStore: dataProofStore,
		clockStore:     clockStore,
		coinStore:      coinStore,
		keyManager:     keyManager,
		pebble:         pebble,
		coreId:         coreId,
		ipcServer:      ipcServer,
		frameProver:    frameProver,
		globalTimeReel: globalTimeReel,
		parentProcess:  parentProcess,
		rpcMultiaddr:   rpcMultiaddr,
		quit:           make(chan struct{}),
	}, nil
}

func (n *DataWorkerNode) Start(
	done chan os.Signal,
	quitCh chan struct{},
) error {
	n.logger.Info(
		"starting data worker node",
		zap.Uint("core_id", n.coreId),
		zap.String("rpc_multiaddr", n.rpcMultiaddr),
	)

	go func() {
		err := n.ipcServer.Start()
		if err != nil {
			n.logger.Error(
				"error while starting ipc server for core",
				zap.Uint64("core", uint64(n.coreId)),
				zap.Error(err),
			)
			n.Stop()
		} else {
			n.logger.Info(
				"IPC server started successfully",
				zap.Uint("core_id", n.coreId),
			)
		}
	}()

	// Start port health check in background
	n.logger.Info(
		"starting port health check monitor",
		zap.Uint("core_id", n.coreId),
	)
	go n.monitorPortHealth()

	n.logger.Info("data worker node started", zap.Uint("core_id", n.coreId))

	select {
	case <-n.quit:
	case <-done:
	}

	n.ipcServer.Stop()
	err := n.pebble.Close()
	if err != nil {
		n.logger.Error(
			"database shut down with errors",
			zap.Error(err),
			zap.Uint("core_id", n.coreId),
		)
	} else {
		n.logger.Info(
			"database stopped cleanly",
			zap.Uint("core_id", n.coreId),
		)
	}

	quitCh <- struct{}{}
	return nil
}

func (n *DataWorkerNode) Stop() {
	n.stopOnce.Do(func() {
		n.logger.Info("stopping data worker node")
		if n.quit != nil {
			close(n.quit)
		}
	})
}

// GetQuitChannel returns the quit channel for external signaling
func (n *DataWorkerNode) GetQuitChannel() chan struct{} {
	return n.quit
}

func (n *DataWorkerNode) GetLogger() *zap.Logger {
	return n.logger
}

func (n *DataWorkerNode) GetClockStore() store.ClockStore {
	return n.clockStore
}

func (n *DataWorkerNode) GetCoinStore() store.TokenStore {
	return n.coinStore
}

func (n *DataWorkerNode) GetDataProofStore() store.DataProofStore {
	return n.dataProofStore
}

func (n *DataWorkerNode) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *DataWorkerNode) GetGlobalTimeReel() *consensustime.GlobalTimeReel {
	return n.globalTimeReel
}

func (n *DataWorkerNode) GetCoreId() uint {
	return n.coreId
}

func (n *DataWorkerNode) GetFrameProver() crypto.FrameProver {
	return n.frameProver
}

func (n *DataWorkerNode) GetIPCServer() *datarpc.DataWorkerIPCServer {
	return n.ipcServer
}

// extractPortFromMultiaddr extracts the TCP port from a multiaddr string
func extractPortFromMultiaddr(multiaddrStr string) (string, error) {
	ma, err := multiaddr.NewMultiaddr(multiaddrStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse multiaddr")
	}

	port, err := ma.ValueForProtocol(multiaddr.P_TCP)
	if err != nil {
		// Try UDP as fallback
		port, err = ma.ValueForProtocol(multiaddr.P_UDP)
		if err != nil {
			return "", errors.Wrap(err, "failed to extract port from multiaddr")
		}
	}

	return port, nil
}

// isPortListening checks if a port is currently listening (in use)
func isPortListening(port string) bool {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		// Port is in use (listening) or in TIME_WAIT state
		return true
	}
	if err := ln.Close(); err != nil {
		// Log but don't fail - port was available
	}
	// Port is available (not listening)
	return false
}

// waitForPortAvailable waits for a port to become available, checking periodically
// Returns true if port becomes available, false if timeout is reached
func waitForPortAvailable(port string, timeout time.Duration, logger *zap.Logger) bool {
	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	logger.Info(
		"waiting for port to become available",
		zap.String("port", port),
		zap.Duration("timeout", timeout),
	)

	for time.Now().Before(deadline) {
		if !isPortListening(port) {
			logger.Info(
				"port is now available",
				zap.String("port", port),
			)
			return true
		}
		time.Sleep(checkInterval)
	}

	logger.Warn(
		"port did not become available within timeout",
		zap.String("port", port),
		zap.Duration("timeout", timeout),
	)
	return false
}

// WaitForWorkerPortsAvailable waits for both P2P and stream ports to become available
// This helps avoid race conditions when processes restart quickly
// Returns true if all ports are available, false otherwise
func WaitForWorkerPortsAvailable(
	logger *zap.Logger,
	config *config.Config,
	coreId uint,
	rpcMultiaddr string,
	timeout time.Duration,
) bool {
	var wg sync.WaitGroup
	streamPortAvailable := make(chan bool, 1)
	p2pPortAvailable := make(chan bool, 1)

	// Check stream port in parallel
	streamPort, err := extractPortFromMultiaddr(rpcMultiaddr)
	if err != nil {
		logger.Warn(
			"failed to extract stream port, skipping stream port availability check",
			zap.String("multiaddr", rpcMultiaddr),
			zap.Uint("core_id", coreId),
			zap.Error(err),
		)
		streamPortAvailable <- true // Skip check, assume available
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			available := waitForPortAvailable(streamPort, timeout, logger)
			streamPortAvailable <- available
		}()
	}

	// Check P2P port in parallel
	if config.Engine.DataWorkerBaseP2PPort > 0 {
		p2pPort := int(config.Engine.DataWorkerBaseP2PPort) + int(coreId) - 1
		p2pPortStr := fmt.Sprintf("%d", p2pPort)
		wg.Add(1)
		go func() {
			defer wg.Done()
			available := waitForPortAvailable(p2pPortStr, timeout, logger)
			p2pPortAvailable <- available
		}()
	} else {
		p2pPortAvailable <- true // Skip check, assume available
	}

	// Wait for both checks to complete
	wg.Wait()

	// Read results
	streamOk := <-streamPortAvailable
	p2pOk := <-p2pPortAvailable

	return streamOk && p2pOk
}

// monitorPortHealth checks if both the stream port and P2P listen port are listening after startup
// The stream port is calculated as: base_stream_port + core_index - 1
// The P2P listen port is calculated as: base_p2p_port + core_index - 1
// The stream port check waits for the IPC server to be ready before checking
func (n *DataWorkerNode) monitorPortHealth() {
	n.logger.Info(
		"checking port health",
		zap.Uint("core_id", n.coreId),
		zap.String("rpc_multiaddr", n.rpcMultiaddr),
	)

	var wg sync.WaitGroup
	streamResult := make(chan bool, 1)
	p2pResult := make(chan bool, 1)

	// Extract stream port from multiaddr
	streamPort, err := extractPortFromMultiaddr(n.rpcMultiaddr)
	if err != nil {
		n.logger.Error(
			"failed to extract stream port from multiaddr, skipping stream port health check",
			zap.String("multiaddr", n.rpcMultiaddr),
			zap.Uint("core_id", n.coreId),
			zap.Error(err),
		)
		streamResult <- false // Mark as failed since we couldn't check
	} else {
		// Wait for IPC server to be ready before checking stream port
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Wait for IPC server to start listening
			n.logger.Debug(
				"waiting for IPC server to be ready before checking stream port",
				zap.String("port", streamPort),
				zap.Uint("core_id", n.coreId),
			)
			<-n.ipcServer.Ready()
			n.logger.Debug(
				"IPC server is ready, checking stream port",
				zap.String("port", streamPort),
				zap.Uint("core_id", n.coreId),
			)
			isStreamListening := isPortListening(streamPort)
			n.logger.Debug(
				"stream port check completed",
				zap.String("port", streamPort),
				zap.Bool("is_listening", isStreamListening),
				zap.Uint("core_id", n.coreId),
			)

			if !isStreamListening {
				n.logger.Warn(
					"stream port is not yet listening, may not be ready yet",
					zap.String("port", streamPort),
					zap.Uint("core_id", n.coreId),
				)
				streamResult <- false
			} else {
				n.logger.Info(
					"stream port is listening successfully",
					zap.String("port", streamPort),
					zap.Uint("core_id", n.coreId),
				)
				streamResult <- true
			}
		}()
	}

	// Check P2P listen port in parallel
	// Calculate P2P port: base_p2p_port + core_index - 1
	if n.config.Engine.DataWorkerBaseP2PPort == 0 {
		n.logger.Warn(
			"DataWorkerBaseP2PPort is not set, skipping P2P port health check",
			zap.Uint("core_id", n.coreId),
		)
		p2pResult <- true // Skip check, assume OK
	} else {
		p2pPort := int(n.config.Engine.DataWorkerBaseP2PPort) + int(n.coreId) - 1
		p2pPortStr := fmt.Sprintf("%d", p2pPort)

		wg.Add(1)
		go func() {
			defer wg.Done()
			n.logger.Debug(
				"attempting to bind to P2P port to check if it's listening",
				zap.String("port", p2pPortStr),
				zap.Uint("core_id", n.coreId),
			)
			isP2PListening := isPortListening(p2pPortStr)
			n.logger.Debug(
				"P2P port check completed",
				zap.String("port", p2pPortStr),
				zap.Bool("is_listening", isP2PListening),
				zap.Uint("core_id", n.coreId),
			)

			if !isP2PListening {
				n.logger.Error(
					"P2P listen port is not yet listening, may not be ready yet",
					zap.String("port", p2pPortStr),
					zap.Uint("core_id", n.coreId),
				)
				p2pResult <- false
			} else {
				n.logger.Info(
					"P2P listen port is listening successfully",
					zap.String("port", p2pPortStr),
					zap.Uint("core_id", n.coreId),
				)
				p2pResult <- true
			}
		}()
	}

	// Wait for both checks to complete
	wg.Wait()

	// Read results
	streamOk := <-streamResult
	p2pOk := <-p2pResult

	// Ports are listening successfully, reset attempt counter
	if streamOk && p2pOk {
		n.logger.Info(
			"all ports are listening successfully",
			zap.Uint("core_id", n.coreId),
		)
	}
	n.logger.Info(
		"port health check completed",
		zap.Uint("core_id", n.coreId),
	)
}
