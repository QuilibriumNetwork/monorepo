package datarpc

import (
	"context"
	"encoding/hex"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/app"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

type DataWorkerIPCServer struct {
	protobufs.UnimplementedDataIPCServiceServer

	ctx                       lifecycle.SignalerContext
	cancel                    func()
	listenAddrGRPC            string
	config                    *config.Config
	logger                    *zap.Logger
	coreId                    uint32
	parentProcessId           int
	signer                    crypto.Signer
	signerRegistry            consensus.SignerRegistry
	proverRegistry            consensus.ProverRegistry
	peerInfoManager           tp2p.PeerInfoManager
	pubsub                    tp2p.PubSub
	authProvider              channel.AuthenticationProvider
	appConsensusEngineFactory *app.AppConsensusEngineFactory
	appConsensusEngine        *app.AppConsensusEngine
	server                    *grpc.Server
	frameProver               crypto.FrameProver
	quit                      chan struct{}
	peerInfoCtx               lifecycle.SignalerContext
	peerInfoCancel            context.CancelFunc
}

func NewDataWorkerIPCServer(
	listenAddrGRPC string,
	config *config.Config,
	signerRegistry consensus.SignerRegistry,
	proverRegistry consensus.ProverRegistry,
	peerInfoManager tp2p.PeerInfoManager,
	pubsub tp2p.PubSub,
	frameProver crypto.FrameProver,
	appConsensusEngineFactory *app.AppConsensusEngineFactory,
	logger *zap.Logger,
	coreId uint32,
	parentProcessId int,
) (*DataWorkerIPCServer, error) {
	peerPrivKey, err := hex.DecodeString(config.P2P.PeerPrivKey)
	if err != nil {
		logger.Panic("error decoding peerkey", zap.Error(err))
	}

	privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	rawPriv, err := privKey.Raw()
	if err != nil {
		logger.Panic("error getting private key", zap.Error(err))
	}

	rawPub, err := privKey.GetPublic().Raw()
	if err != nil {
		logger.Panic("error getting public key", zap.Error(err))
	}

	signer, err := keys.Ed448KeyFromBytes(rawPriv, rawPub)
	if err != nil {
		logger.Panic("error creating signer", zap.Error(err))
	}

	return &DataWorkerIPCServer{
		listenAddrGRPC:            listenAddrGRPC,
		config:                    config,
		logger:                    logger,
		coreId:                    coreId,
		parentProcessId:           parentProcessId,
		pubsub:                    pubsub,
		signer:                    signer,
		appConsensusEngineFactory: appConsensusEngineFactory,
		signerRegistry:            signerRegistry,
		proverRegistry:            proverRegistry,
		frameProver:               frameProver,
		peerInfoManager:           peerInfoManager,
		quit:                      make(chan struct{}),
	}, nil
}

func (r *DataWorkerIPCServer) Start() error {
	peerInfoCtx, peerInfoCancel, _ := lifecycle.WithSignallerAndCancel(
		context.Background(),
	)
	peerInfoReady := make(chan struct{})
	go r.peerInfoManager.Start(
		peerInfoCtx,
		func() {
			close(peerInfoReady)
		},
	)
	select {
	case <-peerInfoReady:
	case <-time.After(5 * time.Second):
		r.logger.Warn("peer info manager did not start before timeout")
	}
	r.peerInfoCtx = peerInfoCtx
	r.peerInfoCancel = peerInfoCancel

	r.RespawnServer(nil)

	<-r.quit
	return nil
}

func (r *DataWorkerIPCServer) Stop() error {
	r.logger.Info("stopping server gracefully")

	// Stop the app consensus engine first, then synchronously close the
	// snapshot manager so no Pebble snapshots remain when the database closes.
	if r.appConsensusEngine != nil {
		if r.cancel != nil {
			r.cancel()
		}
		<-r.appConsensusEngine.Stop(false)
		r.appConsensusEngine = nil
	}
	r.appConsensusEngineFactory.CloseSnapshots()

	r.pubsub.Close()
	if r.server != nil {
		stopped := make(chan struct{})
		srv := r.server
		go func() {
			srv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			r.logger.Warn("server graceful stop timed out during shutdown, forcing")
			srv.Stop()
			<-stopped
		}
	}
	if r.peerInfoCancel != nil {
		r.peerInfoCancel()
		r.peerInfoCancel = nil
	}
	go func() {
		r.quit <- struct{}{}
	}()
	return nil
}

func (r *DataWorkerIPCServer) Respawn(
	ctx context.Context,
	req *protobufs.RespawnRequest,
) (*protobufs.RespawnResponse, error) {
	go r.RespawnServer(req.Filter)
	return &protobufs.RespawnResponse{}, nil
}

func (r *DataWorkerIPCServer) RespawnServer(filter []byte) error {
	if r.appConsensusEngine != nil {
		// Re-respawn: gracefully shut down the process for a clean restart.
		// The master's spawn loop (manager.go) detects the exit and
		// immediately restarts the worker process, giving it fresh
		// memory, a clean pubsub mesh, and a ProverRegistry built
		// from the current on-disk hypergraph state.
		r.logger.Info("re-respawn requested, shutting down worker for clean restart",
			zap.Uint32("core_id", r.coreId),
		)
		r.Stop()
		return nil
	}
	if r.server != nil {
		r.logger.Info("stopping server for respawn")
		stopped := make(chan struct{})
		srv := r.server
		go func() {
			srv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			r.logger.Warn("server graceful stop timed out, forcing stop")
			srv.Stop()
			<-stopped
		}
		r.server = nil
	}

	// Establish an auth provider
	r.authProvider = p2p.NewPeerAuthenticator(
		r.logger,
		r.config.P2P,
		r.peerInfoManager,
		r.proverRegistry,
		r.signerRegistry,
		filter,
		nil,
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.application.pb.HypergraphComparisonService": channel.AnyProverPeer,
			"quilibrium.node.node.pb.DataIPCService":                     channel.OnlySelfPeer,
			"quilibrium.node.global.pb.GlobalService":                    channel.OnlyGlobalProverPeer,
			"quilibrium.node.global.pb.AppShardService":                  channel.OnlyShardProverPeer,
			"quilibrium.node.global.pb.OnionService":                     channel.AnyPeer,
			"quilibrium.node.global.pb.KeyRegistryService":               channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{
			"/quilibrium.node.application.pb.HypergraphComparisonService/HyperStream": channel.OnlyShardProverPeer,
			"/quilibrium.node.application.pb.HypergraphComparisonService/PerformSync": channel.OnlyShardProverPeer,
			"/quilibrium.node.global.pb.MixnetService/GetTag":                         channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/PutTag":                         channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/PutMessage":                     channel.AnyPeer,
			"/quilibrium.node.global.pb.MixnetService/RoundStream":                    channel.OnlyGlobalProverPeer,
			"/quilibrium.node.global.pb.DispatchService/PutInboxMessage":              channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/GetInboxMessages":             channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/PutHub":                       channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/GetHub":                       channel.OnlySelfPeer,
			"/quilibrium.node.global.pb.DispatchService/Sync":                         channel.AnyProverPeer,
			"/quilibrium.node.ferretproxy.pb.FerretProxy/AliceProxy":                  channel.OnlySelfPeer,
			"/quilibrium.node.ferretproxy.pb.FerretProxy/BobProxy":                    channel.AnyPeer,
		},
	)

	tlsCreds, err := r.authProvider.CreateServerTLSCredentials()
	if err != nil {
		return errors.Wrap(err, "respawn server")
	}
	r.server = qgrpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.ChainUnaryInterceptor(r.authProvider.UnaryInterceptor),
		grpc.ChainStreamInterceptor(r.authProvider.StreamInterceptor),
		grpc.MaxRecvMsgSize(10*1024*1024),
		grpc.MaxSendMsgSize(10*1024*1024),
	)

	mg, err := multiaddr.NewMultiaddr(r.listenAddrGRPC)
	if err != nil {
		return errors.Wrap(err, "respawn server")
	}

	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "respawn server")
	}

	r.logger.Info(
		"data worker listening",
		zap.String("address", r.listenAddrGRPC),
		zap.String("resolved", lis.Addr().String()),
	)
	if len(filter) != 0 {
		globalTimeReel, err := r.appConsensusEngineFactory.CreateGlobalTimeReel()
		if err != nil {
			return errors.Wrap(err, "respawn server")
		}

		r.appConsensusEngine, err = r.appConsensusEngineFactory.CreateAppConsensusEngine(
			filter,
			uint(r.coreId),
			globalTimeReel,
			r.server,
		)
		if err != nil {
			return errors.Wrap(err, "respawn server")
		}

		var errCh <-chan error
		r.ctx, r.cancel, errCh = lifecycle.WithSignallerAndCancel(context.Background())
		// Capture engine and ctx in local variables to avoid race with subsequent RespawnServer calls
		engine := r.appConsensusEngine
		ctx := r.ctx
		go func() {
			if err, ok := <-errCh; ok && err != nil {
				r.logger.Error("app engine fatal error during respawn",
					zap.Error(err))
			}
		}()
		r.logger.Info("respawning worker: engine created, starting")
		go func() {
			if engine == nil {
				return
			}
			if err = engine.Start(ctx); err != nil {
				r.logger.Error("respawning worker: engine start failed", zap.Error(err))
			} else {
				r.logger.Info("respawning worker: engine started successfully")
			}
		}()
	}
	go func() {
		protobufs.RegisterDataIPCServiceServer(r.server, r)
		if err := r.server.Serve(mn.NetListener(lis)); err != nil {
			r.logger.Info("terminating server", zap.Error(err))
		}
	}()

	return nil
}

// CreateJoinProof implements protobufs.DataIPCServiceServer.
func (r *DataWorkerIPCServer) CreateJoinProof(
	ctx context.Context,
	req *protobufs.CreateJoinProofRequest,
) (*protobufs.CreateJoinProofResponse, error) {
	r.logger.Debug("received request to create join proof")
	proof := r.frameProver.CalculateMultiProof(
		[32]byte(req.Challenge),
		req.Difficulty,
		req.Ids,
		req.ProverIndex,
	)

	return &protobufs.CreateJoinProofResponse{
		Response: proof[:],
	}, nil
}
