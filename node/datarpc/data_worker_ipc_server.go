package datarpc

import (
	"context"
	"encoding/hex"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/app"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type DataWorkerIPCServer struct {
	protobufs.UnimplementedDataIPCServiceServer

	listenAddrGRPC            string
	config                    *config.Config
	logger                    *zap.Logger
	coreId                    uint32
	parentProcessId           int
	signer                    crypto.Signer
	signerRegistry            consensus.SignerRegistry
	proverRegistry            consensus.ProverRegistry
	peerInfoManager           p2p.PeerInfoManager
	authProvider              channel.AuthenticationProvider
	appConsensusEngineFactory *app.AppConsensusEngineFactory
	appConsensusEngine        *app.AppConsensusEngine
	server                    *grpc.Server
	frameProver               crypto.FrameProver
	quit                      chan struct{}
}

func NewDataWorkerIPCServer(
	listenAddrGRPC string,
	config *config.Config,
	signerRegistry consensus.SignerRegistry,
	proverRegistry consensus.ProverRegistry,
	peerInfoManager p2p.PeerInfoManager,
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
		signer:                    signer,
		appConsensusEngineFactory: appConsensusEngineFactory,
		signerRegistry:            signerRegistry,
		proverRegistry:            proverRegistry,
		frameProver:               frameProver,
		peerInfoManager:           peerInfoManager,
	}, nil
}

func (r *DataWorkerIPCServer) Start() error {
	r.quit = make(chan struct{})
	r.RespawnServer(nil)

	<-r.quit
	return nil
}

func (r *DataWorkerIPCServer) Stop() error {
	r.logger.Info("stopping server gracefully")
	r.server.GracefulStop()
	go func() {
		r.quit <- struct{}{}
	}()
	return nil
}

func (r *DataWorkerIPCServer) Respawn(
	ctx context.Context,
	req *protobufs.RespawnRequest,
) (*protobufs.RespawnResponse, error) {
	err := r.RespawnServer(req.Filter)
	if err != nil {
		return nil, err
	}
	return &protobufs.RespawnResponse{}, nil
}

func (r *DataWorkerIPCServer) RespawnServer(filter []byte) error {
	if r.server != nil {
		r.logger.Info("stopping server for respawn")
		r.server.GracefulStop()
		r.server = nil
	}
	if r.appConsensusEngine != nil {
		<-r.appConsensusEngine.Stop(false)
		r.appConsensusEngine = nil
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
