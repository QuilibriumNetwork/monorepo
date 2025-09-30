package rpc

import (
	"bytes"
	"context"
	"math/big"
	"net/http"
	"slices"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/manager"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/worker"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

type PeerInfoProvider interface {
	GetPeerInfo() *protobufs.PeerInfo
}

// RPCServer strictly implements NodeService.
type RPCServer struct {
	protobufs.NodeServiceServer

	// dependencies
	config           *config.Config
	logger           *zap.Logger
	keyManager       keys.KeyManager
	pubSub           p2p.PubSub
	peerInfoProvider PeerInfoProvider
	workerManager    worker.WorkerManager
	proverRegistry   consensus.ProverRegistry
	executionManager *manager.ExecutionEngineManager
	coinStore        store.TokenStore
	hypergraph       hypergraph.Hypergraph

	// server interfaces
	grpcServer *grpc.Server
	httpServer *http.Server
}

// GetTokensByAccount implements protobufs.NodeServiceServer.
func (r *RPCServer) GetTokensByAccount(
	ctx context.Context,
	req *protobufs.GetTokensByAccountRequest,
) (*protobufs.GetTokensByAccountResponse, error) {
	// Handle legacy (pre-2.1) coins:
	if (len(req.Domain) == 0 ||
		bytes.Equal(req.Domain, token.QUIL_TOKEN_ADDRESS)) &&
		len(req.Address) == 32 {
		frameNumbers, addresses, coins, err := r.coinStore.GetCoinsForOwner(
			req.Address,
		)

		if err != nil {
			return nil, errors.Wrap(err, "get tokens by account")
		}

		legacyCoins := []*protobufs.LegacyCoin{}
		for i, coin := range coins {
			legacyCoins = append(legacyCoins, &protobufs.LegacyCoin{
				Coin:        coin,
				Address:     addresses[i],
				FrameNumber: frameNumbers[i],
			})
		}

		return &protobufs.GetTokensByAccountResponse{
			LegacyCoins: legacyCoins,
		}, nil
	}

	if len(req.Address) != 112 {
		return nil, errors.Wrap(
			errors.New("invalid address"),
			"get tokens by account",
		)
	}

	if len(req.Domain) != 32 && len(req.Domain) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid domain"),
			"get tokens by account",
		)
	}

	if len(req.Domain) == 0 {
		req.Domain = token.QUIL_TOKEN_ADDRESS
	}

	transactions, err := r.coinStore.GetTransactionsForOwner(
		req.Domain,
		req.Address,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"get tokens by account",
		)
	}

	pendingTransactions, err := r.coinStore.GetPendingTransactionsForOwner(
		req.Domain,
		req.Address,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"get tokens by account",
		)
	}

	return &protobufs.GetTokensByAccountResponse{
		Transactions:        transactions,
		PendingTransactions: pendingTransactions,
	}, nil
}

func (r *RPCServer) GetPeerInfo(
	ctx context.Context,
	_ *protobufs.GetPeerInfoRequest,
) (*protobufs.PeerInfoResponse, error) {
	self := r.peerInfoProvider.GetPeerInfo()
	if self == nil {
		return nil, errors.Wrap(errors.New("no peer info"), "get peer info")
	}

	return &protobufs.PeerInfoResponse{
		PeerInfo: self,
	}, nil
}

func (r *RPCServer) GetNodeInfo(
	ctx context.Context,
	_ *protobufs.GetNodeInfoRequest,
) (*protobufs.NodeInfoResponse, error) {
	peerID := r.pubSub.GetPeerID()

	workers, err := r.workerManager.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverKey, err := r.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverAddress, err := poseidon.HashBytes(proverKey.Public().([]byte))
	if err != nil {
		return nil, errors.Wrap(err, "get node info")
	}

	proverInfo, err := r.proverRegistry.GetProverInfo(
		proverAddress.FillBytes(make([]byte, 32)),
	)
	seniority := big.NewInt(0)
	if err == nil && proverInfo != nil {
		seniority = seniority.SetUint64(proverInfo.Seniority)
	}

	return &protobufs.NodeInfoResponse{
		PeerId:        peer.ID(peerID).String(),
		PeerScore:     uint64(r.pubSub.GetPeerScore(peerID)),
		Version:       append([]byte{}, config.GetVersion()...),
		PeerSeniority: seniority.FillBytes(make([]byte, 8)),
		Workers:       uint32(len(workers)),
	}, nil
}

func (r *RPCServer) GetWorkerInfo(
	ctx context.Context,
	_ *protobufs.GetWorkerInfoRequest,
) (*protobufs.WorkerInfoResponse, error) {
	workers, err := r.workerManager.RangeWorkers()
	if err != nil {
		return nil, errors.Wrap(err, "get worker info")
	}

	info := []*protobufs.WorkerInfo{}
	for _, worker := range workers {
		info = append(info, &protobufs.WorkerInfo{
			CoreId: uint32(worker.CoreId),
			Filter: worker.Filter,
			// TODO(2.1.1+): Expose available storage
			AvailableStorage: uint64(worker.TotalStorage),
			TotalStorage:     uint64(worker.TotalStorage),
		})
	}

	return &protobufs.WorkerInfoResponse{
		WorkerInfo: info,
	}, nil
}

// Send implements protobufs.NodeServiceServer.
func (r *RPCServer) Send(
	ctx context.Context,
	req *protobufs.SendRequest,
) (*protobufs.SendResponse, error) {
	if req == nil || req.Request == nil || len(req.Authentication) == 0 {
		return &protobufs.SendResponse{}, nil
	}

	signer, err := r.keyManager.GetSigningKey("q-node-auth")
	if err != nil {
		r.logger.Error("no node auth key found")
		// Do not flag auth failures
		return &protobufs.SendResponse{}, nil
	}

	var payload []byte
	var request []byte
	if req.Request != nil {
		payload, err = req.Request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "send")
		}
		request = slices.Clone(payload)
	}

	if len(req.DeliveryData) != 0 {
		for _, d := range req.DeliveryData {
			p, err := proto.Marshal(d)
			if err != nil {
				return nil, errors.Wrap(err, "send")
			}
			payload = append(payload, p...)
		}
	}

	if len(payload) == 0 {
		return &protobufs.SendResponse{}, nil
	}

	valid, err := r.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		signer.Public().([]byte),
		payload,
		req.Authentication,
		slices.Concat([]byte("NODE_AUTHENTICATION"), req.Domain),
	)
	if err != nil || !valid {
		// Do not flag auth failures
		return &protobufs.SendResponse{}, nil
	}

	if len(request) != 0 {
		if bytes.Equal(req.Domain, bytes.Repeat([]byte{0xff}, 32)) {
			r.pubSub.Subscribe(
				[]byte{0x00, 0x00, 0x00},
				func(message *pb.Message) error { return nil },
			)
			err := r.pubSub.PublishToBitmask([]byte{0x00, 0x00, 0x00}, payload)
			if err != nil {
				return nil, err
			}
		} else {
			bitmask := up2p.GetBloomFilter(req.Domain, 256, 3)
			r.pubSub.Subscribe(
				bitmask,
				func(message *pb.Message) error { return nil },
			)
			err := r.pubSub.PublishToBitmask(bitmask, payload)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(req.DeliveryData) != 0 {
		for _, d := range req.DeliveryData {
			for _, i := range d.Messages {
				bitmask := slices.Concat(
					[]byte{0, 0},
					up2p.GetBloomFilter(i.Address, 256, 3),
				)
				r.pubSub.Subscribe(
					bitmask,
					func(message *pb.Message) error { return nil },
				)
				msg, err := i.ToCanonicalBytes()
				if err != nil {
					return nil, err
				}
				err = r.pubSub.PublishToBitmask(bitmask, msg)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return &protobufs.SendResponse{}, nil
}

func NewRPCServer(
	config *config.Config,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	peerInfoProvider PeerInfoProvider,
	workerManager worker.WorkerManager,
	proverRegistry consensus.ProverRegistry,
	executionManager *manager.ExecutionEngineManager,
) (*RPCServer, error) {
	mg, err := multiaddr.NewMultiaddr(config.ListenGRPCMultiaddr)
	if err != nil {
		return nil, errors.Wrap(err, "new rpc server: grpc multiaddr")
	}
	mga, err := mn.ToNetAddr(mg)
	if err != nil {
		return nil, errors.Wrap(err, "new rpc server: grpc netaddr")
	}

	// HTTP gateway mux (optional)
	mux := runtime.NewServeMux()
	opts := qgrpc.ClientOptions(
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10*1024*1024),
			grpc.MaxCallSendMsgSize(10*1024*1024),
		),
	)
	if config.ListenRestMultiaddr != "" {
		if err := protobufs.RegisterNodeServiceHandlerFromEndpoint(
			context.Background(),
			mux,
			mga.String(),
			opts,
		); err != nil {
			return nil, errors.Wrap(err, "register node service handler")
		}
	}

	rpcServer := &RPCServer{
		config:           config,
		logger:           logger,
		keyManager:       keyManager,
		pubSub:           pubSub,
		peerInfoProvider: peerInfoProvider,
		workerManager:    workerManager,
		proverRegistry:   proverRegistry,
		executionManager: executionManager,
		grpcServer: qgrpc.NewServer(
			grpc.MaxRecvMsgSize(10*1024*1024),
			grpc.MaxSendMsgSize(10*1024*1024),
		),
		httpServer: &http.Server{Handler: mux},
	}

	protobufs.RegisterNodeServiceServer(rpcServer.grpcServer, rpcServer)
	return rpcServer, nil
}

func (r *RPCServer) Start() error {
	// Start GRPC
	mg, err := multiaddr.NewMultiaddr(r.config.ListenGRPCMultiaddr)
	if err != nil {
		return errors.Wrap(err, "start: grpc multiaddr")
	}
	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start: grpc listen")
	}
	go func() {
		if err := r.grpcServer.Serve(mn.NetListener(lis)); err != nil {
			r.logger.Error("grpc serve error", zap.Error(err))
		}
	}()

	// Start HTTP gateway if requested
	if r.config.ListenRestMultiaddr != "" {
		mh, err := multiaddr.NewMultiaddr(r.config.ListenRestMultiaddr)
		if err != nil {
			return errors.Wrap(err, "start: http multiaddr")
		}
		hl, err := mn.Listen(mh)
		if err != nil {
			return errors.Wrap(err, "start: http listen")
		}
		go func() {
			if err := r.httpServer.Serve(
				mn.NetListener(hl),
			); err != nil && !errors.Is(err, http.ErrServerClosed) {
				r.logger.Error("http serve error", zap.Error(err))
			}
		}()
	}

	return nil
}

func (r *RPCServer) Stop() {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.grpcServer.GracefulStop()
	}()
	go func() {
		defer wg.Done()
		_ = r.httpServer.Shutdown(context.Background())
	}()
	wg.Wait()
}
