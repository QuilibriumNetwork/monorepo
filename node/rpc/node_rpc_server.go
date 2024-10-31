package rpc

import (
	"bytes"
	"context"
	"math/big"
	"net/http"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/master"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type RPCServer struct {
	protobufs.UnimplementedNodeServiceServer
	listenAddrGRPC   string
	listenAddrHTTP   string
	logger           *zap.Logger
	dataProofStore   store.DataProofStore
	clockStore       store.ClockStore
	coinStore        store.CoinStore
	keyManager       keys.KeyManager
	pubSub           p2p.PubSub
	masterClock      *master.MasterClockConsensusEngine
	executionEngines []execution.ExecutionEngine
}

// GetFrameInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetFrameInfo(
	ctx context.Context,
	req *protobufs.GetFrameInfoRequest,
) (*protobufs.FrameInfoResponse, error) {
	if bytes.Equal(req.Filter, make([]byte, 32)) {
		frame, err := r.clockStore.GetMasterClockFrame(
			req.Filter,
			req.FrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		return &protobufs.FrameInfoResponse{
			ClockFrame: frame,
		}, nil
	} else if req.Selector == nil {
		frame, _, err := r.clockStore.GetDataClockFrame(
			req.Filter,
			req.FrameNumber,
			false,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		return &protobufs.FrameInfoResponse{
			ClockFrame: frame,
		}, nil
	} else {
		return nil, errors.Wrap(errors.New("not found"), "get frame info")
	}
}

// GetFrames implements protobufs.NodeServiceServer.
func (r *RPCServer) GetFrames(
	ctx context.Context,
	req *protobufs.GetFramesRequest,
) (*protobufs.FramesResponse, error) {
	if bytes.Equal(req.Filter, make([]byte, 32)) {
		iter, err := r.clockStore.RangeMasterClockFrames(
			req.Filter,
			req.FromFrameNumber,
			req.ToFrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		frames := []*protobufs.ClockFrame{}
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			if err != nil {
				iter.Close()
				return nil, errors.Wrap(err, "get frames")
			}
			frames = append(frames, frame)
		}

		if err := iter.Close(); err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		return &protobufs.FramesResponse{
			TruncatedClockFrames: frames,
		}, nil
	} else {
		iter, err := r.clockStore.RangeDataClockFrames(
			req.Filter,
			req.FromFrameNumber,
			req.ToFrameNumber,
		)
		if err != nil {
			return nil, errors.Wrap(err, "get frame info")
		}

		frames := []*protobufs.ClockFrame{}
		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.TruncatedValue()
			if err != nil {
				iter.Close()
				return nil, errors.Wrap(err, "get frames")
			}
			frames = append(frames, frame)
		}

		if err := iter.Close(); err != nil {
			return nil, errors.Wrap(err, "get frames")
		}

		return &protobufs.FramesResponse{
			TruncatedClockFrames: frames,
		}, nil
	}
}

// GetNetworkInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetNetworkInfo(
	ctx context.Context,
	req *protobufs.GetNetworkInfoRequest,
) (*protobufs.NetworkInfoResponse, error) {
	return r.pubSub.GetNetworkInfo(), nil
}

// GetNodeInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetNodeInfo(
	ctx context.Context,
	req *protobufs.GetNodeInfoRequest,
) (*protobufs.NodeInfoResponse, error) {
	peerID, err := peer.IDFromBytes(r.pubSub.GetPeerID())
	if err != nil {
		return nil, errors.Wrap(err, "getting id from bytes")
	}
	peerScore := r.pubSub.GetPeerScore(r.pubSub.GetPeerID())

	head := r.executionEngines[0].GetFrame()
	frame := uint64(0)
	if head != nil {
		frame = head.FrameNumber
	}
	return &protobufs.NodeInfoResponse{
		PeerId:    peerID.String(),
		MaxFrame:  frame,
		PeerScore: uint64(peerScore),
		Version: append(
			append([]byte{}, config.GetVersion()...), config.GetPatchNumber(),
		),
	}, nil
}

// GetPeerInfo implements protobufs.NodeServiceServer.
func (r *RPCServer) GetPeerInfo(
	ctx context.Context,
	req *protobufs.GetPeerInfoRequest,
) (*protobufs.PeerInfoResponse, error) {
	resp := &protobufs.PeerInfoResponse{}
	manifests := r.masterClock.GetPeerManifests()
	for _, m := range manifests.PeerManifests {
		multiaddr := r.pubSub.GetMultiaddrOfPeer(m.PeerId)
		addrs := []string{}
		if multiaddr != "" {
			addrs = append(addrs, multiaddr)
		}

		resp.PeerInfo = append(resp.PeerInfo, &protobufs.PeerInfo{
			PeerId:     m.PeerId,
			Multiaddrs: addrs,
			MaxFrame:   m.MasterHeadFrame,
			Timestamp:  m.LastSeen,
			// We can get away with this for this release only, we will want to add
			// version info in manifests.
			Version: config.GetVersion(),
		})
	}
	return resp, nil
}

func (r *RPCServer) SendMessage(
	ctx context.Context,
	req *protobufs.TokenRequest,
) (*protobufs.SendMessageResponse, error) {
	any := &anypb.Any{}
	if err := any.MarshalFrom(req); err != nil {
		return nil, errors.Wrap(err, "publish message")
	}

	// annoying protobuf any hack
	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return nil, errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return nil, errors.Wrap(err, "publish message")
	}

	intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: intrinsicFilter,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "publish message")
	}
	return &protobufs.SendMessageResponse{}, r.pubSub.PublishToBitmask(
		intrinsicFilter,
		data,
	)
}

func (r *RPCServer) GetTokensByAccount(
	ctx context.Context,
	req *protobufs.GetTokensByAccountRequest,
) (*protobufs.TokensByAccountResponse, error) {
	frameNumbers, addresses, coins, err := r.coinStore.GetCoinsForOwner(
		req.Address,
	)
	if err != nil {
		return nil, err
	}

	return &protobufs.TokensByAccountResponse{
		Coins:        coins,
		FrameNumbers: frameNumbers,
		Addresses:    addresses,
	}, nil
}

func (r *RPCServer) GetTokenInfo(
	ctx context.Context,
	req *protobufs.GetTokenInfoRequest,
) (*protobufs.TokenInfoResponse, error) {
	// 1 QUIL = 0x1DCD65000 units
	if req.Address != nil {
		_, _, coins, err := r.coinStore.GetCoinsForOwner(req.Address)
		if err != nil {
			return nil, errors.New("no coins found for address")
		}

		total := big.NewInt(0)
		for _, coin := range coins {
			total.Add(total, new(big.Int).SetBytes(coin.Amount))
		}

		return &protobufs.TokenInfoResponse{
			OwnedTokens: total.FillBytes(make([]byte, 32)),
		}, nil
	} else {
		provingKey, err := r.keyManager.GetRawKey(
			"default-proving-key",
		)
		if err != nil {
			return nil, errors.Wrap(err, "get token info")
		}

		peerBytes := r.pubSub.GetPeerID()
		peerAddr, err := poseidon.HashBytes(peerBytes)
		if err != nil {
			panic(err)
		}

		addr, err := poseidon.HashBytes(provingKey.PublicKey)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))
		peerAddrBytes := peerAddr.FillBytes(make([]byte, 32))

		_, _, coins, err := r.coinStore.GetCoinsForOwner(addrBytes)
		if err != nil {
			panic(err)
		}

		_, _, otherCoins, err := r.coinStore.GetCoinsForOwner(peerAddrBytes)
		if err != nil {
			panic(err)
		}

		total := big.NewInt(0)
		for _, coin := range coins {
			total.Add(total, new(big.Int).SetBytes(coin.Amount))
		}

		for _, coin := range otherCoins {
			total.Add(total, new(big.Int).SetBytes(coin.Amount))
		}

		return &protobufs.TokenInfoResponse{
			OwnedTokens: total.FillBytes(make([]byte, 32)),
		}, nil
	}
}

func (r *RPCServer) GetPeerManifests(
	ctx context.Context,
	req *protobufs.GetPeerManifestsRequest,
) (*protobufs.PeerManifestsResponse, error) {
	return r.masterClock.GetPeerManifests(), nil
}

func NewRPCServer(
	listenAddrGRPC string,
	listenAddrHTTP string,
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	masterClock *master.MasterClockConsensusEngine,
	executionEngines []execution.ExecutionEngine,
) (*RPCServer, error) {
	return &RPCServer{
		listenAddrGRPC:   listenAddrGRPC,
		listenAddrHTTP:   listenAddrHTTP,
		logger:           logger,
		dataProofStore:   dataProofStore,
		clockStore:       clockStore,
		coinStore:        coinStore,
		keyManager:       keyManager,
		pubSub:           pubSub,
		masterClock:      masterClock,
		executionEngines: executionEngines,
	}, nil
}

func (r *RPCServer) Start() error {
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(600*1024*1024),
		grpc.MaxSendMsgSize(600*1024*1024),
	)
	protobufs.RegisterNodeServiceServer(s, r)
	reflection.Register(s)

	mg, err := multiaddr.NewMultiaddr(r.listenAddrGRPC)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	go func() {
		if err := s.Serve(mn.NetListener(lis)); err != nil {
			panic(err)
		}
	}()

	if r.listenAddrHTTP != "" {
		m, err := multiaddr.NewMultiaddr(r.listenAddrHTTP)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		ma, err := mn.ToNetAddr(m)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		mga, err := mn.ToNetAddr(mg)
		if err != nil {
			return errors.Wrap(err, "start")
		}

		go func() {
			mux := runtime.NewServeMux()
			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(
					grpc.MaxCallRecvMsgSize(600*1024*1024),
					grpc.MaxCallSendMsgSize(600*1024*1024),
				),
			}

			if err := protobufs.RegisterNodeServiceHandlerFromEndpoint(
				context.Background(),
				mux,
				mga.String(),
				opts,
			); err != nil {
				panic(err)
			}

			if err := http.ListenAndServe(ma.String(), mux); err != nil {
				panic(err)
			}
		}()
	}

	return nil
}
