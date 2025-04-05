package rpc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"runtime"
	"syscall"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type DataWorkerIPCServer struct {
	protobufs.UnimplementedDataIPCServiceServer
	listenAddrGRPC  string
	logger          *zap.Logger
	coreId          uint32
	prover          crypto.FrameProver
	indices         []int
	parentProcessId int
}

// GetFrameInfo implements protobufs.NodeServiceServer.
func (r *DataWorkerIPCServer) CalculateChallengeProof(
	ctx context.Context,
	req *protobufs.ChallengeProofRequest,
) (*protobufs.ChallengeProofResponse, error) {
	challenge := []byte{}
	challenge = append(challenge, req.PeerId...)

	difficulty := req.Difficulty
	frameNumber := req.FrameNumber
	if req.Output != nil {
		challenge = binary.BigEndian.AppendUint64(
			challenge,
			frameNumber,
		)
		challenge = binary.BigEndian.AppendUint32(challenge, req.Core)
		challenge = append(challenge, req.Output...)
		r.logger.Debug(
			"worker calculating challenge proof",
			zap.String("peer_id", peer.ID(req.PeerId).String()),
			zap.Uint32("core", req.Core),
			zap.Uint64("frame_number", req.FrameNumber),
			zap.Uint32("difficulty", req.Difficulty),
			zap.Int("output_len", len(req.Output)),
		)
	} else {
		return nil, errors.Wrap(
			errors.New("invalid request"),
			"calculate challenge proof",
		)
	}

	if difficulty == 0 || frameNumber == 0 {
		return nil, errors.Wrap(
			errors.New("invalid request"),
			"calculate challenge proof",
		)
	}

	proof, err := r.prover.CalculateChallengeProof(
		challenge,
		difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "calculate challenge proof")
	}

	return &protobufs.ChallengeProofResponse{
		Output: proof,
	}, nil
}

func NewDataWorkerIPCServer(
	listenAddrGRPC string,
	logger *zap.Logger,
	coreId uint32,
	prover crypto.FrameProver,
	config *config.Config,
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

	pub := privKey.GetPublic()

	pubKey, err := pub.Raw()
	if err != nil {
		logger.Panic("error getting public key", zap.Error(err))
	}

	digest := make([]byte, 128)
	s := sha3.NewShake256()
	s.Write([]byte(pubKey))
	_, err = s.Read(digest)
	if err != nil {
		logger.Panic("error reading digest", zap.Error(err))
	}

	indices := p2p.GetOnesIndices(p2p.GetBloomFilter(digest, 1024, 64))

	return &DataWorkerIPCServer{
		listenAddrGRPC: listenAddrGRPC,
		logger:         logger,
		coreId:         coreId,
		prover:         prover,
		indices: []int{
			indices[int(coreId)%len(indices)],
		},
		parentProcessId: parentProcessId,
	}, nil
}

func (r *DataWorkerIPCServer) Start() error {
	s := qgrpc.NewServer(
		grpc.MaxRecvMsgSize(600*1024*1024),
		grpc.MaxSendMsgSize(600*1024*1024),
	)
	protobufs.RegisterDataIPCServiceServer(s, r)
	reflection.Register(s)

	mg, err := multiaddr.NewMultiaddr(r.listenAddrGRPC)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	lis, err := mn.Listen(mg)
	if err != nil {
		return errors.Wrap(err, "start")
	}

	go r.monitorParent()

	r.logger.Info(
		"data worker listening",
		zap.String("address", r.listenAddrGRPC),
	)
	if err := s.Serve(mn.NetListener(lis)); err != nil {
		r.logger.Panic("terminating server", zap.Error(err))
	}

	return nil
}

func (r *DataWorkerIPCServer) monitorParent() {
	if r.parentProcessId == 0 {
		r.logger.Info(
			"no parent process id specified, running in detached worker mode",
			zap.Uint32("core_id", r.coreId),
		)
		return
	}

	for {
		time.Sleep(1 * time.Second)
		proc, err := os.FindProcess(r.parentProcessId)
		if err != nil {
			r.logger.Error("parent process not found, terminating")
			os.Exit(1)
		}

		// Windows returns an error if the process is dead, nobody else does
		if runtime.GOOS != "windows" {
			err := proc.Signal(syscall.Signal(0))
			if err != nil {
				r.logger.Error("parent process not found, terminating")
				os.Exit(1)
			}
		}
	}
}
