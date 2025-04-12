package master

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qtime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

func TestHandleMessage(t *testing.T) {
	t.Run("test handle message", func(t *testing.T) {
		logger := utils.GetDebugLogger()
		engine := &MasterClockConsensusEngine{
			logger: logger,
		}
		anyPb := &anypb.Any{}
		anyBytes, err := proto.Marshal(anyPb)
		assert.NoError(t, err)

		msg := &protobufs.Message{
			Payload: anyBytes,
		}
		msgBytes, err := proto.Marshal(msg)
		assert.NoError(t, err)
		message := &pb.Message{
			Data:      msgBytes,
			From:      []byte("test from"),
			Signature: []byte("test signature"),
		}
		if err := engine.handleMessage(message); err != nil {
			assert.Equal(t, err.Error(), "handle message: invalid message")
		}
	})
}

func TestHandleClockFrameData(t *testing.T) {
	t.Run("test handle clock frame data", func(t *testing.T) {
		logger := utils.GetDebugLogger()
		config.DownloadAndVerifyGenesis(1)
		filter := "0000000000000000000000000000000000000000000000000000000000000000"
		difficulty := uint32(160000)
		engineConfig := &config.EngineConfig{
			ProvingKeyId: "default-proving-key",
			Filter:       filter,
			GenesisSeed:  strings.Repeat("00", 516),
			Difficulty:   difficulty,
		}
		kvStore := store.NewInMemKVDB()
		cs := store.NewPebbleClockStore(kvStore, logger)
		km := keys.NewInMemoryKeyManager()

		bpub, bprivKey, _ := ed448.GenerateKey(rand.Reader)
		ps := &pubsub{
			privkey: bprivKey,
			pubkey:  bpub,
		}
		dataProver := qcrypto.NewKZGInclusionProver(logger)
		frameProver := qcrypto.NewWesolowskiFrameProver(logger)
		masterTimeReel := qtime.NewMasterTimeReel(logger, cs, engineConfig, frameProver)
		peerInfoManager := p2p.NewInMemoryPeerInfoManager(logger)
		report := &protobufs.SelfTestReport{}

		mockFrameProver := &mockFrameProver{
			verifyMasterClockFrame: func(frame *protobufs.ClockFrame) error {
				return nil
			},
		}
		engine := NewMasterClockConsensusEngine(
			engineConfig, logger, cs, km, ps, dataProver, mockFrameProver,
			masterTimeReel, peerInfoManager, report)
		engine.Start()
		anyPb := &anypb.Any{}
		frameNumber := uint64(1)
		frame := &protobufs.ClockFrame{
			FrameNumber: frameNumber,
			Difficulty:  difficulty,
		}
		err := anyPb.MarshalFrom(frame)
		assert.NoError(t, err)

		peerID, err := peer.Decode("QmNSGavG2DfJwGpHmzKjVmTD6CVSyJsUFTXsW4JXt2eySR")
		assert.NoError(t, err)
		err = engine.handleClockFrameData([]byte(peerID), anyPb)
		assert.NoError(t, err)
	})
}
