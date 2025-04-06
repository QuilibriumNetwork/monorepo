package master

import (
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

type pubsub struct {
	privkey ed448.PrivateKey
	pubkey  []byte
}

func (pubsub) GetBitmaskPeers() map[string][]string                                    { return nil }
func (pubsub) Publish(address []byte, data []byte) error                               { return nil }
func (pubsub) PublishToBitmask(bitmask []byte, data []byte) error                      { return nil }
func (pubsub) Subscribe(bitmask []byte, handler func(message *pb.Message) error) error { return nil }
func (pubsub) Unsubscribe(bitmask []byte, raw bool)                                    {}
func (pubsub) RegisterValidator(bitmask []byte, validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult, sync bool) error {
	return nil
}
func (pubsub) UnregisterValidator(bitmask []byte) error     { return nil }
func (pubsub) GetPeerID() []byte                            { return nil }
func (pubsub) GetPeerstoreCount() int                       { return 0 }
func (pubsub) GetNetworkPeersCount() int                    { return 0 }
func (pubsub) GetRandomPeer(bitmask []byte) ([]byte, error) { return nil, nil }
func (pubsub) GetMultiaddrOfPeerStream(ctx context.Context, peerId []byte) <-chan multiaddr.Multiaddr {
	return nil
}
func (pubsub) GetMultiaddrOfPeer(peerId []byte) string { return "" }
func (pubsub) GetNetwork() uint                        { return 1 }
func (pubsub) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	return nil
}
func (pubsub) GetDirectChannel(ctx context.Context, peerId []byte, purpose string) (*grpc.ClientConn, error) {
	return nil, nil
}
func (pubsub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	return nil
}
func (p pubsub) SignMessage(msg []byte) ([]byte, error) {
	return p.privkey.Sign(rand.Reader, msg, gocrypto.Hash(0))
}
func (p pubsub) GetPublicKey() []byte                       { return p.pubkey }
func (pubsub) GetPeerScore(peerId []byte) int64             { return 0 }
func (pubsub) SetPeerScore(peerId []byte, score int64)      {}
func (pubsub) AddPeerScore(peerId []byte, scoreDelta int64) {}
func (pubsub) Reconnect(peerId []byte) error                { return nil }
func (pubsub) Bootstrap(context.Context) error              { return nil }
func (pubsub) DiscoverPeers(context.Context) error          { return nil }
func (pubsub) IsPeerConnected(peerId []byte) bool           { return false }
func (pubsub) Reachability() *wrapperspb.BoolValue          { return nil }

var _ p2p.PubSub = (*pubsub)(nil)

type mockFrameProver struct {
	qcrypto.FrameProver
	verifyMasterClockFrame func(frame *protobufs.ClockFrame) error
}

var _ qcrypto.FrameProver = (*mockFrameProver)(nil)

func (m *mockFrameProver) VerifyMasterClockFrame(frame *protobufs.ClockFrame) error {
	return m.verifyMasterClockFrame(frame)
}

func TestStartMasterClockConsensusEngine(t *testing.T) {
	t.Run("test validate and storage", func(t *testing.T) {
		logger := utils.GetDebugLogger()
		config.DownloadAndVerifyGenesis(1)
		filter := "0000000000000000000000000000000000000000000000000000000000000000"
		engineConfig := &config.EngineConfig{
			ProvingKeyId: "default-proving-key",
			Filter:       filter,
			GenesisSeed:  strings.Repeat("00", 516),
			Difficulty:   10,
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
		testFrameNumber := uint64(1)
		report := &protobufs.SelfTestReport{}
		var wg sync.WaitGroup
		wg.Add(1)

		mockFrameProver := &mockFrameProver{
			verifyMasterClockFrame: func(frame *protobufs.ClockFrame) error {
				assert.Equal(t, testFrameNumber, frame.FrameNumber)
				logger.Info("frame verified", zap.Uint64("frame_number", frame.FrameNumber))
				defer wg.Done()
				return nil
			},
		}
		engine := NewMasterClockConsensusEngine(engineConfig, logger, cs, km, ps, dataProver, mockFrameProver, masterTimeReel, peerInfoManager, report)
		engine.Start()

		head1, err := masterTimeReel.Head()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), head1.FrameNumber)
		head1Selector, err := head1.GetSelector()
		assert.NoError(t, err)

		newFrame := &protobufs.ClockFrame{
			FrameNumber:    testFrameNumber,
			ParentSelector: head1Selector.FillBytes(make([]byte, 32)),
		}
		engine.frameValidationCh <- newFrame
		wg.Wait()

		// Wait for the frame to be stored, this is a bit of a hack, because
		// masterTimeReel.Insert is async in Start() function, and this function not return
		// the channel, remove this time.Sleep after refactor Start()
		time.Sleep(1 * time.Second)

		newHeadFrame, err := masterTimeReel.Head()
		assert.NoError(t, err)
		assert.Equal(t, testFrameNumber, newHeadFrame.FrameNumber)
	})
}
