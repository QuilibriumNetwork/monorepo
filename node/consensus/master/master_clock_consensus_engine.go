package master

import (
	"bytes"
	gcrypto "crypto"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qtime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type SyncStatusType int

const (
	SyncStatusNotSyncing = iota
	SyncStatusAwaitingResponse
	SyncStatusSynchronizing
)

type MasterClockConsensusEngine struct {
	*protobufs.UnimplementedValidationServiceServer

	difficulty          uint32
	logger              *zap.Logger
	state               consensus.EngineState
	pubSub              p2p.PubSub
	keyManager          keys.KeyManager
	dataProver          crypto.InclusionProver
	frameProver         crypto.FrameProver
	lastFrameReceivedAt time.Time

	frameChan        chan *protobufs.ClockFrame
	executionEngines map[string]execution.ExecutionEngine
	filter           []byte
	input            []byte
	syncingStatus    SyncStatusType
	syncingTarget    []byte
	engineMx         sync.Mutex
	seenFramesMx     sync.Mutex
	seenFrames       []*protobufs.ClockFrame

	clockStore                  store.ClockStore
	masterTimeReel              *qtime.MasterTimeReel
	peerInfoManager             p2p.PeerInfoManager
	report                      *protobufs.SelfTestReport
	frameValidationCh           chan *protobufs.ClockFrame
	beacon                      peer.ID
	currentReceivingSyncPeers   int
	currentReceivingSyncPeersMx sync.Mutex
	collectedProverSlots        []*protobufs.InclusionAggregateProof
	collectedProverSlotsMx      sync.Mutex
	engineConfig                *config.EngineConfig
}

var _ consensus.ConsensusEngine = (*MasterClockConsensusEngine)(nil)

var MASTER_CLOCK_RATE = uint32(160000)

func NewMasterClockConsensusEngine(
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	dataProver crypto.InclusionProver,
	frameProver crypto.FrameProver,
	masterTimeReel *qtime.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	report *protobufs.SelfTestReport,
) *MasterClockConsensusEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	if engineConfig == nil {
		panic(errors.New("engine config is nil"))
	}

	if keyManager == nil {
		panic(errors.New("key manager is nil"))
	}

	if pubSub == nil {
		panic(errors.New("pubsub is nil"))
	}

	if dataProver == nil {
		panic(errors.New("data prover is nil"))
	}

	if frameProver == nil {
		panic(errors.New("frame prover is nil"))
	}

	if masterTimeReel == nil {
		panic(errors.New("master time reel is nil"))
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(errors.New("genesis seed is nil"))
	}

	e := &MasterClockConsensusEngine{
		difficulty:           MASTER_CLOCK_RATE,
		logger:               logger,
		state:                consensus.EngineStateStopped,
		keyManager:           keyManager,
		pubSub:               pubSub,
		executionEngines:     map[string]execution.ExecutionEngine{},
		frameChan:            make(chan *protobufs.ClockFrame),
		input:                seed,
		lastFrameReceivedAt:  time.Time{},
		syncingStatus:        SyncStatusNotSyncing,
		clockStore:           clockStore,
		dataProver:           dataProver,
		frameProver:          frameProver,
		masterTimeReel:       masterTimeReel,
		peerInfoManager:      peerInfoManager,
		report:               report,
		frameValidationCh:    make(chan *protobufs.ClockFrame),
		collectedProverSlots: []*protobufs.InclusionAggregateProof{},
		engineConfig:         engineConfig,
	}

	e.addPeerManifestReport(e.pubSub.GetPeerID(), report)

	if e.filter, err = hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000000",
	); err != nil {
		panic(errors.Wrap(err, "could not parse filter value"))
	}

	e.getProvingKey(engineConfig)

	if err := e.createCommunicationKeys(); err != nil {
		panic(err)
	}

	logger.Info("constructing consensus engine")

	return e
}

func (e *MasterClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting master consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)

	e.peerInfoManager.Start()

	e.state = consensus.EngineStateLoading
	e.logger.Info("syncing last seen state")

	err := e.masterTimeReel.Start()
	if err != nil {
		panic(err)
	}

	beaconPubKey, err := pcrypto.UnmarshalEd448PublicKey(
		config.GetGenesis().Beacon,
	)
	if err != nil {
		panic(err)
	}

	e.beacon, err = peer.IDFromPublicKey(beaconPubKey)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case newFrame := <-e.frameValidationCh:
				head, err := e.masterTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if head.FrameNumber > newFrame.FrameNumber ||
					newFrame.FrameNumber-head.FrameNumber > 128 {
					e.logger.Debug(
						"frame out of range, ignoring",
						zap.Uint64("number", newFrame.FrameNumber),
					)
					continue
				}

				if err := e.frameProver.VerifyMasterClockFrame(newFrame); err != nil {
					e.logger.Error("could not verify clock frame", zap.Error(err))
					continue
				}

				e.masterTimeReel.Insert(newFrame, false)
			}
		}
	}()

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage)

	e.state = consensus.EngineStateCollecting

	go func() {
		for {
			e.logger.Info(
				"peers in store",
				zap.Int("peer_store_count", e.pubSub.GetPeerstoreCount()),
				zap.Int("network_peer_count", e.pubSub.GetNetworkPeersCount()),
			)
			time.Sleep(10 * time.Second)
		}
	}()

	go func() {
		if !bytes.Equal(e.pubSub.GetPeerID(), []byte(e.beacon)) {
			return
		}

		for e.state < consensus.EngineStateStopping {
			frame, err := e.masterTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if frame, err = e.prove(frame); err != nil {
				e.logger.Error("could not prove", zap.Error(err))
				continue
			}
			if err = e.publishProof(frame); err != nil {
				e.logger.Error("could not publish", zap.Error(err))
			}
		}
	}()

	go func() {
		errChan <- nil
	}()

	return errChan
}

func (e *MasterClockConsensusEngine) Stop(force bool) <-chan error {
	e.logger.Info("stopping consensus engine")
	e.state = consensus.EngineStateStopping
	errChan := make(chan error)

	wg := sync.WaitGroup{}
	wg.Add(len(e.executionEngines))
	for name := range e.executionEngines {
		name := name
		go func(name string) {
			frame, err := e.masterTimeReel.Head()
			if err != nil {
				errChan <- err
				return
			}

			err = <-e.UnregisterExecutor(name, frame.FrameNumber, force)
			if err != nil {
				errChan <- err
			}
			wg.Done()
		}(name)
	}

	e.logger.Info("waiting for execution engines to stop")
	wg.Wait()
	e.logger.Info("execution engines stopped")
	e.masterTimeReel.Stop()
	e.peerInfoManager.Stop()

	e.state = consensus.EngineStateStopped
	go func() {
		errChan <- nil
	}()
	return errChan
}

func (
	e *MasterClockConsensusEngine,
) GetPeerManifests() *protobufs.PeerManifestsResponse {
	response := &protobufs.PeerManifestsResponse{
		PeerManifests: []*protobufs.PeerManifest{},
	}
	peerMap := e.peerInfoManager.GetPeerMap()
	for peerId, peerManifest := range peerMap {
		peerId := peerId
		peerManifest := peerManifest
		manifest := &protobufs.PeerManifest{
			PeerId:          []byte(peerId),
			Cores:           peerManifest.Cores,
			Memory:          new(big.Int).SetBytes(peerManifest.Memory).Bytes(),
			Storage:         new(big.Int).SetBytes(peerManifest.Storage).Bytes(),
			MasterHeadFrame: peerManifest.MasterHeadFrame,
			LastSeen:        peerManifest.LastSeen,
		}

		for _, capability := range peerManifest.Capabilities {
			metadata := make([]byte, len(capability.AdditionalMetadata))
			copy(metadata[:], capability.AdditionalMetadata[:])
			manifest.Capabilities = append(
				manifest.Capabilities,
				&protobufs.Capability{
					ProtocolIdentifier: capability.ProtocolIdentifier,
					AdditionalMetadata: metadata,
				},
			)
		}

		response.PeerManifests = append(
			response.PeerManifests,
			manifest,
		)
	}
	return response
}

func (e *MasterClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *MasterClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
	frame, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	return frame
}

func (e *MasterClockConsensusEngine) GetState() consensus.EngineState {
	return e.state
}

func (
	e *MasterClockConsensusEngine,
) GetFrameChannel() <-chan *protobufs.ClockFrame {
	return e.frameChan
}

func (e *MasterClockConsensusEngine) addPeerManifestReport(
	peerId []byte,
	report *protobufs.SelfTestReport,
) {
	manifest := &p2p.PeerManifest{
		PeerId:          peerId,
		Cores:           report.Cores,
		Memory:          report.Memory,
		Storage:         report.Storage,
		Capabilities:    []p2p.Capability{},
		MasterHeadFrame: report.MasterHeadFrame,
		LastSeen:        time.Now().UnixMilli(),
	}

	for _, capability := range manifest.Capabilities {
		metadata := make([]byte, len(capability.AdditionalMetadata))
		copy(metadata[:], capability.AdditionalMetadata[:])
		manifest.Capabilities = append(
			manifest.Capabilities,
			p2p.Capability{
				ProtocolIdentifier: capability.ProtocolIdentifier,
				AdditionalMetadata: metadata,
			},
		)
	}

	e.peerInfoManager.AddPeerInfo(manifest)
}

func (e *MasterClockConsensusEngine) getProvingKey(
	engineConfig *config.EngineConfig,
) (gcrypto.Signer, keys.KeyType, []byte, []byte) {
	provingKey, err := e.keyManager.GetSigningKey(engineConfig.ProvingKeyId)
	if errors.Is(err, keys.KeyNotFoundErr) {
		e.logger.Info("could not get proving key, generating")
		provingKey, err = e.keyManager.CreateSigningKey(
			engineConfig.ProvingKeyId,
			keys.KeyTypeEd448,
		)
	}

	if err != nil {
		e.logger.Error("could not get proving key", zap.Error(err))
		panic(err)
	}

	rawKey, err := e.keyManager.GetRawKey(engineConfig.ProvingKeyId)
	if err != nil {
		e.logger.Error("could not get proving key type", zap.Error(err))
		panic(err)
	}

	provingKeyType := rawKey.Type

	h, err := poseidon.HashBytes(rawKey.PublicKey)
	if err != nil {
		e.logger.Error("could not hash proving key", zap.Error(err))
		panic(err)
	}

	provingKeyAddress := h.Bytes()
	provingKeyAddress = append(
		make([]byte, 32-len(provingKeyAddress)),
		provingKeyAddress...,
	)

	return provingKey, provingKeyType, rawKey.PublicKey, provingKeyAddress
}

func (e *MasterClockConsensusEngine) createCommunicationKeys() error {
	_, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "create communication keys")
			}
		} else {
			return errors.Wrap(err, "create communication keys")
		}
	}

	_, err = e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-spk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "create communication keys")
			}
		} else {
			return errors.Wrap(err, "create communication keys")
		}
	}

	return nil
}
