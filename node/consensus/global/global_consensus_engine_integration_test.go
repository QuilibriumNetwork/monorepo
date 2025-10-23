//go:build integrationtest
// +build integrationtest

package global

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/channel"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/difficulty"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/events"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/registration"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

type testTransitionListener struct {
	onTransition func(from, to consensus.State, event consensus.Event)
}

func (l *testTransitionListener) OnTransition(from, to consensus.State, event consensus.Event) {
	if l.onTransition != nil {
		l.onTransition(from, to, event)
	}
}

// mockIntegrationPubSub is a pubsub mock for integration testing
type mockIntegrationPubSub struct {
	mock.Mock
	mu                   sync.RWMutex
	subscribers          map[string][]func(message *pb.Message) error
	validators           map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult
	peerID               []byte
	peerCount            int
	networkPeers         map[string]*mockIntegrationPubSub
	frames               []*protobufs.GlobalFrame
	onPublish            func(bitmask []byte, data []byte)
	deliveryComplete     chan struct{}     // Signal when all deliveries are done
	msgProcessor         func(*pb.Message) // Custom message processor for tracking
	underlyingHost       host.Host
	underlyingBlossomSub *qp2p.BlossomSub
}

// GetOwnMultiaddrs implements p2p.PubSub.
func (m *mockIntegrationPubSub) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	ma, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/8336")
	return []multiaddr.Multiaddr{ma}
}

func newMockIntegrationPubSub(config *config.Config, logger *zap.Logger, peerID []byte, host host.Host, privKey pcrypto.PrivKey, bootstrapHosts []host.Host) *mockIntegrationPubSub {
	blossomSub := qp2p.NewBlossomSubWithHost(config.P2P, config.Engine, logger, 1, true, host, privKey, bootstrapHosts)
	return &mockIntegrationPubSub{
		subscribers:          make(map[string][]func(message *pb.Message) error),
		validators:           make(map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult),
		peerID:               peerID,
		peerCount:            0, // Start with 0 to trigger genesis
		networkPeers:         make(map[string]*mockIntegrationPubSub),
		frames:               make([]*protobufs.GlobalFrame, 0),
		deliveryComplete:     make(chan struct{}),
		underlyingHost:       host,
		underlyingBlossomSub: blossomSub,
	}
}

func (m *mockIntegrationPubSub) Subscribe(bitmask []byte, handler func(message *pb.Message) error) error {
	m.mu.Lock()
	key := string(bitmask)
	m.subscribers[key] = append(m.subscribers[key], handler)
	m.mu.Unlock()

	return m.underlyingBlossomSub.Subscribe(bitmask, handler)
}

func (m *mockIntegrationPubSub) PublishToBitmask(bitmask []byte, data []byte) error {
	if m.onPublish != nil {
		m.onPublish(bitmask, data)
	}

	// Check if data is long enough to contain type prefix
	if len(data) >= 4 {
		// Read type prefix from first 4 bytes
		typePrefix := binary.BigEndian.Uint32(data[:4])

		// Check if it's a GlobalFrame
		if typePrefix == protobufs.GlobalFrameType {
			frame := &protobufs.GlobalFrame{}
			if err := frame.FromCanonicalBytes(data); err == nil {
				m.mu.Lock()
				m.frames = append(m.frames, frame)
				m.mu.Unlock()
			}
		}
	}

	// Count total handlers to track
	m.mu.RLock()
	handlers := m.subscribers[string(bitmask)]
	totalHandlers := len(handlers) // self handlers
	for _, peer := range m.networkPeers {
		peer.mu.RLock()
		totalHandlers += len(peer.subscribers[string(bitmask)])
		peer.mu.RUnlock()
	}
	m.mu.RUnlock()

	return m.underlyingBlossomSub.PublishToBitmask(bitmask, data)
}

func (m *mockIntegrationPubSub) deliverMessage(bitmask []byte, message *pb.Message, wg *sync.WaitGroup) {
	// Check validator first
	m.mu.RLock()
	validator := m.validators[string(bitmask)]
	m.mu.RUnlock()

	if validator != nil {
		result := validator(peer.ID(message.From), message)
		if result != p2p.ValidationResultAccept {
			// Message rejected by validator, still need to decrement wait group
			m.mu.RLock()
			handlerCount := len(m.subscribers[string(bitmask)])
			m.mu.RUnlock()
			for i := 0; i < handlerCount; i++ {
				wg.Done()
			}
			return
		}
	}

	m.mu.RLock()
	handlers := m.subscribers[string(bitmask)]
	m.mu.RUnlock()

	// Create wrapped handler that decrements wait group
	wrappedHandler := func(h func(*pb.Message) error, msg *pb.Message) {
		defer wg.Done()
		if m.msgProcessor != nil {
			m.msgProcessor(msg)
		}
		h(msg)
	}

	// Deliver asynchronously
	for _, handler := range handlers {
		go wrappedHandler(handler, message)
	}
}

func (m *mockIntegrationPubSub) RegisterValidator(bitmask []byte, validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult, sync bool) error {
	m.mu.Lock()
	m.validators[string(bitmask)] = validator
	m.mu.Unlock()
	return m.underlyingBlossomSub.RegisterValidator(bitmask, validator, sync)
}

func (m *mockIntegrationPubSub) UnregisterValidator(bitmask []byte) error {
	m.mu.Lock()
	delete(m.validators, string(bitmask))
	m.mu.Unlock()
	return m.underlyingBlossomSub.UnregisterValidator(bitmask)
}

func (m *mockIntegrationPubSub) Unsubscribe(bitmask []byte, raw bool) {
	m.mu.Lock()
	delete(m.subscribers, string(bitmask))
	m.mu.Unlock()
	m.underlyingBlossomSub.Unsubscribe(bitmask, raw)
}

func (m *mockIntegrationPubSub) GetPeerID() []byte {
	return m.peerID
}

func (m *mockIntegrationPubSub) GetPeerstoreCount() int {
	return m.peerCount
}

func (m *mockIntegrationPubSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	return &protobufs.NetworkInfoResponse{
		NetworkInfo: []*protobufs.NetworkInfo{},
	}
}

// Stub implementations for other interface methods
func (m *mockIntegrationPubSub) Publish(address []byte, data []byte) error    { return nil }
func (m *mockIntegrationPubSub) GetNetworkPeersCount() int                    { return m.peerCount }
func (m *mockIntegrationPubSub) GetRandomPeer(bitmask []byte) ([]byte, error) { return nil, nil }
func (m *mockIntegrationPubSub) GetMultiaddrOfPeerStream(ctx context.Context, peerId []byte) <-chan multiaddr.Multiaddr {
	return nil
}
func (m *mockIntegrationPubSub) GetMultiaddrOfPeer(peerId []byte) string { return "" }
func (m *mockIntegrationPubSub) StartDirectChannelListener(key []byte, purpose string, server *grpc.Server) error {
	return nil
}
func (m *mockIntegrationPubSub) GetDirectChannel(ctx context.Context, peerId []byte, purpose string) (*grpc.ClientConn, error) {
	return nil, nil
}
func (m *mockIntegrationPubSub) SignMessage(msg []byte) ([]byte, error)       { return nil, nil }
func (m *mockIntegrationPubSub) GetPublicKey() []byte                         { return nil }
func (m *mockIntegrationPubSub) GetPeerScore(peerId []byte) int64             { return 0 }
func (m *mockIntegrationPubSub) SetPeerScore(peerId []byte, score int64)      {}
func (m *mockIntegrationPubSub) AddPeerScore(peerId []byte, scoreDelta int64) {}
func (m *mockIntegrationPubSub) Reconnect(peerId []byte) error                { return nil }
func (m *mockIntegrationPubSub) Bootstrap(ctx context.Context) error          { return nil }
func (m *mockIntegrationPubSub) DiscoverPeers(ctx context.Context) error      { return nil }
func (m *mockIntegrationPubSub) GetNetwork() uint                             { return 0 }
func (m *mockIntegrationPubSub) IsPeerConnected(peerId []byte) bool           { return false }
func (m *mockIntegrationPubSub) Reachability() *wrapperspb.BoolValue          { return nil }

// Helper functions

// calculateProverAddress calculates the prover address from public key using poseidon hash
func calculateProverAddress(publicKey []byte) []byte {
	hash, err := poseidon.HashBytes(publicKey)
	if err != nil {
		panic(err) // Should not happen in tests
	}
	return hash.FillBytes(make([]byte, 32))
}

// registerProverInHypergraph registers a prover without filter (for global consensus)
func registerProverInHypergraph(t *testing.T, hg thypergraph.Hypergraph, publicKey []byte, address []byte) {
	// Create the full address: GLOBAL_INTRINSIC_ADDRESS + prover address
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], address)

	// Create a VectorCommitmentTree with the prover data
	tree := &qcrypto.VectorCommitmentTree{}

	// Index 0: Public key
	err := tree.Insert([]byte{0}, publicKey, nil, big.NewInt(0))
	if err != nil {
		t.Fatalf("Failed to insert public key: %v", err)
	}

	// Index 1<<2 (4): Status (1 byte) - 1 = active
	err = tree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(0))
	if err != nil {
		t.Fatalf("Failed to insert status: %v", err)
	}

	// Type Index:
	typeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
	)
	tree.Insert(bytes.Repeat([]byte{0xff}, 32), typeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

	// Create allocation
	allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, []byte{}))
	require.NoError(t, err)
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

	allocationTree := &qcrypto.VectorCommitmentTree{}
	// Store allocation data
	err = allocationTree.Insert([]byte{0 << 2}, fullAddress[32:], nil, big.NewInt(0))
	require.NoError(t, err)
	err = allocationTree.Insert([]byte{2 << 2}, []byte{}, nil, big.NewInt(0))
	require.NoError(t, err)
	err = allocationTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(0)) // active
	require.NoError(t, err)
	joinFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinFrameBytes, 0)
	err = allocationTree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(0))
	require.NoError(t, err)
	allocationTypeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
	)
	allocationTree.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

	// Add the prover to the hypergraph
	inclusionProver := bls48581.NewKZGInclusionProver(zap.L())
	commitment := tree.Commit(inclusionProver, false)
	if len(commitment) != 74 && len(commitment) != 64 {
		t.Fatalf("Invalid commitment length: %d", len(commitment))
	}
	allocCommitment := allocationTree.Commit(inclusionProver, false)
	if len(allocCommitment) != 74 && len(allocCommitment) != 64 {
		t.Fatalf("Invalid commitment length: %d", len(allocCommitment))
	}

	// Add vertex to hypergraph
	txn, _ := hg.NewTransaction(false)
	err = hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(fullAddress[:32]), [32]byte(fullAddress[32:]), commitment, big.NewInt(0)))
	if err != nil {
		t.Fatalf("Failed to add prover vertex to hypergraph: %v", err)
	}
	err = hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(fullAddress[:32]), [32]byte(allocationAddress[:]), allocCommitment, big.NewInt(0)))
	if err != nil {
		t.Fatalf("Failed to add prover vertex to hypergraph: %v", err)
	}

	hg.SetVertexData(txn, fullAddress, tree)
	hg.SetVertexData(txn, [64]byte(slices.Concat(fullAddress[:32], allocationAddress)), allocationTree)
	txn.Commit()

	// Commit the hypergraph
	hg.Commit(0)

	t.Logf("    Registered global prover with address: %x (public key length: %d)", address, len(publicKey))
}

// Test helper to create a fully wired  engine for integration tests
func createIntegrationTestGlobalConsensusEngine(
	t *testing.T,
	peerID []byte,
	network uint8,
	h host.Host,
	privKey pcrypto.PrivKey,
	bootstrapHosts []host.Host,
) (
	*GlobalConsensusEngine,
	*mockIntegrationPubSub,
	*consensustime.GlobalTimeReel,
	func(),
) {
	return createIntegrationTestGlobalConsensusEngineWithHypergraph(t, peerID, nil, network, h, privKey, bootstrapHosts)
}

// createIntegrationTestGlobalConsensusEngineWithHypergraph creates an engine with optional shared hypergraph
func createIntegrationTestGlobalConsensusEngineWithHypergraph(
	t *testing.T,
	peerID []byte,
	sharedHypergraph thypergraph.Hypergraph,
	network uint8,
	h host.Host,
	privKey pcrypto.PrivKey,
	bootstrapHosts []host.Host,
) (
	*GlobalConsensusEngine,
	*mockIntegrationPubSub,
	*consensustime.GlobalTimeReel,
	func(),
) {
	return createIntegrationTestGlobalConsensusEngineWithHypergraphAndKey(t, peerID, sharedHypergraph, nil, network, h, privKey, bootstrapHosts)
}

// createIntegrationTestGlobalConsensusEngineWithHypergraphAndKey creates an engine with optional shared hypergraph and pre-generated key
func createIntegrationTestGlobalConsensusEngineWithHypergraphAndKey(
	t *testing.T,
	peerID []byte,
	sharedHypergraph thypergraph.Hypergraph,
	preGeneratedKey *tkeys.Key,
	network uint8,
	h host.Host,
	privKey pcrypto.PrivKey,
	bootstrapHosts []host.Host,
) (
	*GlobalConsensusEngine,
	*mockIntegrationPubSub,
	*consensustime.GlobalTimeReel,
	func(),
) {
	logcfg := zap.NewDevelopmentConfig()
	if preGeneratedKey != nil {
		adBI, _ := poseidon.HashBytes(preGeneratedKey.PublicKey)
		addr := adBI.FillBytes(make([]byte, 32))
		logcfg.EncoderConfig.TimeKey = "M"
		logcfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(fmt.Sprintf("node | %s", hex.EncodeToString(addr)[:10]))
		}
	}
	logger, _ := logcfg.Build()

	// Create unique in-memory key manager for each node
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	// Create alert signer and put it in the config
	alertSigner, _, _ := keyManager.CreateSigningKey("alert-key", crypto.KeyTypeEd448)
	pub := alertSigner.Public().([]byte)
	alertHex := hex.EncodeToString(pub)

	// Set up peer key
	peerkey, _, _ := keyManager.CreateSigningKey("q-peer-key", crypto.KeyTypeEd448)
	peerpriv := peerkey.Private()
	peerHex := hex.EncodeToString(peerpriv)
	p2pcfg := config.P2PConfig{}.WithDefaults()

	p2pcfg.Network = network
	p2pcfg.PeerPrivKey = peerHex
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	cfg := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   100,
			ProvingKeyId: "q-prover-key", // Always use the required key ID
			AlertKey:     alertHex,
			ArchiveMode:  true,
		},
		P2P: &p2pcfg,
	}

	// Create the required "q-prover-key"
	var proverKey crypto.Signer
	var err error

	if preGeneratedKey != nil {
		// Use the pre-generated key from the multi-node test
		preGeneratedKey.Id = "q-prover-key"
		err = keyManager.PutRawKey(preGeneratedKey)
		require.NoError(t, err)

		proverKey, err = keyManager.GetSigningKey("q-prover-key")
		require.NoError(t, err)
	} else {
		// Single node test - just create the key normally
		proverKey, _, err = keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
	}

	// Create stores
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/global"}, 0)

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	// Create or use shared hypergraph
	var hg thypergraph.Hypergraph
	if sharedHypergraph != nil {
		hg = sharedHypergraph
	} else {
		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/global"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg = hgcrdt.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})
	}

	// Create key store
	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

	// Create clock store
	clockStore := store.NewPebbleClockStore(pebbleDB, logger)

	// Create concrete components
	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)

	// Create prover registry with hypergraph
	proverRegistry, err := provers.NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Register multiple provers in hypergraph (no filter for global)
	// We need at least a few provers for the consensus to work
	proverKeys := []crypto.Signer{proverKey}

	// Only register provers if we're creating a new hypergraph
	if sharedHypergraph == nil {
		// Register all provers
		for i, key := range proverKeys {
			proverAddress := calculateProverAddress(key.Public().([]byte))
			registerProverInHypergraph(t, hg, key.Public().([]byte), proverAddress)
			t.Logf("Registered prover %d with address: %x", i, proverAddress)
		}
	}

	// Refresh the prover registry
	proverRegistry.Refresh()

	// Create fee manager
	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	// Create validators and adjusters
	appFrameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	frameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	// Create pubsub
	pubsub := newMockIntegrationPubSub(cfg, logger, peerID, h, privKey, bootstrapHosts)

	// Create time reel
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, network, true)
	require.NoError(t, err)

	// Create event distributor
	eventDistributor := events.NewGlobalEventDistributor(
		globalTimeReel.GetEventCh(),
	)

	// Create engine
	engine, err := NewGlobalConsensusEngine(
		logger,
		cfg,
		1000, // frameTimeMillis
		pubsub,
		hg,
		keyManager,
		keyStore,
		frameProver,
		inclusionProver,
		signerRegistry,
		proverRegistry,
		dynamicFeeManager,
		appFrameValidator,
		frameValidator,
		difficultyAdjuster,
		rewardIssuance,
		eventDistributor,
		globalTimeReel,
		clockStore,
		nil, // inboxStore
		nil, // hypergraphStore
		store.NewPebbleShardsStore(pebbleDB, logger),
		store.NewPebbleWorkerStore(pebbleDB, logger),
		channel.NewDoubleRatchetEncryptedChannel(), // encryptedChannel
		&bulletproofs.Decaf448BulletproofProver{},  // bulletproofProver
		&verenc.MPCitHVerifiableEncryptor{},        // verEnc
		&bulletproofs.Decaf448KeyConstructor{},     // decafConstructor
		compiler.NewBedlamCompiler(),
		nil,
		nil,
	)
	require.NoError(t, err)

	cleanup := func() {
		engine.Stop(false)
	}

	return engine, pubsub, globalTimeReel, cleanup
}

func TestGlobalConsensusEngine_Integration_BasicFrameProgression(t *testing.T) {
	// Generate hosts for testing
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanupHosts()

	engine, pubsub, _, _ := createIntegrationTestGlobalConsensusEngine(t, []byte(m.Nodes[0].ID()), 99, m.Nodes[0], m.Keys[0], m.Nodes)

	// Track published frames
	publishedFrames := make([]*protobufs.GlobalFrame, 0)
	var mu sync.Mutex
	pubsub.onPublish = func(bitmask []byte, data []byte) {
		// Check if data is long enough to contain type prefix
		if len(data) >= 4 {
			// Read type prefix from first 4 bytes
			typePrefix := binary.BigEndian.Uint32(data[:4])

			// Check if it's a GlobalFrame
			if typePrefix == protobufs.GlobalFrameType {
				frame := &protobufs.GlobalFrame{}
				if err := frame.FromCanonicalBytes(data); err == nil {
					mu.Lock()
					publishedFrames = append(publishedFrames, frame)
					mu.Unlock()
				}
			}
		}
	}

	// Start the engine
	quit := make(chan struct{})
	errChan := engine.Start(quit)

	// Check for startup errors
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		// No error is good
	}

	// Wait for state transitions
	time.Sleep(2 * time.Second)

	// Verify engine is in an active state
	state := engine.GetState()
	t.Logf("Current engine state: %v", state)
	assert.NotEqual(t, tconsensus.EngineStateStopped, state)
	assert.NotEqual(t, tconsensus.EngineStateStarting, state)

	// Wait for frame processing
	time.Sleep(10 * time.Second)

	// Check if frames were published
	mu.Lock()
	frameCount := len(publishedFrames)
	mu.Unlock()

	t.Logf("Published %d frames", frameCount)

	// Stop the engine
	close(quit)
	<-engine.Stop(false)
}

func TestGlobalConsensusEngine_Integration_StateTransitions(t *testing.T) {
	// Generate hosts for testing
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanupHosts()

	engine, _, _, _ := createIntegrationTestGlobalConsensusEngine(t, []byte(m.Nodes[0].ID()), 99, m.Nodes[0], m.Keys[0], m.Nodes)

	// Track state transitions
	transitions := make([]string, 0)
	var mu sync.Mutex

	listener := &testTransitionListener{
		onTransition: func(from, to consensus.State, event consensus.Event) {
			mu.Lock()
			transitions = append(transitions, fmt.Sprintf("%s->%s", from, to))
			mu.Unlock()
			t.Logf("State transition: %s -> %s (event: %s)", from, to, event)
		},
	}

	// Start the engine
	quit := make(chan struct{})
	errChan := engine.Start(quit)
	engine.stateMachine.AddListener(listener)

	// Check for startup errors
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		// No error is good
	}

	// Wait for state transitions
	time.Sleep(10 * time.Second)

	// Verify we had some state transitions
	mu.Lock()
	transitionCount := len(transitions)
	mu.Unlock()

	assert.Greater(t, transitionCount, 0, "Expected at least one state transition")

	// Stop the engine
	close(quit)
	<-engine.Stop(false)
}

func TestGlobalConsensusEngine_Integration_MultiNodeConsensus(t *testing.T) {
	// Generate hosts for all 6 nodes first
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, 6, []libp2p.Option{})
	defer cleanupHosts()

	// Create shared components first
	logger, _ := zap.NewDevelopment()

	// Create shared hypergraph that all nodes will use
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/global_shared"}, 0)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	hypergraphStores := make([]*store.PebbleHypergraphStore, 6)
	hypergraphs := make([]*hgcrdt.HypergraphCRDT, 6)

	// Create a temporary key manager to generate keys for hypergraph registration
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}

	// Create and store raw keys for all nodes
	nodeRawKeys := make([]*tkeys.Key, 6)

	// Create and register 6 provers (one for each node)
	for i := 0; i < 6; i++ {
		hypergraphStores[i] = store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/global_shared"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hypergraphs[i] = hgcrdt.NewHypergraph(logger, hypergraphStores[i], inclusionProver, []int{}, &tests.Nopthenticator{})
	}
	for i := 0; i < 6; i++ {
		tempKeyManager := keys.NewInMemoryKeyManager(bc, dc)

		proverKey, _, err := tempKeyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)

		// Get the raw key for later use
		rawKey, err := tempKeyManager.GetRawKey("q-prover-key")
		require.NoError(t, err)
		nodeRawKeys[i] = rawKey

		proverAddress := calculateProverAddress(proverKey.Public().([]byte))
		registerProverInHypergraph(t, hypergraphs[0], proverKey.Public().([]byte), proverAddress)
		registerProverInHypergraph(t, hypergraphs[1], proverKey.Public().([]byte), proverAddress)
		registerProverInHypergraph(t, hypergraphs[2], proverKey.Public().([]byte), proverAddress)
		registerProverInHypergraph(t, hypergraphs[3], proverKey.Public().([]byte), proverAddress)
		registerProverInHypergraph(t, hypergraphs[4], proverKey.Public().([]byte), proverAddress)
		registerProverInHypergraph(t, hypergraphs[5], proverKey.Public().([]byte), proverAddress)
		t.Logf("Registered prover %d with address: %x", i, proverAddress)
	}

	// Commit the hypergraph
	for i := 0; i < 6; i++ {
		hypergraphs[i].Commit(0)
	}

	// Create six engines that can communicate (minimum required for consensus)
	engines := make([]*GlobalConsensusEngine, 6)
	pubsubs := make([]*mockIntegrationPubSub, 6)

	for i := 0; i < 6; i++ {
		peerID := []byte(m.Nodes[i].ID())
		engine, pubsub, _, _ := createIntegrationTestGlobalConsensusEngineWithHypergraphAndKey(t, peerID, hypergraphs[i], nodeRawKeys[i], 1, m.Nodes[i], m.Keys[i], m.Nodes)
		engines[i] = engine
		pubsubs[i] = pubsub
	}

	// Connect all pubsubs to each other
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			if i != j {
				tests.ConnectSimnetHosts(t, m.Nodes[i], m.Nodes[j])
				pubsubs[i].networkPeers[fmt.Sprintf("peer%d", j)] = pubsubs[j]
			}
		}
	}

	// Track frames and messages from all nodes
	allFrames := make([][]*protobufs.GlobalFrame, 6)
	proposalCount := make([]int, 6)
	voteCount := make([]int, 6)
	livenessCount := make([]int, 6)
	var mu sync.Mutex

	for i := 0; i < 6; i++ {
		nodeIdx := i
		pubsubs[i].onPublish = func(bitmask []byte, data []byte) {
			// Check if data is long enough to contain type prefix
			if len(data) >= 4 {
				// Read type prefix from first 4 bytes
				typePrefix := binary.BigEndian.Uint32(data[:4])

				// Check if it's a GlobalFrame
				if typePrefix == protobufs.GlobalFrameType {
					frame := &protobufs.GlobalFrame{}
					if err := frame.FromCanonicalBytes(data); err == nil {
						mu.Lock()
						allFrames[nodeIdx] = append(allFrames[nodeIdx], frame)
						mu.Unlock()
						t.Logf("Node %d published frame %d", nodeIdx+1, frame.Header.FrameNumber)
					}
				}
			}
		}

		// Track message processing
		pubsubs[i].Subscribe([]byte{0x00}, func(msg *pb.Message) error {
			// Check if data is long enough to contain type prefix
			if len(msg.Data) >= 4 {
				// Read type prefix from first 4 bytes
				typePrefix := binary.BigEndian.Uint32(msg.Data[:4])

				mu.Lock()
				defer mu.Unlock()
				switch typePrefix {
				case protobufs.GlobalFrameType:
					proposalCount[nodeIdx]++
				case protobufs.FrameVoteType:
					voteCount[nodeIdx]++
				case protobufs.ProverLivenessCheckType:
					livenessCount[nodeIdx]++
				}
			}
			return nil
		})
	}

	// Start all engines
	quits := make([]chan struct{}, 6)
	for i := 0; i < 6; i++ {
		quits[i] = make(chan struct{})
		errChan := engines[i].Start(quits[i])

		// Check for startup errors
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(100 * time.Millisecond):
			// No error is good
		}
	}

	// Let the engines run and reach initial sync
	time.Sleep(5 * time.Second)

	// Monitor state transitions and ensure all proposals are seen
	proposalsSeen := make([]bool, 6)
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Wait for all nodes to see all proposals
loop:
	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for all nodes to see proposals")
		case <-ticker.C:
			// Check if all nodes have seen at least 5 proposals (from other nodes)
			allSeen := true
			mu.Lock()
			for i := 0; i < 6; i++ {
				if proposalCount[i] < 5 {
					allSeen = false
				} else if !proposalsSeen[i] {
					proposalsSeen[i] = true
					t.Logf("Node %d has seen %d proposals", i+1, proposalCount[i])
				}
			}
			mu.Unlock()

			if allSeen {
				// Wait for message deliveries to complete
				time.Sleep(1 * time.Second)
				t.Log("All nodes have seen all proposals, proceeding")
				break loop
			}

			// Log current state
			for i := 0; i < 6; i++ {
				state := engines[i].GetState()
				mu.Lock()
				t.Logf("Engine %d state: %v, proposals: %d, votes: %d, liveness: %d",
					i+1, state, proposalCount[i], voteCount[i], livenessCount[i])
				mu.Unlock()
			}
		}
	}

	// Give time for voting and finalization
	time.Sleep(10 * time.Second)

	// Check states after consensus
	for i := 0; i < 6; i++ {
		state := engines[i].GetState()
		mu.Lock()
		t.Logf("Final Engine %d state: %v, proposals: %d, votes: %d",
			i+1, state, proposalCount[i], voteCount[i])
		mu.Unlock()
	}

	// Check if any frames were published
	mu.Lock()
	totalFrames := 0
	for i := 0; i < 6; i++ {
		totalFrames += len(allFrames[i])
	}
	mu.Unlock()

	t.Logf("Total frames published across all nodes: %d", totalFrames)

	// Stop all engines
	for i := 0; i < 6; i++ {
		close(quits[i])
		<-engines[i].Stop(false)
	}
}

func TestGlobalConsensusEngine_Integration_ShardCoverage(t *testing.T) {
	// This test needs to run long enough to hit the condition required
	if testing.Short() {
		t.Skip("Skipping shard coverage scenario test in short mode")
	}

	// Generate hosts for testing
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanupHosts()

	pebbleDB := store.NewPebbleDB(zap.L(), &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/global_shared"}, 0)

	inclusionProver := bls48581.NewKZGInclusionProver(zap.L())
	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{
		InMemoryDONOTUSE: true,
		Path:             ".test/global",
	}, pebbleDB, zap.L(), &verenc.MPCitHVerifiableEncryptor{}, inclusionProver)
	hg := hgcrdt.NewHypergraph(zap.NewNop(), hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})
	for i := range 6 {
		k := make([]byte, 585)
		k[1] = byte(i)
		abi, _ := poseidon.HashBytes(k)
		registerProverInHypergraphWithFilter(t, hg, k, abi.FillBytes(make([]byte, 32)), []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	}
	engine, _, _, _ := createIntegrationTestGlobalConsensusEngineWithHypergraphAndKey(t, []byte(m.Nodes[0].ID()), hg, nil, 1, m.Nodes[0], m.Keys[0], m.Nodes)

	// simulate a one byte vertex so the shard has space being used
	txn, _ := hg.NewTransaction(false)
	c := make([]byte, 74)
	c[0] = 0x02
	hg.AddVertex(txn, hgcrdt.NewVertex([32]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}, [32]byte{}, c, big.NewInt(1)))
	txn.Commit()

	// Track emitted events
	var publishedEvents []tconsensus.ControlEvent
	var mu sync.Mutex

	// Replace event distributor to capture events
	eventDistributor := events.NewGlobalEventDistributor(nil)

	// Subscribe to capture events
	eventCh := eventDistributor.Subscribe("test")
	go func() {
		for event := range eventCh {
			mu.Lock()
			publishedEvents = append(publishedEvents, event)
			mu.Unlock()
			t.Logf("Event published: %d", event.Type)
		}
	}()

	engine.eventDistributor = eventDistributor

	// Start the event distributor
	engine.Start(make(chan struct{}))

	// Run shard coverage check
	err := engine.checkShardCoverage(1)
	require.NoError(t, err)

	// Wait for event processing and possible new app shard head
	time.Sleep(1800 * time.Second)
	mu.Lock()
	found := false
	newHeadAfter := false
	for _, e := range publishedEvents {
		if e.Type == tconsensus.ControlEventCoverageHalt {
			found = true
		}
		if found && e.Type == tconsensus.ControlEventAppNewHead {
			newHeadAfter = true
		}
	}
	mu.Unlock()

	require.True(t, found)
	require.False(t, newHeadAfter)

	// Stop the event distributor
	eventDistributor.Stop()
}

// TestGlobalConsensusEngine_Integration_NoProversStaysInVerifying tests that engines
// remain in the verifying state when no provers are registered in the hypergraph
func TestGlobalConsensusEngine_Integration_NoProversStaysInVerifying(t *testing.T) {
	t.Log("Testing global consensus engines with no registered provers")

	// Create six nodes
	numNodes := 6

	// Generate hosts for all nodes first
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, numNodes, []libp2p.Option{})
	defer cleanupHosts()

	// Create shared components
	logger, _ := zap.NewDevelopment()

	engines := make([]*GlobalConsensusEngine, numNodes)
	pubsubs := make([]*mockIntegrationPubSub, numNodes)
	quits := make([]chan struct{}, numNodes)

	// Create shared hypergraph with NO provers registered
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	// Create separate hypergraph and prover registry for each node to ensure isolation
	for i := 0; i < numNodes; i++ {
		nodeID := i + 1
		peerID := []byte(m.Nodes[i].ID())

		t.Logf("Creating node %d with peer ID: %x", nodeID, peerID)

		// Create unique components for each node
		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{
			InMemoryDONOTUSE: true,
			Path:             fmt.Sprintf(".test/global_no_provers_%d", nodeID),
		}, 0)

		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{
			InMemoryDONOTUSE: true,
			Path:             fmt.Sprintf(".test/global_no_provers_%d", nodeID),
		}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hgcrdt.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

		// Create prover registry - but don't register any provers
		proverRegistry, err := provers.NewProverRegistry(logger, hg)
		require.NoError(t, err)

		// Create key manager with prover key (but not registered in hypergraph)
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManager := keys.NewInMemoryKeyManager(bc, dc)
		_, _, err = keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)

		// Create other components
		keyStore := store.NewPebbleKeyStore(pebbleDB, logger)
		clockStore := store.NewPebbleClockStore(pebbleDB, logger)
		frameProver := vdf.NewWesolowskiFrameProver(logger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		// Create global time reel
		globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)
		require.NoError(t, err)

		eventDistributor := events.NewGlobalEventDistributor(
			globalTimeReel.GetEventCh(),
		)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)
		appFrameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		frameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 10)
		rewardIssuance := reward.NewOptRewardIssuance()

		// Set up peer key
		peerkey, _, _ := keyManager.CreateSigningKey("q-peer-key", crypto.KeyTypeEd448)
		peerpriv := peerkey.Private()
		peerHex := hex.EncodeToString(peerpriv)

		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 2
		p2pcfg.PeerPrivKey = peerHex
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		cfg := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   10,
				ProvingKeyId: "q-prover-key",
				GenesisSeed:  strings.Repeat("00", 585),
			},
			P2P: &p2pcfg,
		}

		// Create pubsub with host and key
		pubsubs[i] = newMockIntegrationPubSub(cfg, logger, peerID, m.Nodes[i], m.Keys[i], m.Nodes)
		pubsubs[i].peerCount = 10 // Set high peer count
		// Create engine
		engine, err := NewGlobalConsensusEngine(
			logger,
			cfg,
			1000, // frameTimeMillis
			pubsubs[i],
			hg,
			keyManager,
			keyStore,
			frameProver,
			inclusionProver,
			signerRegistry,
			proverRegistry,
			dynamicFeeManager,
			appFrameValidator,
			frameValidator,
			difficultyAdjuster,
			rewardIssuance,
			eventDistributor,
			globalTimeReel,
			clockStore,
			nil, // inboxStore
			nil, // hypergraphStore
			store.NewPebbleShardsStore(pebbleDB, logger),
			store.NewPebbleWorkerStore(pebbleDB, logger),
			channel.NewDoubleRatchetEncryptedChannel(),
			&bulletproofs.Decaf448BulletproofProver{}, // bulletproofProver
			&verenc.MPCitHVerifiableEncryptor{},       // verEnc
			&bulletproofs.Decaf448KeyConstructor{},    // decafConstructor
			compiler.NewBedlamCompiler(),
			nil, // blsConstructor
			nil,
		)
		require.NoError(t, err)

		engines[i] = engine
		quits[i] = make(chan struct{})
	}

	// Wire up all pubsubs to each other
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i != j {
				pubsubs[i].networkPeers[fmt.Sprintf("peer%d", j)] = pubsubs[j]
			}
		}
	}

	// Start all engines
	for i := 0; i < numNodes; i++ {
		errChan := engines[i].Start(quits[i])
		select {
		case err := <-errChan:
			require.NoError(t, err)
		case <-time.After(100 * time.Millisecond):
			// No error is good
		}
	}

	// Let engines run for a while
	t.Log("Letting engines run for 10 seconds...")
	time.Sleep(10 * time.Second)

	// Check that all engines are still in loading state
	for i := 0; i < numNodes; i++ {
		state := engines[i].GetState()
		t.Logf("Node %d state: %v", i+1, state)

		// Should be in loading state since no provers are registered
		assert.Equal(t, tconsensus.EngineStateVerifying, state,
			"Node %d should be in verifying state when no provers are registered", i+1)
	}

	// Stop all engines
	for i := 0; i < numNodes; i++ {
		close(quits[i])
		<-engines[i].Stop(false)
	}

	t.Log("Test completed - all nodes remained in verifying state as expected")
}

// TestGlobalConsensusEngine_Integration_AlertStopsProgression tests that engines
// halt when an alert broadcast occurs
func TestGlobalConsensusEngine_Integration_AlertStopsProgression(t *testing.T) {
	// Generate hosts for testing
	_, m, cleanupHosts := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanupHosts()

	engine, pubsub, _, _ := createIntegrationTestGlobalConsensusEngine(t, []byte(m.Nodes[0].ID()), 99, m.Nodes[0], m.Keys[0], m.Nodes)

	// Track published frames
	publishedFrames := make([]*protobufs.GlobalFrame, 0)
	afterAlertFrames := make([]*protobufs.GlobalFrame, 0)
	afterAlert := false

	var mu sync.Mutex
	pubsub.onPublish = func(bitmask []byte, data []byte) {
		// Check if data is long enough to contain type prefix
		if len(data) >= 4 {
			// Read type prefix from first 4 bytes
			typePrefix := binary.BigEndian.Uint32(data[:4])

			// Check if it's a GlobalFrame
			if typePrefix == protobufs.GlobalFrameType {
				frame := &protobufs.GlobalFrame{}
				if err := frame.FromCanonicalBytes(data); err == nil {
					mu.Lock()
					if afterAlert {
						afterAlertFrames = append(afterAlertFrames, frame)
					} else {
						publishedFrames = append(publishedFrames, frame)
					}
					mu.Unlock()
				}
			}
		}
	}

	// Start the engine
	quit := make(chan struct{})
	errChan := engine.Start(quit)

	// Check for startup errors
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		// No error is good
	}

	// Wait for state transitions
	time.Sleep(10 * time.Second)

	// Verify engine is in an active state
	state := engine.GetState()
	t.Logf("Current engine state: %v", state)
	assert.NotEqual(t, tconsensus.EngineStateStopped, state)
	assert.NotEqual(t, tconsensus.EngineStateStarting, state)

	// Wait for frame processing
	time.Sleep(10 * time.Second)

	alertKey, _ := engine.keyManager.GetSigningKey("alert-key")
	sig, _ := alertKey.SignWithDomain([]byte("It's time to stop!"), []byte("GLOBAL_ALERT"))
	alertMessage := &protobufs.GlobalAlert{
		Message:   "It's time to stop!",
		Signature: sig,
	}

	alertMessageBytes, _ := alertMessage.ToCanonicalBytes()

	// Send alert
	engine.globalAlertMessageQueue <- &pb.Message{
		From: []byte{0x00},
		Data: alertMessageBytes,
	}

	// Wait for event bus to catch up
	time.Sleep(1 * time.Second)

	mu.Lock()
	afterAlert = true
	mu.Unlock()

	// Wait for any new messages to flow after
	time.Sleep(10 * time.Second)

	// Check if frames were published
	mu.Lock()
	frameCount := len(publishedFrames)
	afterAlertCount := len(afterAlertFrames)
	mu.Unlock()

	t.Logf("Published %d frames before alert", frameCount)
	t.Logf("Published %d frames after alert", afterAlertCount)

	require.Equal(t, 0, afterAlertCount)

	// Stop the engine
	close(quit)
	<-engine.Stop(false)
}

// registerProverInHypergraphWithFilter registers a prover with a specific filter (shard address)
func registerProverInHypergraphWithFilter(t *testing.T, hg thypergraph.Hypergraph, publicKey []byte, address []byte, filter []byte) {
	// Create the full address: GLOBAL_INTRINSIC_ADDRESS + prover address
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], address)

	// Create a VectorCommitmentTree with the prover data
	tree := &qcrypto.VectorCommitmentTree{}

	// Index 0: Public key
	err := tree.Insert([]byte{0}, publicKey, nil, big.NewInt(0))
	if err != nil {
		t.Fatalf("Failed to insert public key: %v", err)
	}

	// Index 1<<2 (4): Status (1 byte) - 1 = active
	err = tree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(0))
	if err != nil {
		t.Fatalf("Failed to insert status: %v", err)
	}

	// Type Index:
	typeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
	)
	tree.Insert(bytes.Repeat([]byte{0xff}, 32), typeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

	// Create allocation
	allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), publicKey, []byte{}))
	require.NoError(t, err)
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

	allocationTree := &qcrypto.VectorCommitmentTree{}
	// Store allocation data
	err = allocationTree.Insert([]byte{0 << 2}, fullAddress[32:], nil, big.NewInt(0))
	require.NoError(t, err)
	err = allocationTree.Insert([]byte{2 << 2}, filter, nil, big.NewInt(0)) // confirm filter
	require.NoError(t, err)
	err = allocationTree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(0)) // active
	require.NoError(t, err)
	joinFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinFrameBytes, 0)
	err = allocationTree.Insert([]byte{4 << 2}, joinFrameBytes, nil, big.NewInt(0))
	require.NoError(t, err)
	allocationTypeBI, _ := poseidon.HashBytes(
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
	)
	allocationTree.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

	// Add the prover to the hypergraph
	inclusionProver := bls48581.NewKZGInclusionProver(zap.L())
	commitment := tree.Commit(inclusionProver, false)
	if len(commitment) != 74 && len(commitment) != 64 {
		t.Fatalf("Invalid commitment length: %d", len(commitment))
	}
	allocCommitment := allocationTree.Commit(inclusionProver, false)
	if len(allocCommitment) != 74 && len(allocCommitment) != 64 {
		t.Fatalf("Invalid commitment length: %d", len(allocCommitment))
	}

	// Add vertex to hypergraph
	txn, _ := hg.NewTransaction(false)
	err = hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(fullAddress[:32]), [32]byte(fullAddress[32:]), commitment, big.NewInt(0)))
	if err != nil {
		t.Fatalf("Failed to add prover vertex to hypergraph: %v", err)
	}
	err = hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(fullAddress[:32]), [32]byte(allocationAddress[:]), allocCommitment, big.NewInt(0)))
	if err != nil {
		t.Fatalf("Failed to add prover vertex to hypergraph: %v", err)
	}

	hg.SetVertexData(txn, fullAddress, tree)
	hg.SetVertexData(txn, [64]byte(slices.Concat(fullAddress[:32], allocationAddress)), allocationTree)
	txn.Commit()

	// Commit the hypergraph
	hg.Commit(0)

	t.Logf("    Registered prover with address: %x, filter: %x (public key length: %d)", address, filter, len(publicKey))
}
