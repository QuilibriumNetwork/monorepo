//go:build integrationtest
// +build integrationtest

package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/channel"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/difficulty"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/events"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/registration"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	tstore "source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// computeParentSelector computes the parent selector from a frame's output using Poseidon hash
func computeParentSelector(output []byte) ([]byte, error) {
	if len(output) < 32 {
		return nil, fmt.Errorf("output too short: %d bytes", len(output))
	}

	// Hash the output using Poseidon
	hash, err := poseidon.HashBytes(output)
	if err != nil {
		return nil, err
	}

	// Convert to 32 bytes
	parentSelector := hash.FillBytes(make([]byte, 32))
	return parentSelector, nil
}

// Scenario: Single app shard progresses through frames with fee voting
// Expected: Frames produced with appropriate fee votes
func TestAppConsensusEngine_Integration_BasicFrameProgression(t *testing.T) {
	t.Log("Testing basic app shard frame progression")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03, 0xAA, 0x01, 0x02, 0x03} // App shard address
	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	t.Logf("  - App shard address: %x", appAddress)
	t.Logf("  - Peer ID: %x", peerID)

	// Create in-memory key manager
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	proverKey, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	t.Logf("  - Created prover key: %x", proverKey.Public().([]byte)[:16]) // Log first 16 bytes
	cfg := zap.NewDevelopmentConfig()
	adBI, _ := poseidon.HashBytes(proverKey.Public().([]byte))
	addr := adBI.FillBytes(make([]byte, 32))
	cfg.EncoderConfig.TimeKey = "M"
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(fmt.Sprintf("node %d | %s", 0, hex.EncodeToString(addr)[:10]))
	}
	logger, _ := cfg.Build()
	// Create stores
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_basic"}, 0)

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bulletproof := bulletproofs.NewBulletproofProver()
	decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	compiler := compiler.NewBedlamCompiler()

	// Create hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_basic"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
	hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

	// Create key store
	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

	// Create clock store
	clockStore := store.NewPebbleClockStore(pebbleDB, logger)

	// Create inbox store
	inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)

	// Create shards store
	shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)

	// Create concrete components
	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)

	// Create prover registry with hypergraph
	proverRegistry, err := provers.NewProverRegistry(logger, hg)
	require.NoError(t, err)

	// Create peer info manager
	peerInfoManager := qp2p.NewInMemoryPeerInfoManager(logger)

	// Create fee manager and track votes
	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	// Establish prover key in genesis seed
	seed := []byte{}
	seed = append(seed, proverKey.Public().([]byte)...)
	seedHex := hex.EncodeToString(seed)

	p2pcfg := config.P2PConfig{}.WithDefaults()
	p2pcfg.Network = 1
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	p2pcfg.MinBootstrapPeers = 0
	p2pcfg.DiscoveryPeerLookupLimit = 0
	p2pcfg.D = 0
	p2pcfg.DLo = 0
	p2pcfg.DHi = 0
	p2pcfg.DScore = 0
	p2pcfg.DOut = 0
	p2pcfg.DLazy = 0
	config := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   80000,
			ProvingKeyId: "q-prover-key",
			GenesisSeed:  seedHex,
		},
		P2P: &p2pcfg,
	}
	// Calculate prover address using poseidon hash
	proverAddress := calculateProverAddress(proverKey.Public().([]byte))
	// Register prover in hypergraph
	registerProverInHypergraphWithFilter(t, hg, proverKey.Public().([]byte), proverAddress, appAddress)
	t.Logf("  - Registered prover %d with address: %x", 0, proverAddress)

	// Refresh the prover registry to pick up the newly added provers
	err = proverRegistry.Refresh()
	require.NoError(t, err)
	_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanup()
	pubsub := newMockAppIntegrationPubSub(config, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)

	pubsub.peerCount = 0

	// Create global time reel (needed for app consensus)
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)
	require.NoError(t, err)

	// Create factory and engine
	factory := NewAppConsensusEngineFactory(
		logger,
		config,
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
		shardsStore,
		hypergraphStore,
		frameProver,
		inclusionProver,
		bulletproof,
		verifiableEncryptor,
		decafConstructor,
		compiler,
		signerRegistry,
		proverRegistry,
		peerInfoManager,
		dynamicFeeManager,
		frameValidator,
		globalFrameValidator,
		difficultyAdjuster,
		rewardIssuance,
		&mocks.MockBlsConstructor{},
		channel.NewDoubleRatchetEncryptedChannel(),
	)

	engine, err := factory.CreateAppConsensusEngine(
		appAddress,
		0, // coreId
		globalTimeReel,
		nil,
	)
	require.NoError(t, err)
	mockGSC := &mockGlobalClientLocks{}
	engine.SetGlobalClient(mockGSC)

	// Track frames and fee votes
	frameHistory := make([]*protobufs.AppShardFrame, 0)
	var framesMu sync.Mutex

	// Subscribe to frames
	pubsub.Subscribe(engine.getConsensusMessageBitmask(), func(message *pb.Message) error {
		// Check if data is long enough to contain type prefix
		if len(message.Data) < 4 {
			return errors.New("message too short")
		}

		// Read type prefix from first 4 bytes
		typePrefix := binary.BigEndian.Uint32(message.Data[:4])

		switch typePrefix {
		case protobufs.AppShardFrameType:
			frame := &protobufs.AppShardFrame{}
			if err := frame.FromCanonicalBytes(message.Data); err != nil {
				return errors.New("error")
			}
			framesMu.Lock()
			frameHistory = append(frameHistory, frame)
			framesMu.Unlock()

		case protobufs.ProverLivenessCheckType:
			livenessCheck := &protobufs.ProverLivenessCheck{}
			if err := livenessCheck.FromCanonicalBytes(message.Data); err != nil {
				return errors.New("error")
			}

		case protobufs.FrameVoteType:
			vote := &protobufs.FrameVote{}
			if err := vote.FromCanonicalBytes(message.Data); err != nil {
				return errors.New("error")
			}

		case protobufs.FrameConfirmationType:
			confirmation := &protobufs.FrameConfirmation{}
			if err := confirmation.FromCanonicalBytes(message.Data); err != nil {
				return errors.New("error")
			}

		default:
			return errors.New("error")
		}
		return nil
	})

	// Start engine
	t.Log("Step 2: Starting consensus engine")
	quit := make(chan struct{})
	errChan := engine.Start(quit)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
	}
	t.Log("  - Engine started successfully")

	// Wait for genesis initialization
	t.Log("Step 3: Waiting for genesis initialization (0 peers)")
	time.Sleep(2 * time.Second)

	// Now increase peer count to allow normal operation
	t.Log("Step 4: Enabling normal operation")
	pubsub.peerCount = 10
	t.Log("  - Increased peer count to 10")

	// Let it run
	t.Log("Step 5: Letting engine run and produce frames")
	time.Sleep(20 * time.Second)

	// Verify results
	t.Log("Step 6: Verifying results")
	frame := engine.GetFrame()
	assert.NotNil(t, frame)
	if frame != nil && frame.Header != nil {
		t.Logf("  ✓ Current frame number: %d", frame.Header.FrameNumber)
	}

	// Wait a bit more to ensure we capture all frames
	time.Sleep(500 * time.Millisecond)

	framesMu.Lock()
	t.Logf("  - Total frames received: %d", len(frameHistory))
	assert.GreaterOrEqual(t, len(frameHistory), 2)

	// Check fee votes
	hasNonZeroFeeVote := false
	for _, f := range frameHistory {
		if f.Header.FeeMultiplierVote > 0 {
			hasNonZeroFeeVote = true
			break
		}
	}
	t.Logf("  - Has non-zero fee votes: %v", hasNonZeroFeeVote)
	assert.True(t, hasNonZeroFeeVote, "Should have fee votes in frames")

	// Verify parent selector chain consistency
	if len(frameHistory) >= 2 {
		t.Log("  - Verifying parent selector chain:")
		for i := 1; i < len(frameHistory); i++ {
			currentFrame := frameHistory[i]
			previousFrame := frameHistory[i-1]

			// The current frame's parent selector should be the Poseidon hash of the previous frame's output
			if len(previousFrame.Header.Output) >= 32 {
				expectedParentSelector, err := computeParentSelector(previousFrame.Header.Output)
				require.NoError(t, err, "Failed to compute parent selector")

				assert.Equal(t, expectedParentSelector, currentFrame.Header.ParentSelector,
					"Frame %d parent selector should match Poseidon hash of previous frame's output", currentFrame.Header.FrameNumber)
				t.Logf("    ✓ Frame %d parent selector matches hash of frame %d output",
					currentFrame.Header.FrameNumber, previousFrame.Header.FrameNumber)
			}
		}
	}
	framesMu.Unlock()

	// Stop
	t.Log("Step 8: Cleaning up")
	engine.UnregisterExecutor("test-executor", 0, false)
	engine.Stop(false)
}

// Scenario: Multiple nodes vote on fees, consensus emerges
// Expected: Fee multiplier adjusts based on voting
func TestAppConsensusEngine_Integration_FeeVotingMechanics(t *testing.T) {
	t.Log("Testing fee voting mechanics with multiple nodes")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}
	numNodes := 6
	engines := make([]*AppConsensusEngine, numNodes)
	pubsubs := make([]*mockAppIntegrationPubSub, numNodes)
	t.Logf("  - App shard address: %x", appAddress)
	t.Logf("  - Number of nodes: %d", numNodes)

	// Shared fee manager to observe voting
	logger, _ := zap.NewDevelopment()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	sharedFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	// Create key managers and prover keys for all nodes
	keyManagers := make([]tkeys.KeyManager, numNodes)
	proverKeys := make([][]byte, numNodes)
	var err error
	seed := []byte{}
	for i := 0; i < numNodes; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
		seed = append(seed, proverKeys[i]...)
	}
	seedHex := hex.EncodeToString(seed)

	_, m, cleanup := tests.GenerateSimnetHosts(t, numNodes, []libp2p.Option{})
	defer cleanup()
	// Create network
	t.Log("Step 2: Creating network of nodes")
	for i := 0; i < numNodes; i++ {
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		p2pcfg.MinBootstrapPeers = numNodes - 1
		p2pcfg.DiscoveryPeerLookupLimit = numNodes - 1
		config := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
				GenesisSeed:  seedHex,
			},
			P2P: &p2pcfg,
		}
		pubsubs[i] = newMockAppIntegrationPubSub(config, logger, []byte(m.Nodes[i].ID()), m.Nodes[i], m.Keys[i], m.Nodes)
		pubsubs[i].peerCount = numNodes - 1
		t.Logf("  - Created node %d with peer ID: %x", i, []byte(m.Nodes[i].ID()))
	}

	// Connect pubsubs
	t.Log("Step 3: Connecting nodes in full mesh")
	for i := 0; i < numNodes; i++ {
		pubsubs[i].mu.Lock()
		for j := 0; j < numNodes; j++ {
			if i != j {
				tests.ConnectSimnetHosts(t, m.Nodes[i], m.Nodes[j])
				pubsubs[i].networkPeers[string(pubsubs[j].peerID)] = pubsubs[j]
			}
		}
		pubsubs[i].mu.Unlock()
	}
	t.Log("  - All nodes connected")

	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_fee_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_fee_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)

	tempClockStore := store.NewPebbleClockStore(tempDB, logger)
	tempInboxStore := store.NewPebbleInboxStore(tempDB, logger)
	tempShardsStore := store.NewPebbleShardsStore(tempDB, logger)

	// Create engines with different fee voting strategies
	t.Log("Step 4: Creating consensus engines for each node")
	for i := 0; i < numNodes; i++ {
		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_fee_%d", i)}, 0)
		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_fee_%d", i)}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})
		proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
		require.NoError(t, err)

		// Register all prover keys in the hypergraph
		for i, proverKey := range proverKeys {
			// Calculate prover address using poseidon hash
			proverAddress := calculateProverAddress(proverKey)
			// Register prover in hypergraph
			registerProverInHypergraphWithFilter(t, hg, proverKey, proverAddress, appAddress)
			t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
		}

		// Refresh the prover registry to pick up the newly added provers
		err = proverRegistry.Refresh()
		require.NoError(t, err)

		globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 1, true)
		require.NoError(t, err)
		bc := &bls48581.Bls48581KeyConstructor{}
		keyManager := keyManagers[i]

		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		bulletproof := bulletproofs.NewBulletproofProver()
		decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		compiler := compiler.NewBedlamCompiler()

		keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

		frameProver := vdf.NewWesolowskiFrameProver(logger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)
		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
		rewardIssuance := reward.NewOptRewardIssuance()
		cfg := zap.NewDevelopmentConfig()
		adBI, _ := poseidon.HashBytes(proverKeys[i])
		addr := adBI.FillBytes(make([]byte, 32))
		cfg.EncoderConfig.TimeKey = "M"
		cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(fmt.Sprintf("node %d | %s", i, hex.EncodeToString(addr)[:10]))
		}
		logger, _ := cfg.Build()

		factory := NewAppConsensusEngineFactory(
			logger,
			&config.Config{
				Engine: &config.EngineConfig{
					Difficulty:   80000,
					ProvingKeyId: "q-prover-key",
				},
				P2P: &config.P2PConfig{
					Network:               1,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsubs[i],
			hg,
			keyManager,
			keyStore,
			tempClockStore,
			tempInboxStore,
			tempShardsStore,
			tempHypergraphStore,
			frameProver,
			inclusionProver,
			bulletproof,
			verifiableEncryptor,
			decafConstructor,
			compiler,
			signerRegistry,
			proverRegistry,
			qp2p.NewInMemoryPeerInfoManager(logger),
			sharedFeeManager, // Shared to observe voting
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		engine, err := factory.CreateAppConsensusEngine(
			appAddress,
			0, // coreId
			globalTimeReel,
			nil,
		)
		require.NoError(t, err)
		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		engines[i] = engine
		t.Logf("  - Created engine for node %d", i)
	}

	// Start all engines
	t.Log("Step 5: Starting all consensus engines")
	quits := make([]chan struct{}, numNodes)

	// Start remaining nodes one at a time to ensure proper sync
	for i := 0; i < numNodes; i++ {
		pubsubs[i].peerCount = numNodes - 1
		quits[i] = make(chan struct{})
		engines[i].Start(quits[i])
		t.Logf("  - Started engine %d with %d peers", i, pubsubs[i].peerCount)
	}

	// Wait for all nodes to stabilize and verify they're on the same chain
	t.Log("Step 6: Waiting for nodes to stabilize and checking consensus")
	time.Sleep(10 * time.Second)

	// Verify all nodes are on the same chain before proceeding
	var refFrame *protobufs.AppShardFrame
	for i := 0; i < numNodes; i++ {
		frame := engines[i].GetFrame()
		if frame == nil {
			t.Fatalf("Node %d has no frame after sync", i)
		}
		if refFrame == nil {
			refFrame = frame
			t.Logf("  - Reference: Node %d at frame %d, parent: %x",
				i, frame.Header.FrameNumber, frame.Header.ParentSelector[:8])
		} else {
			// Check if nodes are on the same chain (might be off by 1 frame)
			frameDiff := int64(frame.Header.FrameNumber) - int64(refFrame.Header.FrameNumber)
			if frameDiff < -1 || frameDiff > 1 {
				t.Logf("  - WARNING: Node %d at frame %d (diff: %d), parent: %x",
					i, frame.Header.FrameNumber, frameDiff, frame.Header.ParentSelector[:8])
			} else {
				t.Logf("  - Node %d at frame %d, parent: %x",
					i, frame.Header.FrameNumber, frame.Header.ParentSelector[:8])
			}
		}
	}

	// Ensure all nodes have sufficient peer count
	t.Log("Step 7: Ensuring normal operation")
	for i := 0; i < numNodes; i++ {
		pubsubs[i].peerCount = 10
	}
	t.Log("  - Set peer count to 10 for all nodes")

	// Let them run and vote on fees
	t.Log("Step 8: Letting nodes run and vote on fees")
	time.Sleep(10 * time.Second)

	// Check fee voting history
	t.Log("Step 9: Verifying fee voting results")
	voteHistory, err := sharedFeeManager.GetVoteHistory(appAddress)
	require.NoError(t, err)
	t.Logf("  - Collected %d fee votes", len(voteHistory))
	assert.Greater(t, len(voteHistory), 0, "Should have collected fee votes")

	// Verify fee multiplier updated
	currentMultiplier, err := sharedFeeManager.GetNextFeeMultiplier(appAddress)
	require.NoError(t, err)
	t.Logf("  - Current fee multiplier: %d", currentMultiplier)
	assert.Greater(t, currentMultiplier, uint64(0))

	// Verify all nodes have the same frame (same frame number and parent)
	t.Log("Step 10: Verifying frame consensus across nodes")

	// First, wait for all nodes to have frames
	maxRetries := 10
	for retry := 0; retry < maxRetries; retry++ {
		allHaveFrames := true
		for i := 0; i < numNodes; i++ {
			if engines[i].GetFrame() == nil {
				allHaveFrames = false
				t.Logf("  - Node %d doesn't have a frame yet, waiting... (retry %d/%d)", i, retry+1, maxRetries)
				break
			}
		}
		if allHaveFrames {
			break
		}
		time.Sleep(1 * time.Second)
	}
	time.Sleep(2 * time.Second)

	// Now verify consensus
	var referenceFrame *protobufs.AppShardFrame
	for i := 0; i < numNodes; i++ {
		frame := engines[i].GetFrame()
		require.NotNil(t, frame, "Node %d should have a frame after waiting", i)
		if referenceFrame == nil {
			referenceFrame = frame
		} else {
			// Allow for nodes to be within 1 frame of each other due to timing
			frameDiff := int64(frame.Header.FrameNumber) - int64(referenceFrame.Header.FrameNumber)
			assert.True(t, frameDiff >= -1 && frameDiff <= 1,
				"Node %d frame number too different: expected ~%d, got %d",
				i, referenceFrame.Header.FrameNumber, frame.Header.FrameNumber)

			// If they're on the same frame number, they should have the same parent
			if frame.Header.FrameNumber == referenceFrame.Header.FrameNumber {
				assert.Equal(t, referenceFrame.Header.ParentSelector, frame.Header.ParentSelector,
					"Node %d parent selector mismatch - nodes are not building on the same chain", i)
			}
		}
		t.Logf("  ✓ Node %d frame: %d, parent: %x", i, frame.Header.FrameNumber, frame.Header.ParentSelector)
	}

	// Stop all
	t.Log("Step 11: Stopping all nodes")
	for i := 0; i < numNodes; i++ {
		engines[i].Stop(false)
		t.Logf("  - Stopped node %d", i)
	}
}

// Scenario: A partitioned node catches up after reconnection
// Expected: Five connected nodes advance, the isolated node lags, then synchronizes and
// continues participating once network connectivity is restored.
func TestAppConsensusEngine_Integration_ReconnectCatchup(t *testing.T) {
	t.Log("Testing partitioned node catch-up after reconnection")

	const numNodes = 6
	const detachedIdx = numNodes - 1
	connectedCount := numNodes - 1

	appAddress := []byte{0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03, 0xAA, 0x06, 0x02, 0x03}

	baseLogger, _ := zap.NewDevelopment()

	// Create key managers and prover keys for all nodes
	keyManagers := make([]tkeys.KeyManager, numNodes)
	proverKeys := make([][]byte, numNodes)
	seed := []byte{}
	for i := 0; i < numNodes; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		publicKey := pk.Public().([]byte)
		proverKeys[i] = publicKey
		seed = append(seed, publicKey...)
	}
	seedHex := hex.EncodeToString(seed)

	_, simnet, cleanup := tests.GenerateSimnetHosts(t, numNodes, []libp2p.Option{})
	defer cleanup()

	// Create pubsubs with a partition: nodes [0..4] connected, node 5 isolated
	pubsubs := make([]*mockAppIntegrationPubSub, numNodes)
	for i := 0; i < numNodes; i++ {
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		if i < connectedCount {
			p2pcfg.MinBootstrapPeers = connectedCount - 1
			p2pcfg.DiscoveryPeerLookupLimit = connectedCount - 1
		} else {
			p2pcfg.MinBootstrapPeers = 0
			p2pcfg.DiscoveryPeerLookupLimit = 0
		}

		cfg := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
				GenesisSeed:  seedHex,
			},
			P2P: &p2pcfg,
		}
		if i < connectedCount {
			pubsubs[i] = newMockAppIntegrationPubSub(cfg, baseLogger, []byte(simnet.Nodes[i].ID()), simnet.Nodes[i], simnet.Keys[i], simnet.Nodes[:connectedCount])
			pubsubs[i].peerCount = connectedCount - 1
		} else {
			pubsubs[i] = newMockAppIntegrationPubSub(cfg, baseLogger, []byte(simnet.Nodes[i].ID()), simnet.Nodes[i], simnet.Keys[i], []host.Host{simnet.Nodes[i]})
			pubsubs[i].peerCount = 0
		}
	}

	// Fully connect the first five nodes to each other
	for i := 0; i < connectedCount; i++ {
		for j := 0; j < connectedCount; j++ {
			if i == j {
				continue
			}
			tests.ConnectSimnetHosts(t, simnet.Nodes[i], simnet.Nodes[j])
			pubsubs[i].mu.Lock()
			pubsubs[i].networkPeers[string(pubsubs[j].peerID)] = pubsubs[j]
			pubsubs[i].mu.Unlock()
		}
	}

	engines := make([]*AppConsensusEngine, numNodes)
	quits := make([]chan struct{}, numNodes)

	for i := 0; i < numNodes; i++ {
		// Shared backing stores used by the factories
		tempDB := store.NewPebbleDB(baseLogger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_partition_catchup_temp"}, 0)
		defer tempDB.Close()
		tempInclusionProver := bls48581.NewKZGInclusionProver(baseLogger)
		tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_partition_catchup_temp"}, tempDB, baseLogger, tempVerifiableEncryptor, tempInclusionProver)
		tempClockStore := store.NewPebbleClockStore(tempDB, baseLogger)
		tempInboxStore := store.NewPebbleInboxStore(tempDB, baseLogger)
		tempShardsStore := store.NewPebbleShardsStore(tempDB, baseLogger)
		cfg := zap.NewDevelopmentConfig()
		adBI, _ := poseidon.HashBytes(proverKeys[i])
		addr := adBI.FillBytes(make([]byte, 32))
		cfg.EncoderConfig.TimeKey = "M"
		cfg.EncoderConfig.EncodeTime = func(ts time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(fmt.Sprintf("node %d | %s", i, hex.EncodeToString(addr)[:10]))
		}
		nodeLogger, _ := cfg.Build()

		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		nodeDB := store.NewPebbleDB(nodeLogger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_partition_catchup_%d", i)}, 0)
		defer nodeDB.Close()
		inclusionProver := bls48581.NewKZGInclusionProver(nodeLogger)
		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_partition_catchup_%d", i)}, nodeDB, nodeLogger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(nodeLogger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})
		proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
		require.NoError(t, err)

		tx, _ := tempClockStore.NewTransaction(false)
		l1 := up2p.GetBloomFilterIndices(appAddress, 256, 3)
		tempShardsStore.PutAppShard(tx, tstore.ShardInfo{L1: l1, L2: appAddress, Path: []uint32{}})
		tx.Commit()

		for idx, proverKey := range proverKeys {
			proverAddress := calculateProverAddress(proverKey)
			registerProverInHypergraphWithFilter(t, hg, proverKey, proverAddress, appAddress)
			if i == 0 {
				t.Logf("  - Registered prover %d with address: %x", idx, proverAddress)
			}
		}

		err = proverRegistry.Refresh()
		require.NoError(t, err)

		keyStore := store.NewPebbleKeyStore(nodeDB, nodeLogger)
		nodeBC := &bls48581.Bls48581KeyConstructor{}
		frameProver := vdf.NewWesolowskiFrameProver(nodeLogger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManagers[i], nodeBC, bulletproofs.NewBulletproofProver(), nodeLogger)
		require.NoError(t, err)
		dynamicFeeManager := fees.NewDynamicFeeManager(nodeLogger, inclusionProver)
		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, nodeBC, frameProver, nodeLogger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, nodeBC, frameProver, nodeLogger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
		rewardIssuance := reward.NewOptRewardIssuance()
		bulletproof := bulletproofs.NewBulletproofProver()
		decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		compiler := compiler.NewBedlamCompiler()

		factoryConfig := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
				GenesisSeed:  seedHex,
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		}

		factory := NewAppConsensusEngineFactory(
			nodeLogger,
			factoryConfig,
			pubsubs[i],
			hg,
			keyManagers[i],
			keyStore,
			tempClockStore,
			tempInboxStore,
			tempShardsStore,
			tempHypergraphStore,
			frameProver,
			inclusionProver,
			bulletproof,
			verifiableEncryptor,
			decafConstructor,
			compiler,
			signerRegistry,
			proverRegistry,
			qp2p.NewInMemoryPeerInfoManager(nodeLogger),
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		globalReel, err := factory.CreateGlobalTimeReel()
		require.NoError(t, err)

		engine, err := factory.CreateAppConsensusEngine(
			appAddress,
			0,
			globalReel,
			nil,
		)
		require.NoError(t, err)

		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		engines[i] = engine
	}

	// Start all engines
	for i := 0; i < numNodes; i++ {
		quits[i] = make(chan struct{})
		engines[i].Start(quits[i])
	}

	// Let connected nodes advance while the detached node remains isolated
	time.Sleep(20 * time.Second)

	connectedBefore := make([]uint64, connectedCount)
	for i := 0; i < connectedCount; i++ {
		frame := engines[i].GetFrame()
		require.NotNil(t, frame, "connected node %d should have a frame before reconnection", i)
		connectedBefore[i] = frame.Header.FrameNumber
		t.Logf("  - Connected node %d frame before reconnection: %d", i, frame.Header.FrameNumber)
	}
	minConnectedBefore := connectedBefore[0]
	for i := 1; i < connectedCount; i++ {
		if connectedBefore[i] < minConnectedBefore {
			minConnectedBefore = connectedBefore[i]
		}
	}
	assert.Greater(t, minConnectedBefore, uint64(0), "connected nodes should progress beyond genesis before reconnection")

	detachedFrame := engines[detachedIdx].GetFrame()
	var detachedBefore uint64
	if detachedFrame != nil && detachedFrame.Header != nil {
		detachedBefore = detachedFrame.Header.FrameNumber
	}
	t.Logf("  - Detached node frame before reconnection: %d", detachedBefore)
	assert.Less(t, detachedBefore, minConnectedBefore, "detached node should lag behind the connected group before reconnection")

	// Reconnect the detached node to the rest of the network
	for i := 0; i < connectedCount; i++ {
		tests.ConnectSimnetHosts(t, simnet.Nodes[i], simnet.Nodes[detachedIdx])
		pubsubs[i].mu.Lock()
		pubsubs[i].networkPeers[string(pubsubs[detachedIdx].peerID)] = pubsubs[detachedIdx]
		pubsubs[i].mu.Unlock()
	}
	pubsubs[detachedIdx].mu.Lock()
	for i := 0; i < connectedCount; i++ {
		pubsubs[detachedIdx].networkPeers[string(pubsubs[i].peerID)] = pubsubs[i]
	}
	pubsubs[detachedIdx].mu.Unlock()

	pubsubs[detachedIdx].peerCount = numNodes - 1
	for i := 0; i < numNodes; i++ {
		pubsubs[i].peerCount = 10
	}

	// Give the detached node time to synchronize
	time.Sleep(10 * time.Second)

	connectedAfter := make([]uint64, connectedCount)
	for i := 0; i < connectedCount; i++ {
		frame := engines[i].GetFrame()
		require.NotNil(t, frame, "connected node %d should have a frame after reconnection", i)
		connectedAfter[i] = frame.Header.FrameNumber
		t.Logf("  - Connected node %d frame after reconnection: %d", i, frame.Header.FrameNumber)
	}
	maxConnectedAfter := connectedAfter[0]
	for i := 1; i < connectedCount; i++ {
		if connectedAfter[i] > maxConnectedAfter {
			maxConnectedAfter = connectedAfter[i]
		}
	}

	detachedAfterFrame := engines[detachedIdx].GetFrame()
	require.NotNil(t, detachedAfterFrame, "detached node should have a frame after reconnection")
	detachedAfter := detachedAfterFrame.Header.FrameNumber
	t.Logf("  - Detached node frame after reconnection: %d", detachedAfter)
	assert.Greater(t, detachedAfter, detachedBefore, "detached node should advance once reconnected")

	var delta uint64
	if detachedAfter > maxConnectedAfter {
		delta = detachedAfter - maxConnectedAfter
	} else {
		delta = maxConnectedAfter - detachedAfter
	}
	assert.LessOrEqual(t, delta, uint64(1), "detached node should be within one frame of the connected group after catching up")

	// Let the network run a little longer to confirm the node continues participating
	time.Sleep(10 * time.Second)

	detachedFinalFrame := engines[detachedIdx].GetFrame()
	require.NotNil(t, detachedFinalFrame, "detached node should have a frame after additional time")
	detachedFinal := detachedFinalFrame.Header.FrameNumber
	assert.Greater(t, detachedFinal, detachedAfter, "detached node should keep advancing after catching up")

	maxConnectedFinal := connectedAfter[0]
	for i := 0; i < connectedCount; i++ {
		frame := engines[i].GetFrame()
		require.NotNil(t, frame, "connected node %d should have a frame at the end", i)
		if frame.Header.FrameNumber > maxConnectedFinal {
			maxConnectedFinal = frame.Header.FrameNumber
		}
	}
	if detachedFinal > maxConnectedFinal {
		delta = detachedFinal - maxConnectedFinal
	} else {
		delta = maxConnectedFinal - detachedFinal
	}
	assert.LessOrEqual(t, delta, uint64(1), "detached node should remain aligned with the connected nodes")

	// Stop all engines
	for i := 0; i < numNodes; i++ {
		engines[i].Stop(false)
	}
}

// Scenario: Multiple app shards running in parallel
// Expected: Each shard maintains independent consensus
func TestAppConsensusEngine_Integration_MultipleAppShards(t *testing.T) {
	t.Log("Testing multiple app shards running in parallel")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	logger, _ := zap.NewDevelopment()
	numShards := 3
	shardAddresses := make([][]byte, numShards)
	engines := make([]*AppConsensusEngine, numShards)
	t.Logf("  - Number of shards: %d", numShards)

	// Create shard addresses
	t.Log("Step 2: Creating shard addresses")
	for i := 0; i < numShards; i++ {
		shardAddresses[i] = []byte{0xAA, byte(i + 1), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		t.Logf("  - Shard %d address: %x", i, shardAddresses[i])
	}

	// Create key managers and prover keys for all shards
	keyManagers := make([]tkeys.KeyManager, numShards)
	proverKeys := make([][]byte, numShards)
	var err error
	for i := 0; i < numShards; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
	}

	// Create shared infrastructure
	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_multi_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_multi_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)
	tempHg := hypergraph.NewHypergraph(logger, tempHypergraphStore, tempInclusionProver, []int{}, &tests.Nopthenticator{})
	tempClockStore := store.NewPebbleClockStore(tempDB, logger)
	tempInboxStore := store.NewPebbleInboxStore(tempDB, logger)
	tempShardsStore := store.NewPebbleShardsStore(tempDB, logger)
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register all provers
	for i, proverKey := range proverKeys {
		proverAddress := calculateProverAddress(proverKey)
		registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, shardAddresses[i])
		t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
	}
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 1, true)
	require.NoError(t, err)

	proverRegistry.Refresh()

	_, m, cleanup := tests.GenerateSimnetHosts(t, numShards, []libp2p.Option{})
	defer cleanup()
	// Create engines for each shard
	t.Log("Step 3: Creating consensus engines for each shard")
	for i := 0; i < numShards; i++ {
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		p2pcfg.MinBootstrapPeers = 0
		p2pcfg.DiscoveryPeerLookupLimit = 0
		c := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &p2pcfg,
		}
		pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[i].ID()), m.Nodes[i], m.Keys[i], m.Nodes)
		// Start with 0 peers for genesis initialization
		pubsub.peerCount = 0

		bc := &bls48581.Bls48581KeyConstructor{}
		keyManager := keyManagers[i]

		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_multi_%d", i)}, 0)

		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		bulletproof := bulletproofs.NewBulletproofProver()
		decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		compiler := compiler.NewBedlamCompiler()

		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_multi_%d", i)}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

		keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

		frameProver := vdf.NewWesolowskiFrameProver(logger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
		rewardIssuance := reward.NewOptRewardIssuance()

		factory := NewAppConsensusEngineFactory(
			logger,
			&config.Config{
				Engine: &config.EngineConfig{
					Difficulty:   80000,
					ProvingKeyId: "q-prover-key",
				},
				P2P: &config.P2PConfig{
					Network:               1,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsub,
			hg,
			keyManager,
			keyStore,
			tempClockStore,
			tempInboxStore,
			tempShardsStore,
			tempHypergraphStore,
			frameProver,
			inclusionProver,
			bulletproof,
			verifiableEncryptor,
			decafConstructor,
			compiler,
			signerRegistry,
			proverRegistry,
			qp2p.NewInMemoryPeerInfoManager(logger),
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		engine, err := factory.CreateAppConsensusEngine(
			shardAddresses[i],
			uint(i), // coreId - use different core IDs for different shards
			globalTimeReel,
			nil,
		)
		require.NoError(t, err)
		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		engines[i] = engine
		t.Logf("  - Created engine for shard %d", i)
	}

	// Start all shards
	t.Log("Step 4: Starting all shard engines")
	quits := make([]chan struct{}, numShards)
	for i := 0; i < numShards; i++ {
		quits[i] = make(chan struct{})
		engines[i].Start(quits[i])
		t.Logf("  - Started shard %d", i)
	}

	// Wait for genesis initialization
	t.Log("Step 5: Waiting for genesis initialization")
	time.Sleep(2 * time.Second)

	// Let them run independently
	t.Log("Step 6: Letting shards run independently")
	time.Sleep(10 * time.Second)

	// Verify each shard is progressing
	t.Log("Step 7: Verifying shard progression")
	shardFrames := make([]*protobufs.AppShardFrame, numShards)
	for i := 0; i < numShards; i++ {
		frame := engines[i].GetFrame()
		assert.NotNil(t, frame)
		if frame != nil && frame.Header != nil {
			shardFrames[i] = frame
			t.Logf("  ✓ Shard %d: frame %d, address %x, parent: %x",
				i, frame.Header.FrameNumber, frame.Header.Address, frame.Header.ParentSelector[:8])
			assert.Greater(t, frame.Header.FrameNumber, uint64(0))
			// Verify shard address
			assert.Equal(t, shardAddresses[i], frame.Header.Address)
		} else {
			t.Logf("  ✗ Shard %d: no frame available", i)
		}
	}

	// Verify that different shards have different parent selectors (independent chains)
	t.Log("  - Verifying shards are independent:")
	if numShards >= 2 && shardFrames[0] != nil && shardFrames[1] != nil {
		// Different shards should have different parent selectors
		assert.True(t, !bytes.Equal(shardFrames[0].Header.Address, shardFrames[1].Header.Address), "Addresses should not match: "+hex.EncodeToString(shardFrames[0].Header.Address)+" "+hex.EncodeToString(shardFrames[1].Header.Address))
		assert.NotEqual(t, shardFrames[0].Header.ParentSelector, shardFrames[1].Header.ParentSelector,
			"Different shards should have different parent selectors")
		t.Log("    ✓ Shards have different parent selectors (independent chains)")
	}

	// Stop all
	t.Log("Step 8: Stopping all shards")
	for i := 0; i < numShards; i++ {
		engines[i].Stop(false)
		t.Logf("  - Stopped shard %d", i)
	}
}

// Scenario: App consensus coordinates with global consensus events
// Expected: App reacts to global new head events appropriately
func TestAppConsensusEngine_Integration_GlobalAppCoordination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, _ := zap.NewDevelopment()
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}

	// Create key manager and prover key
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	pk, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	proverKey := pk.Public().([]byte)

	// Create prover registry
	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_coord_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_coord_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)
	tempHg := hypergraph.NewHypergraph(logger, tempHypergraphStore, tempInclusionProver, []int{}, &tests.Nopthenticator{})
	tempClockStore := store.NewPebbleClockStore(tempDB, logger)
	tempInboxStore := store.NewPebbleInboxStore(tempDB, logger)
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register the prover
	proverAddress := calculateProverAddress(proverKey)
	registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, appAddress)

	// Refresh the prover registry to pick up the newly added prover
	err = proverRegistry.Refresh()
	require.NoError(t, err)

	// Create global time reel
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 1, true)
	require.NoError(t, err)

	// Create app time reel
	appTimeReel, err := consensustime.NewAppTimeReel(logger, appAddress, proverRegistry, tempClockStore, true)
	require.NoError(t, err)

	// Create event distributor that combines both
	eventDistributor := events.NewAppEventDistributor(
		globalTimeReel.GetEventCh(),
		appTimeReel.GetEventCh(),
	)

	// Track events
	receivedEvents := make([]consensus.ControlEvent, 0)
	var eventsMu sync.Mutex

	eventCh := eventDistributor.Subscribe("test-tracker")
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-eventCh:
				eventsMu.Lock()
				receivedEvents = append(receivedEvents, event)
				eventsMu.Unlock()
			}
		}
	}()

	// Start event distributor
	err = eventDistributor.Start(ctx)
	require.NoError(t, err)

	// Don't add initial frame - let the time reel initialize itself

	// Create app engine
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_coordination"}, 0)

	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)
	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_coordination"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
	hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)

	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanup()
	p2pcfg := config.P2PConfig{}.WithDefaults()
	p2pcfg.Network = 1
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	p2pcfg.MinBootstrapPeers = 0
	p2pcfg.DiscoveryPeerLookupLimit = 0
	c := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   80000,
			ProvingKeyId: "q-prover-key",
		},
		P2P: &p2pcfg,
	}
	pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)
	// Start with 0 peers to trigger genesis initialization
	pubsub.peerCount = 0

	engine, err := NewAppConsensusEngine(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		1,
		appAddress,
		pubsub,
		hg,
		keyManager,
		keyStore,
		tempClockStore,
		tempInboxStore,
		shardsStore,
		hypergraphStore,
		frameProver,
		inclusionProver,
		bulletproofs.NewBulletproofProver(),    // bulletproofProver
		verifiableEncryptor,                    // verEnc
		&bulletproofs.Decaf448KeyConstructor{}, // decafConstructor
		nil,                                    // compiler - can be nil for consensus tests
		signerRegistry,
		proverRegistry,
		dynamicFeeManager,
		frameValidator,
		globalFrameValidator,
		difficultyAdjuster,
		rewardIssuance,
		eventDistributor,
		qp2p.NewInMemoryPeerInfoManager(logger),
		appTimeReel,
		globalTimeReel,
		&mocks.MockBlsConstructor{},
		channel.NewDoubleRatchetEncryptedChannel(),
		nil,
	)
	require.NoError(t, err)
	mockGSC := &mockGlobalClientLocks{}
	engine.SetGlobalClient(mockGSC)

	// Start engine
	quit := make(chan struct{})
	engine.Start(quit)

	// Wait for genesis initialization
	time.Sleep(2 * time.Second)

	// Now increase peer count to allow normal operation
	pubsub.peerCount = 10

	// Let the engine run and generate app events
	time.Sleep(8 * time.Second)

	// Verify events received
	eventsMu.Lock()
	t.Logf("Total events received: %d", len(receivedEvents))
	hasAppEvents := false
	for _, event := range receivedEvents {
		t.Logf("Event type: %v", event.Type)
		if event.Type == consensus.ControlEventAppNewHead {
			hasAppEvents = true
		}
	}
	// For this test, we mainly care about app events since we're testing app consensus
	assert.True(t, hasAppEvents, "Should receive app events")
	eventsMu.Unlock()

	eventDistributor.Unsubscribe("test-tracker")
	eventDistributor.Stop()
	engine.Stop(false)
}

// Scenario: Test prover trie membership and rotation
// Expected: Only valid provers can prove frames
func TestAppConsensusEngine_Integration_ProverTrieMembership(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, _ := zap.NewDevelopment()
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}

	// Create key managers and prover keys for all nodes
	keyManagers := make([]tkeys.KeyManager, 3)
	proverKeys := make([][]byte, 3)
	var err error
	for i := 0; i < 3; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
	}

	// Create prover registry with specific provers
	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_prover_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempBulletproof := bulletproofs.NewBulletproofProver()
	tempDecafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	tempCompiler := compiler.NewBedlamCompiler()
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_prover_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)
	tempHg := hypergraph.NewHypergraph(logger, tempHypergraphStore, tempInclusionProver, []int{}, &tests.Nopthenticator{})
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register all provers
	for i, proverKey := range proverKeys {
		proverAddress := calculateProverAddress(proverKey)
		registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, appAddress)
		t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
	}

	// Refresh the prover registry to pick up the newly added provers
	err = proverRegistry.Refresh()
	require.NoError(t, err)

	// Create engines for different provers
	engines := make([]*AppConsensusEngine, 3)
	for i := 0; i < 3; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		keyManager := keyManagers[i]

		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_prover_%d", i)}, 0)

		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)
		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_prover_%d", i)}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

		keyStore := store.NewPebbleKeyStore(pebbleDB, logger)
		clockStore := store.NewPebbleClockStore(pebbleDB, logger)
		inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)

		frameProver := vdf.NewWesolowskiFrameProver(logger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
		rewardIssuance := reward.NewOptRewardIssuance()

		_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
		defer cleanup()
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		p2pcfg.MinBootstrapPeers = 0
		p2pcfg.DiscoveryPeerLookupLimit = 0
		c := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &p2pcfg,
		}
		pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)
		// Start with 0 peers to trigger genesis initialization
		pubsub.peerCount = 0

		globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)

		factory := NewAppConsensusEngineFactory(
			logger,
			&config.Config{
				Engine: &config.EngineConfig{
					Difficulty:   80000,
					ProvingKeyId: "q-prover-key",
				},
				P2P: &config.P2PConfig{
					Network:               1,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsub,
			hg,
			keyManager,
			keyStore,
			clockStore,
			inboxStore,
			shardsStore,
			hypergraphStore,
			frameProver,
			inclusionProver,
			tempBulletproof,
			verifiableEncryptor,
			tempDecafConstructor,
			tempCompiler,
			signerRegistry,
			proverRegistry,
			qp2p.NewInMemoryPeerInfoManager(logger),
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		engine, err := factory.CreateAppConsensusEngine(
			appAddress,
			0, // coreId
			globalTimeReel,
			nil,
		)
		require.NoError(t, err)
		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		engines[i] = engine

		// Check prover trie membership
		key := proverKeys[i]
		isMember := engine.IsInProverTrie(key)
		t.Logf("Prover %d membership: %v", i, isMember)
	}
}

// Scenario: Detailed state transition testing with various triggers
// Expected: Proper transitions through all states
func TestAppConsensusEngine_Integration_StateTransitions(t *testing.T) {
	t.Log("Testing engine state transitions")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	logger, _ := zap.NewDevelopment()
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}
	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	t.Logf("  - App shard address: %x", appAddress)
	t.Logf("  - Peer ID: %x", peerID)

	// Create engine with controlled components
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	pk, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	proverKey := pk.Public().([]byte)

	// Create stores
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_state_transitions"}, 0)

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bulletproof := bulletproofs.NewBulletproofProver()
	decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	compiler := compiler.NewBedlamCompiler()

	// Create hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_state_transitions"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
	hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

	// Create key store
	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

	// Create clock store
	clockStore := store.NewPebbleClockStore(pebbleDB, logger)

	// Create inbox store
	inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)

	// Create shards store
	shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)

	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
	require.NoError(t, err)

	// Register the prover
	proverAddress := calculateProverAddress(proverKey)
	registerProverInHypergraphWithFilter(t, hg, proverKey, proverAddress, appAddress)

	proverRegistry.Refresh()

	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	// Create pubsub with controlled peer count
	_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanup()
	p2pcfg := config.P2PConfig{}.WithDefaults()
	p2pcfg.Network = 1
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	p2pcfg.MinBootstrapPeers = 0
	p2pcfg.DiscoveryPeerLookupLimit = 0
	c := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   80000,
			ProvingKeyId: "q-prover-key",
		},
		P2P: &p2pcfg,
	}
	pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)
	pubsub.peerCount = 0 // Start with 0 peers to trigger genesis

	globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)

	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
		shardsStore,
		hypergraphStore,
		frameProver,
		inclusionProver,
		bulletproof,
		verifiableEncryptor,
		decafConstructor,
		compiler,
		signerRegistry,
		proverRegistry,
		qp2p.NewInMemoryPeerInfoManager(logger),
		dynamicFeeManager,
		frameValidator,
		globalFrameValidator,
		difficultyAdjuster,
		rewardIssuance,
		&mocks.MockBlsConstructor{},
		channel.NewDoubleRatchetEncryptedChannel(),
	)

	engine, err := factory.CreateAppConsensusEngine(
		appAddress,
		0, // coreId
		globalTimeReel,
		nil,
	)
	require.NoError(t, err)
	mockGSC := &mockGlobalClientLocks{}
	engine.SetGlobalClient(mockGSC)

	// Track state transitions
	t.Log("Step 2: Setting up state transition tracking")
	stateHistory := make([]consensus.EngineState, 0)
	var statesMu sync.Mutex

	go func() {
		ticker := time.NewTicker(1 * time.Millisecond)
		defer ticker.Stop()

		lastState := consensus.EngineStateStopped
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				state := engine.GetState()
				if state != lastState {
					statesMu.Lock()
					stateHistory = append(stateHistory, state)
					statesMu.Unlock()
					lastState = state
					t.Logf("  [State Change] %v → %v", lastState, state)
				}
			}
		}
	}()

	// Start engine
	t.Log("Step 3: Starting consensus engine")
	quit := make(chan struct{})
	engine.Start(quit)

	// Should go through genesis initialization and reach collecting
	t.Log("Step 4: Waiting for genesis initialization (0 peers)")
	time.Sleep(10 * time.Second)

	// Increase peers to allow normal operation
	t.Log("Step 5: Increasing peer count to allow normal operation")
	pubsub.peerCount = 5
	t.Log("  - Set peer count to 5")
	time.Sleep(10 * time.Second)

	// Should transition through states
	t.Log("Step 6: Verifying state transitions")
	statesMu.Lock()
	t.Logf("  - Total state transitions: %d", len(stateHistory))
	assert.Contains(t, stateHistory, consensus.EngineStateLoading)
	assert.Contains(t, stateHistory, consensus.EngineStateProving)

	// May also see Proving/Publishing if frames were produced
	t.Logf("  - Complete state history: %v", stateHistory)
	statesMu.Unlock()

	t.Log("Step 7: Stopping engine")
	engine.Stop(false)
}

// Scenario: Invalid frames are rejected by the network
// Expected: Only valid frames are accepted and processed
func TestAppConsensusEngine_Integration_InvalidFrameRejection(t *testing.T) {
	t.Skip("retrofit for test pubsub")
	t.Log("Testing invalid frame rejection")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	logger, _ := zap.NewDevelopment()
	appAddress := []byte{
		0xAA, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	t.Logf("  - App shard address: %x", appAddress)

	// Create engine
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	pk, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	proverKey := pk.Public().([]byte)

	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_invalid_rejection"}, 0)

	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bulletproof := bulletproofs.NewBulletproofProver()
	decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	compiler := compiler.NewBedlamCompiler()

	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_invalid_rejection"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
	hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)
	clockStore := store.NewPebbleClockStore(pebbleDB, logger)
	inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)
	shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)
	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
	require.NoError(t, err)

	// Register the prover
	proverAddress := calculateProverAddress(proverKey)
	registerProverInHypergraphWithFilter(t, hg, proverKey, proverAddress, appAddress)

	proverRegistry.Refresh()

	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanup()
	p2pcfg := config.P2PConfig{}.WithDefaults()
	p2pcfg.Network = 1
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	p2pcfg.MinBootstrapPeers = 0
	p2pcfg.DiscoveryPeerLookupLimit = 0
	c := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   80000,
			ProvingKeyId: "q-prover-key",
		},
		P2P: &p2pcfg,
	}
	pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)

	globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)

	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
		shardsStore,
		hypergraphStore,
		frameProver,
		inclusionProver,
		bulletproof,
		verifiableEncryptor,
		decafConstructor,
		compiler,
		signerRegistry,
		proverRegistry,
		qp2p.NewInMemoryPeerInfoManager(logger),
		dynamicFeeManager,
		frameValidator,
		globalFrameValidator,
		difficultyAdjuster,
		rewardIssuance,
		&mocks.MockBlsConstructor{},
		channel.NewDoubleRatchetEncryptedChannel(),
	)

	engine, err := factory.CreateAppConsensusEngine(
		appAddress,
		0, // coreId
		globalTimeReel,
		nil,
	)
	require.NoError(t, err)
	mockGSC := &mockGlobalClientLocks{}
	engine.SetGlobalClient(mockGSC)

	// Track validation results
	validationResults := make([]p2p.ValidationResult, 0)
	var validationMu sync.Mutex

	// Start engine
	t.Log("Step 2: Starting consensus engine")
	quit := make(chan struct{})
	engine.Start(quit)

	// Wait a bit for engine to register validator
	time.Sleep(500 * time.Millisecond)

	// Override validator to track results
	bitmask := engine.getConsensusMessageBitmask()
	originalValidator := pubsub.validators[string(bitmask)]
	if originalValidator != nil {
		pubsub.validators[string(bitmask)] = func(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
			result := originalValidator(peerID, message)
			validationMu.Lock()
			validationResults = append(validationResults, result)
			validationMu.Unlock()
			return result
		}
	}

	// Wait for genesis initialization
	t.Log("  - Waiting for genesis initialization")
	time.Sleep(2 * time.Second)

	// Now increase peer count to allow normal operation
	pubsub.peerCount = 10
	t.Log("  - Increased peer count to 10")

	// Wait for engine to transition and produce frames
	time.Sleep(5 * time.Second)

	// Create invalid frames
	t.Log("Step 3: Creating invalid test frames")
	// invalidFrames := []*protobufs.AppShardFrame{
	// 	// Frame with nil header
	// 	{
	// 		Header: nil,
	// 	},
	// 	// Frame with invalid frame number (skipping ahead)
	// 	{
	// 		Header: &protobufs.FrameHeader{
	// 			Address:     appAddress,
	// 			FrameNumber: 1000,
	// 			Timestamp:   time.Now().UnixMilli(),
	// 		},
	// 	},
	// 	// Frame with wrong address
	// 	{
	// 		Header: &protobufs.FrameHeader{
	// 			Address:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
	// 			FrameNumber: 1,
	// 			Timestamp:   time.Now().UnixMilli(),
	// 		},
	// 	},
	// }

	// Send invalid frames
	t.Log("Step 4: Sending invalid frames")
	// for i, frame := range invalidFrames {
	// 	frameData, err := frame.ToCanonicalBytes()
	// 	require.NoError(t, err)

	// 	message := &pb.Message{
	// 		Data: frameData,
	// 		From: []byte{0xFF, 0xFF, 0xFF, byte(i)},
	// 	}

	// 	// Simulate receiving the message
	// 	pubsub.receiveFromNetwork(engine.getConsensusMessageBitmask(), message)
	// 	time.Sleep(100 * time.Millisecond)
	// 	t.Logf("  - Sent invalid frame %d", i)
	// }

	time.Sleep(2 * time.Second)

	// Check validation results
	t.Log("Step 5: Verifying validation results")
	validationMu.Lock()
	t.Logf("  - Total validation results: %d", len(validationResults))

	// This should be three because only three messages were received by pubsub
	require.GreaterOrEqual(t, len(validationResults), 3)

	// First 3 should be rejected
	rejectedCount := 0
	for i := 0; i < 3 && i < len(validationResults); i++ {
		if validationResults[i] == p2p.ValidationResultReject {
			rejectedCount++
		}
	}
	t.Logf("  ✓ Rejected %d invalid frames", rejectedCount)
	assert.Equal(t, 3, rejectedCount, "All 3 invalid frames should be rejected")

	validationMu.Unlock()

	t.Log("Step 6: Cleaning up")
	engine.Stop(false)
}

// Scenario: Complex scenario with multiple shards, executors, and events
// - Multiple app shards
// - Each with multiple executors
// - Fee voting variations
// - Message processing
// - Network events
func TestAppConsensusEngine_Integration_ComplexMultiShardScenario(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	// vksHex := []string{
	// "67ebe1f52284c24bbb2061b6b35823726688fb2d1d474195ad629dc2a8a7442df3e72f164fecc624df8f720ba96ebaf4e3a9ca551490f200",
	// "05e729b718f137ce985471e80e3530e1b6a6356f218f64571f3249f9032dd3c08fec428c368959e0e0ff0e6a0e42aa4ca18427cac0b14516",
	// "651e960896531bd98ea94d5ff33e266a13c759acee0f607aec902f887efbdf6afeb59238531246215ce7d35541ba6fb1f8bf71b0c023b908",
	// "ffd96fec0d48ccea6e8c87869049be34350fcd853b5719c8297618101cb7e395720e0432fd245abd9e3adeece5e84cebe6af3f17ef015e38",
	// "81dc886d6c76094567c6334054a033f5828de797db4b0cb3c07eda13bd5764ed5c17050cea7aa26e9913b0f81bd67bded64c7c0086378f3c",
	// "bc3fce2efc7309c5308d9ca22905b4f0c72e1705721890c8eb380774c3291d532ab05c4f6b7778e39f4f091c09c19787c5651b3db00fce0f",
	// }

	// sksHex := []string{
	// "894aa2e20c43d0bd656f2d7939565d3dbe5bc798b06afc4bb2217c15d0fa5ce7b22be4602a3da3eb15c35ddcf673f2a8f2b314b62d0f283d",
	// "77ca5d3775dfce0f3b79bdc9aa731cead7a81dd4bbfe359a21a4145cc7d0a51b50cca25ee16ed609005cb413494f373e5f98fe80a6c6c526",
	// "cc64ab8d9359830d57870629f76364be15b3b77cc2f595a7c9e775345e84d24be49f9faf4493e43e01145d989d5096861632694cf2728c39",
	// "f56bd16d0223bac7066ee5516a6fc579fa5bddcb1d1fc8031b613d471c1dbce7e99fbd0f4234fa6f114cb617c5ba581e5d0278c3f9ec5715",
	// "5768f1ceb995f36e1cb16e5c1fd1692b171a7172a23fe727be0b595d9f73b290f975cc1b31a84e6228e2e2a706e86e38cdd5fb52c974d71d",
	// "c182028d183f630ad905be6bc1d732cecacfee6654c378969f68282dac12c5969f42ffcbc9daf8bd30b81ee980743f82e62260232fd59d24",
	// }

	input1sAddrsHex := []string{
		"0022621ae0decf28cba81a089f7ad0b1ad7351d4cbdc118aafcab4233e63c68f",
		"008cdcc66fbac67e14526cb5e1b146655ed9f7706616aa14e2b43f71747ce00f",
		"018be7b5f4f5d23975d287178146b71b7b3b96980db2c61b4e0b59c9d580f9c6",
		"017f8f45297de7f0cbff0363cfc6d4246e6cd43b66925883fa4f212b38ae6883",
		"02f32001d9b21af3668daae4a9353d243c596b862b5b63d585fd8add10bcf2b7",
		"02456149c98d096093b709a04a2f9799456f3c3e0d1c07cf5f2cf2bf07450f62",
	}
	input2sAddrsHex := []string{
		"00a001aadc02e2f68937e7fa127abf186ac81806ffeb6abddf27acb4355cd2a0",
		"007d1e45cd6005379a5e2c75b1b494ec92519741b963943192301d3ec2b50ea9",
		"0196bc6c7180167a92883dc569561c6961fae026abbbdfe1c723ef49df527d4f",
		"014795afa5937061f8d17393071117c01f92968093724ccc8684662ee471a7ca",
		"028662c8f5b7636188b091bc268190c75cc75c55623ac732c2681540ad107379",
		"02292e333b9353fc9bf73313abd262a6ebf2b661f9144cec984625b4725d8374",
	}
	input1sHex := []string{
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038ae88dfce6591a57c7d7f1f2cc34e055b8cd6b5d3fe1a9c15615feeec4b3dc4b5e6055a403dbdb3c488b561e16a1b1b61274b8309f010409d000000000000000000000000000000408b150bc76107750467ded45db257fffb1627207f9d2ec2e996aec396bafe849b38b5e0beeef2e2b9e6aad30370d3d102438535090bb016bde28fe6d6a14e079b0000000000000001380100000000000000010800000000000000383a53ee0cf5d968985fe0b5dcf73c1b8b414a19e32d62bc24be9e6257fca32b5edc526851566981e3027f36dae164470845954f1fe3f67ae400000000000000000000000000000040db1cde6da1a556c2bd3edf464768cb31dc4967ccc56061c9bc0ffb3ddb4eaf79ea823f0ded99adc4e6ddcb21a6b0102d7ecef7bba088626eaaed9f2c3e8e74210000000000000001380100000000000000010c000000000000003810faa89bae23767fbfd52fe408ced3485221bcc69f82f44eca574d2f680ece1b8655de5e38d37bc7a9c3dc57c8c601be36ace4e10e859fdb0000000000000000000000000000004027a92c83e3301926edc5f3f575c37f218b3724ad47b047d587040d249a34253b2bbc099fcd003c11740888ad1e5e391061c7757b50323a4d26ab6719dab5ba65000000000000000138010000000000000001100000000000000038cee6dfdf902a1fadadc01d323a2aaf06d1e0543e025604f4e2ee267b921845ce329df9178f148c867bf1a0d15c8529794ae272451c906caa00000000000000000000000000000040d34e4372127765ea688e322fb849c17059c1aeacaf32b950b109b9fb3f583bd58afdeafd52c548bbd5cb42c365ba3cd319ac18e6439bb555d50ea0fb7c0648f5000000000000000138010000000000000001140000000000000038d25e5deee0103955e65131ab7e93fe5f16246f8374286ed5ba2362933745b75516ddf5a33fcb5755620803db581c5c0b380b1c41bd75b84c000000000000000000000000000000409261545c70d884076e112943ca0bfaeebde044cb31d12d95f718fde9285e4d7c050cfd616db6794b0793cda5c4fa95746927326934f6486335536a2813b04166000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0308df55282203b2f04d7c85df121adc35cb39447d1ee81ced4043381f23e1d837eca1f28696a096b0d909763d90ade0fc529a52ef1f5d39c01c7bd765e80c73ccba5dedbdce1eba766400000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba0000000000000001080100000000000000010400000000000000380c863b30d5d7195f74f668bea8cc173643e18c20999e90c7a8e29c32cded6edf144fae91240fba39d7fd35c1fba1a60e9ced79d25399763300000000000000000000000000000040e419d3d12a5a73bbf0660f6d76f27f25bd097133d57cb5864a00f77832b7ca9d23074d491dd02210ddd6cdab0f06891e8743a3803381bbd9f19af5e11adc803300000000000000013801000000000000000108000000000000003864d5a183d3d9864066533046508f22faa0ee336c83e1e3a06ba973966731b292d399cc0418710b4a1fa0c5ec545b393d7d079e273f38005a000000000000000000000000000000403fd06944ac87a384522ace6d8c7d9c7253c0f0ee26841057f9a4e152abbd889f0a4aa29a6076da5fef9f28946da6f5a3f7de7dee2b4bd1ddbab8f32438bfdab00000000000000001380100000000000000010c0000000000000038480177428d1a5b03fb6d1bd296ab51bc975ff27bccb3335d86e4bc1f586f0e678b19645938ee7e6b087cfd7113af3759b0b5fef5a1fa46150000000000000000000000000000004059ec85400863e4424d36ceac39d6e1111cc5b97cfa4e8a2a88be664f3dfef61284d7481a9f34810f34056d07103cbbbfbabe0e0069006a10313bc2b251282bda000000000000000138010000000000000001100000000000000038938cd024fac643758290d8bf542842f0fce61410ff4c691a3cf68678db6379c3d511280bf5d99306a6793a7135e4bf2c203df314b85eb54d000000000000000000000000000000403aefd1787d1c98a00e77b532741b16d335a6dfc018b31dd5eb5b6b29d0554a0f6995b08fa7dbee411b5e0628f43d9aeba54cf741aa1d67ddc334b0808a0e208d000000000000000138010000000000000001140000000000000038f3e760ebb60dab844157b39b8b24396142953315e0f54dd7fc7167915c43279a69e33d37b938a90e71f976e8ee2af5f6a06bba8211960d7a000000000000000000000000000000408b1db471bc94d1a5ba7566fe848b5a877d6eb86f1e500918813c5725f888b2e902e13d44e45b51805b0d55c2919c913c923dded013dc96078efed3de4a606909000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030e724a32423c6019bced8a9522f78e6ddbacb3aabd387c4b962260efa3267359932059128bf229798cd74001ed9f22be021b76c95d5cbb03f17b50b74ef92369c8fc7b273de3da1f0400000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003854f22387bf44bb124091d8bb190ee10b0c386002518e848f81df838fea97b8dfc41b37dd2fed2a39be0a247ff173a78e6553f8cf0685537d0000000000000000000000000000004033a811dd03637b65e8749f23e8631846b4b5e9d946ad59e2f33dcf9761e4a65d12361704843380f8d2226a7ec96e2b2afc407011fbdd1b563b54794eab760e170000000000000001380100000000000000010800000000000000385edecc81303531b1c083f98d333fc3a9ca411a60f378806410682f07f10d557550748332ae7fa04d550d2953714d5e90933e7c94eb0bc6c3000000000000000000000000000000403b301a356dd40b57a9bdd37aafcb414d673ab9ce48b844572b429ee5a3123b36e0f06f60f363aa4dbab1fa9590ff4610390a5a0a9f7d14bae3a7246594e2f7e30000000000000001380100000000000000010c0000000000000038560b56505ed9f90182a7d6c327c24813352f8dbbdeeb217d5864125aab3362e8a462c05ae2cbd8377a1f557feb330ec086e6aadd1e77ac710000000000000000000000000000004042a59599308f8dab96ac86bdabe19671e0d819a4e1842c10af24c3be47dae07ec21189ea123b9db586b9ec690d991b8b63fcad5772e53bf8c09f31e30ab89162000000000000000138010000000000000001100000000000000038a28ade3ba862a537022cd16a6bbb8c771ea289534c812f3c7a724cc8897e0740a33bd50e5c8eb6f6497eee7cf7a4a296eb6cecd0295c41380000000000000000000000000000004044122efedb1559717c531eb8ca508f93ccf50e2d36b3438d327267b0768de9ca9190d71d5dee4988b05cb1758e4af31055a5ba53157d6d80693929f577c5cb5d000000000000000138010000000000000001140000000000000038e287e7d4a40c948ef785acaa55c3ff6d8fc3dc99f2fb4e2e33f10047bf89a912f4d4c67902d1bb0d6d05124617fef28b4d3f316c2c8eea5500000000000000000000000000000040588200f8627b165cf2f24ae6c1d4792a80b02d198c6d9c6617359039f8711e51ad8619ac92ea5f6c2a7163e0fcc1705628c1a8f861964726dd2d1532fd15d207000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a020d88b324089d0052d61fe6cd87c52f8b9f846578cb11aa912fcb15b1ee2fff58dec4e3c79a522b4595f8396864fbacdbac0d88b673ece59803c380380903bc922c4ca3dcac0ded99ae00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038803e6cf22ee4363df44db5f41d2b727d3386daef8c2197e8c2be78cfaf03fc12b163f11446454b75db66dad4fadfa8391ce78e3453100cc50000000000000000000000000000004099aa42efb620e36cda7b9ce32bc64907e764c005ff711d9f5383988cadfbc59071c5e44010775692b001f6709b0607c5aa273dcb40a4fd3217dfd76523b27b2d000000000000000138010000000000000001080000000000000038e29f36a9072c911c17e979fc9226b6daafbe4f7eef16bc2b0fa17e1ff9e5e16a276f4e71a236d38742ada11bdad34d09fd345d3e54ec89e400000000000000000000000000000040255f4a9cb181fcc29c8513348122adf1059df4d94ff19d086a04dc578144606cfd3b4a2b5d525f72136592d856b48966afd40b790b14dc462f814ebf65e4cdae0000000000000001380100000000000000010c0000000000000038b6ade01b62ece200b427ef10a65304a1f15cbcedca17ab4ac118bb689e530fc68114010289c8bb35f80b783136f9b56d436c029e6692242000000000000000000000000000000040aedb079b12417f05158d0a3576bf0800f1c11c77041ddc2d38ea14ec7c22dc151a06900f6085569cfcbad0101fd48e206ca437a091649bd61bcf3ece5327b8be00000000000000013801000000000000000110000000000000003859843ecf158910ca5d1fa6c3ef8269a40fa7d35e17ccf97ff17ed7bafb0e58b047b2a479997ed199abbeb4a6e2c48352e991c8ecb2efbb0400000000000000000000000000000040351d632e4eb53a4f5eba9a35d5488555911346853b0ee3b1b5a2367d7ace53261164df96777746114101114f221b61394bdf900f7a58ac29341f79b224100296000000000000000138010000000000000001140000000000000038779bb19976b4665daaa366cf854f49115a2dc3e6f3a91c202488a319c34f89ffc8babfb425a5aba6496c8bb42fa2ec3ec2c04e7db7fc548300000000000000000000000000000040c797f0cd70e6136b49a37fe82fcac414dc544bb93bd7e8d2a09fb7ea36252ae45c0ba7678a8bca9581b2d9d6aa4ce35a5cee19c9fea5d9bdda17343b1cc13b32000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0300bc59ec21055089c298489a9370ac660b97cee0870cfb22ead1be4bad18aa754cc66bc1e7dc6e3527c929db7876603aed6565a8a99f4a2654454cf9160dcd2aef53638e0ef6704cc200000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038aa13bd61e0132474d7611d6dc624213f3898b16f85a0cb008372a39fbaeda5d4c28f8ace198c4849256ac3c6a8fc856c5474b0bdb3f057040000000000000000000000000000004053c50cf851267fbea21d7fd5b0a2359577cb494b629a9de65bbd30e65a43a4f77be3c20b4c6bc98296a0d8aa569447ae8aa7832cfb28d113a214a1a5d5b2390600000000000000013801000000000000000108000000000000003882619486287c30b53a7cf99da8229d02a1e55cd3cf3565fc5e08ad2373e11be8c303d8b34972350a41635d8a9f099fea9cf986f213cf795100000000000000000000000000000040d46d1f03e52327689055a107c8e2cb6d7f93bb2c60bf1fbe419d4445036c241d0321224856ada0f1aa79089fc23b7ca500df33ed01728ae006b22acde5260dcb0000000000000001380100000000000000010c0000000000000038287ff24c072e16cd496861d43cc601b8eecb51da65ddb0f05306f7f24af828c44897bd1d0075734a0f7c7c651bfc5c7747453fe530b924e500000000000000000000000000000040aa3cd8a69b56c6a9a7800a0e1416a94e6f4b76bf362c77c64738f60bfe26011aec530fa6c400cdcbbd950ad220358487973f8eadd0d8714d78a8e48bc3d41369000000000000000138010000000000000001100000000000000038f79ae0865d4f83fec288fe300386733ec325242ceafa24c39c94323bb8689963846bad84c8e599a99a9412e675ae294ddea0034ba62566540000000000000000000000000000004034c4bf061070c6e4a47298a985cb26705160c2ded4d9734a513db03956ffd519d6fd8ed9baed223cb1ac9df24354e5e69deb309983eff02161b7d56140aec6ad00000000000000013801000000000000000114000000000000003846f3edc37a3b1ff5ad5f85d121e2d873da4e76bf4b53629789c512ceeea1526341ccacfb46cdadb3d10902cc8bb8a809e484832cb1527b6d00000000000000000000000000000040adc4c8786e6f79ef2530f623daffa1990663aa7c1c718160694480e468503cc00af4097a8630d4597385f00d6831a0ebbec8aea660f820bf033c531d08799d5b000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0203c75444ecbc6a9d71042d852c3c4dedfefe5469423d89089415ea61cdfb0d62afb23d4e736526c4b6eedf1623dbd2efaf71fdfc06fbc6c71891ef48270e0f1c68373d86a48e7baf4700000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003830690a46df7a9dee951871add7a7ee0578f562ff6c3fff255e95ca1915115a4816eb7d021dc8c82818f7c2dbf3b644b42ce32f0274053b5b00000000000000000000000000000040288ee4da6fa1932b2ca02052f62fe5db1d307329d792b148a7f1c80be8d181ede6a763cec41e5ab6f82098f86be885f6837bff37e4ff28858dd68c3ad7e8c9e900000000000000013801000000000000000108000000000000003840417bdef348774073b89de0f180472132d99b4557162fb7d70d8dda6d9c4018789c54117053f1612de8d8483a2f6ed972dc01a9408f941c00000000000000000000000000000040497865d10608095085c77ca23e4051ce16ddc4b2aec864c31bfb64679babd15bcd9e1694edb98e0cb99c7a86f34dc24d9c52635e67b5f9c563cb6fe3f5a4258c0000000000000001380100000000000000010c0000000000000038b405d9d14f0ffd29dc083f4ca377314af225da77a1a9b2529554cf88e8e9778b82e948dbecb9616b09c5339ad8e963c55d686bf63948cb0400000000000000000000000000000040e691e27174341a159ca02d1226aa79785f87e68e968b379f33d54ca67b474fe13ec5d561df92245c769c24dd3fafd028e550e9b48fe3b42852f3fe7ba80de0d8000000000000000138010000000000000001100000000000000038748ca3a93d251fa30e161254f92bf705094db44a11900b73b9b6e558e3111c4e5e811044098d264f444f8aa749bfc3d87e8904193957443d000000000000000000000000000000407ea993a1342af5d69b00bc4829a4de449deea1c2df37d822f89ed27050651ca96fcdadb6e628b76b75e737a454f709f55c054f6375ddd44af1319085a5b9f706000000000000000138010000000000000001140000000000000038c66e1b2d50b17c0652db0f2f407658416a26b597745d3cb9388b810a0da6b3fae0ddabb3c3270912000df65a1984c561ff1258cd1703710100000000000000000000000000000040cca00e6faf19eb0598359a1488f6428eed6f6016cf158ac96f68dad57f6446f686cb626a32cb3ab3b9813e2a7c26b5101b58041ca653dab90212c34bfaca2528000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0306001627250ca093db4e629d8b95acc359eba050ca24cb99257e0be9984d5d4dae2addcc7e8ee3842e8234d82e85819e85d6c0a6affd4bd486be1e14cf8d4e7d794944b6a6e344cfa000000000000000020140000000000000000700000001",
	}
	input2sHex := []string{
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038eca50c819743e01055f66ba9b7a9b8c8d53c684bc1a54fc4cdf2a069e2528cfc6ef550ad426480387cca34d8e8b8ea948164bcedac19015a00000000000000000000000000000040c95668039d2d2499039d6f15d05a9089f084cc1b2ff7bea76fb2dcb43fc9ba017a6cd0fe215723b1c9607f060f3bb0b32bb207c64b1bc36aa0382b86f2d0fffb0000000000000001380100000000000000010800000000000000387c0a49759730be4192c40f349b69ad83aa6392e004a2d4c8df3b62b6afb50ba903d91d18f002510e6d70069b0a472c22497473adcedf5cc30000000000000000000000000000004024bdc2952e1faff3acf2ae4db3ae25b66c5f884340ce3b92b34e9116b96d770fdb8a292af2b534d717220ae2ce6e889549ec8e7be38e048632777545e50124200000000000000001380100000000000000010c0000000000000038c0e2e8b883e9a1955fe5ff2c60a0ff16ad51f5bf933f164868b5b91ee302b445a92497f337ba32f1fe134256f2ee6e989210ad463776f45000000000000000000000000000000040d7fa035ff925c5bd57c713aff9307fb6e59584a885f5e8a56b15539682b99259056217b4472f61378572f07b4ba91fa8874fc34238faeaf7bfbde4524da3194a0000000000000001380100000000000000011000000000000000380fabbc7785bf8de8474908503708e545f481180150d4d364e0d91cd0400c89d13dda5358ed42dc8109ba708b1ade4d19a28248ad15036f04000000000000000000000000000000403a59f9a33de9f0ba9452ce66f2a950de60e6a3663535adf510c994ef1cb3194fbf00084514d0e00c74a4663327f84b5e7c39c720ccec04a9b90b9b3dc118e2780000000000000001380100000000000000011400000000000000381c3bd4b1f39038aeb7c24e512ef3351b8f09dbf1dd71bddb45b67b5e8d6cadc8050d9d2feaf2626fd9d4efef0fa650ea140f51928d4e96430000000000000000000000000000004007f2af233e3cf4523ab1b52c93ccac3de6c574456314a07f0d1f59ceed625641ab5794c9d2a3f65f3489df0db9b82f2db055721d9fc6d533cc2fd07d614689ba000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030e4e382d25430f4a2ccf3287357861dcc9d93a55c3854f4990f84910f8706a5db11fefea3e5347c299bf76675c62c79171e40a15b4650d61eed9020c01480c47de7f0ede22c399bae700000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba0000000000000001080100000000000000010400000000000000383a2c5db4af04028fc97d326d9cf150a51a80388da52341f35cd846cff4a75f8fce178c819cbd10b6e849905498fe07048b3200223cb8ca5a000000000000000000000000000000402eb5312e772b0130ffa7e97b63f406d431889c4dd9665effb545b73e4a6fed72382b67226d10c9ed048d61163a1fbf332fdb0e31f613fe15b4069e9bf9f8da82000000000000000138010000000000000001080000000000000038aaaadcd757a397ae8931a010986f8c6d9d5441ab743d3a4bc4a54c2b7f7643be17dc6f6013cb5f18f242e5d6846b55a6c9aacf8313f66b0300000000000000000000000000000040afd6b9f03e2aaeee40926fae6f3455e9764d29611562a5d6779b39dd7a423fc0b866b8bc0966aef4f7c7898dd9afb5ae583351dd73b8046d98fcaf7480949ad00000000000000001380100000000000000010c00000000000000386693b092ea13e66b48663159f9ad038c814e547684b8dc9827e397db055c3c982cf79b94307cc165cbfdab5b1665ba6184e58d963a08f228000000000000000000000000000000400a13f689a41b237960fadadac0f915fb9045e15a8e1a1b1dd0afd1c9058972888ebac386f1bd5cec79d1b446eda0e620d6cadd69649dc564b81eb402b8a8e36f0000000000000001380100000000000000011000000000000000382c048fc6a0ea16545c4c6556bd2922a3b6d2e06262fa30f1b6761eef4ed0504309136598796b31cd0ded7f00ff93691ebe0e3f52493bdb4f000000000000000000000000000000406cf0aa474af68435d2def24afc2268a3f88295d9efdc902cc4578f5748a5f82fbb993f8657c5aafd3a3202187ce7c68798118b638d8c1fb72ba0d28aa7118727000000000000000138010000000000000001140000000000000038b40f9eeb76a1c30b37643e919862afebe07feab58ef4c4447a2ba2217e00b4efcb4a09321dcf067a51f4b770d1e758b75fd576477008f2a300000000000000000000000000000040597db9d4b41e07965453e951d8285f1681359e6102de427aa0207819191f4e17472666ba5bb3e784adb2658f498f4c5c1aaf0f7012f870c2514b5c0fcd9183b8000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030f9053d34dc6e3f62e7cd8fe42aef9071766377943467b469c33d81022566009e20457d95a49886ac6dba89c45f56b7dc88cdfaa971410fdcf78dbf0f306199ed2941b7017a978707e00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038aea03cd1e5296fbbd4a57adb77fd68011410a5879d277e3c7bec1201ef8bfd46df0937b197a4a10401d73f4c158a945647755aacabbe6962000000000000000000000000000000403ccbd1002b266e186ff526759cdc928647f22a39dc638648ca9a519db69c3708994815bb74ad8ca6b22470006d7c950262104a400c09735d65eb38e123ae088c000000000000000138010000000000000001080000000000000038a0e2979cf6125461575bf19359a0cc7642b6b5af73c4b1a77e6cf09b7d46bf7a0911fdfe6acb619eefaa60512d9e1a195984a47ee8642834000000000000000000000000000000400d92bea8487bdf02810bbc011b0cedb3b33197e63f890be523108bf05d5e353756a917fa83c8008ca57184ecf683a278b33e9333ab2ccad9ef74ffc569bb29cd0000000000000001380100000000000000010c000000000000003844c02fab19700480662ad893619a9836de1630e54c937a6a94372876ebd04a5af865c05202b3245366404e3cb5b4601b50a99439a0c6c06e00000000000000000000000000000040740e450df21d330ae8ebfb5a0250547565b4ef82fd6e371383afa9f48d03b42878d177b6d90c991bf5867af91670620cff45198ac3074f2d8643bb7763dcfa2a00000000000000013801000000000000000110000000000000003883dd1f44174047f8e60a6c5e2ee45dceb3b0fb48167690066e600e614f284e390d54024154b256b1e54c5f0617997ee962a367a60fe076770000000000000000000000000000004098dd7eac64f808eb1630663b323930d19ab935ff8417716759b3ec0a9be97c22b36d1e9a8d7be3942b154aaab0b9cac7842448280b2dcfbdb695dcbd8fafa05f000000000000000138010000000000000001140000000000000038d6b5e20e91f64e82d79e92449a20abc5e74fb145c8c9a3c5e3dc98221fb5d785a67b87fc2590e63cb59efe1cdb0ee9d6fd151be07a180d6b000000000000000000000000000000407312fa0a4ab297787378ecf23827897ee0e4127e8891506dd87b93b12c694d380472c6e2a0a3ac7a75d5a5ea9ffe2bedc6d08343394335f28aefcd13fbb35559000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a03015b69771e503285338884d8c4f062aab9c219d4dd99ce5f8bf7dcf0fb5b7bc5d4ae7c3c13975c1d769240d08177763bdfdb6b4748d916254a66f62585f72c179d29375f8fa9f227bd00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003870bba67d6c3e698d796082117612c0decabc2e7d8dd9beba5b3b663f1450836f65e816564dfe743eeeb2b3604f3b9a420f7d68ebe2b0d96e000000000000000000000000000000407c6f9b424679ec00b5167e453e76d8d95565858c5338cab0f66fa14f88a71a16531c66cf050dc734f2f7e816c4563fc7fa63a1f26de5a613c44dd2013ceac5c6000000000000000138010000000000000001080000000000000038f6c80f745497ff51b7e334d214b915982d220c89670cf73b20b307c5db44426a884e4d0f923c77b08d4c5a576509e8794d4118b1e82f5845000000000000000000000000000000401ccba1f36a6c90231b648df1d1546b41e682d52cd07409b6c0de67d4ce91c8da45672b6c048a3b19283466cd2582410eeed3563904dce0983a499d989052e9980000000000000001380100000000000000010c00000000000000382ce6d8d803addd976a4a09fa98781d9ce273e21106c0d1f5bef495a3570a9ff4afac556ff803fda6d62d8a224229b8661f29a17c2877a53a00000000000000000000000000000040f2886fc71c55719b5386458e444886d096330d3af5ca52afa6db10afac62ffd840ec9f254052e77ba6d1374cf0684752009e217d85866ec4454229885bb2c69a00000000000000013801000000000000000110000000000000003816dfe96e184dbcb15b5fac0a6efd3c1baf60409ef264c2f8c80764726685ea3dcae84b683cf2e694126bb992d571582ea8a002aa4000f3be00000000000000000000000000000040c3b6120ccc636d66750f8a48c350dca78ba17f0bb5949d36e67ba93888daa970542d63327dc74216188e189b594e1aaf58e1c428f76efb4f198b2a2f73cf4bb5000000000000000138010000000000000001140000000000000038ef6050801a487a88db7bf46f96e66b567e828d84c624fdf7d067ecd89b5a8d1a1931aa0721c28f98f92b43917372588c572062f0346c0f0200000000000000000000000000000040907fdecec88e8f645c002edb2d29c37de2286eaccaf0cb22379d53d27b6d8c124cab88f83480df0fb3d2ef839d0d5098092530d3baebd4ea680ec55ad1c85d32000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0302c9c9d4dde5e62aafc1683d9ecb81791f703036a317b0dd36582c70f1835367776db27c824552210a7b5d65ccd9715870da915aad587fbc19e425e1668882fb416184b45af79457a000000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003870452ed77781d41f3a1af90b008ef4b2330a94cb20f82a5e6536fcf96a5257fbbb393f5f8ad227d35f21a4d19286eff58c9b36ebbe30534b0000000000000000000000000000004015303e6dde9d9d2faa7cb69a2675f21bfab3b063abfdb1b732624fbc7d1a5a34f40e7cc1781c6847dbb09f6691ff414fb6e7c8ea9971c3ec1862cd42c0e33661000000000000000138010000000000000001080000000000000038c8778171bd5983cafc4d46f9584eee717f2aa6ae2bae15158927d1011551d5ff055bfe4d9d7034fb8f2d278c0cba999c99d5afbdb39865290000000000000000000000000000004067cf1b4c291c4b0c9384eda5547e3ba8e27f2fa60c70e76f6d97343e59f0dbe6b63a15bc9b6d6f49909cd00d23974051f1f4cc9816f37cba10a97469e7d0e2580000000000000001380100000000000000010c000000000000003806a32053c55c919a6346ef2ddc86891b4b32768cd0fb9f514d4f370382b1768a1552a86e8c583a073150d3965907f245111fd863b2f950a700000000000000000000000000000040b71f10034888251a9ccbc44b3f719a24f506e938ca08a7ce96e831290e4792f58ebe84a4932834fd29764a9340ba65bbe6219d9d98efadd1b5cbfd835224708b0000000000000001380100000000000000011000000000000000389c626d014755722670df38934fb3ab05c94485d6109e290453d58d161ce853f96b82f0e4f1a0469dc5c5ec800cd40001e8d7936ae08803c700000000000000000000000000000040f65b1be90ce6553570e53f690df5666f8335d594ea9594613b829bd1469010666df9d6e2f8eddf541f6c550e5417058bd2d99405ceb6324a1c72259cd342e98d000000000000000138010000000000000001140000000000000038a17ba6f6d445b25a7e93136939bbd64ffa4ab17ccd0ba81d67da8b267fe807cd1bca94ef3245493e272acde0b7adec5b2160d84282e0116c00000000000000000000000000000040c620cf3f50381c1f875a2d35e1acc377900b19b579a8dca3b1e586a81f34cbd59ba77e9783281605f8918a18b756a704ad6bcf1c2983e4b2926e01afbca95e1b000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a02073fe7087632b5bcfa4261dffcad91ebc04f29ade8408b44b250a1cf1c1501d29b329070309761dce8013b2d6252270a88499def769c9997e7b19a5db34ab19b0a6be85a3c3028b5e900000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038d085722c5c2373d8928b900ce8d0c34403d95078320b5033f7d74f1faafa3c20408dd19996f0bfab598a69e7b1a813c40b8c99ccbc50e72f00000000000000000000000000000040a32a72719da0ba9d5ab4e2d079ac396886fe8155cf74d81519a52774921b6c0ef49f733e0b14c38badedecd64be36005c11b6c59fd099d4416d64168107dfe430000000000000001380100000000000000010800000000000000382cf2c6fdb0eb79089eaa010e9941768ef8dc5e3c60fee70d79b50e18162edf6d500b7cb014df5d4efd4bf3667abad91f1ae492561138f62a0000000000000000000000000000004008dd2a9a7e82484b11deebc16c2af26d4f3ca18085edf3f5e0ba3008795254af417b1fe08710c345d067c2786a33aea5d5ffc5b9ae398fad2dc9beee30642bd70000000000000001380100000000000000010c00000000000000381a8ec1d0d9d9e89ffcb1ff85415682956347ea663a6ecfd95343d7b07dfa391605e8ec11959e7f655bdba17ae9172cb27c8c44acc04d97bc00000000000000000000000000000040eb85e87c4833d7a3e817599c726c11a9b2ad4f086ee62e57c3bf9d45a70fa844c413b3e593d2ab534182c84d9be97066a16d026c7b0d8ec6fff101ba31c774e80000000000000001380100000000000000011000000000000000385f2f3ce2c1e3ec5f8c16e5ebb083ef86eff145da20f9f89b136f587cc3ddad6a2559a2843c2cec33092e3004dcf4fa650e90a910d98bb0ff00000000000000000000000000000040af88f2bcb0be6f12b108254c641859a18505a4aba2c2734fce02e8ddb82d91aa34ce2ad4a7ea565daaf0d03929515d3aef1d1e3bf15488a2a0de59679b8608200000000000000001380100000000000000011400000000000000381ca7e18ce166eb638f5e11cb0f41750cca1f572ccb0889869c94367b731e12146de06a6db1a672299007572e0d00c608d056573a34113f5800000000000000000000000000000040e554e9e66246ff311c11dc52608f98793fcc76a52be2841b74b1c66d546569a5d50c40d40b6f23c275ef638c8082b7e74ff5df61dc9dcb29b77a7c1197064291000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0209a29679708b0bb745b611bfb8058303618ac35de0113fed51f8ff99a517bb7b039013430caa67255361e7246d94ee5b704141ae33a14102b8dd00d8734adff87a6e055e71d927db0900000000000000020140000000000000000700000001",
	}

	pendingTxsHex := []string{
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a00000038ae88dfce6591a57c7d7f1f2cc34e055b8cd6b5d3fe1a9c15615feeec4b3dc4b5e6055a403dbdb3c488b561e16a1b1b61274b8309f010409d000001500ea8ee360b367fefb37e8b1c2dace5c8d010592e1cf50126c1f1ed8c5f346f307ab365722caa20a40bd743d040d21296326ea61b0189eddd74433fdf8dda25d7b7f4e9656413a7abac71d473c811ccf80bd6971b93e1960fc495f1f16d8343012350e0d7ed5e2de2c9453a2e7edde50f8f7293bf37200505a28ecc128d55b9e22fa382d910c59c912b2eb9a1401ff07092fd47359ba713f1f173b7baaeb56885287756db6bb8a93876e1bdb7c219c936166b56ca7412f0efacc7bbda6af8c573d573b65cf2bd69827312cf22a4e396d6844285e59988f3569bdaae2d87244f1210faa89bae23767fbfd52fe408ced3485221bcc69f82f44eca574d2f680ece1b8655de5e38d37bc7a9c3dc57c8c601be36ace4e10e859fdbae88dfce6591a57c7d7f1f2cc34e055b8cd6b5d3fe1a9c15615feeec4b3dc4b5e6055a403dbdb3c488b561e16a1b1b61274b8309f010409d000000010000009c0000004a020a96a4d605bbd9c6eedc0d902ccbd9b88e5d66475fa0d1a329909a6f4f1767c199ba6a0654d0f4d2270ef44009efd8ab08afdab6fb4416e5de220f347278e879ab620240e9799c13400000004a0307c3fa7d3bcc4ce57e13c3087d1fee2cc615bfa607b3d84d3c37138972e76b2cbce3c170be03e695aabb3e695a25c1582ef683ee6bffc2253ee8706539b1cab29ad8737738ca96dd3e000002380000050a00000038eca50c819743e01055f66ba9b7a9b8c8d53c684bc1a54fc4cdf2a069e2528cfc6ef550ad426480387cca34d8e8b8ea948164bcedac19015a000001508ef00ce814c2a062f6d1d98866755c7aedacfafb1eea7506a24c08d313105232bd25636804cf74b431b51493178268c221a0c3eef6b5de25d3ffb17f54934857ab19de228d1b6a5e0fb0af0733742f0abe9bde5178e0e21562d43d45c430efbab98d932f923587a85f1b70f457cf272a02e8d615fdde2c052810dd3a0ba28bc84a46fac3162a22cef9762142723feb7e7f059124fd374e382531147c7e91cffcfce05c0cf4954c10007cd53467623db622aeaf960f8e816e86720cf77cd07f4832699134a8f21ac362604de175382ae89ffa6bafbadc2e2e021a6d23c7b1ea0cc0e2e8b883e9a1955fe5ff2c60a0ff16ad51f5bf933f164868b5b91ee302b445a92497f337ba32f1fe134256f2ee6e989210ad463776f450eca50c819743e01055f66ba9b7a9b8c8d53c684bc1a54fc4cdf2a069e2528cfc6ef550ad426480387cca34d8e8b8ea948164bcedac19015a000000010000009c0000004a030910ea340a936dc1aaa3763f304d57b0bacd8a44f7c16095210352a7cdd2055fad5d6d34dff7c7c179295f66de99d2d7e8bf20de0ea785d457e1ac6fe27c2f07c5e27a9ec612bbb07a0000004a0309fdd1720691d6a06249227f448897bfedced29a12934b3561951ddb762159090c46dd12b58c4604e3f5800865706fe2f25dc7a0b7fa7f2535863972f8e4160e573baa9b0d8e6a826900000002000002540000050b0000000800000000000000000000003874e569b1eb0c9c7eba4a412d4da4a3262fb196ca9a9161af2dbb6bca7212584ec289908f3590e85ce2347a92b12a26729269154f7689eddc000000fc00000506000000382e2576a7a4da71552153f68fe5cea2f160a41b255590314c75da9af3b706e9390869563898f0c3796736c98f7c41e0ca0f3bdd16f4a26dc8000000385cf43b313b2216bc840ac15e65e9cfc3538ee7ef42d63a36c257fc21e2d4ca9748979c65ea2453add13b0ed4f7cd944d73990c377810bf13000000384dd3ef79491b65da77cae91f5c448020e76f64be71cba5947de94108b6f97e09e0ef9ad06587fbd36acca7e72dd7bc1552904d68fc531a9100000038630cae512bfdc31a26f87b07856d323235366637117290c80379c8317988563b2dcda2b9b379cdc4c473aa0fba9f43db509e85d0cbfa8caf0000000000000000000000fc0000050600000038f8a053e6ecb9634e14ac599cc48b6b0922d82c772a0bb3532e2cb85154a6cd4ee54840f2b715c7568c42d8548d998b24e2ad562a6458f50d00000038640a0730b9850241a36a90b08c5ed82b46ee2106cd34ed9f03390a2da70441262efd77fec3c7203b41b5557d744b63e619e0fcbbb7c7193200000038c88b992269c250ea5b61ba00f6aced154dda653b605b6ea8534640098988c18b41cc5b9ba498a5345f26f93e9dfe821f764d99ab840358540000003801a160cfe1db7d78338696dcbe0e71a665fefd38ce3cfb16c7caa8ef293a83bd2f401989eaaabf0389040466a3828f987ec0c03fffe8f1c700000000000000000000000000000000000002540000050b000000080000000000000000000000385851690089cf29a0ae5f13aa7b7024ef075e441df7bbf3c3c41e81eac36206aa7fc724645c4b762aa714e281e24c4eef9b2a1389407f73c2000000fc00000506000000384812e2ebe34c308b2d366c948e0ae1decd24b6cb7f3c4dff7aad3b614c6fc0aba5e0d864f5b1a3d3f2cee09b32014d94181d46fe38a9310200000038e2d8b6de09a5d322475af88c07d7a12ed20a19aa767b3fae765e226202bc6d102e14a52207ace21bb4201dd07e5e96107fcfc70d1b2ee53700000038c75f65a0af1bbec776d4d809d6c7acdf0d3a38c8dc13a5bdf4c317ad7067c4bda9c6909c7d5ea46b841c8d38a99b2409b9587b2fceeebfbd00000038c01905a368f9e03f97211d31dd2855b4bf33ed4671549cb9ddbdc22dd7cbfe8fba0a80b7329e6ffc2488454ef1b254a8d057c5f81aad66670000000000000000000000fc000005060000003884728faafd055ce7ab5172580b45951f8cc66e2e282d939df68e9b61cf0f4487656fc8f6b7a9a0c748dd779beae3994b1b602a8a33d898c4000000381a9b530bed680a6dd3d838d88440a4ca9dd0e53d033f3dbe1f0f5daa48b03b281fe12f4ddec42bc7bde8b24c81db264a3134ae57ee2af371000000387a8afed480793ef6b835dab41f83c0f6c9b4b4b66224b40df41717a9d67251245cf0c452b13cc0066c9bebbb51ea78953c049b9774ae24520000003860f69fd5dc4f1ed13d31136be9360494ff1cb3476379301fa824185eb40e3b4348c5bf3d8d898b8baf3ad87f158f50a6e7ba1673c5c7da18000000000000000000000000000000000000000200000020000000000000000000000000000000000000000000000000000000000000000100000020000000000000000000000000000000000000000000000000000000000000000200000578406d1e5cf2859cb447ef5c46121694e096f96afeb608692d21da65ea329622cc9f10893c84e6d6bef4726997709cf96bd05b85281bb1a23dc488c9b332610570344af0a395f9a46e566bc8f7d7bd600ea8d74934d702ee62a7ca6f18a183c859c31f1149df8c3333549c8e091f00a0bfd2f17ec42a3f17c28b6cb5abc72fd6c5f0eb3c3c4c59fd4ce641370cd8716eda2ea4563f590b8e40d6db881d4bbe88d9cc51366d384fb5391e8d62910844ec649f627852db6b72112edbcaae229e03e6a04162894f3139ebaaa30e21b821008967cd75c32de84a1b0dbb004a5a9d16aa63683b1e4ff91421dfc0d83d65f5bb299142d71ee516bec49d3881942ce9cc82b52874b8d666bb881d5ee90fd3a62a8da4c5a4d107a02102c25ba59f343ec47eff346723ac270d60fcaca3c595df561f8b39a1644cfb429e2f015c071d5e13b2453094e6f4125187f59d4327ea259b0455393d9e99ee90b457f0a7e1d2dee6b19a7cbe0028ba2d9d973db7c976da5d99ff8c5834e14f3fb50fd4362affedae374b6eeb7d548f2635f2519c5c0a5c86babb4501f40fb4b55b84683937e6859ed0cb8c4336dacb4635ef8f0d6b0f964242932bef78498097f0f2f938f665126f90d65b454e1304fcb60c7a7a2c789282c5a79200a24523102e6220b70e00c7d6818c6f5d677697827d1aae0e4f0bd67cdba146a0e3aeb83ab8e2b2e52a7781b9467e3ca42ee292747ccd7141858e6a9e6979f0ed5b4f6ed41f1167c1518575bd6b168271ce1c2324490f6b3c3f38b1b549cef5f431325357ccf69aa4f637816f821b665a0cb74157c6b36eb4adbc6b4c680855b2e8d2314bf0616f013d14084704c196a3aba9a1223438f99092038e3fdb8b451d1f54c9bdf5fb63680f2246efefa21af6425a805c207715c33c2685d9f2482998f21f9390e9cc70f70d3ad2b615a0306504c3aaabc11a628c4b459e8f727775b4e9df377c03b5142da319c1464e33627765a7f1353ae00f11c12bee8e7fdc56829fb094d68eb25951184c441b4a5a11a6cbb8428251fa038c65e2ea68ed27a2a405f5dd19b2b6692bcb8c01e6474fbec4d2c4faad800661654ccfb5d5952aa69296a39765c5ab964e690673a96e714b7e90e088faa4d4cfe8976e58872f09efb4ec4f1cc5e87067aa695dd6fa7e405a7304e1ef347ff4fd8999b9fc082f2a2716496a1ac11ad9711c1d972c264d1cb3387554e68cc27da5e5dda3ff4a44a4298ca37f17e38f0d1ec3613d41a7d390c8f25540631c16daabf81cb7ea63ddbeb047f76bc69b3b6df59ed11cdbf1c1f17c04ad754f8a1f10ee85cde7e62647facef00238abd99526f952c61ab9b81d381c42868f15b05156ec8bd893d3dae8819159505c673322e873731906950615850bac24f70be486c9953b526cb68ba656967f9876af4f60c07cfcc249cfeaf2561a2ae44c366dead9591ac22116489b098d397138e5960f5513e9d063f3dd02f0f83d0c9a934fea308b872c7bb2bb3a23ae3f028072cd331d351bf34148347b37e6c72c9a275e992c5024fec878539cdba25cf1976c4653be96741608df5d7580b6a1b49d5e4962994a869b23f06363b9aadcd54294091d3ba8514f22a44959f754e60a0ae54f299dfd789d802692a67222db14d359d893661720b550f0ca57eb67c5f8647c68729dc769ded82d7d77710737d4ddfe63c055309e6c6856d183df86549b82db022800a4ff50d56a412262466721cf8f35f05bdb59b624a7bbc856d5d84d7568a7581aab8ebcfadefef3be3e58b65365e202fb8634b51fe80444a02b071eba8761c2d79d063c0c90614d3dcfedb03f2f160ca88992ce9c7c92841ead7219a1b42d2336801b16e336ac987b80f84bd6cecefb64efd7fd930cd6136fee97c8c4f9158caff52dfa3ec267792c60d199af37289efdda0c2ab29726869018e97a9403dcc1637c34f514f1237f1407b7bb056b46090000074800000316000000a8000003130000004a0000004a0210469dc86e9bba408074fba1d252e9534b8f0ac65ed40b41f509ccd996afab15a20b68d1f90b9f153d10223a365eef281c7688cc53c9bd5d4a19b0509b0bce4232cffe952800000052baf4223e0000004a030019f1e3e3f7b7f6462f111d56850a0c61b4c8dbad054211e64f850834badbec6980b7b4d81f8b0b9981a5cdaa9aee61dc2375345ee18a2a66db5780c39c6e3b9124a465eb16a97669000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a0204bb3417801e577cee3081796332950b136735db24a531b8531c59ea5bc9bcce020ecfd999bc6969919afcf2935d8cb12826546a1e5d0d075b7ee56d0396d608490712048a89f0a8fa000000401726ecacd0c3d5a1aa1bd35a142c2b7e9e62514346d1845e3b87eb9828fc6af043718fdd94d8348444a881ce777f21f8256bfdd591617443b8c078b5088f88980000000300000040f72aba8ce19a2017b5b97d5d9b41a98f5abc393ab8bed926bb86d25a4756da47452c6d934cec18f451b0a341d8f6956714804035610c1677e7938510081f653e000000401726ecacd0c3d5a1aa1bd35a142c2b7e9e62514346d1845e3b87eb9828fc6af043718fdd94d8348444a881ce777f21f8256bfdd591617443b8c078b5088f88980000004a0308df55282203b2f04d7c85df121adc35cb39447d1ee81ced4043381f23e1d837eca1f28696a096b0d909763d90ade0fc529a52ef1f5d39c01c7bd765e80c73ccba5dedbdce1eba76640000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d0000000000000024000000000000000000000010000003140000000100000000000000080000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a0204bb3417801e577cee3081796332950b136735db24a531b8531c59ea5bc9bcce020ecfd999bc6969919afcf2935d8cb12826546a1e5d0d075b7ee56d0396d608490712048a89f0a8fa00000040706cc313a3aca15824e173d962343d4fa9e96b4f3b306b64eb8d0676c837ae931994b65d9d52a761c7b1e816d4b13dc6ddc7a299b9d398794e18e7bee93292ce0000000300000040f72aba8ce19a2017b5b97d5d9b41a98f5abc393ab8bed926bb86d25a4756da47452c6d934cec18f451b0a341d8f6956714804035610c1677e7938510081f653e00000040706cc313a3aca15824e173d962343d4fa9e96b4f3b306b64eb8d0676c837ae931994b65d9d52a761c7b1e816d4b13dc6ddc7a299b9d398794e18e7bee93292ce0000004a030e4e382d25430f4a2ccf3287357861dcc9d93a55c3854f4990f84910f8706a5db11fefea3e5347c299bf76675c62c79171e40a15b4650d61eed9020c01480c47de7f0ede22c399bae70000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d000000000000002400000000000000000000001000000314000000010000000000000028",
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a000000380c863b30d5d7195f74f668bea8cc173643e18c20999e90c7a8e29c32cded6edf144fae91240fba39d7fd35c1fba1a60e9ced79d25399763300000150c496a30f78b2d0c1787fec6b813b9e7247941bef5202d969f877d4409477dbeadfddcb5fa2f6c918542ea30f95c6dc20c57b422105cfaed406021ba38d4e6934ecc850b65960076ac67d1b3d4bd63517f9e3954b1460dc2b3c5169549a48a9901608a5fe2213700b7955ea0896551c0e9f76a6b00e680c4de09ceafb7e8f7f20bbd0b3a0719c6f4eb747f5558256a681a862c54db372902a6cb59600bbc5ee5355943036c7904a1168a2276cc30c0ea2bca7ada8b23fb265cd24ef038bd32378e7d026a86010057330bc78785a94ff90c148b3b8c5f6343ec12dd64f2507a321480177428d1a5b03fb6d1bd296ab51bc975ff27bccb3335d86e4bc1f586f0e678b19645938ee7e6b087cfd7113af3759b0b5fef5a1fa46150c863b30d5d7195f74f668bea8cc173643e18c20999e90c7a8e29c32cded6edf144fae91240fba39d7fd35c1fba1a60e9ced79d253997633000000010000009c0000004a021199a35c34ce01668824e04ba225fb751e8dfe83f3bed560199a5340ed60014508144a59cb1812536fb26d44c74e570f47d17cb185c233d02af1f789edabeb886066a34aabfaee1bda0000004a031062bf68755640def1126562c802cdbb7b06703e60f7ad0b9c58eb37899929b640a71de5c6a49fc823df1f0e56fae06471edbd24cb9dbf39d698d22d6699ddcdab9e7096b4ce918595000002380000050a000000383a2c5db4af04028fc97d326d9cf150a51a80388da52341f35cd846cff4a75f8fce178c819cbd10b6e849905498fe07048b3200223cb8ca5a000001503e7e2e594b656755143bc7a0e4f53ccaaa4327a76c29eddbb58dd47440920e899a490cd265bf34c9ee07cea2040a4b07e5874896d98a3acdcd60279f3384489d7ad27556137858bacf4a44adfc3a1f1c8c56887c8272ec052b12d32d83b1628a6feb1beb56ca6af3f0a26c8a0b025f17006f5ef4a92f9473a80b084a6d89b3f22bb9c3172a9d7590d2169dce2f3d04079a7f119cdf49b45a31681b06ff9adab62395e69e6499d12937ea7ff1ee1681e995a668f4824c5cbd9cb9539494a089fbbffffd9c046d11abebff6196b59f6de2374c0a0e8b3349c6ca7414f1c69515356693b092ea13e66b48663159f9ad038c814e547684b8dc9827e397db055c3c982cf79b94307cc165cbfdab5b1665ba6184e58d963a08f2283a2c5db4af04028fc97d326d9cf150a51a80388da52341f35cd846cff4a75f8fce178c819cbd10b6e849905498fe07048b3200223cb8ca5a000000010000009c0000004a0207490b7bcf3e12b56e54468d32175669306b01601637dd0ee117d3dcc1f01c0ec378fa5b233a6f4fc7455002c593d1d697548655ca87a587f0a11b43e535f92c5699304726d979c8880000004a030864833271f150e03c04a9eba2a1b0edd52b37bafa9f7ca86744262801b27fdb226c430b95360ef5d78ddc71908cd27fd5b4d3bf9b260059c2b4ffd60edee33e66bc7edb0dfce77d1500000002000002540000050b0000000800000000000000000000003822869d7797ea390c4dfa07206b4f5c9847aff24de0a161690be7a5a19f5c5291d2b4ba2a406a4db101a90da87f3c440ea4c67dd7f49425d1000000fc000005060000003894f955d7cfacace447d425b218ab368669ac2782e91dfd12c29f0df63f45e2e4cbe19796661873d4105e1605436ce958c3a6bded22803f27000000387cf3181a9454c276f639b23e8573856a4327049f86fa6b79bd54f4187415b73224b8ed88e52ad47413771eff234b577c2c138b2f0c5831ba00000038c92bd1b9bc7a807980be3be4e016b96905db4730bc3bbf2087ce6b602c7e17ab98962c4d5fc13bdc4678096f495f37ab6efce7647906a67d00000038616e0058f47a4efbf2977d6586c378866283c2eb2d1aad6e55dee41beedda7edefe422ac47c1d9ba49b8982b4ad4c9f1f1aa1b01c15169700000000000000000000000fc0000050600000038fc0384c6aedf678fe5767b2a50dc28cf94fe74c8a0abb8aa5bd73f54a135329ca1c0d51a457528de05374a7af427cb50f761df2640b2f493000000382caa77f16f860aac1ec404849be546c3763245485ecefb6a69f6f441a730f1759cd2b1cfc95eedd9f6c59b05aa5a01d11f9a3dd8b21f0d0a00000038fc8228c02d30736cea18bb7fbd477cf909a26bcb70216af1751f25f98ab079622921cc0b49430f4d3e88f3c8c95b4f729d4c152fee68c87b000000382e9a30a689cfc53b86183967e044be85aad2be18198432e2d63b694a55f900653fe7a3ba927b9a6b26c5769f802fb79843c2e81e49dc60d900000000000000000000000000000000000002540000050b0000000800000000000000000000003870f33cca03b466dca77a6d95f8ed5c96004d6b76b3cb3fa3882d52c2f9576a614247fd499507be4f5a59e8e81be3fc4aba929c2e7c72a41d000000fc0000050600000038e496e9d3592991ce8dab285b274cc9e8fa0722eb95dff14c8d1a7b3045e25dc00cf82f0aac6995eaeaae052f83e90a9101847a19d3f4f5640000003880e8a4fdc9c310e276499cf5dd8bda67a850481a95fdfe5d933fc3ff249d329c45f2d364335373b431f801c35fc2499f7cf6693c346f836900000038ef9f59eb9b5e7456349352a828b40f414b0165a14e1c9ba005c65ab8d91c3eaf3092fb5cbd7682899bc1146c6cd3f9161fa635ec1db90c6c00000038f69ea126d30a30fad37745ad9014a3a907a5120a083f0aef7e7cabab21b72eec547d390315604a315523148c6ee3ae6a0de94bc2a7fdca110000000000000000000000fc000005060000003836fa60e16dddaab13d0b191e313d1b7c8a92b3002f7f42c18d4409df03e4cc7143bc1ee4dd6961f222641b5ebbfda3a5d69cfc6e4d2477d000000038d6fbb803dac9f379963c0cb1707e9e7e7f5716e08dd382ad3532e9b0719944686ad5351a2bf5af4becaf2a673615b02ee605e65e398a89c900000038538a21396d1eb04a788e2f808158c406dbc5f3299e259ca79de526950ceb43d640a17be4cbbe97585d3a7a2abc9c29f5e7c2eb626aacfa1f000000387e0ed9d8e4eb3f2426e5c9e76e4c83a40aec069a0e9a8c0901b415e011820d17440e4d5d83d94bc0b845c5889cf294ec3c6beb85d1f39cf300000000000000000000000000000000000000020000002000000000000000000000000000000000000000000000000000000000000000010000002000000000000000000000000000000000000000000000000000000000000000020000057846641d42d38936671cbc4aba8837843e3d656f7bfb293fec37eee531be56d993b26dc44962d14f5a1fb19a6f375583fd76adc2d5528be4ca666e1828415926c4ce0f3c1c9d0a0f68f587f94915be09b71ade0957497d0abbba8c624c0fa9e07cbd8b71902b051175b2d7618c8f6c5245a23154f0c8e30a93e2f4c2400058283830affa516708698211455bb53843f96e94c45c45dcb2f3afe804a813989363bd3a68a9fd6f4b01c5c262653c4b69a92a2c80435d4614461cbff1842f5a523aeaa54f86d8297defab1f15054c000b3c929f6fc5549584a42e3443cadacfa5074e7094071863dc0840770333015a5d02044b93a2ab032f0944a2a1f6cba10d52ee36b23383afcc64a97e6ace130d0b1aa8002562bf10ac5f2efe6729a692fe6dde815053e6f74624a33e2aae512975ae190f70e50f921740d22c87b9fee65d5758f71dd9a77c189f61d33f8bd2bd9e53229d9afe2951137d308454faa067870a1ec4df12951c5aacdf299c4bad422252e8a4fc5f1bf97513f1a2028f6b4a35c708d416156cfa2f961a6c7530f00ed68d9df2c1d8c49d1cdb253bb4effab65222a238c89a69adbb7c43619317872b3262c6cba600004617cc4566d8d2f3f99d3ac258093decb0f365a7592749ea2f6e0b2b13806d24d5f8ea03210116b2d9648c99ca5e24e2ec4baed07bccd3aa27f9ce1eea1832f12db6e3537c963b1a620627f56beda1ce6b6a5ce2c699c364516ee562e49d88271681ef36d338ad079a61a77a2f47083db95a7a5cd5e7ae19e373a5e1c025a60b300012bb2de2095d5e7c3773d869e65e915759ef3137c01b32a6d305d6b6bab58ef3a8422d643640c284e2a575fbe2b27db9d89532e2ce5101616c1bb035d5854ba5acc0caab303aad90f1d6e5280014214ec28ba548b61546ac19fcc87341e25a09b936e9b565abd492c1e6963ad97f1ca315c810bfcc3d085254c9c97f42026b83f4833fa83218f80a187f6508e52c98e058f0c987a308cc290a25cfa1f5090446297950df0cf6b7556eefcc91791bd741d1186e49bf75ff39820e466528a0b0e5576a1a856e9da36638d2d5d807702955b13b011a2b633f0ca1708cd7b3cdfb6f4f66a31088fbb5b6bba830262150a2168675b5d8e313694fad38c690cdacd6fd0e846f5cabe6ac220fb0d63782d16b59a0d68c778d7a717aae15290a19073c2f4246a1f523f6d53c2629fddfd747d5f1ab097d78d7ea7d566a666af017629f4a0fbf1c4734403f738c299a378f91188c4a4e67910bec3811cc85fe15e3c4499ade78fb6c4c181ffba0dbc4b7b0c05553d48a5cbcf40df9751f1f4dbd5e2a4d5dcd1828573380e2661ac34a1b708e6dbd71a5526955930003469d16776260031e6957adc9f0ff5c6b741724f3a94fca33a4d48608e44545e6bd01fed10359d3ad8d78f2d7e20d2bbdb4a2fe574dcf9ab3321bfdc35c385333f424f8c4c6347e6266924f7e87bcb8bedf36fa8ad2d2b8ffb8a2b4a13f989243e14a5fcf8519aefce55d36808938e809c54c994013e07668591c9f2c0c8f373e43a6b1545c269cd2f9e59a60360f49a8211c1ad9a59cf9b4e31df4aa91ef05b64fec4f0232717d46c614ede46289acd06db589f82c173da33c6a57e569f0a18c913b5500c8dac42e9d20d42b22ea5db84dc6f4543f85f19146f45b435c2dcae8cf107a35ffd7dddd0c0fcbb8fbf5a397e359b25864cf5cab5f8b546879cd364335803099cb6dac559be204a85d00cc644f9b813b254d3f19e87ac95c86bc8224d085087f543e173d4b1d8b7c9d60bd5cf11834af35ff43ab17311ad0b85a5f64faea8c4eafdcd3be37f96bdb1a43469214ebaac12c393fa23068f0e43008a7c648698498edc4d525cff80d47e1628580253d940c8a004a52fdfb79ad919fa008cf241595195400a210d17e0f518d972b5407fbb17ae30cf9bd0279472c758f453a0f4217d01fc596a71f0000074800000316000000a8000003130000004a0000004a0310126c5d6480de6feca007facd642fb9f4527fbc52d1f22d30d4f6cc5949389fef6c4c9e5412dbe5b1df68569508dc8f55dcb5b736e56ebb879e12377315813bdae3db866700000052f6b1d7a40000004a0203ccc67cb218ab69f2c0251399c4af94585a38ef20aceb63dec52c66669ca37285314639ff7600a2bc2f7ce829ad3cf1bf6ca0f2c02ff2864f7a337f7312fa933655edd52e014b4051000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a0204bb3417801e577cee3081796332950b136735db24a531b8531c59ea5bc9bcce020ecfd999bc6969919afcf2935d8cb12826546a1e5d0d075b7ee56d0396d608490712048a89f0a8fa00000040709f9535840833b7e48c45d35904520950ae679148e7a980573df6022c79b0d434ce993e2d5bc2a4ae7a83a8bc46c818f2f749dc8cbc0f8eb82f97b911b41ea70000000300000040f72aba8ce19a2017b5b97d5d9b41a98f5abc393ab8bed926bb86d25a4756da47452c6d934cec18f451b0a341d8f6956714804035610c1677e7938510081f653e00000040709f9535840833b7e48c45d35904520950ae679148e7a980573df6022c79b0d434ce993e2d5bc2a4ae7a83a8bc46c818f2f749dc8cbc0f8eb82f97b911b41ea70000004a030e724a32423c6019bced8a9522f78e6ddbacb3aabd387c4b962260efa3267359932059128bf229798cd74001ed9f22be021b76c95d5cbb03f17b50b74ef92369c8fc7b273de3da1f040000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d0000000000000024000000000000000000000010000003140000000100000000000000230000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a0204bb3417801e577cee3081796332950b136735db24a531b8531c59ea5bc9bcce020ecfd999bc6969919afcf2935d8cb12826546a1e5d0d075b7ee56d0396d608490712048a89f0a8fa000000406538407ebb46fe6e5e585b301b7230a822a70f1980607c5977c087e4496711506091e372d903c4b6a3b8e0b278bfa6b4daec1c52d497da40ffad617874169c8a0000000300000040f72aba8ce19a2017b5b97d5d9b41a98f5abc393ab8bed926bb86d25a4756da47452c6d934cec18f451b0a341d8f6956714804035610c1677e7938510081f653e000000406538407ebb46fe6e5e585b301b7230a822a70f1980607c5977c087e4496711506091e372d903c4b6a3b8e0b278bfa6b4daec1c52d497da40ffad617874169c8a0000004a030f9053d34dc6e3f62e7cd8fe42aef9071766377943467b469c33d81022566009e20457d95a49886ac6dba89c45f56b7dc88cdfaa971410fdcf78dbf0f306199ed2941b7017a978707e0000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d00000000000000240000000000000000000000100000031400000001000000000000001f",
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a0000003854f22387bf44bb124091d8bb190ee10b0c386002518e848f81df838fea97b8dfc41b37dd2fed2a39be0a247ff173a78e6553f8cf0685537d00000150235c387befb1b52d86e7599982722ab5338f3a3fa14f0f3057ea944e2ebc927081f06e824401dd7c100af302938cb7ddc9260c04241d5062650742130fc411efccb8443f870b9a7cf2122adf4c757426a1937b5bf60650d9f0253b8768d674c4b82a619310908ca2a7bb4f209bf21125a30a94feabff28f6d1c5b2bbea2a9ddcbb1f6d847b3e4a885397786b29330982215a66fa0b44dff993defed539ea8555aed65f8bace7853bf773ebc84990ba92f4579f14177ac30a8efdab0080387ff7e5ee81f38ab797e42ccab93190cdc2e687707de45403c4850df4a8b0b1628614560b56505ed9f90182a7d6c327c24813352f8dbbdeeb217d5864125aab3362e8a462c05ae2cbd8377a1f557feb330ec086e6aadd1e77ac7154f22387bf44bb124091d8bb190ee10b0c386002518e848f81df838fea97b8dfc41b37dd2fed2a39be0a247ff173a78e6553f8cf0685537d000000010000009c0000004a0304e779919dc34bc7fc29fb081245c823aa90277ac6fa7812c13e95fb0c3d1b95733825bd537892c79557e724054d6c066e01b91a302049348fc91c4ca2be3333368589aafcad6876020000004a0302687a7e05c65f1ced34a0eed1cc13107c42188acc003070af6d0eda91ea2565ac677ec18c6806c6472e14df5515003c6019b84e65e05e57fad6f024b96b29767dc0a9f61820e29cb3000002380000050a00000038aea03cd1e5296fbbd4a57adb77fd68011410a5879d277e3c7bec1201ef8bfd46df0937b197a4a10401d73f4c158a945647755aacabbe6962000001508552c5667c9958408a72abf9003f8809a7556627d1a5a96f8899a1b14c718f6e3c2f801b9d97d043cf88b592c9bc1e2bf1967e00dc4925974bb8b1ff0895e3e4503f25a95728aaf6d0d26ab7603bd7faa730863af1d1ecfd0e0a9b3b0c52e74fb353190ffcd97754e7e81b4bca9faf379c4f08720155df6444c562d0b7993f86944b57974d885060b0106cbc80f5fb7e39e6066dc439b7dd3c9cf43f38dea9d6cd85a2982897e13597ef740b89f04b108e950605f562c443bf7e5300cfb20102fad1d0917fbf7c0265b8b90e267847fa72d9a18ed6fcf7bfd74d1c57c13aab2344c02fab19700480662ad893619a9836de1630e54c937a6a94372876ebd04a5af865c05202b3245366404e3cb5b4601b50a99439a0c6c06eaea03cd1e5296fbbd4a57adb77fd68011410a5879d277e3c7bec1201ef8bfd46df0937b197a4a10401d73f4c158a945647755aacabbe6962000000010000009c0000004a02008e45081607d99cd913e7435bae72a57cdf83b66d37ca79c0f7afc979ce9e93b6d7a47f12a8ffc0a18207693ef14c37714145416c0f8a21b449dc026900a21cc9e58e4e0046b7f2ac0000004a020c3499e3153ef037baf7cc330767b6c7378fdc059180d2f8846bb2d54af3f9147cb862fcf5112ea7daf284dfa3921e7c1f1da6c2ab396b38650c5cdaaa9209cfc6170c0c454919940800000002000002540000050b000000080000000000000000000000387462d7a59d2819ee3de92aae05c0eb1667e80b00b327aefe39d97f81784e009610ba7d44e91c8cbb350fe63e7ac0bc91588cc0b4b09faf0b000000fc000005060000003878fe0469d2a35b762fc61fbcb8b1fb536186b80ca76bcf7355b9dbb2305964d7d5a0e19a6e8aaca56efda6041556763d1c419f55a19ba8ed00000038ec0c69e73db75883fd64ff32bed86a109bf86c81503e149007c6d4f84005cd4c4ad3bdde212243810c9ac735d9931db29a842f962f9325d20000003854eb7e8b911e852976c3fab833d65137983d4847818e92f22e4ecba2081963dbb7ebdc12493b0382ec9b41806ce03a8bf95b6e49432abe8a00000038b59680a0e5d4f0451597186a12cc2b83e0b32eda2411d30535f372925a392faebf023fffd0d1c2968edc28c12dcabad340bfcca7b1c1a2ab0000000000000000000000fc0000050600000038fca479c5c4dd9e151792fe1960d6bbcb822dbf8696dd6aee0bedcdac194a700be822e610d14be8e4b4b29c388864379f8680d67bc16675500000003862f5372107ad07ec6dedece4ee4550bf8d0cc02c98d1f748eb6dd5e50258ffe5e21e34d02055c775be42cc3c36400732b23a80811fa04042000000385dadc6f19f52e112fbb3d1c5dfeb336a95212ef41b97e4d4d395aba2e19f6b2193514276f851b7b11ff484c7f8b4f36fc8b3c67c68d73344000000388457d5c290161e59578c4ebb4383a126cac4cea1b96f31ca4f0fc06bb41dced758bd599f486de104c2ffea52f369840b767a571ce014b73200000000000000000000000000000000000002540000050b00000008000000000000000000000038e474a9c0b4f01f2b0ae77f307bd683e9527f8905e83644e056f2f91b42005ea97e59f4f1fed8ffd2f41e638c12b27fd2565920348df6e312000000fc00000506000000386ef5404a0a687ae316d2036ff2ba05fa2d80a62c9e256ed3cab2c943b3b4153d16862c5e09969951f7306126a7b698b84b405889fdfe61f2000000385ae44ec256765a153ac88586d6273128b24ddedbede7508c41406c8b1cf3d8610b066c1138e6afb2bd3aad94544621a52bf9b43b9e1d8a80000000387a03b5fd354bf81b0afc5137a8079ea18d5d76eb1cacd7b50137891ac5e8b2c2e8918c76b978103123974b238c3e15ee5a82e125dc1b13790000003868a70e0125a6a1e64e6f91bdad5eda2bedb6ac9477e0142fab5ef4866dad3b523f949e2d79fa29725632256af175fa777972e1cf9a72c81c0000000000000000000000fc000005060000003860f084d62a3aac58a7256fa11d8b5ebf9123f8a14605b6cb0dd2c13fd2980993c0d473d169306d5a9d0c98dc4cd031ecc42e07299ef6446100000038665edf729fd868caf9f75ad9487b1a0283c8ba1d3870ac228a9902cdbac2f12108f35ae20aa7e0fa4e3a56938e53337bc9b54be32ee106200000003853c886c1a374ccd1f78a96287d5d27c3022a435b88c6ecc05432789baf4744bfd9e129481ac9ceea428c1a14f5c9c1a030368e21bd893b4000000038fc23bed9b74026e1ac301496834c01e9c4ff595a120f6b0cf4b6172a87a0ecb8615bcecb84b3168fe8294696ca44efd0934e3255f2fcd0480000000000000000000000000000000000000002000000200000000000000000000000000000000000000000000000000000000000000001000000200000000000000000000000000000000000000000000000000000000000000002000005786491c88ab02d8568622d98f41eccb14409745091e7630e2eb08f7143daa36b3db5d5cd77a44418db2eb4103eba10b148df4684a1d19802e11273bf3d7f01307d50291c623fbbde73ddf4f8a21fa8a059b7afa378b9c50cdea055b088f516f9ec2ffdb7327f3cb0a84fe658234b572fc73a59ec7d6bed2eff1a0716dfa2c9b35c4207c66a4a3fe891ae4e0dc22c00b1556a0e10b4239cac79eb6dc23bb6c7cb80f7768ab0f2bc24ec62b4457541697c39d16041dfe63c370ad6b46d44d6698ecd9180d0c63f818d916adeda271f20363cd4d5d960174a6228d505ce71bf71a6214db093b684f8f919a2872abc038ec94206fd97ed9563b41fa8fa2104c65b3f27dd1fde34c67f0b7cc0648a4026e2382df1b8d814caa99e212cb54b4b311dbbe5d49ed8181818252f71593458a4875c556f78dcbb925574dd0d963cbd9d1d6a8753809339d546e2ee4062d2286452c0241ebbec79f355511d2c01a14b1c8b4ac9aeedf828834f9ae9ffb191665f41b582c799f6a660eb1eaaa24b430dcb3e08676e40219368485406744fea52264a159952201542d47c06fce607057ed1bcd210ff601806e4b32eac5998a5a4f5ee1b7cd3f3dcca82cd43a2091a65e208c9693f5c789411e8e8fa532fd18c6382b4e3795dc10e4f548d48b69374a55b20bc185e125d1de59ca7729b95eaf44e5dace60e2ad8da685b53154c8c1222f5b830ae4d8d4bf1ada108ba3df623ae9fc26febc7202d2b3143f91c4155efa1787739b1e5d1cf2428db3501a3afa22a772d1d44c13ca50c16aa46fd9b70a7836d247a4da2559ae20eef2b613d16c9d5a0342b1b17323ec554401be76510c21712fbfc8f7eb5e572e3ef04da52c2a3010615258cf8014076e0051b6b54642d46f76d8beb1034c89374178e7ce6da5dcea291917dfb853dedd5b8c0b8c5f1389ea47f0e30591ccdeee85ff07c1bbafe0f1cda786d33234c237ff03153b86661a8b06b5c0e1daa8cff30d073c7ab21b8b8e380666d0307f2c4554eb3a391acb17f77ff0bcdfc56908e4a4dfe47c29e1bb03d23db09f1f80d33e33c195d0df70ddeb4916d79027a4b891605a759f5bb2c3c3ea43629c0caf5c5aabf643a1586c9b2ac1a47e386525f66aa76b27e71ff7bb109549b0ff3380d0f853374911a3fdf4afc3953d201d216e6644d85ebcc98201a210fe4e0c0403092f57c59cd82e4997b8e628e54d5795bf1895cc43a90d6dfb18d6bd36a57293bf1c9f5313970aa671be0f1e2dd2e96d133a9bdffe3e6fb4f4d4505c519be4b97a76dfb95141abbf59fabe02519399bce89c5a460cfc386f7cfd43bfe11e28033a61370dc6c4852afaafe1d3980fc4e3ebe6159ddb5900e0e3b27ade364cde6c7d56d960d546db93629b6ac3e90c864f3070b410309de486fcd3c278c2d7a1ca45d70012a0b97bb0a8b1e66ff5956e3abb4abd49a8783b7b4afd96e9490edeec2a420f3f752932004f1f2b7dac3cc4cbbdba30c51f5c7aa3114294f0a0c06c932e4b48fa980c2ed29b8ea5e77b05251561905eda98dba88c42572e6c931d03203a2bb11795f42d122c5d31de70cf650a8e6eab961b54c5a246d07c6a3c3c0eaface7085e28ac92b0f97f4be6de264882cfbc483dc34a4070a19fdb3969cbe57ae8758dd2ecac7de866d68dbb16a60ff889632184f95c705e605d723810c58188ab65e06c394900aef60f4aced2f9f9c55b1af1ce9df0a4ef24453934cabb12468ee826c12f345dc79905f432c2c75a77df23af4c09f269bb2673233d48b167dd81e3472c29f43d90706226df29903600890bc68613253693653b0650d66bb6eb8b9836c6a1e57687ad57d9d4a790c58c0be0ac043a1fc81cb2a3bb86499df10a7f8dbae801a82333ed8867d9b8d3ff2099e870d5a005034018be34afc4fca381338dcf212c80f8f60b91ef24b1ad997e75a393a67550e127bd594c768b5421c359125e5d3dd2c0000074800000316000000a8000003130000004a0000004a0311e108c705442ee38e143e1381de7fd76996651fa617af64174d2383956cc89e0f19e23d51446662ab4642c962ceb1b07a9014e9b48f19d00f54c936e924c0dfbc718e58de000000524975f1a30000004a03104a8c519e63118faa17b7df69f2b47b3a148d311d97c550c7ea458228ad6ded3b2865e31a2ab6ef9950aa6e323a25b47688afb05286d7cbe003288da60efd1eb7d5ab8e81ad3ef851000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a030a47594e12b69cf9f781087a1ecd7138047c5920098eea69737fd21475f8ec2c9d5b7c326f1c06949a40f781d6c3a428fc7b73cdc5ee76164f718e390e0e4fcd9f9ab7df1a6a9f3296000000400c9122fad238b19c43e7b642a01f483fb6fa024df0396e8baf5ffea1bb32edb8b761ad5f3c3618294fe395d7be7bae9c942c801b39ca0384e1a61d40826a54860000000300000040a138e834a7e59e8a0a711f870eb9e32cfc33c0b427ebc245b4f8474a4a1f3858083f4c54aa592ee41e64c197770def81aecb8f36ed80411e5df02892e48c00d9000000400c9122fad238b19c43e7b642a01f483fb6fa024df0396e8baf5ffea1bb32edb8b761ad5f3c3618294fe395d7be7bae9c942c801b39ca0384e1a61d40826a54860000004a020d88b324089d0052d61fe6cd87c52f8b9f846578cb11aa912fcb15b1ee2fff58dec4e3c79a522b4595f8396864fbacdbac0d88b673ece59803c380380903bc922c4ca3dcac0ded99ae0000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d0000000000000024000000000000000100000010000003140000000100000000000000220000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a030a47594e12b69cf9f781087a1ecd7138047c5920098eea69737fd21475f8ec2c9d5b7c326f1c06949a40f781d6c3a428fc7b73cdc5ee76164f718e390e0e4fcd9f9ab7df1a6a9f329600000040f90da4e49554d5f809575076817668696e2ce15d7f99a5bc08e6eee1c3cabe3d7fc4eaa759073cdd5aac767673e60110e79e0e4c1d0031a7dd7255b0fe0b009a0000000300000040a138e834a7e59e8a0a711f870eb9e32cfc33c0b427ebc245b4f8474a4a1f3858083f4c54aa592ee41e64c197770def81aecb8f36ed80411e5df02892e48c00d900000040f90da4e49554d5f809575076817668696e2ce15d7f99a5bc08e6eee1c3cabe3d7fc4eaa759073cdd5aac767673e60110e79e0e4c1d0031a7dd7255b0fe0b009a0000004a03015b69771e503285338884d8c4f062aab9c219d4dd99ce5f8bf7dcf0fb5b7bc5d4ae7c3c13975c1d769240d08177763bdfdb6b4748d916254a66f62585f72c179d29375f8fa9f227bd0000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d000000000000002400000000000000010000001000000314000000010000000000000025",
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a00000038803e6cf22ee4363df44db5f41d2b727d3386daef8c2197e8c2be78cfaf03fc12b163f11446454b75db66dad4fadfa8391ce78e3453100cc500000150d6a4afe9ef00ceeed7a0cb1c231273a8cbf80eed219b9d014cbdd953346a4f089b19541fed0d90047e6b8b0280756db1db968f9bcf36d46140c4605f9abf24549c60e966dd2ecc256a8ef363f1bab43f59a6de518d99308fcff041dd76c5f57e3314b3a3573b6d49728bc812f991233b283dd69ee0d88ca8e7e63f21e9b78d4af5e92d5e59b84f4b0c657750930a082757fb1910eac4c88f8fa57db4b946da617eb2b6caa2f80c290cbb3c455898831a9d18c027eeb163a9f9ffdd12388bf1131dee6db323dad47408899c81887feda1776bf036fa0baac58d153a6178677818b6ade01b62ece200b427ef10a65304a1f15cbcedca17ab4ac118bb689e530fc68114010289c8bb35f80b783136f9b56d436c029e66922420803e6cf22ee4363df44db5f41d2b727d3386daef8c2197e8c2be78cfaf03fc12b163f11446454b75db66dad4fadfa8391ce78e3453100cc5000000010000009c0000004a020a44132692bbc2cb6abfd55a2b06b0d62dfb5a7e42bd2717e7bfc5f3116ac508aea5988a05c3e59139016b9b94d24e1006ccc2411526e8f93d788505af246265338b8a334bd021aa670000004a02067f7b6bdc584e10e6272d2c7540a3bf7eb9dff38ac71b8f43f3b91170ab3fc061e0f7adcb34b06aa35c33113b1d8a2d6e75fe252c7001daace1e86c4691537a9f39d625781756bf2c000002380000050a0000003870bba67d6c3e698d796082117612c0decabc2e7d8dd9beba5b3b663f1450836f65e816564dfe743eeeb2b3604f3b9a420f7d68ebe2b0d96e0000015050f8e967568fa71055bf3305ccb6ac150da6f6625228a6644b1f6e7be5b3f36d4f0b4e8d32a1fb90d25af2e572b998c8b2cef82b8d265ea852dca7e07aa70b5f46039c436f596d0ef06921be0d7327268d4a97c6847a87b2f99f04cf7f8c376c65440f47f634a176c6160cf52268fe2dcfa969aec10f16cba488cbfce70991c09987c16f9831dc43ec0a68fdc7073550a8d5e55b3239bad9c8b7962b1eb7ba7a62367059854e381c292cfe0e9213474fa9ff87ba087899d07e9cc3418d93d88495a3d40112319607ae4e3db6b332f285bad8ba804d0114c7b6e90a786caec8272ce6d8d803addd976a4a09fa98781d9ce273e21106c0d1f5bef495a3570a9ff4afac556ff803fda6d62d8a224229b8661f29a17c2877a53a70bba67d6c3e698d796082117612c0decabc2e7d8dd9beba5b3b663f1450836f65e816564dfe743eeeb2b3604f3b9a420f7d68ebe2b0d96e000000010000009c0000004a0208cd3358ea4d92e626b4680550b1a7daf7af022bff15e7a771a2e8c888e8e796485e2ce8a5dda9a4ae9b38ca134138d2473096082e947f1dbc0ce5257213b68cf0b96bcb99a36f79370000004a0302c9c0bfcd4f1d61cb4ddbe45c221f94af5777da9082014ed92ff33b2316a8b7a32505da1df90082d3079f5ec511dedf87584df7ae03795577503ad8e8134852961e10ee76db511c9600000002000002540000050b00000008000000000000000000000038ae4dcf34313c53dd6444275596e5b5c636b9072525b94b7b7e28c2916902a1892b70236674f1278c152b380773a26d29cf743e1603015332000000fc00000506000000388cd579257a99e7eb9d67adae170fa830f555d716f66832795895994e66127bc211e725af327056da627a594bf0f026e4ac2a61f350bb71c700000038322e4087f10355632ae1c3b7bd39205016c655463f09fe2e990eb07b8f4fd280df177d37936549bff833cd4b7f306ba9ee11794ee9e10c0a00000038804a49bcce54b3caf638f9ecda7fabda542b39891a5ebee0deb19f7e4963a33bee39daed9ef88d612817a68a40a6119151d3982a306e360a00000038d9df1bd12af77b5cc274a6a8777044d09b8def4e17f7c232d25c44994df6c7a83d1da6f8e545d10535380d3c31e9912b60f295395130e14a0000000000000000000000fc00000506000000382a4d3c4f2f743b28b8c487326a5e7db3da4ad0c1dca44ed3b7a339dc777a1e3ea7874cfc6dc21ed939db7f0620abb826fd810b43e40deac70000003826c5753a40dce0a1504d75024cd331797ce38008fc61f90dd825cadac46528f88625dedf02d8d21aed93564110c0de0f9ca619010c372d920000003852dcbf2ea183dfe501dbef04b7587e47170ae53f4980f62ce42d0ce3b7d6cab798ca6b8e7246a7691f4541a8cae06f4022b7e3cfab5f542700000038d5e2638abe3fc050fe9ae7f0060f649ff9955844e20839c7f1d6d84b31a04d3f3e24fbf550fae545ca29931961312c1819e44995256ed28500000000000000000000000000000000000002540000050b00000008000000000000000000000038a4e7a2c258cb6bc5e6ad2d9dd25819b07172518329f90765c6dc06fc33cd4c30760ccab1602ccba821f26e0276e4713478a6144603a9d8a8000000fc00000506000000386a7dd19e2fef18acce4d2a4e935366e4804a69ff72c327c2c7b78e2d2b63d0d7bc095406940c6baa4f8c5153aa51876e221a76b4d906e8e700000038d6e8f250022162b9619da0d02aad25c93bf2db90ab53f628391eb4960c5a344946743c09d04a301e9cccbb4dc2de94f2d7684d1282a19dfd0000003876e88b9a107361e146817d297b482cb9924e62a57f9bbed23d0f3ff42b2c5b6fbbf0a002de28d7cb27c3a080466945840f8e16844faeecb30000003862aa860026dbd2c05138e3bae064f73909698d976059154173518ce2b66fdeb769a0554c2836ad31151d0e292df4f3a25bed4b5127db2d510000000000000000000000fc0000050600000038d4b6f4f153b3fc55ada6cef559cc6b7087584dda437a4bd3746afda281a0a21103240e311693e54024e9f5eae02e4b5b36c142aa4e661c0600000038c026d4fa1e75426c2eed0b93fe3288de08a808ac1148a9c1991034b7e44deb52a04a8092d9f9ec4aaeaa7da7b430975c9100045de555536e00000038a5c44496472863c6e75139ab8422128a514cd58d534d77bb0b42e5674873002810e5d304aabab1a0ab6e8e2039420c975c64b6ea5aa5d39300000038d8316f45b60fd1dde613bedded5d8b5b0897c2d3c2467c501741122ef3e61d1a36057a3cb8f75b970f9e12fa9bcbd978440e12f7716810fa0000000000000000000000000000000000000002000000200000000000000000000000000000000000000000000000000000000000000001000000200000000000000000000000000000000000000000000000000000000000000002000005783a426983d94c223c6dfdf38e140ebc7aa862ba94f5a5ea568adbc76e42211be9b2833664121a6a32092198359bd1268aa293236104ba69e11ea6b2c84347a5852976f06d9a56cba9bf199f501110f0ca317ced3f19c5df8f75d6501ad734e2a994625c6755b7d3bd364151b6c6ca24069ea707da72e04ff4a45696dbceed5e1aba5ea4e37f94da8d2bb3f29b2bf8ca44ccc0830256f322021e443734001e6c30546d3a3d360c345a304886d0383c2607a5040a8384689e415f6500fe028687507a2c06240a1f8dee68f3fed347b7a6399d56793aeb260639ff6a28871290326d3a44874eb5703e3d807ef17cc11727c8cfb5a325e882c81aa40055b933bbdd202cca0d763c5a4bec03d8b4d14c2f17b16add528e4a29272096274444fc344055a6941fa0bb98a57529b804946570ada3dfeb232bb8d1e45bccd5b730c448408633a11c34885bd993a4dbfbb53b3ca31d2236ea084f55a5a4d956148c3ba2fcba45f6e32256448f91289cb3ade5061642a7913b1af2bf884870d346c8f36a18b1fd6648d458ff6b0432c36beacfb6f20d60be43891378366f211ccfda7a2d1d033408c106da217952881098c86e4a2e3f4d39e604f13e3fd1e770f7d2d17406cf8a6a9985f29eb5fb2eb6399f4d29d1fbcf298928d9cad1a23dd6ea954a67e80068c9a4b2b733c2c5441d2a23783963999aa47814d8e65a1e60b4f00eab4c3b33f6f34c86c44f0435273200ba26431410f3a584c7d1eb50a2703989f05368e946e886259027d7b7c9fedef6208705272f16d525a56d8ff6cea3c889f13e5888c1f51e673e7040bd77357b2454517faa5b9b48214085d50c819f4bd66218937b1f417e15a53602d0274ac42f39880572c604485377b7bcd53ef84a4e6459f3084e2b83a7a8ac3a3198326948e45526adfd34064aee6be16cb86b6c8f5b7ea2ca0f867385f565bfbf3b6ffbc87857a0ab54f99463df8458b239c1da7cc6d0ffdc6e9b9f815b3e64a66795169357bc06872fc2d8f6512522db036c958c7622b9bf9d93e08136a0d3e1fe4c3db543999f0eb95801736346bdc5353e7831a88920912267d7a23fe730d4a0c7e04fe8c18c8794fef9f87eb9b6109a5fffd884184c643b994d2db4307785ddfb1ab175685cf0bd4484f0609873abdda71ac471fae4aba4ae6776f96699b1e19e9be49a4e2619958e52ca97d3f8ab1b32142406fab25634de2eea38673df9904e470efe2729e76b1a43eaf482c86c2d274d737c3e5336ab1616a2dc248712d1ac15033d38314350cf59dc919481e5f1750f923076beb44142932eda982e0849bec4ab50f997198ceadad9b405b430497464c9b78023f1255c3840678bc1c681be72ed20c2334f10515ce683777d9c129c0273b144197bd83683d33878924e3a0b81c9acbfe7be69d80c18e4d4ad980e16b7e27c496b1107bb469384f7fbec72af9da10dc1810bc9f2516e81778114a33267a195321d18dda57e4aeb4ca7365f78b578cf09f0eca5bc4a93462b00dbdb5f78d0eb73c8b9ed4da2dc084c85d752bb2f81a01e1fb9ea2c502b787f79d92f5d12a9619c1fca97d2431df3fe420c78496bf970d853b12dd58a0431278beed8a516fe5f727a3e3a4bfb75a1d2ea97fbf0887056205ae094d5069ed9bc21dcb3aec948943ddd1649c78e6906d14e2405e0a0abae912c4cd40e513ab2ce827a399be8b8f116c2cda0459a98b32bf69408a0622d6df325f427f2aabe9a24123dc601392ca581310aa0adabb692845e776aec19f861b255875fa50dcc5906ac53fc4452adfbfc20b35d907f7d6bc498a48aa08596707f8f0ff41def8cbb877369e9fdedd8ef45e0d5fa4845920e56a5a43d1d119efc0a06b1ebb994df5439f3937c426a8730ba6ef832a914c6cdcafc83f7e54655f457c5e6f27b202a868774bc62d2240492941642e046ccf30d9bc1f09dd328fe2f0d1b3ff1f831bd221d3f75170000074800000316000000a8000003130000004a0000004a0208f3abae7096338945c24e1870ae67f96d23ea078802f7f7fd469810c11ec0044ac504e02bd0c449466a64e965873f6a9f13ab61d4cd3c01118187a16b927ec1736441495900000052f50d4bf00000004a02105327ff1dba5b7f2ce0162d7d8f638f324483c16670b786531ca5f19c1aeb3acf6003ba4667eb0c1f4f9a74d3c9eaac50cb31417b20c2dc8f0f5459f82bca81b24b8dab685be5fd22000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a030a47594e12b69cf9f781087a1ecd7138047c5920098eea69737fd21475f8ec2c9d5b7c326f1c06949a40f781d6c3a428fc7b73cdc5ee76164f718e390e0e4fcd9f9ab7df1a6a9f329600000040ad1fde2ba6d9f39b76b5887e5768edc59d36d314ee8fa20d55b9fa26e59226487466ec98f367e5926a9305a693b72cb349ff19e48725c0a54960b35635df8d080000000300000040a138e834a7e59e8a0a711f870eb9e32cfc33c0b427ebc245b4f8474a4a1f3858083f4c54aa592ee41e64c197770def81aecb8f36ed80411e5df02892e48c00d900000040ad1fde2ba6d9f39b76b5887e5768edc59d36d314ee8fa20d55b9fa26e59226487466ec98f367e5926a9305a693b72cb349ff19e48725c0a54960b35635df8d080000004a0300bc59ec21055089c298489a9370ac660b97cee0870cfb22ead1be4bad18aa754cc66bc1e7dc6e3527c929db7876603aed6565a8a99f4a2654454cf9160dcd2aef53638e0ef6704cc20000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d00000000000000240000000000000001000000100000031400000001000000000000001f0000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a030a47594e12b69cf9f781087a1ecd7138047c5920098eea69737fd21475f8ec2c9d5b7c326f1c06949a40f781d6c3a428fc7b73cdc5ee76164f718e390e0e4fcd9f9ab7df1a6a9f3296000000406cbd0f2e78f35f8c3813ebd95882b320d9b1ef7cd0f758806c14868ade1bace046cbe4f19f643aae254c899677537c4a5edc5ab9d72966e5dc320617d6ef389c0000000300000040a138e834a7e59e8a0a711f870eb9e32cfc33c0b427ebc245b4f8474a4a1f3858083f4c54aa592ee41e64c197770def81aecb8f36ed80411e5df02892e48c00d9000000406cbd0f2e78f35f8c3813ebd95882b320d9b1ef7cd0f758806c14868ade1bace046cbe4f19f643aae254c899677537c4a5edc5ab9d72966e5dc320617d6ef389c0000004a0302c9c9d4dde5e62aafc1683d9ecb81791f703036a317b0dd36582c70f1835367776db27c824552210a7b5d65ccd9715870da915aad587fbc19e425e1668882fb416184b45af79457a00000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d000000000000002400000000000000010000001000000314000000010000000000000011",
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a00000038aa13bd61e0132474d7611d6dc624213f3898b16f85a0cb008372a39fbaeda5d4c28f8ace198c4849256ac3c6a8fc856c5474b0bdb3f05704000001505ce5e784b5874283895ec8b2425180ddde53b4561169c81699d223dfd5b11f52b9ec9d0e74065c9df2980bc18a493492bb2113381fa451d0a5293dd8aced95934259fe1f522a933a41f6a78c4fa83f80d7969767f3d445f64ef07cffc6ed429970ccabd0b72b9925eb3438bc548d113585b84fd792f60e3b6180cc390c42600ee08147bc49b294ecb6b926813b7c3bf40cc32e3cf09d7fd72b86731d37aa2931827389252bf5610bcf22fe54e56446ca43033434f7949664c2a9f6f08c7155447ed72c5bcb1dc6c524d2212ad5cf04c1cc0f2a31b059569bdd4fa4a062baa40d287ff24c072e16cd496861d43cc601b8eecb51da65ddb0f05306f7f24af828c44897bd1d0075734a0f7c7c651bfc5c7747453fe530b924e5aa13bd61e0132474d7611d6dc624213f3898b16f85a0cb008372a39fbaeda5d4c28f8ace198c4849256ac3c6a8fc856c5474b0bdb3f05704000000010000009c0000004a03019d0ac1f065be9286c0c72a689c78c88f540f2e0a187f2b86934ec4de25203a504768c2f3d994058009648821989ff1e6a61d8d53cec09c625b754230d1055583962c7bc9314c4dd40000004a020b22cf64994049e6d6a67bf14e26cd08738d1ecd76e99f224cc38830d90ebe051e0128d11ac3e456481ba6afc847f0c2f4290fb1fe483d7302d470bed16be6e7b9a473ba70e89dd1ed000002380000050a0000003870452ed77781d41f3a1af90b008ef4b2330a94cb20f82a5e6536fcf96a5257fbbb393f5f8ad227d35f21a4d19286eff58c9b36ebbe30534b00000150458cdd0d9e44d80f85a89e3c20b3d9a1f015ba379ceac6641cc86a120fd02b32b3ddc7a7c143fc830db0c6420b4924226b23067592186d2a232cf6f3545a284e2e78e5d9f16a654167d5369d015396c734038c926b9888a4b418af71e22479c30b59f2ffb0e72789288416b2238ee02d13f379fc22bbfe1dd9cdbfcb2d707974de74907d4baf60371fc2e04e0fcc90f533207844db1c0be7ae4c1e9f1dc4a1d75e056f7cc4b7a711d4fbf6b4500bad7adc965c774c7615abad6280097033b7038f6b15f9011e637360071df2082b648a7e322af5ca73f0e42d588c997b3ff63006a32053c55c919a6346ef2ddc86891b4b32768cd0fb9f514d4f370382b1768a1552a86e8c583a073150d3965907f245111fd863b2f950a770452ed77781d41f3a1af90b008ef4b2330a94cb20f82a5e6536fcf96a5257fbbb393f5f8ad227d35f21a4d19286eff58c9b36ebbe30534b000000010000009c0000004a03010a72dccb4b40e0885b8a098e48a3c6b6c08bdd1715d8c7f6e9378db42ab082fb0efe415c3a5e3052d9a5c31e861881347dd58d7b5001f4865ac5f9e6420b0a8c5dd1bea3faaa6d5e0000004a0307dd2f180aeefde74b09788147f9faa8a1a4ac5bf0cf10e7ab0618f3f7473823fa311129732a4b9d9b6e12be10b280b06669f6d823a481ac12091f795d4f43b4804b72a8afa390a8f800000002000002540000050b000000080000000000000000000000388ca28b7b5bdb7487396b4aa536aeba2f852eb8f7af7ade1457927678174d6b0aaabdcb761f62aa27e21243469358f89b1aaf81c2ebc25f55000000fc00000506000000380a63128931034297465d1575792ae277b0d4cb29d41c4bc66964e4b44a67c4fdfe8742ed4b45be4ff3186d06a6d92ece6feeef69acf10a2100000038b2a6dc18ba45ef30dc52dca02237fb88123b71eab6227e74b13187c47e2c8871bd1995e663e9dc9c663860c8c12934a2ee0ab22ace1c3448000000380db2f33733f6ff9f7307b9b324ed6ec4e6af250ed8d8453e5e979c02b6824c0da67fc948af6d3510f43dc3740bc0d5a099baee732202471a000000382d71dd75b5b4d2e03bf76e46c7ae0cb314c9331ccf13b7238de576b860b087c62fcc89aeeec3f36f6bd83b14d364d67fd9951eee88dbbb850000000000000000000000fc0000050600000038965a0c0a6521ad449784ab3eaae11ff601a8c2b9c9c5521953651fd58cc2fbbd078092f2ea3273414b3cc0b61f9f4cfb312ef5d7b4b475d9000000380213633600aff685e31e04f5418ffc0e6e4514e28cada7cca38424cd3ecc92d574e0535f0f67d4e4ce170aa6cca863a35c8af225edc632d000000038d72a0c7bf6d51e38d5850e5c4386fed8885da2cad02e168dd6a27bde0edb132da81d8d2ce89198ec50e6b6ed6df170f79aa96a0c8a7a05d60000003873b99b32ccda1d2e63c5e4bcdeb3c9c5b36fdfa4a45b490e1f9e22f9083ddd87ac6b53cd83808a60a6e49f4fc651a281a5e13edd628f639a00000000000000000000000000000000000002540000050b00000008000000000000000000000038e835e791b29a3b2019285710ea99fe1c690d793f1e1d4480569763877a18bf5f57ff586c040af579d149d7ddbc988d966de8513ed825fada000000fc00000506000000388a0d1db344502d85331926b209933c3c81f0d598319f3791ed87d1c1b7c5a242dbd46f8427b6fe1ca41579aee22bc20ef476d61ef69787bd0000003878bb13dd6cc60b15a7eb52d626c2bfb20b36cbc210b1a40de6cfd6fba03d75419f59540d34980343b0abf978c224ed915a559dddfe7411000000003822d7fb6d757b3a245341cfa09c308fc461054c31e3a4559d86f36285871423dd57c637c5e4571c262bfc86bd8dc5284dc12f4d92b177d9e400000038ad5e691dcc2490ce7158f396f1a855aee5b70b3beaf1ef5be2c123d36cdc7c4e09ee293b2ebf85b03784a1962c6cd695c430fbbb95e655120000000000000000000000fc00000506000000386453cfd38fbbba0d44064f5326a433b06f7d9826430dbc21e4cd6252175298ca3115e9107a8573ef8b26ca61bf49c598057ab5abf4faa748000000383870791808e2116922b51eb3da0ea2bb4c50ae44659315a284dcd2b763adec2c9c2052b59a223cff4c7c3fbe84b60401929ed09a59fc22cb0000003825801a54a9defeae876d42e1c3ffe27d30d69b6599ae62c3f5e76215e79483518b8edf62cb1cde313ed5389a55ff8a21423c5c55cabf2cf20000003863470519b0c0345589cbc8181371c6ab8d09f25bb6e7fa2ad55721b12121de419b5b6080d97838f6a60910ec586cc3be867f86b7ba6a8a200000000000000000000000000000000000000002000000200000000000000000000000000000000000000000000000000000000000000001000000200000000000000000000000000000000000000000000000000000000000000002000005789a6e70628bde96e7087ca4b64e1af6b0bf2c74a231d9099436617eaeacf4ba8182cc1d3cf326894dd7b7be2875e811898afcbab1469250c752534292e6a0577a28f49abd3f71a508c22ca40fb14d3fa2d1f79d8c0b2ea3a170d12bdf13b3204cc8f99dc7e83a6ff955bfd6a89e192f05fcc51223c61c9c2d4a391870cf0a912cf9cd7762b9d1ce16b8ad7629afaf2fd2dfff38fa29dc8cc3e2b8d1d1bb0578ea82d2cece8cc08d6dc8fa03c7f62b0a6624c77d06fcc8aacd0b5064c6dc67301c0e63c98b61660d635797e47e60ac87ccddd307b092b9f779cd29af1443a090dd51765f9e4508b57b3aa028ddf393702a808369744035808383b7753dab530a446aa9d26e37c3a9948ea47034a129abaf6e8e6cf0c2618d1a70c628535a3f6cd9f18edfa6df448fd08656a95c36f9cea2fbad030fd670fbe41bfa61069b6a2202fc737263e484e270fc4aef2b4e4de60998f65769e4e680f873d8aa2a26b0a6b70db4291102dc0ba88cbe5e3ef5494b7517dfdc6f25e5c721b649ad0d8fc0679071f1a6d887476e0128ac81455b063caee5d939e5493fd6cb333de62f8c000e5650aab8fa1ccbb9fe77fe63ecaacb256675ebb03be9dd1518a745c6aeb8d8bcac527ed71ebde6938f5e03cbdda0231499df1ef785f38f9f1fc264f40c634db3fced0b05ad8c78365cf8cefeb1840acfd88893e71df192e4f848e2ee65499fe45d1eef06d57619cf329343f3d6bf8e4a826587d98ec34b808450978b581214c1bab8c77db048c2133cb4a6a7517b17b7f7ce57836af22ebde6bb7db34ecce1b1b3c094e298b6325ab8006d7a238d484f11178588ffa28348d3684a51de524e46df75c9a8fb094fed97b42ba4730d751c21928cf6dc0f88d6bbf0181245139d248b3f04017284c082a17a07034077bf90e8c591f0073e6f95252e853d808983c11dcc35e3f4e6095aea34b55ec73c6fa2ad7e9a01a12430ae9e8830cfbf4e087fdfa491fa8ce1567939abe15e60d5b0a33a5c45705a6cae7b19ca7ec433f36bf72ba303e0182644b8bf9ef18e8a0199feab831c617411d3eff216e004ac36d686706f0e1388c129a79975521cf4131fc103fce3ff23349b231a963d280415e0e980664d8185441ee846b45e972d7b3d738f9bdfd46b3c3114167dc3d64db1327b521144665b492ca34daae1b1d7717e5f661c1e9842cffc300e86937ab89ce26cef10a325a6d57630a9dc2c83dca7374d770904e318d14b34960113efaf6365980ebc8b3f2c9098bc824090eedc096f0d87a876f9f04ae12f6bdb34bd71e4b3287da27ea58097d8b433101e7e6313f07d73a283efe669139649b004fbe2d10daee619e603bd1ec916f614c6438e0dfb6243d2fa6c7af012af5039546e712005b0db6b049c43293718c927c36ba2a43ab56c3002c4dd4dd1fae11045371bd7fe8f8b67a0100be376dce4f26f9a066a94c5ed8224788ccff0e505ef81b35be342420e22711dc082b3e417a0a93bec00edda6d3461a304e01ef69fe535e219edf22008c3fb9f85024127859460fc660367bb346942eee5f7fcbe6de03666f19b17891444ec0fb27add17a2d974ee5308104b8cd5fec32d77983bdeb7c0e3e49dc474cc9460cd4e853cf4b43c251dbe281fdc73aa436ddcc60ea8988e4e14c1785b0c49c3c0854c24e987428049f305de7ad6292b1f041b2ab7ee56c913e6131f8a4a39fc1356cb0fdeea32177c6b129246251ac4b85b9075c91c51f86d99a9122d1349b691d0c920a1967400cea5020caeb74dcc200dbec4c2ef40a56f2e1227c0d9930299187557f6a76e5d13b16fc27dd862dd9bc3fad9d09d37bc8f3a9a1963f87d55ffe1df9751242f2be777ae80095bfa169f760b1f41e0ed6f9efe42085a7d3a46b07b6c8306e90f604fc955ed253c4bce6b50ae5553bb40b0c3b0f87eb18f73e16bf01f53d494b36fd51a3d3b725778303fb406fc28f41b0000074800000316000000a8000003130000004a0000004a020f6b4f5c0469e5355aa4a6ff384995355eb6b5ddd997ef7035f6ad7e708eb6bbb2308092b7cd555b8e7471b3fbcd9c6517b55dad62ae3563c1694030e50747a1672a5edbea000000528c264cf00000004a0202f3006b93375dde242cd7bef7f4ce320acd9718ba15565572f4db89597fd035789fe4e74391ebfcff320f75748df082a8019333d596257d4e4080e6d5aa62cb194eae5bb148103884000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a02082d960a2cd2c8fb8c5e96cadfe0e53da7d082d1ca3595c6cdb1febb6e5d8d84fc1879413bc02d594bcbc9785ba40db172698bec97668411d4b0789ddeee44d716096572b58fc5c6f800000040f1f0cba3b9e53ce96086794d10490c57d8e63ead89e0879d11a6b4d677c0bfdbb4a2d9e898bc0b69935d71e13ab2fdf9533620c002d616d2581d14633d0df261000000030000004027314af77b7c29c354de07b7c73c6cd938ba3a2d0a210b2ed46d41b9b67ea3cff3ad39153accccd9fc76857805054ca84f1f1d09f2716a5a17c22c33d457522900000040f1f0cba3b9e53ce96086794d10490c57d8e63ead89e0879d11a6b4d677c0bfdbb4a2d9e898bc0b69935d71e13ab2fdf9533620c002d616d2581d14633d0df2610000004a0203c75444ecbc6a9d71042d852c3c4dedfefe5469423d89089415ea61cdfb0d62afb23d4e736526c4b6eedf1623dbd2efaf71fdfc06fbc6c71891ef48270e0f1c68373d86a48e7baf470000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d00000000000000240000000000000002000000100000031400000001000000000000003c0000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a02082d960a2cd2c8fb8c5e96cadfe0e53da7d082d1ca3595c6cdb1febb6e5d8d84fc1879413bc02d594bcbc9785ba40db172698bec97668411d4b0789ddeee44d716096572b58fc5c6f80000004010798b3c4f204a5e23989ec134d19bdab12dbd9d42288b48fa57fa7fedce2449979138046f6bfbbc460c60e42ba1ecd9f876b29933b35e74c5a1bb18b5b8e6d6000000030000004027314af77b7c29c354de07b7c73c6cd938ba3a2d0a210b2ed46d41b9b67ea3cff3ad39153accccd9fc76857805054ca84f1f1d09f2716a5a17c22c33d45752290000004010798b3c4f204a5e23989ec134d19bdab12dbd9d42288b48fa57fa7fedce2449979138046f6bfbbc460c60e42ba1ecd9f876b29933b35e74c5a1bb18b5b8e6d60000004a02073fe7087632b5bcfa4261dffcad91ebc04f29ade8408b44b250a1cf1c1501d29b329070309761dce8013b2d6252270a88499def769c9997e7b19a5db34ab19b0a6be85a3c3028b5e90000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d000000000000002400000000000000020000001000000314000000010000000000000021",
		"0000050c0000002011558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900000002000002380000050a0000003830690a46df7a9dee951871add7a7ee0578f562ff6c3fff255e95ca1915115a4816eb7d021dc8c82818f7c2dbf3b644b42ce32f0274053b5b00000150fd870809049305ac701fe1fe78026231990ffbaad2cc79ae9a11efc303f515bcbd9c41fe31ce1188f259c2baaca3656062a7b7b03e122a8a32778e230cd73d5e910faf83a8c14f3769f966cc28118f9048706c298c2a700e43142af21c5100c2faf8b58d6f8f3467bebecaaf8281a33c7b2ae4a0167fd44ce898105969788dac8a2557b70250d09bded9ae4ea10d4e23e806f43a00bebd5ba143cd12af868c25a96171463fb1d708b8f1ac6a092b6b3b0199b167a7df354c9326c917cb54255d534a922b1a7991a230d5881b749fbf104168a0eada3fc64205ae2d9cc7ef090ab405d9d14f0ffd29dc083f4ca377314af225da77a1a9b2529554cf88e8e9778b82e948dbecb9616b09c5339ad8e963c55d686bf63948cb0430690a46df7a9dee951871add7a7ee0578f562ff6c3fff255e95ca1915115a4816eb7d021dc8c82818f7c2dbf3b644b42ce32f0274053b5b000000010000009c0000004a020f3c55fbfac7ea844f13606bfd70680a380ec2302f16dcb7a17a96633aa8031d72aa0796b3d8c06fb3e2802c63031270bb4fa26abe1b0d658e34b79fb01dc77a5c34e83c655c2a18a30000004a0202955bc9f9ba36526899ec5e2b2dbf04a5b236b8a620458a8e75cb19718e1ffa4c63ba8c63bee666f575d5ffc2090675ae518bf9e72c0f60ff5bb066eae59d9e0692ac8c9041a1eb22000002380000050a00000038d085722c5c2373d8928b900ce8d0c34403d95078320b5033f7d74f1faafa3c20408dd19996f0bfab598a69e7b1a813c40b8c99ccbc50e72f00000150d763fd92bf91d552e0a1f85e43e94d8832dfb5025bd8b0e1a09ad8c388a4c274e055778e53e0c027b831a110e8fecbe8227841b6f6ffe372b2675bea42d083845314c10e1601eda29ebc4840496a30ea5dae1ecc6bc46996d8194e956df27fc15e7674a6a7ea46025053f4f0fb32b1315a9dfb1c4136486350c569071d2b3d5a3d71c9f4a6b3e130ab3db117ce84ab2c1bdf7800033cf70964e9915a4ae3ad86758cb616cd1f1538447428a25e196348a69193d9eeb0c444e56a5fc6e96154f90cb7aa8232179f013974a025c1a3df7c5f9df8fb7f848a924d9e1d2df3be940c1a8ec1d0d9d9e89ffcb1ff85415682956347ea663a6ecfd95343d7b07dfa391605e8ec11959e7f655bdba17ae9172cb27c8c44acc04d97bcd085722c5c2373d8928b900ce8d0c34403d95078320b5033f7d74f1faafa3c20408dd19996f0bfab598a69e7b1a813c40b8c99ccbc50e72f000000010000009c0000004a0311dde37635cd318ddee6bb749a21c3a748446888569412ab0c417b2e2813b404d87a25592a68caa8477551cd64169b5e4354e1cbd174c22f9df6c700ab9a4ed7dcf68712c78a2cbc0a0000004a031093a705ed1a5a92db691d6ef2ec81a3715e5ccdce737f6478faf5fd16eab5767d3703186c00f2237056eb7d3e1355df5253d7076eb5335bbab584d1c246b7fd7d03415e731516812e00000002000002540000050b0000000800000000000000000000003810632fc94bf9716561dc875bf74bd88d7fd1f961cbde5700ead91beb903aee949a6268b8f7b8ec4483651a8396d9770209da8207c2a4b0f0000000fc0000050600000038a49457e78dc27d654efe35348fef88d47158af45ab451bec9339a3ce555b7c55c20c9234b401336274c3743b62ac1b0f4966e23dab3993120000003824ef13faa2e5e2b1e2e250acba82a1d62513e24391aaad7df8e819c9acabda71566c8d9e2ffd9c51e12d5d08f5f6b71b04868a06fa1f88ef00000038e757ade400eb8dcdf059b3a493b573c14ef0a76c8eb6f6d33c81cafc6a307a4424acb4dd090de9b6c2aaa1bea6eb83d86acf9ab100e40fc100000038897d1d42d8b844afbc55f846918735b0ba45ba8c795270ca36eda08ebb2d5f45d9941e6dd86fc71d16a65887693f4678130bd1588819d20f0000000000000000000000fc00000506000000384cbb7007bc0d4e2423be764cae286572e170bafa4b9eb35bf293dd8bb4909d9b8371cdfaf3964ea199e2e6d310aee95e3979c527c8a7fa5a00000038e449f88a86f03c4f72861eb71ca0237df3e6b9d8be45516be04d2705633a90213c1df0a3cf3d9c11661d292ee66c75aa87376c4d8a772051000000388fcb987fb0205e04f007cb00d5145e66b9f13d3e1c9b1302b02749ade339c656526fdbef5701c1516bdbdf4ea7e7032f0c432adf99896f4f00000038bb54e5ef08b07ca506dceb83ae7b62ee6457a61dba66979696bbfc089e6d500aca45b9a4edfd5bf196b8aaf738f535c91a8953ab438e9cb400000000000000000000000000000000000002540000050b0000000800000000000000000000003832166164fc8241d1d2fd4dc1d171b7b37e2734456e640854227bdd67ec17ea4c3d707f55a190f01d4686a7fd4ebd737393a14d46b949348f000000fc00000506000000386c583c3b089454f25e082374693e6f8dbd942d1d46d06c8647df501dbf09f822f3111b78efd1d4a00462acdadfb5984566ad29722431cf1b00000038d2184583c56b686d651eab7a11f07d6d7259cd20c4fd6397a43fc3e78c087f4daf085c70462118cac02e157621b5a3b4c4465b677f902d2a000000386fab508c5aff37b60f8e1ab1266514f81f7c1241a3cb022752a27325abc42989231c5e11a80a059865d0aa172d939f734cfa6925c5c4faa300000038f4625f59880e654a0037597b5f5f13e8ce90da9c4f9ff9041f686a85fcfd9a9e68f28726c0d926e5394bc064d2aea3a57c825db0d48b6ece0000000000000000000000fc0000050600000038d263d839b9b7e80d1d55b04be6d121b78db4146e8d25d94e86b0ced1ce10f8a089d95ff2df9708077993686b64cfa319a37f661a224137f400000038f832592a21d508d90b92d70fd30785a3d909e7714eb453fa64ab92afc00ca7dfac74070dcb379eb577059ae4ba2aa7c71c5fd2154f9d7c0c00000038a971d7104790e185aa36dfe8e2b1886543ef90f2df93871d9cd92d49bf94743b3b4d33638428620ca6132894695bce674b00b53d9cb3705e00000038f04720b13479d33c4331006f01f652347c58e023553faea48f83c495379e6b5551d1c543a7afd3ccc91895862ee6a1a1d52af7b0651ebc0b000000000000000000000000000000000000000200000020000000000000000000000000000000000000000000000000000000000000000100000020000000000000000000000000000000000000000000000000000000000000000200000578f63cbb512acf918d6358057d168147debeec3bc7c42a42663b24706f6aef2a56d88f5ba47f2c27ed52aae629057420f75d60f74f178fccb6321e97f142ae8ce52f5ec341e9443116b86e705054dffa0a5c07a6400bcc3d9af97a4d6da26843dc12e7ccc1ba8f41345784071aff07bbc3ae3ad2904c50fbec696da97543fbc9a6f89ddc4372575507ee768d9e787012e494610ac8786670444e5ebfd9127d194656f534a55a3a86dbb6fdc497a9cd793c0475c49dd876de64cd40dc190c837cedb65148efe93f858e99317ed7a54f00118f5108436447291c8fb768f61d6bb44dfa7d37679dc31aebf7c4dcee9373be381f04d46ed6c017698c23fd8bea8f848abcffae2dbbf620f9033965545629e57912152781955fa9388cd5eb9a5fdc1e4a9ed2620e2e8f3ea7c6332c7198c89cafdc50f86db09f84efcafbf88e96e32fa58b0749867fbbfa830f306c9c7592cb3957089f0b291ca767cb5d8c3edb197230a41ff88c1857bc4d2363f681ffa345489cfe6409c3bbe083b69d7938bd4d9c2aa63095132ce70c0c48c683e8e7990346734c33f8ba45c65710dbf4cfaf1f336d5d00eba343206fc8cd530447b89fa82209371c4da9672cb858e72cadc0228b7c5286cefb6b79449fd3151825570804b3a051dca86cfdc4bb85e21958db53614fc29a9ef5218ea975e63d1ff7af79259820b31d3c7335412ba4f30f23f462d4b135de924a62965d2acabb433c8686c3eb14b882a583cc2f8a8248f8df368a32548a025dc631a42f20d1963377864e60f01ee541daafcfbb3589e0262d24ff8f817954cd1e39fa0cba2712720c61b72a450468ee5d125d506d5c654e916faf22289f657562e832a7640ac49b6579d2fbfc477b8d9877cc8f2f518011ee3ebfb290b7db6e023cd88d89ed3214c3f479d52f76485d4cbc1beb8435153e64d0f60c2008dadeb272f844c57a74f7d0b033ca5cb578189c0ea7a22688ee9ee283bcbe78e0db789fb06891dfa8cbbcb3025f404b0a2b25576f8804860648166cda9b0328ef8539d3c3a1dffec368cf9fa216713722fac485175e69c56928a954c31aa89ec7398b7b93c64b3edab463334a98744838187c882725ab5022b0be3a902574e454f83f664be6f60aa83a06269aad8da8e6b989722343bb00f51d40c5d49452f58a991ce3ec941900968aa0b2a165fab47956b69f313a0af7133008c76fced0f1e5c9f228388e57ca498d7d393ffa0400d2972dd4def1e74276d0ada3976f303f8cb002043e96bfd265d2bc3c7441b286a7db741b527f2c4f0d4767698ac9cc1529030c1799abf689241f5c5ff0b4ef102464142e7ef2a9f55aee3727415a38c25be6eed24d9e789f74fe28dc44a7871706b4f3b779e2a28e6b7dfcd4a65d08aef194cd9d4f1ddd289ccbf7f03736095d54f97b3ab2326fef95fc4dba9d05c52ea5f092dae4312d56ff869c31582619a10511c636b1cf078488825caea4a12dcb27664d62dfd4390b483dc49262b2045fe4293ed20d37e8b6b488402f602323c928db3cd61f611e8f4896e56450659ade113578334f0784b8d4fbb9b5e5f95d696c9b8a2191de2b764c76de1b6d29fd2ffd6af02ae969df7bd4770c42c730da8db3aadc2d19a0504d41adaf40df887ab1c14d8c733a55ded386f6fd220f594ccb11c73275bb138099559b0c355a854b31cacab0c2c206c9722405c9b4048fcd5c41b64d3b74e2a25a05f3f8c03213b597c6f148c6ebe440367f2c34b52cc22dda2a7f1458bb6e7f9605686547cb70e31ba5a1911573fde5ee0edfe49e03bff97512b20f4e237b62424904189d146e1ac384ccff9dcc0f76703e96ac1d18ba3dc8e46b06b5540ec4147a654df569bfd8301232e0a490399ceb5f7ecae73e8e94014f7173e5f6fe4ef67b46cd11da9716725f435d15c70e89a62164e351fa74c5efec70544fb975d28f482fab92e4dc45eeb1a601b4abdfb3280000074800000316000000a8000003130000004a0000004a030c89cbdaaf398109a6ac60bf2090cedcb12b97b50ca81922cd2143fa4644b1e130521fdd71eae7d831c72984ed0c26597dc5b76bff13d01410f84c6b066c3ba1d3ace0f2d600000052d866c2c40000004a030d5cf3d4ba0f1eafee46943b2aa18e89b44f85fd6fc33fe0f693b73bca2b6afe038d60a0e2f22952ea4419da3621847831009a20670d0d02875c9cb263691d56d2f55c28ecc725320e000000020000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a02082d960a2cd2c8fb8c5e96cadfe0e53da7d082d1ca3595c6cdb1febb6e5d8d84fc1879413bc02d594bcbc9785ba40db172698bec97668411d4b0789ddeee44d716096572b58fc5c6f800000040950c654e48e48d472a35765596da3f76968ffef1ad2a372757f7d0c79af8edb1abbf8e464b67857e35a7d5459df658a554fa076c6848df77312f7a18a7745448000000030000004027314af77b7c29c354de07b7c73c6cd938ba3a2d0a210b2ed46d41b9b67ea3cff3ad39153accccd9fc76857805054ca84f1f1d09f2716a5a17c22c33d457522900000040950c654e48e48d472a35765596da3f76968ffef1ad2a372757f7d0c79af8edb1abbf8e464b67857e35a7d5459df658a554fa076c6848df77312f7a18a77454480000004a0306001627250ca093db4e629d8b95acc359eba050ca24cb99257e0be9984d5d4dae2addcc7e8ee3842e8234d82e85819e85d6c0a6affd4bd486be1e14cf8d4e7d794944b6a6e344cfa00000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d0000000000000024000000000000000200000010000003140000000100000000000000110000034600000315000000030000004a030caaf237a6027d33d6d6ca23ae0334551f8458d9d5cba810a9fe93b94b7f0fc623516e916432c09bc045b52db62611a328375a4b1c68d51800f47f2a6dfed206fa8395e6ea585f55ab0000004a02082d960a2cd2c8fb8c5e96cadfe0e53da7d082d1ca3595c6cdb1febb6e5d8d84fc1879413bc02d594bcbc9785ba40db172698bec97668411d4b0789ddeee44d716096572b58fc5c6f800000040139940bad435d31d46f9e138a1395893a07e0cc669c2ef3417e9f8f11fc4ce8b85116c6fcd60afd93377f1fbc4bdd72a0c4865e30cbbb1f2dbe24c4171727239000000030000004027314af77b7c29c354de07b7c73c6cd938ba3a2d0a210b2ed46d41b9b67ea3cff3ad39153accccd9fc76857805054ca84f1f1d09f2716a5a17c22c33d457522900000040139940bad435d31d46f9e138a1395893a07e0cc669c2ef3417e9f8f11fc4ce8b85116c6fcd60afd93377f1fbc4bdd72a0c4865e30cbbb1f2dbe24c41717272390000004a0209a29679708b0bb745b611bfb8058303618ac35de0113fed51f8ff99a517bb7b039013430caa67255361e7246d94ee5b704141ae33a14102b8dd00d8734adff87a6e055e71d927db090000000200000168000003140000002c00000000000000040000000000000015000000000000001600000000000000050000000000000021000000000000000a000000000000003d00000000000000300000000000000005000000000000003a0000000000000026000000000000003f0000000000000034000000000000001f000000000000003c0000000000000018000000000000001900000000000000030000000000000000000000000000002d00000000000000190000000000000003000000000000003e000000000000003e0000000000000016000000000000000c0000000000000018000000000000002d000000000000003300000000000000390000000000000003000000000000000b00000000000000330000000000000018000000000000003f000000000000001e000000000000001d000000000000000a000000000000000900000000000000270000000000000025000000000000000d00000000000000240000000000000002000000100000031400000001000000000000000a",
	}
	numShards := 3
	numNodesPerShard := 6
	shardAddresses := make([][]byte, numShards)

	// Create shard addresses
	for i := 0; i < numShards; i++ {
		shardAddresses[i] = slices.Concat(token.QUIL_TOKEN_ADDRESS, []byte{byte(i)})
	}

	// Create key managers and prover keys for all nodes
	totalNodes := numShards * numNodesPerShard
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManagers := make([]tkeys.KeyManager, totalNodes)
	proverKeys := make([][]byte, totalNodes)

	for i := 0; i < totalNodes; i++ {
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
	}

	// Create engines for each shard
	type shardNode struct {
		engine         *AppConsensusEngine
		pubsub         *mockAppIntegrationPubSub
		hg             *hypergraph.HypergraphCRDT
		db             *store.PebbleDB
		gsc            *mockGlobalClientLocks
		proverRegistry consensus.ProverRegistry
	}

	_, m, cleanup := tests.GenerateSimnetHosts(t, numShards*numNodesPerShard, []libp2p.Option{})
	defer cleanup()
	nodeDBs := make([]*store.PebbleDB, totalNodes)

	createAppNodeWithFactory := func(nodeIdx int, appAddress []byte, proverKey []byte, keyManager tkeys.KeyManager) (*AppConsensusEngine, *mockAppIntegrationPubSub, *consensustime.GlobalTimeReel, *hypergraph.HypergraphCRDT, consensus.ProverRegistry, *mockGlobalClientLocks, func()) {
		cfg := zap.NewDevelopmentConfig()
		adBI, _ := poseidon.HashBytes(proverKey)
		addr := adBI.FillBytes(make([]byte, 32))
		cfg.EncoderConfig.TimeKey = "M"
		cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(fmt.Sprintf("node %d | %s", nodeIdx, hex.EncodeToString(addr)[:10]))
		}
		logger, _ := cfg.Build()
		// Create node-specific components
		nodeDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_chaos__%d", nodeIdx)}, 0)
		nodeInclusionProver := bls48581.NewKZGInclusionProver(logger)
		nodeVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		nodeHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_chaos__%d", nodeIdx)}, nodeDB, logger, nodeVerifiableEncryptor, nodeInclusionProver)
		nodeKeyStore := store.NewPebbleKeyStore(nodeDB, logger)
		nodeClockStore := store.NewPebbleClockStore(nodeDB, logger)
		nodeInboxStore := store.NewPebbleInboxStore(nodeDB, logger)
		nodeShardsStore := store.NewPebbleShardsStore(nodeDB, logger)
		nodeHg := hypergraph.NewHypergraph(logger, nodeHypergraphStore, nodeInclusionProver, []int{}, &tests.Nopthenticator{})
		nodeProverRegistry, err := provers.NewProverRegistry(zap.NewNop(), nodeHg)
		nodeBulletproof := bulletproofs.NewBulletproofProver()
		nodeDecafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		nodeCompiler := compiler.NewBedlamCompiler()
		nodeDBs[nodeIdx] = nodeDB

		// Create mock pubsub for network simulation
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		p2pcfg.MinBootstrapPeers = numNodesPerShard - 1
		p2pcfg.DiscoveryPeerLookupLimit = numNodesPerShard - 1
		p2pcfg.D = 4
		p2pcfg.DLo = 3
		p2pcfg.DHi = 6
		conf := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &p2pcfg,
		}
		pubsub := newMockAppIntegrationPubSub(conf, logger, []byte(m.Nodes[nodeIdx].ID()), m.Nodes[nodeIdx], m.Keys[nodeIdx], m.Nodes[(nodeIdx/numNodesPerShard)*numNodesPerShard:((nodeIdx/numNodesPerShard)*numNodesPerShard)+numNodesPerShard])

		// Create frame prover using the concrete implementation
		frameProver := vdf.NewWesolowskiFrameProver(logger)

		// Create signer registry using the concrete implementation
		signerRegistry, err := registration.NewCachedSignerRegistry(nodeKeyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, nodeInclusionProver)
		frameValidator := validator.NewBLSAppFrameValidator(nodeProverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(nodeProverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 160000)
		rewardIssuance := reward.NewOptRewardIssuance()

		// Create the factory
		factory := NewAppConsensusEngineFactory(
			logger,
			conf,
			pubsub,
			nodeHg,
			keyManager,
			nodeKeyStore,
			nodeClockStore,
			nodeInboxStore,
			nodeShardsStore,
			nodeHypergraphStore,
			frameProver,
			nodeInclusionProver,
			nodeBulletproof,
			nodeVerifiableEncryptor,
			nodeDecafConstructor,
			nodeCompiler,
			signerRegistry,
			nodeProverRegistry,
			qp2p.NewInMemoryPeerInfoManager(logger),
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		// Create global time reel
		globalTimeReel, err := factory.CreateGlobalTimeReel()
		if err != nil {
			panic(fmt.Sprintf("failed to create global time reel: %v", err))
		}

		// Create  engine using factory
		engine, err := factory.CreateAppConsensusEngine(
			appAddress,
			0, // coreId
			globalTimeReel,
			nil,
		)
		if err != nil {
			panic(fmt.Sprintf("failed to create  engine: %v", err))
		}

		mockGSC := &mockGlobalClientLocks{
			shardAddresses: map[string][][]byte{},
		}
		engine.SetGlobalClient(mockGSC)

		cleanup := func() {
			nodeDB.Close()
		}

		return engine, pubsub, globalTimeReel, nodeHg, nodeProverRegistry, mockGSC, cleanup
	}
	shards := make([][]shardNode, numShards)

	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		shards[shardIdx] = make([]shardNode, numNodesPerShard)

		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			nodeID := shardIdx*numNodesPerShard + nodeIdx
			engine, pubsub, _, nodeHg, proverRegistry, gsc, cleanup := createAppNodeWithFactory(nodeID, shardAddresses[shardIdx], proverKeys[nodeID], keyManagers[nodeID])
			defer cleanup()

			for i, i1aH := range input1sAddrsHex {
				addr1, _ := hex.DecodeString(i1aH)
				addr2, _ := hex.DecodeString(input2sAddrsHex[i])
				tree1Bytes, _ := hex.DecodeString(input1sHex[i])
				tree1, _ := tries.DeserializeNonLazyTree(tree1Bytes)
				tree2Bytes, _ := hex.DecodeString(input2sHex[i])
				tree2, _ := tries.DeserializeNonLazyTree(tree2Bytes)

				txn, _ := nodeHg.NewTransaction(false)
				nodeHg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(addr1[:]), tree1.Commit(nodeHg.GetProver(), false), big.NewInt(55*26)))
				nodeHg.SetVertexData(txn, [64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, addr1)), tree1)
				nodeHg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(addr2[:]), tree2.Commit(nodeHg.GetProver(), false), big.NewInt(55*26)))
				nodeHg.SetVertexData(txn, [64]byte(slices.Concat(token.QUIL_TOKEN_ADDRESS, addr2)), tree2)
				err := txn.Commit()
				if err != nil {
					t.Fatal(err)
				}
			}

			shards[shardIdx][nodeIdx] = shardNode{
				engine:         engine,
				pubsub:         pubsub,
				hg:             nodeHg,
				db:             nodeDBs[shardIdx*6+nodeIdx],
				gsc:            gsc,
				proverRegistry: proverRegistry,
			}
		}
	}

	// Connect nodes within each shard
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		pubsubs := make([]*mockAppIntegrationPubSub, numNodesPerShard)
		for i := 0; i < numNodesPerShard; i++ {
			pubsubs[i] = shards[shardIdx][i].pubsub
		}
		for otherShardIdx := 0; otherShardIdx < numShards; otherShardIdx++ {
			if otherShardIdx == shardIdx {
				continue
			}
			for i := 0; i < numNodesPerShard; i++ {
				// addrmap := map[string]struct{}{}
				// msg := make(chan *pb.Message, 1000)
				// go func() {
				// 	for {
				// 		select {
				// 		case m := <-msg:
				// 			livenessCheck := &protobufs.ProverLivenessCheck{}
				// 			err := livenessCheck.FromCanonicalBytes(m.Data)
				// 			if err != nil {
				// 				continue
				// 			}
				// 			if len(livenessCheck.CommitmentHash) > 32 {
				// 				if _, ok := addrmap[string(livenessCheck.CommitmentHash[:32])]; ok {
				// 					continue
				// 				}
				// 				addrmap[string(livenessCheck.CommitmentHash[:32])] = struct{}{}
				// 				set, err := tries.DeserializeNonLazyTree(livenessCheck.CommitmentHash[32:])
				// 				if err != nil {
				// 					fmt.Println(err)
				// 					continue
				// 				}

				// 				leaves := tries.GetAllPreloadedLeaves(set.Root)
				// 				for _, l := range leaves {
				// 					fmt.Println("adding tx from", shardIdx, "-", i, ":", hex.EncodeToString(l.Key))
				// 					shards[otherShardIdx][i].gsc.shardAddressesMu.Lock()
				// 					if _, ok := shards[otherShardIdx][i].gsc.shardAddresses[string(livenessCheck.Filter)]; !ok {
				// 						shards[otherShardIdx][i].gsc.shardAddresses[string(livenessCheck.Filter)] = [][]byte{}
				// 					}
				// 					shards[otherShardIdx][i].gsc.shardAddresses[string(livenessCheck.Filter)] = append(shards[otherShardIdx][i].gsc.shardAddresses[string(livenessCheck.Filter)], l.Key)
				// 					shards[otherShardIdx][i].gsc.shardAddressesMu.Unlock()
				// 				}
				// 			}
				// 		}
				// 	}
				// }()
				// err := shards[otherShardIdx][i].pubsub.Subscribe(shards[shardIdx][i].engine.getConsensusMessageBitmask(), func(message *pb.Message) error {
				// 	msg <- message
				// 	return nil
				// })
				// if err != nil {
				// 	panic(err)
				// }
			}
		}
		connectAppNodes(pubsubs...)
	}

	for i := 0; i < numNodesPerShard*numShards; i++ {
		for j := 0; j < numNodesPerShard*numShards; j++ {
			if i != j {
				tests.ConnectSimnetHosts(t, m.Nodes[i], m.Nodes[j])
			}
		}
	}

	// Start all nodes
	quits := make([][]chan struct{}, numShards)
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		quits[shardIdx] = make([]chan struct{}, numNodesPerShard)

		// Start first node in each shard to create genesis
		quits[shardIdx][0] = make(chan struct{})
		node := shards[shardIdx][0]
		node.engine.Start(quits[shardIdx][0])

		// Set peer count for first node
		shards[shardIdx][0].pubsub.peerCount = numNodesPerShard - 1

		// Start remaining nodes in shard one at a time
		for nodeIdx := 1; nodeIdx < numNodesPerShard; nodeIdx++ {
			shards[shardIdx][nodeIdx].pubsub.peerCount = numNodesPerShard - 1
			quits[shardIdx][nodeIdx] = make(chan struct{})
		}
	}

	// Now ensure normal operation with higher peer count
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			shards[shardIdx][nodeIdx].pubsub.peerCount = 10
		}
	}

	l1 := up2p.GetBloomFilterIndices(token.QUIL_TOKEN_ADDRESS[:], 256, 3)
	shardKey := tries.ShardKey{
		L1: [3]byte(l1),
		L2: [32]byte(token.QUIL_TOKEN_ADDRESS),
	}
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for _, s := range shards[shardIdx] {
			shardStore := store.NewPebbleShardsStore(s.db, zap.L())
			txn := s.db.NewBatch(false)
			for i := uint32(0); i < uint32(6*shardIdx); i++ {
				shardStore.PutAppShard(txn, tstore.ShardInfo{
					L1:   l1,
					L2:   token.QUIL_TOKEN_ADDRESS,
					Path: []uint32{i},
				})
			}
			txn.Commit()
		}
	}

	hgs := []thypergraph.Hypergraph{}
	prs := []consensus.ProverRegistry{}
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for _, s := range shards[shardIdx] {
			hgs = append(hgs, s.hg)
			prs = append(prs, s.proverRegistry)
		}
	}

	priors := [][]byte{}
	for j, hg := range hgs {
		// Register all provers
		for i, proverKey := range proverKeys {
			proverAddress := calculateProverAddress(proverKey)
			// NOTE: This calls hg.Commit(0)
			registerProverInHypergraphWithFilter(t, hg, proverKey, proverAddress, shardAddresses[i/6])
			t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
		}
		prs[j].Refresh()
		r, err := hg.Commit(0)
		if err != nil {
			t.Fatal(err)
		}
		priors = append(priors, r[shardKey][0])
	}

	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			// Start engine
			shards[shardIdx][nodeIdx].engine.Start(quits[shardIdx][nodeIdx])
		}
	}

	pending := []*protobufs.PendingTransaction{}
	for _, txHex := range pendingTxsHex {
		p, _ := hex.DecodeString(txHex)
		pend := &protobufs.PendingTransaction{}
		err := pend.FromCanonicalBytes(p)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, pend)
	}
	time.Sleep(15 * time.Second)
	outs := [][]byte{}
	for _, tx := range pending {
		req := &protobufs.MessageBundle{
			Requests: []*protobufs.MessageRequest{
				{
					Request: &protobufs.MessageRequest_PendingTransaction{
						PendingTransaction: tx,
					},
				},
			},
			Timestamp: time.Now().UnixMilli(),
		}
		out, err := req.ToCanonicalBytes()
		assert.NoError(t, err)
		outs = append(outs, out)
	}

	// Send shard-specific messages
	for s := 0; s < numShards; s++ {
		for i := 0; i < 2; i++ {
			payload := outs[0]
			outs = outs[1:]
			// Send to first node in shard
			if err := shards[s][0].pubsub.PublishToBitmask(shards[s][0].engine.getProverMessageBitmask(), payload); err != nil {
				t.Fatal(err)
			}
			for _, node := range shards[s] {
				hash := sha3.Sum256(payload)
				node.gsc.shardAddressesMu.Lock()
				if _, ok := node.gsc.shardAddresses[string(node.engine.appAddress)]; !ok {
					node.gsc.shardAddresses[string(node.engine.appAddress)] = [][]byte{}
				}
				node.gsc.shardAddresses[string(node.engine.appAddress)] = append(node.gsc.shardAddresses[string(node.engine.appAddress)], hash[:])
				node.gsc.committed = true
				node.gsc.shardAddressesMu.Unlock()
				l1 := up2p.GetBloomFilterIndices(token.QUIL_TOKEN_ADDRESS[:], 256, 3)
				va := node.hg.GetVertexAddsSet(tries.ShardKey{L1: [3]byte(l1), L2: [32]byte(token.QUIL_TOKEN_ADDRESS)})
				path := tries.GetFullPath(token.QUIL_TOKEN_ADDRESS[:])
				path = append(path, int(node.engine.appAddress[32]))
				va.GetTree().CoveredPrefix = path
			}
		}
	}

	// Let system run
	time.Sleep(200 * time.Second)

	// Verify each shard is progressing independently
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		t.Logf("Checking shard %d", shardIdx)

		// First wait for all nodes in shard to have frames
		maxRetries := 10
		for retry := 0; retry < maxRetries; retry++ {
			t.Logf("Checking shard %d, retry %d", shardIdx, retry)

			allHaveFrames := true
			for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
				t.Logf("Checking shard %d, retry %d, node %d", shardIdx, retry, nodeIdx)

				if shards[shardIdx][nodeIdx].engine.GetFrame() == nil {
					allHaveFrames = false
					t.Logf("  Shard %d node %d doesn't have a frame yet, waiting... (retry %d/%d)",
						shardIdx, nodeIdx, retry+1, maxRetries)
					break
				}
			}

			if allHaveFrames {
				t.Logf("all frames found for shard %d, retry %d", shardIdx, retry)
				break
			}

			time.Sleep(1 * time.Second)
		}

		time.Sleep(1 * time.Second)

		var referenceFrame *protobufs.AppShardFrame
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			frame := shards[shardIdx][nodeIdx].engine.GetFrame()
			require.NotNil(t, frame, "Shard %d node %d should have a frame after waiting", shardIdx, nodeIdx)
			assert.Equal(t, shardAddresses[shardIdx], frame.Header.Address)

			if referenceFrame == nil {
				referenceFrame = frame
			} else {
				// Allow for nodes to be within 1 frame of each other due to timing
				frameDiff := int64(frame.Header.FrameNumber) - int64(referenceFrame.Header.FrameNumber)
				assert.True(t, frameDiff >= -1 && frameDiff <= 1,
					"Shard %d node %d frame number too different: expected ~%d, got %d",
					shardIdx, nodeIdx, referenceFrame.Header.FrameNumber, frame.Header.FrameNumber)

				// If they're on the same frame number, they should have the same parent
				if frame.Header.FrameNumber == referenceFrame.Header.FrameNumber {
					assert.Equal(t, referenceFrame.Header.ParentSelector, frame.Header.ParentSelector,
						"Shard %d node %d parent selector mismatch - nodes are not building on the same chain",
						shardIdx, nodeIdx)
				}
			}
			t.Logf("  Node %d: frame %d, parent: %x", nodeIdx, frame.Header.FrameNumber, frame.Header.ParentSelector)
		}
	}

	// Check fee voting across shards
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		voteHistory, err := shards[shardIdx][0].engine.GetDynamicFeeManager().GetVoteHistory(shardAddresses[shardIdx])
		require.NoError(t, err)
		assert.NotEmpty(t, voteHistory, "Shard %d should have fee vote history", shardIdx)
	}

	commits := [][]byte{}

	// Stop all nodes
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			node := shards[shardIdx][nodeIdx]

			// Stop engine
			node.engine.Stop(false)
			// Frame number is likely wrong, but irrelevant for the test
			r, _ := node.hg.Commit(7)
			commits = append(commits, r[shardKey][0])
		}
	}

	hgs[0].Commit(7)

	for j := range 3 {
		for i := 0; i < len(commits)/3-1; i++ {
			fmt.Printf("new %d:%x\n", i, commits[i])
			assert.True(t, bytes.Equal(commits[i], commits[i+1]), fmt.Sprintf("index mismatch: %d: %x, %d: %x", i, commits[i], i+1, commits[i+1]))
			fmt.Printf("old %d:%x\n", i, priors[i])
			// we can forego the last check here because all priors are equal to each other too
			assert.True(t, !bytes.Equal(commits[i], priors[i]))
		}
		if j != 2 {
			commits = commits[6:]
			priors = priors[6:]
		}
	}
}

// Not a real test, generates addresses, stored values, and transactions intended to target specific shards independently.
// Can take a long time to run.
func TestGenerateAddressesForComplexTest(t *testing.T) {
	token.BEHAVIOR_PASS = true
	t.Skip("not a test")
	nodeInclusionProver := bls48581.NewKZGInclusionProver(zap.L())
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}

	nodeDB := store.NewPebbleDB(zap.L(), &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_chaos"}, 0)
	nodeVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	nodeHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_chaos"}, nodeDB, zap.L(), nodeVerifiableEncryptor, nodeInclusionProver)

	nodeHg := hypergraph.NewHypergraph(zap.L(), nodeHypergraphStore, nodeInclusionProver, []int{}, &tests.Nopthenticator{})
	vksHex := []string{
		"67ebe1f52284c24bbb2061b6b35823726688fb2d1d474195ad629dc2a8a7442df3e72f164fecc624df8f720ba96ebaf4e3a9ca551490f200",
		"05e729b718f137ce985471e80e3530e1b6a6356f218f64571f3249f9032dd3c08fec428c368959e0e0ff0e6a0e42aa4ca18427cac0b14516",
		"651e960896531bd98ea94d5ff33e266a13c759acee0f607aec902f887efbdf6afeb59238531246215ce7d35541ba6fb1f8bf71b0c023b908",
		"ffd96fec0d48ccea6e8c87869049be34350fcd853b5719c8297618101cb7e395720e0432fd245abd9e3adeece5e84cebe6af3f17ef015e38",
		"81dc886d6c76094567c6334054a033f5828de797db4b0cb3c07eda13bd5764ed5c17050cea7aa26e9913b0f81bd67bded64c7c0086378f3c",
		"bc3fce2efc7309c5308d9ca22905b4f0c72e1705721890c8eb380774c3291d532ab05c4f6b7778e39f4f091c09c19787c5651b3db00fce0f",
	}
	sksHex := []string{
		"894aa2e20c43d0bd656f2d7939565d3dbe5bc798b06afc4bb2217c15d0fa5ce7b22be4602a3da3eb15c35ddcf673f2a8f2b314b62d0f283d",
		"77ca5d3775dfce0f3b79bdc9aa731cead7a81dd4bbfe359a21a4145cc7d0a51b50cca25ee16ed609005cb413494f373e5f98fe80a6c6c526",
		"cc64ab8d9359830d57870629f76364be15b3b77cc2f595a7c9e775345e84d24be49f9faf4493e43e01145d989d5096861632694cf2728c39",
		"f56bd16d0223bac7066ee5516a6fc579fa5bddcb1d1fc8031b613d471c1dbce7e99fbd0f4234fa6f114cb617c5ba581e5d0278c3f9ec5715",
		"5768f1ceb995f36e1cb16e5c1fd1692b171a7172a23fe727be0b595d9f73b290f975cc1b31a84e6228e2e2a706e86e38cdd5fb52c974d71d",
		"c182028d183f630ad905be6bc1d732cecacfee6654c378969f68282dac12c5969f42ffcbc9daf8bd30b81ee980743f82e62260232fd59d24",
	}
	input1sAddrsHex := []string{
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d90022621ae0decf28cba81a089f7ad0b1ad7351d4cbdc118aafcab4233e63c68f",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9008cdcc66fbac67e14526cb5e1b146655ed9f7706616aa14e2b43f71747ce00f",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9018be7b5f4f5d23975d287178146b71b7b3b96980db2c61b4e0b59c9d580f9c6",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9017f8f45297de7f0cbff0363cfc6d4246e6cd43b66925883fa4f212b38ae6883",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d902f32001d9b21af3668daae4a9353d243c596b862b5b63d585fd8add10bcf2b7",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d902456149c98d096093b709a04a2f9799456f3c3e0d1c07cf5f2cf2bf07450f62",
	}
	input2sAddrsHex := []string{
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d900a001aadc02e2f68937e7fa127abf186ac81806ffeb6abddf27acb4355cd2a0",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9007d1e45cd6005379a5e2c75b1b494ec92519741b963943192301d3ec2b50ea9",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d90196bc6c7180167a92883dc569561c6961fae026abbbdfe1c723ef49df527d4f",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9014795afa5937061f8d17393071117c01f92968093724ccc8684662ee471a7ca",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9028662c8f5b7636188b091bc268190c75cc75c55623ac732c2681540ad107379",
		"11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d902292e333b9353fc9bf73313abd262a6ebf2b661f9144cec984625b4725d8374",
	}
	bufs1 := []string{
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038ae88dfce6591a57c7d7f1f2cc34e055b8cd6b5d3fe1a9c15615feeec4b3dc4b5e6055a403dbdb3c488b561e16a1b1b61274b8309f010409d000000000000000000000000000000408b150bc76107750467ded45db257fffb1627207f9d2ec2e996aec396bafe849b38b5e0beeef2e2b9e6aad30370d3d102438535090bb016bde28fe6d6a14e079b0000000000000001380100000000000000010800000000000000383a53ee0cf5d968985fe0b5dcf73c1b8b414a19e32d62bc24be9e6257fca32b5edc526851566981e3027f36dae164470845954f1fe3f67ae400000000000000000000000000000040db1cde6da1a556c2bd3edf464768cb31dc4967ccc56061c9bc0ffb3ddb4eaf79ea823f0ded99adc4e6ddcb21a6b0102d7ecef7bba088626eaaed9f2c3e8e74210000000000000001380100000000000000010c000000000000003810faa89bae23767fbfd52fe408ced3485221bcc69f82f44eca574d2f680ece1b8655de5e38d37bc7a9c3dc57c8c601be36ace4e10e859fdb0000000000000000000000000000004027a92c83e3301926edc5f3f575c37f218b3724ad47b047d587040d249a34253b2bbc099fcd003c11740888ad1e5e391061c7757b50323a4d26ab6719dab5ba65000000000000000138010000000000000001100000000000000038cee6dfdf902a1fadadc01d323a2aaf06d1e0543e025604f4e2ee267b921845ce329df9178f148c867bf1a0d15c8529794ae272451c906caa00000000000000000000000000000040d34e4372127765ea688e322fb849c17059c1aeacaf32b950b109b9fb3f583bd58afdeafd52c548bbd5cb42c365ba3cd319ac18e6439bb555d50ea0fb7c0648f5000000000000000138010000000000000001140000000000000038d25e5deee0103955e65131ab7e93fe5f16246f8374286ed5ba2362933745b75516ddf5a33fcb5755620803db581c5c0b380b1c41bd75b84c000000000000000000000000000000409261545c70d884076e112943ca0bfaeebde044cb31d12d95f718fde9285e4d7c050cfd616db6794b0793cda5c4fa95746927326934f6486335536a2813b04166000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0308df55282203b2f04d7c85df121adc35cb39447d1ee81ced4043381f23e1d837eca1f28696a096b0d909763d90ade0fc529a52ef1f5d39c01c7bd765e80c73ccba5dedbdce1eba766400000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba0000000000000001080100000000000000010400000000000000380c863b30d5d7195f74f668bea8cc173643e18c20999e90c7a8e29c32cded6edf144fae91240fba39d7fd35c1fba1a60e9ced79d25399763300000000000000000000000000000040e419d3d12a5a73bbf0660f6d76f27f25bd097133d57cb5864a00f77832b7ca9d23074d491dd02210ddd6cdab0f06891e8743a3803381bbd9f19af5e11adc803300000000000000013801000000000000000108000000000000003864d5a183d3d9864066533046508f22faa0ee336c83e1e3a06ba973966731b292d399cc0418710b4a1fa0c5ec545b393d7d079e273f38005a000000000000000000000000000000403fd06944ac87a384522ace6d8c7d9c7253c0f0ee26841057f9a4e152abbd889f0a4aa29a6076da5fef9f28946da6f5a3f7de7dee2b4bd1ddbab8f32438bfdab00000000000000001380100000000000000010c0000000000000038480177428d1a5b03fb6d1bd296ab51bc975ff27bccb3335d86e4bc1f586f0e678b19645938ee7e6b087cfd7113af3759b0b5fef5a1fa46150000000000000000000000000000004059ec85400863e4424d36ceac39d6e1111cc5b97cfa4e8a2a88be664f3dfef61284d7481a9f34810f34056d07103cbbbfbabe0e0069006a10313bc2b251282bda000000000000000138010000000000000001100000000000000038938cd024fac643758290d8bf542842f0fce61410ff4c691a3cf68678db6379c3d511280bf5d99306a6793a7135e4bf2c203df314b85eb54d000000000000000000000000000000403aefd1787d1c98a00e77b532741b16d335a6dfc018b31dd5eb5b6b29d0554a0f6995b08fa7dbee411b5e0628f43d9aeba54cf741aa1d67ddc334b0808a0e208d000000000000000138010000000000000001140000000000000038f3e760ebb60dab844157b39b8b24396142953315e0f54dd7fc7167915c43279a69e33d37b938a90e71f976e8ee2af5f6a06bba8211960d7a000000000000000000000000000000408b1db471bc94d1a5ba7566fe848b5a877d6eb86f1e500918813c5725f888b2e902e13d44e45b51805b0d55c2919c913c923dded013dc96078efed3de4a606909000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030e724a32423c6019bced8a9522f78e6ddbacb3aabd387c4b962260efa3267359932059128bf229798cd74001ed9f22be021b76c95d5cbb03f17b50b74ef92369c8fc7b273de3da1f0400000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003854f22387bf44bb124091d8bb190ee10b0c386002518e848f81df838fea97b8dfc41b37dd2fed2a39be0a247ff173a78e6553f8cf0685537d0000000000000000000000000000004033a811dd03637b65e8749f23e8631846b4b5e9d946ad59e2f33dcf9761e4a65d12361704843380f8d2226a7ec96e2b2afc407011fbdd1b563b54794eab760e170000000000000001380100000000000000010800000000000000385edecc81303531b1c083f98d333fc3a9ca411a60f378806410682f07f10d557550748332ae7fa04d550d2953714d5e90933e7c94eb0bc6c3000000000000000000000000000000403b301a356dd40b57a9bdd37aafcb414d673ab9ce48b844572b429ee5a3123b36e0f06f60f363aa4dbab1fa9590ff4610390a5a0a9f7d14bae3a7246594e2f7e30000000000000001380100000000000000010c0000000000000038560b56505ed9f90182a7d6c327c24813352f8dbbdeeb217d5864125aab3362e8a462c05ae2cbd8377a1f557feb330ec086e6aadd1e77ac710000000000000000000000000000004042a59599308f8dab96ac86bdabe19671e0d819a4e1842c10af24c3be47dae07ec21189ea123b9db586b9ec690d991b8b63fcad5772e53bf8c09f31e30ab89162000000000000000138010000000000000001100000000000000038a28ade3ba862a537022cd16a6bbb8c771ea289534c812f3c7a724cc8897e0740a33bd50e5c8eb6f6497eee7cf7a4a296eb6cecd0295c41380000000000000000000000000000004044122efedb1559717c531eb8ca508f93ccf50e2d36b3438d327267b0768de9ca9190d71d5dee4988b05cb1758e4af31055a5ba53157d6d80693929f577c5cb5d000000000000000138010000000000000001140000000000000038e287e7d4a40c948ef785acaa55c3ff6d8fc3dc99f2fb4e2e33f10047bf89a912f4d4c67902d1bb0d6d05124617fef28b4d3f316c2c8eea5500000000000000000000000000000040588200f8627b165cf2f24ae6c1d4792a80b02d198c6d9c6617359039f8711e51ad8619ac92ea5f6c2a7163e0fcc1705628c1a8f861964726dd2d1532fd15d207000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a020d88b324089d0052d61fe6cd87c52f8b9f846578cb11aa912fcb15b1ee2fff58dec4e3c79a522b4595f8396864fbacdbac0d88b673ece59803c380380903bc922c4ca3dcac0ded99ae00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038803e6cf22ee4363df44db5f41d2b727d3386daef8c2197e8c2be78cfaf03fc12b163f11446454b75db66dad4fadfa8391ce78e3453100cc50000000000000000000000000000004099aa42efb620e36cda7b9ce32bc64907e764c005ff711d9f5383988cadfbc59071c5e44010775692b001f6709b0607c5aa273dcb40a4fd3217dfd76523b27b2d000000000000000138010000000000000001080000000000000038e29f36a9072c911c17e979fc9226b6daafbe4f7eef16bc2b0fa17e1ff9e5e16a276f4e71a236d38742ada11bdad34d09fd345d3e54ec89e400000000000000000000000000000040255f4a9cb181fcc29c8513348122adf1059df4d94ff19d086a04dc578144606cfd3b4a2b5d525f72136592d856b48966afd40b790b14dc462f814ebf65e4cdae0000000000000001380100000000000000010c0000000000000038b6ade01b62ece200b427ef10a65304a1f15cbcedca17ab4ac118bb689e530fc68114010289c8bb35f80b783136f9b56d436c029e6692242000000000000000000000000000000040aedb079b12417f05158d0a3576bf0800f1c11c77041ddc2d38ea14ec7c22dc151a06900f6085569cfcbad0101fd48e206ca437a091649bd61bcf3ece5327b8be00000000000000013801000000000000000110000000000000003859843ecf158910ca5d1fa6c3ef8269a40fa7d35e17ccf97ff17ed7bafb0e58b047b2a479997ed199abbeb4a6e2c48352e991c8ecb2efbb0400000000000000000000000000000040351d632e4eb53a4f5eba9a35d5488555911346853b0ee3b1b5a2367d7ace53261164df96777746114101114f221b61394bdf900f7a58ac29341f79b224100296000000000000000138010000000000000001140000000000000038779bb19976b4665daaa366cf854f49115a2dc3e6f3a91c202488a319c34f89ffc8babfb425a5aba6496c8bb42fa2ec3ec2c04e7db7fc548300000000000000000000000000000040c797f0cd70e6136b49a37fe82fcac414dc544bb93bd7e8d2a09fb7ea36252ae45c0ba7678a8bca9581b2d9d6aa4ce35a5cee19c9fea5d9bdda17343b1cc13b32000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0300bc59ec21055089c298489a9370ac660b97cee0870cfb22ead1be4bad18aa754cc66bc1e7dc6e3527c929db7876603aed6565a8a99f4a2654454cf9160dcd2aef53638e0ef6704cc200000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038aa13bd61e0132474d7611d6dc624213f3898b16f85a0cb008372a39fbaeda5d4c28f8ace198c4849256ac3c6a8fc856c5474b0bdb3f057040000000000000000000000000000004053c50cf851267fbea21d7fd5b0a2359577cb494b629a9de65bbd30e65a43a4f77be3c20b4c6bc98296a0d8aa569447ae8aa7832cfb28d113a214a1a5d5b2390600000000000000013801000000000000000108000000000000003882619486287c30b53a7cf99da8229d02a1e55cd3cf3565fc5e08ad2373e11be8c303d8b34972350a41635d8a9f099fea9cf986f213cf795100000000000000000000000000000040d46d1f03e52327689055a107c8e2cb6d7f93bb2c60bf1fbe419d4445036c241d0321224856ada0f1aa79089fc23b7ca500df33ed01728ae006b22acde5260dcb0000000000000001380100000000000000010c0000000000000038287ff24c072e16cd496861d43cc601b8eecb51da65ddb0f05306f7f24af828c44897bd1d0075734a0f7c7c651bfc5c7747453fe530b924e500000000000000000000000000000040aa3cd8a69b56c6a9a7800a0e1416a94e6f4b76bf362c77c64738f60bfe26011aec530fa6c400cdcbbd950ad220358487973f8eadd0d8714d78a8e48bc3d41369000000000000000138010000000000000001100000000000000038f79ae0865d4f83fec288fe300386733ec325242ceafa24c39c94323bb8689963846bad84c8e599a99a9412e675ae294ddea0034ba62566540000000000000000000000000000004034c4bf061070c6e4a47298a985cb26705160c2ded4d9734a513db03956ffd519d6fd8ed9baed223cb1ac9df24354e5e69deb309983eff02161b7d56140aec6ad00000000000000013801000000000000000114000000000000003846f3edc37a3b1ff5ad5f85d121e2d873da4e76bf4b53629789c512ceeea1526341ccacfb46cdadb3d10902cc8bb8a809e484832cb1527b6d00000000000000000000000000000040adc4c8786e6f79ef2530f623daffa1990663aa7c1c718160694480e468503cc00af4097a8630d4597385f00d6831a0ebbec8aea660f820bf033c531d08799d5b000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0203c75444ecbc6a9d71042d852c3c4dedfefe5469423d89089415ea61cdfb0d62afb23d4e736526c4b6eedf1623dbd2efaf71fdfc06fbc6c71891ef48270e0f1c68373d86a48e7baf4700000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003830690a46df7a9dee951871add7a7ee0578f562ff6c3fff255e95ca1915115a4816eb7d021dc8c82818f7c2dbf3b644b42ce32f0274053b5b00000000000000000000000000000040288ee4da6fa1932b2ca02052f62fe5db1d307329d792b148a7f1c80be8d181ede6a763cec41e5ab6f82098f86be885f6837bff37e4ff28858dd68c3ad7e8c9e900000000000000013801000000000000000108000000000000003840417bdef348774073b89de0f180472132d99b4557162fb7d70d8dda6d9c4018789c54117053f1612de8d8483a2f6ed972dc01a9408f941c00000000000000000000000000000040497865d10608095085c77ca23e4051ce16ddc4b2aec864c31bfb64679babd15bcd9e1694edb98e0cb99c7a86f34dc24d9c52635e67b5f9c563cb6fe3f5a4258c0000000000000001380100000000000000010c0000000000000038b405d9d14f0ffd29dc083f4ca377314af225da77a1a9b2529554cf88e8e9778b82e948dbecb9616b09c5339ad8e963c55d686bf63948cb0400000000000000000000000000000040e691e27174341a159ca02d1226aa79785f87e68e968b379f33d54ca67b474fe13ec5d561df92245c769c24dd3fafd028e550e9b48fe3b42852f3fe7ba80de0d8000000000000000138010000000000000001100000000000000038748ca3a93d251fa30e161254f92bf705094db44a11900b73b9b6e558e3111c4e5e811044098d264f444f8aa749bfc3d87e8904193957443d000000000000000000000000000000407ea993a1342af5d69b00bc4829a4de449deea1c2df37d822f89ed27050651ca96fcdadb6e628b76b75e737a454f709f55c054f6375ddd44af1319085a5b9f706000000000000000138010000000000000001140000000000000038c66e1b2d50b17c0652db0f2f407658416a26b597745d3cb9388b810a0da6b3fae0ddabb3c3270912000df65a1984c561ff1258cd1703710100000000000000000000000000000040cca00e6faf19eb0598359a1488f6428eed6f6016cf158ac96f68dad57f6446f686cb626a32cb3ab3b9813e2a7c26b5101b58041ca653dab90212c34bfaca2528000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0306001627250ca093db4e629d8b95acc359eba050ca24cb99257e0be9984d5d4dae2addcc7e8ee3842e8234d82e85819e85d6c0a6affd4bd486be1e14cf8d4e7d794944b6a6e344cfa000000000000000020140000000000000000700000001",
	}
	bufs2 := []string{
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038eca50c819743e01055f66ba9b7a9b8c8d53c684bc1a54fc4cdf2a069e2528cfc6ef550ad426480387cca34d8e8b8ea948164bcedac19015a00000000000000000000000000000040c95668039d2d2499039d6f15d05a9089f084cc1b2ff7bea76fb2dcb43fc9ba017a6cd0fe215723b1c9607f060f3bb0b32bb207c64b1bc36aa0382b86f2d0fffb0000000000000001380100000000000000010800000000000000387c0a49759730be4192c40f349b69ad83aa6392e004a2d4c8df3b62b6afb50ba903d91d18f002510e6d70069b0a472c22497473adcedf5cc30000000000000000000000000000004024bdc2952e1faff3acf2ae4db3ae25b66c5f884340ce3b92b34e9116b96d770fdb8a292af2b534d717220ae2ce6e889549ec8e7be38e048632777545e50124200000000000000001380100000000000000010c0000000000000038c0e2e8b883e9a1955fe5ff2c60a0ff16ad51f5bf933f164868b5b91ee302b445a92497f337ba32f1fe134256f2ee6e989210ad463776f45000000000000000000000000000000040d7fa035ff925c5bd57c713aff9307fb6e59584a885f5e8a56b15539682b99259056217b4472f61378572f07b4ba91fa8874fc34238faeaf7bfbde4524da3194a0000000000000001380100000000000000011000000000000000380fabbc7785bf8de8474908503708e545f481180150d4d364e0d91cd0400c89d13dda5358ed42dc8109ba708b1ade4d19a28248ad15036f04000000000000000000000000000000403a59f9a33de9f0ba9452ce66f2a950de60e6a3663535adf510c994ef1cb3194fbf00084514d0e00c74a4663327f84b5e7c39c720ccec04a9b90b9b3dc118e2780000000000000001380100000000000000011400000000000000381c3bd4b1f39038aeb7c24e512ef3351b8f09dbf1dd71bddb45b67b5e8d6cadc8050d9d2feaf2626fd9d4efef0fa650ea140f51928d4e96430000000000000000000000000000004007f2af233e3cf4523ab1b52c93ccac3de6c574456314a07f0d1f59ceed625641ab5794c9d2a3f65f3489df0db9b82f2db055721d9fc6d533cc2fd07d614689ba000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030e4e382d25430f4a2ccf3287357861dcc9d93a55c3854f4990f84910f8706a5db11fefea3e5347c299bf76675c62c79171e40a15b4650d61eed9020c01480c47de7f0ede22c399bae700000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba0000000000000001080100000000000000010400000000000000383a2c5db4af04028fc97d326d9cf150a51a80388da52341f35cd846cff4a75f8fce178c819cbd10b6e849905498fe07048b3200223cb8ca5a000000000000000000000000000000402eb5312e772b0130ffa7e97b63f406d431889c4dd9665effb545b73e4a6fed72382b67226d10c9ed048d61163a1fbf332fdb0e31f613fe15b4069e9bf9f8da82000000000000000138010000000000000001080000000000000038aaaadcd757a397ae8931a010986f8c6d9d5441ab743d3a4bc4a54c2b7f7643be17dc6f6013cb5f18f242e5d6846b55a6c9aacf8313f66b0300000000000000000000000000000040afd6b9f03e2aaeee40926fae6f3455e9764d29611562a5d6779b39dd7a423fc0b866b8bc0966aef4f7c7898dd9afb5ae583351dd73b8046d98fcaf7480949ad00000000000000001380100000000000000010c00000000000000386693b092ea13e66b48663159f9ad038c814e547684b8dc9827e397db055c3c982cf79b94307cc165cbfdab5b1665ba6184e58d963a08f228000000000000000000000000000000400a13f689a41b237960fadadac0f915fb9045e15a8e1a1b1dd0afd1c9058972888ebac386f1bd5cec79d1b446eda0e620d6cadd69649dc564b81eb402b8a8e36f0000000000000001380100000000000000011000000000000000382c048fc6a0ea16545c4c6556bd2922a3b6d2e06262fa30f1b6761eef4ed0504309136598796b31cd0ded7f00ff93691ebe0e3f52493bdb4f000000000000000000000000000000406cf0aa474af68435d2def24afc2268a3f88295d9efdc902cc4578f5748a5f82fbb993f8657c5aafd3a3202187ce7c68798118b638d8c1fb72ba0d28aa7118727000000000000000138010000000000000001140000000000000038b40f9eeb76a1c30b37643e919862afebe07feab58ef4c4447a2ba2217e00b4efcb4a09321dcf067a51f4b770d1e758b75fd576477008f2a300000000000000000000000000000040597db9d4b41e07965453e951d8285f1681359e6102de427aa0207819191f4e17472666ba5bb3e784adb2658f498f4c5c1aaf0f7012f870c2514b5c0fcd9183b8000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a030f9053d34dc6e3f62e7cd8fe42aef9071766377943467b469c33d81022566009e20457d95a49886ac6dba89c45f56b7dc88cdfaa971410fdcf78dbf0f306199ed2941b7017a978707e00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038aea03cd1e5296fbbd4a57adb77fd68011410a5879d277e3c7bec1201ef8bfd46df0937b197a4a10401d73f4c158a945647755aacabbe6962000000000000000000000000000000403ccbd1002b266e186ff526759cdc928647f22a39dc638648ca9a519db69c3708994815bb74ad8ca6b22470006d7c950262104a400c09735d65eb38e123ae088c000000000000000138010000000000000001080000000000000038a0e2979cf6125461575bf19359a0cc7642b6b5af73c4b1a77e6cf09b7d46bf7a0911fdfe6acb619eefaa60512d9e1a195984a47ee8642834000000000000000000000000000000400d92bea8487bdf02810bbc011b0cedb3b33197e63f890be523108bf05d5e353756a917fa83c8008ca57184ecf683a278b33e9333ab2ccad9ef74ffc569bb29cd0000000000000001380100000000000000010c000000000000003844c02fab19700480662ad893619a9836de1630e54c937a6a94372876ebd04a5af865c05202b3245366404e3cb5b4601b50a99439a0c6c06e00000000000000000000000000000040740e450df21d330ae8ebfb5a0250547565b4ef82fd6e371383afa9f48d03b42878d177b6d90c991bf5867af91670620cff45198ac3074f2d8643bb7763dcfa2a00000000000000013801000000000000000110000000000000003883dd1f44174047f8e60a6c5e2ee45dceb3b0fb48167690066e600e614f284e390d54024154b256b1e54c5f0617997ee962a367a60fe076770000000000000000000000000000004098dd7eac64f808eb1630663b323930d19ab935ff8417716759b3ec0a9be97c22b36d1e9a8d7be3942b154aaab0b9cac7842448280b2dcfbdb695dcbd8fafa05f000000000000000138010000000000000001140000000000000038d6b5e20e91f64e82d79e92449a20abc5e74fb145c8c9a3c5e3dc98221fb5d785a67b87fc2590e63cb59efe1cdb0ee9d6fd151be07a180d6b000000000000000000000000000000407312fa0a4ab297787378ecf23827897ee0e4127e8891506dd87b93b12c694d380472c6e2a0a3ac7a75d5a5ea9ffe2bedc6d08343394335f28aefcd13fbb35559000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a03015b69771e503285338884d8c4f062aab9c219d4dd99ce5f8bf7dcf0fb5b7bc5d4ae7c3c13975c1d769240d08177763bdfdb6b4748d916254a66f62585f72c179d29375f8fa9f227bd00000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003870bba67d6c3e698d796082117612c0decabc2e7d8dd9beba5b3b663f1450836f65e816564dfe743eeeb2b3604f3b9a420f7d68ebe2b0d96e000000000000000000000000000000407c6f9b424679ec00b5167e453e76d8d95565858c5338cab0f66fa14f88a71a16531c66cf050dc734f2f7e816c4563fc7fa63a1f26de5a613c44dd2013ceac5c6000000000000000138010000000000000001080000000000000038f6c80f745497ff51b7e334d214b915982d220c89670cf73b20b307c5db44426a884e4d0f923c77b08d4c5a576509e8794d4118b1e82f5845000000000000000000000000000000401ccba1f36a6c90231b648df1d1546b41e682d52cd07409b6c0de67d4ce91c8da45672b6c048a3b19283466cd2582410eeed3563904dce0983a499d989052e9980000000000000001380100000000000000010c00000000000000382ce6d8d803addd976a4a09fa98781d9ce273e21106c0d1f5bef495a3570a9ff4afac556ff803fda6d62d8a224229b8661f29a17c2877a53a00000000000000000000000000000040f2886fc71c55719b5386458e444886d096330d3af5ca52afa6db10afac62ffd840ec9f254052e77ba6d1374cf0684752009e217d85866ec4454229885bb2c69a00000000000000013801000000000000000110000000000000003816dfe96e184dbcb15b5fac0a6efd3c1baf60409ef264c2f8c80764726685ea3dcae84b683cf2e694126bb992d571582ea8a002aa4000f3be00000000000000000000000000000040c3b6120ccc636d66750f8a48c350dca78ba17f0bb5949d36e67ba93888daa970542d63327dc74216188e189b594e1aaf58e1c428f76efb4f198b2a2f73cf4bb5000000000000000138010000000000000001140000000000000038ef6050801a487a88db7bf46f96e66b567e828d84c624fdf7d067ecd89b5a8d1a1931aa0721c28f98f92b43917372588c572062f0346c0f0200000000000000000000000000000040907fdecec88e8f645c002edb2d29c37de2286eaccaf0cb22379d53d27b6d8c124cab88f83480df0fb3d2ef839d0d5098092530d3baebd4ea680ec55ad1c85d32000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0302c9c9d4dde5e62aafc1683d9ecb81791f703036a317b0dd36582c70f1835367776db27c824552210a7b5d65ccd9715870da915aad587fbc19e425e1668882fb416184b45af79457a000000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba00000000000000010801000000000000000104000000000000003870452ed77781d41f3a1af90b008ef4b2330a94cb20f82a5e6536fcf96a5257fbbb393f5f8ad227d35f21a4d19286eff58c9b36ebbe30534b0000000000000000000000000000004015303e6dde9d9d2faa7cb69a2675f21bfab3b063abfdb1b732624fbc7d1a5a34f40e7cc1781c6847dbb09f6691ff414fb6e7c8ea9971c3ec1862cd42c0e33661000000000000000138010000000000000001080000000000000038c8778171bd5983cafc4d46f9584eee717f2aa6ae2bae15158927d1011551d5ff055bfe4d9d7034fb8f2d278c0cba999c99d5afbdb39865290000000000000000000000000000004067cf1b4c291c4b0c9384eda5547e3ba8e27f2fa60c70e76f6d97343e59f0dbe6b63a15bc9b6d6f49909cd00d23974051f1f4cc9816f37cba10a97469e7d0e2580000000000000001380100000000000000010c000000000000003806a32053c55c919a6346ef2ddc86891b4b32768cd0fb9f514d4f370382b1768a1552a86e8c583a073150d3965907f245111fd863b2f950a700000000000000000000000000000040b71f10034888251a9ccbc44b3f719a24f506e938ca08a7ce96e831290e4792f58ebe84a4932834fd29764a9340ba65bbe6219d9d98efadd1b5cbfd835224708b0000000000000001380100000000000000011000000000000000389c626d014755722670df38934fb3ab05c94485d6109e290453d58d161ce853f96b82f0e4f1a0469dc5c5ec800cd40001e8d7936ae08803c700000000000000000000000000000040f65b1be90ce6553570e53f690df5666f8335d594ea9594613b829bd1469010666df9d6e2f8eddf541f6c550e5417058bd2d99405ceb6324a1c72259cd342e98d000000000000000138010000000000000001140000000000000038a17ba6f6d445b25a7e93136939bbd64ffa4ab17ccd0ba81d67da8b267fe807cd1bca94ef3245493e272acde0b7adec5b2160d84282e0116c00000000000000000000000000000040c620cf3f50381c1f875a2d35e1acc377900b19b579a8dca3b1e586a81f34cbd59ba77e9783281605f8918a18b756a704ad6bcf1c2983e4b2926e01afbca95e1b000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a02073fe7087632b5bcfa4261dffcad91ebc04f29ade8408b44b250a1cf1c1501d29b329070309761dce8013b2d6252270a88499def769c9997e7b19a5db34ab19b0a6be85a3c3028b5e900000000000000020140000000000000000700000001",
		"020000000001000000000000000100000000000000000800000000000000000000000000000000000000000000004019bd3cbb62b1937957a11cabd0d39860582b6928e77d0e0ea5ee7f3b2f8cacb3dea8ea0972651adc3245fd10926f2f31e80377196e4e6c7ee2bd74051e58bcba000000000000000108010000000000000001040000000000000038d085722c5c2373d8928b900ce8d0c34403d95078320b5033f7d74f1faafa3c20408dd19996f0bfab598a69e7b1a813c40b8c99ccbc50e72f00000000000000000000000000000040a32a72719da0ba9d5ab4e2d079ac396886fe8155cf74d81519a52774921b6c0ef49f733e0b14c38badedecd64be36005c11b6c59fd099d4416d64168107dfe430000000000000001380100000000000000010800000000000000382cf2c6fdb0eb79089eaa010e9941768ef8dc5e3c60fee70d79b50e18162edf6d500b7cb014df5d4efd4bf3667abad91f1ae492561138f62a0000000000000000000000000000004008dd2a9a7e82484b11deebc16c2af26d4f3ca18085edf3f5e0ba3008795254af417b1fe08710c345d067c2786a33aea5d5ffc5b9ae398fad2dc9beee30642bd70000000000000001380100000000000000010c00000000000000381a8ec1d0d9d9e89ffcb1ff85415682956347ea663a6ecfd95343d7b07dfa391605e8ec11959e7f655bdba17ae9172cb27c8c44acc04d97bc00000000000000000000000000000040eb85e87c4833d7a3e817599c726c11a9b2ad4f086ee62e57c3bf9d45a70fa844c413b3e593d2ab534182c84d9be97066a16d026c7b0d8ec6fff101ba31c774e80000000000000001380100000000000000011000000000000000385f2f3ce2c1e3ec5f8c16e5ebb083ef86eff145da20f9f89b136f587cc3ddad6a2559a2843c2cec33092e3004dcf4fa650e90a910d98bb0ff00000000000000000000000000000040af88f2bcb0be6f12b108254c641859a18505a4aba2c2734fce02e8ddb82d91aa34ce2ad4a7ea565daaf0d03929515d3aef1d1e3bf15488a2a0de59679b8608200000000000000001380100000000000000011400000000000000381ca7e18ce166eb638f5e11cb0f41750cca1f572ccb0889869c94367b731e12146de06a6db1a672299007572e0d00c608d056573a34113f5800000000000000000000000000000040e554e9e66246ff311c11dc52608f98793fcc76a52be2841b74b1c66d546569a5d50c40d40b6f23c275ef638c8082b7e74ff5df61dc9dcb29b77a7c1197064291000000000000000138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000020096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f0000000000000000000000000000004073d5f052421a08341635e867289caba8280d204ba4ae7fa79f598afc047a79cd961783dbba87e4ef317c2bbefd72840f689649467cc651f7a39dfaf234e98a94000000000000000120000000000000004a0209a29679708b0bb745b611bfb8058303618ac35de0113fed51f8ff99a517bb7b039013430caa67255361e7246d94ee5b704141ae33a14102b8dd00d8734adff87a6e055e71d927db0900000000000000020140000000000000000700000001",
	}
	for i, addr1Hex := range input1sAddrsHex {
		txn, _ := nodeHg.NewTransaction(false)
		addr1, _ := hex.DecodeString(addr1Hex)
		addr2, _ := hex.DecodeString(input2sAddrsHex[i])
		buf1, _ := hex.DecodeString(bufs1[i])
		buf2, _ := hex.DecodeString(bufs2[i])
		tree1, _ := tries.DeserializeNonLazyTree(buf1)
		tree2, _ := tries.DeserializeNonLazyTree(buf2)
		nodeHg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(addr1[32:]), tree1.Commit(nodeHg.GetProver(), false), big.NewInt(55*26)))
		nodeHg.SetVertexData(txn, [64]byte(addr1), tree1)
		nodeHg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(addr2[32:]), tree2.Commit(nodeHg.GetProver(), false), big.NewInt(55*26)))
		nodeHg.SetVertexData(txn, [64]byte(addr2), tree2)
		err := txn.Commit()
		if err != nil {
			t.Fatal(err)
		}
	}
	nodeHg.Commit(0)
	shardIdx := 2
	pos := 5
loop:
	for shardIdx < 3 {
		addr1, _ := hex.DecodeString(input1sAddrsHex[pos])
		addr2, _ := hex.DecodeString(input2sAddrsHex[pos])
		// simulate input as commitment to total
		input1, err := token.NewPendingTransactionInput(slices.Concat(token.QUIL_TOKEN_ADDRESS, addr1[32:]))
		if err != nil {
			t.Fatal(err)
		}
		input2, err := token.NewPendingTransactionInput(slices.Concat(token.QUIL_TOKEN_ADDRESS, addr2[32:]))
		if err != nil {
			t.Fatal(err)
		}
		tokenconfig := &token.TokenIntrinsicConfiguration{
			Behavior: token.Mintable | token.Burnable | token.Divisible | token.Acceptable | token.Expirable | token.Tenderable,
			MintStrategy: &token.TokenMintStrategy{
				MintBehavior: token.MintWithProof,
				ProofBasis:   token.ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(8000000000),
			Name:   "QUIL",
			Symbol: "QUIL",
		}

		// Create RDF multiprover for testing
		rdfSchema, err := prepareRDFSchemaFromConfig(token.QUIL_TOKEN_ADDRESS, tokenconfig)
		assert.NoError(t, err)
		parser := &schema.TurtleRDFParser{}
		rdfMultiprover := schema.NewRDFMultiprover(parser, nodeHg.GetProver())
		km := keys.NewInMemoryKeyManager(bc, dc)
		vk, _ := hex.DecodeString(vksHex[pos])
		vkd, _ := dc.NewFromScalar(vk)
		err = km.PutRawKey(&tkeys.Key{
			Id:         "q-view-key",
			Type:       crypto.KeyTypeDecaf448,
			PrivateKey: vkd.Private(),
			PublicKey:  vkd.Public(),
		})
		if err != nil {
			t.Fatal(err)
		}
		sk, _ := hex.DecodeString(sksHex[pos])
		skd, _ := dc.NewFromScalar(sk)
		err = km.PutRawKey(&tkeys.Key{
			Id:         "q-spend-key",
			Type:       crypto.KeyTypeDecaf448,
			PrivateKey: skd.Private(),
			PublicKey:  skd.Public(),
		})
		if err != nil {
			t.Fatal(err)
		}

		rvk, _ := dc.New()
		rsk, _ := dc.New()
		out1, err := token.NewPendingTransactionOutput(big.NewInt(7), vkd.Public(), skd.Public(), rvk.Public(), rsk.Public(), 0)
		if err != nil {
			t.Fatal(err)
		}
		out2, err := token.NewPendingTransactionOutput(big.NewInt(2), vkd.Public(), skd.Public(), rvk.Public(), rsk.Public(), 0)
		if err != nil {
			t.Fatal(err)
		}
		tx := token.NewPendingTransaction(
			[32]byte(token.QUIL_TOKEN_ADDRESS),
			[]*token.PendingTransactionInput{input1, input2},
			[]*token.PendingTransactionOutput{out1, out2},
			[]*big.Int{big.NewInt(1), big.NewInt(2)},
			tokenconfig,
			nodeHg,
			&bulletproofs.Decaf448BulletproofProver{},
			nodeHg.GetProver(),
			verenc.NewMPCitHVerifiableEncryptor(1),
			dc,
			keys.ToKeyRing(km, false),
			rdfSchema,
			rdfMultiprover,
		)
		err = tx.Prove(0)
		if err != nil {
			t.Fatal(err)
		}
		for _, output := range tx.Outputs {
			// Create PendingTransaction tree
			pendingTree := &qcrypto.VectorCommitmentTree{}

			// Index 0: FrameNumber
			if err := pendingTree.Insert(
				[]byte{0},
				output.FrameNumber,
				nil,
				big.NewInt(8),
			); err != nil {
				panic(err)
			}

			// Index 1: Commitment
			if err := pendingTree.Insert(
				[]byte{1 << 2},
				output.Commitment,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 2: To OneTimeKey
			if err := pendingTree.Insert(
				[]byte{2 << 2},
				output.ToOutput.OneTimeKey,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 3: Refund OneTimeKey
			if err := pendingTree.Insert(
				[]byte{3 << 2},
				output.RefundOutput.OneTimeKey,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 4: To VerificationKey
			if err := pendingTree.Insert(
				[]byte{4 << 2},
				output.ToOutput.VerificationKey,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 5: Refund VerificationKey
			if err := pendingTree.Insert(
				[]byte{5 << 2},
				output.RefundOutput.VerificationKey,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 6: To CoinBalance
			if err := pendingTree.Insert(
				[]byte{6 << 2},
				output.ToOutput.CoinBalance,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 7: Refund CoinBalance
			if err := pendingTree.Insert(
				[]byte{7 << 2},
				output.RefundOutput.CoinBalance,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 8: To Mask
			if err := pendingTree.Insert(
				[]byte{8 << 2},
				output.ToOutput.Mask,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 9: Refund Mask
			if err := pendingTree.Insert(
				[]byte{9 << 2},
				output.RefundOutput.Mask,
				nil,
				big.NewInt(56),
			); err != nil {
				panic(err)
			}

			// Index 10: Expiration
			expirationBytes := binary.BigEndian.AppendUint64(nil, output.Expiration)
			if err := pendingTree.Insert(
				[]byte{10 << 2},
				expirationBytes,
				nil,
				big.NewInt(8),
			); err != nil {
				panic(err)
			}
			pendingTypeBI, err := poseidon.HashBytes(
				slices.Concat(tx.Domain[:], []byte("pending:PendingTransaction")),
			)

			// Type marker at max index
			if err := pendingTree.Insert(
				bytes.Repeat([]byte{0xff}, 32),
				pendingTypeBI.FillBytes(make([]byte, 32)),
				nil,
				big.NewInt(32),
			); err != nil {
				panic(err)
			}

			// Compute address from tree commit
			commit := pendingTree.Commit(nodeInclusionProver, false)
			outAddrBI, err := poseidon.HashBytes(commit)
			if err != nil {
				panic(err)
			}
			outAddr := slices.Concat(
				tx.Domain[:],
				outAddrBI.FillBytes(make([]byte, 32)),
			)
			if outAddr[32] != byte(shardIdx) {
				fmt.Printf("%v %v\n", outAddr[32], byte(shardIdx))
				continue loop
			}
		}
		data, err := tx.ToBytes()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%x\n", data)
		shardIdx++
	}
	t.FailNow()
}

// TestAppConsensusEngine_Integration_NoProversStaysInLoading tests that engines
// remain in the loading state when no provers are registered in the hypergraph
func TestAppConsensusEngine_Integration_NoProversStaysInLoading(t *testing.T) {
	t.Log("Testing app consensus engines with no registered provers")

	// Create shared components
	logger, _ := zap.NewDevelopment()
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}

	// Create six nodes
	numNodes := 6
	engines := make([]*AppConsensusEngine, numNodes)
	pubsubs := make([]*mockAppIntegrationPubSub, numNodes)
	quits := make([]chan struct{}, numNodes)

	// Create shared hypergraph with NO provers registered
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	_, m, cleanup := tests.GenerateSimnetHosts(t, numNodes, []libp2p.Option{})

	defer cleanup()
	// Create separate hypergraph and prover registry for each node to ensure isolation
	for i := 0; i < numNodes; i++ {
		nodeID := i + 1
		peerID := []byte{byte(nodeID)}

		t.Logf("Creating node %d with peer ID: %x", nodeID, peerID)

		// Create unique components for each node
		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{
			InMemoryDONOTUSE: true,
			Path:             fmt.Sprintf(".test/app_no_provers_%d", nodeID),
		}, 0)

		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{
			InMemoryDONOTUSE: true,
			Path:             fmt.Sprintf(".test/app_no_provers_%d", nodeID),
		}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

		clockStore := store.NewPebbleClockStore(pebbleDB, logger)
		inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)
		shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)

		// Create prover registry - but don't register any provers
		proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
		require.NoError(t, err)

		// Create key manager with prover key (but not registered in hypergraph)
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManager := keys.NewInMemoryKeyManager(bc, dc)
		_, _, err = keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)

		// Create other components
		keyStore := store.NewPebbleKeyStore(pebbleDB, logger)
		frameProver := vdf.NewWesolowskiFrameProver(logger)
		signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		// Create global time reel (needed for app consensus)
		globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)
		require.NoError(t, err)

		appTimeReel, err := consensustime.NewAppTimeReel(logger, appAddress, proverRegistry, clockStore, true)
		require.NoError(t, err)

		eventDistributor := events.NewAppEventDistributor(
			globalTimeReel.GetEventCh(),
			appTimeReel.GetEventCh(),
		)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)
		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 10)
		rewardIssuance := reward.NewOptRewardIssuance()

		// Create pubsub
		p2pcfg := config.P2PConfig{}.WithDefaults()
		p2pcfg.Network = 1
		p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
		p2pcfg.MinBootstrapPeers = numNodes - 1
		p2pcfg.DiscoveryPeerLookupLimit = numNodes - 1
		c := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &p2pcfg,
		}
		pubsubs[i] = newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[i].ID()), m.Nodes[i], m.Keys[i], m.Nodes)
		pubsubs[i].peerCount = 10 // Set high peer count

		// Create engine
		engine, err := NewAppConsensusEngine(
			logger,
			&config.Config{
				Engine: &config.EngineConfig{
					Difficulty:   10,
					ProvingKeyId: "q-prover-key",
				},
				P2P: &config.P2PConfig{
					Network:               1,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			1,
			appAddress,
			pubsubs[i],
			hg,
			keyManager,
			keyStore,
			clockStore,
			inboxStore,
			shardsStore,
			hypergraphStore,
			frameProver,
			inclusionProver,
			bulletproofs.NewBulletproofProver(), // bulletproofProver
			verifiableEncryptor,                 // verEnc
			dc,                                  // decafConstructor
			nil,                                 // compiler - can be nil for consensus tests
			signerRegistry,
			proverRegistry,
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			eventDistributor,
			qp2p.NewInMemoryPeerInfoManager(logger),
			appTimeReel,
			globalTimeReel,
			&mocks.MockBlsConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
			nil,
		)
		require.NoError(t, err)
		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		engines[i] = engine
		quits[i] = make(chan struct{})
	}

	// Wire up all pubsubs to each other
	for i := 0; i < numNodes; i++ {
		pubsubs[i].mu.Lock()
		for j := 0; j < numNodes; j++ {
			if i != j {
				tests.ConnectSimnetHosts(t, m.Nodes[i], m.Nodes[j])
				pubsubs[i].networkPeers[fmt.Sprintf("peer%d", j)] = pubsubs[j]
			}
		}
		pubsubs[i].mu.Unlock()
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
		assert.Equal(t, tconsensus.EngineStateLoading, state,
			"Node %d should be in loading state when no provers are registered", i+1)
	}

	// Stop all engines
	for i := 0; i < numNodes; i++ {
		<-engines[i].Stop(false)
	}

	t.Log("Test completed - all nodes remained in loading state as expected")
}

// TestAppConsensusEngine_Integration_AlertStopsProgression tests that engines
// halt when an alert broadcast occurs
func TestAppConsensusEngine_Integration_AlertStopsProgression(t *testing.T) {
	t.Log("Testing alert halt")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	appAddress := []byte{0xAA, 0x01, 0x02, 0x03} // App shard address
	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	t.Logf("  - App shard address: %x", appAddress)
	t.Logf("  - Peer ID: %x", peerID)

	// Create in-memory key manager
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)
	proverKey, _, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	t.Logf("  - Created prover key: %x", proverKey.Public().([]byte)[:16]) // Log first 16 bytes
	cfg := zap.NewDevelopmentConfig()
	adBI, _ := poseidon.HashBytes(proverKey.Public().([]byte))
	addr := adBI.FillBytes(make([]byte, 32))
	cfg.EncoderConfig.TimeKey = "M"
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(fmt.Sprintf("node %d | %s", 0, hex.EncodeToString(addr)[:10]))
	}
	logger, _ := cfg.Build()
	// Create stores
	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_basic"}, 0)

	// Create inclusion prover and verifiable encryptor
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	bulletproof := bulletproofs.NewBulletproofProver()
	decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
	compiler := compiler.NewBedlamCompiler()

	// Create hypergraph
	hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_basic"}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
	hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

	// Create key store
	keyStore := store.NewPebbleKeyStore(pebbleDB, logger)

	// Create clock store
	clockStore := store.NewPebbleClockStore(pebbleDB, logger)

	// Create inbox store
	inboxStore := store.NewPebbleInboxStore(pebbleDB, logger)

	// Create shards store
	shardsStore := store.NewPebbleShardsStore(pebbleDB, logger)

	// Create concrete components
	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)

	// Create prover registry with hypergraph
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
	require.NoError(t, err)

	// Register the prover in hypergraph
	proverAddress := calculateProverAddress(proverKey.Public().([]byte))
	registerProverInHypergraphWithFilter(t, hg, proverKey.Public().([]byte), proverAddress, appAddress)
	t.Logf("  - Created prover registry and registered prover with address: %x", proverAddress)

	proverRegistry.Refresh()

	// Create fee manager and track votes
	dynamicFeeManager := fees.NewDynamicFeeManager(logger, inclusionProver)

	frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
	globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
	difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(0, time.Now().UnixMilli(), 80000)
	rewardIssuance := reward.NewOptRewardIssuance()

	_, m, cleanup := tests.GenerateSimnetHosts(t, 1, []libp2p.Option{})
	defer cleanup()
	p2pcfg := config.P2PConfig{}.WithDefaults()
	p2pcfg.Network = 1
	p2pcfg.StreamListenMultiaddr = "/ip4/0.0.0.0/tcp/0"
	p2pcfg.MinBootstrapPeers = 0
	p2pcfg.DiscoveryPeerLookupLimit = 0

	c := &config.Config{
		Engine: &config.EngineConfig{
			Difficulty:   80000,
			ProvingKeyId: "q-prover-key",
		},
		P2P: &p2pcfg,
	}
	pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[0].ID()), m.Nodes[0], m.Keys[0], m.Nodes)
	// Start with 0 peers to trigger genesis initialization
	pubsub.peerCount = 0

	// Create global time reel (needed for app consensus)
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 1, true)
	require.NoError(t, err)

	alertKey, _, _ := keyManager.CreateSigningKey("alert-key", crypto.KeyTypeEd448)
	pub := alertKey.Public().([]byte)
	alertHex := hex.EncodeToString(pub)

	// Create factory and engine
	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
				AlertKey:     alertHex,
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
		shardsStore,
		hypergraphStore,
		frameProver,
		inclusionProver,
		bulletproof,
		verifiableEncryptor,
		decafConstructor,
		compiler,
		signerRegistry,
		proverRegistry,
		qp2p.NewInMemoryPeerInfoManager(logger),
		dynamicFeeManager,
		frameValidator,
		globalFrameValidator,
		difficultyAdjuster,
		rewardIssuance,
		&mocks.MockBlsConstructor{},
		channel.NewDoubleRatchetEncryptedChannel(),
	)

	engine, err := factory.CreateAppConsensusEngine(
		appAddress,
		0, // coreId
		globalTimeReel,
		nil,
	)
	require.NoError(t, err)
	mockGSC := &mockGlobalClientLocks{}
	engine.SetGlobalClient(mockGSC)

	quit := make(chan struct{})
	errChan := engine.Start(quit)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
	}
	t.Log("  - Engine started successfully")

	// Track published frames
	publishedFrames := make([]*protobufs.AppShardFrame, 0)
	afterAlertFrames := make([]*protobufs.AppShardFrame, 0)
	afterAlert := false

	var mu sync.Mutex
	pubsub.Subscribe(engine.getConsensusMessageBitmask(), func(message *pb.Message) error {
		data := message.Data
		// Check if data is long enough to contain type prefix
		if len(data) >= 4 {
			// Read type prefix from first 4 bytes
			typePrefix := binary.BigEndian.Uint32(data[:4])

			// Check if it's a GlobalFrame
			if typePrefix == protobufs.AppShardFrameType {
				frame := &protobufs.AppShardFrame{}
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
		return nil
	})

	sig, _ := alertKey.SignWithDomain([]byte("It's time to stop!"), []byte("GLOBAL_ALERT"))
	alertMessage := &protobufs.GlobalAlert{
		Message:   "It's time to stop!",
		Signature: sig,
	}

	alertMessageBytes, _ := alertMessage.ToCanonicalBytes()

	// Wait for any new messages to flow after
	time.Sleep(10 * time.Second)

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

	// Stop
	engine.UnregisterExecutor("test-executor", 0, false)
	engine.Stop(false)
}
