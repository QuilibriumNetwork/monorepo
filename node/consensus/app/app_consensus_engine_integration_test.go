//go:build integrationtest
// +build integrationtest

package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
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
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
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

	// Create concrete components
	frameProver := vdf.NewWesolowskiFrameProver(logger)
	signerRegistry, err := registration.NewCachedSignerRegistry(keyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
	require.NoError(t, err)

	// Create prover registry with hypergraph
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), hg)
	require.NoError(t, err)

	// Create peer info manager
	peerInfoManager := qp2p.NewInMemoryPeerInfoManager(logger)

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

	pubsub := newMockAppIntegrationPubSub(peerID)
	// Start with 0 peers to trigger genesis initialization
	pubsub.peerCount = 0

	// Create global time reel (needed for app consensus)
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)
	require.NoError(t, err)

	// Create factory and engine
	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               99,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
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

	// Register an executor to generate activity
	t.Log("Step 3: Registering executor")
	executor := newMockIntegrationExecutor("test-executor")
	engine.RegisterExecutor(executor, 0)
	t.Log("  - Registered executor: test-executor")

	// Wait for genesis initialization
	t.Log("Step 4: Waiting for genesis initialization (0 peers)")
	time.Sleep(2 * time.Second)

	// Now increase peer count to allow normal operation
	t.Log("Step 5: Enabling normal operation")
	pubsub.peerCount = 10
	t.Log("  - Increased peer count to 10")

	// Let it run
	t.Log("Step 6: Letting engine run and produce frames")
	time.Sleep(20 * time.Second)

	// Verify results
	t.Log("Step 7: Verifying results")
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

	// Create network
	t.Log("Step 2: Creating network of nodes")
	for i := 0; i < numNodes; i++ {
		peerID := []byte{byte(i + 1), 0x00, 0x00, 0x00}
		pubsubs[i] = newMockAppIntegrationPubSub(peerID)
		pubsubs[i].peerCount = numNodes - 1
		t.Logf("  - Created node %d with peer ID: %x", i, peerID)
	}

	// Connect pubsubs
	t.Log("Step 3: Connecting nodes in full mesh")
	for i := 0; i < numNodes; i++ {
		pubsubs[i].mu.Lock()
		for j := 0; j < numNodes; j++ {
			if i != j {
				pubsubs[i].networkPeers[string(pubsubs[j].peerID)] = pubsubs[j]
			}
		}
		pubsubs[i].mu.Unlock()
	}
	t.Log("  - All nodes connected")

	// Create key managers and prover keys for all nodes
	keyManagers := make([]tkeys.KeyManager, numNodes)
	proverKeys := make([][]byte, numNodes)
	var err error
	for i := 0; i < numNodes; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		dc := &bulletproofs.Decaf448KeyConstructor{}
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
	}

	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_fee_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_fee_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)
	tempHg := hypergraph.NewHypergraph(logger, tempHypergraphStore, tempInclusionProver, []int{}, &tests.Nopthenticator{})
	tempClockStore := store.NewPebbleClockStore(tempDB, logger)
	tempInboxStore := store.NewPebbleInboxStore(tempDB, logger)
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register all prover keys in the hypergraph
	for i, proverKey := range proverKeys {
		// Calculate prover address using poseidon hash
		proverAddress := calculateProverAddress(proverKey)
		// Register prover in hypergraph
		registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, appAddress)
		t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
	}

	// Refresh the prover registry to pick up the newly added provers
	err = proverRegistry.Refresh()
	require.NoError(t, err)

	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 99, true)
	require.NoError(t, err)

	// Create engines with different fee voting strategies
	t.Log("Step 4: Creating consensus engines for each node")
	for i := 0; i < numNodes; i++ {
		bc := &bls48581.Bls48581KeyConstructor{}
		keyManager := keyManagers[i]

		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_fee_%d", i)}, 0)

		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
		bulletproof := bulletproofs.NewBulletproofProver()
		decafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		compiler := compiler.NewBedlamCompiler()

		hypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_fee_%d", i)}, pebbleDB, logger, verifiableEncryptor, inclusionProver)
		hg := hypergraph.NewHypergraph(logger, hypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{})

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
					Network:               99,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsubs[i],
			hg,
			keyManager,
			keyStore,
			tempClockStore,
			tempInboxStore,
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
		shardAddresses[i] = []byte{0xAA, byte(i + 1), 0x00, 0x00}
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
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register all provers
	for i, proverKey := range proverKeys {
		proverAddress := calculateProverAddress(proverKey)
		registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, shardAddresses[i])
		t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
	}
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 99, true)
	require.NoError(t, err)

	proverRegistry.Refresh()

	// Create engines for each shard
	t.Log("Step 3: Creating consensus engines for each shard")
	for i := 0; i < numShards; i++ {
		peerID := []byte{byte(i + 1), 0x00, 0x00, 0x00}
		pubsub := newMockAppIntegrationPubSub(peerID)
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
					Network:               99,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsub,
			hg,
			keyManager,
			keyStore,
			tempClockStore,
			tempInboxStore,
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
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, tempClockStore, 99, true)
	require.NoError(t, err)

	// Create app time reel
	appTimeReel, err := consensustime.NewAppTimeReel(logger, appAddress, proverRegistry, tempClockStore)
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
	peerID := []byte{0x01, 0x02, 0x03, 0x04}

	pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_coordination"}, 0)

	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

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

	pubsub := newMockAppIntegrationPubSub(peerID)
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
				Network:               99,
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
		peerID := []byte{byte(i + 1), 0x00, 0x00, 0x00}
		bc := &bls48581.Bls48581KeyConstructor{}
		keyManager := keyManagers[i]

		pebbleDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".test/app_prover_%d", i)}, 0)

		inclusionProver := bls48581.NewKZGInclusionProver(logger)
		verifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

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

		pubsub := newMockAppIntegrationPubSub(peerID)
		// Start with 0 peers to trigger genesis initialization
		pubsub.peerCount = 0

		globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)

		factory := NewAppConsensusEngineFactory(
			logger,
			&config.Config{
				Engine: &config.EngineConfig{
					Difficulty:   80000,
					ProvingKeyId: "q-prover-key",
				},
				P2P: &config.P2PConfig{
					Network:               99,
					StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
				},
			},
			pubsub,
			hg,
			keyManager,
			keyStore,
			clockStore,
			inboxStore,
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
	pubsub := newMockAppIntegrationPubSub(peerID)
	pubsub.peerCount = 0 // Start with 0 peers to trigger genesis

	globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)

	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               99,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
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
	t.Log("Testing invalid frame rejection")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Step 1: Setting up test components")
	logger, _ := zap.NewDevelopment()
	appAddress := []byte{0xAA, 0x01, 0x02, 0x03}
	peerID := []byte{0x01, 0x02, 0x03, 0x04}
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

	pubsub := newMockAppIntegrationPubSub(peerID)

	globalTimeReel, _ := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)

	factory := NewAppConsensusEngineFactory(
		logger,
		&config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               99,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
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
	invalidFrames := []*protobufs.AppShardFrame{
		// Frame with nil header
		{
			Header: nil,
		},
		// Frame with invalid frame number (skipping ahead)
		{
			Header: &protobufs.FrameHeader{
				Address:     appAddress,
				FrameNumber: 1000,
				Timestamp:   time.Now().UnixMilli(),
			},
		},
		// Frame with wrong address
		{
			Header: &protobufs.FrameHeader{
				Address:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
				FrameNumber: 1,
				Timestamp:   time.Now().UnixMilli(),
			},
		},
	}

	// Send invalid frames
	t.Log("Step 4: Sending invalid frames")
	for i, frame := range invalidFrames {
		frameData, err := frame.ToCanonicalBytes()
		require.NoError(t, err)

		message := &pb.Message{
			Data: frameData,
			From: []byte{0xFF, 0xFF, 0xFF, byte(i)},
		}

		// Simulate receiving the message
		pubsub.receiveFromNetwork(engine.getConsensusMessageBitmask(), message)
		time.Sleep(100 * time.Millisecond)
		t.Logf("  - Sent invalid frame %d", i)
	}

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

	logger, _ := zap.NewDevelopment()
	numShards := 3
	numNodesPerShard := 6
	shardAddresses := make([][]byte, numShards)

	// Create shard addresses
	for i := 0; i < numShards; i++ {
		shardAddresses[i] = []byte{0xAA, byte(i + 1), 0x00, 0x00}
	}

	// Create key managers and prover keys for all nodes
	totalNodes := numShards * numNodesPerShard
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManagers := make([]tkeys.KeyManager, totalNodes)
	proverKeys := make([][]byte, totalNodes)

	var err error
	for i := 0; i < totalNodes; i++ {
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		proverKeys[i] = pk.Public().([]byte)
	}

	// Create a temporary hypergraph for prover registry
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_complex_temp"}, 0)
	tempInclusionProver := bls48581.NewKZGInclusionProver(logger)
	tempVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	tempHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_complex_temp"}, tempDB, logger, tempVerifiableEncryptor, tempInclusionProver)
	tempHg := hypergraph.NewHypergraph(logger, tempHypergraphStore, tempInclusionProver, []int{}, &tests.Nopthenticator{})
	proverRegistry, err := provers.NewProverRegistry(zap.NewNop(), tempHg)
	require.NoError(t, err)

	// Register all provers
	for i, proverKey := range proverKeys {
		proverAddress := calculateProverAddress(proverKey)
		registerProverInHypergraphWithFilter(t, tempHg, proverKey, proverAddress, shardAddresses[i/6])
		t.Logf("  - Registered prover %d with address: %x", i, proverAddress)
	}

	proverRegistry.Refresh()

	// Create engines for each shard
	type shardNode struct {
		engine *AppConsensusEngine
		pubsub *mockAppIntegrationPubSub
	}
	createAppNodeWithFactory := func(nodeIdx int, appAddress []byte, proverRegistry tconsensus.ProverRegistry, proverKey []byte, keyManager tkeys.KeyManager) (*AppConsensusEngine, *mockAppIntegrationPubSub, *consensustime.GlobalTimeReel, func()) {
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
		nodeHg := hypergraph.NewHypergraph(logger, nodeHypergraphStore, nodeInclusionProver, []int{}, &tests.Nopthenticator{})
		nodeBulletproof := bulletproofs.NewBulletproofProver()
		nodeDecafConstructor := &bulletproofs.Decaf448KeyConstructor{}
		nodeCompiler := compiler.NewBedlamCompiler()

		// Create mock pubsub for network simulation
		pubsub := newMockAppIntegrationPubSub([]byte(fmt.Sprintf("node-%d", nodeIdx)))

		// Create concrete components instead of mocks where possible
		conf := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               99,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		}

		// Create frame prover using the concrete implementation
		frameProver := vdf.NewWesolowskiFrameProver(logger)

		// Create signer registry using the concrete implementation
		signerRegistry, err := registration.NewCachedSignerRegistry(nodeKeyStore, keyManager, bc, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, nodeInclusionProver)
		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
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
			nodeHypergraphStore,
			frameProver,
			nodeInclusionProver,
			nodeBulletproof,
			nodeVerifiableEncryptor,
			nodeDecafConstructor,
			nodeCompiler,
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

		cleanup := func() {
			nodeDB.Close()
		}

		return engine, pubsub, globalTimeReel, cleanup
	}
	shards := make([][]shardNode, numShards)

	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		shards[shardIdx] = make([]shardNode, numNodesPerShard)

		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			nodeID := shardIdx*numNodesPerShard + nodeIdx
			engine, pubsub, _, cleanup := createAppNodeWithFactory(nodeID, shardAddresses[shardIdx], proverRegistry, proverKeys[nodeID], keyManagers[nodeID])
			defer cleanup()

			// Start with 0 peers for genesis initialization
			pubsub.peerCount = 0

			shards[shardIdx][nodeIdx] = shardNode{
				engine: engine,
				pubsub: pubsub,
			}
		}
	}

	// Connect nodes within each shard
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		pubsubs := make([]*mockAppIntegrationPubSub, numNodesPerShard)
		for i := 0; i < numNodesPerShard; i++ {
			pubsubs[i] = shards[shardIdx][i].pubsub
		}
		connectAppNodes(pubsubs...)
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
			node := shards[shardIdx][nodeIdx]

			// Start engine
			node.engine.Start(quits[shardIdx][nodeIdx])

			// Wait for sync
			time.Sleep(1 * time.Second)
		}
	}

	// Let shards synchronize
	time.Sleep(5 * time.Second)

	// Now ensure normal operation with higher peer count
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			shards[shardIdx][nodeIdx].pubsub.peerCount = 10
		}
	}

	// Send messages to different shards
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		messageBitmask := make([]byte, len(shardAddresses[shardIdx])+1)
		messageBitmask[0] = 0x01
		copy(messageBitmask[1:], shardAddresses[shardIdx])
		node := shards[shardIdx][0]

		// Send shard-specific messages
		for i := 0; i < 3; i++ {
			msg := &protobufs.Message{
				Hash:    []byte(fmt.Sprintf("shard-%d-msg-%d", shardIdx, i)),
				Payload: []byte(fmt.Sprintf("shard %d payload %d", shardIdx, i)),
			}

			msgData, err := proto.Marshal(msg)
			require.NoError(t, err)

			// Send to first node in shard
			shards[shardIdx][0].pubsub.PublishToBitmask(node.engine.getConsensusMessageBitmask(), msgData)
		}
	}

	// Let system run
	time.Sleep(10 * time.Second)

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

	// Stop all nodes
	for shardIdx := 0; shardIdx < numShards; shardIdx++ {
		for nodeIdx := 0; nodeIdx < numNodesPerShard; nodeIdx++ {
			node := shards[shardIdx][nodeIdx]

			// Stop engine
			node.engine.Stop(false)
		}
	}
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
		globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)
		require.NoError(t, err)

		appTimeReel, err := consensustime.NewAppTimeReel(logger, appAddress, proverRegistry, clockStore)
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
		pubsubs[i] = newMockAppIntegrationPubSub(peerID)
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
					Network:               99,
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

		engines[i] = engine
		quits[i] = make(chan struct{})
	}

	// Wire up all pubsubs to each other
	for i := 0; i < numNodes; i++ {
		pubsubs[i].mu.Lock()
		for j := 0; j < numNodes; j++ {
			if i != j {
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

	pubsub := newMockAppIntegrationPubSub(peerID)
	// Start with 0 peers to trigger genesis initialization
	pubsub.peerCount = 0

	// Create global time reel (needed for app consensus)
	globalTimeReel, err := consensustime.NewGlobalTimeReel(logger, proverRegistry, clockStore, 99, true)
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
				Network:               99,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		},
		pubsub,
		hg,
		keyManager,
		keyStore,
		clockStore,
		inboxStore,
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
