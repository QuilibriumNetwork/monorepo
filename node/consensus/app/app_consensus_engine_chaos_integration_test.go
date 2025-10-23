//go:build integrationtest
// +build integrationtest

package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p"
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
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/fees"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/provers"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/registration"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	consensustime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/validator"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// TestAppConsensusEngine_Integration_ChaosScenario tests all scenarios in a long-running chaos test
// This test is marked to be skipped in CI/CD due to its long execution time
func TestAppConsensusEngine_Integration_ChaosScenario(t *testing.T) {
	// Skip this test if SHORT flag is set (for CI/CD)
	if testing.Short() {
		t.Skip("Skipping chaos scenario test in short mode")
	}

	// Also skip if SKIP_CHAOS_TEST env var is set
	if os.Getenv("SKIP_CHAOS_TEST") != "" {
		t.Skip("Skipping chaos scenario test due to SKIP_CHAOS_TEST env var")
	}

	var seed int64

	if os.Getenv("CHAOS_SEED") != "" {
		var err error
		seed, err = strconv.ParseInt(os.Getenv("CHAOS_SEED"), 10, 0)
		if err != nil {
			panic(err)
		}

	} else {
		seed = time.Now().UnixMilli()
	}

	random := rand.New(rand.NewSource(seed))

	// Scenario: Comprehensive chaos testing with all scenarios
	// Expected: System maintains consensus despite chaos
	t.Log("=========================================")
	t.Log("CHAOS SCENARIO TEST - LONG RUNNING")
	t.Log("Target: 1080+ frames with random scenarios")
	t.Logf("Seed: %d", seed)
	t.Log("=========================================")

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test configuration
	const (
		numNodes                = 8
		targetFrames            = 1080
		feeVotingInterval       = 360
		maxFramesPerScenario    = 100
		partitionProbability    = 0.1
		equivocationProbability = 0.1
	)

	t.Log("Step 1: Setting up chaos test environment")
	t.Logf("  - Number of nodes: %d", numNodes)
	t.Logf("  - Target frames: %d", targetFrames)
	t.Logf("  - Fee voting interval: %d frames", feeVotingInterval)

	// Scenario types
	type ScenarioType int
	const (
		ScenarioBasicProgression ScenarioType = iota
		ScenarioFeeVoting
		ScenarioMessageFlow
		ScenarioNetworkPartition
		ScenarioEquivocation
		ScenarioGlobalEvents
		ScenarioStateRewind
	)

	scenarioNames := map[ScenarioType]string{
		ScenarioBasicProgression: "Basic Progression",
		ScenarioFeeVoting:        "Fee Voting",
		ScenarioMessageFlow:      "Message Flow",
		ScenarioNetworkPartition: "Network Partition",
		ScenarioEquivocation:     "Equivocation Attempt",
		ScenarioGlobalEvents:     "Global Events",
		ScenarioStateRewind:      "State Rewind",
	}

	appAddress := token.QUIL_TOKEN_ADDRESS

	// Create nodes
	type chaosNode struct {
		engine         *AppConsensusEngine
		pubsub         *mockAppIntegrationPubSub
		globalTimeReel *consensustime.GlobalTimeReel
		executors      map[string]*mockIntegrationExecutor
		frameHistory   []*protobufs.AppShardFrame
		quit           chan struct{}
		mu             sync.RWMutex
		gsc            *mockGlobalClientLocks
	}

	nodes := make([]*chaosNode, numNodes)

	// Create shared key manager and prover keys for all nodes
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	keyManagers := make([]tkeys.KeyManager, numNodes)
	proverKeys := make([][]byte, numNodes)
	signerSet := make([]crypto.Signer, numNodes)

	var err error
	for i := 0; i < numNodes; i++ {
		keyManagers[i] = keys.NewInMemoryKeyManager(bc, dc)
		pk, _, err := keyManagers[i].CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		signerSet[i] = pk
		proverKeys[i] = pk.Public().([]byte)
	}

	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {}
	logger, _ := cfg.Build()

	// Create a shared hypergraph and prover registry for all nodes
	sharedDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_chaos__shared"}, 0)
	defer sharedDB.Close()

	sharedInclusionProver := bls48581.NewKZGInclusionProver(logger)
	sharedVerifiableEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)
	sharedHypergraphStore := store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/app_chaos__shared"}, sharedDB, logger, sharedVerifiableEncryptor, sharedInclusionProver)
	sharedHg := hypergraph.NewHypergraph(logger, sharedHypergraphStore, sharedInclusionProver, []int{}, &tests.Nopthenticator{})
	proverRegistry, err := provers.NewProverRegistry(logger, sharedHg)
	require.NoError(t, err)

	// Register all provers with the app shard filter
	for i, proverKey := range proverKeys {
		proverAddress := calculateProverAddress(proverKey)
		registerProverInHypergraphWithFilter(t, sharedHg, proverKey, proverAddress, appAddress)
		t.Logf("  - Registered prover %d with address: %x for shard: %x", i, proverAddress, appAddress)
	}

	// Refresh the prover registry to pick up the newly added provers
	err = proverRegistry.Refresh()
	require.NoError(t, err)

	t.Log("Step 2: Creating chaos test nodes with engine using factory")

	_, m, cleanup := tests.GenerateSimnetHosts(t, numNodes, []libp2p.Option{})
	defer cleanup()

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
	// Helper to create node using factory
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
		nodeShardsStore := store.NewPebbleShardsStore(nodeDB, logger)
		nodeHg := hypergraph.NewHypergraph(logger, nodeHypergraphStore, nodeInclusionProver, []int{}, &tests.Nopthenticator{})

		// Create mock pubsub for network simulation
		pubsub := newMockAppIntegrationPubSub(c, logger, []byte(m.Nodes[nodeIdx].ID()), m.Nodes[nodeIdx], m.Keys[nodeIdx], m.Nodes)

		// Aside from pubsub, the rest should be concrete instances
		conf := &config.Config{
			Engine: &config.EngineConfig{
				Difficulty:   80000,
				ProvingKeyId: "q-prover-key",
			},
			P2P: &config.P2PConfig{
				Network:               1,
				StreamListenMultiaddr: "/ip4/0.0.0.0/tcp/0",
			},
		}

		// Create frame prover using the concrete implementation
		frameProver := vdf.NewWesolowskiFrameProver(logger)

		// Create signer registry using the concrete implementation
		signerRegistry, err := registration.NewCachedSignerRegistry(nodeKeyStore, keyManager, &bls48581.Bls48581KeyConstructor{}, bulletproofs.NewBulletproofProver(), logger)
		require.NoError(t, err)

		dynamicFeeManager := fees.NewDynamicFeeManager(logger, nodeInclusionProver)
		frameValidator := validator.NewBLSAppFrameValidator(proverRegistry, bc, frameProver, logger)
		globalFrameValidator := validator.NewBLSGlobalFrameValidator(proverRegistry, bc, frameProver, logger)
		difficultyAdjuster := difficulty.NewAsertDifficultyAdjuster(244200, time.Now().UnixMilli(), 160000)
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
			bulletproofs.NewBulletproofProver(),
			nodeVerifiableEncryptor,
			&bulletproofs.Decaf448KeyConstructor{},
			compiler.NewBedlamCompiler(),
			signerRegistry,
			proverRegistry,
			p2p.NewInMemoryPeerInfoManager(logger),
			dynamicFeeManager,
			frameValidator,
			globalFrameValidator,
			difficultyAdjuster,
			rewardIssuance,
			&bls48581.Bls48581KeyConstructor{},
			channel.NewDoubleRatchetEncryptedChannel(),
		)

		// Create global time reel
		globalTimeReel, err := factory.CreateGlobalTimeReel()
		if err != nil {
			panic(fmt.Sprintf("failed to create global time reel: %v", err))
		}

		// Create engine using factory
		engine, err := factory.CreateAppConsensusEngine(
			appAddress,
			0, // coreId
			globalTimeReel,
			nil,
		)
		if err != nil {
			panic(fmt.Sprintf("failed to create engine: %v", err))
		}

		cleanup := func() {
			nodeDB.Close()
		}
		mockGSC := &mockGlobalClientLocks{}
		engine.SetGlobalClient(mockGSC)

		return engine, pubsub, globalTimeReel, cleanup
	}

	for i := 0; i < numNodes; i++ {
		engine, pubsub, globalTimeReel, cleanup := createAppNodeWithFactory(i, appAddress, proverRegistry, proverKeys[i], keyManagers[i])
		defer cleanup()

		// Start with 0 peers for genesis
		pubsub.peerCount = 0

		node := &chaosNode{
			engine:         engine,
			pubsub:         pubsub,
			globalTimeReel: globalTimeReel,
			executors:      make(map[string]*mockIntegrationExecutor),
			frameHistory:   make([]*protobufs.AppShardFrame, 0),
			quit:           make(chan struct{}),
			gsc:            &mockGlobalClientLocks{},
		}

		// ensure unique global service client per node
		node.engine.SetGlobalClient(node.gsc)

		// Subscribe to frames
		pubsub.Subscribe(engine.getConsensusMessageBitmask(), func(message *pb.Message) error {
			frame := &protobufs.AppShardFrame{}
			if err := frame.FromCanonicalBytes(message.Data); err == nil {
				node.mu.Lock()
				node.frameHistory = append(node.frameHistory, frame)
				node.mu.Unlock()
			}
			return nil
		})

		nodes[i] = node
		t.Logf("  - Created node %d with factory", i)
	}

	// Connect all nodes initially
	t.Log("Step 3: Connecting nodes in full mesh")
	pubsubs := make([]*mockAppIntegrationPubSub, numNodes)
	for i := 0; i < numNodes; i++ {
		pubsubs[i] = nodes[i].pubsub
	}
	connectAppNodes(pubsubs...)

	// Start all nodes
	t.Log("Step 4: Starting all nodes")
	for _, node := range nodes {
		node.engine.Start(node.quit)
	}

	// Wait for genesis
	t.Log("Step 5: Waiting for genesis initialization")
	time.Sleep(3 * time.Second)

	// Increase peer count
	for _, node := range nodes {
		node.pubsub.peerCount = numNodes - 1
	}

	// Pre-generate valid payloads and stash for broadcast; commit initial world state for verification
	// Create per-node hypergraphs slice to feed payload creation
	hgs := make([]thypergraph.Hypergraph, 0, numNodes)
	for _, node := range nodes {
		hgs = append(hgs, node.engine.hypergraph)
	}

	t.Logf("Step 5.a: Generating 6,000 pending transactions")
	pending := make([]*token.PendingTransaction, 0, 6)
	for i := 0; i < 6; i++ {
		for j := 0; j < 1000; j++ {
			tx := createValidPendingTxPayload(t, hgs, keys.NewInMemoryKeyManager(bc, dc), byte(i))
			pending = append(pending, tx)
		}
	}

	t.Logf("Step 5.b: Sealing world state at genesis")
	// Seal initial world state for reference in verification
	for _, hg := range hgs {
		hg.Commit(0)
	}

	// Encode payloads as MessageBundle and stash
	stashedPayloads := make([][]byte, 0, len(pending))
	for _, tx := range pending {
		require.NoError(t, tx.Prove(0))
		req := &protobufs.MessageBundle{
			Requests: []*protobufs.MessageRequest{
				{Request: &protobufs.MessageRequest_PendingTransaction{PendingTransaction: tx.ToProtobuf()}},
			},
			Timestamp: time.Now().UnixMilli(),
		}
		out, err := req.ToCanonicalBytes()
		require.NoError(t, err)
		stashedPayloads = append(stashedPayloads, out)
	}

	// Record hashes into each node's global service client for lock checks
	for _, node := range nodes {
		for _, payload := range stashedPayloads {
			h := sha3.Sum256(payload)
			node.gsc.hashes = append(node.gsc.hashes, h[:])
			node.gsc.committed = true
		}
	}

	// Chaos test state
	type chaosState struct {
		currentFrameNumber uint64
		partitionedNodes   map[int]bool
		feeVoteHistory     []uint64
		scenarioHistory    []ScenarioType
		errorCount         int
		rewindCount        int
		mu                 sync.RWMutex
	}

	state := &chaosState{
		partitionedNodes: make(map[int]bool),
		feeVoteHistory:   make([]uint64, 0),
		scenarioHistory:  make([]ScenarioType, 0),
	}

	// Helper to get current consensus frame number
	getCurrentFrameNumber := func() uint64 {
		// For , we need to check the frame store
		type frameInfo struct {
			nodeId      int
			frameNumber uint64
			output      []byte
			prover      []byte
		}

		activeFrames := make([]frameInfo, 0)
		for i, node := range nodes {
			if !state.partitionedNodes[i] {
				// Access the frame store directly
				var maxFrame *protobufs.AppShardFrame
				frame := node.engine.GetFrame()
				maxFrame = frame

				if maxFrame != nil && maxFrame.Header != nil {
					activeFrames = append(activeFrames, frameInfo{
						nodeId:      i,
						frameNumber: maxFrame.Header.FrameNumber,
						output:      maxFrame.Header.Output,
						prover:      maxFrame.Header.Prover,
					})
				}
			}
		}

		if len(activeFrames) == 0 {
			return 0
		}

		// Group by matching content (output + prover)
		contentGroups := make(map[string][]frameInfo)
		for _, fi := range activeFrames {
			var key string
			if fi.frameNumber == 0 {
				key = string(fi.output)
			} else {
				key = string(fi.output) + string(fi.prover)
			}
			contentGroups[key] = append(contentGroups[key], fi)
		}

		// Find the largest group (consensus)
		var maxGroup []frameInfo
		var maxFrame uint64
		for _, group := range contentGroups {
			if len(group) >= len(maxGroup) {
				maxGroup = group
				if len(group) > 0 {
					if group[0].frameNumber > maxFrame {
						maxFrame = group[0].frameNumber
					}
				}
			}
		}

		t.Logf("  [Frame Check] Consensus frame: %d (from %d/%d nodes with matching content)",
			maxFrame, len(maxGroup), len(activeFrames))

		// Log if there's divergence
		if len(contentGroups) > 7 {
			t.Logf("    - WARNING: Content divergence detected! %d different frame contents", len(contentGroups))
		}

		return maxFrame
	}

	// Scenario implementations
	runBasicProgression := func(frames int) {
		t.Logf("  [Scenario] Basic Progression for %d frames", frames)
		startFrame := getCurrentFrameNumber()
		endTime := time.Now().Add(time.Duration(frames) * 10 * time.Second)

		for time.Now().Before(endTime) {
			currentFrame := getCurrentFrameNumber()
			if currentFrame >= startFrame+uint64(frames) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		finalFrame := getCurrentFrameNumber()
		t.Logf("    - Progressed from frame %d to %d", startFrame, finalFrame)
	}

	runFeeVoting := func() {
		t.Log("  [Scenario] Fee Voting Mechanics")

		// Check current fee votes
		for i, node := range nodes {
			if !state.partitionedNodes[i] {
				if voteHistory, err := node.engine.GetDynamicFeeManager().GetVoteHistory(appAddress); err == nil {
					t.Logf("    - Node %d has %d fee votes", i, len(voteHistory))
				}
			}
		}

		// Let voting continue
		time.Sleep(5 * time.Second)
	}

	runMessageFlow := func() {
		t.Log("  [Scenario] Message Flow Test")

		messageBitmask := make([]byte, len(appAddress)+1)
		messageBitmask[0] = 0x01
		copy(messageBitmask[1:], appAddress)

		// Broadcast pre-generated valid payloads to ensure end-to-end processing
		sent := 0
		for _, payload := range stashedPayloads {
			// Pick random non-partitioned node to send from
			for j, node := range nodes {
				if !state.partitionedNodes[j] {
					node.pubsub.PublishToBitmask(node.engine.getProverMessageBitmask(), payload)
					sent++
					break
				}
			}
		}

		t.Logf("    - Sent %d stashed valid payloads", sent)
		time.Sleep(3 * time.Second)
	}

	runNetworkPartition := func() {
		t.Log("  [Scenario] Network Partition")

		// Partition 1-2 nodes
		partitionSize := random.Intn(2) + 1
		partitioned := make([]int, 0)

		// Clear existing partitions first
		for i := range state.partitionedNodes {
			delete(state.partitionedNodes, i)
		}

		// Reconnect all nodes
		connectAppNodes(pubsubs...)

		// Create new partition
		for i := 0; i < partitionSize && i < numNodes/2; i++ {
			nodeIdx := i
			state.partitionedNodes[nodeIdx] = true
			partitioned = append(partitioned, nodeIdx)

			// Disconnect from others
			for j := 0; j < numNodes; j++ {
				if i != j {
					nodes[nodeIdx].pubsub.mu.Lock()
					nodes[j].pubsub.mu.Lock()
					delete(nodes[nodeIdx].pubsub.networkPeers, string(nodes[j].pubsub.peerID))
					delete(nodes[j].pubsub.networkPeers, string(nodes[nodeIdx].pubsub.peerID))
					nodes[j].pubsub.mu.Unlock()
					nodes[nodeIdx].pubsub.mu.Unlock()
				}
			}
		}

		t.Logf("    - Partitioned nodes: %v", partitioned)

		// Let partition persist
		duration := time.Duration(random.Intn(10)+5) * time.Second
		t.Logf("    - Partition duration: %v", duration)
		time.Sleep(duration)

		// Heal partition
		t.Log("    - Healing partition")
		for i := range state.partitionedNodes {
			delete(state.partitionedNodes, i)
		}
		connectAppNodes(pubsubs...)

		// Allow recovery
		time.Sleep(5 * time.Second)
	}

	runEquivocation := func() {
		frames := random.Intn(maxFramesPerScenario) + 1
		t.Logf("  [Scenario] Equivocation Attempts for %d frames", frames)

		// Pick a node to attempt equivocation
		nodeIdx := random.Intn(2)

		startFrame := getCurrentFrameNumber()
		endTime := time.Now().Add(time.Duration(frames) * 2 * time.Second)
		equivocationCount := 0

		for time.Now().Before(endTime) {
			currentFrame := getCurrentFrameNumber()
			if currentFrame >= startFrame+uint64(frames) {
				break
			}

			// The state machine will handle equivocation detection
			// We can simulate by trying to send conflicting votes
			if currentFrame > 0 {
				nodes[nodeIdx].engine.frameStoreMu.Lock()
				for _, frame := range nodes[nodeIdx].engine.frameStore {
					if frame.Header.FrameNumber > currentFrame {
						// Get signing key
						signer, _, publicKey, _ := nodes[nodeIdx].engine.GetProvingKey(
							nodes[nodeIdx].engine.config.Engine,
						)
						if publicKey == nil {
							break
						}

						// Create vote (signature)
						signatureData, err := nodes[nodeIdx].engine.frameProver.GetFrameSignaturePayload(
							frame.Header,
						)
						if err != nil {
							break
						}

						sig, err := signer.SignWithDomain(
							signatureData,
							append([]byte("shard"), nodes[nodeIdx].engine.appAddress...),
						)
						if err != nil {
							break
						}

						// Get our voter address
						voterAddress := nodes[nodeIdx].engine.getAddressFromPublicKey(publicKey)

						// Create vote message
						vote := &protobufs.FrameVote{
							FrameNumber: frame.Header.FrameNumber,
							Proposer:    frame.Header.Prover,
							Approve:     true,
							PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
								Address:   voterAddress,
								Signature: sig,
							},
						}

						// Serialize and publish
						data, err := vote.ToCanonicalBytes()
						if err != nil {
							break
						}

						if err := nodes[nodeIdx].engine.pubsub.PublishToBitmask(
							nodes[nodeIdx].engine.getConsensusMessageBitmask(),
							data,
						); err != nil {
							nodes[nodeIdx].engine.logger.Error("failed to publish vote", zap.Error(err))
						}
						break
					}
				}
				nodes[nodeIdx].engine.frameStoreMu.Unlock()
				equivocationCount++
				state.rewindCount++
			}

			// Wait between attempts
			time.Sleep(time.Duration(500+random.Intn(1500)) * time.Millisecond)
		}

		finalFrame := getCurrentFrameNumber()
		t.Logf("    - Node %d attempted %d equivocations from frame %d to %d",
			nodeIdx, equivocationCount, startFrame, finalFrame)
	}

	runGlobalEvents := func() {
		t.Log("  [Scenario] Global Events Simulation")

		// Simulate halt scenario
		for _, n := range nodes {
			n.engine.eventDistributor.Publish(tconsensus.ControlEvent{
				Type: tconsensus.ControlEventHalt,
			})
		}
		time.Sleep(time.Duration(random.Intn(60)) * time.Second)

		// Simulate resume
		for _, n := range nodes {
			n.engine.eventDistributor.Publish(tconsensus.ControlEvent{
				Type: tconsensus.ControlEventResume,
			})
		}

		t.Log("    - Simulated global event impact")
	}

	runStateRewind := func() {
		frames := random.Intn(maxFramesPerScenario) + 1
		t.Logf("  [Scenario] State Rewind Simulation for %d frames", frames)

		// State machine will handle rewinds automatically
		// We simulate this by creating temporary partitions

		startFrame := getCurrentFrameNumber()
		endTime := time.Now().Add(time.Duration(frames) * 2 * time.Second)
		rewindAttempts := 0

		for time.Now().Before(endTime) {
			currentFrame := getCurrentFrameNumber()
			if currentFrame >= startFrame+uint64(frames) {
				break
			}

			beforeFrame := getCurrentFrameNumber()

			// Create temporary partition to force divergence
			partitionSize := random.Intn(2) + 1
			partitioned := make([]int, 0)

			// Partition random nodes
			for i := 0; i < partitionSize; i++ {
				nodeIdx := i
				if !state.partitionedNodes[nodeIdx] {
					state.partitionedNodes[nodeIdx] = true
					partitioned = append(partitioned, nodeIdx)

					// Disconnect from others
					for j := 0; j < numNodes; j++ {
						if nodeIdx != j {
							nodes[nodeIdx].pubsub.mu.Lock()
							nodes[j].pubsub.mu.Lock()
							delete(nodes[nodeIdx].pubsub.networkPeers, string(nodes[j].pubsub.peerID))
							delete(nodes[j].pubsub.networkPeers, string(nodes[nodeIdx].pubsub.peerID))
							nodes[j].pubsub.mu.Unlock()
							nodes[nodeIdx].pubsub.mu.Unlock()
						}
					}
				}
			}

			// Let partition create divergence
			partitionDuration := time.Duration(random.Intn(3)+1) * time.Second
			time.Sleep(partitionDuration)

			// Heal partition
			for _, idx := range partitioned {
				delete(state.partitionedNodes, idx)
			}
			connectAppNodes(pubsubs...)

			// Check for rewind
			afterFrame := getCurrentFrameNumber()
			if afterFrame < beforeFrame {
				state.rewindCount++
				rewindAttempts++
				t.Logf("    - Rewind detected: %d -> %d", beforeFrame, afterFrame)
			}

			// Wait for stabilization
			time.Sleep(time.Duration(500+random.Intn(1000)) * time.Millisecond)
		}

		finalFrame := getCurrentFrameNumber()
		t.Logf("    - Completed %d rewind attempts from frame %d to %d",
			rewindAttempts, startFrame, finalFrame)
	}

	// Main chaos loop
	t.Log("Step 6: Starting chaos scenarios with engine")
	t.Log("========================================")

	startTime := time.Now()
	scenarioCount := 0
	lastFrameCheck := uint64(0)

	for getCurrentFrameNumber() < targetFrames {
		state.mu.Lock()
		currentFrame := getCurrentFrameNumber()
		state.currentFrameNumber = currentFrame
		state.mu.Unlock()

		// Progress check every 100 frames
		if currentFrame > lastFrameCheck+100 {
			elapsed := time.Since(startTime)
			framesPerSecond := float64(currentFrame) / elapsed.Seconds()
			estimatedCompletion := time.Duration(float64(targetFrames-currentFrame) / framesPerSecond * float64(time.Second))

			t.Logf("\n[Progress Report - Frame %d/%d]", currentFrame, targetFrames)
			t.Logf("  - Elapsed: %v", elapsed.Round(time.Second))
			t.Logf("  - Rate: %.2f frames/sec", framesPerSecond)
			t.Logf("  - ETA: %v", estimatedCompletion.Round(time.Second))
			t.Logf("  - Scenarios run: %d", scenarioCount)
			t.Logf("  - Rewinds: %d", state.rewindCount)
			t.Logf("  - Errors: %d\n", state.errorCount)

			lastFrameCheck = currentFrame
		}

		// Pick random scenario
		scenario := ScenarioType(random.Intn(8))

		// Override for fee voting interval
		if currentFrame > 0 && currentFrame%uint64(feeVotingInterval) == 0 {
			scenario = ScenarioFeeVoting
		}

		// Apply partition/equivocation probability
		if random.Float64() < partitionProbability {
			scenario = ScenarioNetworkPartition
		} else if random.Float64() < equivocationProbability {
			scenario = ScenarioEquivocation
		}

		t.Logf("\n[Frame %d] Running scenario: %s", currentFrame, scenarioNames[scenario])

		state.mu.Lock()
		state.scenarioHistory = append(state.scenarioHistory, scenario)
		state.mu.Unlock()

		// Execute scenario
		switch scenario {
		case ScenarioBasicProgression:
			frames := random.Intn(maxFramesPerScenario) + 1
			runBasicProgression(frames)

		case ScenarioFeeVoting:
			runFeeVoting()

		case ScenarioMessageFlow:
			runMessageFlow()

		case ScenarioNetworkPartition:
			runNetworkPartition()

		case ScenarioEquivocation:
			runEquivocation()

		case ScenarioGlobalEvents:
			runGlobalEvents()

		case ScenarioStateRewind:
			runStateRewind()
		}

		scenarioCount++

		// Brief pause between scenarios
		time.Sleep(time.Duration(random.Intn(1000)+500) * time.Millisecond)
	}

	// Final convergence check
	t.Log("\n========================================")
	t.Log("Step 7: Final convergence verification")

	// Ensure all partitions are healed
	for i := range state.partitionedNodes {
		delete(state.partitionedNodes, i)
	}
	connectAppNodes(pubsubs...)

	// Wait for final convergence
	t.Log("  - Waiting for final convergence...")
	time.Sleep(10 * time.Second)

	// Check final state - verify frame content matches
	type frameContent struct {
		frameNumber uint64
		output      []byte
		prover      []byte
	}

	finalFrames := make([]*frameContent, numNodes)
	for i, node := range nodes {
		// Get the latest frame from frame store
		frame := node.engine.GetFrame()
		var maxFrameNumber uint64
		var maxFrame *protobufs.AppShardFrame

		if frame.Header != nil && frame.Header.FrameNumber > maxFrameNumber {
			maxFrameNumber = frame.Header.FrameNumber
			maxFrame = frame
		}

		if maxFrame != nil && maxFrame.Header != nil {
			finalFrames[i] = &frameContent{
				frameNumber: maxFrame.Header.FrameNumber,
				output:      maxFrame.Header.Output,
				prover:      maxFrame.Header.Prover,
			}
		}
	}

	// Find consensus on frame content (same output/prover)
	// Group frames by matching content
	contentGroups := make(map[string][]*frameContent)
	for _, fc := range finalFrames {
		if fc == nil {
			continue
		}
		// Create a key from output+prover to group matching frames
		key := string(fc.output) + string(fc.prover)
		contentGroups[key] = append(contentGroups[key], fc)
	}

	// Find the group with most nodes (consensus)
	var consensusFrame uint64
	var maxCount int

	for _, group := range contentGroups {
		if len(group) >= maxCount {
			maxCount = len(group)
			if len(group) > 0 {
				if group[0].frameNumber > consensusFrame {
					consensusFrame = group[0].frameNumber
				}
			}
		}
	}

	t.Log("\nFinal Results:")
	t.Logf("  - Target frames: %d", targetFrames)
	t.Logf("  - Consensus frame: %d", consensusFrame)
	t.Logf("  - Nodes at consensus: %d/%d (matching content)", maxCount, numNodes)
	t.Logf("  - Content groups: %d", len(contentGroups))

	// Log details about non-consensus nodes
	if len(contentGroups) > 7 {
		t.Log("  - Frame divergence detected:")
		groupIdx := 0
		for _, group := range contentGroups {
			if len(group) > 0 {
				t.Logf("    - Group %d: %d nodes at frame %d, prover %x", groupIdx, len(group), group[0].frameNumber, group[0].prover)
				groupIdx++
			}
		}
	}

	t.Logf("  - Total scenarios: %d", scenarioCount)
	t.Logf("  - Total rewinds: %d", state.rewindCount)
	t.Logf("  - Total duration: %v", time.Since(startTime).Round(time.Second))

	// Verify consensus
	assert.GreaterOrEqual(t, consensusFrame, uint64(targetFrames), "Should reach target frames")
	assert.GreaterOrEqual(t, maxCount, (numNodes+1)/2, "Majority should be at consensus")

	// Scenario distribution
	t.Log("\nScenario Distribution:")
	scenarioCounts := make(map[ScenarioType]int)
	for _, s := range state.scenarioHistory {
		scenarioCounts[s]++
	}
	for scenario, count := range scenarioCounts {
		t.Logf("  - %s: %d times", scenarioNames[scenario], count)
	}

	// Stop all nodes
	t.Log("\nStep 8: Cleanup")
	for i, node := range nodes {
		// Unregister executors
		node.mu.RLock()
		for name := range node.executors {
			node.engine.UnregisterExecutor(name, 0, true)
		}
		node.mu.RUnlock()

		// Stop engine
		node.engine.Stop(true)
		close(node.quit)
		t.Logf("  - Stopped node %d", i)
	}

	t.Log("\n========================================")
	t.Log("CHAOS SCENARIO TEST COMPLETED")
	t.Log("========================================")
}
