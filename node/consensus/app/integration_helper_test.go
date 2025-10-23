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
	"math/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qp2p "source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// mockAppIntegrationPubSub extends the basic mock with app-specific features
type mockAppIntegrationPubSub struct {
	mock.Mock
	mu                   sync.RWMutex
	subscribers          map[string][]func(message *pb.Message) error
	validators           map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult
	peerID               []byte
	peerCount            int
	networkPeers         map[string]*mockAppIntegrationPubSub
	messageLog           []messageRecord            // Track all messages for debugging
	frames               []*protobufs.AppShardFrame // Store frames for sync
	underlyingHost       host.Host
	underlyingBlossomSub *qp2p.BlossomSub
}

// GetOwnMultiaddrs implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetOwnMultiaddrs() []multiaddr.Multiaddr {
	panic("unimplemented")
}

// AddPeerScore implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) AddPeerScore(peerId []byte, scoreDelta int64) {
	panic("unimplemented")
}

// Bootstrap implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) Bootstrap(ctx context.Context) error {
	panic("unimplemented")
}

// DiscoverPeers implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) DiscoverPeers(ctx context.Context) error {
	panic("unimplemented")
}

// GetDirectChannel implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetDirectChannel(ctx context.Context, peerId []byte, purpose string) (*grpc.ClientConn, error) {
	panic("unimplemented")
}

// GetMultiaddrOfPeer implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetMultiaddrOfPeer(peerId []byte) string {
	panic("unimplemented")
}

// GetMultiaddrOfPeerStream implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetMultiaddrOfPeerStream(ctx context.Context, peerId []byte) <-chan multiaddr.Multiaddr {
	panic("unimplemented")
}

// GetNetwork implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetNetwork() uint {
	panic("unimplemented")
}

// GetNetworkPeersCount implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetNetworkPeersCount() int {
	panic("unimplemented")
}

// GetPeerScore implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetPeerScore(peerId []byte) int64 {
	panic("unimplemented")
}

// GetPublicKey implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetPublicKey() []byte {
	panic("unimplemented")
}

// GetRandomPeer implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) GetRandomPeer(bitmask []byte) ([]byte, error) {
	panic("unimplemented")
}

// IsPeerConnected implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) IsPeerConnected(peerId []byte) bool {
	panic("unimplemented")
}

// Publish implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) Publish(address []byte, data []byte) error {
	panic("unimplemented")
}

// Reachability implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) Reachability() *wrapperspb.BoolValue {
	panic("unimplemented")
}

// Reconnect implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) Reconnect(peerId []byte) error {
	panic("unimplemented")
}

// SetPeerScore implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) SetPeerScore(peerId []byte, score int64) {
	panic("unimplemented")
}

// SignMessage implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) SignMessage(msg []byte) ([]byte, error) {
	panic("unimplemented")
}

// StartDirectChannelListener implements p2p.PubSub.
func (m *mockAppIntegrationPubSub) StartDirectChannelListener(key []byte, purpose string, server *grpc.Server) error {
	panic("unimplemented")
}

type messageRecord struct {
	timestamp time.Time
	from      []byte
	to        []byte
	data      []byte
}

func newMockAppIntegrationPubSub(config *config.Config, logger *zap.Logger, peerID []byte, host host.Host, privKey pcrypto.PrivKey, bootstrapHosts []host.Host) *mockAppIntegrationPubSub {
	blossomSub := qp2p.NewBlossomSubWithHost(config.P2P, config.Engine, logger, 1, true, host, privKey, bootstrapHosts)

	return &mockAppIntegrationPubSub{
		subscribers:          make(map[string][]func(message *pb.Message) error),
		validators:           make(map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult),
		peerID:               peerID,
		peerCount:            10,
		networkPeers:         make(map[string]*mockAppIntegrationPubSub),
		messageLog:           make([]messageRecord, 0),
		frames:               make([]*protobufs.AppShardFrame, 0),
		underlyingHost:       host,
		underlyingBlossomSub: blossomSub,
	}
}

func (m *mockAppIntegrationPubSub) Subscribe(bitmask []byte, handler func(message *pb.Message) error) error {
	m.mu.Lock()
	key := string(bitmask)
	m.subscribers[key] = append(m.subscribers[key], handler)
	m.mu.Unlock()
	return m.underlyingBlossomSub.Subscribe(bitmask, handler)
}

func (m *mockAppIntegrationPubSub) PublishToBitmask(bitmask []byte, data []byte) error {
	m.mu.Lock()
	m.messageLog = append(m.messageLog, messageRecord{
		timestamp: time.Now(),
		from:      m.peerID,
		to:        bitmask,
		data:      data,
	})

	// If this is an app frame, store it for sync
	if len(bitmask) >= 4 && bitmask[0] != 0x01 { // Not a message bitmask
		// Check if data is long enough to contain type prefix
		if len(data) >= 4 {
			// Read type prefix from first 4 bytes
			typePrefix := binary.BigEndian.Uint32(data[:4])
			if typePrefix == protobufs.AppShardFrameType {
				frame := &protobufs.AppShardFrame{}
				if err := frame.FromCanonicalBytes(data); err == nil {
					m.frames = append(m.frames, frame)
				}
			}
		}
	}
	m.mu.Unlock()

	return m.underlyingBlossomSub.PublishToBitmask(bitmask, data)
}

// func (m *mockAppIntegrationPubSub) receiveFromNetwork(bitmask []byte, message *pb.Message) {
// 	m.mu.RLock()
// 	validator := m.validators[string(bitmask)]
// 	m.mu.RUnlock()

// 	if validator != nil {
// 		result := validator(peer.ID(message.From), message)
// 		if result != p2p.ValidationResultAccept {
// 			// Log validation rejection for debugging
// 			if len(message.Data) >= 4 {
// 				typePrefix := binary.BigEndian.Uint32(message.Data[:4])
// 				if typePrefix == protobufs.AppShardFrameType {
// 					frame := &protobufs.AppShardFrame{}
// 					if err := frame.FromCanonicalBytes(message.Data); err == nil && frame.Header != nil {
// 						fmt.Printf("DEBUG: Node %x rejected frame %d from %x (validation result: %v)\n",
// 							m.peerID[:4], frame.Header.FrameNumber, message.From[:4], result)
// 					}
// 				}
// 			}
// 			return
// 		}
// 	}

// 	m.mu.RLock()
// 	handlers := m.subscribers[string(bitmask)]
// 	m.mu.RUnlock()

// 	for _, handler := range handlers {
// 		go handler(message) // Make async to match PublishToBitmask behavior
// 	}
// }

func (m *mockAppIntegrationPubSub) RegisterValidator(bitmask []byte, validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult, sync bool) error {
	m.mu.Lock()
	m.validators[string(bitmask)] = validator
	m.mu.Unlock()
	m.underlyingBlossomSub.RegisterValidator(bitmask, validator, sync)
	return nil
}

func (m *mockAppIntegrationPubSub) GetPeerstoreCount() int {
	return m.peerCount
}

func (m *mockAppIntegrationPubSub) GetPeerID() []byte {
	return m.peerID
}

func (m *mockAppIntegrationPubSub) Unsubscribe(bitmask []byte, raw bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subscribers, string(bitmask))
}

func (m *mockAppIntegrationPubSub) UnregisterValidator(bitmask []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.validators, string(bitmask))
	return nil
}

func (m *mockAppIntegrationPubSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	return &protobufs.NetworkInfoResponse{}
}

type ExecutorState int

const (
	ExecutorStateStopped ExecutorState = iota
	ExecutorStateRunning
)

// mockExecutor for integration testing
type mockIntegrationExecutor struct {
	mock.Mock
	name     string
	state    ExecutorState
	messages []*protobufs.Message
	mu       sync.RWMutex
	eventCh  <-chan consensus.ControlEvent
}

// Prove implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) Prove(domain []byte, frameNumber uint64, message []byte) (*protobufs.MessageRequest, error) {
	panic("unimplemented")
}

// GetCost implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetCost(message []byte) (*big.Int, error) {
	panic("unimplemented")
}

// AnnounceProverJoin implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) AnnounceProverJoin() {
	panic("unimplemented")
}

// GetBulletproofProver implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetBulletproofProver() crypto.BulletproofProver {
	panic("unimplemented")
}

// GetDecafConstructor implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetDecafConstructor() crypto.DecafConstructor {
	panic("unimplemented")
}

// GetFrameHeader implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetFrameHeader() *protobufs.FrameHeader {
	panic("unimplemented")
}

func (m *mockIntegrationExecutor) GetCapabilities() []*protobufs.Capability {
	panic("unimplemented")
}

// GetGlobalFrameHeader implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetGlobalFrameHeader() *protobufs.GlobalFrameHeader {
	panic("unimplemented")
}

// GetHypergraph implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetHypergraph() thypergraph.Hypergraph {
	panic("unimplemented")
}

// GetInclusionProver implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetInclusionProver() crypto.InclusionProver {
	panic("unimplemented")
}

// GetPeerInfo implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetPeerInfo() *protobufs.PeerInfoResponse {
	panic("unimplemented")
}

// GetRingPosition implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetRingPosition() int {
	panic("unimplemented")
}

// GetSeniority implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetSeniority() *big.Int {
	panic("unimplemented")
}

// GetVerifiableEncryptor implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetVerifiableEncryptor() crypto.VerifiableEncryptor {
	panic("unimplemented")
}

// GetWorkerCount implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) GetWorkerCount() uint32 {
	panic("unimplemented")
}

// ValidateMessage implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) ValidateMessage(frameNumber uint64, address []byte, message []byte) error {
	// Simply accept the message for processing
	return nil
}

// ProcessMessage implements execution.ShardExecutionEngine.
func (m *mockIntegrationExecutor) ProcessMessage(frameNumber uint64, feeMultiplier *big.Int, address []byte, message []byte, state state.State) (*execution.ProcessMessageResult, error) {
	// Simply accept the message for processing
	return nil, nil
}

func newMockIntegrationExecutor(name string) *mockIntegrationExecutor {
	return &mockIntegrationExecutor{
		name:     name,
		state:    ExecutorStateStopped,
		messages: make([]*protobufs.Message, 0),
	}
}

func (m *mockIntegrationExecutor) GetName() string {
	return m.name
}

func (m *mockIntegrationExecutor) GetState() ExecutorState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *mockIntegrationExecutor) Start() <-chan error {
	m.mu.Lock()
	m.state = ExecutorStateRunning
	m.mu.Unlock()

	// Process events
	go func() {
		for {
			time.Sleep(10 * time.Millisecond)
			// Generate some messages
			m.mu.Lock()
			m.messages = append(m.messages, &protobufs.Message{
				Hash:    []byte(fmt.Sprintf("msg-%s-%d", m.name, len(m.messages))),
				Payload: []byte("test message"),
			})
			m.mu.Unlock()
		}
	}()

	return nil
}

func (m *mockIntegrationExecutor) Stop(force bool) <-chan error {
	errCh := make(chan error, 1)
	m.mu.Lock()
	m.state = ExecutorStateStopped
	m.mu.Unlock()
	close(errCh)
	return errCh
}

func (m *mockIntegrationExecutor) CollectPendingMessages(maxMessages int) []*protobufs.Message {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.messages) == 0 {
		return nil
	}

	count := len(m.messages)
	if count > maxMessages {
		count = maxMessages
	}

	result := m.messages[:count]
	m.messages = m.messages[count:]
	return result
}

func connectAppNodes(pubsubs ...*mockAppIntegrationPubSub) {
	for i, p1 := range pubsubs {
		for j, p2 := range pubsubs {
			if i != j {
				p1.mu.Lock()
				p1.networkPeers[string(p2.peerID)] = p2
				p1.mu.Unlock()
			}
		}
	}
}

// calculateProverAddress calculates the prover address from public key using poseidon hash
func calculateProverAddress(publicKey []byte) []byte {
	hash, err := poseidon.HashBytes(publicKey)
	if err != nil {
		panic(err) // Should not happen in tests
	}
	return hash.FillBytes(make([]byte, 32))
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
	err = hg.AddVertex(txn, hypergraph.NewVertex([32]byte(fullAddress[:32]), [32]byte(fullAddress[32:]), commitment, big.NewInt(0)))
	if err != nil {
		t.Fatalf("Failed to add prover vertex to hypergraph: %v", err)
	}
	err = hg.AddVertex(txn, hypergraph.NewVertex([32]byte(fullAddress[:32]), [32]byte(allocationAddress[:]), allocCommitment, big.NewInt(0)))
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

type mockGlobalClientLocks struct {
	committed        bool
	hashes           [][]byte
	shardAddresses   map[string][][]byte
	shardAddressesMu sync.Mutex
}

func (m *mockGlobalClientLocks) GetGlobalFrame(ctx context.Context, in *protobufs.GetGlobalFrameRequest, opts ...grpc.CallOption) (*protobufs.GlobalFrameResponse, error) {
	return nil, errors.New("not used in this test")
}
func (m *mockGlobalClientLocks) GetAppShards(ctx context.Context, in *protobufs.GetAppShardsRequest, opts ...grpc.CallOption) (*protobufs.GetAppShardsResponse, error) {
	return nil, errors.New("not used in this test")
}
func (m *mockGlobalClientLocks) GetGlobalShards(ctx context.Context, in *protobufs.GetGlobalShardsRequest, opts ...grpc.CallOption) (*protobufs.GetGlobalShardsResponse, error) {
	return nil, errors.New("not used in this test")
}
func (m *mockGlobalClientLocks) GetLockedAddresses(ctx context.Context, in *protobufs.GetLockedAddressesRequest, opts ...grpc.CallOption) (*protobufs.GetLockedAddressesResponse, error) {
	out := &protobufs.GetLockedAddressesResponse{Transactions: []*protobufs.LockedTransaction{}}
	m.shardAddressesMu.Lock()
	hits := m.shardAddresses[string(in.ShardAddress)]
	for _, h := range hits {
		out.Transactions = append(out.Transactions, &protobufs.LockedTransaction{
			TransactionHash: h,
			Committed:       m.committed,
		})
	}
	m.shardAddressesMu.Unlock()
	return out, nil
}

func createValidPendingTxPayload(t *testing.T, hgs []thypergraph.Hypergraph, km *keys.InMemoryKeyManager, prefix byte) *token.PendingTransaction {
	// set this value so we skip cutover checks
	token.BEHAVIOR_PASS = true

	dc := &bulletproofs.Decaf448KeyConstructor{}
	vk, _ := dc.New()
	sk, _ := dc.New()
	rvk, _ := dc.New()
	rsk, _ := dc.New()

	out1, err := token.NewPendingTransactionOutput(big.NewInt(7), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := token.NewPendingTransactionOutput(big.NewInt(2), vk.Public(), sk.Public(), rvk.Public(), rsk.Public(), 0)
	if err != nil {
		t.Fatal(err)
	}

	bp := &bulletproofs.Decaf448BulletproofProver{}
	pvk, err := km.CreateAgreementKey("q-view-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)
	psk, err := km.CreateAgreementKey("q-spend-key", crypto.KeyTypeDecaf448)
	assert.NoError(t, err)

	// Control shard placement
	address1 := [64]byte{}
	copy(address1[:32], token.QUIL_TOKEN_ADDRESS)
	address1[32] = prefix
	rand.Read(address1[33:])
	address2 := [64]byte{}
	copy(address2[:32], token.QUIL_TOKEN_ADDRESS)
	address2[32] = prefix
	rand.Read(address2[33:])

	tree1 := &qcrypto.VectorCommitmentTree{}
	tree2 := &qcrypto.VectorCommitmentTree{}
	otk1, _ := dc.New()
	otk2, _ := dc.New()
	c1, _ := dc.New()
	c2, _ := dc.New()
	comm1 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(3)}, c1.Private())
	comm2 := bp.GenerateInputCommitmentsFromBig([]*big.Int{big.NewInt(9)}, c2.Private())
	mask1 := c1.Private()
	mask2 := c2.Private()
	a1, _ := otk1.AgreeWithAndHashToScalar(pvk.Public())
	a2, _ := otk2.AgreeWithAndHashToScalar(pvk.Public())

	blindMask1 := make([]byte, 56)
	coinMask1 := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a1.Public())
	shake.Read(blindMask1)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a1.Public())
	shake.Read(coinMask1)

	for i := range blindMask1 {
		mask1[i] ^= blindMask1[i]
	}
	maskedCoinBalanceBytes1 := make([]byte, 56)
	maskedCoinBalanceBytes1[0] = 0x03
	for i := range maskedCoinBalanceBytes1 {
		maskedCoinBalanceBytes1[i] ^= coinMask1[i]
	}
	blindMask2 := make([]byte, 56)
	coinMask2 := make([]byte, 56)
	shake = sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(a2.Public())
	shake.Read(blindMask2)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(a2.Public())
	shake.Read(coinMask2)

	for i := range blindMask2 {
		mask2[i] ^= blindMask2[i]
	}
	maskedCoinBalanceBytes2 := make([]byte, 56)
	maskedCoinBalanceBytes2[0] = 0x09
	for i := range maskedCoinBalanceBytes2 {
		maskedCoinBalanceBytes2[i] ^= coinMask2[i]
	}

	verifkey1, _ := a1.Add(psk.Public())
	tree1.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, 0), nil, big.NewInt(8))
	tree1.Insert([]byte{1 << 2}, comm1, nil, big.NewInt(56))
	tree1.Insert([]byte{2 << 2}, otk1.Public(), nil, big.NewInt(56))
	tree1.Insert([]byte{3 << 2}, verifkey1, nil, big.NewInt(56))
	tree1.Insert([]byte{4 << 2}, maskedCoinBalanceBytes1, nil, big.NewInt(56))
	tree1.Insert([]byte{5 << 2}, mask1, nil, big.NewInt(56))
	verifkey2, _ := a2.Add(psk.Public())
	tree2.Insert([]byte{0}, binary.BigEndian.AppendUint64(nil, 0), nil, big.NewInt(8))
	tree2.Insert([]byte{1 << 2}, comm2, nil, big.NewInt(56))
	tree2.Insert([]byte{2 << 2}, otk2.Public(), nil, big.NewInt(56))
	tree2.Insert([]byte{3 << 2}, verifkey2, nil, big.NewInt(56))
	tree2.Insert([]byte{4 << 2}, maskedCoinBalanceBytes2, nil, big.NewInt(56))
	tree2.Insert([]byte{5 << 2}, mask2, nil, big.NewInt(56))

	// qcrypto.DebugNonLazyNode(tree.Root, 0, "")
	typeAddr, _ := hex.DecodeString("096de9a09f693f92cfa9cf3349bab2b3baee09f3e4f9c596514ecb3e8b0dff8f")
	tree1.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	tree2.Insert(bytes.Repeat([]byte{0xff}, 32), typeAddr, nil, big.NewInt(32))
	for _, hg := range hgs {
		txn, _ := hg.NewTransaction(false)
		hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address1[32:]), tree1.Commit(hg.GetProver(), false), big.NewInt(55*26)))
		hg.SetVertexData(txn, address1, tree1)
		hg.AddVertex(txn, hypergraph.NewVertex([32]byte(token.QUIL_TOKEN_ADDRESS), [32]byte(address2[32:]), tree2.Commit(hg.GetProver(), false), big.NewInt(55*26)))
		hg.SetVertexData(txn, address2, tree2)
		err := txn.Commit()
		if err != nil {
			t.Fatal(err)
		}
	}

	// simulate input as commitment to total
	input1, _ := token.NewPendingTransactionInput(address1[:])
	input2, _ := token.NewPendingTransactionInput(address2[:])
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
	rdfMultiprover := schema.NewRDFMultiprover(parser, hgs[0].GetProver())

	tx := token.NewPendingTransaction(
		[32]byte(token.QUIL_TOKEN_ADDRESS),
		[]*token.PendingTransactionInput{input1, input2},
		[]*token.PendingTransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		hgs[0],
		bp,
		hgs[0].GetProver(),
		verenc.NewMPCitHVerifiableEncryptor(1),
		dc,
		keys.ToKeyRing(km, false),
		rdfSchema,
		rdfMultiprover,
	)

	return tx
}

func prepareRDFSchemaFromConfig(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) (string, error) {
	schema := generateRDFPrelude(appAddress, config)

	schema += "coin:Coin a rdfs:Class.\n" +
		"coin:FrameNumber a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 8;\n" +
		"  qcl:order 0;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Commitment a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 1;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:OneTimeKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 2;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:VerificationKey a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 3;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:CoinBalance a rdfs:Property;\n" +
		"  rdfs:domain qcl:Uint;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 4;\n" +
		"  rdfs:range coin:Coin.\n" +
		"coin:Mask a rdfs:Property;\n" +
		"  rdfs:domain qcl:ByteArray;\n" +
		"  qcl:size 56;\n" +
		"  qcl:order 5;\n" +
		"  rdfs:range coin:Coin.\n"

	if config.Behavior&token.Divisible == 0 {
		schema += "coin:AdditionalReference a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 64;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range coin:Coin.\n"
		schema += "coin:AdditionalReferenceKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range coin:Coin.\n"
	}

	if config.Behavior&token.Acceptable != 0 {
		schema += "\npending:PendingTransaction a rdfs:Class;\n" +
			"  rdfs:label \"a pending transaction\".\n" +
			"pending:FrameNumber a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 8;\n" +
			"  qcl:order 0;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:Commitment a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 1;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 2;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundOneTimeKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 3;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 4;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundVerificationKey a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 5;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 6;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundCoinBalance a rdfs:Property;\n" +
			"  rdfs:domain qcl:Uint;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 7;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:ToMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 8;\n" +
			"  rdfs:range pending:PendingTransaction.\n" +
			"pending:RefundMask a rdfs:Property;\n" +
			"  rdfs:domain qcl:ByteArray;\n" +
			"  qcl:size 56;\n" +
			"  qcl:order 9;\n" +
			"  rdfs:range pending:PendingTransaction.\n"

		if config.Behavior&token.Divisible == 0 {
			schema += "pending:ToAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 10;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:ToAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 11;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReference a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 64;\n" +
				"  qcl:order 12;\n" +
				"  rdfs:range pending:PendingTransaction.\n" +
				"pending:RefundAdditionalReferenceKey a rdfs:Property;\n" +
				"  rdfs:domain qcl:ByteArray;\n" +
				"  qcl:size 56;\n" +
				"  qcl:order 13;\n" +
				"  rdfs:range pending:PendingTransaction.\n"
		}

		if config.Behavior&token.Expirable != 0 {
			schema += "pending:Expiration a rdfs:Property;\n" +
				"  rdfs:domain qcl:Uint;\n" +
				"  qcl:size 8;\n"

			if config.Behavior&token.Divisible == 0 {
				schema += "  qcl:order 14;\n"
			} else {
				schema += "  qcl:order 10;\n"
			}

			schema += "  rdfs:range pending:PendingTransaction.\n"
		}
	}

	schema += "\n"

	return schema, nil
}

func generateRDFPrelude(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) string {
	appAddressHex := hex.EncodeToString(appAddress)

	prelude := "BASE <https://types.quilibrium.com/schema-repository/>\n" +
		"PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n" +
		"PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n" +
		"PREFIX qcl: <https://types.quilibrium.com/qcl/>\n" +
		"PREFIX coin: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/coin/>\n"

	if config.Behavior&token.Acceptable != 0 {
		prelude += "PREFIX pending: <https://types.quilibrium.com/schema-repository/token/" + appAddressHex + "/pending/>\n"
	}

	prelude += "\n"

	return prelude
}
