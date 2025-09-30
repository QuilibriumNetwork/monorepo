//go:build integrationtest
// +build integrationtest

package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// mockAppIntegrationPubSub extends the basic mock with app-specific features
type mockAppIntegrationPubSub struct {
	mock.Mock
	mu           sync.RWMutex
	subscribers  map[string][]func(message *pb.Message) error
	validators   map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult
	peerID       []byte
	peerCount    int
	networkPeers map[string]*mockAppIntegrationPubSub
	messageLog   []messageRecord            // Track all messages for debugging
	frames       []*protobufs.AppShardFrame // Store frames for sync
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

func newMockAppIntegrationPubSub(peerID []byte) *mockAppIntegrationPubSub {
	return &mockAppIntegrationPubSub{
		subscribers:  make(map[string][]func(message *pb.Message) error),
		validators:   make(map[string]func(peerID peer.ID, message *pb.Message) p2p.ValidationResult),
		peerID:       peerID,
		peerCount:    10,
		networkPeers: make(map[string]*mockAppIntegrationPubSub),
		messageLog:   make([]messageRecord, 0),
		frames:       make([]*protobufs.AppShardFrame, 0),
	}
}

func (m *mockAppIntegrationPubSub) Subscribe(bitmask []byte, handler func(message *pb.Message) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(bitmask)
	m.subscribers[key] = append(m.subscribers[key], handler)
	return nil
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

	message := &pb.Message{
		Data: data,
		From: m.peerID,
	}

	// Deliver to local subscribers
	m.mu.RLock()
	handlers := m.subscribers[string(bitmask)]
	m.mu.RUnlock()

	for _, handler := range handlers {
		go handler(message)
	}

	// Deliver to network peers
	m.mu.RLock()
	peers := make([]*mockAppIntegrationPubSub, 0, len(m.networkPeers))
	for _, peer := range m.networkPeers {
		if peer != m {
			peers = append(peers, peer)
		}
	}
	m.mu.RUnlock()

	for _, peer := range peers {
		// Deliver synchronously to ensure proper ordering
		peer.receiveFromNetwork(bitmask, message)
	}

	return nil
}

func (m *mockAppIntegrationPubSub) receiveFromNetwork(bitmask []byte, message *pb.Message) {
	m.mu.RLock()
	validator := m.validators[string(bitmask)]
	m.mu.RUnlock()

	if validator != nil {
		result := validator(peer.ID(message.From), message)
		if result != p2p.ValidationResultAccept {
			// Log validation rejection for debugging
			if len(message.Data) >= 4 {
				typePrefix := binary.BigEndian.Uint32(message.Data[:4])
				if typePrefix == protobufs.AppShardFrameType {
					frame := &protobufs.AppShardFrame{}
					if err := frame.FromCanonicalBytes(message.Data); err == nil && frame.Header != nil {
						fmt.Printf("DEBUG: Node %x rejected frame %d from %x (validation result: %v)\n",
							m.peerID[:4], frame.Header.FrameNumber, message.From[:4], result)
					}
				}
			}
			return
		}
	}

	m.mu.RLock()
	handlers := m.subscribers[string(bitmask)]
	m.mu.RUnlock()

	for _, handler := range handlers {
		go handler(message) // Make async to match PublishToBitmask behavior
	}
}

func (m *mockAppIntegrationPubSub) RegisterValidator(bitmask []byte, validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult, sync bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validators[string(bitmask)] = validator
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
	hg.Commit()

	t.Logf("    Registered prover with address: %x, filter: %x (public key length: %d)", address, filter, len(publicKey))
}
