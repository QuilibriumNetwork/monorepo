package global_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestProverJoin_Verify(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)
	mockHypergraph := new(mocks.MockHypergraph)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockFrameProver := new(mocks.MockFrameProver)
	mockFrameStore := new(mocks.MockClockStore)
	mockFrameStore.On("GetGlobalClockFrame", mock.Anything).Return(&protobufs.GlobalFrame{
		Header: &protobufs.GlobalFrameHeader{
			FrameNumber: 12345,
			Output:      make([]byte, 516),
		},
	}, nil)

	// Test data
	filter := []byte("testfiltertestfiltertestfilterte")
	frameNumber := uint64(12345)
	pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	// Create the prover join operation
	rdfMultiprover := createMockRDFMultiprover()
	proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
	require.NoError(t, err)
	proverJoin.Proof = make([]byte, 516)

	// Set up the signature data manually
	proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
		Signature:    []byte("signature"),
		PublicKey:    pubKey,
		PopSignature: []byte("pop_signature"),
	}

	// Create expected domain for join signature
	joinDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_JOIN"))
	joinDomain, err := poseidon.HashBytes(joinDomainPreimage)
	require.NoError(t, err)

	// Create expected message
	joinpb := proverJoin.ToProtobuf()
	joinpb.PublicKeySignatureBls48581 = nil
	expectedMessage, _ := joinpb.ToCanonicalBytes()

	// Configure mock hypergraph - prover doesn't exist
	addressBI, _ := poseidon.HashBytes(pubKey)
	address := addressBI.FillBytes(make([]byte, 32))
	fullAddress := [64]byte{}
	copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullAddress[32:], address)
	mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)
	mockHypergraph.On("GetProver").Return(mockInclusionProver)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
	mockFrameProver.On("VerifyMultiProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	// Configure mock key manager
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		expectedMessage,
		[]byte("signature"),
		joinDomain.Bytes(),
	).Return(true, nil)

	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		pubKey,
		[]byte("pop_signature"),
		[]byte("BLS48_POP_SK"),
	).Return(true, nil)

	// Call the verify function
	valid, err := proverJoin.Verify(frameNumber)
	require.NoError(t, err)
	assert.True(t, valid)

	// Verify that all expected methods were called
	mockKeyManager.AssertExpectations(t)

	// Test case: verify fails if the join signature is invalid
	mockKeyManager = new(mocks.MockKeyManager)
	mockHypergraph = new(mocks.MockHypergraph)
	mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		expectedMessage,
		[]byte("signature"),
		joinDomain.Bytes(),
	).Return(false, nil)
	proverJoin, err = global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
	require.NoError(t, err)
	proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
		Signature:    []byte("signature"),
		PublicKey:    pubKey,
		PopSignature: []byte("pop_signature"),
	}
	proverJoin.Proof = make([]byte, 516)
	valid, err = proverJoin.Verify(frameNumber)
	require.Error(t, err)
	assert.False(t, valid)

	// Test case: verify fails if prover is already active (not in left state)
	mockKeyManager = new(mocks.MockKeyManager)
	mockHypergraph = new(mocks.MockHypergraph)

	// Create a tree showing prover is active (status = 1)
	tree := &qcrypto.VectorCommitmentTree{}
	tree.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = 1 (active) at order 1
	mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)

	// Configure key manager to validate signatures
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		expectedMessage,
		[]byte("signature"),
		joinDomain.Bytes(),
	).Return(true, nil)
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		pubKey,
		[]byte("pop_signature"),
		[]byte("BLS48_POP_SK"),
	).Return(true, nil)

	proverJoin, err = global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
	require.NoError(t, err)
	proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
		Signature:    []byte("signature"),
		PublicKey:    pubKey,
		PopSignature: []byte("pop_signature"),
	}
	proverJoin.Proof = make([]byte, 516)
	valid, err = proverJoin.Verify(frameNumber)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prover already exists in non-left state")
	assert.False(t, valid)

	// Test case: verify succeeds if prover is in left state (4)
	mockKeyManager = new(mocks.MockKeyManager)
	mockHypergraph = new(mocks.MockHypergraph)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)

	// Create a tree showing prover is left (status = 4)
	tree = &qcrypto.VectorCommitmentTree{}
	tree.Insert([]byte{1 << 2}, []byte{4}, nil, big.NewInt(1)) // status = 4 (left) at order 1
	mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)

	// Configure key manager to validate signatures
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		expectedMessage,
		[]byte("signature"),
		joinDomain.Bytes(),
	).Return(true, nil)
	mockKeyManager.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		pubKey,
		[]byte("pop_signature"),
		[]byte("BLS48_POP_SK"),
	).Return(true, nil)

	proverJoin, err = global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
	require.NoError(t, err)
	proverJoin.Proof = make([]byte, 516)
	proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
		Signature:    []byte("signature"),
		PublicKey:    pubKey,
		PopSignature: []byte("pop_signature"),
	}
	valid, err = proverJoin.Verify(frameNumber)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestProverJoin_Materialize(t *testing.T) {
	t.Run("Materialize new prover - creates new vertex", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockInclusionProver := new(mocks.MockInclusionProver)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameStore := new(mocks.MockClockStore)

		// Test data
		filter := []byte("testfiltertestfiltertestfilterte")
		frameNumber := uint64(252900)
		pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Compute expected address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Configure mock to return nil vertex (prover doesn't exist yet)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockHypergraph.On("GetVertex", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetProver").Return(mockInclusionProver)
		mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)

		// Expect a new vertex to be created with proper initial state
		mockHypergraph.On("Add",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) &&
					bytes.Equal(id[32:], address)
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that public key was stored (order 0)
				storedPubKey, _ := tree.Get([]byte{0})
				if !bytes.Equal(storedPubKey, pubKey) {
					return false
				}
				// Check that status is joining (0) (order 1)
				statusBytes, _ := tree.Get([]byte{1 << 2})
				if len(statusBytes) != 1 || statusBytes[0] != 0 {
					return false
				}
				// Check that join frame was stored (order 4)
				frameBytes, _ := tree.Get([]byte{4 << 2})
				if len(frameBytes) != 8 {
					return false
				}
				storedFrame := binary.BigEndian.Uint64(frameBytes)
				return storedFrame == frameNumber
			}),
		).Return(nil)

		// Create the prover join operation
		rdfMultiprover := createMockRDFMultiprover()
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
		require.NoError(t, err)

		// Set up the signature data
		proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
			Signature:    []byte("signature"),
			PublicKey:    pubKey,
			PopSignature: []byte("pop_signature"),
		}

		// Call Materialize
		newState, err := proverJoin.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
		assert.Equal(t, hypergraphState, newState)
	})

	t.Run("Materialize existing prover - updates existing vertex", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockInclusionProver := new(mocks.MockInclusionProver)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameStore := new(mocks.MockClockStore)

		// Test data
		filter := []byte("testfiltertestfiltertestfilterte")
		frameNumber := uint64(252900)
		pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Compute expected address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Setup existing tree with some data
		existingTree := &qcrypto.VectorCommitmentTree{}
		existingTree.Insert([]byte{5 << 2}, []byte("existing data"), nil, big.NewInt(13))

		// Create existing vertex
		existingVertex := hypergraph.NewVertex(
			[32]byte(fullAddress[:32]),
			[32]byte(fullAddress[32:]),
			make([]byte, 74),
			big.NewInt(13),
		)

		// Configure mock to return existing vertex and tree
		mockHypergraph.On("GetVertex", mock.Anything).Return(existingVertex, nil)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(existingTree, nil)
		mockHypergraph.On("GetProver").Return(mockInclusionProver)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(&mockHyperedge{}, nil)

		mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)

		// Expect the tree to be updated with new prover data
		mockHypergraph.On("Add",
			mock.MatchedBy(func(v thypergraph.Vertex) bool {
				id := v.GetID()
				return bytes.Equal(id[:], fullAddress[:])
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that public key was stored (order 0)
				storedPubKey, _ := tree.Get([]byte{0})
				if !bytes.Equal(storedPubKey, pubKey) {
					return false
				}
				// Check that status is joining (0) (order 1)
				statusBytes, _ := tree.Get([]byte{1 << 2})
				if len(statusBytes) != 1 || statusBytes[0] != 0 {
					return false
				}
				// Check that join frame was stored (order 4)
				frameBytes, _ := tree.Get([]byte{4 << 2})
				if len(frameBytes) != 8 {
					return false
				}
				storedFrame := binary.BigEndian.Uint64(frameBytes)
				if storedFrame != frameNumber {
					return false
				}
				// Check that existing data is preserved (order 5 is LeaveFrameNumber)
				existingData, _ := tree.Get([]byte{5 << 2})
				return bytes.Equal(existingData, []byte("existing data"))
			}),
		).Return(nil)

		// Create the prover join operation
		rdfMultiprover := createMockRDFMultiprover()
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
		require.NoError(t, err)

		// Set up the signature data
		proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
			Signature:    []byte("signature"),
			PublicKey:    pubKey,
			PopSignature: []byte("pop_signature"),
		}

		// Call Materialize
		newState, err := proverJoin.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
		assert.Equal(t, hypergraphState, newState)
	})

	t.Run("Materialize hypergraph add error - returns error", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockInclusionProver := new(mocks.MockInclusionProver)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameStore := new(mocks.MockClockStore)

		// Test data
		filter := []byte("testfiltertestfiltertestfilterte")
		frameNumber := uint64(252900)
		pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Compute expected address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Configure mock to return nil vertex (prover doesn't exist yet)
		mockHypergraph.On("GetVertex", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("NewTransaction", false).Return(&mockTransaction{}, nil)
		mockHypergraph.On("GetProver").Return(mockInclusionProver)
		mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)

		// Configure Add to return an error
		mockHypergraph.On("AddVertex",
			mock.Anything,
			mock.Anything,
		).Return(errors.New("hypergraph add error"))

		// Create the prover join operation
		rdfMultiprover := createMockRDFMultiprover()
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
		require.NoError(t, err)

		// Set up the signature data
		proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
			Signature:    []byte("signature"),
			PublicKey:    pubKey,
			PopSignature: []byte("pop_signature"),
		}

		// Call Materialize
		newState, err := proverJoin.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)

		err = newState.Commit()
		require.Error(t, err)
	})

	t.Run("Materialize address computation error - returns error", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameStore := new(mocks.MockClockStore)

		// Test data
		filter := []byte("testfiltertestfiltertestfilterte")
		frameNumber := uint64(252900)

		// Create the prover join operation
		rdfMultiprover := createMockRDFMultiprover()
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
		require.NoError(t, err)

		// Set up the signature data with nil public key (will cause poseidon hash error)
		proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
			Signature:    []byte("signature"),
			PublicKey:    nil,
			PopSignature: []byte("pop_signature"),
		}

		// Call Materialize
		newState, err := proverJoin.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "materialize")
		assert.Nil(t, newState)
	})

	t.Run("Materialize with merge targets - sets seniority from Ed448 keys", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)
		mockInclusionProver := new(mocks.MockInclusionProver)
		mockFrameProver := new(mocks.MockFrameProver)
		mockFrameStore := new(mocks.MockClockStore)

		// Test data
		filter := []byte("testfiltertestfiltertestfilterte")
		frameNumber := uint64(252900)
		pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create actual Ed448 key
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)

		peerId, err := peer.IDFromPublicKey(ed448PubKey)
		require.NoError(t, err)

		addrBI, err := poseidon.HashBytes([]byte(peerId))
		require.NoError(t, err)

		addr := addrBI.FillBytes(make([]byte, 32))

		compat.OverrideSeniority(
			&compat.FirstRetroJson{PeerId: peerId.String(), Reward: "157208"},
			&compat.SecondRetroJson{PeerId: peerId.String(), JanPresence: true, FebPresence: true, MarPresence: true, AprPresence: true, MayPresence: true},
			&compat.ThirdRetroJson{PeerId: peerId.String(), Reward: "100"},
			&compat.FourthRetroJson{PeerId: peerId.String(), Reward: "100"},
			hex.EncodeToString(addr),
			100000,
		)

		// Compute expected address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Configure mock to return nil vertex (prover doesn't exist yet)
		mockHypergraph.On("GetVertex", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetVertexData", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("GetHyperedge", mock.Anything).Return(nil, assert.AnError)
		mockHypergraph.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockHypergraph.On("GetProver").Return(mockInclusionProver)
		mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)

		mockTransaction := &mockTransaction{}
		mockHypergraph.On("NewTransaction", false).Return(mockTransaction, nil)
		mockHypergraph.On("Commit").Return(map[qcrypto.ShardKey][][]byte{qcrypto.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()

		// Expect a new vertex to be created with seniority = legacy value over mainnet
		mockHypergraph.On("AddVertex",
			mock.Anything,
			mock.Anything,
		).Return(nil)
		mockHypergraph.On("SetVertexData",
			mock.Anything,
			mock.MatchedBy(func(id [64]byte) bool {
				return bytes.Equal(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) &&
					bytes.Equal(id[32:], address)
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				// Check that public key was stored (order 0)
				storedPubKey, _ := tree.Get([]byte{0})
				if !bytes.Equal(storedPubKey, pubKey) {
					return false
				}
				// Check that status is joining (0) (order 1)
				statusBytes, _ := tree.Get([]byte{1 << 2})
				if len(statusBytes) != 1 || statusBytes[0] != 0 {
					return false
				}
				// Check that seniority is non-zero (order 3)
				seniorityBytes, _ := tree.Get([]byte{3 << 2})
				if len(seniorityBytes) != 8 {
					return false
				}
				seniority := binary.BigEndian.Uint64(seniorityBytes)

				return seniority == 0x0000000001921980
			}),
		).Return(nil)

		// For the other vertex data calls, just pass them
		mockHypergraph.On("SetVertexData", mock.Anything, mock.MatchedBy(func(id [64]byte) bool {
			return !(bytes.Equal(id[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:]) &&
				bytes.Equal(id[32:], address))
		}), mock.Anything).Return(nil)

		mockHypergraph.On("AddHyperedge", mock.Anything, mock.Anything).Return(nil)

		// Create the prover join operation
		rdfMultiprover := createMockRDFMultiprover()
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, mockFrameProver, mockFrameStore)
		require.NoError(t, err)

		// Set up the signature data
		proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
			Signature:    []byte("signature"),
			PublicKey:    pubKey,
			PopSignature: []byte("pop_signature"),
		}

		// Add merge targets with Ed448 keys
		rawPub, err := ed448PubKey.Raw()
		require.NoError(t, err)
		proverJoin.MergeTargets = []*global.SeniorityMerge{
			{
				KeyType:   crypto.KeyTypeEd448,
				PublicKey: rawPub,
				Signature: []byte("ed448_signature"),
			},
		}

		// Call Materialize
		newState, err := proverJoin.Materialize(frameNumber, hypergraphState)
		require.NoError(t, err)
		assert.NotNil(t, newState)
		err = newState.Commit()
		require.NoError(t, err)
	})
}

func TestProverJoin_GetCost(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)
	mockHypergraph := new(mocks.MockHypergraph)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
	mockFrameStore := new(mocks.MockClockStore)

	// Test data
	filter := []byte("testfiltertestfiltertestfilterte")
	frameNumber := uint64(12345)
	pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	// Create the prover join operation
	rdfMultiprover := createMockRDFMultiprover()
	proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, mockKeyManager, mockHypergraph, rdfMultiprover, &mocks.MockFrameProver{}, mockFrameStore)
	require.NoError(t, err)

	// Set up the signature data manually
	proverJoin.PublicKeySignatureBLS48581 = global.BLS48581SignatureWithProofOfPossession{
		Signature:    []byte("signature"),
		PublicKey:    pubKey,
		PopSignature: []byte("pop_signature"),
	}

	// Call the GetCost function
	cost, err := proverJoin.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}

type mockTransaction struct{}

// Abort implements store.Transaction.
func (m *mockTransaction) Abort() error {
	return nil
}

// Commit implements store.Transaction.
func (m *mockTransaction) Commit() error {
	return nil
}

// Delete implements store.Transaction.
func (m *mockTransaction) Delete(key []byte) error {
	panic("unimplemented")
}

// DeleteRange implements store.Transaction.
func (m *mockTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	panic("unimplemented")
}

// Get implements store.Transaction.
func (m *mockTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	panic("unimplemented")
}

// NewIter implements store.Transaction.
func (m *mockTransaction) NewIter(lowerBound []byte, upperBound []byte) (store.Iterator, error) {
	panic("unimplemented")
}

// Set implements store.Transaction.
func (m *mockTransaction) Set(key []byte, value []byte) error {
	return nil
}

var _ store.Transaction = (*mockTransaction)(nil)
