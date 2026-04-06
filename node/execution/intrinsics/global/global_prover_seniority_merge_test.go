package global_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestProverSeniorityMerge_Verify(t *testing.T) {
	t.Run("verify passes signature validation but fails seniority check with test data", func(t *testing.T) {
		// This test verifies that all signature validations pass correctly.
		// The final seniority check will fail because test Ed448 keys have 0 seniority
		// in the compat.GetAggregatedSeniority() lookup. This is expected behavior -
		// in production, only merge targets with actual seniority would be used.

		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		pubKey := make([]byte, 585) // Simulate a BLS48581G1 public key
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Compute prover address from public key
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create a tree showing prover exists with a public key (no existing seniority)
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubKey, nil, big.NewInt(int64(len(pubKey))))

		// Configure mock hypergraph - prover exists
		mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)
		mockHypergraph.On("GetVertex", mock.Anything).Return(nil, assert.AnError) // no spent merge

		// Configure mock key manager for Ed448 merge target signature (this WILL be called)
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			rawEd448PubKey,
			pubKey,
			[]byte("ed448_signature"),
			[]byte("PROVER_SENIORITY_MERGE"),
		).Return(true, nil)

		// Note: BLS signature validation will NOT be called because seniority check
		// happens before final signature validation

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		// Set up the addressed signature
		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify - should fail due to seniority check (test peer IDs have 0 seniority)
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge would not increase seniority")
		assert.False(t, valid)

		// Verify that Ed448 signature validation was called (proving validation passed)
		mockKeyManager.AssertExpectations(t)
		mockHypergraph.AssertExpectations(t)
	})

	t.Run("verify fails if prover does not exist", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Create full address
		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Configure mock hypergraph - prover does not exist
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.False(t, valid)
	})

	t.Run("verify fails if no merge targets", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create the operation with no merge targets
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{}, // empty
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no merge targets")
		assert.False(t, valid)
	})

	t.Run("verify fails if merge target already used via PROVER_SENIORITY_MERGE", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Compute prover address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create a tree showing prover exists
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubKey, nil, big.NewInt(int64(len(pubKey))))

		// Compute spent merge address
		spentMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_SENIORITY_MERGE"),
			rawEd448PubKey,
		))
		require.NoError(t, err)
		spentAddress := [64]byte{}
		copy(spentAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentAddress[32:], spentMergeBI.FillBytes(make([]byte, 32)))

		// Configure mock - prover exists, merge target already used
		mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)
		// Return a proper vertex to indicate the merge target was already used
		mockHypergraph.On("GetVertex", spentAddress).Return(
			hypergraph.NewVertex(
				[32]byte(spentAddress[:32]),
				[32]byte(spentAddress[32:]),
				make([]byte, 74),
				big.NewInt(0),
			),
			nil,
		)

		// Configure mock key manager for Ed448 signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			rawEd448PubKey,
			pubKey,
			[]byte("ed448_signature"),
			[]byte("PROVER_SENIORITY_MERGE"),
		).Return(true, nil)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge target already used")
		assert.False(t, valid)
	})

	t.Run("verify fails if merge target already used via PROVER_JOIN_MERGE", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Compute prover address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create a tree showing prover exists
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubKey, nil, big.NewInt(int64(len(pubKey))))

		// Compute spent merge address for PROVER_SENIORITY_MERGE (not found)
		spentSeniorityMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_SENIORITY_MERGE"),
			rawEd448PubKey,
		))
		require.NoError(t, err)
		spentSeniorityAddress := [64]byte{}
		copy(spentSeniorityAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentSeniorityAddress[32:], spentSeniorityMergeBI.FillBytes(make([]byte, 32)))

		// Compute spent merge address for PROVER_JOIN_MERGE (found - already used in join)
		spentJoinMergeBI, err := poseidon.HashBytes(slices.Concat(
			[]byte("PROVER_JOIN_MERGE"),
			rawEd448PubKey,
		))
		require.NoError(t, err)
		spentJoinAddress := [64]byte{}
		copy(spentJoinAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(spentJoinAddress[32:], spentJoinMergeBI.FillBytes(make([]byte, 32)))

		// Configure mock - prover exists, PROVER_SENIORITY_MERGE not used, PROVER_JOIN_MERGE used
		mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)
		mockHypergraph.On("GetVertex", spentSeniorityAddress).Return(nil, assert.AnError) // not used
		// Return a proper vertex to indicate it was already used in join
		mockHypergraph.On("GetVertex", spentJoinAddress).Return(
			hypergraph.NewVertex(
				[32]byte(spentJoinAddress[:32]),
				[32]byte(spentJoinAddress[32:]),
				make([]byte, 74),
				big.NewInt(0),
			),
			nil,
		)

		// Configure mock key manager for Ed448 signature verification
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			rawEd448PubKey,
			pubKey,
			[]byte("ed448_signature"),
			[]byte("PROVER_SENIORITY_MERGE"),
		).Return(true, nil)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge target already used in join")
		assert.False(t, valid)
	})

	t.Run("verify fails if merge target signature is invalid", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Compute prover address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create a tree showing prover exists
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubKey, nil, big.NewInt(int64(len(pubKey))))

		mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)

		// Configure mock key manager for invalid Ed448 signature
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			rawEd448PubKey,
			pubKey,
			[]byte("bad_signature"),
			[]byte("PROVER_SENIORITY_MERGE"),
		).Return(false, nil)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("bad_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail - invalid signature returns false without error
		valid, err := seniorityMerge.Verify(frameNumber)
		// Note: When ValidateSignature returns (false, nil), errors.Wrap(nil, "verify") returns nil
		assert.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verify fails if merge would not increase seniority", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		pubKey := make([]byte, 585)
		for i := range pubKey {
			pubKey[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target (with no seniority override, so 0 seniority)
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Compute prover address
		addressBI, err := poseidon.HashBytes(pubKey)
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create a tree showing prover exists with existing seniority > 0
		tree := &qcrypto.VectorCommitmentTree{}
		tree.Insert([]byte{0}, pubKey, nil, big.NewInt(int64(len(pubKey))))
		// Set existing seniority to a high value (order 3 in RDF schema)
		existingSeniority := make([]byte, 8)
		binary.BigEndian.PutUint64(existingSeniority, 1000000) // 1 million seniority
		tree.Insert([]byte{3 << 2}, existingSeniority, nil, big.NewInt(8))

		mockHypergraph.On("GetVertexData", fullAddress).Return(tree, nil)
		mockHypergraph.On("GetVertex", mock.Anything).Return(nil, assert.AnError) // no spent merge

		// Configure mock key manager for Ed448 merge target signature validation
		mockKeyManager.On("ValidateSignature",
			crypto.KeyTypeEd448,
			rawEd448PubKey,
			pubKey,
			[]byte("ed448_signature"),
			[]byte("PROVER_SENIORITY_MERGE"),
		).Return(true, nil)

		// Create the operation with a merge target that has 0 seniority
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail because merge seniority (0) <= existing seniority (1000000)
		valid, err := seniorityMerge.Verify(frameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge would not increase seniority")
		assert.False(t, valid)
	})

	t.Run("verify fails if request is outdated", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data - request from frame 100, but current frame is 200
		requestFrameNumber := uint64(100)
		currentFrameNumber := uint64(200)
		address := make([]byte, 32)

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			requestFrameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Verify should fail due to outdated request
		valid, err := seniorityMerge.Verify(currentFrameNumber)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outdated request")
		assert.False(t, valid)
	})
}

func TestProverSeniorityMerge_Materialize(t *testing.T) {
	t.Run("Materialize fails if prover does not exist", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		frameNumber := uint64(252900)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		fullAddress := [64]byte{}
		copy(fullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddress[32:], address)

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Mock - return nil for the prover vertex (prover doesn't exist)
		mockHypergraph.On("GetVertexData", fullAddress).Return(nil, assert.AnError)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize - should fail
		newState, err := seniorityMerge.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prover not found")
		assert.Nil(t, newState)
	})

	t.Run("Materialize fails if no merge targets", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()
		hypergraphState := hgstate.NewHypergraphState(mockHypergraph)

		// Test data
		frameNumber := uint64(252900)
		address := make([]byte, 32)

		// Create the operation with no merge targets
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{}, // empty
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Call Materialize - should fail
		newState, err := seniorityMerge.Materialize(frameNumber, hypergraphState)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no merge targets")
		assert.Nil(t, newState)
	})

}

func TestProverSeniorityMerge_GetCost(t *testing.T) {
	// Setup
	mockKeyManager := new(mocks.MockKeyManager)
	mockHypergraph := new(mocks.MockHypergraph)
	mockHypergraph.On("GetCoveredPrefix").Return([]int{}, nil)
	mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

	// Test data
	frameNumber := uint64(12345)

	// Create Ed448 key for merge target
	_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
	require.NoError(t, err)
	rawEd448PubKey, err := ed448PubKey.Raw()
	require.NoError(t, err)

	// Create the operation
	rdfMultiprover := createMockRDFMultiprover()
	seniorityMerge, err := global.NewProverSeniorityMerge(
		frameNumber,
		[]*global.SeniorityMerge{
			{
				KeyType:   crypto.KeyTypeEd448,
				PublicKey: rawEd448PubKey,
				Signature: []byte("ed448_signature"),
			},
		},
		mockHypergraph,
		rdfMultiprover,
		mockKeyManager,
	)
	require.NoError(t, err)

	// GetCost should return 0
	cost, err := seniorityMerge.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}

func TestProverSeniorityMerge_GetWriteAddresses(t *testing.T) {
	t.Run("GetWriteAddresses returns prover and spent merge addresses", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create Ed448 key for merge target
		_, ed448PubKey, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey, err := ed448PubKey.Raw()
		require.NoError(t, err)

		// Create the operation
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey,
					Signature: []byte("ed448_signature"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Get write addresses
		addresses, err := seniorityMerge.GetWriteAddresses(frameNumber)
		require.NoError(t, err)

		// Should have at least 2 addresses: prover address + 1 spent merge address
		assert.GreaterOrEqual(t, len(addresses), 2)

		// Verify prover address is included
		proverFullAddress := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address)
		found := false
		for _, addr := range addresses {
			if bytes.Equal(addr, proverFullAddress) {
				found = true
				break
			}
		}
		assert.True(t, found, "prover address should be in write addresses")
	})

	t.Run("GetWriteAddresses with multiple merge targets", func(t *testing.T) {
		// Setup
		mockKeyManager := new(mocks.MockKeyManager)
		mockHypergraph := new(mocks.MockHypergraph)
		mockHypergraph.On("GetProver").Return(func() *mocks.MockInclusionProver { m := new(mocks.MockInclusionProver); m.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe(); return m }()).Maybe()

		// Test data
		frameNumber := uint64(12345)
		address := make([]byte, 32)
		for i := range address {
			address[i] = byte(i % 256)
		}

		// Create two Ed448 keys for merge targets
		_, ed448PubKey1, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey1, err := ed448PubKey1.Raw()
		require.NoError(t, err)

		_, ed448PubKey2, err := pcrypto.GenerateEd448Key(rand.Reader)
		require.NoError(t, err)
		rawEd448PubKey2, err := ed448PubKey2.Raw()
		require.NoError(t, err)

		// Create the operation with two merge targets
		rdfMultiprover := createMockRDFMultiprover()
		seniorityMerge, err := global.NewProverSeniorityMerge(
			frameNumber,
			[]*global.SeniorityMerge{
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey1,
					Signature: []byte("ed448_signature_1"),
				},
				{
					KeyType:   crypto.KeyTypeEd448,
					PublicKey: rawEd448PubKey2,
					Signature: []byte("ed448_signature_2"),
				},
			},
			mockHypergraph,
			rdfMultiprover,
			mockKeyManager,
		)
		require.NoError(t, err)

		seniorityMerge.PublicKeySignatureBLS48581 = global.BLS48581AddressedSignature{
			Signature: []byte("signature"),
			Address:   address,
		}

		// Get write addresses
		addresses, err := seniorityMerge.GetWriteAddresses(frameNumber)
		require.NoError(t, err)

		// Should have 3 addresses: prover address + 2 spent merge addresses
		assert.Equal(t, 3, len(addresses))
	})
}

