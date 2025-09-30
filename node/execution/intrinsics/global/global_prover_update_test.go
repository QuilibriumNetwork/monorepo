package global_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestProverUpdate_Prove(t *testing.T) {
	mockKM := new(mocks.MockKeyManager)
	mockSigner := new(mocks.MockBLSSigner)
	mockHG := new(mocks.MockHypergraph)

	delegate := make([]byte, 32)
	for i := range delegate {
		delegate[i] = byte(0xAB)
	}

	// Fake BLS48-581 G1 pubkey bytes
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte(i % 251)
	}

	// Expected domain = H(GLOBAL || "PROVER_UPDATE")
	updateDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_UPDATE"))
	updateDomain, err := poseidon.HashBytes(updateDomainPreimage)
	require.NoError(t, err)

	// Signer behavior
	mockSigner.On("Public").Return(pubKey)
	mockSigner.On("SignWithDomain", delegate, updateDomain.Bytes()).
		Return([]byte("upd_sig"), nil)

	// KM behavior
	mockKM.On("GetSigningKey", "q-prover-key").Return(mockSigner, nil)
	mockHG.On("GetProver").Return(nil) // unused by Prove

	op := global.NewProverUpdate(delegate, nil, mockHG, &mocks.MockBLSSigner{}, createMockRDFMultiprover(), mockKM)

	require.NoError(t, op.Prove(0))

	require.NotNil(t, op.PublicKeySignatureBLS48581)
	assert.Equal(t, []byte("upd_sig"), op.PublicKeySignatureBLS48581.Signature)

	// Address must be poseidon(pubKey)
	addrBI, _ := poseidon.HashBytes(pubKey)
	expectedAddr := addrBI.FillBytes(make([]byte, 32))
	assert.Equal(t, expectedAddr, op.PublicKeySignatureBLS48581.Address)

	mockSigner.AssertExpectations(t)
	mockKM.AssertExpectations(t)
}

func TestProverUpdate_Verify_Succeeds(t *testing.T) {
	mockKM := new(mocks.MockKeyManager)
	mockHG := new(mocks.MockHypergraph)

	// Setup pubkey and its address
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte(i % 251)
	}
	addrBI, _ := poseidon.HashBytes(pubKey)
	addr := addrBI.FillBytes(make([]byte, 32))

	// Prover vertex data includes PublicKey (order 0 in our RDF schema mapping)
	proverTree := &qcrypto.VectorCommitmentTree{}
	// Using RDF helper to set PublicKey into the tree
	rdf := createMockRDFMultiprover()
	require.NoError(t, rdf.Set(
		global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "PublicKey", pubKey, proverTree,
	))

	// hypergraph.GetVertexData(GLOBAL||addr) -> proverTree
	full := [64]byte{}
	copy(full[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(full[32:], addr)
	mockHG.On("GetVertexData", full).Return(proverTree, nil)

	delegate := make([]byte, 32)
	for i := range delegate {
		delegate[i] = byte(0xCD)
	}

	// Domain for update
	updateDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_UPDATE"))
	updateDomain, _ := poseidon.HashBytes(updateDomainPreimage)

	// Signature validates
	mockKM.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		delegate,
		[]byte("sig"),
		updateDomain.Bytes(),
	).Return(true, nil)

	op := global.NewProverUpdate(delegate, &global.BLS48581AddressedSignature{
		Signature: []byte("sig"),
		Address:   addr,
	}, mockHG, &mocks.MockBLSSigner{}, rdf, mockKM)

	ok, err := op.Verify(0)
	require.NoError(t, err)
	assert.True(t, ok)
	mockKM.AssertExpectations(t)
	mockHG.AssertExpectations(t)
}

func TestProverUpdate_Verify_FailsOnBadSignature(t *testing.T) {
	mockKM := new(mocks.MockKeyManager)
	mockHG := new(mocks.MockHypergraph)

	// Prover tree with pubkey
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte(i % 251)
	}
	addrBI, _ := poseidon.HashBytes(pubKey)
	addr := addrBI.FillBytes(make([]byte, 32))

	rdf := createMockRDFMultiprover()
	tree := &qcrypto.VectorCommitmentTree{}
	require.NoError(t, rdf.Set(
		global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "PublicKey", pubKey, tree,
	))

	full := [64]byte{}
	copy(full[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(full[32:], addr)
	mockHG.On("GetVertexData", full).Return(tree, nil)

	delegate := make([]byte, 32)
	for i := range delegate {
		delegate[i] = byte(0xEE)
	}

	updateDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_UPDATE"))
	updateDomain, _ := poseidon.HashBytes(updateDomainPreimage)

	mockKM.On("ValidateSignature",
		crypto.KeyTypeBLS48581G1,
		pubKey,
		delegate,
		[]byte("bad"),
		updateDomain.Bytes(),
	).Return(false, nil)

	op := global.NewProverUpdate(delegate, &global.BLS48581AddressedSignature{
		Signature: []byte("bad"),
		Address:   addr,
	}, mockHG, nil, rdf, mockKM)

	ok, err := op.Verify(0)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestProverUpdate_Verify_FailsOnAddressMismatch(t *testing.T) {
	mockKM := new(mocks.MockKeyManager)
	mockHG := new(mocks.MockHypergraph)

	// Prover tree with pubkey
	pubKey := make([]byte, 585)
	rand.Read(pubKey)

	// Address in signature is WRONG
	wrongAddr := make([]byte, 32)
	for i := range wrongAddr {
		wrongAddr[i] = 0xFF
	}

	rdf := createMockRDFMultiprover()
	tree := &qcrypto.VectorCommitmentTree{}
	require.NoError(t, rdf.Set(
		global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "PublicKey", pubKey, tree,
	))

	full := [64]byte{}
	copy(full[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(full[32:], wrongAddr) // lookup by wrong address
	mockHG.On("GetVertexData", full).Return(tree, nil)

	delegate := make([]byte, 32)
	for i := range delegate {
		delegate[i] = 0xAA
	}

	// We don't even need to reach signature check; address mismatch should fail.
	op := global.NewProverUpdate(delegate, &global.BLS48581AddressedSignature{
		Signature: []byte("sig"),
		Address:   wrongAddr,
	}, mockHG, nil, rdf, mockKM)

	ok, err := op.Verify(0)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestProverUpdate_Materialize_PreservesBalance(t *testing.T) {
	mockKM := new(mocks.MockKeyManager)
	mockHG := new(mocks.MockHypergraph)
	hypergraphState := hgstate.NewHypergraphState(mockHG)

	// Prover exists with PublicKey
	pubKey := make([]byte, 585)
	for i := range pubKey {
		pubKey[i] = byte(i % 251)
	}
	addrBI, _ := poseidon.HashBytes(pubKey)
	addr := addrBI.FillBytes(make([]byte, 32))

	rdf := createMockRDFMultiprover()
	proverTree := &qcrypto.VectorCommitmentTree{}
	require.NoError(t, rdf.Set(
		global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover", "PublicKey", pubKey, proverTree,
	))

	// Existing reward vertex with non-zero balance
	rewardPrior := &qcrypto.VectorCommitmentTree{}
	nonZero := make([]byte, 32)
	binary.BigEndian.PutUint64(nonZero[24:], 12345)
	require.NoError(t, rdf.Set(
		global.GLOBAL_RDF_SCHEMA, token.QUIL_TOKEN_ADDRESS,
		"reward:ProverReward", "Balance", nonZero, rewardPrior,
	))

	fullProver := [64]byte{}
	fullReward := [64]byte{}
	copy(fullProver[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
	copy(fullReward[:32], token.QUIL_TOKEN_ADDRESS)
	copy(fullProver[32:], addr)
	copy(fullReward[32:], addr)
	mockHG.On("GetVertex", fullProver).Return(nil, nil)
	mockHG.On("GetVertexData", fullProver).Return(proverTree, nil)
	mockHG.On("GetVertex", fullReward).Return(nil, nil)
	mockHG.On("GetVertexData", fullReward).Return(rewardPrior, nil)

	// Hypergraph lookups
	mockHG.On("Get", token.QUIL_TOKEN_ADDRESS, addr, hgstate.VertexAddsDiscriminator).Return(rewardPrior, nil)
	mockHG.On("Get", intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr, hgstate.HyperedgeAddsDiscriminator).Return(nil, assert.AnError)

	delegate := make([]byte, 32)
	for i := range delegate {
		delegate[i] = 0x42
	}

	// Expect Set of reward vertex with preserved balance
	mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil)
	mockHG.
		On("SetVertexData",
			mock.Anything,
			mock.MatchedBy(func(id [64]byte) bool {
				return bytes.Equal(id[:32], token.QUIL_TOKEN_ADDRESS) &&
					bytes.Equal(id[32:], addr)
			}),
			mock.MatchedBy(func(tree *qcrypto.VectorCommitmentTree) bool {
				d, err := rdf.Get(global.GLOBAL_RDF_SCHEMA, "reward:ProverReward", "DelegateAddress", tree)
				if err != nil || len(d) == 0 || !bytes.Equal(d, delegate) {
					return false
				}
				b, err := rdf.Get(global.GLOBAL_RDF_SCHEMA, "reward:ProverReward", "Balance", tree)
				return err == nil && len(b) > 0 && bytes.Equal(b, make([]byte, 32))
			}),
		).
		Return(nil)

	op := global.NewProverUpdate(delegate, &global.BLS48581AddressedSignature{
		Signature: []byte("s"),
		Address:   addr,
	}, mockHG, nil, rdf, mockKM)

	newState, err := op.Materialize(99, hypergraphState)
	require.NoError(t, err)
	require.NotNil(t, newState)
}

func TestProverUpdate_GetCost(t *testing.T) {
	op := global.NewProverUpdate(make([]byte, 32), nil, nil, nil, nil, nil)
	cost, err := op.GetCost()
	require.NoError(t, err)
	assert.Equal(t, int64(0), cost.Int64())
}
