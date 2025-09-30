//go:build integrationtest
// +build integrationtest

package global_test

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// Helper function to create a fresh hypergraph
func createHypergraph(t *testing.T) (hypergraph.Hypergraph, *bls48581.KZGInclusionProver, *schema.RDFMultiprover) {
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hgcrdt.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)
	rm := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, ip)
	return hg, ip, rm
}

// Helper function to create an active prover with allocations in the hypergraph
func createActiveProverWithAllocation(t *testing.T, hg hypergraph.Hypergraph, ip *bls48581.KZGInclusionProver, rm *schema.RDFMultiprover, pubKey []byte, filter []byte, joinFrame uint64) {
	addrBI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	addr := addrBI.FillBytes(make([]byte, 32))

	// Create prover tree
	proverTree := &qcrypto.VectorCommitmentTree{}
	// Store public key
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "PublicKey", pubKey, proverTree)
	require.NoError(t, err)
	// Store status (1 = active)
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "Status", []byte{1}, proverTree)
	require.NoError(t, err)

	// Create allocation
	allocationAddressBI, err := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubKey, filter))
	require.NoError(t, err)
	allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

	allocationTree := &qcrypto.VectorCommitmentTree{}
	// Store allocation data
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Prover", addr, allocationTree)
	require.NoError(t, err)
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "ConfirmationFilter", filter, allocationTree)
	require.NoError(t, err)
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Status", []byte{1}, allocationTree) // active
	require.NoError(t, err)
	joinFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinFrameBytes, joinFrame)
	err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "JoinFrameNumber", joinFrameBytes, allocationTree)
	require.NoError(t, err)

	// Create hyperedge
	hyperedgeTree := &qcrypto.VectorCommitmentTree{}
	// Add allocation to hyperedge
	hyperedgeTree.Insert(allocationAddress, []byte{1}, nil, big.NewInt(1))

	txn, _ := hg.NewTransaction(false)
	// Add prover vertex
	prover := hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr), proverTree.Commit(ip, false), big.NewInt(0))
	hg.AddVertex(txn, prover)
	hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr)), proverTree)
	// Add allocation vertex
	allocation := hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(allocationAddress), allocationTree.Commit(ip, false), big.NewInt(0))
	hg.AddVertex(txn, allocation)
	hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocationAddress)), allocationTree)
	// Add hyperedge
	he := hgcrdt.NewHyperedge([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr))
	he.AddExtrinsic(allocation)
	hg.AddHyperedge(txn, he)
	txn.Commit()
}

// Integration test that uses BLS48581 signatures with keys
func TestGlobalProverOperations_Integration(t *testing.T) {
	// Create a key manager with BLS48581 keys
	keyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})
	signer, popk, err := keyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, popk)

	// Test data
	filter := []byte("integration-test-filter000000000000000")
	filter2 := []byte("integration-test-filter000000000000002")
	frameNumber := uint64(123456789)

	// Test ProverJoin with signatures
	t.Run("ProverJoin", func(t *testing.T) {
		// Create a fresh hypergraph for ProverJoin (no pre-existing prover)
		hg, _, rm := createHypergraph(t)

		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverJoin.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverJoin.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverJoin with multiple filters
	t.Run("ProverJoinMultipleFilters", func(t *testing.T) {
		// Create a fresh hypergraph for ProverJoin (no pre-existing prover)
		hg, _, rm := createHypergraph(t)

		proverJoin, err := global.NewProverJoin([][]byte{filter, filter2}, frameNumber, nil, nil, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverJoin.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverJoin.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)

		proverClone := proverJoin.ToProtobuf()
		proverClone.PublicKeySignatureBls48581 = nil
		expectedMessage, _ := proverClone.ToCanonicalBytes()

		// Verify the BLS48581 signature manually
		joinDomainPreimage := slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], []byte("PROVER_JOIN"))
		joinDomain, err := poseidon.HashBytes(joinDomainPreimage)
		require.NoError(t, err)

		valid, err = keyManager.ValidateSignature(
			crypto.KeyTypeBLS48581G1,
			signer.Public().([]byte),
			expectedMessage,
			proverJoin.PublicKeySignatureBLS48581.Signature,
			joinDomain.Bytes(),
		)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverLeave with signatures
	t.Run("ProverLeave", func(t *testing.T) {
		// Create a hypergraph with an active prover and allocation
		hg, ip, rm := createHypergraph(t)
		createActiveProverWithAllocation(t, hg, ip, rm, signer.Public().([]byte), filter, 100000)

		proverLeave, err := global.NewProverLeave([][]byte{filter}, frameNumber, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverLeave.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures - this should succeed because allocation is active
		valid, err := proverLeave.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)

		// Calculate expected address from public key
		addressBI, err := poseidon.HashBytes(signer.Public().([]byte))
		require.NoError(t, err)
		address := addressBI.FillBytes(make([]byte, 32))

		// Check that the address in the signature matches
		assert.Equal(t, address, proverLeave.PublicKeySignatureBLS48581.Address)
	})

	// Test ProverLeave with multiple filters
	t.Run("ProverLeaveMultipleFilters", func(t *testing.T) {
		// Create a hypergraph with active allocations for both filters
		hg, ip, rm := createHypergraph(t)
		createActiveProverWithAllocation(t, hg, ip, rm, signer.Public().([]byte), filter, 100000)

		// Also add second allocation manually
		addrBI, _ := poseidon.HashBytes(signer.Public().([]byte))
		addr := addrBI.FillBytes(make([]byte, 32))

		allocationAddressBI2, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), signer.Public().([]byte), filter2))
		allocationAddress2 := allocationAddressBI2.FillBytes(make([]byte, 32))

		allocationTree2 := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Prover", addr, allocationTree2)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "ConfirmationFilter", filter2, allocationTree2)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Status", []byte{1}, allocationTree2) // active
		require.NoError(t, err)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, 100000)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "JoinFrameNumber", joinFrameBytes, allocationTree2)
		require.NoError(t, err)
		allocation2 := hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(allocationAddress2), allocationTree2.Commit(ip, false), big.NewInt(0))
		// Update hyperedge to include second allocation
		hyperedgeFullAddress := [64]byte{}
		copy(hyperedgeFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(hyperedgeFullAddress[32:], addr)
		hyperedge, _ := hg.GetHyperedge(hyperedgeFullAddress)
		hyperedge.AddExtrinsic(allocation2)

		txn, _ := hg.NewTransaction(false)
		hg.AddVertex(txn, allocation2)
		hg.AddHyperedge(txn, hyperedge)
		hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocationAddress2)), allocationTree2)
		txn.Commit()

		proverLeave, err := global.NewProverLeave([][]byte{filter, filter2}, frameNumber, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverLeave.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures - this should succeed because allocations are active
		valid, err := proverLeave.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverPause with signatures
	t.Run("ProverPause", func(t *testing.T) {
		// Create a hypergraph with an active prover and allocation
		hg, ip, rm := createHypergraph(t)
		createActiveProverWithAllocation(t, hg, ip, rm, signer.Public().([]byte), filter, 100000)

		proverPause, err := global.NewProverPause(filter, frameNumber, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverPause.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverPause.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverResume with signatures
	t.Run("ProverResume", func(t *testing.T) {
		// Create a hypergraph with a paused allocation
		hg, ip, rm := createHypergraph(t)
		// First create active prover and allocation
		createActiveProverWithAllocation(t, hg, ip, rm, signer.Public().([]byte), filter, 100000)
		// Then modify allocation to paused state
		allocationAddressBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), signer.Public().([]byte), filter))
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))
		allocationFullAddress := [64]byte{}
		copy(allocationFullAddress[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(allocationFullAddress[32:], allocationAddress)

		tree, _ := hg.GetVertexData(allocationFullAddress)
		// Update allocation status to paused (2)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Status", []byte{2}, tree)
		require.NoError(t, err)
		// Store pause frame
		pauseFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(pauseFrameBytes, frameNumber-100) // Paused 100 frames ago
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "PauseFrameNumber", pauseFrameBytes, tree)
		require.NoError(t, err)

		txn, _ := hg.NewTransaction(false)
		hg.SetVertexData(txn, allocationFullAddress, tree)
		txn.Commit()

		proverResume, err := global.NewProverResume(filter, frameNumber, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverResume.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverResume.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverConfirm with signatures
	t.Run("ProverConfirm", func(t *testing.T) {
		// Create a hypergraph with a joining allocation
		hg, ip, rm := createHypergraph(t)
		// Create a prover and allocation in joining state
		addrBI, _ := poseidon.HashBytes(signer.Public().([]byte))
		addr := addrBI.FillBytes(make([]byte, 32))

		// Create prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "PublicKey", signer.Public().([]byte), proverTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "Status", []byte{0}, proverTree) // joining
		require.NoError(t, err)

		// Create allocation in joining state
		allocationAddressBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), signer.Public().([]byte), filter))
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		allocationTree := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Prover", addr, allocationTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "ConfirmationFilter", filter, allocationTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Status", []byte{0}, allocationTree) // joining
		require.NoError(t, err)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, 252840)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "JoinFrameNumber", joinFrameBytes, allocationTree)
		require.NoError(t, err)

		// Create hyperedge
		hyperedge := hgcrdt.NewHyperedge([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr))
		allocation := hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(allocationAddress), allocationTree.Commit(ip, false), big.NewInt(0))
		hyperedge.AddExtrinsic(allocation)

		txn, _ := hg.NewTransaction(false)
		hg.AddHyperedge(txn, hyperedge)
		hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr), proverTree.Commit(ip, false), big.NewInt(0)))
		hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr)), proverTree)
		hg.AddVertex(txn, allocation)
		hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocationAddress)), allocationTree)
		txn.Commit()

		// Try to confirm at frame 252840 + 360
		confirmFrame := uint64(252840 + 360)
		proverConfirm, err := global.NewProverConfirm(filter, confirmFrame, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverConfirm.Prove(confirmFrame)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverConfirm.Verify(confirmFrame)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test ProverReject with signatures
	t.Run("ProverReject", func(t *testing.T) {
		// Create a hypergraph with a leaving allocation
		hg, ip, rm := createHypergraph(t)
		// Create a prover and allocation in leaving state
		addrBI, _ := poseidon.HashBytes(signer.Public().([]byte))
		addr := addrBI.FillBytes(make([]byte, 32))

		// Create prover tree
		proverTree := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "PublicKey", signer.Public().([]byte), proverTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "prover:Prover", "Status", []byte{3}, proverTree) // leaving
		require.NoError(t, err)

		// Create allocation in leaving state
		allocationAddressBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), signer.Public().([]byte), filter))
		allocationAddress := allocationAddressBI.FillBytes(make([]byte, 32))

		allocationTree := &qcrypto.VectorCommitmentTree{}
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Prover", addr, allocationTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "ConfirmationFilter", filter, allocationTree)
		require.NoError(t, err)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "Status", []byte{3}, allocationTree) // leaving
		require.NoError(t, err)
		joinFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(joinFrameBytes, 100000)
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "JoinFrameNumber", joinFrameBytes, allocationTree)
		require.NoError(t, err)
		leaveFrameBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(leaveFrameBytes, frameNumber-400) // Left 400 frames ago
		err = rm.Set(global.GLOBAL_RDF_SCHEMA, intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], "allocation:ProverAllocation", "LeaveFrameNumber", leaveFrameBytes, allocationTree)
		require.NoError(t, err)

		// Create hyperedge
		hyperedge := hgcrdt.NewHyperedge([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr))
		allocation := hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(allocationAddress), allocationTree.Commit(ip, false), big.NewInt(0))
		hyperedge.AddExtrinsic(allocation)

		txn, _ := hg.NewTransaction(false)
		hg.AddHyperedge(txn, hyperedge)
		hg.AddVertex(txn, hgcrdt.NewVertex([32]byte(intrinsics.GLOBAL_INTRINSIC_ADDRESS), [32]byte(addr), proverTree.Commit(ip, false), big.NewInt(0)))
		hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], addr)), proverTree)
		hg.AddVertex(txn, allocation)
		hg.SetVertexData(txn, [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], allocationAddress)), allocationTree)
		txn.Commit()

		proverReject, err := global.NewProverReject(filter, frameNumber, keyManager, hg, rm)
		require.NoError(t, err)

		// Generate the signatures with keys
		err = proverReject.Prove(frameNumber)
		require.NoError(t, err)

		// Verify the signatures
		valid, err := proverReject.Verify(frameNumber)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	// Test invalid signature verification
	t.Run("InvalidSignatures", func(t *testing.T) {
		// Create a fresh hypergraph
		hg, _, rm := createHypergraph(t)

		// Create a different key manager with different keys
		differentKeyManager := keys.NewInMemoryKeyManager(&bls48581.Bls48581KeyConstructor{}, &bulletproofs.Decaf448KeyConstructor{})
		differentSigner, differentPubKey, err := differentKeyManager.CreateSigningKey("q-prover-key", crypto.KeyTypeBLS48581G1)
		require.NoError(t, err)
		require.NotNil(t, differentSigner)
		require.NotNil(t, differentPubKey)

		// Attempt to verify a signature created with the original key using the different key
		proverJoin, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, keyManager, hg, rm)
		require.NoError(t, err)
		err = proverJoin.Prove(frameNumber)
		require.NoError(t, err)

		// Replace the key manager with the different one
		// This simulates an attempt to verify with a different key
		proverJoin2, err := global.NewProverJoin([][]byte{filter}, frameNumber, nil, nil, differentKeyManager, hg, rm)
		require.NoError(t, err)
		proverJoin2.PublicKeySignatureBLS48581 = proverJoin.PublicKeySignatureBLS48581
		proverJoin2.PublicKeySignatureBLS48581.PublicKey = []byte("foobar")

		// The verification should fail since the keys don't match
		valid, err := proverJoin2.Verify(frameNumber)
		assert.Error(t, err)
		assert.False(t, valid)
	})
}
