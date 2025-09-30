//go:build integrationtest
// +build integrationtest

package crypto_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestRDFMultiprover(t *testing.T) {
	// Create test RDF document
	rdfDoc := `
		@prefix coin: <https://types.quilibrium.com/schema-repository/token/test/coin/> .
		@prefix qcl: <https://types.quilibrium.com/qcl/> .
		@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

		coin:Coin a rdfs:Class.
		coin:Commitment a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 1;
			rdfs:range coin:Coin.
		coin:OneTimeKey a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 2;
			rdfs:range coin:Coin.
		coin:VerificationKey a rdfs:Property;
			rdfs:domain qcl:ByteArray;
			qcl:size 56;
			qcl:order 3;
			rdfs:range coin:Coin.
	`

	// Create components
	parser := &schema.TurtleRDFParser{}
	log := zap.NewNop()
	inclusionProver := bls48581.NewKZGInclusionProver(log)
	multiprover := schema.NewRDFMultiprover(parser, inclusionProver)

	// Create a test tree
	tree := &qcrypto.VectorCommitmentTree{}

	// Insert test data at the correct indices
	// The tree needs to have data at indices that will be used in the polynomial
	// Insert enough data to ensure polynomial has values at indices 1, 2, 3
	for i := 0; i < 63; i++ {
		data := bytes.Repeat([]byte{byte(i + 1)}, 56)
		err := tree.Insert([]byte{byte(i << 2)}, data, nil, big.NewInt(56))
		require.NoError(t, err)
	}
	tree.Commit(inclusionProver, false)

	t.Run("Prove", func(t *testing.T) {
		fields := []string{"Commitment", "VerificationKey"}
		proof, err := multiprover.Prove(rdfDoc, fields, tree)
		require.NoError(t, err)
		assert.NotNil(t, proof)
	})

	t.Run("ProveWithType", func(t *testing.T) {
		fields := []string{"Commitment", "VerificationKey"}
		typeIndex := uint64(63)
		proof, err := multiprover.ProveWithType(rdfDoc, fields, tree, &typeIndex)
		require.NoError(t, err)
		assert.NotNil(t, proof)

		// Test without type index
		proof, err = multiprover.ProveWithType(rdfDoc, fields, tree, nil)
		require.NoError(t, err)
		assert.NotNil(t, proof)
	})

	t.Run("Get", func(t *testing.T) {
		// Test getting commitment field (order 1, so key is 1<<2 = 4, data at index 1)
		value, err := multiprover.Get(rdfDoc, "coin:Coin", "Commitment", tree)
		require.NoError(t, err)
		assert.Equal(t, bytes.Repeat([]byte{2}, 56), value) // Index 1 has value 2

		// Test getting one-time key field (order 2, so key is 2<<2 = 8, data at index 2)
		value, err = multiprover.Get(rdfDoc, "coin:Coin", "OneTimeKey", tree)
		require.NoError(t, err)
		assert.Equal(t, bytes.Repeat([]byte{3}, 56), value) // Index 2 has value 3

		// Test getting verification key field (order 3, so key is 3<<2 = 12, data at index 3)
		value, err = multiprover.Get(rdfDoc, "coin:Coin", "VerificationKey", tree)
		require.NoError(t, err)
		assert.Equal(t, bytes.Repeat([]byte{4}, 56), value) // Index 3 has value 4
	})

	t.Run("GetFieldOrder", func(t *testing.T) {
		order, maxOrder, err := multiprover.GetFieldOrder(rdfDoc, "coin:Coin", "Commitment")
		require.NoError(t, err)
		assert.Equal(t, 1, order)
		assert.Equal(t, 3, maxOrder)

		order, maxOrder, err = multiprover.GetFieldOrder(rdfDoc, "coin:Coin", "OneTimeKey")
		require.NoError(t, err)
		assert.Equal(t, 2, order)
		assert.Equal(t, 3, maxOrder)

		order, maxOrder, err = multiprover.GetFieldOrder(rdfDoc, "coin:Coin", "VerificationKey")
		require.NoError(t, err)
		assert.Equal(t, 3, order)
		assert.Equal(t, 3, maxOrder)
	})

	t.Run("GetFieldKey", func(t *testing.T) {
		key, err := multiprover.GetFieldKey(rdfDoc, "coin:Coin", "Commitment")
		require.NoError(t, err)
		assert.Equal(t, []byte{1 << 2}, key)

		key, err = multiprover.GetFieldKey(rdfDoc, "coin:Coin", "OneTimeKey")
		require.NoError(t, err)
		assert.Equal(t, []byte{2 << 2}, key)
	})

	t.Run("Verify", func(t *testing.T) {
		// Create proof without type index for simpler verification
		fields := []string{"Commitment", "OneTimeKey", "VerificationKey"}
		proof, err := multiprover.ProveWithType(rdfDoc, fields, tree, nil)
		require.NoError(t, err)

		// Get actual data from tree for verification
		data := make([][]byte, len(fields))
		for i, field := range fields {
			value, err := multiprover.Get(rdfDoc, "coin:Coin", field, tree)
			require.NoError(t, err)
			data[i] = value
		}

		// Create commit
		commit := tree.Commit(inclusionProver, false)
		proofBytes, _ := proof.ToBytes()

		// Verify should pass with correct data
		// keys parameter is nil to use default index-based keys
		valid, err := multiprover.Verify(rdfDoc, fields, nil, commit, proofBytes, data)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify should fail with wrong data
		wrongData := make([][]byte, len(fields))
		for i := range wrongData {
			wrongData[i] = []byte("wrong data")
		}
		valid, err = multiprover.Verify(rdfDoc, fields, nil, commit, proofBytes, wrongData)
		require.NoError(t, err)
		assert.False(t, valid)

		// Verify should error with non-existent field
		invalidFields := []string{"Commitment", "NonExistent"}
		_, err = multiprover.Verify(rdfDoc, invalidFields, nil, commit, proofBytes, data[:2])
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("VerifyWithType", func(t *testing.T) {
		// Add type marker to tree
		typeData := bytes.Repeat([]byte{0xff}, 32)
		typeIndex := uint64(63)
		err := tree.Insert(typeData, typeData, nil, big.NewInt(32))
		require.NoError(t, err)

		// Get commit after all data is inserted
		commit := tree.Commit(inclusionProver, false)

		// Create proof with type
		fields := []string{"Commitment", "VerificationKey"}
		proof, err := multiprover.ProveWithType(rdfDoc, fields, tree, &typeIndex)
		require.NoError(t, err)

		// Get actual data from tree
		data := make([][]byte, len(fields))
		for i, field := range fields {
			value, err := multiprover.Get(rdfDoc, "coin:Coin", field, tree)
			require.NoError(t, err)
			data[i] = value
		}

		proofBytes, _ := proof.ToBytes()

		// Verify with type should pass
		valid, err := multiprover.VerifyWithType(rdfDoc, fields, nil, commit, proofBytes, data, &typeIndex, typeData)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify without type when proof was created with type should fail
		valid, err = multiprover.VerifyWithType(rdfDoc, fields, nil, commit, proofBytes, data, nil, nil)
		require.NoError(t, err)
		assert.False(t, valid) // Should fail due to missing type data

		// Create proof without type
		proofNoType, err := multiprover.ProveWithType(rdfDoc, fields, tree, nil)
		require.NoError(t, err)
		proofNoTypeBytes, _ := proofNoType.ToBytes()

		// Verify without type should pass
		valid, err = multiprover.VerifyWithType(rdfDoc, fields, nil, commit, proofNoTypeBytes, data, nil, nil)
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify with wrong type data should fail
		wrongTypeData := []byte("wrong type data")
		valid, err = multiprover.VerifyWithType(rdfDoc, fields, nil, commit, proofBytes, data, &typeIndex, wrongTypeData)
		require.NoError(t, err)
		assert.False(t, valid)

		// Verify with different type index but same data should still fail
		// because the hash uses the fixed key bytes.Repeat([]byte{0xff}, 32)
		differentTypeIndex := uint64(50)
		valid, err = multiprover.VerifyWithType(rdfDoc, fields, nil, commit, proofBytes, data, &differentTypeIndex, typeData)
		require.NoError(t, err)
		assert.False(t, valid) // Should fail because proof was created with index 63
	})

	t.Run("ErrorCases", func(t *testing.T) {
		// Test non-existent field
		_, err := multiprover.Get(rdfDoc, "coin:Coin", "NonExistent", tree)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		// Test invalid document
		_, err = multiprover.Get("invalid rdf", "coin:Coin", "Commitment", tree)
		assert.Error(t, err)

		// Test verify with mismatched data count
		fields := []string{"Commitment", "OneTimeKey"}
		proof, err := multiprover.ProveWithType(rdfDoc, fields, tree, nil)
		require.NoError(t, err)

		// Wrong number of data elements
		wrongData := [][]byte{[]byte("data1")}
		commit := tree.Commit(inclusionProver, false)
		_, err = multiprover.Verify(rdfDoc, fields, nil, commit, proof.GetProof(), wrongData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fields and data length mismatch")
	})
}
