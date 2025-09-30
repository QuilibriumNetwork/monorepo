package schema_test

import (
	"bytes"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestRDFMultiprover_Validate(t *testing.T) {
	// Create mock inclusion prover
	mockProver := new(mocks.MockInclusionProver)
	parser := &schema.TurtleRDFParser{}
	multiprover := schema.NewRDFMultiprover(parser, mockProver)

	// Sample RDF schema
	rdfSchema := `
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix test: <https://example.com/test/> .

test:TestClass a rdfs:Class .

test:field1 a rdfs:Property ;
    rdfs:domain qcl:ByteArray ;
    qcl:size 32 ;
    qcl:order 0 ;
    rdfs:range test:TestClass .

test:field2 a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 8 ;
    qcl:order 1 ;
    rdfs:range test:TestClass .

test:field3 a rdfs:Property ;
    rdfs:domain qcl:String ;
    qcl:size 16 ;
    qcl:order 2 ;
    rdfs:range test:TestClass .
`

	t.Run("Valid tree passes validation", func(t *testing.T) {
		tree := &tries.VectorCommitmentTree{}

		// Add valid values at expected indexes
		key0, _ := schema.OrderToKey(0, 64)
		key1, _ := schema.OrderToKey(1, 64)
		key2, _ := schema.OrderToKey(2, 64)

		// field1: 32 bytes
		value1 := make([]byte, 32)
		for i := range value1 {
			value1[i] = byte(i)
		}
		tree.Insert(key0, value1, nil, big.NewInt(32))

		// field2: 8 bytes (uint64)
		value2 := make([]byte, 8)
		value2[0] = 42
		tree.Insert(key1, value2, nil, big.NewInt(8))

		// field3: 16 bytes string
		value3 := []byte("hello world     ") // padded to 16 bytes
		tree.Insert(key2, value3, nil, big.NewInt(16))
		typeBI, err := poseidon.HashBytes(
			slices.Concat(make([]byte, 32), []byte("test:TestClass")),
		)

		require.NoError(t, err)

		typeBytes := typeBI.FillBytes(make([]byte, 32))
		tree.Insert(bytes.Repeat([]byte{0xff}, 32), typeBytes, nil, big.NewInt(32))
		typeName, err := multiprover.GetType(rdfSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		require.Equal(t, typeName, "test:TestClass")
		valid, err := multiprover.Validate(rdfSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Tree with unexpected index fails validation", func(t *testing.T) {
		tree := &tries.VectorCommitmentTree{}

		// Add valid value at expected index
		key0, _ := schema.OrderToKey(0, 64)
		value1 := make([]byte, 32)
		tree.Insert(key0, value1, nil, big.NewInt(32))

		// Add unexpected value at non-schema index
		unexpectedKey, _ := schema.OrderToKey(10, 64) // order 10 not in schema
		tree.Insert(unexpectedKey, []byte("unexpected"), nil, big.NewInt(10))

		valid, err := multiprover.Validate(rdfSchema, make([]byte, 32), tree)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "unexpected index")
	})

	t.Run("Tree with wrong size value fails validation", func(t *testing.T) {
		tree := &tries.VectorCommitmentTree{}

		// Add value with wrong size
		key0, _ := schema.OrderToKey(0, 64)
		wrongSizeValue := make([]byte, 16) // Should be 32 bytes
		tree.Insert(key0, wrongSizeValue, nil, big.NewInt(16))

		valid, err := multiprover.Validate(rdfSchema, make([]byte, 32), tree)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "ByteArray field: expected size 32, got 16")
	})

	t.Run("Boolean field validates correctly", func(t *testing.T) {
		boolSchema := `
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix test: <https://example.com/test/> .

test:TestClass a rdfs:Class .

test:isActive a rdfs:Property ;
    rdfs:domain qcl:Bool ;
    qcl:order 0 ;
    rdfs:range test:TestClass .
`
		tree := &tries.VectorCommitmentTree{}
		key0, _ := schema.OrderToKey(0, 64)

		// Valid boolean (1 byte)
		tree.Insert(key0, []byte{1}, nil, big.NewInt(1))
		valid, err := multiprover.Validate(boolSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		assert.True(t, valid)

		// Invalid boolean (2 bytes)
		tree2 := &tries.VectorCommitmentTree{}
		tree2.Insert(key0, []byte{1, 0}, nil, big.NewInt(2))
		valid, err = multiprover.Validate(boolSchema, make([]byte, 32), tree2)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "Bool field must be exactly 1 byte")
	})

	t.Run("Integer fields validate size correctly", func(t *testing.T) {
		intSchema := `
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix test: <https://example.com/test/> .

test:TestClass a rdfs:Class .

test:count a rdfs:Property ;
    rdfs:domain qcl:Uint ;
    qcl:size 4 ;
    qcl:order 0 ;
    rdfs:range test:TestClass .

test:bigCount a rdfs:Property ;
    rdfs:domain qcl:Int ;
    qcl:size 8 ;
    qcl:order 1 ;
    rdfs:range test:TestClass .
`
		tree := &tries.VectorCommitmentTree{}

		// Valid uint32
		key0, _ := schema.OrderToKey(0, 64)
		tree.Insert(key0, []byte{0, 0, 0, 42}, nil, big.NewInt(4))

		// Valid int64
		key1, _ := schema.OrderToKey(1, 64)
		tree.Insert(key1, []byte{0, 0, 0, 0, 0, 0, 0, 100}, nil, big.NewInt(8))

		valid, err := multiprover.Validate(intSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		assert.True(t, valid)

		// Invalid size for uint
		tree2 := &tries.VectorCommitmentTree{}
		tree2.Insert(key0, []byte{0, 0, 42}, nil, big.NewInt(3)) // Wrong size
		valid, err = multiprover.Validate(intSchema, make([]byte, 32), tree2)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "Uint field: expected size 4, got 3")
	})

	t.Run("Empty tree passes validation", func(t *testing.T) {
		// Empty tree should be valid (fields might be optional)
		tree := &tries.VectorCommitmentTree{}

		valid, err := multiprover.Validate(rdfSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Schema with extrinsic field validates size", func(t *testing.T) {
		// Schema with extrinsic field
		extrinsicSchema := `
@prefix qcl: <https://types.quilibrium.com/qcl/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix test: <https://example.com/test/> .
@prefix ext: <https://example.com/external/> .

test:TestClass a rdfs:Class .

test:extField a rdfs:Property ;
    rdfs:domain ext:ExternalClass ;
    qcl:order 0 ;
    rdfs:range test:TestClass .
`

		tree := &tries.VectorCommitmentTree{}

		// Extrinsic fields should be 32 bytes
		key0, _ := schema.OrderToKey(0, 64)

		// Test with correct size
		correctValue := make([]byte, 32)
		tree.Insert(key0, correctValue, nil, big.NewInt(32))

		valid, err := multiprover.Validate(extrinsicSchema, make([]byte, 32), tree)
		require.NoError(t, err)
		assert.True(t, valid)

		// Test with wrong size
		tree2 := &tries.VectorCommitmentTree{}
		wrongValue := make([]byte, 16)
		tree2.Insert(key0, wrongValue, nil, big.NewInt(16))

		valid, err = multiprover.Validate(extrinsicSchema, make([]byte, 32), tree2)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "Struct field must be exactly 32 bytes")
	})

	t.Run("Skip type verification for encrypted data", func(t *testing.T) {
		tree := &tries.VectorCommitmentTree{}

		// Add encrypted values that don't match expected types/sizes
		key0, _ := schema.OrderToKey(0, 64)
		key1, _ := schema.OrderToKey(1, 64)
		key2, _ := schema.OrderToKey(2, 64)

		// These would normally fail validation:
		// - field1 should be 32 bytes but we're using 74 (typical crypto.VerEnc size)
		// - field2 should be 8 bytes but we're using 74
		// - field3 should be 16 bytes but we're using 74
		encryptedValue := make([]byte, 74)
		for i := range encryptedValue {
			encryptedValue[i] = byte(i % 256)
		}

		tree.Insert(key0, encryptedValue, nil, big.NewInt(74))
		tree.Insert(key1, encryptedValue, nil, big.NewInt(74))
		tree.Insert(key2, encryptedValue, nil, big.NewInt(74))

		// With skipTypeVerification=true, this should pass
		valid, err := multiprover.ValidateWithOptions(rdfSchema, make([]byte, 32), tree, true)
		require.NoError(t, err)
		assert.True(t, valid)

		// Without skipTypeVerification, this should fail
		valid, err = multiprover.ValidateWithOptions(rdfSchema, make([]byte, 32), tree, false)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "expected size")
	})

	t.Run("Skip type verification still checks unexpected indices", func(t *testing.T) {
		tree := &tries.VectorCommitmentTree{}

		// Add valid encrypted value at expected index
		key0, _ := schema.OrderToKey(0, 64)
		encryptedValue := make([]byte, 74)
		tree.Insert(key0, encryptedValue, nil, big.NewInt(74))

		// Add unexpected index
		unexpectedKey, _ := schema.OrderToKey(10, 64) // order 10 not in schema
		tree.Insert(unexpectedKey, encryptedValue, nil, big.NewInt(74))

		// Even with skipTypeVerification=true, unexpected indices should fail
		valid, err := multiprover.ValidateWithOptions(rdfSchema, make([]byte, 32), tree, true)
		require.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "unexpected index")
	})
}
