package token_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// mockMultiproof implements crypto.Multiproof for testing
type mockMultiproof struct{}

func (m *mockMultiproof) GetMulticommitment() []byte { return make([]byte, 74) }
func (m *mockMultiproof) GetProof() []byte           { return make([]byte, 74) }
func (m *mockMultiproof) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(74))
	buf.Write(make([]byte, 74))
	binary.Write(buf, binary.BigEndian, uint32(74))
	buf.Write(make([]byte, 74))
	return buf.Bytes(), nil
}
func (m *mockMultiproof) FromBytes([]byte) error { return nil }

// FuzzTransactionSerialization tests full Transaction serialization/deserialization
func FuzzTransactionSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), 1, 1, 1, []byte{}, []byte{})
	f.Add(make([]byte, 32), 0, 0, 0, []byte{0x01}, []byte{0x02})
	f.Add(make([]byte, 32), 5, 5, 2, make([]byte, 100), make([]byte, 200))

	f.Fuzz(func(t *testing.T, domain []byte, numInputs, numOutputs, numFees int, rangeProof, traversalProof []byte) {
		// Limit sizes to avoid memory issues
		if numInputs > 100 || numInputs < 0 || numOutputs > 100 || numOutputs < 0 || numFees > 10 || numFees < 0 {
			return
		}
		if len(rangeProof) > 10000 || len(traversalProof) > 10000 {
			return
		}
		if len(domain) != 32 {
			return
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		// Create transaction with fuzz data
		tx := &token.Transaction{}
		copy(tx.Domain[:], domain)

		// Add inputs
		for i := 0; i < numInputs; i++ {
			tx.Inputs = append(tx.Inputs, &token.TransactionInput{
				Commitment: make([]byte, 74),
				Signature:  make([]byte, 114),
				Proofs:     [][]byte{make([]byte, 32)},
			})
		}

		// Add outputs
		for i := 0; i < numOutputs; i++ {
			tx.Outputs = append(tx.Outputs, &token.TransactionOutput{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 74),
				RecipientOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 32),
					VerificationKey: make([]byte, 57),
					CoinBalance:     make([]byte, 32),
					Mask:            make([]byte, 32),
				},
			})
		}

		// Add fees
		for i := 0; i < numFees; i++ {
			tx.Fees = append(tx.Fees, big.NewInt(int64(i)))
		}

		tx.RangeProof = rangeProof

		// Create a valid traversal proof structure
		// Skip if no traversal proof data
		if len(traversalProof) > 0 {
			// Try to deserialize the traversal proof data
			tp := &tries.TraversalProof{}
			if err := tp.FromBytes(traversalProof, mockIP); err == nil {
				tx.TraversalProof = tp
			} else {
				// If deserialization fails, skip this test case
				return
			}
		} else {
			// Create minimal valid traversal proof
			tx.TraversalProof = &tries.TraversalProof{
				Multiproof: &mockMultiproof{},
				SubProofs:  make([]tries.TraversalSubProof, 0),
			}
		}

		// Serialize
		data, err := tx.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		tx2 := &token.Transaction{}
		err = tx2.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)

		// If deserialization succeeds, verify basic structure
		if err == nil {
			require.Equal(t, tx.Domain, tx2.Domain)
			require.Equal(t, len(tx.Inputs), len(tx2.Inputs))
			require.Equal(t, len(tx.Outputs), len(tx2.Outputs))
			require.Equal(t, len(tx.Fees), len(tx2.Fees))
			require.Equal(t, tx.RangeProof, tx2.RangeProof)
		}
	})
}

// FuzzPendingTransactionSerialization tests PendingTransaction serialization/deserialization
func FuzzPendingTransactionSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), 1, 1, 1, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, domain []byte, numInputs, numOutputs, numFees int, rangeProof, traversalProof []byte) {
		// Limit sizes
		if numInputs > 100 || numInputs < 0 || numOutputs > 100 || numOutputs < 0 || numFees > 10 || numFees < 0 {
			return
		}
		if len(rangeProof) > 10000 || len(traversalProof) > 10000 {
			return
		}
		if len(domain) != 32 {
			return
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		// Create pending transaction
		tx := &token.PendingTransaction{}
		copy(tx.Domain[:], domain)

		// Add inputs
		for i := 0; i < numInputs; i++ {
			tx.Inputs = append(tx.Inputs, &token.PendingTransactionInput{
				Commitment: make([]byte, 74),
			})
		}

		// Add outputs
		for i := 0; i < numOutputs; i++ {
			tx.Outputs = append(tx.Outputs, &token.PendingTransactionOutput{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 74),
				ToOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 32),
					VerificationKey: make([]byte, 57),
					CoinBalance:     make([]byte, 32),
					Mask:            make([]byte, 32),
				},
			})
		}

		// Add fees
		for i := 0; i < numFees; i++ {
			tx.Fees = append(tx.Fees, big.NewInt(int64(i)))
		}

		tx.RangeProof = rangeProof
		tx.TraversalProof = &tries.TraversalProof{
			Multiproof: &mockMultiproof{},
			SubProofs:  make([]tries.TraversalSubProof, 0),
		}

		// Serialize
		data, err := tx.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		tx2 := &token.PendingTransaction{}
		err = tx2.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)

		// Verify if successful
		if err == nil {
			require.Equal(t, tx.Domain, tx2.Domain)
			require.Equal(t, len(tx.Inputs), len(tx2.Inputs))
			require.Equal(t, len(tx.Outputs), len(tx2.Outputs))
			require.Equal(t, len(tx.Fees), len(tx2.Fees))
			require.Equal(t, tx.RangeProof, tx2.RangeProof)
		}
	})
}

// FuzzMintTransactionSerialization tests MintTransaction serialization/deserialization
func FuzzMintTransactionSerialization(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 32), 1, 1, 1, []byte{})

	f.Fuzz(func(t *testing.T, domain []byte, numInputs, numOutputs, numFees int, rangeProof []byte) {
		// Limit sizes
		if numInputs > 100 || numInputs < 0 || numOutputs > 100 || numOutputs < 0 || numFees > 10 || numFees < 0 {
			return
		}
		if len(rangeProof) > 10000 {
			return
		}
		if len(domain) != 32 {
			return
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		// Create mint transaction
		tx := &token.MintTransaction{}
		copy(tx.Domain[:], domain)

		// Add inputs
		for i := 0; i < numInputs; i++ {
			tx.Inputs = append(tx.Inputs, &token.MintTransactionInput{
				Value:      big.NewInt(1000),
				Commitment: make([]byte, 74),
			})
		}

		// Add outputs
		for i := 0; i < numOutputs; i++ {
			tx.Outputs = append(tx.Outputs, &token.MintTransactionOutput{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 74),
				RecipientOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 32),
					VerificationKey: make([]byte, 57),
					CoinBalance:     make([]byte, 32),
					Mask:            make([]byte, 32),
				},
			})
		}

		// Add fees
		for i := 0; i < numFees; i++ {
			tx.Fees = append(tx.Fees, big.NewInt(int64(i)))
		}

		tx.RangeProof = rangeProof

		// Serialize
		data, err := tx.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		tx2 := &token.MintTransaction{}
		err = tx2.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)

		// Verify if successful
		if err == nil {
			require.Equal(t, tx.Domain, tx2.Domain)
			require.Equal(t, len(tx.Inputs), len(tx2.Inputs))
			require.Equal(t, len(tx.Outputs), len(tx2.Outputs))
			require.Equal(t, len(tx.Fees), len(tx2.Fees))
			require.Equal(t, tx.RangeProof, tx2.RangeProof)
		}
	})
}

// FuzzTransactionTypeDetection tests that the correct transaction type is detected from serialized data
func FuzzTransactionTypeDetection(f *testing.F) {
	// Add various type prefixes
	f.Add(uint32(protobufs.TokenConfigurationType), []byte{})
	f.Add(uint32(protobufs.TransactionType), []byte{})
	f.Add(uint32(protobufs.PendingTransactionType), []byte{})
	f.Add(uint32(protobufs.MintTransactionType), []byte{})
	f.Add(uint32(999999), []byte{}) // Invalid type
	f.Add(uint32(0), make([]byte, 100))

	f.Fuzz(func(t *testing.T, typePrefix uint32, additionalData []byte) {
		// Create data with type prefix
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, typePrefix)
		buf.Write(additionalData)
		data := buf.Bytes()

		// The deserialization functions should handle type checking properly
		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		// Try deserializing as different types
		switch typePrefix {
		case protobufs.TransactionType:
			tx := &token.Transaction{}
			_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		case protobufs.PendingTransactionType:
			tx := &token.PendingTransaction{}
			_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		case protobufs.MintTransactionType:
			tx := &token.MintTransaction{}
			_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		}

		// Wrong type should fail gracefully
		if typePrefix != protobufs.TransactionType {
			tx := &token.Transaction{}
			err := tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
			if len(data) >= 4 && typePrefix != protobufs.TransactionType {
				require.Error(t, err)
			}
		}
	})
}

// Specific deserialization-focused fuzz tests for robustness against malformed inputs
func FuzzTransaction_Deserialization(f *testing.F) {
	// Add valid case
	validTx := &token.Transaction{
		Domain: [32]byte{1, 2, 3},
		Inputs: []*token.TransactionInput{
			{
				Commitment: make([]byte, 56),
				Signature:  make([]byte, 114),
				Proofs:     [][]byte{make([]byte, 32)},
			},
		},
		Outputs: []*token.TransactionOutput{
			{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 56),
				RecipientOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 56),
					VerificationKey: make([]byte, 56),
					CoinBalance:     make([]byte, 56),
					Mask:            make([]byte, 56),
				},
			},
		},
		Fees:       []*big.Int{big.NewInt(100)},
		RangeProof: make([]byte, 74),
		TraversalProof: &tries.TraversalProof{
			Multiproof: &mockMultiproof{},
			SubProofs:  make([]tries.TraversalSubProof, 0),
		},
	}
	validData, _ := validTx.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	// Add invalid type prefix
	f.Add([]byte{0x00, 0x00, 0x00, 0x99})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		tx := &token.Transaction{}
		_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover) // Should not panic
	})
}

func FuzzPendingTransaction_Deserialization(f *testing.F) {
	// Add valid case
	validTx := &token.PendingTransaction{
		Domain: [32]byte{1, 2, 3},
		Inputs: []*token.PendingTransactionInput{
			{
				Commitment: make([]byte, 56),
				Signature:  make([]byte, 114),
				Proofs:     [][]byte{make([]byte, 32)},
			},
		},
		Outputs: []*token.PendingTransactionOutput{
			{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 56),
				ToOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 56),
					VerificationKey: make([]byte, 56),
					CoinBalance:     make([]byte, 56),
					Mask:            make([]byte, 56),
				},
				RefundOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 56),
					VerificationKey: make([]byte, 56),
					CoinBalance:     make([]byte, 56),
					Mask:            make([]byte, 56),
				},
				Expiration: 12345,
			},
		},
		Fees:       []*big.Int{big.NewInt(100)},
		RangeProof: make([]byte, 74),
		TraversalProof: &tries.TraversalProof{
			Multiproof: &mockMultiproof{},
			SubProofs:  make([]tries.TraversalSubProof, 0),
		},
	}
	validData, _ := validTx.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		tx := &token.PendingTransaction{}
		_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover) // Should not panic
	})
}

func FuzzMintTransaction_Deserialization(f *testing.F) {
	// Add valid case
	validTx := &token.MintTransaction{
		Domain: [32]byte{1, 2, 3},
		Inputs: []*token.MintTransactionInput{
			{
				Value:      big.NewInt(1000),
				Commitment: make([]byte, 56),
				Signature:  make([]byte, 114),
				Proofs:     [][]byte{make([]byte, 32)},
			},
		},
		Outputs: []*token.MintTransactionOutput{
			{
				FrameNumber: make([]byte, 8),
				Commitment:  make([]byte, 56),
				RecipientOutput: token.RecipientBundle{
					OneTimeKey:      make([]byte, 56),
					VerificationKey: make([]byte, 56),
					CoinBalance:     make([]byte, 56),
					Mask:            make([]byte, 56),
				},
			},
		},
		Fees:       []*big.Int{big.NewInt(100)},
		RangeProof: make([]byte, 74),
	}
	validData, _ := validTx.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		tx := &token.MintTransaction{}
		_ = tx.FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover) // Should not panic
	})
}

func FuzzTransactionArrayHandling(f *testing.F) {
	// Add cases with various array sizes
	f.Add(uint32(0), uint32(0), uint32(0))         // Empty arrays
	f.Add(uint32(1), uint32(1), uint32(1))         // Single elements
	f.Add(uint32(10), uint32(10), uint32(5))       // Multiple elements
	f.Add(uint32(1000), uint32(1000), uint32(100)) // Large arrays

	f.Fuzz(func(t *testing.T, numInputs, numOutputs, numFees uint32) {
		// Limit to reasonable values
		if numInputs > 1000 || numOutputs > 1000 || numFees > 100 {
			return
		}

		// Create transaction with fuzz array sizes
		buf := new(bytes.Buffer)

		// Write type prefix
		binary.Write(buf, binary.BigEndian, uint32(protobufs.TransactionType))

		// Write domain
		buf.Write(make([]byte, 32))

		// Write inputs
		binary.Write(buf, binary.BigEndian, numInputs)
		for i := uint32(0); i < min32(numInputs, 100); i++ {
			// Create minimal valid input
			inputBuf := new(bytes.Buffer)
			binary.Write(inputBuf, binary.BigEndian, uint32(56)) // Commitment length
			inputBuf.Write(make([]byte, 56))
			binary.Write(inputBuf, binary.BigEndian, uint32(114)) // Signature length
			inputBuf.Write(make([]byte, 114))
			binary.Write(inputBuf, binary.BigEndian, uint32(1))  // Proofs count
			binary.Write(inputBuf, binary.BigEndian, uint32(32)) // Proof length
			inputBuf.Write(make([]byte, 32))

			inputBytes := inputBuf.Bytes()
			binary.Write(buf, binary.BigEndian, uint32(len(inputBytes)))
			buf.Write(inputBytes)
		}

		// Write outputs (simplified)
		binary.Write(buf, binary.BigEndian, numOutputs)
		for i := uint32(0); i < min32(numOutputs, 100); i++ {
			binary.Write(buf, binary.BigEndian, uint32(100)) // Simplified output length
			buf.Write(make([]byte, 100))
		}

		// Write fees
		binary.Write(buf, binary.BigEndian, numFees)
		for i := uint32(0); i < min32(numFees, 50); i++ {
			binary.Write(buf, binary.BigEndian, uint32(4)) // Fee length
			buf.Write([]byte{0x00, 0x00, 0x00, 0x64})      // Fee value (100)
		}

		// Write range proof
		binary.Write(buf, binary.BigEndian, uint32(74))
		buf.Write(make([]byte, 74))

		// Write traversal proof
		binary.Write(buf, binary.BigEndian, uint32(74))
		buf.Write(make([]byte, 74))

		// Try to deserialize
		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		tx := &token.Transaction{}
		_ = tx.FromBytes(buf.Bytes(), config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
	})
}

func FuzzTransactionFeeHandling(f *testing.F) {
	// Add cases with invalid fee lengths
	f.Add(uint32(33), uint32(100))       // Fee too large (> 32 bytes)
	f.Add(uint32(0), uint32(0))          // Zero length fee
	f.Add(uint32(32), uint32(32))        // Valid max length
	f.Add(uint32(0xFFFFFFFF), uint32(4)) // Huge declared length

	f.Fuzz(func(t *testing.T, feeLen, actualDataLen uint32) {
		// Limit actual data to reasonable size
		if actualDataLen > 1000 {
			return
		}

		// Create transaction with potentially bad fee data
		buf := new(bytes.Buffer)

		// Write minimal transaction header
		binary.Write(buf, binary.BigEndian, uint32(protobufs.TransactionType))
		buf.Write(make([]byte, 32))                    // Domain
		binary.Write(buf, binary.BigEndian, uint32(0)) // No inputs
		binary.Write(buf, binary.BigEndian, uint32(0)) // No outputs

		// Write fee with bad length
		binary.Write(buf, binary.BigEndian, uint32(1))      // One fee
		binary.Write(buf, binary.BigEndian, feeLen)         // Declared length
		buf.Write(make([]byte, min32(actualDataLen, 1000))) // Actual data

		// Complete transaction
		binary.Write(buf, binary.BigEndian, uint32(0)) // Empty range proof
		binary.Write(buf, binary.BigEndian, uint32(0)) // Empty traversal proof

		// Try to deserialize
		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		tx := &token.Transaction{}
		_ = tx.FromBytes(buf.Bytes(), config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
	})
}

func FuzzMixedTransactionTypeDeserialization(f *testing.F) {
	// Add valid prefixes for each transaction type
	types := []uint32{
		protobufs.TokenConfigurationType,
		protobufs.TransactionType,
		protobufs.PendingTransactionType,
		protobufs.MintTransactionType,
	}

	for _, typ := range types {
		data := make([]byte, 4)
		data[0] = byte(typ >> 24)
		data[1] = byte(typ >> 16)
		data[2] = byte(typ >> 8)
		data[3] = byte(typ)
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		// Try deserializing as each transaction type - should handle gracefully
		mockHG := new(mocks.MockHypergraph)
		mockBP := new(mocks.MockBulletproofProver)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)
		mockVerEnc := new(mocks.MockVerifiableEncryptor)
		mockDecaf := new(mocks.MockDecafConstructor)
		mockKM := new(mocks.MockKeyRing)
		config := &token.TokenIntrinsicConfiguration{}
		rdfMultiprover := &schema.RDFMultiprover{}

		_ = (&token.Transaction{}).FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		_ = (&token.PendingTransaction{}).FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		_ = (&token.MintTransaction{}).FromBytes(data, config, mockHG, mockBP, mockIP, mockVerEnc, mockDecaf, mockKM, "", rdfMultiprover)
		// Try deserializing as TokenDeploy
		pbDeploy := &protobufs.TokenDeploy{}
		_ = pbDeploy.FromCanonicalBytes(data)
		if pbDeploy != nil && pbDeploy.Config != nil {
			_, _ = token.TokenConfigurationFromProtobuf(pbDeploy.Config)
		}
	})
}

func setupMockHypergraph(mockHypergraph *mocks.MockHypergraph, mockInclusionProver *mocks.MockInclusionProver) {
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil)
	mockMultiproof := &mocks.MockMultiproof{}
	mockMultiproof.On("FromBytes", mock.Anything).Return(nil).Maybe()
	mockInclusionProver.On("NewMultiproof").Return(mockMultiproof).Maybe()

	// Create test configuration
	config := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Burnable | token.Divisible,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithAuthority,
			Authority: &token.Authority{
				KeyType:   tcrypto.KeyTypeEd448,
				PublicKey: []byte("test-public-key"),
				CanBurn:   true,
			},
		},
		Units:  big.NewInt(100),
		Supply: big.NewInt(1000000),
		Name:   "Mintable Test Token",
		Symbol: "MTEST",
	}

	// Create the metadata tree with valid configuration
	metadataTree := &crypto.VectorCommitmentTree{}
	rdfMultiprover := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, mockInclusionProver)
	configTree, err := token.NewTokenConfigurationMetadata(config, rdfMultiprover)

	tokenDomainBI, _ := poseidon.HashBytes(
		slices.Concat(
			token.TOKEN_PREFIX,
			configTree.Commit(mockInclusionProver, false),
		),
	)

	appAddress := tokenDomainBI.FillBytes(make([]byte, 32))
	metadataAddress := make([]byte, 64)
	copy(metadataAddress[:32], appAddress)
	mockHypergraph.On("GetVertex", mock.Anything).Return(hypergraph.NewVertex([32]byte{}, [32]byte{}, []byte{}, big.NewInt(0)), nil)

	// Store consensus tree
	consensus := &crypto.VectorCommitmentTree{}
	consensusData, _ := crypto.SerializeNonLazyTree(consensus)
	metadataTree.Insert([]byte{0 << 2}, consensusData, nil, big.NewInt(int64(len(consensusData))))

	// Store sumcheck tree
	sumcheck := &crypto.VectorCommitmentTree{}
	sumcheckData, _ := crypto.SerializeNonLazyTree(sumcheck)
	metadataTree.Insert([]byte{1 << 2}, sumcheckData, nil, big.NewInt(int64(len(sumcheckData))))

	// Store RDF schema
	rdfschema, err := token.PrepareRDFSchemaFromConfig(appAddress, config)
	if err != nil {
		panic(err)
	}
	metadataTree.Insert([]byte{2 << 2}, []byte(rdfschema), nil, big.NewInt(int64(len(rdfschema))))

	// Store config metadata at the right index
	configBytes, err := crypto.SerializeNonLazyTree(configTree)
	metadataTree.Insert([]byte{16 << 2}, configBytes, nil, big.NewInt(int64(len(configBytes))))

	// Mock the GetVertexData to return our tree
	mockHypergraph.On("GetVertexData", mock.Anything).Return(metadataTree, nil)
}
