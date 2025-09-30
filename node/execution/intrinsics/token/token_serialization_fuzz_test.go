package token_test

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

// FuzzRecipientBundleSerialization tests RecipientBundle serialization/deserialization
func FuzzRecipientBundleSerialization(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0x01, 0x02, 0x03}, []byte{0x04, 0x05, 0x06}, []byte{0x07, 0x08, 0x09}, []byte{0x0a, 0x0b, 0x0c}, []byte{}, []byte{})
	f.Add(make([]byte, 32), make([]byte, 57), make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 57))
	f.Add(make([]byte, 57), make([]byte, 57), make([]byte, 16), make([]byte, 16), []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, oneTimeKey, verificationKey, coinBalance, mask, addRef, addRefKey []byte) {
		// Create recipient bundle with fuzz data
		rb := &token.RecipientBundle{
			OneTimeKey:             oneTimeKey,
			VerificationKey:        verificationKey,
			CoinBalance:            coinBalance,
			Mask:                   mask,
			AdditionalReference:    addRef,
			AdditionalReferenceKey: addRefKey,
		}

		// Serialize
		data, err := rb.ToBytes()
		if err != nil {
			// Serialization can fail for invalid inputs, which is expected
			return
		}

		// Deserialize
		rb2 := &token.RecipientBundle{}
		err = rb2.FromBytes(data)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			require.Equal(t, rb.OneTimeKey, rb2.OneTimeKey)
			require.Equal(t, rb.VerificationKey, rb2.VerificationKey)
			require.Equal(t, rb.CoinBalance, rb2.CoinBalance)
			require.Equal(t, rb.Mask, rb2.Mask)
			require.Equal(t, rb.AdditionalReference, rb2.AdditionalReference)
			require.Equal(t, rb.AdditionalReferenceKey, rb2.AdditionalReferenceKey)
		}
		// If deserialization fails, that's acceptable for malformed input
	})
}

// FuzzTransactionOutputSerialization tests TransactionOutput serialization/deserialization
func FuzzTransactionOutputSerialization(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0x01}, []byte{0x02}, []byte{0x03}, []byte{0x04}, []byte{0x05}, []byte{0x06})
	f.Add(make([]byte, 8), make([]byte, 74), make([]byte, 32), make([]byte, 57), make([]byte, 32), make([]byte, 32))

	f.Fuzz(func(t *testing.T, frameNumber, commitment, oneTimeKey, verificationKey, coinBalance, mask []byte) {
		// Create transaction output with fuzz data
		output := &token.TransactionOutput{
			FrameNumber: frameNumber,
			Commitment:  commitment,
			RecipientOutput: token.RecipientBundle{
				OneTimeKey:      oneTimeKey,
				VerificationKey: verificationKey,
				CoinBalance:     coinBalance,
				Mask:            mask,
			},
		}

		// Serialize
		data, err := output.ToBytes()
		if err != nil {
			// Serialization can fail for invalid inputs
			return
		}

		// Deserialize
		output2 := &token.TransactionOutput{}
		err = output2.FromBytes(data)

		// If deserialization succeeds, verify round-trip
		if err == nil {
			require.Equal(t, output.FrameNumber, output2.FrameNumber)
			require.Equal(t, output.Commitment, output2.Commitment)
			require.Equal(t, output.RecipientOutput.OneTimeKey, output2.RecipientOutput.OneTimeKey)
			require.Equal(t, output.RecipientOutput.VerificationKey, output2.RecipientOutput.VerificationKey)
			require.Equal(t, output.RecipientOutput.CoinBalance, output2.RecipientOutput.CoinBalance)
			require.Equal(t, output.RecipientOutput.Mask, output2.RecipientOutput.Mask)
		}
	})
}

// FuzzTransactionInputSerialization tests TransactionInput serialization/deserialization
func FuzzTransactionInputSerialization(f *testing.F) {
	// Add seed corpus with various lengths
	f.Add([]byte{0x01}, []byte{0x02}, 0)
	f.Add(make([]byte, 74), make([]byte, 114), 3)

	f.Fuzz(func(t *testing.T, commitment, signature []byte, numProofs int) {
		// Limit proofs to reasonable number
		if numProofs < 0 || numProofs > 100 {
			return
		}

		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		// Create transaction input with fuzz data
		input := &token.TransactionInput{
			Commitment: commitment,
			Signature:  signature,
			Proofs:     make([][]byte, numProofs),
		}

		// Generate random proofs
		for i := 0; i < numProofs; i++ {
			input.Proofs[i] = make([]byte, 32)
		}

		// Serialize
		data, err := input.ToBytes()
		if err != nil {
			return
		}

		// Deserialize
		input2 := &token.TransactionInput{}
		err = input2.FromBytes(data)

		// If deserialization succeeds, verify basic fields
		if err == nil {
			require.Equal(t, input.Commitment, input2.Commitment)
			require.Equal(t, input.Signature, input2.Signature)
			require.Equal(t, len(input.Proofs), len(input2.Proofs))
		}
	})
}

// FuzzTokenConfigurationSerialization tests TokenConfiguration serialization/deserialization
func FuzzTokenConfigurationSerialization(f *testing.F) {
	// Add seed corpus
	f.Add("Token", "TKN", uint16(1), int64(100), int64(1000000))
	f.Add("", "", uint16(0), int64(1), int64(0))
	f.Add("A"+string(make([]byte, 100)), "B", uint16(255), int64(8), int64(^int64(0)>>1))

	f.Fuzz(func(t *testing.T, name, symbol string, behavior uint16, units int64, supply int64) {
		// Skip extremely large inputs
		if len(name) > 10000 || len(symbol) > 10000 {
			t.Skip("Input too large")
		}
		if units < 0 || supply < 0 {
			return // Skip negative values
		}

		config := &token.TokenIntrinsicConfiguration{
			Name:     name,
			Symbol:   symbol,
			Behavior: token.TokenIntrinsicBehavior(behavior),
			Units:    big.NewInt(units),
			Supply:   big.NewInt(supply),
		}

		// Convert to protobuf
		pb := config.ToProtobuf()

		// Serialize using protobuf
		data, err := pb.ToCanonicalBytes()
		if err != nil {
			return
		}

		// Deserialize using protobuf
		pb2 := &protobufs.TokenConfiguration{}
		err = pb2.FromCanonicalBytes(data)
		if err != nil {
			return
		}

		// Convert back from protobuf
		config2, err := token.TokenConfigurationFromProtobuf(pb2)

		// If deserialization succeeds, verify round-trip
		if err == nil && config2 != nil {
			require.Equal(t, config.Name, config2.Name)
			require.Equal(t, config.Symbol, config2.Symbol)
			require.Equal(t, config.Behavior, config2.Behavior)
			if config.Units != nil && config2.Units != nil {
				require.Equal(t, config.Units.Cmp(config2.Units), 0)
			}
			if config.Supply != nil && config2.Supply != nil {
				require.Equal(t, config.Supply.Cmp(config2.Supply), 0)
			}
		}
	})
}

// FuzzDeserializationRobustness tests deserialization with completely random data
func FuzzDeserializationRobustness(f *testing.F) {
	// Add various malformed inputs
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x01}) // Just type prefix
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // Invalid type
	f.Add(bytes.Repeat([]byte{0x00}, 1000))
	f.Add(bytes.Repeat([]byte{0xff}, 1000))

	// Add some structured but potentially malformed data
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{0x41}, 100)...))
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x02}, bytes.Repeat([]byte{0x42}, 200)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test all deserialization functions with random data
		// They should either succeed or fail gracefully without panicking

		// Test TokenConfiguration
		pbConfig := &protobufs.TokenConfiguration{}
		_ = pbConfig.FromCanonicalBytes(data)
		if pbConfig != nil {
			config, _ := token.TokenConfigurationFromProtobuf(pbConfig)
			_ = config
		}

		// Test RecipientBundle
		rb := &token.RecipientBundle{}
		_ = rb.FromBytes(data)

		// Test TransactionOutput
		output := &token.TransactionOutput{}
		_ = output.FromBytes(data)

		// Test TransactionInput
		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		input := &token.TransactionInput{}
		_ = input.FromBytes(data)

		// Test PendingTransactionInput
		ptInput := &token.PendingTransactionInput{}
		_ = ptInput.FromBytes(data)

		// Test PendingTransactionOutput
		ptOutput := &token.PendingTransactionOutput{}
		_ = ptOutput.FromBytes(data)

		// Test MintTransactionInput
		mtInput := &token.MintTransactionInput{}
		_ = mtInput.FromBytes(data)

		// Test MintTransactionOutput
		mtOutput := &token.MintTransactionOutput{}
		_ = mtOutput.FromBytes(data)
	})
}

// Specific deserialization-focused fuzz tests for robustness against malformed inputs
func FuzzRecipientBundle_Deserialization(f *testing.F) {
	// Add valid case
	validRB := &token.RecipientBundle{
		OneTimeKey:             make([]byte, 56),
		VerificationKey:        make([]byte, 56),
		CoinBalance:            make([]byte, 56),
		Mask:                   make([]byte, 56),
		AdditionalReference:    make([]byte, 64), // Can be 0 or 64
		AdditionalReferenceKey: make([]byte, 56), // Can be 0 or 56
	}
	validData, _ := validRB.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	// Add invalid length combinations
	f.Add([]byte{0x00, 0x00, 0x00, 0x10})                         // Invalid OneTimeKey length (16 instead of 56)
	f.Add([]byte{0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x10}) // Valid OneTimeKey, invalid VerificationKey

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		rb := &token.RecipientBundle{}
		_ = rb.FromBytes(data) // Should not panic
	})
}

func FuzzTransactionOutput_Deserialization(f *testing.F) {
	// Add valid case
	validOutput := &token.TransactionOutput{
		FrameNumber: make([]byte, 8),
		Commitment:  make([]byte, 56),
		RecipientOutput: token.RecipientBundle{
			OneTimeKey:      make([]byte, 56),
			VerificationKey: make([]byte, 56),
			CoinBalance:     make([]byte, 56),
			Mask:            make([]byte, 56),
		},
	}
	validData, _ := validOutput.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		output := &token.TransactionOutput{}
		_ = output.FromBytes(data) // Should not panic
	})
}

func FuzzTransactionInput_Deserialization(f *testing.F) {
	// Add valid case
	validInput := &token.TransactionInput{
		Commitment: make([]byte, 56),
		Signature:  make([]byte, 114),
		Proofs:     [][]byte{make([]byte, 32), make([]byte, 32)},
	}
	validData, _ := validInput.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		input := &token.TransactionInput{}
		_ = input.FromBytes(data) // Should not panic
	})
}

func FuzzPendingTransactionInput_Deserialization(f *testing.F) {
	// Add valid case
	validInput := &token.PendingTransactionInput{
		Commitment: make([]byte, 56),
		Signature:  make([]byte, 114),
		Proofs:     [][]byte{make([]byte, 32)},
	}
	validData, _ := validInput.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		input := &token.PendingTransactionInput{}
		_ = input.FromBytes(data) // Should not panic
	})
}

func FuzzPendingTransactionOutput_Deserialization(f *testing.F) {
	// Add valid case
	validOutput := &token.PendingTransactionOutput{
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
	}
	validData, _ := validOutput.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		output := &token.PendingTransactionOutput{}
		_ = output.FromBytes(data) // Should not panic
	})
}

func FuzzMintTransactionInput_Deserialization(f *testing.F) {
	// Add valid case
	validInput := &token.MintTransactionInput{
		Value:                  big.NewInt(1000),
		Commitment:             make([]byte, 56),
		Signature:              make([]byte, 114),
		Proofs:                 [][]byte{make([]byte, 32)},
		AdditionalReference:    make([]byte, 64),
		AdditionalReferenceKey: make([]byte, 56),
	}
	validData, _ := validInput.ToBytes()
	f.Add(validData)

	// Add case without additional reference
	validInputNoRef := &token.MintTransactionInput{
		Value:      big.NewInt(1000),
		Commitment: make([]byte, 56),
		Signature:  make([]byte, 114),
		Proofs:     [][]byte{make([]byte, 32)},
	}
	validDataNoRef, _ := validInputNoRef.ToBytes()
	f.Add(validDataNoRef)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		input := &token.MintTransactionInput{}
		_ = input.FromBytes(data) // Should not panic
	})
}

func FuzzMintTransactionOutput_Deserialization(f *testing.F) {
	// Add valid case
	validOutput := &token.MintTransactionOutput{
		FrameNumber: make([]byte, 8),
		Commitment:  make([]byte, 56),
		RecipientOutput: token.RecipientBundle{
			OneTimeKey:      make([]byte, 56),
			VerificationKey: make([]byte, 56),
			CoinBalance:     make([]byte, 56),
			Mask:            make([]byte, 56),
		},
	}
	validData, _ := validOutput.ToBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 100; i++ {
		f.Add(validData[:i])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		output := &token.MintTransactionOutput{}
		_ = output.FromBytes(data) // Should not panic
	})
}

func FuzzTokenConfiguration_Deserialization(f *testing.F) {
	// Add valid case
	validConfig := &token.TokenIntrinsicConfiguration{
		Name:     "Test Token",
		Symbol:   "TT",
		Behavior: token.TokenIntrinsicBehavior(1),
		Units:    big.NewInt(18),
		Supply:   big.NewInt(1000000),
	}
	pb := validConfig.ToProtobuf()
	validData, _ := pb.ToCanonicalBytes()
	f.Add(validData)

	// Add truncated data
	for i := 0; i < len(validData) && i < 50; i++ {
		f.Add(validData[:i])
	}

	// Add invalid type prefix
	f.Add([]byte{0x00, 0x00, 0x00, 0x99}) // Wrong type prefix

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1000000 {
			t.Skip("Skipping very large input")
		}

		pbConfig := &protobufs.TokenConfiguration{}
		_ = pbConfig.FromCanonicalBytes(data)
		if pbConfig != nil {
			_, _ = token.TokenConfigurationFromProtobuf(pbConfig) // Should not panic
		}
	})
}

func FuzzInvalidLengthFields(f *testing.F) {
	// Add cases with invalid length fields
	f.Add(uint32(0xFFFFFFFF), uint32(0xFFFFFFFF))
	f.Add(uint32(1<<31), uint32(1<<31))
	f.Add(uint32(1000000), uint32(1000000))
	f.Add(uint32(0), uint32(100)) // Zero length with data
	f.Add(uint32(100), uint32(0)) // Data length with zero

	f.Fuzz(func(t *testing.T, len1, len2 uint32) {
		// Create data with potentially overflowing lengths
		buf := new(bytes.Buffer)

		// Write a valid-looking structure with bad lengths
		binary.Write(buf, binary.BigEndian, len1) // OneTimeKey length
		buf.Write(make([]byte, min(int(len1), 100)))
		binary.Write(buf, binary.BigEndian, len2) // VerificationKey length
		buf.Write(make([]byte, min(int(len2), 100)))

		// Try to deserialize - should handle gracefully
		rb := &token.RecipientBundle{}
		_ = rb.FromBytes(buf.Bytes())
	})
}

func FuzzProofArrayHandling(f *testing.F) {
	// Add cases with various proof array sizes
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(1), uint32(32))
	f.Add(uint32(10), uint32(32))
	f.Add(uint32(1000), uint32(32))   // Many proofs
	f.Add(uint32(5), uint32(1000000)) // Large proof size

	f.Fuzz(func(t *testing.T, numProofs, proofSize uint32) {
		// Limit to reasonable values
		if numProofs > 1000 || proofSize > 100000 {
			return
		}

		// Create transaction input with fuzz number of proofs
		buf := new(bytes.Buffer)

		// Write commitment
		binary.Write(buf, binary.BigEndian, uint32(56))
		buf.Write(make([]byte, 56))

		// Write signature
		binary.Write(buf, binary.BigEndian, uint32(114))
		buf.Write(make([]byte, 114))

		// Write proofs
		binary.Write(buf, binary.BigEndian, numProofs)
		for i := uint32(0); i < min32(numProofs, 100); i++ {
			binary.Write(buf, binary.BigEndian, min32(proofSize, 1000))
			buf.Write(make([]byte, min32(proofSize, 1000)))
		}

		// Try to deserialize
		mockHG := new(mocks.MockHypergraph)
		mockIP := new(mocks.MockInclusionProver)
		setupMockHypergraph(mockHG, mockIP)

		input := &token.TransactionInput{}
		_ = input.FromBytes(buf.Bytes())
	})
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
