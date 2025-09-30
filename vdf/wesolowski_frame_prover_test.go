package vdf_test

import (
	"bytes"
	gcrypto "crypto"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/vdf"
)

func TestMasterProve(t *testing.T) {
	l, _ := zap.NewProduction()
	w := vdf.NewWesolowskiFrameProver(l)
	m, err := w.CreateMasterGenesisFrame([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, bytes.Repeat([]byte{0x00}, 516), 10000)
	assert.NoError(t, err)

	next, err := w.ProveMasterClockFrame(
		m,
		time.Now().UnixMilli(),
		10000,
		[]*protobufs.InclusionAggregateProof{},
	)
	assert.NoError(t, err)
	err = w.VerifyMasterClockFrame(next)
	assert.NoError(t, err)
}

func TestCalculateChallengeProofDifficulty(t *testing.T) {
	l, _ := zap.NewProduction()
	w := vdf.NewWesolowskiFrameProver(l)

	// At 0 increments, the difficulty should be 200,000
	difficulty0 := w.CalculateChallengeProofDifficulty(0)
	assert.Equal(t, uint32(200000), difficulty0)

	// At 100,000 increments, the difficulty should be 175,000
	difficulty100k := w.CalculateChallengeProofDifficulty(100000)
	assert.Equal(t, uint32(175000), difficulty100k)

	// At 700,000 increments, the difficulty should be 25,000
	difficulty700k := w.CalculateChallengeProofDifficulty(700000)
	assert.Equal(t, uint32(25000), difficulty700k)

	// At 800,000 increments, the difficulty should stay at 25,000
	difficulty800k := w.CalculateChallengeProofDifficulty(800000)
	assert.Equal(t, uint32(25000), difficulty800k)
}

func TestProveAndVerifyFrameHeader(t *testing.T) {
	l, _ := zap.NewProduction()
	w := vdf.NewWesolowskiFrameProver(l)

	// Create a mock BLS constructor
	blsConstructor := &MockBlsConstructor{}

	// Create a mock BLS key
	blsKey := &MockBlsSigner{}

	// Create a previous frame
	previousFrame := &protobufs.FrameHeader{
		Address:        []byte("test-address"),
		FrameNumber:    1,
		Timestamp:      time.Now().UnixMilli(),
		Difficulty:     10000,
		Output:         bytes.Repeat([]byte{0x01}, 516),
		ParentSelector: bytes.Repeat([]byte{0x00}, 32),
		RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
		StateRoots: [][]byte{
			bytes.Repeat([]byte{0x03}, 74),
			bytes.Repeat([]byte{0x04}, 74),
			bytes.Repeat([]byte{0x05}, 74),
			bytes.Repeat([]byte{0x06}, 74),
		},
		Prover: bytes.Repeat([]byte{0x07}, 32),
	}

	// Test parameters
	address := []byte("test-address")
	requestsRoot := bytes.Repeat([]byte{0x08}, 74)
	stateRoots := [][]byte{
		bytes.Repeat([]byte{0x09}, 74),
		bytes.Repeat([]byte{0x0a}, 74),
		bytes.Repeat([]byte{0x0b}, 74),
		bytes.Repeat([]byte{0x0c}, 74),
	}
	prover := bytes.Repeat([]byte{0x0d}, 32)
	timestamp := time.Now().UnixMilli()
	difficulty := uint32(10000)
	proverIndex := uint8(0)

	// Prove frame header
	header, err := w.ProveFrameHeader(
		previousFrame,
		address,
		requestsRoot,
		stateRoots,
		prover,
		blsKey,
		timestamp,
		difficulty,
		10000,
		proverIndex,
	)
	assert.NoError(t, err)
	assert.NotNil(t, header)
	assert.Equal(t, previousFrame.FrameNumber+1, header.FrameNumber)
	assert.Equal(t, timestamp, header.Timestamp)
	assert.Equal(t, difficulty, header.Difficulty)
	assert.Equal(t, address, header.Address)
	assert.Equal(t, requestsRoot, header.RequestsRoot)
	assert.Equal(t, stateRoots, header.StateRoots)
	assert.Equal(t, prover, header.Prover)
	assert.NotNil(t, header.PublicKeySignatureBls48581)

	// Verify frame header
	indices, err := w.VerifyFrameHeader(header, blsConstructor)
	assert.NoError(t, err)
	assert.Equal(t, []uint8{0}, indices)
}

func TestVerifyFrameHeaderValidation(t *testing.T) {
	l, _ := zap.NewProduction()
	w := vdf.NewWesolowskiFrameProver(l)
	blsConstructor := &MockBlsConstructor{}

	tests := []struct {
		name        string
		frame       *protobufs.FrameHeader
		expectError string
	}{
		{
			name: "missing signature",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: bytes.Repeat([]byte{0x07}, 32),
			},
			expectError: "no valid signature provided",
		},
		{
			name: "empty address",
			frame: &protobufs.FrameHeader{
				Address:        []byte{},
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: bytes.Repeat([]byte{0x07}, 32),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid address",
		},
		{
			name: "invalid requests root length",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 73), // Wrong length
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: bytes.Repeat([]byte{0x07}, 32),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid requests root length",
		},
		{
			name: "invalid state roots count",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
				}, // Only 3 roots instead of 4
				Prover: bytes.Repeat([]byte{0x07}, 32),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid state roots count",
		},
		{
			name: "invalid state root length",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 73), // Wrong length
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: bytes.Repeat([]byte{0x07}, 32),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid state root length",
		},
		{
			name: "empty prover",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 516),
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: []byte{}, // Empty prover
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid prover",
		},
		{
			name: "invalid output length",
			frame: &protobufs.FrameHeader{
				Address:        []byte("test"),
				FrameNumber:    1,
				Timestamp:      time.Now().UnixMilli(),
				Difficulty:     10000,
				Output:         bytes.Repeat([]byte{0x01}, 515), // Wrong length
				ParentSelector: bytes.Repeat([]byte{0x00}, 32),
				RequestsRoot:   bytes.Repeat([]byte{0x02}, 74),
				StateRoots: [][]byte{
					bytes.Repeat([]byte{0x03}, 74),
					bytes.Repeat([]byte{0x04}, 74),
					bytes.Repeat([]byte{0x05}, 74),
					bytes.Repeat([]byte{0x06}, 74),
				},
				Prover: bytes.Repeat([]byte{0x07}, 32),
				PublicKeySignatureBls48581: &protobufs.BLS48581AggregateSignature{
					Bitmask:   bytes.Repeat([]byte{0x01}, 32),
					Signature: bytes.Repeat([]byte{0x02}, 74),
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: bytes.Repeat([]byte{0x03}, 585),
					},
				},
			},
			expectError: "invalid output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := w.VerifyFrameHeader(tt.frame, blsConstructor)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestProveFrameHeaderMissingPreviousFrame(t *testing.T) {
	l, _ := zap.NewProduction()
	w := vdf.NewWesolowskiFrameProver(l)
	blsKey := &MockBlsSigner{}

	_, err := w.ProveFrameHeader(
		nil, // Missing previous frame
		[]byte("test"),
		bytes.Repeat([]byte{0x01}, 74),
		[][]byte{
			bytes.Repeat([]byte{0x02}, 74),
			bytes.Repeat([]byte{0x03}, 74),
			bytes.Repeat([]byte{0x04}, 74),
			bytes.Repeat([]byte{0x05}, 74),
		},
		bytes.Repeat([]byte{0x06}, 32),
		blsKey,
		time.Now().UnixMilli(),
		10000,
		10000,
		0,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing header")
}

// Mock implementations for testing

type MockBlsConstructor struct{}

func (m *MockBlsConstructor) New() (crypto.Signer, []byte, error) {
	return &MockBlsSigner{}, bytes.Repeat([]byte{0x01}, 74), nil
}

func (m *MockBlsConstructor) FromBytes(privKey, pubKey []byte) (crypto.Signer, error) {
	return &MockBlsSigner{}, nil
}

func (m *MockBlsConstructor) VerifySignatureRaw(pubKey, signature, message, domain []byte) bool {
	return true // Always return true for testing
}

type MockBlsSigner struct{}

// Sign implements crypto.Signer.
func (m *MockBlsSigner) Sign(rand io.Reader, digest []byte, opts gcrypto.SignerOpts) (signature []byte, err error) {
	return bytes.Repeat([]byte{0x03}, 74), nil
}

func (m *MockBlsSigner) GetType() crypto.KeyType {
	return crypto.KeyTypeBLS48581G2
}

func (m *MockBlsSigner) Public() gcrypto.PublicKey {
	return bytes.Repeat([]byte{0x01}, 585)
}

func (m *MockBlsSigner) Private() []byte {
	return bytes.Repeat([]byte{0x02}, 74)
}

func (m *MockBlsSigner) SignWithDomain(message, domain []byte) ([]byte, error) {
	return bytes.Repeat([]byte{0x03}, 74), nil
}
