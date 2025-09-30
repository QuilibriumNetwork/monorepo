package engines_test

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"slices"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/engines"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestGlobalExecutionEngine_Start(t *testing.T) {
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockClockStore := new(mocks.MockClockStore)
	mockShardsStore := new(mocks.MockShardsStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	engine, err := engines.NewGlobalExecutionEngine(
		logger,
		&config.P2PConfig{Network: 99},
		mockHG,
		mockClockStore,
		mockShardsStore,
		mockKeyManager,
		mockInclusionProver,
		mockBulletproofProver,
		mockVerEnc,
		mockDecaf,
	)
	require.NoError(t, err)

	// Test starting and stopping the engine
	errChan := engine.Start()

	// Engine should start without errors
	select {
	case err := <-errChan:
		t.Fatalf("unexpected error from Start: %v", err)
	default:
		// Expected: no immediate error
	}

	// Stop the engine
	<-engine.Stop(false)
}

func TestGlobalExecutionEngine_ProcessMessage(t *testing.T) {
	join, _ := createProverJoinPayload(t).ToCanonicalBytes()

	tests := []struct {
		name        string
		setupMocks  func(*mocks.MockHypergraph, *mocks.MockInclusionProver, *mocks.MockKeyManager)
		message     *protobufs.Message
		address     []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "nil_message",
			setupMocks: func(mockHG *mocks.MockHypergraph, mockIP *mocks.MockInclusionProver, mockKM *mocks.MockKeyManager) {
				// No mocks needed
			},
			message:     &protobufs.Message{Payload: nil},
			address:     intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			wantErr:     true,
			errContains: "invalid message",
		},
		{
			name: "message_payload_too_short",
			setupMocks: func(mockHG *mocks.MockHypergraph, mockIP *mocks.MockInclusionProver, mockKM *mocks.MockKeyManager) {
				// No mocks needed
			},
			message: &protobufs.Message{
				Payload: []byte{0x01}, // Less than 4 bytes
			},
			address:     intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
			wantErr:     true,
			errContains: "invalid message",
		},
		{
			name: "invalid_address",
			setupMocks: func(mockHG *mocks.MockHypergraph, mockIP *mocks.MockInclusionProver, mockKM *mocks.MockKeyManager) {
				// No mocks needed
			},
			message: &protobufs.Message{
				Payload: join,
			},
			address:     []byte("invalid_address"),
			wantErr:     true,
			errContains: "invalid address for global execution engine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			mockHG := new(mocks.MockHypergraph)
			mockClockStore := new(mocks.MockClockStore)
			mockShardsStore := new(mocks.MockShardsStore)
			mockShardsStore.On("GetAppShards", mock.Anything, mock.Anything).Return([]store.ShardInfo{}, nil)
			mockKeyManager := new(mocks.MockKeyManager)
			mockInclusionProver := new(mocks.MockInclusionProver)
			mockBulletproofProver := new(mocks.MockBulletproofProver)
			mockVerEnc := new(mocks.MockVerifiableEncryptor)
			mockDecaf := new(mocks.MockDecafConstructor)

			tt.setupMocks(mockHG, mockInclusionProver, mockKeyManager)

			engine, err := engines.NewGlobalExecutionEngine(
				logger,
				&config.P2PConfig{Network: 99},
				mockHG,
				mockClockStore,
				mockShardsStore,
				mockKeyManager,
				mockInclusionProver,
				mockBulletproofProver,
				mockVerEnc,
				mockDecaf,
			)
			require.NoError(t, err)

			// Process message
			state := hgstate.NewHypergraphState(mockHG)
			responses, err := engine.ProcessMessage(1, big.NewInt(1), tt.address, tt.message.Payload, state)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, responses)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, responses)
				err = responses.State.Commit()
				assert.NoError(t, err)
			}

			mockHG.AssertExpectations(t)
			mockInclusionProver.AssertExpectations(t)
		})
	}
}

func TestGlobalExecutionEngine_AllOperationTypes(t *testing.T) {
	tests := []struct {
		name          string
		operationType string
		payload       func(t *testing.T) *protobufs.MessageRequest
	}{
		{
			name:          "prover_leave",
			operationType: "ProverLeave",
			payload:       createProverLeavePayload,
		},
		{
			name:          "prover_pause",
			operationType: "ProverPause",
			payload:       createProverPausePayload,
		},
		{
			name:          "prover_resume",
			operationType: "ProverResume",
			payload:       createProverResumePayload,
		},
		{
			name:          "prover_confirm",
			operationType: "ProverConfirm",
			payload:       createProverConfirmPayload,
		},
		{
			name:          "prover_reject",
			operationType: "ProverReject",
			payload:       createProverRejectPayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			mockHG := new(mocks.MockHypergraph)
			mockClockStore := new(mocks.MockClockStore)
			mockShardsStore := new(mocks.MockShardsStore)
			mockKeyManager := new(mocks.MockKeyManager)
			mockInclusionProver := new(mocks.MockInclusionProver)
			mockBulletproofProver := new(mocks.MockBulletproofProver)
			mockVerEnc := new(mocks.MockVerifiableEncryptor)
			mockDecaf := new(mocks.MockDecafConstructor)

			// Set up mocks for loading global intrinsic
			mockInclusionProver.On("VerifyInclusion", mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
			mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 64), nil).Maybe()

			// Mock for InvokeStep
			mockHG.On("GetVertex", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x23, 0x4d, 0x4b, 0x38, 0xe3, 0xcd, 0xc8, 0x11, 0xce, 0x82, 0xd3, 0x92, 0x9b, 0xe1, 0xbd, 0x48, 0x8c, 0x23, 0x41, 0xf6, 0xa6, 0xb8, 0xf5, 0xa1, 0x10, 0x1, 0x82, 0xe6, 0xd, 0x2, 0x6a, 0x78}).Return(nil, nil).Maybe()
			// Running balance for prover check
			mockHG.On("GetVertex", [64]uint8{0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9, 0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64, 0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb, 0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9, 0x23, 0x4d, 0x4b, 0x38, 0xe3, 0xcd, 0xc8, 0x11, 0xce, 0x82, 0xd3, 0x92, 0x9b, 0xe1, 0xbd, 0x48, 0x8c, 0x23, 0x41, 0xf6, 0xa6, 0xb8, 0xf5, 0xa1, 0x10, 0x1, 0x82, 0xe6, 0xd, 0x2, 0x6a, 0x78}).Return(nil, errors.New("not found")).Maybe()

			// Mock for TrackChange
			mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

			// Filter1 allocation
			mockHG.On("GetVertex", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x25, 0xc2, 0x6f, 0xc, 0x1, 0x45, 0x1, 0xf2, 0x4e, 0x2d, 0xfd, 0x87, 0x1, 0xd8, 0x2e, 0x98, 0x82, 0x6a, 0x3e, 0x71, 0x0, 0x1a, 0xdd, 0x0, 0xbb, 0xf2, 0x5c, 0xe9, 0xa9, 0x97, 0x46, 0xf5}).Return(nil, errors.New("not found")).Maybe()
			// Filter2 allocation
			mockHG.On("GetVertex", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8, 0x96, 0xcc, 0xcc, 0xd4, 0xc9, 0x26, 0xf8, 0x54, 0xa4, 0xc8, 0x5f, 0x35, 0xeb, 0xc8, 0xda, 0x2c, 0x17, 0xe2, 0x28, 0x1c, 0xb5, 0x7c, 0x5c, 0xe2, 0x76, 0x49, 0x6b, 0xc6, 0x2b, 0x8d, 0xcf}).Return(nil, errors.New("not found")).Maybe()
			mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()

			// For prover lookup cases
			mockHG.On("GetVertex", [64]byte(slices.Concat(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x00}, 32)))).Return(&mockVertex{}, nil).Maybe()

			// Mock for GetVertexData - prover does exist
			pubkey := make([]byte, 585)

			// Calculate prover address from pubkey
			addressBI, _ := poseidon.HashBytes(pubkey)
			address := addressBI.FillBytes(make([]byte, 32))
			proverFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], address))

			// Setup prover tree with type hash
			proverTypeBI, _ := poseidon.HashBytes(
				slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("prover:Prover")),
			)
			proverTrie := &tries.VectorCommitmentTree{}
			proverTrie.Insert([]byte{0}, pubkey, nil, big.NewInt(585))
			proverTrie.Insert(bytes.Repeat([]byte{0xff}, 32), proverTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(1))

			if tt.operationType == "ProverLeave" || tt.operationType == "ProverPause" {
				proverTrie.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active

				// Setup allocation tree for resume
				allocationTypeBI, _ := poseidon.HashBytes(
					slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
				)
				filter := []byte("filter1filter1filter1filter1filter1")
				allocTrie := &tries.VectorCommitmentTree{}
				allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
				allocTrie.Insert([]byte{1 << 2}, []byte{1}, nil, big.NewInt(1)) // status = active
				allocTrie.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
				allocTrie.Insert([]byte{4 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDB, 0x40}, nil, big.NewInt(8)) // join frame
				allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

				// Calculate allocation address
				allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
				alloc := allocBI.FillBytes(make([]byte, 32))
				allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

				// Mock allocation vertex data
				mockHG.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
				// Other cases
				mockHG.On("GetVertexData", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x25, 0xc2, 0x6f, 0xc, 0x1, 0x45, 0x1, 0xf2, 0x4e, 0x2d, 0xfd, 0x87, 0x1, 0xd8, 0x2e, 0x98, 0x82, 0x6a, 0x3e, 0x71, 0x0, 0x1a, 0xdd, 0x0, 0xbb, 0xf2, 0x5c, 0xe9, 0xa9, 0x97, 0x46, 0xf5}).Return(nil, errors.New("not found")).Maybe()
			} else if tt.operationType == "ProverConfirm" || tt.operationType == "ProverReject" {
				proverTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1)) // status = joining

				// Setup allocation tree for resume
				allocationTypeBI, _ := poseidon.HashBytes(
					slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
				)
				filter := []byte("filter1filter1filter1filter1filter1")
				allocTrie := &tries.VectorCommitmentTree{}
				allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
				allocTrie.Insert([]byte{1 << 2}, []byte{0}, nil, big.NewInt(1)) // status = joining
				allocTrie.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
				allocTrie.Insert([]byte{4 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDA, 0x30}, nil, big.NewInt(8)) // join frame
				allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

				// Calculate allocation address
				allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
				alloc := allocBI.FillBytes(make([]byte, 32))
				allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

				// Mock allocation vertex data
				mockHG.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
			} else if tt.operationType == "ProverResume" {
				proverTrie.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused

				// Setup allocation tree for resume
				allocationTypeBI, _ := poseidon.HashBytes(
					slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte("allocation:ProverAllocation")),
				)
				filter := []byte("filter1filter1filter1filter1filter1")
				allocTrie := &tries.VectorCommitmentTree{}
				allocTrie.Insert([]byte{0}, address, nil, big.NewInt(32))
				allocTrie.Insert([]byte{1 << 2}, []byte{2}, nil, big.NewInt(1)) // status = paused
				allocTrie.Insert([]byte{2 << 2}, filter, nil, big.NewInt(32))
				allocTrie.Insert([]byte{6 << 2}, []byte{0, 0, 0, 0, 0, 3, 0xDB, 0xA7}, nil, big.NewInt(8)) // pause frame = 252839
				allocTrie.Insert(bytes.Repeat([]byte{0xff}, 32), allocationTypeBI.FillBytes(make([]byte, 32)), nil, big.NewInt(32))

				// Calculate allocation address
				allocBI, _ := poseidon.HashBytes(slices.Concat([]byte("PROVER_ALLOCATION"), pubkey, filter))
				alloc := allocBI.FillBytes(make([]byte, 32))
				allocFullAddr := [64]byte(slices.Concat(intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], alloc))

				// Mock allocation vertex data
				mockHG.On("GetVertexData", allocFullAddr).Return(allocTrie, nil).Maybe()
			} else if tt.operationType == "ProverJoin" {
				// Mock for GetVertexData - prover doesn't exist yet
				mockHG.On("GetVertexData", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x25, 0xc2, 0x6f, 0xc, 0x1, 0x45, 0x1, 0xf2, 0x4e, 0x2d, 0xfd, 0x87, 0x1, 0xd8, 0x2e, 0x98, 0x82, 0x6a, 0x3e, 0x71, 0x0, 0x1a, 0xdd, 0x0, 0xbb, 0xf2, 0x5c, 0xe9, 0xa9, 0x97, 0x46, 0xf5}).Return(nil, errors.New("not found")).Maybe()

				mockHG.On("GetVertexData", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8, 0x96, 0xcc, 0xcc, 0xd4, 0xc9, 0x26, 0xf8, 0x54, 0xa4, 0xc8, 0x5f, 0x35, 0xeb, 0xc8, 0xda, 0x2c, 0x17, 0xe2, 0x28, 0x1c, 0xb5, 0x7c, 0x5c, 0xe2, 0x76, 0x49, 0x6b, 0xc6, 0x2b, 0x8d, 0xcf}).Return(nil, errors.New("not found")).Maybe()
			}

			// Mock prover vertex data
			mockHG.On("GetVertex", proverFullAddr).Return(nil, nil).Maybe()
			mockHG.On("GetVertexData", proverFullAddr).Return(proverTrie, nil).Maybe()
			// Keep backward compatibility mocks
			mockHG.On("GetVertexData", [64]uint8(slices.Concat(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x00}, 32)))).Return(proverTrie, nil).Maybe()
			mockHG.On("GetVertexData", [64]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30, 0x5f, 0xf8, 0xd4, 0x32, 0xb6, 0xde, 0xbc, 0xb6, 0xbf, 0x3e, 0xb4, 0x55, 0x4, 0x95, 0x2b, 0x19, 0x8f, 0x31, 0xa3, 0xe5, 0xb4, 0xcf, 0xb2, 0x63, 0xb7, 0xdc, 0x70, 0x42, 0x90, 0x22, 0x7e}).Return(proverTrie, nil).Maybe()

			// Mock for SetVertexData - setting new prover data (transaction, ID, tree)
			mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

			// Mock for GetHyperedge - hyperedge doesn't exist yet
			mockHG.On("GetHyperedge", mock.Anything).Return(nil, errors.New("not found")).Maybe()

			// Mock for SetHyperedge - setting new hyperedge data
			mockHG.On("SetHyperedge", mock.Anything, mock.Anything).Return(nil).Maybe()

			// Mock for GetProver - required for Commit operations
			mockHG.On("GetProver").Return(mockInclusionProver).Maybe()

			// Mock key manager for signature validation
			mockKeyManager.On("ValidateSignature", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

			// Mock for transaction operations
			mockTxn := &mockTransaction{}
			mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
			mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
			mockHG.On("AddHyperedge", mock.Anything, mock.Anything).Return(nil).Maybe()

			// Mock for Commit
			mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{}).Maybe()

			engine, err := engines.NewGlobalExecutionEngine(
				logger,
				&config.P2PConfig{Network: 99},
				mockHG,
				mockClockStore,
				mockShardsStore,
				mockKeyManager,
				mockInclusionProver,
				mockBulletproofProver,
				mockVerEnc,
				mockDecaf,
			)
			require.NoError(t, err)

			payload, err := tt.payload(t).ToCanonicalBytes()
			require.NoError(t, err)

			// Create message
			msg := &protobufs.Message{
				Address: intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
				Payload: payload,
			}

			// Process message
			state := hgstate.NewHypergraphState(mockHG)
			responses, err := engine.ProcessMessage(252840, big.NewInt(1), intrinsics.GLOBAL_INTRINSIC_ADDRESS[:], msg.Payload, state)

			assert.NoError(t, err)
			assert.NotNil(t, responses)
			err = state.Commit()
			assert.NoError(t, err)
		})
	}
}

// Helper functions
func createProverJoinPayload(t *testing.T) *protobufs.MessageRequest {
	join := &global.ProverJoin{
		Filters:     [][]byte{[]byte("filter1filter1filter1filter1filter1"), []byte("filter1filter1filter1filter1filter2")},
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581SignatureWithProofOfPossession{
			PublicKey:    make([]byte, 585),
			Signature:    make([]byte, 74),
			PopSignature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(join.PublicKeySignatureBLS48581.Signature)
	rand.Read(join.PublicKeySignatureBLS48581.PopSignature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Join{
			Join: join.ToProtobuf(),
		},
	}
}

func createProverLeavePayload(t *testing.T) *protobufs.MessageRequest {
	leave := &global.ProverLeave{
		Filters:     [][]byte{[]byte("filter1filter1filter1filter1filter1")},
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(leave.PublicKeySignatureBLS48581.Signature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Leave{
			Leave: leave.ToProtobuf(),
		},
	}
}

func createProverPausePayload(t *testing.T) *protobufs.MessageRequest {
	pause := &global.ProverPause{
		Filter:      []byte("filter1filter1filter1filter1filter1"),
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(pause.PublicKeySignatureBLS48581.Signature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Pause{
			Pause: pause.ToProtobuf(),
		},
	}
}

func createProverResumePayload(t *testing.T) *protobufs.MessageRequest {
	// Use the same pubkey as in the mock setup
	pubkey := make([]byte, 585)

	// Calculate address from pubkey
	addressBI, _ := poseidon.HashBytes(pubkey)
	address := addressBI.FillBytes(make([]byte, 32))

	resume := &global.ProverResume{
		Filter:      []byte("filter1filter1filter1filter1filter1"),
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   address,
			Signature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(resume.PublicKeySignatureBLS48581.Signature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Resume{
			Resume: resume.ToProtobuf(),
		},
	}
}

func createProverConfirmPayload(t *testing.T) *protobufs.MessageRequest {
	confirm := &global.ProverConfirm{
		Filter:      []byte("filter1filter1filter1filter1filter1"),
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(confirm.PublicKeySignatureBLS48581.Signature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Confirm{
			Confirm: confirm.ToProtobuf(),
		},
	}
}

func createProverRejectPayload(t *testing.T) *protobufs.MessageRequest {
	reject := &global.ProverReject{
		Filter:      []byte("filter1filter1filter1filter1filter1"),
		FrameNumber: 1,
		PublicKeySignatureBLS48581: global.BLS48581AddressedSignature{
			Address:   make([]byte, 32),
			Signature: make([]byte, 74),
		},
	}

	// Fill with random data
	rand.Read(reject.PublicKeySignatureBLS48581.Signature)

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Reject{
			Reject: reject.ToProtobuf(),
		},
	}
}

func createTokenDeployPayload(t *testing.T) *protobufs.MessageRequest {
	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_TokenDeploy{
			TokenDeploy: &protobufs.TokenDeploy{
				Config: &protobufs.TokenConfiguration{
					Behavior: uint32(protobufs.TokenIntrinsicBehavior_TOKEN_BEHAVIOR_DIVISIBLE),
					Units:    []byte{0x10},
					Supply:   []byte{0xff, 0xff, 0xff},
					Name:     "foo",
					Symbol:   "foo",
				},
				RdfSchema: []byte{},
			},
		},
	}
}
