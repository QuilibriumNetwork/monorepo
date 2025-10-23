package engines_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/engines"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestHypergraphExecutionEngine_Start(t *testing.T) {
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockHG.On("GetCoveredPrefix").Return([]int{}, nil)
	mockClockStore := new(mocks.MockClockStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	engine, err := engines.NewHypergraphExecutionEngine(
		logger,
		mockHG,
		mockClockStore,
		mockKeyManager,
		mockInclusionProver,
		mockBulletproofProver,
		mockVerEnc,
		mockDecaf,
		engines.ApplicationMode,
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

func TestHypergraphExecutionEngine_ProcessMessage_Deploy(t *testing.T) {
	mockhg := tests.CreateHypergraphWithInclusionProver(&mocks.MockInclusionProver{})
	mockhg.On("GetCoveredPrefix").Return([]int{}, nil)
	hypergraphDeployReq := createHypergraphDeployPayload(t, mockhg)
	vertexAdd := createVertexAddPayload(t, mockhg)
	tests := []struct {
		name        string
		mode        engines.ExecutionMode
		setupMocks  func(*mocks.MockHypergraph, *mocks.MockKeyManager, *mocks.MockBulletproofProver, *mocks.MockInclusionProver)
		message     *protobufs.Message
		address     []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "nil_message",
			mode: engines.ApplicationMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				// No mocks needed
			},
			message:     &protobufs.Message{},
			address:     hypergraph.HYPERGRAPH_BASE_DOMAIN[:], // Use 32-byte address
			wantErr:     true,
			errContains: "invalid message",
		},
		{
			name: "message_payload_too_short",
			mode: engines.ApplicationMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				// No mocks needed
			},
			message: &protobufs.Message{
				Payload: []byte{0x01}, // Less than 4 bytes
			},
			address:     hypergraph.HYPERGRAPH_BASE_DOMAIN[:], // Use 32-byte address
			wantErr:     true,
			errContains: "invalid message",
		},
		{
			name: "hypergraph_deploy_success",
			mode: engines.ApplicationMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				// Mock for deployment
				deployAddr := make([]byte, 32)
				rand.Read(deployAddr)

				// Mock GetProver - required for NewHypergraphIntrinsic
				mockHG.On("GetProver").Return(mockIP).Maybe()

				// Mock for TrackChange
				mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

				// Mock inclusion prover for Commit operations
				mockIP.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe()

				// Mock metadata operations
				mockHG.On("GetMetadata", mock.Anything).Return(nil, errors.New("not found")).Maybe()
				mockHG.On("SetMetadata", mock.Anything, mock.Anything).Return(nil).Maybe()

				// Mock vertex operations
				mockHG.On("GetVertex", mock.Anything).Return(nil, errors.New("not found")).Maybe()
				mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()

				// Mock for HypergraphState operations
				mockTxn := &mockTransaction{}
				mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
				mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
				mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

				// Mock commit
				mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()

				// Mock key manager
				mockKM.On("GetSigningKey").Return(make([]byte, 57), nil).Maybe()
				mockKM.On("Prove", mock.Anything, mock.Anything, mock.Anything).Return([]byte("signature"), nil).Maybe()
			},
			message: &protobufs.Message{
				Address: hypergraph.HYPERGRAPH_BASE_DOMAIN[:],
				Payload: hypergraphDeployReq,
			},
			address: hypergraph.HYPERGRAPH_BASE_DOMAIN[:], // Use 32-byte address
			wantErr: false,
		},
		{
			name: "non_deploy_global_mode",
			mode: engines.GlobalMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				mockHG.On("GetVertex", mock.Anything).Return(nil, nil).Maybe()
				mockHG.On("GetVertexData", mock.Anything).Return(&tries.VectorCommitmentTree{}, nil).Maybe()
			},
			message: &protobufs.Message{
				Payload: vertexAdd,
			},
			address:     hypergraph.HYPERGRAPH_BASE_DOMAIN[:], // Use 32-byte address
			wantErr:     true,
			errContains: "non-deploy messages not allowed in global mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			mockHG := new(mocks.MockHypergraph)
			mockHG.On("GetCoveredPrefix").Return([]int{}, nil).Maybe()
			mockClockStore := new(mocks.MockClockStore)
			mockKeyManager := new(mocks.MockKeyManager)
			mockInclusionProver := new(mocks.MockInclusionProver)
			mockBulletproofProver := new(mocks.MockBulletproofProver)
			mockVerEnc := new(mocks.MockVerifiableEncryptor)
			mockDecaf := new(mocks.MockDecafConstructor)

			tt.setupMocks(mockHG, mockKeyManager, mockBulletproofProver, mockInclusionProver)

			engine, err := engines.NewHypergraphExecutionEngine(
				logger,
				mockHG,
				mockClockStore,
				mockKeyManager,
				mockInclusionProver,
				mockBulletproofProver,
				mockVerEnc,
				mockDecaf,
				tt.mode,
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
				if responses != nil && responses.State != nil {
					err = responses.State.Commit()
				}
				assert.NoError(t, err)
			}

			mockHG.AssertExpectations(t)
			mockKeyManager.AssertExpectations(t)
		})
	}
}

func TestHypergraphExecutionEngine_BundledMessages(t *testing.T) {
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockHG.On("GetCoveredPrefix").Return([]int{}, nil)
	mockClockStore := new(mocks.MockClockStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	// Set up mocks for deployment and operations
	deployAddr := make([]byte, 32)
	rand.Read(deployAddr)

	// Mock GetProver - required for NewHypergraphIntrinsic
	mockHG.On("GetProver").Return(mockInclusionProver).Maybe()

	// Mock inclusion prover for Commit operations
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe()

	// Mock for TrackChange
	mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock for deployment
	mockHG.On("GetMetadata", mock.Anything).Return(nil, errors.New("not found")).Maybe()
	mockHG.On("SetMetadata", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("GetVertex", mock.Anything).Return(nil, errors.New("not found")).Maybe()
	mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock for HypergraphState operations
	mockTxn := &mockTransaction{}
	mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
	mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()
	mockKeyManager.On("GetSigningKey").Return(make([]byte, 57), nil).Maybe()
	mockKeyManager.On("Prove", mock.Anything, mock.Anything, mock.Anything).Return([]byte("signature"), nil).Maybe()
	mockKeyManager.On("ValidateSignature", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

	// Mock for vertex operations - these will be called after the intrinsic is loaded
	mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("RemoveVertex", mock.Anything).Return(nil).Maybe()
	mockHG.On("AddHyperedge", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("RemoveHyperedge", mock.Anything).Return(nil).Maybe()

	// Mock for loading the intrinsic after deploy (for vertex operations)
	mockVertex := new(mocks.MockVertex)
	mockVertex.On("Commit", mock.Anything).Return(make([]byte, 74)).Maybe()
	mockHG.On("GetVertexData", mock.Anything).Return(&tries.VectorCommitmentTree{}, nil).Maybe()
	mockInclusionProver.On("VerifyInclusion", mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

	engine, err := engines.NewHypergraphExecutionEngine(
		logger,
		mockHG,
		mockClockStore,
		mockKeyManager,
		mockInclusionProver,
		mockBulletproofProver,
		mockVerEnc,
		mockDecaf,
		engines.ApplicationMode,
	)
	require.NoError(t, err)

	// Create a bundle with just deploy and token operation
	// We'll test vertex operations separately since they need the deployed address
	bundle := &protobufs.MessageBundle{}
	err = bundle.FromCanonicalBytes(createHypergraphDeployPayload(t, mockHG))
	require.NoError(t, err)

	tokenOp := createTokenDeployPayloadFull(t, mockHG) // Non-hypergraph operation
	bundle.Requests = append(bundle.Requests, tokenOp.Requests...)

	bundleBytes, err := bundle.ToCanonicalBytes()
	require.NoError(t, err)

	// Create bundle message
	bundleMsg := &protobufs.Message{
		Address: hypergraph.HYPERGRAPH_BASE_DOMAIN[:],
		Payload: bundleBytes,
	}

	// Set hash
	hash := sha3.Sum256(bundleMsg.Payload)
	bundleMsg.Hash = hash[:]

	// Process bundle
	state := hgstate.NewHypergraphState(mockHG)
	responses, err := engine.ProcessMessage(1, big.NewInt(1), hypergraph.HYPERGRAPH_BASE_DOMAIN[:], bundleMsg.Payload, state)
	assert.NoError(t, err)
	assert.NotNil(t, responses)
	if responses != nil && responses.State != nil {
		err = responses.State.Commit()
	}
	assert.NoError(t, err)
}

func TestHypergraphExecutionEngine_AllOperationTypes(t *testing.T) {
	tests := []struct {
		name          string
		operationType string
		payload       func(t *testing.T, mockHG *mocks.MockHypergraph) []byte
		mode          engines.ExecutionMode
		shouldWork    bool
	}{
		{
			name:          "hypergraph_deploy",
			operationType: "HypergraphDeploy",
			payload:       createHypergraphDeployPayload,
			mode:          engines.ApplicationMode,
			shouldWork:    true,
		},
		{
			name:          "vertex_add",
			operationType: "VertexAdd",
			payload:       createVertexAddPayload,
			mode:          engines.ApplicationMode,
			shouldWork:    true,
		},
		{
			name:          "vertex_remove",
			operationType: "VertexRemove",
			payload:       createVertexRemovePayload,
			mode:          engines.ApplicationMode,
			shouldWork:    true,
		},
		{
			name:          "hyperedge_add",
			operationType: "HyperedgeAdd",
			payload:       createHyperedgeAddPayload,
			mode:          engines.ApplicationMode,
			shouldWork:    true,
		},
		{
			name:          "hyperedge_remove",
			operationType: "HyperedgeRemove",
			payload:       createHyperedgeRemovePayload,
			mode:          engines.ApplicationMode,
			shouldWork:    true,
		},
		{
			name:          "vertex_add_global_mode_fails",
			operationType: "VertexAdd",
			payload:       createVertexAddPayload,
			mode:          engines.GlobalMode,
			shouldWork:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			mockHG := new(mocks.MockHypergraph)
			mockHG.On("GetCoveredPrefix").Return([]int{}, nil)
			mockClockStore := new(mocks.MockClockStore)
			mockKeyManager := new(mocks.MockKeyManager)
			mockInclusionProver := new(mocks.MockInclusionProver)
			mockBulletproofProver := new(mocks.MockBulletproofProver)
			mockVerEnc := new(mocks.MockVerifiableEncryptor)
			mockDecaf := new(mocks.MockDecafConstructor)
			// Mock GetProver - required for NewHypergraphIntrinsic
			mockHG.On("GetProver").Return(mockInclusionProver).Maybe()

			// Set up mocks based on operation type
			if tt.shouldWork {

				// Mock inclusion prover for Commit operations
				mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe()
				// Mock for TrackChange
				mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

				if tt.operationType == "HypergraphDeploy" {
					mockHG.On("GetMetadata", mock.Anything).Return(nil, errors.New("not found")).Maybe()
					mockHG.On("SetMetadata", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("GetVertex", mock.Anything).Return(nil, errors.New("not found")).Maybe()
					mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()

					// Mock for HypergraphState operations
					mockTxn := &mockTransaction{}
					mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
					mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

					mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()
					mockKeyManager.On("GetSigningKey").Return(make([]byte, 57), nil).Maybe()
					mockKeyManager.On("Prove", mock.Anything, mock.Anything, mock.Anything).Return([]byte("signature"), nil).Maybe()
				} else {
					// For other operations, mock loading existing intrinsic
					// Create a proper metadata tree structure
					metadataTree := &tries.VectorCommitmentTree{}

					// Create hypergraph configuration metadata subtree
					configTree := &tries.VectorCommitmentTree{}
					// Add read key at index 0
					configTree.Insert([]byte{0 << 2}, make([]byte, 57), nil, big.NewInt(57))
					// Add write key at index 1
					configTree.Insert([]byte{1 << 2}, make([]byte, 57), nil, big.NewInt(57))

					// Serialize the config tree
					configBytes, _ := tries.SerializeNonLazyTree(configTree)

					// Insert config tree at index 16 (0x40)
					metadataTree.Insert([]byte{16 << 2}, configBytes, nil, big.NewInt(int64(len(configBytes))))

					// Also add empty consensus metadata at index 0
					consensusTree := &tries.VectorCommitmentTree{}
					consensusBytes, _ := tries.SerializeNonLazyTree(consensusTree)
					metadataTree.Insert([]byte{0 << 2}, consensusBytes, nil, big.NewInt(int64(len(consensusBytes))))

					// Add empty sumcheck info at index 1
					sumcheckTree := &tries.VectorCommitmentTree{}
					sumcheckBytes, _ := tries.SerializeNonLazyTree(sumcheckTree)
					metadataTree.Insert([]byte{1 << 2}, sumcheckBytes, nil, big.NewInt(int64(len(sumcheckBytes))))

					// Add RDF schema at index 2
					rdfSchema := []byte(`PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX test: <http://example.com/test#>
test:TestClass a rdfs:Class.`)
					metadataTree.Insert([]byte{2 << 2}, rdfSchema, nil, big.NewInt(int64(len(rdfSchema))))

					mockVertex := new(mocks.MockVertex)
					mockVertex.On("Commit", mock.Anything).Return(make([]byte, 74)).Maybe()
					mockVertex.On("GetSize").Return(big.NewInt(100)).Maybe()
					mockHG.On("GetVertex", mock.Anything).Return(mockVertex, nil).Maybe()
					mockHG.On("GetVertexData", mock.Anything).Return(metadataTree, nil).Maybe()
					mockInclusionProver.On("VerifyInclusion", mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
					mockInclusionProver.On("Commit", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(make([]byte, 74), nil).Maybe()
					mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("RemoveVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("AddHyperedge", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("RemoveHyperedge", mock.Anything, mock.Anything).Return(nil).Maybe()
					mockHG.On("MarkVertexDataForDeletion", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

					// Mock for hyperedge operations
					mockHyperedge := new(mocks.MockHyperedge)
					mockHyperedge.On("GetExtrinsicTree").Return(&tries.VectorCommitmentTree{}, nil).Maybe()
					mockHyperedge.On("GetID").Return([64]byte{}).Maybe()
					mockHyperedge.On("GetSize").Return(big.NewInt(100)).Maybe()
					mockHG.On("GetHyperedge", mock.Anything).Return(mockHyperedge, nil).Maybe()

					// Mock transaction operations
					mockTxn := &mockTransaction{}
					mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
					mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

					// Mock commit operations - Commit() returns [][]byte
					mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()

					mockKeyManager.On("GetSigningKey").Return(make([]byte, 57), nil).Maybe()
					mockKeyManager.On("ValidateSignature", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

					// Mock for verenc deserializtion
					proof := &mocks.MockVerEncProof{}
					proof.On("GetEncryptionKey").Return(make([]byte, 57))
					proof.On("Verify").Return(true)
					proof.On("ToBytes").Return(make([]byte, 1100))
					ve := &mocks.MockVerEnc{}
					ve.On("ToBytes").Return(make([]byte, 1000))
					ve.On("GetStatement").Return(make([]byte, 57))
					proof.On("Compress").Return(ve)
					mockVerEnc.On("ProofFromBytes", mock.Anything).Return(proof)
				}
			}

			if tt.name == "vertex_add_global_mode_fails" {
				// Needs to not return an error so it can fail the deploy check
				mockHG.On("GetVertex", mock.Anything).Return(nil, nil).Maybe()
			}

			engine, err := engines.NewHypergraphExecutionEngine(
				logger,
				mockHG,
				mockClockStore,
				mockKeyManager,
				mockInclusionProver,
				mockBulletproofProver,
				mockVerEnc,
				mockDecaf,
				tt.mode,
			)
			require.NoError(t, err)

			// Create message
			testAddr := make([]byte, 32) // Use 32-byte address
			rand.Read(testAddr)
			if tt.name == "hypergraph_deploy" {
				testAddr = hypergraph.HYPERGRAPH_BASE_DOMAIN[:]
			}

			msg := &protobufs.Message{
				Address: testAddr,
				Payload: tt.payload(t, mockHG),
			}

			// Process message
			state := hgstate.NewHypergraphState(mockHG)
			responses, err := engine.ProcessMessage(1, big.NewInt(1), testAddr, msg.Payload, state)

			if tt.shouldWork {
				assert.NoError(t, err)
				assert.NotNil(t, responses)
				if responses != nil && responses.State != nil {
					err = responses.State.Commit()
				}
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "non-deploy messages not allowed in global mode")
			}
		})
	}
}

// Helper functions
func createHypergraphDeployPayload(t *testing.T, mockHG *mocks.MockHypergraph) []byte {
	deploy := &hypergraph.HypergraphDeployArguments{
		Config: &hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
		},
		RDFSchema: []byte(`PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX test: <http://example.com/test#>
test:TestClass a rdfs:Class.`),
	}

	outFees := []*big.Int{big.NewInt(1)}
	total := big.NewInt(10000000)
	outFees = append(outFees, total)

	payment, err := tests.CreateValidQUILPendingTransactionPayload(
		mockHG,
		1,
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[]*big.Int{big.NewInt(10000001)},
		[]*big.Int{big.NewInt(0)},
		outFees,
		0,
	)
	if err != nil {
		panic(err)
	}
	msg, _ := (&protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_HypergraphDeploy{
					HypergraphDeploy: deploy.ToProtobuf(),
				},
			},
		},
	}).ToCanonicalBytes()
	return msg
}

func createVertexAddPayload(t *testing.T, mockHG *mocks.MockHypergraph) []byte {
	domain := [32]byte{}
	rand.Read(domain[:])

	dataAddr := [32]byte{}
	rand.Read(dataAddr[:])

	proof := &mocks.MockVerEncProof{}
	proof.On("ToBytes").Return(make([]byte, 1100))

	verenc := &mocks.MockVerifiableEncryptor{}
	verenc.On("Encrypt", mock.Anything, mock.Anything).Return([]crypto.VerEncProof{proof})
	signer, _ := keys.NewEd448Key()
	vertexAdd := hypergraph.NewVertexAdd(
		domain,
		[32]byte(dataAddr),
		make([]byte, 111),
		signer.Public().([]byte),
		nil,
		signer,
		&hypergraph.HypergraphIntrinsicConfiguration{
			ReadPublicKey:  make([]byte, 57),
			WritePublicKey: make([]byte, 57),
		},
		verenc,
		nil,
	)

	err := vertexAdd.Prove(1)
	assert.NoError(t, err)

	add, err := vertexAdd.ToProtobuf()
	assert.NoError(t, err)

	outFees := []*big.Int{big.NewInt(1)}
	total := big.NewInt(10000000)
	outFees = append(outFees, total)

	payment, err := tests.CreateValidQUILPendingTransactionPayload(
		mockHG,
		1,
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[]*big.Int{big.NewInt(10000001)},
		[]*big.Int{big.NewInt(0)},
		outFees,
		0,
	)
	if err != nil {
		panic(err)
	}
	msg, _ := (&protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_VertexAdd{
					VertexAdd: add,
				},
			},
		},
	}).ToCanonicalBytes()
	return msg
}

func createVertexRemovePayload(t *testing.T, mockHG *mocks.MockHypergraph) []byte {
	domain := [32]byte{}
	rand.Read(domain[:])

	dataAddr := [32]byte{}
	rand.Read(dataAddr[:])

	vertexRemove := &hypergraph.VertexRemove{
		Domain:      domain,
		DataAddress: [32]byte(dataAddr),
		Signature:   make([]byte, 114),
	}

	outFees := []*big.Int{big.NewInt(1)}
	total := big.NewInt(10000000)
	outFees = append(outFees, total)

	payment, err := tests.CreateValidQUILPendingTransactionPayload(
		mockHG,
		1,
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[]*big.Int{big.NewInt(10000001)},
		[]*big.Int{big.NewInt(0)},
		outFees,
		0,
	)
	if err != nil {
		panic(err)
	}
	msg, _ := (&protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_VertexRemove{
					VertexRemove: vertexRemove.ToProtobuf(),
				},
			},
		},
	}).ToCanonicalBytes()
	return msg
}

func createHyperedgeAddPayload(t *testing.T, mockHG *mocks.MockHypergraph) []byte {
	vertexDomain := [32]byte{}
	rand.Read(vertexDomain[:])

	vertexDataAddr := [32]byte{}
	rand.Read(vertexDataAddr[:])

	domain := [32]byte{}
	rand.Read(domain[:])

	dataAddr := [32]byte{}
	rand.Read(dataAddr[:])

	hyperedge := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(dataAddr))
	hyperedge.AddExtrinsic(hgcrdt.NewVertex([32]byte(vertexDomain), [32]byte(vertexDataAddr), make([]byte, 74), big.NewInt(64)))

	hyperedgeAdd := &hypergraph.HyperedgeAdd{
		Domain:    domain,
		Value:     hyperedge,
		Signature: make([]byte, 114),
	}

	ha, _ := hyperedgeAdd.ToProtobuf()
	outFees := []*big.Int{big.NewInt(1)}
	total := big.NewInt(10000000)
	outFees = append(outFees, total)

	payment, err := tests.CreateValidQUILPendingTransactionPayload(
		mockHG,
		1,
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[]*big.Int{big.NewInt(10000001)},
		[]*big.Int{big.NewInt(0)},
		outFees,
		0,
	)
	if err != nil {
		panic(err)
	}
	msg, _ := (&protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_HyperedgeAdd{
					HyperedgeAdd: ha,
				},
			},
		},
	}).ToCanonicalBytes()
	return msg
}

func createHyperedgeRemovePayload(t *testing.T, mockHG *mocks.MockHypergraph) []byte {
	vertexDomain := [32]byte{}
	rand.Read(vertexDomain[:])

	vertexDataAddr := [32]byte{}
	rand.Read(vertexDataAddr[:])

	domain := [32]byte{}
	rand.Read(domain[:])

	dataAddr := [32]byte{}
	rand.Read(dataAddr[:])

	hyperedge := hgcrdt.NewHyperedge([32]byte(domain), [32]byte(dataAddr))
	hyperedge.AddExtrinsic(hgcrdt.NewVertex([32]byte(vertexDomain), [32]byte(vertexDataAddr), make([]byte, 74), big.NewInt(64)))

	hyperedgeRemove := &hypergraph.HyperedgeRemove{
		Domain:    domain,
		Value:     hyperedge,
		Signature: make([]byte, 114),
	}

	hr, _ := hyperedgeRemove.ToProtobuf()
	outFees := []*big.Int{big.NewInt(1)}
	total := big.NewInt(10000000)
	outFees = append(outFees, total)

	payment, err := tests.CreateValidQUILPendingTransactionPayload(
		mockHG,
		1,
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[][]byte{make([]byte, 56)},
		[]*big.Int{big.NewInt(10000001)},
		[]*big.Int{big.NewInt(0)},
		outFees,
		0,
	)
	if err != nil {
		panic(err)
	}
	msg, _ := (&protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_HyperedgeRemove{
					HyperedgeRemove: hr,
				},
			},
		},
	}).ToCanonicalBytes()
	return msg
}
