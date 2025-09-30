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
	"source.quilibrium.com/quilibrium/monorepo/node/execution/engines"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func newTokenRDFHypergraphSchema(
	appAddress []byte,
	config *token.TokenIntrinsicConfiguration,
) (string, error) {
	schemaDoc, err := token.PrepareRDFSchemaFromConfig(appAddress, config)
	if err != nil {
		return "", errors.Wrap(err, "new token rdf hypergraph schema")
	}

	valid, err := (&schema.TurtleRDFParser{}).Validate(schemaDoc)
	if err != nil {
		return "", errors.Wrap(err, "new token rdf hypergraph schema")
	}

	if !valid {
		return "", errors.Wrap(
			errors.New("invalid schema"),
			"new token rdf hypergraph schema",
		)
	}

	return schemaDoc, nil
}

// Creates a mintable token configuration with authority for testing
func createMintableTestConfig() *token.TokenIntrinsicConfiguration {
	return &token.TokenIntrinsicConfiguration{
		Name:     "Test Token",
		Symbol:   "TEST",
		Supply:   big.NewInt(100000),
		Units:    big.NewInt(10),
		Behavior: token.Acceptable | token.Divisible,
	}
}

func TestTokenExecutionEngine_Start(t *testing.T) {
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockClockStore := new(mocks.MockClockStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	engine, err := engines.NewTokenExecutionEngine(
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

func TestTokenExecutionEngine_ProcessMessage_DeployEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		mode        engines.ExecutionMode
		setupMocks  func(*mocks.MockHypergraph, *mocks.MockKeyManager, *mocks.MockVerifiableEncryptor, *mocks.MockDecafConstructor, *mocks.MockBulletproofProver, *mocks.MockInclusionProver)
		message     *protobufs.Message
		address     []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "nil_message",
			mode: engines.ApplicationMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockVE *mocks.MockVerifiableEncryptor, mockDC *mocks.MockDecafConstructor, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				// No mocks needed
			},
			message:     &protobufs.Message{},
			address:     token.TOKEN_BASE_DOMAIN[:], // Use 32-byte address
			wantErr:     true,
			errContains: "invalid message",
		},
		{
			name: "message_payload_too_short",
			mode: engines.ApplicationMode,
			setupMocks: func(mockHG *mocks.MockHypergraph, mockKM *mocks.MockKeyManager, mockVE *mocks.MockVerifiableEncryptor, mockDC *mocks.MockDecafConstructor, mockBP *mocks.MockBulletproofProver, mockIP *mocks.MockInclusionProver) {
				// No mocks needed
			},
			message: &protobufs.Message{
				Payload: []byte{0x01}, // Less than 4 bytes
			},
			address:     token.TOKEN_BASE_DOMAIN[:], // Use 32-byte address
			wantErr:     true,
			errContains: "invalid message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zap.NewNop()
			mockHG := new(mocks.MockHypergraph)
			mockClockStore := new(mocks.MockClockStore)
			mockKeyManager := new(mocks.MockKeyManager)
			mockInclusionProver := new(mocks.MockInclusionProver)
			mockBulletproofProver := new(mocks.MockBulletproofProver)
			mockVerEnc := new(mocks.MockVerifiableEncryptor)
			mockDecaf := new(mocks.MockDecafConstructor)

			tt.setupMocks(mockHG, mockKeyManager, mockVerEnc, mockDecaf, mockBulletproofProver, mockInclusionProver)

			engine, err := engines.NewTokenExecutionEngine(
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
				err = responses.State.Commit()
				assert.NoError(t, err)
			}
		})
	}
}

func TestTokenExecutionEngine_BundledMessages(t *testing.T) {
	t.Skip("something weird about payment setup")
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockClockStore := new(mocks.MockClockStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	// Mock GetProver - required for hypergraph state initialization
	mockHG.On("GetProver").Return(mockInclusionProver).Maybe()

	// Mock inclusion prover for CommitRaw operations
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 64), nil).Maybe()

	// Mock transaction operations
	mockTxn := &mockTransaction{}
	mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
	mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock for TrackChange
	mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock commit - should return [][]byte
	mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()

	// Set up the mock to return not found for token transactions (LoadTokenIntrinsic)
	mockHG.On("GetVertex", [64]byte{0xb, 0x8d, 0xa5, 0x37, 0xba, 0x80, 0x77, 0x1, 0x23, 0x9, 0xc6, 0x53, 0x32, 0xd2, 0xbb, 0x4b, 0x6c, 0xc6, 0x8e, 0x6e, 0x61, 0x60, 0xbd, 0xa, 0xa1, 0x98, 0xe8, 0x7f, 0xa8, 0x1c, 0x65, 0xd5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}).Return(nil, errors.New("not found")).Maybe()

	// Mock for deployment
	mockKeyManager.On("Prove", mock.Anything, mock.Anything, mock.Anything).Return([]byte("signature"), nil).Maybe()
	mockBulletproofProver.On("GenerateRangeProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("proof"), nil).Maybe()
	mockBulletproofProver.On("ProveCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("proof"), nil).Maybe()
	mockBulletproofProver.On("VerifyHidden", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	mockBulletproofProver.On("VerifyRangeProof", mock.Anything, mock.Anything, mock.Anything).Return(true)
	mockBulletproofProver.On("SumCheck", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	mockVerEnc.On("GenerateKeyPair").Return(make([]byte, 57), make([]byte, 57), nil).Maybe()

	engine, err := engines.NewTokenExecutionEngine(
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

	// Create a bundle with just deploy and a payment
	// We'll test vertex operations separately since they need the deployed address
	tokenDeploy := createTokenDeployPayloadFull(t, mockHG)
	require.NoError(t, err)

	bundleBytes, err := tokenDeploy.ToCanonicalBytes()
	require.NoError(t, err)

	// Create bundle message
	bundleMsg := &protobufs.Message{
		Address: token.TOKEN_BASE_DOMAIN[:],
		Payload: bundleBytes,
	}

	// Set hash
	hashBI, err := poseidon.HashBytes(bundleMsg.Payload)
	require.NoError(t, err)
	bundleMsg.Hash = hashBI.FillBytes(make([]byte, 32))

	// Process bundle
	state := hgstate.NewHypergraphState(mockHG)
	responses, err := engine.ProcessMessage(1, big.NewInt(1), token.TOKEN_BASE_DOMAIN[:], bundleMsg.Payload, state)
	assert.NoError(t, err)
	assert.NotNil(t, responses)
	err = responses.State.Commit()
	assert.NoError(t, err)
}

func TestTokenExecutionEngine_ModeSwitch(t *testing.T) {
	// Test that GlobalMode properly restricts operations after deployment
	logger := zap.NewNop()
	mockHG := new(mocks.MockHypergraph)
	mockClockStore := new(mocks.MockClockStore)
	mockKeyManager := new(mocks.MockKeyManager)
	mockInclusionProver := new(mocks.MockInclusionProver)
	mockBulletproofProver := new(mocks.MockBulletproofProver)
	mockVerEnc := new(mocks.MockVerifiableEncryptor)
	mockDecaf := new(mocks.MockDecafConstructor)

	// Create test address
	testAddr := make([]byte, 32)
	rand.Read(testAddr)
	vertexAddr := [64]byte(slices.Concat(testAddr, bytes.Repeat([]byte{0xff}, 32)))

	// First, test that we can deploy in global mode
	mockHG.On("GetVertex", mock.Anything).Return(nil, errors.New("not found")).Maybe()

	// Mock GetProver - required for hypergraph state initialization
	mockHG.On("GetProver").Return(mockInclusionProver).Maybe()

	// Mock inclusion prover for CommitRaw operations
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(make([]byte, 64), nil).Maybe()

	// Mock transaction operations
	mockTxn := &mockTransaction{}
	mockHG.On("NewTransaction", mock.Anything).Return(mockTxn, nil).Maybe()
	mockHG.On("AddVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("SetVertexData", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock for TrackChange
	mockHG.On("TrackChange", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	mockHG.On("GetMetadata", mock.Anything).Return(nil, errors.New("not found")).Maybe()
	mockHG.On("SetMetadata", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("SetVertex", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockHG.On("Commit").Return(map[tries.ShardKey][][]byte{tries.ShardKey{L1: [3]byte{}, L2: [32]byte{}}: [][]byte{make([]byte, 74), make([]byte, 74), make([]byte, 74), make([]byte, 74)}}).Maybe()
	mockKeyManager.On("Prove", mock.Anything, mock.Anything, mock.Anything).Return([]byte("signature"), nil).Maybe()
	mockVerEnc.On("GenerateKeyPair").Return(make([]byte, 57), make([]byte, 57), nil).Maybe()
	mockBulletproofProver.On("ProveCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("proof"), nil).Maybe()
	mockBulletproofProver.On("VerifyHidden", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true).Maybe()
	mockBulletproofProver.On("VerifyRangeProof", mock.Anything, mock.Anything, mock.Anything).Return(true)
	mockBulletproofProver.On("SumCheck", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)

	globalEngine, err := engines.NewTokenExecutionEngine(
		logger,
		mockHG,
		mockClockStore,
		mockKeyManager,
		mockInclusionProver,
		mockBulletproofProver,
		mockVerEnc,
		mockDecaf,
		engines.GlobalMode,
	)
	require.NoError(t, err)

	deploy := createTokenDeployPayloadFull(t, mockHG)
	deployReq, _ := deploy.ToCanonicalBytes()
	// Deploy message should work
	deployMsg := &protobufs.Message{
		Address: token.TOKEN_BASE_DOMAIN[:],
		Payload: deployReq,
	}

	state := hgstate.NewHypergraphState(mockHG)
	responses, err := globalEngine.ProcessMessage(1, big.NewInt(1), token.TOKEN_BASE_DOMAIN[:], deployMsg.Payload, state)
	assert.NoError(t, err)
	assert.NotNil(t, responses)
	err = responses.State.Commit()
	assert.NoError(t, err)

	// Mock that token exists for the second call
	mockVertex := new(mocks.MockVertex)
	mockHG.On("GetVertex", vertexAddr).Return(mockVertex, nil).Once()
	metadataTree := &tries.VectorCommitmentTree{}

	// Create test configuration
	config := createMintableTestConfig()

	// Create the metadata tree with valid configuration
	rdfMultiprover := schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, mockInclusionProver)
	configTree, err := token.NewTokenConfigurationMetadata(config, rdfMultiprover)
	require.NoError(t, err)

	// Store consensus tree
	consensus := &tries.VectorCommitmentTree{}
	consensusData, _ := tries.SerializeNonLazyTree(consensus)
	require.NoError(t, metadataTree.Insert([]byte{0 << 2}, consensusData, nil, big.NewInt(int64(len(consensusData)))))

	// Store sumcheck tree
	sumcheck := &tries.VectorCommitmentTree{}
	sumcheckData, _ := tries.SerializeNonLazyTree(sumcheck)
	require.NoError(t, metadataTree.Insert([]byte{1 << 2}, sumcheckData, nil, big.NewInt(int64(len(sumcheckData)))))

	// Store RDF schema
	rdfschema, _ := newTokenRDFHypergraphSchema(vertexAddr[:32], config)
	require.NoError(t, metadataTree.Insert([]byte{2 << 2}, []byte(rdfschema), nil, big.NewInt(int64(len(rdfschema)))))

	// Store config metadata at the right index
	configBytes, err := tries.SerializeNonLazyTree(configTree)
	require.NoError(t, err)
	require.NoError(t, metadataTree.Insert([]byte{16 << 2}, configBytes, nil, big.NewInt(int64(len(configBytes)))))

	mockHG.On("GetVertexData", mock.Anything).Return(metadataTree, nil)

	payload2, _ := createTokenTransactionPayload(t).ToCanonicalBytes()

	// Transaction should fail in global mode
	txMsg := &protobufs.Message{
		Address: testAddr,
		Payload: payload2,
	}

	state = hgstate.NewHypergraphState(mockHG)
	responses, err = globalEngine.ProcessMessage(1, big.NewInt(1), testAddr, txMsg.Payload, state)
	assert.Error(t, err)
}

// Helper functions
func createTokenDeployPayloadFull(t *testing.T, mockHG *mocks.MockHypergraph) *protobufs.MessageBundle {
	deploy := &token.TokenDeploy{
		Config: &token.TokenIntrinsicConfiguration{
			Name:     "Test Token",
			Symbol:   "TEST",
			Supply:   big.NewInt(100000),
			Units:    big.NewInt(10),
			Behavior: token.Acceptable | token.Divisible,
		},
		RDFSchema: []byte("context"),
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

	return &protobufs.MessageBundle{
		Requests: []*protobufs.MessageRequest{
			payment,
			{
				Request: &protobufs.MessageRequest_TokenDeploy{
					TokenDeploy: deploy.ToProtobuf(),
				},
			},
		},
	}
}

func createTokenTransactionPayload(t *testing.T) *protobufs.MessageRequest {
	// Create mock dependencies
	mockHG := new(mocks.MockHypergraph)
	mockBP := new(mocks.MockBulletproofProver)
	mockIP := new(mocks.MockInclusionProver)
	mockVE := new(mocks.MockVerifiableEncryptor)
	mockDC := new(mocks.MockDecafConstructor)
	mockKM := new(mocks.MockKeyManager)

	// Mock token configuration
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Divisible | token.Acceptable,
		Units:    big.NewInt(8), // Divisible tokens need units >= 8
		Name:     "Test Token",
		Symbol:   "TEST",
	}

	// Create test domain
	domain := make([]byte, 32)
	rand.Read(domain)

	// Create mock inputs
	input1, _ := token.NewTransactionInput(make([]byte, 64))
	input2, _ := token.NewTransactionInput(make([]byte, 64))

	// Create mock outputs (mock keys)
	mockVK := make([]byte, 56)
	mockSK := make([]byte, 56)
	rand.Read(mockVK)
	rand.Read(mockSK)
	out1, _ := token.NewTransactionOutput(big.NewInt(7), mockVK, mockSK)
	out2, _ := token.NewTransactionOutput(big.NewInt(2), mockVK, mockSK)

	// Create transaction
	tx := token.NewTransaction(
		[32]byte(domain),
		[]*token.TransactionInput{input1, input2},
		[]*token.TransactionOutput{out1, out2},
		[]*big.Int{big.NewInt(1), big.NewInt(2)},
		tokenconfig,
		mockHG,
		mockBP,
		mockIP,
		mockVE,
		mockDC,
		keys.ToKeyRing(mockKM, false),
		"",  // rdfSchema
		nil, // rdfMultiprover
	)

	// Mock the Prove call to set required fields
	tx.RangeProof = make([]byte, 100) // Mock range proof

	// Create a mock multiproof
	mockMultiproof := new(mocks.MockMultiproof)
	mockMultiproof.On("ToBytes").Return(make([]byte, 100), nil)

	tx.TraversalProof = &tries.TraversalProof{
		Multiproof: mockMultiproof,
		SubProofs: []tries.TraversalSubProof{
			{
				Commits: [][]byte{make([]byte, 64)},
				Ys:      [][]byte{make([]byte, 64)},
				Paths:   [][]uint64{{0}},
			},
		},
	}

	// Set signatures on inputs
	for _, input := range tx.Inputs {
		input.Signature = make([]byte, 114) // Ed448 signature size
		rand.Read(input.Signature)
		input.Commitment = make([]byte, 56)
		rand.Read(input.Commitment)
		input.Proofs = [][]byte{make([]byte, 32)}
	}

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Transaction{
			Transaction: tx.ToProtobuf(),
		},
	}
}

func createTokenPendingTransactionPayload(t *testing.T) *protobufs.MessageRequest {
	// Create mock dependencies
	mockHG := new(mocks.MockHypergraph)
	mockBP := new(mocks.MockBulletproofProver)
	mockIP := new(mocks.MockInclusionProver)
	mockVE := new(mocks.MockVerifiableEncryptor)
	mockDC := new(mocks.MockDecafConstructor)
	mockKM := new(mocks.MockKeyManager)

	// Mock token configuration
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Divisible | token.Acceptable,
		Units:    big.NewInt(8), // Divisible tokens need units >= 8
		Name:     "Test Token",
		Symbol:   "TEST",
	}

	// Create test domain
	domain := make([]byte, 32)
	rand.Read(domain)

	// Create mock inputs
	input1, _ := token.NewPendingTransactionInput(make([]byte, 64))

	// Create mock outputs (mock keys)
	mockToVK := make([]byte, 56)
	mockToSK := make([]byte, 56)
	mockRefundVK := make([]byte, 56)
	mockRefundSK := make([]byte, 56)
	rand.Read(mockToVK)
	rand.Read(mockToSK)
	rand.Read(mockRefundVK)
	rand.Read(mockRefundSK)
	out1, _ := token.NewPendingTransactionOutput(big.NewInt(9), mockToVK, mockToSK, mockRefundVK, mockRefundSK, 1000)

	// Create pending transaction
	tx := token.NewPendingTransaction(
		[32]byte(domain),
		[]*token.PendingTransactionInput{input1},
		[]*token.PendingTransactionOutput{out1},
		[]*big.Int{big.NewInt(1)},
		tokenconfig,
		mockHG,
		mockBP,
		mockIP,
		mockVE,
		mockDC,
		keys.ToKeyRing(mockKM, false),
		"",  // rdfSchema
		nil, // rdfMultiprover
	)

	// Mock the Prove call to set required fields
	tx.RangeProof = make([]byte, 100) // Mock range proof

	// Create a mock multiproof
	mockMultiproof := new(mocks.MockMultiproof)
	mockMultiproof.On("ToBytes").Return(make([]byte, 100), nil)

	tx.TraversalProof = &tries.TraversalProof{
		Multiproof: mockMultiproof,
		SubProofs: []tries.TraversalSubProof{
			{
				Commits: [][]byte{make([]byte, 64)},
				Ys:      [][]byte{make([]byte, 64)},
				Paths:   [][]uint64{{0}},
			},
		},
	}

	// Set signatures on inputs
	for _, input := range tx.Inputs {
		input.Signature = make([]byte, 114) // Ed448 signature size
		rand.Read(input.Signature)
		input.Commitment = make([]byte, 56)
		rand.Read(input.Commitment)
		input.Proofs = [][]byte{make([]byte, 32)}
	}

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_PendingTransaction{
			PendingTransaction: tx.ToProtobuf(),
		},
	}
}

func createTokenMintTransactionPayload(t *testing.T) *protobufs.MessageRequest {
	// Create mock dependencies
	mockHG := new(mocks.MockHypergraph)
	mockBP := new(mocks.MockBulletproofProver)
	mockIP := new(mocks.MockInclusionProver)
	mockVE := new(mocks.MockVerifiableEncryptor)
	mockDC := new(mocks.MockDecafConstructor)
	mockKM := new(mocks.MockKeyManager)

	// Mock token configuration with mint strategy
	tokenconfig := &token.TokenIntrinsicConfiguration{
		Behavior: token.Mintable | token.Divisible,
		MintStrategy: &token.TokenMintStrategy{
			MintBehavior: token.MintWithProof,
			ProofBasis:   token.ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(1),
		Name:   "Test Token",
		Symbol: "TEST",
	}

	// Create test domain
	domain := make([]byte, 32)
	rand.Read(domain)

	// Create mock mint input with output data
	outputData := make([]byte, 200) // Mock output data
	rand.Read(outputData)
	input, _ := token.NewMintTransactionInput(big.NewInt(10000), outputData)

	// Create mock outputs (mock keys)
	mockVK := make([]byte, 56)
	mockSK := make([]byte, 56)
	rand.Read(mockVK)
	rand.Read(mockSK)
	out, _ := token.NewMintTransactionOutput(big.NewInt(10000), mockVK, mockSK)

	// Create mint transaction
	tx := token.NewMintTransaction(
		[32]byte(domain),
		[]*token.MintTransactionInput{input},
		[]*token.MintTransactionOutput{out},
		[]*big.Int{big.NewInt(1)},
		tokenconfig,
		mockHG,
		mockBP,
		mockIP,
		mockVE,
		mockDC,
		keys.ToKeyRing(mockKM, false),
		"",  // rdfSchema
		nil, // rdfMultiprover
	)

	// Mock the Prove call to set required fields
	tx.RangeProof = make([]byte, 100) // Mock range proof

	// Set signatures on inputs
	for _, input := range tx.Inputs {
		input.Signature = make([]byte, 114) // Ed448 signature size
		rand.Read(input.Signature)
		input.Commitment = make([]byte, 56)
		rand.Read(input.Commitment)
		input.Proofs = [][]byte{make([]byte, 32)}
	}

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_MintTransaction{
			MintTransaction: tx.ToProtobuf(),
		},
	}
}

func createNonTokenPayload(t *testing.T) *protobufs.MessageRequest {
	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Confirm{
			Confirm: &protobufs.ProverConfirm{
				Filter:      []byte{},
				FrameNumber: 1,
				PublicKeySignatureBls48581: &protobufs.BLS48581AddressedSignature{
					Address:   make([]byte, 32),
					Signature: make([]byte, 74),
				},
			},
		},
	}
}
