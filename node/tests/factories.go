package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// CreateHypergraphWithInclusionProver sets up the mock hypergraph to return the
// provided prover instance
func CreateHypergraphWithInclusionProver(
	inclusionProver crypto.InclusionProver,
) *mocks.MockHypergraph {
	mockHG := new(mocks.MockHypergraph)
	mockHG.On("GetProver").Return(inclusionProver)
	return mockHG
}

// CreateTestRDFMultiprover creates a RDFMultiprover for test usage
func CreateTestRDFMultiprover(
	inclusionProver crypto.InclusionProver,
) *schema.RDFMultiprover {
	parser := &schema.TurtleRDFParser{}
	return schema.NewRDFMultiprover(parser, inclusionProver)
}

// SetHypergraphProverData sets mock hypergraph responses for prover data
func SetHypergraphProverData(
	mockHG *mocks.MockHypergraph,
	proverAddress []byte,
	publicKey []byte,
	status byte,
	availableStorage uint64,
	seniority uint64,
	delegateAddress []byte,
	kickFrameNumber uint64,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree := &qcrypto.VectorCommitmentTree{}

	// Set prover fields in tree using RDF schema
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"PublicKey",
		publicKey,
		tree,
	); err != nil {
		return err
	}

	statusBytes := []byte{status}
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Status",
		statusBytes,
		tree,
	); err != nil {
		return err
	}

	availableStorageBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(availableStorageBytes, availableStorage)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"AvailableStorage",
		availableStorageBytes,
		tree,
	); err != nil {
		return err
	}

	seniorityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seniorityBytes, seniority)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"Seniority",
		seniorityBytes,
		tree,
	); err != nil {
		return err
	}

	kickFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(kickFrameBytes, kickFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"prover:Prover",
		"KickFrameNumber",
		kickFrameBytes,
		tree,
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(proverAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", proverAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", proverAddress).Return(tree, nil)

	return nil
}

// SetHypergraphAllocationData sets mock hypergraph responses for allocation
// data
func SetHypergraphAllocationData(
	mockHG *mocks.MockHypergraph,
	allocationAddress []byte,
	proverRef []byte,
	status byte,
	confirmationFilter []byte,
	rejectionFilter []byte,
	joinFrameNumber uint64,
	leaveFrameNumber uint64,
	pauseFrameNumber uint64,
	resumeFrameNumber uint64,
	kickFrameNumber uint64,
	joinConfirmFrameNumber uint64,
	joinRejectFrameNumber uint64,
	leaveConfirmFrameNumber uint64,
	leaveRejectFrameNumber uint64,
	lastActiveFrameNumber uint64,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree := &qcrypto.VectorCommitmentTree{}

	// Set allocation fields in tree
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Prover",
		proverRef,
		tree,
	); err != nil {
		return err
	}

	statusBytes := []byte{status}
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"Status",
		statusBytes,
		tree,
	); err != nil {
		return err
	}

	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"ConfirmationFilter",
		confirmationFilter,
		tree,
	); err != nil {
		return err
	}

	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"RejectionFilter",
		rejectionFilter,
		tree,
	); err != nil {
		return err
	}

	joinFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinFrameBytes, joinFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinFrameNumber",
		joinFrameBytes,
		tree,
	); err != nil {
		return err
	}

	leaveFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(leaveFrameBytes, leaveFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LeaveFrameNumber",
		leaveFrameBytes,
		tree,
	); err != nil {
		return err
	}

	pauseFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pauseFrameBytes, pauseFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"PauseFrameNumber",
		pauseFrameBytes,
		tree,
	); err != nil {
		return err
	}

	resumeFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(resumeFrameBytes, resumeFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"ResumeFrameNumber",
		resumeFrameBytes,
		tree,
	); err != nil {
		return err
	}

	kickFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(kickFrameBytes, kickFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"KickFrameNumber",
		kickFrameBytes,
		tree,
	); err != nil {
		return err
	}

	joinConfirmFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinConfirmFrameBytes, joinConfirmFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinConfirmFrameNumber",
		joinConfirmFrameBytes,
		tree,
	); err != nil {
		return err
	}

	joinRejectFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(joinRejectFrameBytes, joinRejectFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"JoinRejectFrameNumber",
		joinRejectFrameBytes,
		tree,
	); err != nil {
		return err
	}

	leaveConfirmFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(leaveConfirmFrameBytes, leaveConfirmFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LeaveConfirmFrameNumber",
		leaveConfirmFrameBytes,
		tree,
	); err != nil {
		return err
	}

	leaveRejectFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(leaveRejectFrameBytes, leaveRejectFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LeaveRejectFrameNumber",
		leaveRejectFrameBytes,
		tree,
	); err != nil {
		return err
	}

	lastActiveFrameBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lastActiveFrameBytes, lastActiveFrameNumber)
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		"allocation:ProverAllocation",
		"LastActiveFrameNumber",
		lastActiveFrameBytes,
		tree,
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(allocationAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", allocationAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", allocationAddress).Return(tree, nil)

	return nil
}

// SetHypergraphRewardData sets mock hypergraph responses for reward data
func SetHypergraphRewardData(
	mockHG *mocks.MockHypergraph,
	rewardAddress []byte,
	delegateAddress []byte,
	balance *big.Int,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree := &qcrypto.VectorCommitmentTree{}

	// Set reward fields in tree
	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		token.QUIL_TOKEN_ADDRESS[:],
		"reward:ProverReward",
		"DelegateAddress",
		delegateAddress,
		tree,
	); err != nil {
		return err
	}

	balanceBytes := balance.FillBytes(make([]byte, 32))

	if err := rdfProver.Set(
		global.GLOBAL_RDF_SCHEMA,
		token.QUIL_TOKEN_ADDRESS[:],
		"reward:ProverReward",
		"Balance",
		balanceBytes,
		tree,
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(rewardAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", rewardAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", rewardAddress).Return(tree, nil)

	return nil
}

// SetHypergraphTokenMetadataData sets mock hypergraph responses for token
// metadata
func SetHypergraphTokenMetadataData(
	mockHG *mocks.MockHypergraph,
	config *token.TokenIntrinsicConfiguration,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree, err := token.NewTokenConfigurationMetadata(config, rdfProver)
	if err != nil {
		return err
	}

	tokenDomainBI, err := poseidon.HashBytes(
		slices.Concat(
			token.TOKEN_PREFIX,
			tree.Commit(mockHG.GetProver(), false),
		),
	)
	if err != nil {
		return err
	}

	metadataAddress := slices.Concat(
		tokenDomainBI.FillBytes(make([]byte, 32)),
		bytes.Repeat([]byte{0xff}, 32),
	)

	emptyTree := &qcrypto.VectorCommitmentTree{}
	emptyTreeBytes, _ := qcrypto.SerializeNonLazyTree(emptyTree)
	configTreeBytes, _ := qcrypto.SerializeNonLazyTree(tree)
	metadataTree := &qcrypto.VectorCommitmentTree{}
	metadataTree.Insert(
		[]byte{0},
		emptyTreeBytes,
		nil,
		big.NewInt(int64(len(emptyTreeBytes))),
	)
	metadataTree.Insert(
		[]byte{1 << 2},
		emptyTreeBytes,
		nil,
		big.NewInt(int64(len(emptyTreeBytes))),
	)
	metadataTree.Insert(
		[]byte{16 << 2},
		configTreeBytes,
		nil,
		big.NewInt(int64(len(configTreeBytes))),
	)

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(metadataAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", metadataAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", metadataAddress).Return(tree, nil)

	return nil
}

// SetHypergraphPendingTransactionData sets mock hypergraph responses for
// pending transaction data
func SetHypergraphPendingTransactionData(
	mockHG *mocks.MockHypergraph,
	config *token.TokenIntrinsicConfiguration,
	transactionAddress []byte,
	commitment []byte,
	toOneTimeKey []byte,
	toVerificationKey []byte,
	toCoinBalance []byte,
	toMask []byte,
	refundOneTimeKey []byte,
	refundVerificationKey []byte,
	refundCoinBalance []byte,
	refundMask []byte,
	expiration uint64,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree := &qcrypto.VectorCommitmentTree{}
	schema, err := token.PrepareRDFSchemaFromConfig(
		transactionAddress[:32],
		config,
	)
	if err != nil {
		return err
	}

	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"Commitment",
		commitment,
		tree,
	); err != nil {
		return err
	}

	// Set pending transaction fields - To output
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"ToOneTimeKey",
		toOneTimeKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"ToVerificationKey",
		toVerificationKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"ToCoinBalance",
		toCoinBalance,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"ToMask",
		toMask,
		tree,
	); err != nil {
		return err
	}

	// Set pending transaction fields - Refund output
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"RefundOneTimeKey",
		refundOneTimeKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"RefundVerificationKey",
		refundVerificationKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"RefundCoinBalance",
		refundCoinBalance,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		transactionAddress[:32],
		"pending:PendingTransaction",
		"RefundMask",
		refundMask,
		tree,
	); err != nil {
		return err
	}

	// Set expiration if non-zero
	if expiration > 0 {
		expirationBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(expirationBytes, expiration)
		if err := rdfProver.Set(
			schema,
			transactionAddress[:32],
			"pending:PendingTransaction",
			"Expiration",
			expirationBytes,
			tree,
		); err != nil {
			return err
		}
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(transactionAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", transactionAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", transactionAddress).Return(tree, nil)

	return nil
}

// SetHypergraphCoinData sets mock hypergraph responses for coin data
func SetHypergraphCoinData(
	mockHG *mocks.MockHypergraph,
	config *token.TokenIntrinsicConfiguration,
	coinAddress []byte,
	frameNumber uint64,
	commitment []byte,
	oneTimeKey []byte,
	verificationKey []byte,
	coinBalance []byte,
	mask []byte,
	additionalReference []byte,
	additionalReferenceKey []byte,
) error {
	rdfProver := CreateTestRDFMultiprover(mockHG.GetProver())
	tree := &qcrypto.VectorCommitmentTree{}

	schema, err := token.PrepareRDFSchemaFromConfig(coinAddress[:32], config)
	if err != nil {
		return err
	}

	// Set coin fields
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frameNumber)
	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"FrameNumber",
		frameNumberBytes,
		tree,
	); err != nil {
		return err
	}

	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"Commitment",
		commitment,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"OneTimeKey",
		oneTimeKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"VerificationKey",
		verificationKey,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"CoinBalance",
		coinBalance,
		tree,
	); err != nil {
		return err
	}
	if err := rdfProver.Set(
		schema,
		coinAddress[:32],
		"coin:Coin",
		"Mask",
		mask,
		tree,
	); err != nil {
		return err
	}

	// Set optional additional reference fields
	if additionalReference != nil {
		if err := rdfProver.Set(
			schema,
			coinAddress[:32],
			"coin:Coin",
			"AdditionalReference",
			additionalReference,
			tree,
		); err != nil {
			return err
		}
	}
	if additionalReferenceKey != nil {
		if err := rdfProver.Set(
			schema,
			coinAddress[:32],
			"coin:Coin",
			"AdditionalReferenceKey",
			additionalReferenceKey,
			tree,
		); err != nil {
			return err
		}
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(coinAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", coinAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", coinAddress).Return(tree, nil)

	return nil
}

// SetHypergraphComputeMetadataData sets mock hypergraph responses for compute
// metadata
func SetHypergraphComputeMetadataData(
	mockHG *mocks.MockHypergraph,
	computeAddress []byte,
	schema string,
	creator []byte,
	readPublicKey []byte,
	writePublicKey []byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Index 0: Consensus metadata (empty for tests)
	consensusMetadata := &qcrypto.VectorCommitmentTree{}
	consensusMetadataBytes, err := qcrypto.SerializeNonLazyTree(consensusMetadata)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{0 << 2},
		consensusMetadataBytes,
		nil,
		big.NewInt(int64(len(consensusMetadataBytes))),
	); err != nil {
		return err
	}

	// Index 1: Sumcheck info (empty for tests)
	sumcheckInfo := &qcrypto.VectorCommitmentTree{}
	sumcheckInfoBytes, err := qcrypto.SerializeNonLazyTree(sumcheckInfo)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{1 << 2},
		sumcheckInfoBytes,
		nil,
		big.NewInt(int64(len(sumcheckInfoBytes))),
	); err != nil {
		return err
	}

	// Index 2: RDF schema
	schemaBytes := []byte(schema)
	if err := tree.Insert(
		[]byte{2 << 2},
		schemaBytes,
		nil,
		big.NewInt(int64(len(schemaBytes))),
	); err != nil {
		return err
	}

	// Index 16: Compute configuration metadata (same as index 13 in
	// additionalData array)
	configTree := &qcrypto.VectorCommitmentTree{}

	// Store Read key (byte 0)
	if err := configTree.Insert(
		[]byte{0 << 2},
		readPublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return err
	}

	// Store Write key (byte 1)
	if err := configTree.Insert(
		[]byte{1 << 2},
		writePublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return err
	}

	configBytes, err := qcrypto.SerializeNonLazyTree(configTree)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{16 << 2},
		configBytes,
		nil,
		big.NewInt(int64(len(configBytes))),
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(computeAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph - handle both []byte and [64]byte
	mockHG.On("GetVertex", computeAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", computeAddress).Return(tree, nil)

	// Also set up for [64]byte if address is 64 bytes
	if len(computeAddress) == 64 {
		var addr64 [64]byte
		copy(addr64[:], computeAddress)
		mockHG.On("GetVertex", addr64).Return(mockVertex, nil).Maybe()
		mockHG.On("GetVertexData", addr64).Return(tree, nil).Maybe()
	}

	return nil
}

// SetHypergraphCodeData sets mock hypergraph responses for code deployment data
func SetHypergraphCodeData(
	mockHG *mocks.MockHypergraph,
	codeAddress []byte,
	code []byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Store the code content at index 0 (same as CodeDeployment.Materialize)
	if err := tree.Insert(
		[]byte{0 << 2},
		code,
		nil,
		big.NewInt(int64(len(code))),
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(codeAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", codeAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", codeAddress).Return(tree, nil)

	return nil
}

// SetHypergraphExecutionData sets mock hypergraph responses for code execution
// data
func SetHypergraphExecutionData(
	mockHG *mocks.MockHypergraph,
	executionAddress []byte,
	codeRef []byte,
	inputData []byte,
	outputData []byte,
	status byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Store execution data following compute execution structure
	// Index 0: Code reference
	if err := tree.Insert(
		[]byte{0 << 2},
		codeRef,
		nil,
		big.NewInt(int64(len(codeRef))),
	); err != nil {
		return err
	}

	// Index 1: Input data
	if err := tree.Insert(
		[]byte{1 << 2},
		inputData,
		nil,
		big.NewInt(int64(len(inputData))),
	); err != nil {
		return err
	}

	// Index 2: Output data
	if err := tree.Insert(
		[]byte{2 << 2},
		outputData,
		nil,
		big.NewInt(int64(len(outputData))),
	); err != nil {
		return err
	}

	// Index 3: Status
	statusBytes := []byte{status}
	if err := tree.Insert(
		[]byte{3 << 2},
		statusBytes,
		nil,
		big.NewInt(1),
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(executionAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", executionAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", executionAddress).Return(tree, nil)

	return nil
}

// SetHypergraphFinalizedData sets mock hypergraph responses for finalized
// execution data
func SetHypergraphFinalizedData(
	mockHG *mocks.MockHypergraph,
	finalizedAddress []byte,
	executionRef []byte,
	finalizedOutput []byte,
	proofs []byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Store finalized data following compute finalization structure
	// Index 0: Execution reference
	if err := tree.Insert(
		[]byte{0 << 2},
		executionRef,
		nil,
		big.NewInt(int64(len(executionRef))),
	); err != nil {
		return err
	}

	// Index 1: Finalized output
	if err := tree.Insert(
		[]byte{1 << 2},
		finalizedOutput,
		nil,
		big.NewInt(int64(len(finalizedOutput))),
	); err != nil {
		return err
	}

	// Index 2: Proofs (if provided)
	if proofs != nil {
		if err := tree.Insert(
			[]byte{2 << 2},
			proofs,
			nil,
			big.NewInt(int64(len(proofs))),
		); err != nil {
			return err
		}
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(finalizedAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", finalizedAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", finalizedAddress).Return(tree, nil)

	return nil
}

// SetHypergraphHypergraphMetadataData sets mock hypergraph responses for
// hypergraph metadata
func SetHypergraphHypergraphMetadataData(
	mockHG *mocks.MockHypergraph,
	metadataAddress []byte,
	schema string,
	readPublicKey []byte,
	writePublicKey []byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Index 0: Consensus metadata (empty for tests)
	consensusMetadata := &qcrypto.VectorCommitmentTree{}
	consensusMetadataBytes, err := qcrypto.SerializeNonLazyTree(consensusMetadata)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{0 << 2},
		consensusMetadataBytes,
		nil,
		big.NewInt(int64(len(consensusMetadataBytes))),
	); err != nil {
		return err
	}

	// Index 1: Sumcheck info (empty for tests)
	sumcheckInfo := &qcrypto.VectorCommitmentTree{}
	sumcheckInfoBytes, err := qcrypto.SerializeNonLazyTree(sumcheckInfo)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{1 << 2},
		sumcheckInfoBytes,
		nil,
		big.NewInt(int64(len(sumcheckInfoBytes))),
	); err != nil {
		return err
	}

	// Index 2: RDF schema
	schemaBytes := []byte(schema)
	if err := tree.Insert(
		[]byte{2 << 2},
		schemaBytes,
		nil,
		big.NewInt(int64(len(schemaBytes))),
	); err != nil {
		return err
	}

	// Index 16: Hypergraph configuration metadata (same as index 13 in
	// additionalData array)
	configTree := &qcrypto.VectorCommitmentTree{}

	// Store Read key (byte 0)
	if err := configTree.Insert(
		[]byte{0 << 2},
		readPublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return err
	}

	// Store Write key (byte 1)
	if err := configTree.Insert(
		[]byte{1 << 2},
		writePublicKey,
		nil,
		big.NewInt(57),
	); err != nil {
		return err
	}

	configBytes, err := qcrypto.SerializeNonLazyTree(configTree)
	if err != nil {
		return err
	}
	if err := tree.Insert(
		[]byte{16 << 2},
		configBytes,
		nil,
		big.NewInt(int64(len(configBytes))),
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(metadataAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", metadataAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", metadataAddress).Return(tree, nil)

	return nil
}

// SetHypergraphVertexAddData sets mock hypergraph responses for vertex add
// operations
func SetHypergraphVertexAddData(
	mockHG *mocks.MockHypergraph,
	vertexAddress []byte,
	data []byte,
	timestamp uint64,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Store vertex data
	if err := tree.Insert(
		[]byte("data"),
		data,
		nil,
		big.NewInt(int64(len(data))),
	); err != nil {
		return err
	}

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestamp)
	if err := tree.Insert(
		[]byte("timestamp"),
		timestampBytes,
		nil,
		big.NewInt(8),
	); err != nil {
		return err
	}

	// Create mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetAddress").Return(vertexAddress)
	mockVertex.On("GetData").Return(tree, nil)

	// Set expectations on mock hypergraph
	mockHG.On("GetVertex", vertexAddress).Return(mockVertex, nil)
	mockHG.On("GetVertexData", vertexAddress).Return(tree, nil)

	return nil
}

// SetHypergraphVertexRemoveData sets mock hypergraph responses for vertex
// remove operations
func SetHypergraphVertexRemoveData(
	mockHG *mocks.MockHypergraph,
	vertexAddress []byte,
	removalTimestamp uint64,
) error {
	// For removal, we typically return nil or an error indicating vertex doesn't
	// exist
	mockHG.On("GetVertex", vertexAddress).Return(nil, store.ErrNotFound)
	mockHG.On("GetVertexData", vertexAddress).Return(nil, store.ErrNotFound)

	return nil
}

// SetHypergraphHyperedgeAddData sets mock hypergraph responses for hyperedge
// add operations
func SetHypergraphHyperedgeAddData(
	mockHG *mocks.MockHypergraph,
	hyperedgeAddress []byte,
	sourceVertices [][]byte,
	targetVertices [][]byte,
	data []byte,
) error {
	tree := &qcrypto.VectorCommitmentTree{}

	// Store hyperedge data
	if err := tree.Insert(
		[]byte("data"),
		data,
		nil,
		big.NewInt(int64(len(data))),
	); err != nil {
		return err
	}

	// Store source vertex references
	for i, source := range sourceVertices {
		key := append([]byte("source_"), byte(i))
		if err := tree.Insert(
			key,
			source,
			nil,
			big.NewInt(int64(len(source))),
		); err != nil {
			return err
		}
	}

	// Store target vertex references
	for i, target := range targetVertices {
		key := append([]byte("target_"), byte(i))
		if err := tree.Insert(
			key,
			target,
			nil,
			big.NewInt(int64(len(target))),
		); err != nil {
			return err
		}
	}

	// Create mock hyperedge
	mockHyperedge := &mocks.MockHyperedge{}
	mockHyperedge.On("GetAddress").Return(hyperedgeAddress)
	mockHyperedge.On("GetData").Return(tree, nil)
	mockHyperedge.On("GetSourceVertices").Return(sourceVertices)
	mockHyperedge.On("GetTargetVertices").Return(targetVertices)

	// Set expectations on mock hypergraph for hyperedge
	mockHG.On("GetHyperedge", hyperedgeAddress).Return(mockHyperedge, nil)

	return nil
}

// SetHypergraphHyperedgeRemoveData sets mock hypergraph responses for hyperedge
// remove operations
func SetHypergraphHyperedgeRemoveData(
	mockHG *mocks.MockHypergraph,
	hyperedgeAddress []byte,
) error {
	// For removal, we typically return nil or an error indicating hyperedge
	// doesn't exist
	mockHG.On("GetHyperedge", hyperedgeAddress).Return(nil, store.ErrNotFound)

	return nil
}

// Helper to set up a chain of vertex lookups for following references
func SetHypergraphVertexChain(
	mockHG *mocks.MockHypergraph,
	addresses [][]byte,
	trees []*qcrypto.VectorCommitmentTree,
) {
	if len(addresses) != len(trees) {
		panic("addresses and trees must have same length")
	}

	for i := range addresses {
		mockVertex := &mocks.MockVertex{}
		mockVertex.On("GetAddress").Return(addresses[i])
		mockVertex.On("GetData").Return(trees[i], nil)

		mockHG.On("GetVertex", addresses[i]).Return(mockVertex, nil)
		mockHG.On("GetVertexData", addresses[i]).Return(trees[i], nil)
	}
}

func CreateValidQUILPendingTransactionPayload(
	mockHG *mocks.MockHypergraph,
	frameNumber uint64,
	toSpendKeys [][]byte,
	toViewKeys [][]byte,
	refundSpendKeys [][]byte,
	refundViewKeys [][]byte,
	inputAmounts []*big.Int,
	outputAmounts []*big.Int,
	outputFees []*big.Int,
	expiration uint64,
) (*protobufs.MessageRequest, error) {
	if len(toSpendKeys) != len(toViewKeys) ||
		len(refundSpendKeys) != len(refundViewKeys) ||
		len(toSpendKeys) != len(refundSpendKeys) ||
		len(toSpendKeys) != len(outputAmounts) || frameNumber == 0 {
		panic("incorrect parameters")
	}

	mp := &mocks.MockMultiproof{}
	mp.On("FromBytes", mock.Anything).Return(nil)
	mp.On("GetMulticommitment").Return(make([]byte, 74))
	mp.On("GetProof").Return(make([]byte, 74))
	mockHG.GetProver().(*mocks.MockInclusionProver).On("NewMultiproof").Return(mp)
	mockHG.GetProver().(*mocks.MockInclusionProver).On("VerifyMultiple", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
	mockHG.On("VerifyTraversalProof", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	pendingInputs := []*protobufs.PendingTransactionInput{}

	for _, input := range inputAmounts {
		address := []byte{0x0f, 0x63, 0xcd, 0x0c, 0x9f, 0xbe, 0x67, 0x9a, 0x56, 0x24, 0x69, 0x83, 0x1d, 0x8e, 0x81, 0x0c, 0x9d, 0x33, 0xcc, 0x24, 0x09, 0x69, 0x5b, 0x8e, 0x6a, 0x89, 0x3e, 0x62, 0x7e, 0xa9, 0x52, 0xd1}
		err := SetHypergraphCoinData(
			mockHG,
			token.QUIL_TOKEN_CONFIGURATION,
			slices.Concat(token.QUIL_TOKEN_ADDRESS, address),
			frameNumber-1,
			make([]byte, 56),
			make([]byte, 56),
			make([]byte, 56),
			input.FillBytes(make([]byte, 56)),
			make([]byte, 56),
			nil,
			nil,
		)
		if err != nil {
			return nil, err
		}

		pendingInputs = append(pendingInputs, &protobufs.PendingTransactionInput{
			Commitment: make([]byte, 56),
			Signature:  make([]byte, 336),
			Proofs:     make([][]byte, 1),
		})
	}

	// Create verification key for consistency
	verKey := make([]byte, 56)
	rand.Read(verKey)

	pendingOutputs := []*protobufs.PendingTransactionOutput{}
	for _, output := range outputAmounts {
		pendingOutputs = append(pendingOutputs, &protobufs.PendingTransactionOutput{
			FrameNumber: big.NewInt(int64(frameNumber)).FillBytes(make([]byte, 8)),
			Commitment:  make([]byte, 56),
			To: &protobufs.RecipientBundle{
				OneTimeKey:             make([]byte, 56),
				VerificationKey:        verKey,
				CoinBalance:            output.FillBytes(make([]byte, 56)),
				Mask:                   make([]byte, 56),
				AdditionalReference:    []byte{},
				AdditionalReferenceKey: []byte{},
			},
			Refund: &protobufs.RecipientBundle{
				OneTimeKey:             make([]byte, 56),
				VerificationKey:        verKey,
				CoinBalance:            output.FillBytes(make([]byte, 56)),
				Mask:                   make([]byte, 56),
				AdditionalReference:    []byte{},
				AdditionalReferenceKey: []byte{},
			},
			Expiration: expiration,
		})
	}

	fees := [][]byte{}
	for _, fee := range outputFees {
		fees = append(fees, fee.FillBytes(make([]byte, 32)))
	}

	// Create PendingTransaction using protobuf
	pbTx := &protobufs.PendingTransaction{
		Domain:     token.QUIL_TOKEN_ADDRESS[:],
		Inputs:     pendingInputs,
		Outputs:    pendingOutputs,
		Fees:       fees,
		RangeProof: make([]byte, 100),
		TraversalProof: &protobufs.TraversalProof{
			Multiproof: nil,
			SubProofs: []*protobufs.TraversalSubProof{
				{
					Commits: [][]byte{make([]byte, 74)},
					Ys:      [][]byte{make([]byte, 64)},
					Paths: []*protobufs.Path{
						{
							Indices: []uint64{0},
						},
					},
				},
			},
		},
	}

	return &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_PendingTransaction{
			PendingTransaction: pbTx,
		},
	}, nil
}

type Nopthenticator struct{}

// CreateClientTLSCredentials implements channel.AuthenticationProvider.
func (n *Nopthenticator) CreateClientTLSCredentials(expectedPeerId []byte) (
	credentials.TransportCredentials,
	error,
) {
	return insecure.NewCredentials(), nil

}

// CreateServerTLSCredentials implements channel.AuthenticationProvider.
func (n *Nopthenticator) CreateServerTLSCredentials() (
	credentials.TransportCredentials,
	error,
) {
	return insecure.NewCredentials(), nil

}

type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *authenticatedStream) Context() context.Context { return w.ctx }

// StreamInterceptor implements channel.AuthenticationProvider.
func (n *Nopthenticator) StreamInterceptor(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	ss = &authenticatedStream{
		ServerStream: ss,
		ctx:          qgrpc.NewContextWithPeerID(ss.Context(), peer.ID("peer")),
	}
	return handler(srv, ss)
}

// UnaryInterceptor implements channel.AuthenticationProvider.
func (n *Nopthenticator) UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	return handler(qgrpc.NewContextWithPeerID(ctx, peer.ID("peer")), req)
}

// Identify implements channel.AuthenticationProvider.
func (n *Nopthenticator) Identify(ctx context.Context) (peer.ID, error) {
	return peer.ID("peer"), nil
}

var _ channel.AuthenticationProvider = (*Nopthenticator)(nil)
