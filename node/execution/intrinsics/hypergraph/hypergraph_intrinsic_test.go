package hypergraph_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/hypergraph"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func setupMockHypergraph(t *testing.T) (*mocks.MockInclusionProver, *mocks.MockHypergraph) {
	mockHypergraph := &mocks.MockHypergraph{}

	// Setup mock prover
	mockProver := &mocks.MockInclusionProver{}
	mockHypergraph.On("GetProver").Return(mockProver)

	return mockProver, mockHypergraph
}

func TestNewHypergraphIntrinsic(t *testing.T) {
	_, mockHypergraph := setupMockHypergraph(t)

	// Create a valid configuration
	config := &hypergraph.HypergraphIntrinsicConfiguration{
		ReadPublicKey:  make([]byte, 57),
		WritePublicKey: make([]byte, 57),
	}

	// Create a mock key manager
	mockKeyManager := &mocks.MockKeyManager{}

	// Create a new intrinsic
	intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, mockKeyManager, nil, nil)

	// Verify the intrinsic was created successfully
	assert.NotNil(t, intrinsic)
	assert.Equal(t, config, intrinsic.Config())
	assert.Equal(t, mockHypergraph, intrinsic.Hypergraph())
}

func TestLoadHypergraphIntrinsic(t *testing.T) {
	// Setup mock objects
	_, mockHypergraph := setupMockHypergraph(t)
	mockInclusionProver := &mocks.MockInclusionProver{}
	mockKeyManager := &mocks.MockKeyManager{}

	// Setup app address
	appAddress := make([]byte, 32)
	vertexAddress := slices.Concat(appAddress, hg.HYPERGRAPH_METADATA_ADDRESS)
	vertexId := [64]byte(vertexAddress)

	// Setup mock vertex
	mockVertex := &mocks.MockVertex{}
	mockVertex.On("GetID").Return(vertexId)
	mockHypergraph.On("GetVertex", vertexId).Return(mockVertex, nil)

	// Setup mock tree and tree data
	mockTree := &crypto.VectorCommitmentTree{}

	// Mock the tree consensus structure
	consensusTree := &crypto.VectorCommitmentTree{}

	// Serialize the consensus tree
	consensusBytes, err := crypto.SerializeNonLazyTree(consensusTree)
	require.NoError(t, err)

	// Mock the tree configuration structure
	configTree := &crypto.VectorCommitmentTree{}
	readKey := make([]byte, 57)
	writeKey := make([]byte, 57)
	configTree.Insert([]byte{0 << 2}, readKey, nil, big.NewInt(57))
	configTree.Insert([]byte{1 << 2}, writeKey, nil, big.NewInt(57))

	// Serialize the config tree
	configBytes, err := crypto.SerializeNonLazyTree(configTree)
	require.NoError(t, err)

	// Insert the consensus tree into the main tree
	mockTree.Insert([]byte{0 << 2}, consensusBytes, nil, big.NewInt(int64(len(consensusBytes))))

	// Insert the sumcheck tree into the main tree – we cheat this by reusing the consensus tree because they're equivalent objects here
	mockTree.Insert([]byte{1 << 2}, consensusBytes, nil, big.NewInt(int64(len(consensusBytes))))

	// RDF is empty for this intrinsic
	mockTree.Insert([]byte{2 << 2}, []byte(""), nil, big.NewInt(0))

	// Insert the config tree into the main tree
	mockTree.Insert([]byte{16 << 2}, configBytes, nil, big.NewInt(int64(len(configBytes))))

	// Set up the mock tree commit to return a value that will hash to the appAddress
	mockTreeCommit := make([]byte, 32)
	mockInclusionProver.On("CommitRaw", mock.Anything, mock.Anything).Return(mockTreeCommit, nil)

	// Set up the hypergraph's GetVertexData to return our mock tree
	mockHypergraph.On("GetVertexData", vertexId).Return(mockTree, nil)

	// Create the intrinsic
	intrinsic, err := hypergraph.LoadHypergraphIntrinsic(
		appAddress,
		mockHypergraph,
		mockInclusionProver,
		mockKeyManager,
		nil,
		nil,
	)

	// Verify the intrinsic was created successfully
	assert.NotNil(t, intrinsic)
	assert.NoError(t, err)

	// Verify the underlying mocks were called
	mockHypergraph.AssertCalled(t, "GetVertex", vertexId)
	mockHypergraph.AssertCalled(t, "GetVertexData", vertexId)
}
