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

func TestLock(t *testing.T) {
	_, mockHypergraph := setupMockHypergraph(t)

	// Create a valid configuration
	config := &hypergraph.HypergraphIntrinsicConfiguration{
		ReadPublicKey:  make([]byte, 57),
		WritePublicKey: make([]byte, 57),
	}

	// Create a new intrinsic
	intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, &mocks.MockKeyManager{}, nil, nil)

	t.Run("Lock successful", func(t *testing.T) {
		writeAddresses := [][]byte{[]byte("write1"), []byte("write2")}
		readAddresses := [][]byte{[]byte("read1"), []byte("read2")}

		// Lock the addresses
		err := intrinsic.Lock(writeAddresses, readAddresses)
		assert.NoError(t, err)

		// Try to lock the same write address (should fail)
		err = intrinsic.Lock([][]byte{[]byte("write1")}, [][]byte{})
		assert.Error(t, err)

		// Try to lock the same read address for writing (should fail)
		err = intrinsic.Lock([][]byte{[]byte("read1")}, [][]byte{})
		assert.Error(t, err)

		// Lock a new write address (should succeed)
		err = intrinsic.Lock([][]byte{[]byte("write3")}, [][]byte{})
		assert.NoError(t, err)

		// Lock a new read address (should succeed)
		err = intrinsic.Lock([][]byte{}, [][]byte{[]byte("read3")})
		assert.NoError(t, err)
	})

	t.Run("Lock same address multiple times for reading", func(t *testing.T) {
		// Create a new intrinsic for clean state
		intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, &mocks.MockKeyManager{}, nil, nil)

		// Lock an address for reading
		err := intrinsic.Lock([][]byte{}, [][]byte{[]byte("shared")})
		assert.NoError(t, err)

		// Lock the same address for reading again (should succeed)
		err = intrinsic.Lock([][]byte{}, [][]byte{[]byte("shared")})
		assert.NoError(t, err)

		// Try to lock for writing (should fail)
		err = intrinsic.Lock([][]byte{[]byte("shared")}, [][]byte{})
		assert.Error(t, err)
	})
}

func TestUnlock(t *testing.T) {
	_, mockHypergraph := setupMockHypergraph(t)

	// Create a valid configuration
	config := &hypergraph.HypergraphIntrinsicConfiguration{
		ReadPublicKey:  make([]byte, 57),
		WritePublicKey: make([]byte, 57),
	}

	// Create a new intrinsic
	intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, &mocks.MockKeyManager{}, nil, nil)

	t.Run("Unlock after lock", func(t *testing.T) {
		writeAddresses := [][]byte{{0x01, 0x02}, {0x01, 0x03}}
		readAddresses := [][]byte{{0x02, 0x02}, {0x02, 0x03}}

		// Lock the addresses
		err := intrinsic.Lock(writeAddresses, readAddresses)
		assert.NoError(t, err)

		// Unlock the addresses
		err = intrinsic.Unlock(writeAddresses, readAddresses)
		assert.NoError(t, err)

		// Lock them again (should succeed since they were unlocked)
		err = intrinsic.Lock(writeAddresses, readAddresses)
		assert.NoError(t, err)
	})

	t.Run("Unlock with referenced read lock", func(t *testing.T) {
		// Create a new intrinsic for clean state
		intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, &mocks.MockKeyManager{}, nil, nil)

		// Lock an address for reading twice
		readAddress := []byte("shared")
		err := intrinsic.Lock([][]byte{}, [][]byte{readAddress})
		assert.NoError(t, err)
		err = intrinsic.Lock([][]byte{}, [][]byte{readAddress})
		assert.NoError(t, err)

		// Unlock once (should still be locked)
		err = intrinsic.Unlock([][]byte{}, [][]byte{readAddress})
		assert.NoError(t, err)

		// Try to lock for writing (should still fail as read lock is still there)
		err = intrinsic.Lock([][]byte{readAddress}, [][]byte{})
		assert.Error(t, err)

		// Unlock again (should completely unlock)
		err = intrinsic.Unlock([][]byte{}, [][]byte{readAddress})
		assert.NoError(t, err)

		// Now should be able to lock for writing
		err = intrinsic.Lock([][]byte{readAddress}, [][]byte{})
		assert.NoError(t, err)
	})

	t.Run("Cannot unlock read address with write lock", func(t *testing.T) {
		// Create a new intrinsic for clean state
		intrinsic := hypergraph.NewHypergraphIntrinsic(config, mockHypergraph, nil, &mocks.MockKeyManager{}, nil, nil)

		// Lock an address for writing
		writeAddress := []byte("locked")
		err := intrinsic.Lock([][]byte{writeAddress}, [][]byte{})
		assert.NoError(t, err)

		// Try to unlock as read (should fail)
		err = intrinsic.Unlock([][]byte{}, [][]byte{writeAddress})
		assert.Error(t, err)

		// Unlock as write (should succeed)
		err = intrinsic.Unlock([][]byte{writeAddress}, [][]byte{})
		assert.NoError(t, err)
	})
}
