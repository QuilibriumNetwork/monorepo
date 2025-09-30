//go:build integrationtest
// +build integrationtest

package compute_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/compiler"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/compute"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	tstore "source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"

	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

// We need ferret because of bedlam's dependency, and bedlam is too complex to
// meaningfully mock, so unfortunately, this must be an integration test

func TestCodeDeployment_NewCodeDeployment(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)
	require.NotNil(t, deployment)

	// Verify fields not set by prove:
	assert.NotNil(t, deployment.Domain)
}

func TestCodeDeployment_GetCost(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	err = deployment.Prove(12345)
	assert.NoError(t, err)

	// Get cost
	cost, err := deployment.GetCost()
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(int64(len(deployment.Circuit))), cost)

	// Test with empty source code
	emptyDeployment, err := compute.NewCodeDeployment(domain, []byte{}, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	err = emptyDeployment.Prove(12345)
	assert.Error(t, err)

	cost, err = emptyDeployment.GetCost()
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), cost)
}

func TestCodeDeployment_Prove(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	frameNumber := uint64(12345)
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	err = deployment.Prove(frameNumber)
	assert.NoError(t, err)

	assert.NotNil(t, deployment.Circuit)
}

func TestCodeDeployment_Verify(t *testing.T) {
	tests := []struct {
		name        string
		sourceCode  []byte
		inputSizes  [2][]int
		expectValid bool
		expectError bool
	}{
		{
			name:        "Valid QCL code",
			sourceCode:  []byte("package main\n\nfunc main(a, b int) int { return a + b }"),
			inputSizes:  [2][]int{{8}, {8}},
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Invalid QCL code - syntax error",
			sourceCode:  []byte("package main\n\nfunc main(a, b int) { return a + b; }"),
			inputSizes:  [2][]int{{8}, {8}},
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Empty source code",
			sourceCode:  []byte(""),
			inputSizes:  [2][]int{{}, {}},
			expectValid: false,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
			deployment, err := compute.NewCodeDeployment(domain, tc.sourceCode, [2]string{"qcl:Int", "qcl:Int"}, tc.inputSizes, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
			require.NoError(t, err)

			err = deployment.Prove(12345)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCodeDeployment_Materialize(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create mock hypergraph
	mockHypergraph := &mocks.MockHypergraph{}

	// Mock the GetVertex call
	mockHypergraph.On("GetVertex", mock.Anything).Return(nil, nil)

	// Create hypergraph state
	state := hgstate.NewHypergraphState(mockHypergraph)

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	// Materialize
	resultState, err := deployment.Materialize(1, state)
	require.NoError(t, err)
	assert.NotNil(t, resultState)

	// Verify the hypergraph state is returned
	_, ok := resultState.(*hgstate.HypergraphState)
	assert.True(t, ok)

	// Verify mocks were called
	mockHypergraph.AssertExpectations(t)
}

func TestCodeDeployment_Materialize_InvalidState(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	// Create invalid state (not a HypergraphState)
	invalidState := &mockState{}

	// Materialize should fail
	resultState, err := deployment.Materialize(1, invalidState)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state type")
	assert.Nil(t, resultState)
}

func TestCodeDeployment_FromBytes(t *testing.T) {
	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create and serialize original deployment
	original, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	// Prove to create the circuit payload
	err = original.Prove(0)
	require.NoError(t, err)

	data, err := original.ToBytes()
	require.NoError(t, err)

	// Deserialize into new deployment
	deployment := &compute.CodeDeployment{}
	err = deployment.FromBytes(data, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Circuit, deployment.Circuit)
}

func TestCodeDeployment_FromBytes_InvalidData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError string
	}{
		{
			name:        "Empty data",
			data:        []byte{},
			expectError: "from bytes",
		},
		{
			name:        "Truncated frame number",
			data:        []byte{0x00, 0x01, 0x02}, // Need 8 bytes for uint64
			expectError: "from bytes",
		},
		{
			name:        "Truncated source length",
			data:        append(make([]byte, 8), []byte{0x00, 0x01}...), // Need 4 bytes for uint32
			expectError: "from bytes",
		},
		{
			name: "Truncated source code",
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.BigEndian, uint64(12345))
				binary.Write(buf, binary.BigEndian, uint32(100)) // Says 100 bytes
				buf.Write([]byte("only 10 bytes"))               // But only provides 13
				return buf.Bytes()
			}(),
			expectError: "from bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deployment := &compute.CodeDeployment{}
			err := deployment.FromBytes(tc.data, compiler.NewBedlamCompiler())
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectError)
		})
	}
}

func TestCodeDeployment_Serialization_RoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		sourceCode  []byte
		frameNumber uint64
	}{
		{
			name:        "Simple code",
			sourceCode:  []byte("package main\n\nfunc main(a, b int) (string, int) { return \"ok\", a + b }"),
			frameNumber: 1,
		},
		{
			name:        "Code with special characters",
			sourceCode:  []byte("package main\n\nfunc main(a, b int) (string, int) { return \"hello\\nworld\\t!@#$%^&*()\", 1 }"),
			frameNumber: 999999,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

			// Create original
			original, err := compute.NewCodeDeployment(domain, tc.sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:String", "qcl:Int"}, compiler.NewBedlamCompiler())
			require.NoError(t, err)

			err = original.Prove(12345)
			require.NoError(t, err)

			// Serialize
			data, err := original.ToBytes()
			require.NoError(t, err)

			// Deserialize
			deserialized := &compute.CodeDeployment{}
			err = deserialized.FromBytes(data, compiler.NewBedlamCompiler())
			require.NoError(t, err)

			// Verify exact match
			assert.Equal(t, original.Domain, deserialized.Domain)
			assert.Equal(t, original.Circuit, deserialized.Circuit)
			assert.Equal(t, original.InputTypes, deserialized.InputTypes)
			assert.Equal(t, original.OutputTypes, deserialized.OutputTypes)
		})
	}
}

func TestCodeDeployment_Materialize_TreeConstruction(t *testing.T) {
	l, _ := zap.NewProduction()
	ip := bls48581.NewKZGInclusionProver(l)
	s := store.NewPebbleDB(l, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
	ve := verenc.NewMPCitHVerifiableEncryptor(1)
	hg := hypergraph.NewHypergraph(
		l,
		store.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, l, ve, ip),
		ip,
		[]int{},
		&tests.Nopthenticator{},
	)

	// Test data
	sourceCode := []byte("package main\n\nfunc main(a, b int) int { return a + b }")
	frameNumber := uint64(12345)
	domain := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Create hypergraph state
	state := hgstate.NewHypergraphState(hg)

	// Create code deployment
	deployment, err := compute.NewCodeDeployment(domain, sourceCode, [2]string{"qcl:Int", "qcl:Int"}, [2][]int{{8}, {8}}, []string{"qcl:Int"}, compiler.NewBedlamCompiler())
	require.NoError(t, err)

	// Prove
	err = deployment.Prove(frameNumber)
	require.NoError(t, err)

	// Materialize
	_, err = deployment.Materialize(frameNumber, state)
	require.NoError(t, err)

	// Verify the state commits
	err = state.Commit()
	require.NoError(t, err)

	// Verify the tree was constructed correctly
	require.NotNil(t, state.Changeset()[0].Value)
	require.NoError(t, err)

	// Verify the tree
	tree, err := hg.GetVertexData([64]byte(slices.Concat(state.Changeset()[0].Domain, state.Changeset()[0].Address)))
	require.NoError(t, err)

	// Check source code at index 0
	sourceData, err := tree.Get([]byte{0 << 2})
	require.NoError(t, err)
	assert.Equal(t, deployment.Circuit, sourceData)
	assert.Equal(t, big.NewInt(int64(len(deployment.Circuit))), tree.GetSize())
}

// mockState is a mock implementation of state.State for testing
type mockState struct{}

// Abort implements state.State.
func (m *mockState) Abort() error {
	panic("unimplemented")
}

// Changeset implements state.State.
func (m *mockState) Changeset() []state.StateChange {
	panic("unimplemented")
}

// Commit implements state.State.
func (m *mockState) Commit() error {
	panic("unimplemented")
}

// Delete implements state.State.
func (m *mockState) Delete(domain []byte, address []byte, discriminator []byte, frameNumber uint64) error {
	panic("unimplemented")
}

// Get implements state.State.
func (m *mockState) Get(domain []byte, address []byte, discriminator []byte) (interface{}, error) {
	panic("unimplemented")
}

// Init implements state.State.
func (m *mockState) Init(domain []byte, consensusMetadata *tries.VectorCommitmentTree, sumcheckInfo *tries.VectorCommitmentTree, rdfSchema string, additionalData []*tries.VectorCommitmentTree, intrinsicType []byte) error {
	panic("unimplemented")
}

// Revert implements state.State.
func (m *mockState) Revert() error {
	panic("unimplemented")
}

// Set implements state.State.
func (m *mockState) Set(domain []byte, address []byte, discriminator []byte, frameNumber uint64, value state.MaterializedState) error {
	panic("unimplemented")
}

func (m *mockState) GetAddress() []byte { return nil }
func (m *mockState) GetData() []byte    { return nil }

type mockTransaction struct{}

// Abort implements store.Transaction.
func (m *mockTransaction) Abort() error {
	panic("unimplemented")
}

// Commit implements store.Transaction.
func (m *mockTransaction) Commit() error {
	return nil
}

// Delete implements store.Transaction.
func (m *mockTransaction) Delete(key []byte) error {
	panic("unimplemented")
}

// DeleteRange implements store.Transaction.
func (m *mockTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	panic("unimplemented")
}

// Get implements store.Transaction.
func (m *mockTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	panic("unimplemented")
}

// NewIter implements store.Transaction.
func (m *mockTransaction) NewIter(lowerBound []byte, upperBound []byte) (tstore.Iterator, error) {
	panic("unimplemented")
}

// Set implements store.Transaction.
func (m *mockTransaction) Set(key []byte, value []byte) error {
	return nil
}

var _ tstore.Transaction = (*mockTransaction)(nil)
