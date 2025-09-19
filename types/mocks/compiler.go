package mocks

import (
	"io"

	"github.com/stretchr/testify/mock"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
)

// MockCompiledCircuit is a mock implementation of CompiledCircuit for testing
type MockCompiledCircuit struct {
	mock.Mock
}

// Marshal implements CompiledCircuit
func (m *MockCompiledCircuit) Marshal(w io.Writer) error {
	args := m.Called(w)
	return args.Error(0)
}

// GetMetadata implements CompiledCircuit
func (m *MockCompiledCircuit) GetMetadata() interface{} {
	args := m.Called()
	return args.Get(0)
}

// MockCompiler is a mock implementation of CircuitCompiler for testing
type MockCompiler struct {
	mock.Mock
}

// Compile implements CircuitCompiler
func (m *MockCompiler) Compile(
	source string,
	inputSizes [][]int,
) (compiler.CompiledCircuit, error) {
	args := m.Called(source, inputSizes)
	return args.Get(0).(compiler.CompiledCircuit), args.Error(1)
}

// ValidateCircuit implements CircuitCompiler
func (m *MockCompiler) ValidateCircuit(reader io.Reader) error {
	args := m.Called(reader)
	return args.Error(0)
}
