package compiler

import (
	"io"
)

// CompiledCircuit represents a compiled circuit without exposing bedlam types
type CompiledCircuit interface {
	// Marshal serializes the circuit to a writer
	Marshal(w io.Writer) error

	// GetMetadata returns any metadata about the compiled circuit
	// This could include annotations or other compiler output
	GetMetadata() interface{}
}

// CircuitCompiler defines the interface for compiling and validating QCL
// circuits
type CircuitCompiler interface {
	// Compile compiles QCL source code into a circuit
	// Returns the compiled circuit and any metadata/annotations
	Compile(source string, inputSizes [][]int) (CompiledCircuit, error)

	// ValidateCircuit validates a compiled circuit from a reader
	// Returns an error if the circuit is invalid
	ValidateCircuit(reader io.Reader) error
}
