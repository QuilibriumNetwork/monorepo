package compiler

import (
	"io"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/circuit"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ast"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	tcompiler "source.quilibrium.com/quilibrium/monorepo/types/compiler"
)

// bedlamCircuit wraps a bedlam circuit to implement compiler.CompiledCircuit
type bedlamCircuit struct {
	circuit     *circuit.Circuit
	annotations ast.Annotations
}

// Marshal implements compiler.CompiledCircuit
func (b *bedlamCircuit) Marshal(w io.Writer) error {
	return b.circuit.Marshal(w)
}

// GetMetadata implements compiler.CompiledCircuit
func (b *bedlamCircuit) GetMetadata() interface{} {
	return b.annotations
}

// BedlamCompiler implements compiler.CircuitCompiler using the bedlam compiler
type BedlamCompiler struct {
	params *utils.Params
}

// NewBedlamCompiler creates a new BedlamCompiler
func NewBedlamCompiler() *BedlamCompiler {
	return &BedlamCompiler{
		params: &utils.Params{},
	}
}

// Compile implements compiler.CircuitCompiler
func (c *BedlamCompiler) Compile(
	source string,
	inputSizes [][]int,
) (tcompiler.CompiledCircuit, error) {
	comp := compiler.New(c.params)
	circ, annotations, err := comp.Compile(source, inputSizes)
	if err != nil {
		return nil, err
	}

	return &bedlamCircuit{
		circuit:     circ,
		annotations: annotations,
	}, nil
}

// ValidateCircuit implements compiler.CircuitCompiler
func (c *BedlamCompiler) ValidateCircuit(reader io.Reader) error {
	_, err := circuit.ParseQCLC(reader)
	return err
}
