package compute

import (
	"bytes"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// CodeDeployment represents a code deployment operation
type CodeDeployment struct {
	// The QCL circuit to deploy
	Circuit []byte
	// The QCL types/classes of the main arguments, 0 - garbler, 1 - evaluator
	InputTypes [2]string
	// The QCL types/classes of the output values
	OutputTypes []string
	// The app address
	Domain [32]byte

	inputQCLSource []byte
	inputSizes     [2][]int
	compiler       compiler.CircuitCompiler
}

// NewCodeDeployment creates a new code deployment
func NewCodeDeployment(
	domain [32]byte,
	sourceCode []byte,
	inputTypes [2]string,
	inputSizes [2][]int,
	outputTypes []string,
	compiler compiler.CircuitCompiler,
) (*CodeDeployment, error) {
	return &CodeDeployment{
		inputQCLSource: sourceCode,
		Domain:         domain,
		InputTypes:     inputTypes,
		OutputTypes:    outputTypes,
		inputSizes:     inputSizes,
		compiler:       compiler,
	}, nil
}

// GetCost implements intrinsics.IntrinsicOperation
func (c *CodeDeployment) GetCost() (*big.Int, error) {
	// Cost based on code size
	return big.NewInt(int64(len(c.Circuit))), nil
}

// Prove implements intrinsics.IntrinsicOperation
func (c *CodeDeployment) Prove(frameNumber uint64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrap(
				errors.New("panic encountered while proving code"),
				"prove",
			)
		}
	}()

	compiledCircuit, err := c.compiler.Compile(
		string(c.inputQCLSource),
		c.inputSizes[:],
	)
	if err != nil {
		return errors.Wrap(err, "verify")
	}

	buf := new(bytes.Buffer)
	if err = compiledCircuit.Marshal(buf); err != nil {
		return errors.Wrap(err, "verify")
	}

	out := buf.Bytes()
	c.Circuit = out

	return nil
}

func (c *CodeDeployment) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (c *CodeDeployment) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	// Get the domain from the hypergraph
	domain := c.Domain

	// Generate a unique address for this code file
	codeAddressBI, err := poseidon.HashBytes(
		slices.Concat(
			domain[:],
			c.Circuit,
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	codeAddress := codeAddressBI.FillBytes(make([]byte, 32))
	codeFullAddress := [64]byte{}
	copy(codeFullAddress[:32], c.Domain[:])
	copy(codeFullAddress[32:], codeAddress)

	return [][]byte{codeFullAddress[:]}, nil
}

// Verify implements intrinsics.IntrinsicOperation
func (c *CodeDeployment) Verify(frameNumber uint64) (bool, error) {
	buf := bytes.NewReader(c.Circuit)
	err := c.compiler.ValidateCircuit(buf)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	return true, nil
}

// Materialize implements intrinsics.IntrinsicOperation
func (c *CodeDeployment) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraph, ok := state.(*hg.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state type"), "materialize")
	}

	// Get the domain from the hypergraph
	domain := c.Domain

	// Generate a unique address for this code file
	codeAddressBI, err := poseidon.HashBytes(
		slices.Concat(
			domain[:],
			c.Circuit,
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	codeAddress := codeAddressBI.FillBytes(make([]byte, 32))

	// Create a tree to store the code
	codeTree := &qcrypto.VectorCommitmentTree{}

	// Store the code content
	if err := codeTree.Insert(
		[]byte{0 << 2}, // Index 0
		c.Circuit,
		nil,
		big.NewInt(int64(len(c.Circuit))),
	); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Create the materialized state
	value := hypergraph.NewVertexAddMaterializedState(
		[32]byte(domain),
		[32]byte(codeAddress),
		frameNumber,
		nil,
		codeTree,
	)

	// Set the state
	err = hypergraph.Set(
		domain[:],
		codeAddress,
		hg.VertexAddsDiscriminator,
		frameNumber,
		value,
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	return hypergraph, nil
}

var _ intrinsics.IntrinsicOperation = (*CodeDeployment)(nil)
