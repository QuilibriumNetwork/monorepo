package compute

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hg "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// StateTransition represents a state change to be committed
type StateTransition struct {
	Domain   [32]byte
	Address  []byte
	OldValue []byte
	NewValue []byte
	Proof    []byte
}

// ExecutionResult represents the result of a single operation
type ExecutionResult struct {
	OperationID []byte
	Success     bool
	Output      []byte
	Error       []byte
}

// CodeFinalize finalizes the execution of a CodeExecute operation
type CodeFinalize struct {
	Rendezvous       [32]byte
	Results          []*ExecutionResult
	StateChanges     []*StateTransition
	ProofOfExecution []byte
	MessageOutput    []byte // Transient output to return to requestor

	domain            [32]byte
	privateKey        []byte // used for prove operation, nil for verify/materialize
	config            *ComputeIntrinsicConfiguration
	hypergraph        hypergraph.Hypergraph
	bulletproofProver crypto.BulletproofProver
	inclusionProver   crypto.InclusionProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	keyManager        tkeys.KeyManager
}

func NewCodeFinalize(
	rendezvous [32]byte,
	domain [32]byte,
	results []*ExecutionResult,
	stateChanges []*StateTransition,
	messageOutput []byte,
	privateKey []byte,
	config *ComputeIntrinsicConfiguration,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyManager tkeys.KeyManager,
) *CodeFinalize {
	return &CodeFinalize{
		Rendezvous:        rendezvous,
		Results:           results,
		StateChanges:      stateChanges,
		MessageOutput:     messageOutput,
		domain:            domain,
		privateKey:        privateKey,
		config:            config,
		hypergraph:        hypergraph,
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		keyManager:        keyManager,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (c *CodeFinalize) GetCost() (*big.Int, error) {
	// Cost based on number of state changes and results
	baseCost := int64(32)

	stateChangeSum := 0
	for _, ch := range c.StateChanges {
		chb, err := ch.ToProtobuf().ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		stateChangeSum += len(chb)
	}

	resultSum := 0
	for _, r := range c.Results {
		rb, err := r.ToProtobuf().ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "get cost")
		}

		resultSum += len(rb)
	}

	return big.NewInt(baseCost + int64(stateChangeSum) + int64(resultSum)), nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (c *CodeFinalize) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraph, ok := state.(*hg.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state type"), "materialize")
	}

	// Store state changes
	if err := c.storeStateChanges(hypergraph, frameNumber); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Store execution results
	if err := c.storeExecutionResults(hypergraph, frameNumber); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	return hypergraph, nil
}

// storeExecutionResults stores the results of successful execution
func (c *CodeFinalize) storeExecutionResults(
	hypergraph *hg.HypergraphState,
	frameNumber uint64,
) error {
	// Create a tree to store execution results
	resultsTree := &qcrypto.VectorCommitmentTree{}

	// Store rendezvous
	if err := resultsTree.Insert(
		[]byte{0 << 2},
		c.Rendezvous[:],
		nil,
		big.NewInt(32),
	); err != nil {
		return errors.Wrap(err, "storeExecutionResults")
	}

	// Store results
	resultsBytes, err := c.serializeResults()
	if err != nil {
		return errors.Wrap(err, "storeExecutionResults")
	}

	if err := resultsTree.Insert(
		[]byte{1 << 2},
		resultsBytes,
		nil,
		big.NewInt(int64(len(resultsBytes))),
	); err != nil {
		return errors.Wrap(err, "storeExecutionResults")
	}

	// Store state changes summary
	changesBytes, err := c.serializeStateChanges()
	if err != nil {
		return errors.Wrap(err, "storeExecutionResults")
	}

	if err := resultsTree.Insert(
		[]byte{2 << 2},
		changesBytes,
		nil,
		big.NewInt(int64(len(changesBytes))),
	); err != nil {
		return errors.Wrap(err, "store execution results")
	}

	// Generate results address
	resultsBI, err := poseidon.HashBytes(slices.Concat(
		c.Rendezvous[:],
		[]byte("RESULTS_CODE_FINALIZE"),
	))
	if err != nil {
		return errors.Wrap(err, "store execution results")
	}
	resultsAddress := resultsBI.FillBytes(make([]byte, 32))

	// Create results state
	value := hypergraph.NewVertexAddMaterializedState(
		c.domain,
		[32]byte(resultsAddress),
		frameNumber,
		nil,
		resultsTree,
	)

	// Store results
	err = hypergraph.Set(
		c.domain[:],
		resultsAddress,
		hg.VertexAddsDiscriminator,
		frameNumber,
		value,
	)

	return err
}

// storeStateChanges stores the state transitions from execution
func (c *CodeFinalize) storeStateChanges(
	hypergraph *hg.HypergraphState,
	frameNumber uint64,
) error {
	// Create a tree to store state changes
	changesTree := &qcrypto.VectorCommitmentTree{}

	// Store each state change with uint16 BigEndian keys
	for i, change := range c.StateChanges {
		// Create key from index
		key := make([]byte, 2)
		binary.BigEndian.PutUint16(key, uint16(i))

		// Convert state change to protobuf and get canonical bytes
		changeProto := change.ToProtobuf()
		changeBytes, err := changeProto.ToCanonicalBytes()
		if err != nil {
			return errors.Wrap(err, "store state changes")
		}

		// Insert the serialized state change
		if err := changesTree.Insert(
			key,
			changeBytes,
			nil,
			big.NewInt(int64(len(changeBytes))),
		); err != nil {
			return errors.Wrap(err, "store state changes")
		}
	}

	// Generate state changes address similar to results address
	changesBI, err := poseidon.HashBytes(slices.Concat(
		c.Rendezvous[:],
		[]byte("STATE_CHANGES_CODE_FINALIZE"),
	))
	if err != nil {
		return errors.Wrap(err, "store state changes")
	}
	changesAddress := changesBI.FillBytes(make([]byte, 32))

	// Create state changes materialized state
	value := hypergraph.NewVertexAddMaterializedState(
		c.domain,
		[32]byte(changesAddress),
		frameNumber,
		nil,
		changesTree,
	)

	// Store state changes
	err = hypergraph.Set(
		c.domain[:],
		changesAddress,
		hg.VertexAddsDiscriminator,
		frameNumber,
		value,
	)

	return errors.Wrap(err, "store state changes")
}

// Prove implements intrinsics.IntrinsicOperation.
func (c *CodeFinalize) Prove(frameNumber uint64) error {
	signer, err := keys.Ed448KeyFromBytes(c.privateKey, c.config.WritePublicKey)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	clone := c.ToProtobuf()
	clone.ProofOfExecution = nil
	msg, err := clone.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	// TODO(2.2): Non-notary proof of execution
	c.ProofOfExecution, err = signer.SignWithDomain(
		msg,
		slices.Concat(c.domain[:], []byte("CODE_FINALIZE")),
	)

	return errors.Wrap(err, "prove")
}

// Verify implements intrinsics.IntrinsicOperation.
func (c *CodeFinalize) Verify(frameNumber uint64) (bool, error) {
	// Verify all results are present
	if len(c.Results) == 0 {
		return false, errors.Wrap(
			errors.New("no execution results provided"),
			"verify",
		)
	}

	// Verify state transitions are valid
	for _, change := range c.StateChanges {
		if len(change.Address) != 32 || len(change.Domain) != 32 {
			return false, errors.Wrap(
				errors.New("invalid address length in state change"),
				"verify",
			)
		}
	}

	clone := c.ToProtobuf()
	clone.ProofOfExecution = nil
	msg, err := clone.ToCanonicalBytes()
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	valid, err := c.keyManager.ValidateSignature(
		crypto.KeyTypeEd448,
		c.config.WritePublicKey,
		msg,
		c.ProofOfExecution,
		slices.Concat(c.domain[:], []byte("CODE_FINALIZE")),
	)

	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	if !valid {
		return false, errors.Wrap(errors.New("invalid signature"), "verify")
	}

	return true, nil
}

// serializeResults serializes all execution results
func (c *CodeFinalize) serializeResults() ([]byte, error) {
	var buf bytes.Buffer

	// Write result count
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(c.Results)),
	); err != nil {
		return nil, err
	}

	// Write each result
	for _, result := range c.Results {
		// Operation ID
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(result.OperationID)),
		); err != nil {
			return nil, err
		}
		buf.Write(result.OperationID)

		// Success flag
		if result.Success {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}

		// Output
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(result.Output)),
		); err != nil {
			return nil, err
		}
		buf.Write(result.Output)
	}

	return buf.Bytes(), nil
}

// serializeStateChanges serializes state transitions
func (c *CodeFinalize) serializeStateChanges() ([]byte, error) {
	var buf bytes.Buffer

	// Write change count
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		uint32(len(c.StateChanges)),
	); err != nil {
		return nil, err
	}

	// Write each change
	for _, change := range c.StateChanges {
		// Domain
		buf.Write(change.Domain[:])

		// Address
		if err := binary.Write(
			&buf,
			binary.BigEndian,
			uint32(len(change.Address)),
		); err != nil {
			return nil, err
		}
		buf.Write(change.Address)

		// New value hash (not full value for space efficiency)
		valueHash, err := poseidon.HashBytes(change.NewValue)
		if err != nil {
			return nil, err
		}
		buf.Write(valueHash.FillBytes(make([]byte, 32)))
	}

	return buf.Bytes(), nil
}

var _ intrinsics.IntrinsicOperation = (*CodeFinalize)(nil)
