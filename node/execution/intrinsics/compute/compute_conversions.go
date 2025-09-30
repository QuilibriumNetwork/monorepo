package compute

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// FromProtobuf converts a protobuf ComputeIntrinsicConfiguration to intrinsics
// ComputeIntrinsicConfiguration
func ComputeConfigurationFromProtobuf(
	pb *protobufs.ComputeConfiguration,
) (*ComputeIntrinsicConfiguration, error) {
	if pb == nil {
		return nil, nil
	}

	return &ComputeIntrinsicConfiguration{
		ReadPublicKey:  pb.ReadPublicKey,
		WritePublicKey: pb.WritePublicKey,
		OwnerPublicKey: pb.OwnerPublicKey,
	}, nil
}

// ToProtobuf converts an intrinsics ComputeIntrinsicConfiguration to protobuf
// ComputeIntrinsicConfiguration
func (
	c *ComputeIntrinsicConfiguration,
) ToProtobuf() *protobufs.ComputeConfiguration {
	if c == nil {
		return nil
	}

	return &protobufs.ComputeConfiguration{
		ReadPublicKey:  c.ReadPublicKey,
		WritePublicKey: c.WritePublicKey,
		OwnerPublicKey: c.OwnerPublicKey,
	}
}

// FromProtobuf converts a protobuf ComputeDeploy to intrinsics
// ComputeDeploy
func ComputeDeployFromProtobuf(
	pb *protobufs.ComputeDeploy,
) (*ComputeDeploy, error) {
	if pb == nil {
		return nil, nil
	}

	if len(pb.RdfSchema) == 0 {
		return nil, errors.Wrap(
			errors.New("missing rdf schema"),
			"compute deploy from protobuf",
		)
	}

	config, err := ComputeConfigurationFromProtobuf(pb.Config)
	if err != nil {
		return nil, errors.Wrap(err, "compute deploy from protobuf")
	}

	return &ComputeDeploy{
		Config:    config,
		RDFSchema: pb.RdfSchema,
	}, nil
}

// ToProtobuf converts an intrinsics ComputeDeploy to protobuf
// ComputeDeploy
func (
	c *ComputeDeploy,
) ToProtobuf() *protobufs.ComputeDeploy {
	if c == nil {
		return nil
	}

	return &protobufs.ComputeDeploy{
		Config:    c.Config.ToProtobuf(),
		RdfSchema: c.RDFSchema,
	}
}

// ComputeUpdateFromProtobuf converts protobuf ComputeUpdate to intrinsics
func ComputeUpdateFromProtobuf(
	pb *protobufs.ComputeUpdate,
) (*ComputeUpdate, error) {
	if pb == nil {
		return nil, nil
	}

	config, err := ComputeConfigurationFromProtobuf(pb.Config)
	if err != nil {
		return nil, errors.Wrap(err, "compute update from protobuf")
	}

	return &ComputeUpdate{
		Config:         config,
		RDFSchema:      pb.RdfSchema,
		OwnerSignature: pb.PublicKeySignatureBls48581,
	}, nil
}

// ToProtobuf converts intrinsics ComputeUpdate to protobuf
func (c *ComputeUpdate) ToProtobuf() *protobufs.ComputeUpdate {
	if c == nil {
		return nil
	}

	return &protobufs.ComputeUpdate{
		Config:                     c.Config.ToProtobuf(),
		RdfSchema:                  c.RDFSchema,
		PublicKeySignatureBls48581: c.OwnerSignature,
	}
}

// FromProtobuf converts a protobuf CodeDeployment to intrinsics CodeDeployment
func CodeDeploymentFromProtobuf(pb *protobufs.CodeDeployment) (
	*CodeDeployment,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert InputTypes from slice to fixed array
	var inputTypes [2]string
	for i := 0; i < len(pb.InputTypes) && i < 2; i++ {
		inputTypes[i] = pb.InputTypes[i]
	}

	return &CodeDeployment{
		Circuit:     pb.Circuit,
		InputTypes:  inputTypes,
		OutputTypes: pb.OutputTypes,
		Domain:      domain,
	}, nil
}

// ToProtobuf converts an intrinsics CodeDeployment to protobuf CodeDeployment
func (c *CodeDeployment) ToProtobuf() *protobufs.CodeDeployment {
	if c == nil {
		return nil
	}

	// Convert InputTypes from fixed array to slice
	inputTypes := make([]string, 0, 2)
	for _, t := range c.InputTypes {
		if t != "" {
			inputTypes = append(inputTypes, t)
		}
	}

	return &protobufs.CodeDeployment{
		Circuit:     c.Circuit,
		InputTypes:  inputTypes,
		OutputTypes: c.OutputTypes,
		Domain:      c.Domain[:],
	}
}

// FromProtobuf converts a protobuf ExecuteOperation to intrinsics
// ExecuteOperation
func ExecuteOperationFromProtobuf(pb *protobufs.ExecuteOperation) (
	*ExecuteOperation,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	app := Application{}
	if pb.Application != nil {
		app.Address = pb.Application.Address
		app.ExecutionContext = ExecutionContext(pb.Application.ExecutionContext)
	}

	return &ExecuteOperation{
		Application:  app,
		Identifier:   pb.Identifier,
		Dependencies: pb.Dependencies,
	}, nil
}

// ToProtobuf converts an intrinsics ExecuteOperation to protobuf
// ExecuteOperation
func (e *ExecuteOperation) ToProtobuf() *protobufs.ExecuteOperation {
	if e == nil {
		return nil
	}

	return &protobufs.ExecuteOperation{
		Application: &protobufs.Application{
			Address: e.Application.Address,
			ExecutionContext: protobufs.ExecutionContext(
				e.Application.ExecutionContext,
			),
		},
		Identifier:   e.Identifier,
		Dependencies: e.Dependencies,
	}
}

// FromProtobuf converts a protobuf CodeExecute to intrinsics CodeExecute
func CodeExecuteFromProtobuf(
	pb *protobufs.CodeExecute,
	hg hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
) (*CodeExecute, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert rendezvous from slice to array
	var rendezvous [32]byte
	copy(rendezvous[:], pb.Rendezvous)

	// Convert ProofOfPayment from [][]byte to [2][]byte
	var proofOfPayment [2][]byte
	for i := 0; i < len(pb.ProofOfPayment) && i < 2; i++ {
		proofOfPayment[i] = pb.ProofOfPayment[i]
	}

	// Convert ExecuteOperations
	executeOps := make([]*ExecuteOperation, len(pb.ExecuteOperations))
	for i, op := range pb.ExecuteOperations {
		converted, err := ExecuteOperationFromProtobuf(op)
		if err != nil {
			return nil, errors.Wrapf(err, "converting execute operation %d", i)
		}
		executeOps[i] = converted
	}

	return &CodeExecute{
		ProofOfPayment:    proofOfPayment,
		Domain:            domain,
		Rendezvous:        rendezvous,
		ExecuteOperations: executeOps,
		hypergraph:        hg,
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		verEnc:            verEnc,
	}, nil
}

// ToProtobuf converts an intrinsics CodeExecute to protobuf CodeExecute
func (c *CodeExecute) ToProtobuf() *protobufs.CodeExecute {
	if c == nil {
		return nil
	}

	// Convert ProofOfPayment from [2][]byte to [][]byte
	proofOfPayment := make([][]byte, 0, 2)
	for _, proof := range c.ProofOfPayment {
		if proof != nil {
			proofOfPayment = append(proofOfPayment, proof)
		}
	}

	// Convert ExecuteOperations
	executeOps := make([]*protobufs.ExecuteOperation, len(c.ExecuteOperations))
	for i, op := range c.ExecuteOperations {
		executeOps[i] = op.ToProtobuf()
	}

	return &protobufs.CodeExecute{
		ProofOfPayment:    proofOfPayment,
		Domain:            c.Domain[:],
		Rendezvous:        c.Rendezvous[:],
		ExecuteOperations: executeOps,
	}
}

// FromProtobuf converts a protobuf StateTransition to intrinsics
// StateTransition
func StateTransitionFromProtobuf(pb *protobufs.StateTransition) (
	*StateTransition,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	return &StateTransition{
		Domain:   domain,
		Address:  pb.Address,
		OldValue: pb.OldValue,
		NewValue: pb.NewValue,
		// Note: intrinsics has additional Proof field not in protobuf
		Proof: nil, // Will need to be set separately if needed
	}, nil
}

// ToProtobuf converts an intrinsics StateTransition to protobuf StateTransition
func (s *StateTransition) ToProtobuf() *protobufs.StateTransition {
	if s == nil {
		return nil
	}

	return &protobufs.StateTransition{
		Domain:   s.Domain[:],
		Address:  s.Address,
		OldValue: s.OldValue,
		NewValue: s.NewValue,
		Proof:    s.Proof,
	}
}

// FromProtobuf converts a protobuf ExecutionResult to intrinsics
// ExecutionResult
func ExecutionResultFromProtobuf(pb *protobufs.ExecutionResult) (
	*ExecutionResult,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	return &ExecutionResult{
		OperationID: pb.OperationId,
		Success:     pb.Success,
		Output:      pb.Output,
		Error:       pb.Error,
	}, nil
}

// ToProtobuf converts an intrinsics ExecutionResult to protobuf ExecutionResult
func (e *ExecutionResult) ToProtobuf() *protobufs.ExecutionResult {
	if e == nil {
		return nil
	}

	return &protobufs.ExecutionResult{
		OperationId: e.OperationID,
		Success:     e.Success,
		Output:      e.Output,
		Error:       e.Error,
	}
}

// FromProtobuf converts a protobuf CodeFinalize to intrinsics CodeFinalize
func CodeFinalizeFromProtobuf(
	pb *protobufs.CodeFinalize,
	domain [32]byte,
	hg hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	keyManager keys.KeyManager,
	config *ComputeIntrinsicConfiguration,
	privateKey []byte,
) (*CodeFinalize, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert rendezvous from slice to array
	var rendezvous [32]byte
	copy(rendezvous[:], pb.Rendezvous)

	// Convert Results
	results := make([]*ExecutionResult, len(pb.Results))
	for i, result := range pb.Results {
		converted, err := ExecutionResultFromProtobuf(result)
		if err != nil {
			return nil, errors.Wrapf(err, "converting execution result %d", i)
		}
		results[i] = converted
	}

	// Convert StateChanges
	stateChanges := make([]*StateTransition, len(pb.StateChanges))
	for i, change := range pb.StateChanges {
		converted, err := StateTransitionFromProtobuf(change)
		if err != nil {
			return nil, errors.Wrapf(err, "converting state transition %d", i)
		}
		stateChanges[i] = converted
	}

	return &CodeFinalize{
		Rendezvous:        rendezvous,
		Results:           results,
		StateChanges:      stateChanges,
		ProofOfExecution:  pb.ProofOfExecution,
		MessageOutput:     pb.MessageOutput,
		domain:            domain,
		hypergraph:        hg,
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		verEnc:            verEnc,
		keyManager:        keyManager,
		config:            config,
		privateKey:        privateKey,
	}, nil
}

// ToProtobuf converts an intrinsics CodeFinalize to protobuf CodeFinalize
func (c *CodeFinalize) ToProtobuf() *protobufs.CodeFinalize {
	if c == nil {
		return nil
	}

	// Convert Results
	results := make([]*protobufs.ExecutionResult, len(c.Results))
	for i, result := range c.Results {
		results[i] = result.ToProtobuf()
	}

	// Convert StateChanges
	stateChanges := make([]*protobufs.StateTransition, len(c.StateChanges))
	for i, change := range c.StateChanges {
		stateChanges[i] = change.ToProtobuf()
	}

	return &protobufs.CodeFinalize{
		Rendezvous:       c.Rendezvous[:],
		Results:          results,
		StateChanges:     stateChanges,
		ProofOfExecution: c.ProofOfExecution,
		MessageOutput:    c.MessageOutput,
	}
}
