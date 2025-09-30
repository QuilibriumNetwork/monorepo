package compute

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/compiler"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

// UpdateToBytes serializes ComputeUpdate to bytes
func (c *ComputeUpdate) UpdateToBytes() ([]byte, error) {
	pb := c.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// UpdateFromBytes deserializes ComputeUpdate from bytes
func UpdateFromBytes(data []byte) (*ComputeUpdate, error) {
	update := &protobufs.ComputeUpdate{}
	err := update.FromCanonicalBytes(data)
	if err != nil {
		return nil, errors.Wrap(err, "update from bytes")
	}

	return ComputeUpdateFromProtobuf(update)
}

// DeployToBytes serializes ComputeDeployArguments to bytes using protobuf
func (c *ComputeDeploy) DeployToBytes() ([]byte, error) {
	pb := c.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// DeployFromBytes deserializes ComputeDeployArguments from bytes using protobuf
func DeployFromBytes(data []byte) (*ComputeDeploy, error) {
	pb := &protobufs.ComputeDeploy{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return nil, errors.Wrap(err, "deploy from bytes")
	}

	return ComputeDeployFromProtobuf(pb)
}

// ToBytes serializes a CodeDeployment to bytes using protobuf
func (c *CodeDeployment) ToBytes() ([]byte, error) {
	pb := c.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a CodeDeployment from bytes using protobuf
func (c *CodeDeployment) FromBytes(
	data []byte,
	compiler compiler.CircuitCompiler,
) error {
	pb := &protobufs.CodeDeployment{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := CodeDeploymentFromProtobuf(pb)
	if err != nil {
		return err
	}

	*c = *converted
	c.compiler = compiler
	return nil
}

// ToBytes serializes a CodeExecute to bytes using protobuf
func (c *CodeExecute) ToBytes() ([]byte, error) {
	pb := c.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a CodeExecute from bytes using protobuf
func (c *CodeExecute) FromBytes(
	data []byte,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyManager keys.KeyManager,
	rdfMultiprover *schema.RDFMultiprover,
) error {
	pb := &protobufs.CodeExecute{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := CodeExecuteFromProtobuf(
		pb,
		hypergraph,
		bulletproofProver,
		inclusionProver,
		verEnc,
	)
	if err != nil {
		return err
	}

	*c = *converted
	// Set additional dependencies not handled in conversion
	c.decafConstructor = decafConstructor
	c.keyManager = keyManager
	c.rdfMultiprover = rdfMultiprover

	return nil
}

// ToBytes serializes a CodeFinalize to bytes using protobuf
func (c *CodeFinalize) ToBytes() ([]byte, error) {
	pb := c.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a CodeFinalize from bytes using protobuf
func (c *CodeFinalize) FromBytes(
	data []byte,
	domain [32]byte,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	keyManager keys.KeyManager,
	config *ComputeIntrinsicConfiguration,
	privateKey []byte,
) error {
	pb := &protobufs.CodeFinalize{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := CodeFinalizeFromProtobuf(
		pb,
		domain,
		hypergraph,
		bulletproofProver,
		inclusionProver,
		verEnc,
		keyManager,
		config,
		privateKey,
	)
	if err != nil {
		return err
	}

	*c = *converted
	return nil
}
