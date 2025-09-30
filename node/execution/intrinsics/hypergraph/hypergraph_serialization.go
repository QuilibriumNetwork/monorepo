package hypergraph

import (
	"github.com/pkg/errors"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// Operation type constants
const (
	HypergraphDeployType uint32 = protobufs.HypergraphDeploymentType
	HypergraphUpdateType uint32 = protobufs.HypergraphUpdateType
	VertexAddType        uint32 = protobufs.VertexAddType
	VertexRemoveType     uint32 = protobufs.VertexRemoveType
	HyperedgeAddType     uint32 = protobufs.HyperedgeAddType
	HyperedgeRemoveType  uint32 = protobufs.HyperedgeRemoveType
)

// ToBytes serializes a VertexAdd operation to bytes using protobuf
func (va *VertexAdd) ToBytes() ([]byte, error) {
	pb, err := va.ToProtobuf()
	if err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a VertexAdd from bytes using protobuf
func (va *VertexAdd) FromBytes(
	data []byte,
	config *HypergraphIntrinsicConfiguration,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	signer crypto.Signer,
	verenc crypto.VerifiableEncryptor,
) error {
	pb := &protobufs.VertexAdd{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	var err error
	va.Data, err = extractVertexAddProofFromBytes(pb.Data, va.verenc)
	va.config = config
	va.inclusionProver = inclusionProver
	va.keyManager = keyManager
	va.signer = signer
	va.verenc = verenc

	return errors.Wrap(err, "from bytes")
}

// ToBytes serializes a VertexRemove operation to bytes using protobuf
func (vr *VertexRemove) ToBytes() ([]byte, error) {
	pb := vr.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a VertexRemove from bytes using protobuf
func (vr *VertexRemove) FromBytes(
	data []byte,
	config *HypergraphIntrinsicConfiguration,
	keyManager keys.KeyManager,
	signer crypto.Signer,
) error {
	pb := &protobufs.VertexRemove{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy the basic fields from protobuf
	copy(vr.Domain[:], pb.Domain)
	copy(vr.DataAddress[:], pb.DataAddress)
	vr.Signature = pb.Signature
	vr.config = config
	vr.keyManager = keyManager
	vr.signer = signer

	return nil
}

// ToBytes serializes a HyperedgeAdd operation to bytes using protobuf
func (ha *HyperedgeAdd) ToBytes() ([]byte, error) {
	pb, err := ha.ToProtobuf()
	if err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a HyperedgeAdd from bytes using protobuf
func (ha *HyperedgeAdd) FromBytes(
	data []byte,
	config *HypergraphIntrinsicConfiguration,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	signer crypto.Signer,
) error {
	pb := &protobufs.HyperedgeAdd{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy the basic fields from protobuf
	copy(ha.Domain[:], pb.Domain)
	ha.Signature = pb.Signature
	ha.config = config
	ha.inclusionProver = inclusionProver
	ha.keyManager = keyManager
	ha.signer = signer

	// Deserialize Value (Hyperedge) if present
	if len(pb.Value) > 0 {
		atom := hgcrdt.AtomFromBytes(pb.Value)
		if atom == nil {
			return errors.Wrap(errors.New("invalid data"), "from bytes")
		}

		var ok bool
		ha.Value, ok = atom.(hypergraph.Hyperedge)
		if !ok {
			return errors.Wrap(errors.New("data not hyperedge"), "from bytes")
		}
	}

	return nil
}

// ToBytes serializes a HyperedgeRemove operation to bytes using protobuf
func (hr *HyperedgeRemove) ToBytes() ([]byte, error) {
	pb, err := hr.ToProtobuf()
	if err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a HyperedgeRemove from bytes using protobuf
func (hr *HyperedgeRemove) FromBytes(
	data []byte,
	config *HypergraphIntrinsicConfiguration,
	keyManager keys.KeyManager,
	signer crypto.Signer,
) error {
	pb := &protobufs.HyperedgeRemove{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy the basic fields from protobuf
	copy(hr.Domain[:], pb.Domain)
	hr.Signature = pb.Signature
	hr.config = config
	hr.keyManager = keyManager
	hr.signer = signer

	// Deserialize Value (Hyperedge) if present
	if len(pb.Value) > 0 {
		atom := hgcrdt.AtomFromBytes(pb.Value)
		if atom == nil {
			return errors.Wrap(errors.New("invalid data"), "from bytes")
		}

		var ok bool
		hr.Value, ok = atom.(hypergraph.Hyperedge)
		if !ok {
			return errors.Wrap(errors.New("data not hyperedge"), "from bytes")
		}
	}

	return nil
}

// HypergraphDeployArguments represents the arguments for deploying a hypergraph intrinsic
type HypergraphDeployArguments struct {
	Config    *HypergraphIntrinsicConfiguration
	RDFSchema []byte
}

// DeployToBytes serializes HypergraphDeployArguments to bytes
func (h *HypergraphDeployArguments) DeployToBytes() ([]byte, error) {
	pb := h.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// DeployFromBytes deserializes HypergraphDeployArguments from bytes
func DeployFromBytes(data []byte) (*HypergraphDeployArguments, error) {
	deploy := &protobufs.HypergraphDeploy{}
	err := deploy.FromCanonicalBytes(data)
	if err != nil {
		return nil, errors.Wrap(err, "deploy from bytes")
	}

	return HypergraphDeployFromProtobuf(deploy)
}

// HypergraphUpdateArguments represents the arguments for updating a hypergraph intrinsic
type HypergraphUpdateArguments struct {
	Domain         [32]byte
	Config         *HypergraphIntrinsicConfiguration
	RDFSchema      []byte
	OwnerSignature *protobufs.BLS48581AggregateSignature
}

// UpdateToBytes serializes HypergraphUpdateArguments to bytes
func (h *HypergraphUpdateArguments) UpdateToBytes() ([]byte, error) {
	pb := h.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// UpdateFromBytes deserializes HypergraphUpdateArguments from bytes
func UpdateFromBytes(data []byte) (*HypergraphUpdateArguments, error) {
	update := &protobufs.HypergraphUpdate{}
	err := update.FromCanonicalBytes(data)
	if err != nil {
		return nil, errors.Wrap(err, "update from bytes")
	}

	return HypergraphUpdateFromProtobuf(update)
}
