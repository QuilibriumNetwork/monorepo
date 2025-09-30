package hypergraph

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// FromProtobuf converts a protobuf HypergraphConfiguration to intrinsics
// HypergraphIntrinsicConfiguration
func HypergraphConfigurationFromProtobuf(
	pb *protobufs.HypergraphConfiguration,
) (*HypergraphIntrinsicConfiguration, error) {
	if pb == nil {
		return nil, nil
	}

	return &HypergraphIntrinsicConfiguration{
		ReadPublicKey:  pb.ReadPublicKey,
		WritePublicKey: pb.WritePublicKey,
		OwnerPublicKey: pb.OwnerPublicKey,
	}, nil
}

// ToProtobuf converts an intrinsics HypergraphIntrinsicConfiguration to
// protobuf HypergraphConfiguration
func (
	h *HypergraphIntrinsicConfiguration,
) ToProtobuf() *protobufs.HypergraphConfiguration {
	if h == nil {
		return nil
	}

	return &protobufs.HypergraphConfiguration{
		ReadPublicKey:  h.ReadPublicKey,
		WritePublicKey: h.WritePublicKey,
		OwnerPublicKey: h.OwnerPublicKey,
	}
}

// FromProtobuf converts a protobuf VertexAdd to intrinsics VertexAdd
func VertexAddFromProtobuf(
	pb *protobufs.VertexAdd,
	inclusionProver qcrypto.InclusionProver,
	keyManager keys.KeyManager,
	signer qcrypto.Signer,
	verenc qcrypto.VerifiableEncryptor,
	config *HypergraphIntrinsicConfiguration,
) (*VertexAdd, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert data address from slice to array
	var dataAddress [32]byte
	copy(dataAddress[:], pb.DataAddress)

	// Deserialize proof from Data field
	data, err := extractVertexAddProofFromBytes(pb.Data, verenc)
	if err != nil {
		return nil, err
	}

	return &VertexAdd{
		Domain:          domain,
		DataAddress:     dataAddress,
		Data:            data,
		Signature:       pb.Signature,
		inclusionProver: inclusionProver,
		config:          config,
		verenc:          verenc,
		keyManager:      keyManager,
	}, nil
}

func extractVertexAddProofFromBytes(
	pbData []byte,
	verenc qcrypto.VerifiableEncryptor,
) ([]qcrypto.VerEncProof, error) {
	data := []qcrypto.VerEncProof{}
	if len(pbData) < 4 {
		return nil, errors.Wrap(
			errors.New("invalid data size"),
			"extract vertex add proof from bytes",
		)
	}

	buf := bytes.NewBuffer(pbData)
	var count uint16
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil ||
		count == 0 {
		return nil, errors.Wrap(
			fmt.Errorf("invalid data size: %d", count),
			"extract vertex add proof from bytes",
		)
	}

	for range count {
		var size uint16
		if err := binary.Read(buf, binary.BigEndian, &size); err != nil ||
			size == 0 {
			return nil, errors.Wrap(
				errors.New("invalid data size"),
				"extract vertex add proof from bytes",
			)
		}

		proofData := make([]byte, size)
		if _, err := buf.Read(proofData); err != nil {
			return nil, errors.Wrap(
				errors.New("invalid data size"),
				"extract vertex add proof from bytes",
			)
		}

		proof := verenc.ProofFromBytes(proofData)
		if proof == nil {
			return nil, errors.Wrap(
				errors.New("invalid proof"),
				"extract vertex add proof from bytes",
			)
		}

		data = append(data, proof)
	}
	return data, nil
}

// ToProtobuf converts an intrinsics VertexAdd to protobuf VertexAdd
func (v *VertexAdd) ToProtobuf() (*protobufs.VertexAdd, error) {
	if v == nil {
		return nil, nil
	}

	// Serialize proofs to bytes
	buf := new(bytes.Buffer)

	if len(v.Data) == 0 {
		return nil, errors.Wrap(errors.New("no proofs"), "to protobuf")
	}

	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint16(len(v.Data)),
	); err != nil {
		return nil, errors.Wrap(err, "to protobuf")
	}

	for _, data := range v.Data {
		proofBytes := data.ToBytes()
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint16(len(proofBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to protobuf")
		}

		if _, err := buf.Write(proofBytes); err != nil {
			return nil, errors.Wrap(err, "to protobuf")
		}
	}

	return &protobufs.VertexAdd{
		Domain:      v.Domain[:],
		DataAddress: v.DataAddress[:],
		Data:        buf.Bytes(),
		Signature:   v.Signature,
	}, nil
}

// FromProtobuf converts a protobuf VertexRemove to intrinsics VertexRemove
func VertexRemoveFromProtobuf(
	pb *protobufs.VertexRemove,
	keyManager keys.KeyManager,
	signer qcrypto.Signer,
	config *HypergraphIntrinsicConfiguration,
) (*VertexRemove, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert data address from slice to array
	var dataAddress [32]byte
	copy(dataAddress[:], pb.DataAddress)

	return &VertexRemove{
		Domain:      domain,
		DataAddress: dataAddress,
		Signature:   pb.Signature,
		keyManager:  keyManager,
		signer:      signer,
		config:      config,
	}, nil
}

// ToProtobuf converts an intrinsics VertexRemove to protobuf VertexRemove
func (v *VertexRemove) ToProtobuf() *protobufs.VertexRemove {
	if v == nil {
		return nil
	}

	return &protobufs.VertexRemove{
		Domain:      v.Domain[:],
		DataAddress: v.DataAddress[:],
		Signature:   v.Signature,
	}
}

// FromProtobuf converts a protobuf HyperedgeAdd to intrinsics HyperedgeAdd
func HyperedgeAddFromProtobuf(
	pb *protobufs.HyperedgeAdd,
	inclusionProver qcrypto.InclusionProver,
	keyManager keys.KeyManager,
	signer qcrypto.Signer,
	config *HypergraphIntrinsicConfiguration,
) (*HyperedgeAdd, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Deserialize Hyperedge from Value field
	var value hypergraph.Hyperedge
	if len(pb.Value) > 0 {
		atom := hgcrdt.AtomFromBytes(pb.Value)
		if atom == nil {
			return nil, errors.Wrap(
				errors.New("invalid hyperedge data"),
				"deserializing hyperedge",
			)
		}
		var ok bool
		value, ok = atom.(hypergraph.Hyperedge)
		if !ok {
			return nil, errors.Wrap(
				errors.New("data not hyperedge"),
				"deserializing hyperedge",
			)
		}
	}

	return &HyperedgeAdd{
		Domain:          domain,
		Value:           value,
		Signature:       pb.Signature,
		inclusionProver: inclusionProver,
		keyManager:      keyManager,
		signer:          signer,
		config:          config,
	}, nil
}

// ToProtobuf converts an intrinsics HyperedgeAdd to protobuf HyperedgeAdd
func (h *HyperedgeAdd) ToProtobuf() (*protobufs.HyperedgeAdd, error) {
	if h == nil {
		return nil, nil
	}

	// Serialize Hyperedge to bytes
	var valueBytes []byte
	if h.Value != nil {
		valueBytes = h.Value.ToBytes()
	}

	return &protobufs.HyperedgeAdd{
		Domain:    h.Domain[:],
		Value:     valueBytes,
		Signature: h.Signature,
	}, nil
}

// FromProtobuf converts a protobuf HyperedgeRemove to intrinsics
// HyperedgeRemove
func HyperedgeRemoveFromProtobuf(
	pb *protobufs.HyperedgeRemove,
	keyManager keys.KeyManager,
	signer qcrypto.Signer,
	config *HypergraphIntrinsicConfiguration,
) (*HyperedgeRemove, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Deserialize Hyperedge from Value field
	var value hypergraph.Hyperedge
	if len(pb.Value) > 0 {
		atom := hgcrdt.AtomFromBytes(pb.Value)
		if atom == nil {
			return nil, errors.Wrap(
				errors.New("invalid hyperedge data"),
				"deserializing hyperedge",
			)
		}
		var ok bool
		value, ok = atom.(hypergraph.Hyperedge)
		if !ok {
			return nil, errors.Wrap(
				errors.New("data not hyperedge"),
				"deserializing hyperedge",
			)
		}
	}

	return &HyperedgeRemove{
		Domain:     domain,
		Value:      value,
		Signature:  pb.Signature,
		keyManager: keyManager,
		signer:     signer,
		config:     config,
	}, nil
}

// ToProtobuf converts an intrinsics HyperedgeRemove to protobuf HyperedgeRemove
func (h *HyperedgeRemove) ToProtobuf() (*protobufs.HyperedgeRemove, error) {
	if h == nil {
		return nil, nil
	}

	// Serialize Hyperedge to bytes
	var valueBytes []byte
	if h.Value != nil {
		valueBytes = h.Value.ToBytes()
	}

	return &protobufs.HyperedgeRemove{
		Domain:    h.Domain[:],
		Value:     valueBytes,
		Signature: h.Signature,
	}, nil
}

// FromProtobuf converts a protobuf HypergraphDeploy to intrinsics
// HypergraphDeployArguments
func HypergraphDeployFromProtobuf(
	pb *protobufs.HypergraphDeploy,
) (*HypergraphDeployArguments, error) {
	if pb == nil {
		return nil, nil
	}

	if len(pb.RdfSchema) == 0 {
		return nil, errors.Wrap(
			errors.New("missing rdf schema"),
			"hypergraph deploy from protobuf",
		)
	}

	config, err := HypergraphConfigurationFromProtobuf(pb.Config)
	if err != nil {
		return nil, errors.Wrap(err, "hypergraph deploy from protobuf")
	}

	return &HypergraphDeployArguments{
		Config:    config,
		RDFSchema: pb.RdfSchema,
	}, nil
}

// ToProtobuf converts an intrinsics HypergraphDeployArguments to protobuf
// HypergraphDeploy
func (h *HypergraphDeployArguments) ToProtobuf() *protobufs.HypergraphDeploy {
	if h == nil {
		return nil
	}

	return &protobufs.HypergraphDeploy{
		Config:    h.Config.ToProtobuf(),
		RdfSchema: h.RDFSchema,
	}
}

// HypergraphUpdateFromProtobuf converts from protobuf HypergraphUpdate
// to intrinsics HypergraphUpdateArguments
func HypergraphUpdateFromProtobuf(
	pb *protobufs.HypergraphUpdate,
) (*HypergraphUpdateArguments, error) {
	if pb == nil {
		return nil, nil
	}

	result := &HypergraphUpdateArguments{
		RDFSchema:      pb.RdfSchema,
		OwnerSignature: pb.PublicKeySignatureBls48581,
	}

	// Convert config if present
	if pb.Config != nil {
		config, err := HypergraphConfigurationFromProtobuf(pb.Config)
		if err != nil {
			return nil, errors.Wrap(err, "hypergraph update from protobuf")
		}
		result.Config = config
	}

	return result, nil
}

// ToProtobuf converts an intrinsics HypergraphUpdateArguments to protobuf
// HypergraphUpdate
func (h *HypergraphUpdateArguments) ToProtobuf() *protobufs.HypergraphUpdate {
	if h == nil {
		return nil
	}

	result := &protobufs.HypergraphUpdate{
		RdfSchema:                  h.RDFSchema,
		PublicKeySignatureBls48581: h.OwnerSignature,
	}

	// Include config if present
	if h.Config != nil {
		result.Config = h.Config.ToProtobuf()
	}

	return result
}
