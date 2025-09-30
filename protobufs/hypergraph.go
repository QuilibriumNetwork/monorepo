package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func (h *HypergraphConfiguration) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		HypergraphConfigurationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write read_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.ReadPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.ReadPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write write_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.WritePublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.WritePublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write owner_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.OwnerPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.OwnerPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (h *HypergraphConfiguration) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HypergraphConfigurationType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read read_public_key
	var readKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &readKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.ReadPublicKey = make([]byte, readKeyLen)
	if _, err := buf.Read(h.ReadPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read write_public_key
	var writeKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &writeKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.WritePublicKey = make([]byte, writeKeyLen)
	if _, err := buf.Read(h.WritePublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read owner_public_key
	var ownerKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ownerKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if ownerKeyLen > 0 {
		h.OwnerPublicKey = make([]byte, ownerKeyLen)
		if _, err := buf.Read(h.OwnerPublicKey); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (h *HypergraphDeploy) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		HypergraphDeploymentType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	if h.Config == nil {
		return nil, errors.Wrap(errors.New("nil config"), "to canonical bytes")
	}

	// Write config
	configBytes, err := h.Config.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(configBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(configBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rdf_schema
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.RdfSchema); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (h *HypergraphDeploy) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HypergraphDeploymentType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read config
	var configLen uint32
	if err := binary.Read(buf, binary.BigEndian, &configLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	configBytes := make([]byte, configLen)
	if _, err := buf.Read(configBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Config = &HypergraphConfiguration{}
	if err := h.Config.FromCanonicalBytes(configBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rdf_schema
	var schemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &schemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if schemaLen > 0 {
		h.RdfSchema = make([]byte, schemaLen)
		if _, err := buf.Read(h.RdfSchema); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (h *HypergraphUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		HypergraphUpdateType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write config (optional)
	if h.Config != nil {
		configBytes, err := h.Config.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(configBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(configBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write rdf_schema (optional)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.RdfSchema); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if h.PublicKeySignatureBls48581 != nil {
		sigBytes, err := h.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (h *HypergraphUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HypergraphUpdateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read config (optional)
	var configLen uint32
	if err := binary.Read(buf, binary.BigEndian, &configLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if configLen > 0 {
		configBytes := make([]byte, configLen)
		if _, err := buf.Read(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		h.Config = &HypergraphConfiguration{}
		if err := h.Config.FromCanonicalBytes(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read rdf_schema (optional)
	var schemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &schemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if schemaLen > 0 {
		h.RdfSchema = make([]byte, schemaLen)
		if _, err := buf.Read(h.RdfSchema); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		h.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := h.PublicKeySignatureBls48581.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (v *VertexAdd) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		VertexAddType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write data_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.DataAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.DataAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write data
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.Data)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.Data); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (v *VertexAdd) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != VertexAddType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.Domain = make([]byte, domainLen)
	if _, err := buf.Read(v.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read data_address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.DataAddress = make([]byte, addressLen)
	if _, err := buf.Read(v.DataAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read data
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.Data = make([]byte, dataLen)
	if _, err := buf.Read(v.Data); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.Signature = make([]byte, sigLen)
	if _, err := buf.Read(v.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (v *VertexRemove) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		VertexRemoveType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write data_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.DataAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.DataAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(v.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(v.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (v *VertexRemove) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != VertexRemoveType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.Domain = make([]byte, domainLen)
	if _, err := buf.Read(v.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read data_address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.DataAddress = make([]byte, addressLen)
	if _, err := buf.Read(v.DataAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	v.Signature = make([]byte, sigLen)
	if _, err := buf.Read(v.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (h *HyperedgeAdd) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		HyperedgeAddType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write value
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Value)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Value); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (h *HyperedgeAdd) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HyperedgeAddType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Domain = make([]byte, domainLen)
	if _, err := buf.Read(h.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read value
	var valueLen uint32
	if err := binary.Read(buf, binary.BigEndian, &valueLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Value = make([]byte, valueLen)
	if _, err := buf.Read(h.Value); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Signature = make([]byte, sigLen)
	if _, err := buf.Read(h.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (h *HyperedgeRemove) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		HyperedgeRemoveType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Domain)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write value
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Value)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Value); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(h.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(h.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (h *HyperedgeRemove) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HyperedgeRemoveType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain
	var domainLen uint32
	if err := binary.Read(buf, binary.BigEndian, &domainLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Domain = make([]byte, domainLen)
	if _, err := buf.Read(h.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read value
	var valueLen uint32
	if err := binary.Read(buf, binary.BigEndian, &valueLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Value = make([]byte, valueLen)
	if _, err := buf.Read(h.Value); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	h.Signature = make([]byte, sigLen)
	if _, err := buf.Read(h.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

var _ ValidatableMessage = (*HypergraphConfiguration)(nil)

func (h *HypergraphConfiguration) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil hypergraph configuration"), "validate")
	}

	// Validate read public key (Ed448 is 57 bytes)
	if len(h.ReadPublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid read public key length"),
			"validate",
		)
	}

	// Validate write public key (Ed448 is 57 bytes)
	if len(h.WritePublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid write public key length"),
			"validate",
		)
	}

	// Validate owner public key (0 or 585 bytes for BLS48-581)
	if len(h.OwnerPublicKey) != 0 && len(h.OwnerPublicKey) != 585 {
		return errors.Wrap(
			errors.New("invalid owner public key length (expected 0 or 585 bytes)"),
			"validate",
		)
	}

	return nil
}

var _ ValidatableMessage = (*HypergraphDeploy)(nil)

func (h *HypergraphDeploy) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil hypergraph deploy"), "validate")
	}

	if h.Config == nil {
		return errors.Wrap(errors.New("nil configuration"), "validate")
	}

	return h.Config.Validate()
}

var _ ValidatableMessage = (*HypergraphUpdate)(nil)

func (h *HypergraphUpdate) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil hypergraph update"), "validate")
	}

	if h.Config == nil && len(h.RdfSchema) == 0 {
		return errors.Wrap(
			errors.New("config and schema can be nil, but not both"),
			"validate",
		)
	}

	// Config is optional for updates
	if h.Config != nil {
		if err := h.Config.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	if h.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("public key signature is nil"), "validate")
	}

	if err := h.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*VertexAdd)(nil)

func (v *VertexAdd) Validate() error {
	if v == nil {
		return errors.Wrap(errors.New("nil vertex add"), "validate")
	}

	// Validate domain (32 bytes)
	if len(v.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Validate data address (32 bytes)
	if len(v.DataAddress) != 32 {
		return errors.Wrap(errors.New("invalid data address length"), "validate")
	}

	// Data can be variable length but should not be empty
	if len(v.Data) == 0 {
		return errors.Wrap(errors.New("empty data"), "validate")
	}

	// Validate signature (Ed448 signature)
	if len(v.Signature) == 0 {
		return errors.Wrap(errors.New("empty signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*VertexRemove)(nil)

func (v *VertexRemove) Validate() error {
	if v == nil {
		return errors.Wrap(errors.New("nil vertex remove"), "validate")
	}

	// Validate domain (32 bytes)
	if len(v.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Validate data address (32 bytes)
	if len(v.DataAddress) != 32 {
		return errors.Wrap(errors.New("invalid data address length"), "validate")
	}

	// Validate signature (Ed448 signature)
	if len(v.Signature) == 0 {
		return errors.Wrap(errors.New("empty signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*HyperedgeAdd)(nil)

func (h *HyperedgeAdd) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil hyperedge add"), "validate")
	}

	// Validate domain (32 bytes)
	if len(h.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Value can be variable length but should not be empty
	if len(h.Value) == 0 {
		return errors.Wrap(errors.New("empty value"), "validate")
	}

	// Validate signature (Ed448 signature)
	if len(h.Signature) == 0 {
		return errors.Wrap(errors.New("empty signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*HyperedgeRemove)(nil)

func (h *HyperedgeRemove) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil hyperedge remove"), "validate")
	}

	// Validate domain (32 bytes)
	if len(h.Domain) != 32 {
		return errors.Wrap(errors.New("invalid domain length"), "validate")
	}

	// Value can be variable length but should not be empty
	if len(h.Value) == 0 {
		return errors.Wrap(errors.New("empty value"), "validate")
	}

	// Validate signature (Ed448 signature)
	if len(h.Signature) == 0 {
		return errors.Wrap(errors.New("empty signature"), "validate")
	}

	return nil
}
