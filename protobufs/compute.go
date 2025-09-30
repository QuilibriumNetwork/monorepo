package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func (a *Application) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ApplicationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(a.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write execution_context
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(a.ExecutionContext),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (a *Application) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ApplicationType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	a.Address = make([]byte, addressLen)
	if _, err := buf.Read(a.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read execution_context
	var execContext uint32
	if err := binary.Read(buf, binary.BigEndian, &execContext); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	a.ExecutionContext = ExecutionContext(execContext)

	return nil
}

// Validate checks if Application is valid
func (a *Application) Validate() error {
	if a == nil {
		return errors.New("nil application")
	}

	// Validate address if present (should be 32 bytes)
	if len(a.Address) > 0 && len(a.Address) != 32 {
		return errors.New("invalid application address length")
	}

	// Validate execution context is a valid enum value
	switch a.ExecutionContext {
	case ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		ExecutionContext_EXECUTION_CONTEXT_HYPERGRAPH,
		ExecutionContext_EXECUTION_CONTEXT_EXTRINSIC:
		// Valid execution context
	default:
		return errors.New("invalid execution context")
	}

	return nil
}

func (i *IntrinsicExecutionInput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		IntrinsicExecutionInputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(i.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(i.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write input
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(i.Input)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(i.Input); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (i *IntrinsicExecutionInput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != IntrinsicExecutionInputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	i.Address = make([]byte, addressLen)
	if _, err := buf.Read(i.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read input
	var inputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &inputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	i.Input = make([]byte, inputLen)
	if _, err := buf.Read(i.Input); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (i *IntrinsicExecutionOutput) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		IntrinsicExecutionOutputType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(i.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(i.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(i.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(i.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(i.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(i.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (i *IntrinsicExecutionOutput) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != IntrinsicExecutionOutputType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	i.Address = make([]byte, addressLen)
	if _, err := buf.Read(i.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	i.Output = make([]byte, outputLen)
	if _, err := buf.Read(i.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	i.Proof = make([]byte, proofLen)
	if _, err := buf.Read(i.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (c *ComputeConfiguration) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ComputeConfigurationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write read_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.ReadPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.ReadPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write write_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.WritePublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.WritePublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write owner_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.OwnerPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.OwnerPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (c *ComputeConfiguration) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ComputeConfigurationType {
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
	c.ReadPublicKey = make([]byte, readKeyLen)
	if _, err := buf.Read(c.ReadPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read write_public_key
	var writeKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &writeKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.WritePublicKey = make([]byte, writeKeyLen)
	if _, err := buf.Read(c.WritePublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read owner_public_key
	var ownerKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ownerKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.OwnerPublicKey = make([]byte, ownerKeyLen)
	if _, err := buf.Read(c.OwnerPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (c *ComputeConfiguration) Validate() error {
	if c == nil {
		return errors.Wrap(
			errors.New("nil compute intrinsic configuration"),
			"validate",
		)
	}
	if len(c.ReadPublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid read public key length (expected 57 bytes)"),
			"validate",
		)
	}
	if len(c.WritePublicKey) != 0 && len(c.WritePublicKey) != 57 {
		return errors.Wrap(
			errors.New("invalid write public key length (expected 57 bytes)"),
			"validate",
		)
	}
	if len(c.OwnerPublicKey) != 0 && len(c.OwnerPublicKey) != 585 {
		return errors.Wrap(
			errors.New("invalid owner public key length (expected 0 or 585 bytes for BLS48-581)"),
			"validate",
		)
	}
	return nil
}

func (c *ComputeDeploy) Validate() error {
	if c == nil {
		return errors.Wrap(
			errors.New("nil compute deploy"),
			"validate",
		)
	}

	if c.Config == nil {
		return errors.Wrap(
			errors.New("nil configuration"),
			"validate",
		)
	}

	if err := c.Config.Validate(); err != nil {
		return errors.Wrap(err, "validate config")
	}

	// RDF schema is optional

	return nil
}

func (c *ComputeDeploy) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ComputeDeploymentType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write config
	if c.Config != nil {
		configBytes, err := c.Config.ToCanonicalBytes()
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

	// Write rdf_schema
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.RdfSchema); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (c *ComputeDeploy) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ComputeDeploymentType {
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
	if configLen > 0 {
		configBytes := make([]byte, configLen)
		if _, err := buf.Read(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.Config = &ComputeConfiguration{}
		if err := c.Config.FromCanonicalBytes(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read rdf_schema
	var schemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &schemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if schemaLen > 0 {
		c.RdfSchema = make([]byte, schemaLen)
		if _, err := buf.Read(c.RdfSchema); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (c *ComputeUpdate) Validate() error {
	if c == nil {
		return errors.Wrap(
			errors.New("nil compute update"),
			"validate",
		)
	}

	if c.Config == nil && len(c.RdfSchema) == 0 {
		return errors.Wrap(
			errors.New("configuration or schema can be null, but not both"),
			"validate",
		)
	}

	if c.Config != nil {
		if err := c.Config.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	if c.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(
			errors.New("public key signature is nil"),
			"validate",
		)
	}

	if err := c.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

func (c *ComputeUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ComputeUpdateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write config
	if c.Config != nil {
		configBytes, err := c.Config.ToCanonicalBytes()
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

	// Write rdf_schema
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.RdfSchema)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.RdfSchema); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if c.PublicKeySignatureBls48581 != nil {
		sigBytes, err := c.PublicKeySignatureBls48581.ToCanonicalBytes()
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

func (c *ComputeUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ComputeUpdateType {
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
	if configLen > 0 {
		configBytes := make([]byte, configLen)
		if _, err := buf.Read(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.Config = &ComputeConfiguration{}
		if err := c.Config.FromCanonicalBytes(configBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read rdf_schema
	var schemaLen uint32
	if err := binary.Read(buf, binary.BigEndian, &schemaLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if schemaLen > 0 {
		c.RdfSchema = make([]byte, schemaLen)
		if _, err := buf.Read(c.RdfSchema); err != nil {
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
		c.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := c.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (d *CodeDeployment) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		CodeDeploymentType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write circuit
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(d.Circuit)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(d.Circuit); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write input_types count and values
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(d.InputTypes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, inputType := range d.InputTypes {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(inputType)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.WriteString(inputType); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write output_types count and values
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(d.OutputTypes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, outputType := range d.OutputTypes {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(outputType)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.WriteString(outputType); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write domain (32 bytes)
	if len(d.Domain) != 32 {
		return nil, errors.Wrap(
			errors.New("domain must be 32 bytes"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(d.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (d *CodeDeployment) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != CodeDeploymentType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read circuit
	var circuitLen uint32
	if err := binary.Read(buf, binary.BigEndian, &circuitLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	d.Circuit = make([]byte, circuitLen)
	if _, err := buf.Read(d.Circuit); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read input_types
	var inputTypesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &inputTypesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	d.InputTypes = make([]string, inputTypesCount)
	for i := uint32(0); i < inputTypesCount; i++ {
		var typeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &typeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		typeBytes := make([]byte, typeLen)
		if _, err := buf.Read(typeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		d.InputTypes[i] = string(typeBytes)
	}

	// Read output_types
	var outputTypesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &outputTypesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	d.OutputTypes = make([]string, outputTypesCount)
	for i := uint32(0); i < outputTypesCount; i++ {
		var typeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &typeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		typeBytes := make([]byte, typeLen)
		if _, err := buf.Read(typeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		d.OutputTypes[i] = string(typeBytes)
	}

	// Read domain (32 bytes)
	d.Domain = make([]byte, 32)
	if _, err := buf.Read(d.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (d *CodeDeployment) Validate() error {
	if d == nil {
		return errors.Wrap(
			errors.New("nil code deployment"),
			"validate",
		)
	}
	if len(d.Circuit) == 0 {
		return errors.Wrap(
			errors.New("circuit required"),
			"validate",
		)
	}
	if len(d.InputTypes) != 2 {
		return errors.Wrap(
			errors.New("exactly 2 input types required (garbler and evaluator)"),
			"validate",
		)
	}
	if len(d.Domain) != 32 {
		return errors.Wrap(
			errors.New("invalid domain length (expected 32 bytes)"),
			"validate",
		)
	}
	return nil
}

func (e *ExecuteOperation) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ExecuteOperationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write application
	appBytes, err := e.Application.ToCanonicalBytes()
	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(appBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(appBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write identifier
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Identifier)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.Identifier); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write dependencies
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Dependencies)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, dep := range e.Dependencies {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(dep)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(dep); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (e *ExecuteOperation) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecuteOperationType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read application
	var appLen uint32
	if err := binary.Read(buf, binary.BigEndian, &appLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	appBytes := make([]byte, appLen)
	if _, err := buf.Read(appBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Application = &Application{}
	if err := e.Application.FromCanonicalBytes(appBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read identifier
	var idLen uint32
	if err := binary.Read(buf, binary.BigEndian, &idLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Identifier = make([]byte, idLen)
	if _, err := buf.Read(e.Identifier); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read dependencies
	var depCount uint32
	if err := binary.Read(buf, binary.BigEndian, &depCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Dependencies = make([][]byte, depCount)
	for i := uint32(0); i < depCount; i++ {
		var depLen uint32
		if err := binary.Read(buf, binary.BigEndian, &depLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.Dependencies[i] = make([]byte, depLen)
		if _, err := buf.Read(e.Dependencies[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (c *CodeExecute) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, CodeExecuteType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof_of_payment (array of 2 byte arrays)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.ProofOfPayment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, proof := range c.ProofOfPayment {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(proof)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(proof); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write domain (32 bytes)
	if len(c.Domain) != 32 {
		return nil, errors.Wrap(
			errors.New("domain must be 32 bytes"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(c.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rendezvous (32 bytes)
	if len(c.Rendezvous) != 32 {
		return nil, errors.Wrap(
			errors.New("rendezvous must be 32 bytes"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(c.Rendezvous); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write execute_operations
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.ExecuteOperations)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, op := range c.ExecuteOperations {
		opBytes, err := op.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(opBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(opBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (c *CodeExecute) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != CodeExecuteType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read proof_of_payment
	var proofCount uint32
	if err := binary.Read(buf, binary.BigEndian, &proofCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.ProofOfPayment = make([][]byte, proofCount)
	for i := uint32(0); i < proofCount; i++ {
		var proofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.ProofOfPayment[i] = make([]byte, proofLen)
		if _, err := buf.Read(c.ProofOfPayment[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read domain (32 bytes)
	c.Domain = make([]byte, 32)
	if _, err := buf.Read(c.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read rendezvous (32 bytes)
	c.Rendezvous = make([]byte, 32)
	if _, err := buf.Read(c.Rendezvous); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read execute_operations
	var opCount uint32
	if err := binary.Read(buf, binary.BigEndian, &opCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.ExecuteOperations = make([]*ExecuteOperation, opCount)
	for i := uint32(0); i < opCount; i++ {
		var opLen uint32
		if err := binary.Read(buf, binary.BigEndian, &opLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		opBytes := make([]byte, opLen)
		if _, err := buf.Read(opBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.ExecuteOperations[i] = &ExecuteOperation{}
		if err := c.ExecuteOperations[i].FromCanonicalBytes(opBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (c *CodeExecute) Validate() error {
	if c == nil {
		return errors.Wrap(
			errors.New("nil code execute"),
			"validate",
		)
	}
	if len(c.ProofOfPayment) != 2 {
		return errors.Wrap(
			errors.New("exactly 2 proof of payment entries required"),
			"validate",
		)
	}
	if len(c.Domain) != 32 {
		return errors.Wrap(
			errors.New("invalid domain length (expected 32 bytes)"),
			"validate",
		)
	}
	if len(c.Rendezvous) != 32 {
		return errors.Wrap(
			errors.New("invalid rendezvous length (expected 32 bytes)"),
			"validate",
		)
	}
	if len(c.ExecuteOperations) == 0 {
		return errors.Wrap(
			errors.New("at least one execute operation required"),
			"validate",
		)
	}
	return nil
}

func (s *StateTransition) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		StateTransitionType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write domain (32 bytes)
	if len(s.Domain) != 32 {
		return nil, errors.Wrap(
			errors.New("domain must be 32 bytes"),
			"to canonical bytes",
		)
	}
	if _, err := buf.Write(s.Domain); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write old_value
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.OldValue)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.OldValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write new_value
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.NewValue)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.NewValue); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (s *StateTransition) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != StateTransitionType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read domain (32 bytes)
	s.Domain = make([]byte, 32)
	if _, err := buf.Read(s.Domain); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.Address = make([]byte, addressLen)
	if _, err := buf.Read(s.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read old_value
	var oldValueLen uint32
	if err := binary.Read(buf, binary.BigEndian, &oldValueLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.OldValue = make([]byte, oldValueLen)
	if _, err := buf.Read(s.OldValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read new_value
	var newValueLen uint32
	if err := binary.Read(buf, binary.BigEndian, &newValueLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.NewValue = make([]byte, newValueLen)
	if _, err := buf.Read(s.NewValue); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.Proof = make([]byte, proofLen)
	if _, err := buf.Read(s.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (e *ExecutionResult) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ExecutionResultType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write operation_id
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.OperationId)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.OperationId); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write success
	successByte := uint8(0)
	if e.Success {
		successByte = 1
	}
	if err := binary.Write(buf, binary.BigEndian, successByte); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write error
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Error)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.Error); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (e *ExecutionResult) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecutionResultType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read operation_id
	var opIdLen uint32
	if err := binary.Read(buf, binary.BigEndian, &opIdLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.OperationId = make([]byte, opIdLen)
	if _, err := buf.Read(e.OperationId); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read success
	var successByte uint8
	if err := binary.Read(buf, binary.BigEndian, &successByte); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Success = successByte != 0

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Output = make([]byte, outputLen)
	if _, err := buf.Read(e.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read error
	var errorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &errorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Error = make([]byte, errorLen)
	if _, err := buf.Read(e.Error); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (c *CodeFinalize) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, CodeFinalizeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write rendezvous (32 bytes)
	if len(c.Rendezvous) != 32 {
		return nil, errors.New("rendezvous must be 32 bytes")
	}
	if _, err := buf.Write(c.Rendezvous); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write results
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.Results)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, result := range c.Results {
		resultBytes, err := result.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(resultBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(resultBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write state_changes
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.StateChanges)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, change := range c.StateChanges {
		changeBytes, err := change.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(changeBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(changeBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write proof_of_execution
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.ProofOfExecution)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.ProofOfExecution); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write message_output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.MessageOutput)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.MessageOutput); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (c *CodeFinalize) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != CodeFinalizeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read rendezvous (32 bytes)
	c.Rendezvous = make([]byte, 32)
	if _, err := buf.Read(c.Rendezvous); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read results
	var resultsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &resultsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.Results = make([]*ExecutionResult, resultsCount)
	for i := uint32(0); i < resultsCount; i++ {
		var resultLen uint32
		if err := binary.Read(buf, binary.BigEndian, &resultLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		resultBytes := make([]byte, resultLen)
		if _, err := buf.Read(resultBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.Results[i] = &ExecutionResult{}
		if err := c.Results[i].FromCanonicalBytes(resultBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read state_changes
	var changesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &changesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.StateChanges = make([]*StateTransition, changesCount)
	for i := uint32(0); i < changesCount; i++ {
		var changeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &changeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		changeBytes := make([]byte, changeLen)
		if _, err := buf.Read(changeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		c.StateChanges[i] = &StateTransition{}
		if err := c.StateChanges[i].FromCanonicalBytes(changeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read proof_of_execution
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.ProofOfExecution = make([]byte, proofLen)
	if _, err := buf.Read(c.ProofOfExecution); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read message_output
	var msgLen uint32
	if err := binary.Read(buf, binary.BigEndian, &msgLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.MessageOutput = make([]byte, msgLen)
	if _, err := buf.Read(c.MessageOutput); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (c *CodeFinalize) Validate() error {
	if c == nil {
		return errors.New("nil code finalize")
	}
	if len(c.Rendezvous) != 32 {
		return errors.New("invalid rendezvous length (expected 32 bytes)")
	}
	return nil
}

func (e *ExecutionDependency) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ExecutionDependencyType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write identifier
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Identifier)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(e.Identifier); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write read_set count and values
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.ReadSet)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, read := range e.ReadSet {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(read)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(read); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write write_set count and values
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.WriteSet)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, write := range e.WriteSet {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(write)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(write); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write stage
	if err := binary.Write(buf, binary.BigEndian, e.Stage); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (e *ExecutionDependency) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecutionDependencyType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read identifier
	var idLen uint32
	if err := binary.Read(buf, binary.BigEndian, &idLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Identifier = make([]byte, idLen)
	if _, err := buf.Read(e.Identifier); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read read_set
	var readCount uint32
	if err := binary.Read(buf, binary.BigEndian, &readCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.ReadSet = make([][]byte, readCount)
	for i := uint32(0); i < readCount; i++ {
		var readLen uint32
		if err := binary.Read(buf, binary.BigEndian, &readLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.ReadSet[i] = make([]byte, readLen)
		if _, err := buf.Read(e.ReadSet[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read write_set
	var writeCount uint32
	if err := binary.Read(buf, binary.BigEndian, &writeCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.WriteSet = make([][]byte, writeCount)
	for i := uint32(0); i < writeCount; i++ {
		var writeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &writeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.WriteSet[i] = make([]byte, writeLen)
		if _, err := buf.Read(e.WriteSet[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read stage
	if err := binary.Read(buf, binary.BigEndian, &e.Stage); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (e *ExecutionNode) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ExecutionNodeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write operation
	if e.Operation != nil {
		opBytes, err := e.Operation.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(opBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(opBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write read_set
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.ReadSet)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, read := range e.ReadSet {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(read)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(read); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write write_set
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.WriteSet)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, write := range e.WriteSet {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(write)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(write); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write stage
	if err := binary.Write(buf, binary.BigEndian, e.Stage); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write visited
	visitedByte := uint8(0)
	if e.Visited {
		visitedByte = 1
	}
	if err := binary.Write(buf, binary.BigEndian, visitedByte); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write in_progress
	inProgressByte := uint8(0)
	if e.InProgress {
		inProgressByte = 1
	}
	if err := binary.Write(buf, binary.BigEndian, inProgressByte); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (e *ExecutionNode) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecutionNodeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read operation
	var opLen uint32
	if err := binary.Read(buf, binary.BigEndian, &opLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if opLen > 0 {
		opBytes := make([]byte, opLen)
		if _, err := buf.Read(opBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.Operation = &ExecuteOperation{}
		if err := e.Operation.FromCanonicalBytes(opBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read read_set
	var readCount uint32
	if err := binary.Read(buf, binary.BigEndian, &readCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.ReadSet = make([][]byte, readCount)
	for i := uint32(0); i < readCount; i++ {
		var readLen uint32
		if err := binary.Read(buf, binary.BigEndian, &readLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.ReadSet[i] = make([]byte, readLen)
		if _, err := buf.Read(e.ReadSet[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read write_set
	var writeCount uint32
	if err := binary.Read(buf, binary.BigEndian, &writeCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.WriteSet = make([][]byte, writeCount)
	for i := uint32(0); i < writeCount; i++ {
		var writeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &writeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.WriteSet[i] = make([]byte, writeLen)
		if _, err := buf.Read(e.WriteSet[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read stage
	if err := binary.Read(buf, binary.BigEndian, &e.Stage); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read visited
	var visitedByte uint8
	if err := binary.Read(buf, binary.BigEndian, &visitedByte); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Visited = visitedByte != 0

	// Read in_progress
	var inProgressByte uint8
	if err := binary.Read(buf, binary.BigEndian, &inProgressByte); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.InProgress = inProgressByte != 0

	return nil
}

func (e *ExecutionStage) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ExecutionStageType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write operation_ids count and values
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.OperationIds)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, opId := range e.OperationIds {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(opId)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.WriteString(opId); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (e *ExecutionStage) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecutionStageType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read operation_ids
	var idsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &idsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.OperationIds = make([]string, idsCount)
	for i := uint32(0); i < idsCount; i++ {
		var idLen uint32
		if err := binary.Read(buf, binary.BigEndian, &idLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		idBytes := make([]byte, idLen)
		if _, err := buf.Read(idBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.OperationIds[i] = string(idBytes)
	}

	return nil
}

func (e *ExecutionDAG) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ExecutionDAGType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write operations map count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Operations)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each operation in the map
	for key, node := range e.Operations {
		// Write key
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(key)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.WriteString(key); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}

		// Write node
		nodeBytes, err := node.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(nodeBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(nodeBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write stages
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(e.Stages)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, stage := range e.Stages {
		stageBytes, err := stage.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(stageBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(stageBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (e *ExecutionDAG) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ExecutionDAGType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read operations map
	var mapCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mapCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Operations = make(map[string]*ExecutionNode)
	for i := uint32(0); i < mapCount; i++ {
		// Read key
		var keyLen uint32
		if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		keyBytes := make([]byte, keyLen)
		if _, err := buf.Read(keyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		key := string(keyBytes)

		// Read node
		var nodeLen uint32
		if err := binary.Read(buf, binary.BigEndian, &nodeLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		nodeBytes := make([]byte, nodeLen)
		if _, err := buf.Read(nodeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		node := &ExecutionNode{}
		if err := node.FromCanonicalBytes(nodeBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.Operations[key] = node
	}

	// Read stages
	var stagesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &stagesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	e.Stages = make([]*ExecutionStage, stagesCount)
	for i := uint32(0); i < stagesCount; i++ {
		var stageLen uint32
		if err := binary.Read(buf, binary.BigEndian, &stageLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		stageBytes := make([]byte, stageLen)
		if _, err := buf.Read(stageBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		e.Stages[i] = &ExecutionStage{}
		if err := e.Stages[i].FromCanonicalBytes(stageBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// Validate checks if ExecuteOperation is valid
func (e *ExecuteOperation) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execute operation"),
			"validate",
		)
	}
	if e.Application == nil {
		return errors.Wrap(
			errors.New("nil application"),
			"validate",
		)
	}
	if err := e.Application.Validate(); err != nil {
		return errors.Wrap(
			errors.Wrap(err, "validate application"),
			"validate",
		)
	}
	if len(e.Identifier) == 0 {
		return errors.Wrap(
			errors.New("identifier required"),
			"validate",
		)
	}
	return nil
}

// Validate checks if StateTransition is valid
func (s *StateTransition) Validate() error {
	if s == nil {
		return errors.Wrap(
			errors.New("nil state transition"),
			"validate",
		)
	}
	if len(s.Domain) != 32 {
		return errors.Wrap(
			errors.New("invalid domain length (expected 32 bytes)"),
			"validate",
		)
	}
	if len(s.Address) == 0 {
		return errors.Wrap(
			errors.New("address required"),
			"validate",
		)
	}
	// OldValue and NewValue can be empty (deleting or creating)
	// Proof is optional
	return nil
}

// Validate checks if ExecutionResult is valid
func (e *ExecutionResult) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execution result"),
			"validate",
		)
	}
	if len(e.OperationId) == 0 {
		return errors.Wrap(
			errors.New("operation id required"),
			"validate",
		)
	}
	// Success is a boolean, always valid
	// Output and Error can be empty
	return nil
}

// Validate checks if ExecutionDependency is valid
func (e *ExecutionDependency) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execution dependency"),
			"validate",
		)
	}
	if len(e.Identifier) == 0 {
		return errors.Wrap(
			errors.New("identifier required"),
			"validate",
		)
	}
	// ReadSet and WriteSet can be empty
	// Stage is a uint32, always valid
	return nil
}

// Validate checks if ExecutionNode is valid
func (e *ExecutionNode) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execution node"),
			"validate",
		)
	}
	if e.Operation == nil {
		return errors.Wrap(
			errors.New("nil operation"),
			"validate",
		)
	}
	if err := e.Operation.Validate(); err != nil {
		return errors.Wrap(
			errors.Wrap(err, "validate operation"),
			"validate",
		)
	}
	// ReadSet and WriteSet can be empty
	// Stage, Visited, InProgress are always valid
	return nil
}

// Validate checks if ExecutionStage is valid
func (e *ExecutionStage) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execution stage"),
			"validate",
		)
	}
	// OperationIds can be empty
	return nil
}

// Validate checks if ExecutionDAG is valid
func (e *ExecutionDAG) Validate() error {
	if e == nil {
		return errors.Wrap(
			errors.New("nil execution dag"),
			"validate",
		)
	}
	// Validate all operations in the map
	for key, node := range e.Operations {
		if node == nil {
			return errors.Wrap(
				errors.Errorf("nil node for operation %s", key),
				"validate",
			)
		}
		if err := node.Validate(); err != nil {
			return errors.Wrap(
				errors.Wrapf(err, "validate node %s", key),
				"validate",
			)
		}
	}
	// Validate all stages
	for i, stage := range e.Stages {
		if stage == nil {
			return errors.Wrap(
				errors.Errorf("nil stage at index %d", i),
				"validate",
			)
		}
		if err := stage.Validate(); err != nil {
			return errors.Wrap(
				errors.Wrapf(err, "validate stage %d", i),
				"validate",
			)
		}
	}
	return nil
}
