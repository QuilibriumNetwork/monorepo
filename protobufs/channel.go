package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

// ToCanonicalBytes serializes a P2PChannelEnvelope to canonical bytes
func (p *P2PChannelEnvelope) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		P2PChannelEnvelopeType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write protocol_identifier
	if err := binary.Write(
		buf,
		binary.BigEndian,
		p.ProtocolIdentifier,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write message_header
	if p.MessageHeader != nil {
		messageHeaderBytes, err := p.MessageHeader.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(messageHeaderBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(messageHeaderBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write message_body
	if p.MessageBody != nil {
		bodyBytes, err := p.MessageBody.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(bodyBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(bodyBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a P2PChannelEnvelope from canonical bytes
func (p *P2PChannelEnvelope) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != P2PChannelEnvelopeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read protocol_identifier
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&p.ProtocolIdentifier,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read message_header
	var headerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if headerLen > 0 {
		headerBytes := make([]byte, headerLen)
		if _, err := buf.Read(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.MessageHeader = &MessageCiphertext{}
		if err := p.MessageHeader.FromCanonicalBytes(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read message_body
	var bodyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &bodyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if bodyLen > 0 {
		bodyBytes := make([]byte, bodyLen)
		if _, err := buf.Read(bodyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.MessageBody = &MessageCiphertext{}
		if err := p.MessageBody.FromCanonicalBytes(bodyBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// ToCanonicalBytes serializes a MessageCiphertext to canonical bytes
func (m *MessageCiphertext) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		MessageCiphertextType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write initialization_vector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.InitializationVector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.InitializationVector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write ciphertext
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Ciphertext)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Ciphertext); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write associated_data
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.AssociatedData)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.AssociatedData); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

// FromCanonicalBytes deserializes a MessageCiphertext from canonical bytes
func (m *MessageCiphertext) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageCiphertextType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read initialization_vector
	var ivLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ivLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.InitializationVector = make([]byte, ivLen)
	if _, err := buf.Read(m.InitializationVector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read ciphertext
	var ciphertextLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ciphertextLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Ciphertext = make([]byte, ciphertextLen)
	if _, err := buf.Read(m.Ciphertext); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read associated_data
	var adLen uint32
	if err := binary.Read(buf, binary.BigEndian, &adLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.AssociatedData = make([]byte, adLen)
	if _, err := buf.Read(m.AssociatedData); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// Validate checks that all fields have valid lengths
func (m *MessageCiphertext) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("message ciphertext is nil"), "validate")
	}

	// Initialization vector should be 12 bytes for AES-GCM
	if len(m.InitializationVector) > 0 && len(m.InitializationVector) != 12 {
		return errors.Wrap(
			errors.Errorf(
				"initialization vector must be 12 bytes, got %d",
				len(m.InitializationVector),
			),
			"validate",
		)
	}

	// Ciphertext and AssociatedData can be variable length
	return nil
}

// Validate checks that all fields have valid values
func (p *P2PChannelEnvelope) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("channel envelope is nil"), "validate")
	}

	// Validate message header if present
	if p.MessageHeader != nil {
		if err := p.MessageHeader.Validate(); err != nil {
			return errors.Wrap(err, "invalid message header")
		}
	}

	// Validate message body if present
	if p.MessageBody != nil {
		if err := p.MessageBody.Validate(); err != nil {
			return errors.Wrap(err, "invalid message body")
		}
	}

	return nil
}
