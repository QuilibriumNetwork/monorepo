package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func (m *Message) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MessageType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hash
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Hash)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Hash); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write payload
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Payload)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Payload); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *Message) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read hash
	var hashLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hashLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Hash = make([]byte, hashLen)
	if _, err := buf.Read(m.Hash); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Address = make([]byte, addressLen)
	if _, err := buf.Read(m.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read payload
	var payloadLen uint32
	if err := binary.Read(buf, binary.BigEndian, &payloadLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Payload = make([]byte, payloadLen)
	if _, err := buf.Read(m.Payload); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (m *Message) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil message"), "validate")
	}

	if len(m.Hash) == 0 {
		return errors.Wrap(errors.New("hash is empty"), "validate")
	}

	if len(m.Address) == 0 {
		return errors.Wrap(errors.New("address is empty"), "validate")
	}

	// Payload can be empty for certain message types

	return nil
}
