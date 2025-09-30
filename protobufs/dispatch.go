package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

// InboxMessage methods
func (m *InboxMessage) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, InboxMessageType); err != nil {
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

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, m.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write ephemeral_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.EphemeralPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.EphemeralPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write message
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Message)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Message); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *InboxMessage) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != InboxMessageType {
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
	m.Address = make([]byte, addressLen)
	if _, err := buf.Read(m.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &m.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read ephemeral_public_key
	var ephemeralKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ephemeralKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.EphemeralPublicKey = make([]byte, ephemeralKeyLen)
	if _, err := buf.Read(m.EphemeralPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read message
	var messageLen uint32
	if err := binary.Read(buf, binary.BigEndian, &messageLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Message = make([]byte, messageLen)
	if _, err := buf.Read(m.Message); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (m *InboxMessage) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil inbox message"), "validate")
	}
	if len(m.Address) == 0 {
		return errors.Wrap(errors.New("address required"), "validate")
	}
	if m.Timestamp == 0 {
		return errors.Wrap(errors.New("timestamp required"), "validate")
	}
	if len(m.EphemeralPublicKey) == 0 {
		return errors.Wrap(errors.New("ephemeral public key required"), "validate")
	}
	if len(m.Message) == 0 {
		return errors.Wrap(errors.New("message content required"), "validate")
	}
	return nil
}

// HubAddInboxMessage methods
func (m *HubAddInboxMessage) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, HubAddInboxType); err != nil {
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

	// Write inbox_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.InboxPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.InboxPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hub_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.HubPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.HubPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write inbox signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.InboxSignature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.InboxSignature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hub signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.HubSignature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.HubSignature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *HubAddInboxMessage) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HubAddInboxType {
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
	m.Address = make([]byte, addressLen)
	if _, err := buf.Read(m.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inbox_public_key
	var inboxKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &inboxKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.InboxPublicKey = make([]byte, inboxKeyLen)
	if _, err := buf.Read(m.InboxPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hub_public_key
	var hubKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hubKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.HubPublicKey = make([]byte, hubKeyLen)
	if _, err := buf.Read(m.HubPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inbox signature
	var inboxSignatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &inboxSignatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.InboxSignature = make([]byte, inboxSignatureLen)
	if _, err := buf.Read(m.InboxSignature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hub signature
	var hubSignatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hubSignatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.HubSignature = make([]byte, hubSignatureLen)
	if _, err := buf.Read(m.HubSignature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (m *HubAddInboxMessage) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil hub add inbox message"), "validate")
	}
	if len(m.Address) == 0 {
		return errors.Wrap(errors.New("address required"), "validate")
	}
	if len(m.InboxPublicKey) == 0 {
		return errors.Wrap(errors.New("inbox public key required"), "validate")
	}
	if len(m.HubPublicKey) == 0 {
		return errors.Wrap(errors.New("hub public key required"), "validate")
	}
	if len(m.InboxSignature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}
	if len(m.HubSignature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}
	return nil
}

// HubDeleteInboxMessage methods
func (m *HubDeleteInboxMessage) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, HubDeleteInboxType); err != nil {
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

	// Write inbox_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.InboxPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.InboxPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hub_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.HubPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.HubPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write inbox signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.InboxSignature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.InboxSignature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write hub signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.HubSignature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.HubSignature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *HubDeleteInboxMessage) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != HubDeleteInboxType {
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
	m.Address = make([]byte, addressLen)
	if _, err := buf.Read(m.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inbox_public_key
	var inboxKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &inboxKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.InboxPublicKey = make([]byte, inboxKeyLen)
	if _, err := buf.Read(m.InboxPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hub_public_key
	var hubKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hubKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.HubPublicKey = make([]byte, hubKeyLen)
	if _, err := buf.Read(m.HubPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read inbox signature
	var inboxSignatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &inboxSignatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.InboxSignature = make([]byte, inboxSignatureLen)
	if _, err := buf.Read(m.InboxSignature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read hub signature
	var hubSignatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &hubSignatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.HubSignature = make([]byte, hubSignatureLen)
	if _, err := buf.Read(m.HubSignature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (m *HubDeleteInboxMessage) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil hub delete inbox message"), "validate")
	}
	if len(m.Address) == 0 {
		return errors.Wrap(errors.New("address required"), "validate")
	}
	if len(m.InboxPublicKey) == 0 {
		return errors.Wrap(errors.New("inbox public key required"), "validate")
	}
	if len(m.HubPublicKey) == 0 {
		return errors.Wrap(errors.New("hub public key required"), "validate")
	}
	if len(m.InboxSignature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}
	if len(m.HubSignature) == 0 {
		return errors.Wrap(errors.New("signature required"), "validate")
	}
	return nil
}
