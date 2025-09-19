package channel

import "source.quilibrium.com/quilibrium/monorepo/protobufs"

type MessageCiphertext struct {
	Ciphertext           []byte `json:"ciphertext"`
	InitializationVector []byte `json:"initialization_vector"`
	AssociatedData       []byte `json:"associated_data"`
}

type P2PChannelEnvelope struct {
	ProtocolIdentifier uint16            `json:"protocol_identifier"`
	MessageHeader      MessageCiphertext `json:"message_header"`
	MessageBody        MessageCiphertext `json:"message_ciphertext"`
}

type PublicChannelClient interface {
	Send(m *protobufs.P2PChannelEnvelope) error
	Recv() (*protobufs.P2PChannelEnvelope, error)
}

// EncryptedChannel defines an interface for establishing and using encrypted
// two-party channels
type EncryptedChannel interface {
	// EstablishTwoPartyChannel creates a new state for encrypted communication
	EstablishTwoPartyChannel(
		isSender bool,
		sendingIdentityPrivateKey []byte,
		sendingSignedPrePrivateKey []byte,
		receivingIdentityKey []byte,
		receivingSignedPreKey []byte,
	) (string, error)

	// EncryptTwoPartyMessage encrypts a message
	EncryptTwoPartyMessage(
		ratchetState string,
		message []byte,
	) (newRatchetState string, envelope *P2PChannelEnvelope, err error)

	// DecryptTwoPartyMessage decrypts a message
	DecryptTwoPartyMessage(
		ratchetState string,
		envelope *P2PChannelEnvelope,
	) (newRatchetState string, message []byte, err error)
}
