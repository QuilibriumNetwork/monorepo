package channel

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

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

// AllowedPeer types
type AllowedPeerPolicyType int

const (
	AnyPeer AllowedPeerPolicyType = iota
	OnlySelfPeer
	AnyProverPeer
	OnlyGlobalProverPeer
	OnlyShardProverPeer
	OnlyWhitelistedPeers
)

// AuthenticationProvider describes an interface for identifying auth
// information from the provided context, creating mTLS credentials, and
// server interceptor methods
type AuthenticationProvider interface {
	Identify(ctx context.Context) (peer.ID, error)
	CreateServerTLSCredentials() (
		credentials.TransportCredentials,
		error,
	)
	CreateClientTLSCredentials(expectedPeerId []byte) (
		credentials.TransportCredentials,
		error,
	)
	UnaryInterceptor(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error)
	StreamInterceptor(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error
}
