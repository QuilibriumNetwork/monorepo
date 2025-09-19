package p2p

import (
	"encoding/binary"
	"sync"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	typeschannel "source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
)

// A simplified P2P channel – the pair of actors communicating is public
// knowledge, even though the data itself is encrypted.
type PublicP2PChannel struct {
	encryptedChannel    typeschannel.EncryptedChannel
	channelState        string
	sendMap             map[uint64][]byte
	receiveMap          map[uint64][]byte
	pubSub              p2p.PubSub
	sendFilter          []byte
	receiveFilter       []byte
	initiator           bool
	senderSeqNo         uint64
	receiverSeqNo       uint64
	receiveChan         chan []byte
	receiveMx           sync.Mutex
	publicChannelClient typeschannel.PublicChannelClient
}

func NewPublicP2PChannel(
	encryptedChannel typeschannel.EncryptedChannel,
	publicChannelClient typeschannel.PublicChannelClient,
	senderIdentifier, receiverIdentifier []byte,
	initiator bool,
	sendingIdentityPrivateKey []byte,
	sendingSignedPrePrivateKey []byte,
	receivingIdentityKey []byte,
	receivingSignedPreKey []byte,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
) (*PublicP2PChannel, error) {
	sendFilter := append(
		append([]byte{}, senderIdentifier...),
		receiverIdentifier...,
	)
	receiveFilter := append(
		append([]byte{}, receiverIdentifier...),
		senderIdentifier...,
	)

	ch := &PublicP2PChannel{
		encryptedChannel:    encryptedChannel,
		publicChannelClient: publicChannelClient,
		sendMap:             map[uint64][]byte{},
		receiveMap:          map[uint64][]byte{},
		initiator:           initiator,
		sendFilter:          sendFilter,
		receiveFilter:       receiveFilter,
		pubSub:              pubSub,
		senderSeqNo:         0,
		receiverSeqNo:       0,
		receiveChan:         make(chan []byte),
	}

	var err error
	channelState, err := encryptedChannel.EstablishTwoPartyChannel(
		initiator,
		sendingIdentityPrivateKey,
		sendingSignedPrePrivateKey,
		receivingIdentityKey,
		receivingSignedPreKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "new public p2p channel")
	}
	ch.channelState = channelState

	return ch, nil
}

func (c *PublicP2PChannel) Send(message []byte) error {
	c.senderSeqNo++
	message = append(
		binary.BigEndian.AppendUint64(nil, c.senderSeqNo),
		message...,
	)

	newState, envelope, err := c.encryptedChannel.EncryptTwoPartyMessage(
		c.channelState,
		message,
	)
	if err != nil {
		return errors.Wrap(err, "send")
	}

	c.channelState = newState

	return errors.Wrap(
		c.publicChannelClient.Send(&protobufs.P2PChannelEnvelope{
			ProtocolIdentifier: uint32(envelope.ProtocolIdentifier),
			MessageHeader: &protobufs.MessageCiphertext{
				InitializationVector: envelope.MessageHeader.InitializationVector,
				Ciphertext:           envelope.MessageHeader.Ciphertext,
				AssociatedData:       envelope.MessageHeader.AssociatedData,
			},
			MessageBody: &protobufs.MessageCiphertext{
				InitializationVector: envelope.MessageBody.InitializationVector,
				Ciphertext:           envelope.MessageBody.Ciphertext,
				AssociatedData:       envelope.MessageBody.AssociatedData,
			},
		}),
		"send",
	)
}

func (c *PublicP2PChannel) Receive() ([]byte, error) {
	c.receiverSeqNo++

	msg, err := c.publicChannelClient.Recv()
	if err != nil {
		return nil, errors.Wrap(err, "receive")
	}

	newState, rawData, err := c.encryptedChannel.DecryptTwoPartyMessage(
		c.channelState,
		&typeschannel.P2PChannelEnvelope{
			ProtocolIdentifier: uint16(msg.ProtocolIdentifier),
			MessageHeader: typeschannel.MessageCiphertext{
				InitializationVector: msg.MessageHeader.InitializationVector,
				Ciphertext:           msg.MessageHeader.Ciphertext,
				AssociatedData:       msg.MessageHeader.AssociatedData,
			},
			MessageBody: typeschannel.MessageCiphertext{
				InitializationVector: msg.MessageBody.InitializationVector,
				Ciphertext:           msg.MessageBody.Ciphertext,
				AssociatedData:       msg.MessageBody.AssociatedData,
			},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "receive")
	}

	c.channelState = newState

	seqNo := binary.BigEndian.Uint64(rawData[:8])

	if seqNo == c.receiverSeqNo {
		return rawData[8:], nil
	} else {
		c.receiveMx.Lock()
		c.receiveMap[seqNo] = rawData[8:]
		c.receiveMx.Unlock()
	}

	return nil, nil
}

func (c *PublicP2PChannel) Close() {
}
