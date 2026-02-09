package channel

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/channel/generated/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	types "source.quilibrium.com/quilibrium/monorepo/types/channel"
)

//go:generate ./generate.sh

// Compile-time check that DoubleRatchetEncryptedChannel implements
// EncryptedChannel
var _ types.EncryptedChannel = (*DoubleRatchetEncryptedChannel)(nil)

// DoubleRatchetEncryptedChannel implements the EncryptedChannel interface using
// double ratchet encryption
type DoubleRatchetEncryptedChannel struct{}

// NewDoubleRatchetEncryptedChannel creates a new instance of
// DoubleRatchetEncryptedChannel
func NewDoubleRatchetEncryptedChannel() *DoubleRatchetEncryptedChannel {
	return &DoubleRatchetEncryptedChannel{}
}

// EstablishTwoPartyChannel creates a new double ratchet state for encrypted
// communication
func (d *DoubleRatchetEncryptedChannel) EstablishTwoPartyChannel(
	isSender bool,
	sendingIdentityPrivateKey []byte,
	sendingSignedPrePrivateKey []byte,
	receivingIdentityKey []byte,
	receivingSignedPreKey []byte,
) (string, error) {
	var sessionKey []byte
	if isSender {
		sessionKeyB64Json := generated.SenderX3dh(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		sessionKeyB64 := ""
		err := json.Unmarshal([]byte(sessionKeyB64Json), &sessionKeyB64)
		if err != nil {
			return "", errors.Wrap(err, "establish two party channel")
		}

		sessionKey, err = base64.StdEncoding.DecodeString(sessionKeyB64)
		if err != nil {
			return "", errors.Wrap(err, "establish two party channel")
		}
	} else {
		sessionKeyB64Json := generated.ReceiverX3dh(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		sessionKeyB64 := ""
		err := json.Unmarshal([]byte(sessionKeyB64Json), &sessionKeyB64)
		if err != nil {
			return "", errors.Wrap(err, "establish two party channel")
		}

		sessionKey, err = base64.StdEncoding.DecodeString(sessionKeyB64)
		if err != nil {
			return "", errors.Wrap(err, "establish two party channel")
		}
	}

	state := NewDoubleRatchet(
		sessionKey[:32],
		sessionKey[32:64],
		sessionKey[64:],
		isSender,
		sendingSignedPrePrivateKey,
		receivingSignedPreKey,
	)
	return state, nil
}

// EncryptTwoPartyMessage encrypts a message using the double ratchet
func (d *DoubleRatchetEncryptedChannel) EncryptTwoPartyMessage(
	ratchetState string,
	message []byte,
) (newRatchetState string, envelope *channel.P2PChannelEnvelope, err error) {
	stateAndMessage := generated.DoubleRatchetStateAndMessage{
		RatchetState: ratchetState,
		Message:      message, // buildutils:allow-slice-alias this assignment is ephemeral
	}

	result, err := DoubleRatchetEncrypt(stateAndMessage)
	if err != nil {
		return "", nil, errors.Wrap(err, "encrypt two party message")
	}
	envelope = &channel.P2PChannelEnvelope{}
	err = json.Unmarshal([]byte(result.Envelope), envelope)
	if err != nil {
		return "", nil, errors.Wrap(err, "encrypt two party message")
	}

	return result.RatchetState, envelope, nil
}

// DecryptTwoPartyMessage decrypts a message using the double ratchet
func (d *DoubleRatchetEncryptedChannel) DecryptTwoPartyMessage(
	ratchetState string,
	envelope *channel.P2PChannelEnvelope,
) (newRatchetState string, message []byte, err error) {
	envelopeJson, err := json.Marshal(envelope)
	if err != nil {
		return "", nil, errors.Wrap(err, "decrypt two party message")
	}

	stateAndEnvelope := generated.DoubleRatchetStateAndEnvelope{
		RatchetState: ratchetState,
		Envelope:     string(envelopeJson),
	}

	result, err := DoubleRatchetDecrypt(stateAndEnvelope)
	if err != nil {
		return "", nil, errors.Wrap(err, "decrypt two party message")
	}
	return result.RatchetState, result.Message, nil
}

func NewDoubleRatchet(
	sessionKey []uint8,
	sendingHeaderKey []uint8,
	nextReceivingHeaderKey []uint8,
	isSender bool,
	sendingEphemeralPrivateKey []uint8,
	receivingEphemeralKey []uint8,
) string {
	return generated.NewDoubleRatchet(
		sessionKey,
		sendingHeaderKey,
		nextReceivingHeaderKey,
		isSender,
		sendingEphemeralPrivateKey,
		receivingEphemeralKey,
	)
}

func NewTripleRatchet(
	peers [][]uint8,
	peerKey []uint8,
	identityKey []uint8,
	signedPreKey []uint8,
	threshold uint64,
	asyncDkgRatchet bool,
) generated.TripleRatchetStateAndMetadata {
	return generated.NewTripleRatchet(
		peers,
		peerKey,
		identityKey,
		signedPreKey,
		threshold,
		asyncDkgRatchet,
	)
}

func DoubleRatchetEncrypt(
	ratchetStateAndMessage generated.DoubleRatchetStateAndMessage,
) (generated.DoubleRatchetStateAndEnvelope, error) {
	result, err := generated.DoubleRatchetEncrypt(ratchetStateAndMessage)
	if err != nil {
		return generated.DoubleRatchetStateAndEnvelope{}, err
	}
	return result, nil
}

func DoubleRatchetDecrypt(
	ratchetStateAndEnvelope generated.DoubleRatchetStateAndEnvelope,
) (generated.DoubleRatchetStateAndMessage, error) {
	result, err := generated.DoubleRatchetDecrypt(ratchetStateAndEnvelope)
	if err != nil {
		return generated.DoubleRatchetStateAndMessage{}, err
	}
	return result, nil
}

func TripleRatchetInitRound1(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	result, err := generated.TripleRatchetInitRound1(ratchetStateAndMetadata)
	if err != nil {
		return generated.TripleRatchetStateAndMetadata{
			Metadata: map[string]string{"error": err.Error()},
		}
	}
	return result
}

func TripleRatchetInitRound2(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	result, err := generated.TripleRatchetInitRound2(ratchetStateAndMetadata)
	if err != nil {
		return generated.TripleRatchetStateAndMetadata{
			Metadata: map[string]string{"error": err.Error()},
		}
	}
	return result
}

func TripleRatchetInitRound3(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	result, err := generated.TripleRatchetInitRound3(ratchetStateAndMetadata)
	if err != nil {
		return generated.TripleRatchetStateAndMetadata{
			Metadata: map[string]string{"error": err.Error()},
		}
	}
	return result
}

func TripleRatchetInitRound4(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	result, err := generated.TripleRatchetInitRound4(ratchetStateAndMetadata)
	if err != nil {
		return generated.TripleRatchetStateAndMetadata{
			Metadata: map[string]string{"error": err.Error()},
		}
	}
	return result
}

func TripleRatchetEncrypt(
	ratchetStateAndMessage generated.TripleRatchetStateAndMessage,
) generated.TripleRatchetStateAndEnvelope {
	result, err := generated.TripleRatchetEncrypt(ratchetStateAndMessage)
	if err != nil {
		return generated.TripleRatchetStateAndEnvelope{}
	}
	return result
}

func TripleRatchetDecrypt(
	ratchetStateAndEnvelope generated.TripleRatchetStateAndEnvelope,
) generated.TripleRatchetStateAndMessage {
	result, err := generated.TripleRatchetDecrypt(ratchetStateAndEnvelope)
	if err != nil {
		return generated.TripleRatchetStateAndMessage{}
	}
	return result
}
