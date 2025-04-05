package channel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

const TRIPLE_RATCHET_PROTOCOL_VERSION = 1
const TRIPLE_RATCHET_PROTOCOL = 2<<8 + TRIPLE_RATCHET_PROTOCOL_VERSION

type TripleRatchetRound int

const (
	TRIPLE_RATCHET_ROUND_UNINITIALIZED = TripleRatchetRound(0)
	TRIPLE_RATCHET_ROUND_INITIALIZED   = TripleRatchetRound(1)
	TRIPLE_RATCHET_ROUND_COMMITTED     = TripleRatchetRound(2)
	TRIPLE_RATCHET_ROUND_REVEALED      = TripleRatchetRound(3)
	TRIPLE_RATCHET_ROUND_RECONSTRUCTED = TripleRatchetRound(4)
)

// Note: If an HSM with raw primitive access becomes available, the raw crypto
// mechanisms should be refactored into calls in KeyManager and implemented
// through the driver
type TripleRatchetParticipant struct {
	peerKey                      curves.Scalar
	sendingEphemeralPrivateKey   curves.Scalar
	receivingEphemeralKeys       map[string]curves.Scalar
	receivingGroupKey            curves.Point
	curve                        curves.Curve
	keyManager                   keys.KeyManager
	rootKey                      []byte
	sendingChainKey              []byte
	currentHeaderKey             []byte
	nextHeaderKey                []byte
	receivingChainKey            map[string][]byte
	currentSendingChainLength    uint32
	previousSendingChainLength   uint32
	currentReceivingChainLength  map[string]uint32
	previousReceivingChainLength map[string]uint32
	peerIdMap                    map[string]int
	idPeerMap                    map[int]*PeerInfo
	skippedKeysMap               map[string]map[string]map[uint32][]byte
	peerChannels                 map[string]*DoubleRatchetParticipant
	dkgRatchet                   *Feldman
}

type PeerInfo struct {
	PublicKey          curves.Point
	IdentityPublicKey  curves.Point
	SignedPrePublicKey curves.Point
}

// Weak-mode synchronous group modification TR – this is not the asynchronous
// TR, does not ratchet group key automatically, know what your use case is
// before adopting this.
func NewTripleRatchetParticipant(
	peers []*PeerInfo,
	curve curves.Curve,
	keyManager keys.KeyManager,
	peerKey curves.Scalar,
	identityKey curves.Scalar,
	signedPreKey curves.Scalar,
) (
	*TripleRatchetParticipant,
	map[string]*protobufs.P2PChannelEnvelope,
	error,
) {
	participant := &TripleRatchetParticipant{}
	participant.skippedKeysMap = make(map[string]map[string]map[uint32][]byte)
	participant.receivingEphemeralKeys = make(map[string]curves.Scalar)
	participant.receivingChainKey = make(map[string][]byte)
	participant.peerChannels = make(map[string]*DoubleRatchetParticipant)
	participant.keyManager = keyManager
	participant.currentSendingChainLength = 0
	participant.previousSendingChainLength = 0
	participant.currentReceivingChainLength = make(map[string]uint32)
	participant.previousReceivingChainLength = make(map[string]uint32)

	peerBasis := append([]*PeerInfo{}, peers...)
	peerBasis = append(peerBasis, &PeerInfo{
		PublicKey:          peerKey.Point().Generator().Mul(peerKey),
		IdentityPublicKey:  identityKey.Point().Generator().Mul(identityKey),
		SignedPrePublicKey: signedPreKey.Point().Generator().Mul(signedPreKey),
	})
	sort.Slice(peerBasis, func(i, j int) bool {
		return bytes.Compare(
			peerBasis[i].PublicKey.ToAffineCompressed(),
			peerBasis[j].PublicKey.ToAffineCompressed(),
		) <= 0
	})

	initMessages := make(map[string]*protobufs.P2PChannelEnvelope)

	peerIdMap := map[string]int{}
	idPeerMap := map[int]*PeerInfo{}
	sender := false
	for i := 0; i < len(peerBasis); i++ {
		peerIdMap[string(peerBasis[i].PublicKey.ToAffineCompressed())] = i + 1
		idPeerMap[i+1] = peerBasis[i]
		if bytes.Equal(
			peerBasis[i].PublicKey.ToAffineCompressed(),
			peerKey.Point().Generator().Mul(peerKey).ToAffineCompressed(),
		) {
			sender = true
		} else {
			participant.skippedKeysMap[string(
				peerBasis[i].PublicKey.ToAffineCompressed(),
			)] = make(map[string]map[uint32][]byte)
			participant.currentReceivingChainLength[string(
				peerBasis[i].PublicKey.ToAffineCompressed(),
			)] = 0
			participant.previousReceivingChainLength[string(
				peerBasis[i].PublicKey.ToAffineCompressed(),
			)] = 0
			var sessionKey []byte
			if sender {
				sessionKey = SenderX3DH(
					identityKey,
					signedPreKey,
					peerBasis[i].IdentityPublicKey,
					peerBasis[i].SignedPrePublicKey,
					96,
				)
			} else {
				sessionKey = ReceiverX3DH(
					identityKey,
					signedPreKey,
					peerBasis[i].IdentityPublicKey,
					peerBasis[i].SignedPrePublicKey,
					96,
				)
			}

			var err error
			participant.peerChannels[string(
				peerBasis[i].PublicKey.ToAffineCompressed(),
			)], err = NewDoubleRatchetParticipant(
				sessionKey[:32],
				sessionKey[32:64],
				sessionKey[64:],
				sender,
				signedPreKey,
				peerBasis[i].SignedPrePublicKey,
				&curve,
				keyManager,
			)
			if err != nil {
				return nil, nil, errors.Wrap(err, "new triple ratchet participant")
			}
			if sender {
				initMessages[string(peerBasis[i].PublicKey.ToAffineCompressed())], err =
					participant.peerChannels[string(
						peerBasis[i].PublicKey.ToAffineCompressed(),
					)].RatchetEncrypt([]byte("init"))
				if err != nil {
					return nil, nil, errors.Wrap(err, "new triple ratchet participant")
				}
			}
		}
	}

	feldman, err := NewFeldman(
		2,
		len(peers)+1,
		peerIdMap[string(
			peerKey.Point().Generator().Mul(peerKey).ToAffineCompressed(),
		)],
		curve.NewScalar().Random(rand.Reader),
		curve,
		curve.Point.Generator(),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "new triple ratchet participant")
	}

	participant.peerIdMap = peerIdMap
	participant.idPeerMap = idPeerMap
	participant.dkgRatchet = feldman
	participant.curve = curve
	participant.peerKey = peerKey

	return participant, initMessages, nil
}

func (r *TripleRatchetParticipant) Initialize(
	initMessages map[string]*protobufs.P2PChannelEnvelope,
) (map[string]*protobufs.P2PChannelEnvelope, error) {
	for k, m := range initMessages {
		msg, err := r.peerChannels[k].RatchetDecrypt(m)
		if err != nil {
			return nil, errors.Wrap(err, "initialize")
		}

		if string(msg) != "init" {
			return nil, errors.Wrap(errors.New("invalid init message"), "initialize")
		}
	}

	if err := r.dkgRatchet.SamplePolynomial(); err != nil {
		return nil, errors.Wrap(err, "initialize")
	}

	result, err := r.dkgRatchet.GetPolyFrags()
	if err != nil {
		return nil, errors.Wrap(err, "initialize")
	}

	resultMap := make(map[string]*protobufs.P2PChannelEnvelope)
	for k, v := range result {
		if r.idPeerMap[k].PublicKey.Equal(
			r.peerKey.Point().Generator().Mul(r.peerKey),
		) {
			continue
		}

		envelope, err := r.peerChannels[string(
			r.idPeerMap[k].PublicKey.ToAffineCompressed(),
		)].RatchetEncrypt(v)
		if err != nil {
			return nil, errors.Wrap(err, "initialize")
		}

		resultMap[string(r.idPeerMap[k].PublicKey.ToAffineCompressed())] = envelope
	}

	return resultMap, nil
}

func (r *TripleRatchetParticipant) ReceivePolyFrag(
	peerId []byte,
	frag *protobufs.P2PChannelEnvelope,
) (map[string]*protobufs.P2PChannelEnvelope, error) {
	b, err := r.peerChannels[string(peerId)].RatchetDecrypt(frag)
	if err != nil {
		return nil, errors.Wrap(err, "receive poly frag")
	}

	result, err := r.dkgRatchet.SetPolyFragForParty(
		r.peerIdMap[string(peerId)],
		b,
	)
	if err != nil {
		return nil, errors.Wrap(err, "receive poly frag")
	}

	if len(result) != 0 {
		envelopes := make(map[string]*protobufs.P2PChannelEnvelope)
		for k, c := range r.peerChannels {
			envelope, err := c.RatchetEncrypt(result)
			if err != nil {
				return nil, errors.Wrap(err, "receive poly frag")
			}
			envelopes[k] = envelope
		}

		return envelopes, errors.Wrap(err, "receive poly frag")
	}

	return nil, nil
}

func (r *TripleRatchetParticipant) ReceiveCommitment(
	peerId []byte,
	zkcommit *protobufs.P2PChannelEnvelope,
) (map[string]*protobufs.P2PChannelEnvelope, error) {
	b, err := r.peerChannels[string(peerId)].RatchetDecrypt(zkcommit)
	if err != nil {
		return nil, errors.Wrap(err, "receive commitment")
	}

	result, err := r.dkgRatchet.ReceiveCommitments(
		r.peerIdMap[string(peerId)],
		b,
	)
	if err != nil {
		return nil, errors.Wrap(err, "receive commitment")
	}

	d, err := json.Marshal(result)
	if err != nil {
		return nil, errors.Wrap(err, "receive commitment")
	}

	if result != nil {
		envelopes := make(map[string]*protobufs.P2PChannelEnvelope)
		for k, c := range r.peerChannels {
			envelope, err := c.RatchetEncrypt(d)
			if err != nil {
				return nil, errors.Wrap(err, "receive commitment")
			}
			envelopes[k] = envelope
		}

		return envelopes, errors.Wrap(err, "receive poly frag")
	}

	return nil, nil
}

func (r *TripleRatchetParticipant) Recombine(
	peerId []byte,
	reveal *protobufs.P2PChannelEnvelope,
) error {
	b, err := r.peerChannels[string(peerId)].RatchetDecrypt(reveal)
	if err != nil {
		return errors.Wrap(err, "recombine")
	}

	rev := &FeldmanReveal{}
	if err = json.Unmarshal(b, rev); err != nil {
		return errors.Wrap(err, "recombine")
	}

	done, err := r.dkgRatchet.Recombine(
		r.peerIdMap[string(peerId)],
		rev,
	)
	if err != nil {
		return errors.Wrap(err, "recombine")
	}

	if !done {
		return nil
	}

	sess := sha512.Sum512_256(r.dkgRatchet.PublicKeyBytes())
	hash := hkdf.New(
		sha512.New,
		r.dkgRatchet.PublicKeyBytes(),
		sess[:],
		[]byte("quilibrium-triple-ratchet"),
	)
	rkck := make([]byte, 96)
	if _, err := hash.Read(rkck[:]); err != nil {
		return errors.Wrap(err, "recombine")
	}

	r.rootKey = rkck[:32]
	r.currentHeaderKey = rkck[32:64]
	r.nextHeaderKey = rkck[64:]
	r.receivingGroupKey = r.dkgRatchet.PublicKey()
	r.sendingEphemeralPrivateKey = r.curve.Scalar.Random(rand.Reader)

	return nil
}

func (r *TripleRatchetParticipant) RatchetEncrypt(
	message []byte,
) (*protobufs.P2PChannelEnvelope, error) {
	envelope := &protobufs.P2PChannelEnvelope{
		ProtocolIdentifier: TRIPLE_RATCHET_PROTOCOL,
		MessageHeader:      &protobufs.MessageCiphertext{},
		MessageBody:        &protobufs.MessageCiphertext{},
	}

	newChainKey, messageKey, aeadKey := ratchetKeys(r.sendingChainKey)
	r.sendingChainKey = newChainKey

	var err error
	header := r.encodeHeader()
	envelope.MessageHeader, err = r.encrypt(
		header,
		r.currentHeaderKey,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not encrypt header")
	}

	envelope.MessageBody, err = r.encrypt(
		message,
		messageKey,
		append(append([]byte{}, aeadKey...), envelope.MessageHeader.Ciphertext...),
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not encrypt message")
	}

	r.currentSendingChainLength++

	return envelope, nil
}

func (r *TripleRatchetParticipant) RatchetDecrypt(
	envelope *protobufs.P2PChannelEnvelope,
) ([]byte, error) {
	plaintext, err := r.trySkippedMessageKeys(envelope)
	if err != nil {
		return nil, errors.Wrap(err, "ratchet decrypt")
	}

	if plaintext != nil {
		return plaintext, nil
	}

	header, shouldRatchet, err := r.decryptHeader(
		envelope.MessageHeader,
		r.currentHeaderKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "ratchet decrypt")
	}

	senderKey,
		receivingEphemeralKey,
		previousReceivingChainLength,
		currentReceivingChainLength,
		err := r.decodeHeader(header)
	if err != nil {
		return nil, errors.Wrap(err, "ratchet decrypt")
	}

	if shouldRatchet {
		if err := r.skipMessageKeys(
			senderKey,
			previousReceivingChainLength,
		); err != nil {
			return nil, errors.Wrap(err, "ratchet decrypt")
		}
		if err := r.ratchetReceiverEphemeralKeys(
			senderKey,
			receivingEphemeralKey,
		); err != nil {
			return nil, errors.Wrap(err, "ratchet decrypt")
		}
	}

	if err := r.skipMessageKeys(
		senderKey,
		currentReceivingChainLength,
	); err != nil {
		return nil, errors.Wrap(err, "ratchet decrypt")
	}

	newChainKey, messageKey, aeadKey := ratchetKeys(
		r.receivingChainKey[string(senderKey.ToAffineCompressed())],
	)
	r.receivingChainKey[string(senderKey.ToAffineCompressed())] = newChainKey
	r.currentReceivingChainLength[string(senderKey.ToAffineCompressed())]++

	plaintext, err = r.decrypt(
		envelope.MessageBody,
		messageKey,
		append(
			append([]byte{}, aeadKey...),
			envelope.MessageHeader.Ciphertext...,
		),
	)

	return plaintext, errors.Wrap(err, "ratchet decrypt")
}

func (r *TripleRatchetParticipant) ratchetSenderEphemeralKeys() error {
	hash := hkdf.New(
		sha512.New,
		r.receivingGroupKey.Mul(
			r.sendingEphemeralPrivateKey,
		).ToAffineCompressed(),
		r.rootKey,
		[]byte("quilibrium-triple-ratchet"),
	)
	rkck2 := make([]byte, 96)
	if _, err := hash.Read(rkck2[:]); err != nil {
		return errors.Wrap(err, "failed ratcheting root key")
	}

	r.rootKey = rkck2[:32]
	r.sendingChainKey = rkck2[32:64]
	r.nextHeaderKey = rkck2[64:]
	return nil
}

func (r *TripleRatchetParticipant) ratchetReceiverEphemeralKeys(
	peerKey curves.Point,
	newEphemeralKey curves.Scalar,
) error {
	r.previousSendingChainLength = r.currentSendingChainLength
	r.currentSendingChainLength = 0
	r.currentReceivingChainLength[string(peerKey.ToAffineCompressed())] = 0
	r.currentHeaderKey = r.nextHeaderKey
	r.receivingEphemeralKeys[string(
		peerKey.ToAffineCompressed(),
	)] = newEphemeralKey

	hash := hkdf.New(
		sha512.New,
		r.receivingGroupKey.Mul(
			newEphemeralKey,
		).ToAffineCompressed(),
		r.rootKey,
		[]byte("quilibrium-triple-ratchet"),
	)
	rkck := make([]byte, 96)
	if _, err := hash.Read(rkck[:]); err != nil {
		return errors.Wrap(err, "failed ratcheting root key")
	}

	r.rootKey = rkck[:32]
	r.receivingChainKey[string(peerKey.ToAffineCompressed())] = rkck[32:64]
	r.nextHeaderKey = rkck[64:]
	r.sendingEphemeralPrivateKey = r.curve.NewScalar().Random(rand.Reader)

	return nil
}

func (r *TripleRatchetParticipant) trySkippedMessageKeys(
	envelope *protobufs.P2PChannelEnvelope,
) ([]byte, error) {
	for receivingHeaderKey, skippedKeys := range r.skippedKeysMap {
		header, _, err := r.decryptHeader(
			envelope.MessageHeader,
			[]byte(receivingHeaderKey),
		)

		if err == nil {
			peerKey, _, _, current, err := r.decodeHeader(header)
			if err != nil {
				return nil, errors.Wrap(err, "try skipped message keys")
			}

			messageKey := skippedKeys[string(
				peerKey.ToAffineCompressed(),
			)][current][:32]
			aeadKey := skippedKeys[string(
				peerKey.ToAffineCompressed(),
			)][current][32:]
			plaintext, err := r.decrypt(
				envelope.MessageBody,
				messageKey,
				append(
					append([]byte{}, aeadKey...),
					envelope.MessageHeader.Ciphertext[:]...,
				),
			)

			if err != nil {
				return nil, errors.Wrap(err, "try skipped message keys")
			}

			delete(r.skippedKeysMap[string(
				peerKey.ToAffineCompressed(),
			)][receivingHeaderKey], current)
			if len(r.skippedKeysMap[string(
				peerKey.ToAffineCompressed(),
			)][receivingHeaderKey]) == 0 {
				delete(r.skippedKeysMap[string(
					peerKey.ToAffineCompressed(),
				)], receivingHeaderKey)
			}

			return plaintext, nil
		}
	}

	return nil, nil
}

func (r *TripleRatchetParticipant) skipMessageKeys(
	senderKey curves.Point,
	until uint32,
) error {
	if r.currentReceivingChainLength[string(
		senderKey.ToAffineCompressed(),
	)]+100 < until {
		return errors.Wrap(errors.New("skip limit exceeded"), "skip message keys")
	}

	if r.receivingChainKey != nil {
		for r.currentReceivingChainLength[string(
			senderKey.ToAffineCompressed(),
		)] < until {
			newChainKey, messageKey, aeadKey := ratchetKeys(
				r.receivingChainKey[string(
					senderKey.ToAffineCompressed(),
				)],
			)
			skippedKeys := r.skippedKeysMap[string(
				senderKey.ToAffineCompressed(),
			)][string(r.currentHeaderKey)]
			if skippedKeys == nil {
				r.skippedKeysMap[string(
					senderKey.ToAffineCompressed(),
				)][string(r.currentHeaderKey)] =
					make(map[uint32][]byte)
			}

			skippedKeys[r.currentReceivingChainLength[string(
				senderKey.ToAffineCompressed(),
			)]] = append(
				append([]byte{}, messageKey...),
				aeadKey...,
			)
			r.receivingChainKey[string(
				senderKey.ToAffineCompressed(),
			)] = newChainKey
			r.currentReceivingChainLength[string(
				senderKey.ToAffineCompressed(),
			)]++
		}
	}

	return nil
}

func (r *TripleRatchetParticipant) encodeHeader() []byte {
	header := []byte{}
	header = append(
		header,
		r.peerKey.Point().Generator().Mul(r.peerKey).ToAffineCompressed()...,
	)
	header = append(
		header,
		r.sendingEphemeralPrivateKey.Bytes()...,
	)
	header = binary.BigEndian.AppendUint32(header, r.previousSendingChainLength)
	header = binary.BigEndian.AppendUint32(header, r.currentSendingChainLength)
	return header
}

func (r *TripleRatchetParticipant) decryptHeader(
	ciphertext *protobufs.MessageCiphertext,
	receivingHeaderKey []byte,
) ([]byte, bool, error) {
	header, err := r.decrypt(
		ciphertext,
		receivingHeaderKey,
		nil,
	)
	if err != nil && subtle.ConstantTimeCompare(
		r.currentHeaderKey,
		receivingHeaderKey,
	) == 1 {
		if header, err = r.decrypt(
			ciphertext,
			r.nextHeaderKey,
			nil,
		); err != nil {
			return nil, false, errors.Wrap(err, "could not decrypt header")
		}
		utils.GetLogger().Info("should ratchet")
		return header, true, nil
	}

	return header, false, errors.Wrap(err, "could not decrypt header")
}

func (r *TripleRatchetParticipant) decodeHeader(
	header []byte,
) (curves.Point, curves.Scalar, uint32, uint32, error) {
	if len(header) < 9 {
		return nil, nil, 0, 0, errors.Wrap(
			errors.New("malformed header"),
			"decode header",
		)
	}

	currentReceivingChainLength := binary.BigEndian.Uint32(header[len(header)-4:])
	previousReceivingChainLength := binary.BigEndian.Uint32(
		header[len(header)-8 : len(header)-4],
	)
	sender := header[:len(r.curve.Point.ToAffineCompressed())]
	senderKey, err := r.curve.Point.FromAffineCompressed(sender)
	if err != nil {
		return nil, nil, 0, 0, errors.Wrap(err, "decode header")
	}

	receivingEphemeralKeyBytes := header[len(
		r.curve.Point.ToAffineCompressed(),
	) : len(header)-8]
	receivingEphemeralKey, err := r.curve.Scalar.Clone().SetBytes(
		receivingEphemeralKeyBytes,
	)

	return senderKey,
		receivingEphemeralKey,
		previousReceivingChainLength,
		currentReceivingChainLength,
		errors.Wrap(err, "decode header")
}

func (r *TripleRatchetParticipant) encrypt(
	plaintext []byte,
	key []byte,
	associatedData []byte,
) (*protobufs.MessageCiphertext, error) {
	iv := [12]byte{}
	rand.Read(iv[:])
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt")
	}

	ciphertext := &protobufs.MessageCiphertext{}

	if associatedData == nil {
		associatedData = make([]byte, 32)
		if _, err := rand.Read(associatedData); err != nil {
			return nil, errors.Wrap(err, "encrypt")
		}
		ciphertext.AssociatedData = associatedData
	}

	ciphertext.Ciphertext = gcm.Seal(nil, iv[:], plaintext, associatedData)
	ciphertext.InitializationVector = iv[:]

	return ciphertext, nil
}

func (r *TripleRatchetParticipant) decrypt(
	ciphertext *protobufs.MessageCiphertext,
	key []byte,
	associatedData []byte,
) ([]byte, error) {
	if associatedData == nil {
		associatedData = ciphertext.AssociatedData
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt")
	}

	plaintext, err := gcm.Open(
		nil,
		ciphertext.InitializationVector,
		ciphertext.Ciphertext,
		associatedData,
	)

	return plaintext, errors.Wrap(err, "decrypt")
}
