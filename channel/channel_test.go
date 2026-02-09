package channel_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/channel"
	generated "source.quilibrium.com/quilibrium/monorepo/channel/generated/channel"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type peer struct {
	privKey         *curves.ScalarEd448
	pubKey          *curves.PointEd448
	pubKeyB64       string
	identityKey     *curves.ScalarEd448
	identityPubKey  *curves.PointEd448
	signedPreKey    *curves.ScalarEd448
	signedPrePubKey *curves.PointEd448
}

func generatePeer() *peer {
	privKey := &curves.ScalarEd448{}
	privKey = privKey.Random(rand.Reader).(*curves.ScalarEd448)
	identityKey := &curves.ScalarEd448{}
	identityKey = identityKey.Random(rand.Reader).(*curves.ScalarEd448)
	signedPreKey := &curves.ScalarEd448{}
	signedPreKey = signedPreKey.Random(rand.Reader).(*curves.ScalarEd448)

	pubkey := privKey.Point().Generator().Mul(privKey).(*curves.PointEd448)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubkey.ToAffineCompressed())
	return &peer{
		privKey:         privKey,
		pubKey:          pubkey,
		pubKeyB64:       pubKeyB64,
		identityKey:     identityKey,
		identityPubKey:  identityKey.Point().Generator().Mul(identityKey).(*curves.PointEd448),
		signedPreKey:    signedPreKey,
		signedPrePubKey: signedPreKey.Point().Generator().Mul(signedPreKey).(*curves.PointEd448),
	}
}

func remapOutputs(maps map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for k := range maps {
		out[k] = map[string]string{}
	}

	for k := range maps {
		for ik, iv := range maps[k] {
			out[ik][k] = iv
		}
	}

	return out
}

// TestX3DHAndDoubleRatchet tests X3DH key agreement and double ratchet session
// establishment between two parties.
func TestX3DHAndDoubleRatchet(t *testing.T) {
	// Generate two peers with their identity and pre-keys
	// Using ScalarEd448 which produces 56-byte private keys (Scalars)
	// and 57-byte public keys (Edwards compressed)
	alice := generatePeer()
	bob := generatePeer()

	// Log key sizes for debugging
	t.Logf("Alice identity private key size: %d bytes", len(alice.identityKey.Bytes()))
	t.Logf("Alice identity public key size: %d bytes", len(alice.identityPubKey.ToAffineCompressed()))
	t.Logf("Alice signed pre-key private size: %d bytes", len(alice.signedPreKey.Bytes()))
	t.Logf("Alice signed pre-key public size: %d bytes", len(alice.signedPrePubKey.ToAffineCompressed()))

	// Test X3DH key agreement
	// Alice is sender, Bob is receiver
	// Sender needs: own identity private, own ephemeral private, peer identity public, peer signed pre public
	// Receiver needs: own identity private, own signed pre private, peer identity public, peer ephemeral public

	// For X3DH, Alice uses her signedPreKey as the ephemeral key
	aliceSessionKeyJson := generated.SenderX3dh(
		alice.identityKey.Bytes(),        // sending identity private key (56 bytes)
		alice.signedPreKey.Bytes(),       // sending ephemeral private key (56 bytes)
		bob.identityPubKey.ToAffineCompressed(),  // receiving identity public key (57 bytes)
		bob.signedPrePubKey.ToAffineCompressed(), // receiving signed pre-key public (57 bytes)
		96, // session key length
	)

	t.Logf("Alice X3DH result: %s", aliceSessionKeyJson)

	// Check if Alice got an error
	if len(aliceSessionKeyJson) == 0 || aliceSessionKeyJson[0] != '"' {
		t.Fatalf("Alice X3DH failed: %s", aliceSessionKeyJson)
	}

	// Bob performs receiver side X3DH
	bobSessionKeyJson := generated.ReceiverX3dh(
		bob.identityKey.Bytes(),          // sending identity private key (56 bytes)
		bob.signedPreKey.Bytes(),         // sending signed pre private key (56 bytes)
		alice.identityPubKey.ToAffineCompressed(),  // receiving identity public key (57 bytes)
		alice.signedPrePubKey.ToAffineCompressed(), // receiving ephemeral public key (57 bytes)
		96, // session key length
	)

	t.Logf("Bob X3DH result: %s", bobSessionKeyJson)

	// Check if Bob got an error
	if len(bobSessionKeyJson) == 0 || bobSessionKeyJson[0] != '"' {
		t.Fatalf("Bob X3DH failed: %s", bobSessionKeyJson)
	}

	// Decode session keys and verify they match
	var aliceSessionKeyB64, bobSessionKeyB64 string
	if err := json.Unmarshal([]byte(aliceSessionKeyJson), &aliceSessionKeyB64); err != nil {
		t.Fatalf("Failed to parse Alice session key: %v", err)
	}
	if err := json.Unmarshal([]byte(bobSessionKeyJson), &bobSessionKeyB64); err != nil {
		t.Fatalf("Failed to parse Bob session key: %v", err)
	}

	aliceSessionKey, err := base64.StdEncoding.DecodeString(aliceSessionKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode Alice session key: %v", err)
	}
	bobSessionKey, err := base64.StdEncoding.DecodeString(bobSessionKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode Bob session key: %v", err)
	}

	assert.Equal(t, 96, len(aliceSessionKey), "Alice session key should be 96 bytes")
	assert.Equal(t, 96, len(bobSessionKey), "Bob session key should be 96 bytes")
	assert.Equal(t, aliceSessionKey, bobSessionKey, "Session keys should match")

	t.Logf("X3DH session key established successfully (%d bytes)", len(aliceSessionKey))

	// Now test double ratchet session establishment
	// Use the DoubleRatchetEncryptedChannel interface
	ch := channel.NewDoubleRatchetEncryptedChannel()

	// Alice establishes session as sender
	aliceState, err := ch.EstablishTwoPartyChannel(
		true, // isSender
		alice.identityKey.Bytes(),
		alice.signedPreKey.Bytes(),
		bob.identityPubKey.ToAffineCompressed(),
		bob.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Alice failed to establish channel: %v", err)
	}
	t.Logf("Alice established double ratchet session")

	// Bob establishes session as receiver
	bobState, err := ch.EstablishTwoPartyChannel(
		false, // isSender (receiver)
		bob.identityKey.Bytes(),
		bob.signedPreKey.Bytes(),
		alice.identityPubKey.ToAffineCompressed(),
		alice.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Bob failed to establish channel: %v", err)
	}
	t.Logf("Bob established double ratchet session")

	// Debug: log the ratchet states
	t.Logf("Alice initial state length: %d", len(aliceState))
	t.Logf("Bob initial state length: %d", len(bobState))

	// Test message encryption/decryption
	testMessage := []byte("Hello, Bob! This is a secret message from Alice.")

	// Alice encrypts
	newAliceState, envelope, err := ch.EncryptTwoPartyMessage(aliceState, testMessage)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}
	t.Logf("Alice encrypted message")
	t.Logf("Alice state after encrypt length: %d", len(newAliceState))
	t.Logf("Envelope: %+v", envelope)
	aliceState = newAliceState

	// Bob decrypts
	newBobState, decrypted, err := ch.DecryptTwoPartyMessage(bobState, envelope)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	t.Logf("Bob state after decrypt length: %d", len(newBobState))
	t.Logf("Decrypted message length: %d", len(decrypted))

	// Check if decryption actually worked
	if len(newBobState) == 0 {
		t.Logf("WARNING: Bob's new ratchet state is empty - decryption likely failed silently")
	}

	assert.Equal(t, testMessage, decrypted, "Decrypted message should match original")
	t.Logf("Bob decrypted message successfully: %s", string(decrypted))
	bobState = newBobState

	// Test reverse direction: Bob sends to Alice
	replyMessage := []byte("Hi Alice! Got your message.")

	bobState, envelope2, err := ch.EncryptTwoPartyMessage(bobState, replyMessage)
	if err != nil {
		t.Fatalf("Bob failed to encrypt reply: %v", err)
	}

	aliceState, decrypted2, err := ch.DecryptTwoPartyMessage(aliceState, envelope2)
	if err != nil {
		t.Fatalf("Alice failed to decrypt reply: %v", err)
	}

	assert.Equal(t, replyMessage, decrypted2, "Decrypted reply should match original")
	t.Logf("Alice decrypted reply successfully: %s", string(decrypted2))

	// Suppress unused variable warnings
	_ = aliceState
	_ = bobState
}

// TestReceiverSendsFirst tests that the X3DH "receiver" CANNOT send first
// This confirms that Signal protocol requires sender to send first.
// The test is expected to fail - documenting the protocol limitation.
func TestReceiverSendsFirst(t *testing.T) {
	t.Skip("Expected to fail - Signal protocol requires sender to send first")

	alice := generatePeer()
	bob := generatePeer()

	ch := channel.NewDoubleRatchetEncryptedChannel()

	// Alice establishes as sender
	aliceState, err := ch.EstablishTwoPartyChannel(
		true,
		alice.identityKey.Bytes(),
		alice.signedPreKey.Bytes(),
		bob.identityPubKey.ToAffineCompressed(),
		bob.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Alice failed to establish: %v", err)
	}

	// Bob establishes as receiver
	bobState, err := ch.EstablishTwoPartyChannel(
		false,
		bob.identityKey.Bytes(),
		bob.signedPreKey.Bytes(),
		alice.identityPubKey.ToAffineCompressed(),
		alice.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Bob failed to establish: %v", err)
	}

	// BOB SENDS FIRST (he's the X3DH receiver but sends first) - THIS WILL FAIL
	bobMessage := []byte("Hello Alice! I'm the receiver but I'm sending first.")
	bobState, envelope, err := ch.EncryptTwoPartyMessage(bobState, bobMessage)
	if err != nil {
		t.Fatalf("Bob (receiver) failed to encrypt first message: %v", err)
	}
	t.Logf("Bob (X3DH receiver) encrypted first message successfully")

	// Alice decrypts - THIS FAILS because receiver can't send first
	aliceState, decrypted, err := ch.DecryptTwoPartyMessage(aliceState, envelope)
	if err != nil {
		t.Fatalf("Alice failed to decrypt Bob's first message: %v", err)
	}
	assert.Equal(t, bobMessage, decrypted)
	t.Logf("Alice decrypted Bob's first message: %s", string(decrypted))

	_ = aliceState
	_ = bobState
}

// TestHandshakePattern tests the correct handshake pattern:
// Sender (Alice) sends hello first, then receiver (Bob) can send.
func TestHandshakePattern(t *testing.T) {
	alice := generatePeer()
	bob := generatePeer()

	ch := channel.NewDoubleRatchetEncryptedChannel()

	// Alice establishes as sender
	aliceState, err := ch.EstablishTwoPartyChannel(
		true,
		alice.identityKey.Bytes(),
		alice.signedPreKey.Bytes(),
		bob.identityPubKey.ToAffineCompressed(),
		bob.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Alice failed to establish: %v", err)
	}

	// Bob establishes as receiver
	bobState, err := ch.EstablishTwoPartyChannel(
		false,
		bob.identityKey.Bytes(),
		bob.signedPreKey.Bytes(),
		alice.identityPubKey.ToAffineCompressed(),
		alice.signedPrePubKey.ToAffineCompressed(),
	)
	if err != nil {
		t.Fatalf("Bob failed to establish: %v", err)
	}

	// Step 1: Alice (sender) sends hello first
	helloMsg := []byte("hello")
	aliceState, helloEnvelope, err := ch.EncryptTwoPartyMessage(aliceState, helloMsg)
	if err != nil {
		t.Fatalf("Alice failed to encrypt hello: %v", err)
	}
	t.Logf("Alice sent hello")

	// Step 2: Bob receives hello
	bobState, decryptedHello, err := ch.DecryptTwoPartyMessage(bobState, helloEnvelope)
	if err != nil {
		t.Fatalf("Bob failed to decrypt hello: %v", err)
	}
	assert.Equal(t, helloMsg, decryptedHello)
	t.Logf("Bob received hello: %s", string(decryptedHello))

	// Step 3: Bob sends ack (now Bob can send after receiving)
	ackMsg := []byte("ack")
	bobState, ackEnvelope, err := ch.EncryptTwoPartyMessage(bobState, ackMsg)
	if err != nil {
		t.Fatalf("Bob failed to encrypt ack: %v", err)
	}
	t.Logf("Bob sent ack")

	// Step 4: Alice receives ack
	aliceState, decryptedAck, err := ch.DecryptTwoPartyMessage(aliceState, ackEnvelope)
	if err != nil {
		t.Fatalf("Alice failed to decrypt ack: %v", err)
	}
	assert.Equal(t, ackMsg, decryptedAck)
	t.Logf("Alice received ack: %s", string(decryptedAck))

	// Now both parties can send freely
	// Bob sends a real message
	bobMessage := []byte("Now I can send real messages!")
	bobState, bobEnvelope, err := ch.EncryptTwoPartyMessage(bobState, bobMessage)
	if err != nil {
		t.Fatalf("Bob failed to encrypt message: %v", err)
	}

	aliceState, decryptedBob, err := ch.DecryptTwoPartyMessage(aliceState, bobEnvelope)
	if err != nil {
		t.Fatalf("Alice failed to decrypt Bob's message: %v", err)
	}
	assert.Equal(t, bobMessage, decryptedBob)
	t.Logf("Alice received Bob's message: %s", string(decryptedBob))

	// Alice sends a real message
	aliceMessage := []byte("And I can keep sending too!")
	aliceState, aliceEnvelope, err := ch.EncryptTwoPartyMessage(aliceState, aliceMessage)
	if err != nil {
		t.Fatalf("Alice failed to encrypt message: %v", err)
	}

	bobState, decryptedAlice, err := ch.DecryptTwoPartyMessage(bobState, aliceEnvelope)
	if err != nil {
		t.Fatalf("Bob failed to decrypt Alice's message: %v", err)
	}
	assert.Equal(t, aliceMessage, decryptedAlice)
	t.Logf("Bob received Alice's message: %s", string(decryptedAlice))

	_ = aliceState
	_ = bobState
}

func TestChannel(t *testing.T) {
	peers := []*peer{}
	for i := 0; i < 4; i++ {
		peers = append(peers, generatePeer())
	}

	sort.Slice(peers, func(i, j int) bool {
		return bytes.Compare(peers[i].pubKey.ToAffineCompressed(), peers[j].pubKey.ToAffineCompressed()) <= 0
	})

	trs := map[string]*generated.TripleRatchetStateAndMetadata{}

	peerids := [][]byte{}
	outs := map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		outs[peers[i].pubKeyB64] = make(map[string]string)
		peerids = append(peerids,
			append(
				append(
					append([]byte{}, peers[i].pubKey.ToAffineCompressed()...),
					peers[i].identityPubKey.ToAffineCompressed()...,
				),
				peers[i].signedPrePubKey.ToAffineCompressed()...,
			),
		)
	}

	for i := 0; i < 4; i++ {
		otherPeerIds := [][]byte{}
		for j := 0; j < 4; j++ {
			if i != j {
				otherPeerIds = append(otherPeerIds, peerids[j])
			}
		}

		tr := channel.NewTripleRatchet(
			otherPeerIds,
			peers[i].privKey.Bytes(),
			peers[i].identityKey.Bytes(),
			peers[i].signedPreKey.Bytes(),
			2,
			true,
		)
		trs[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = trs[peers[i].pubKeyB64].Metadata
	}

	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 1
	next := map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound1(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k, _ := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 2
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound2(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 3
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound3(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 4
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound4(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	for i := 0; i < 4; i++ {
		send := channel.TripleRatchetEncrypt(
			generated.TripleRatchetStateAndMessage{
				RatchetState: trs[peers[i].pubKeyB64].RatchetState,
				Message:      []byte(fmt.Sprintf("hi-%d", i)),
			},
		)
		trs[peers[i].pubKeyB64].RatchetState = send.RatchetState
		for j := 0; j < 4; j++ {
			if i != j {
				msg := channel.TripleRatchetDecrypt(
					generated.TripleRatchetStateAndEnvelope{
						RatchetState: trs[peers[j].pubKeyB64].RatchetState,
						Envelope:     send.Envelope,
					},
				)
				trs[peers[j].pubKeyB64].RatchetState = msg.RatchetState
				if !bytes.Equal(msg.Message, []byte(fmt.Sprintf("hi-%d", i))) {
					assert.FailNow(t, "mismatch messages")
				}
			}
		}
	}
}
