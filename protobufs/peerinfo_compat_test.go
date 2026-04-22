package protobufs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
)

func TestRustPeerInfoCompat(t *testing.T) {
	// Step 1: Produce a Go PeerInfo and hexdump it
	goPeerInfo := &PeerInfo{
		PeerId:      []byte{0x12, 0x20, 0xAA, 0xBB},
		Timestamp:   1700000000000, // milliseconds
		Version:     []byte{2, 1, 0},
		PatchNumber: []byte{23},
		PublicKey:   []byte{0xCC, 0xDD}, // dummy
		Signature:   []byte{0xEE, 0xFF}, // dummy
	}

	goBytes, err := goPeerInfo.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Go PeerInfo hex (%d bytes): %s\n", len(goBytes), hex.EncodeToString(goBytes))

	// Step 2: Try to decode it back
	goDecoded := &PeerInfo{}
	if err := goDecoded.FromCanonicalBytes(goBytes); err != nil {
		t.Fatalf("Go roundtrip failed: %v", err)
	}
	fmt.Printf("Go roundtrip OK: peer_id=%s ts=%d version=%v patch=%v\n",
		hex.EncodeToString(goDecoded.PeerId),
		goDecoded.Timestamp,
		goDecoded.Version,
		goDecoded.PatchNumber)

	// Step 3: Also produce a KeyRegistry and hexdump it
	goKR := &KeyRegistry{
		IdentityKey:      &Ed448PublicKey{KeyValue: make([]byte, 57)},
		ProverKey:        &BLS48581G2PublicKey{KeyValue: make([]byte, 585)},
		IdentityToProver: &Ed448Signature{Signature: make([]byte, 114)},
		ProverToIdentity: &BLS48581Signature{Signature: make([]byte, 74)},
		LastUpdated:      1700000000000,
	}
	krBytes, err := goKR.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Go KeyRegistry hex (%d bytes): %s\n", len(krBytes), hex.EncodeToString(krBytes))
}

// TestEd448SigningCompat generates an Ed448 keypair from a fixed 57-byte seed,
// signs a PeerInfo the exact same way the Go node does, and prints all
// intermediate values so Rust can reproduce byte-for-byte.
func TestEd448SigningCompat(t *testing.T) {
	// Fixed seed — 57 bytes. Rust test will use the same seed.
	seed := make([]byte, 57)
	for i := range seed {
		seed[i] = byte(i + 1) // 0x01, 0x02, ..., 0x39
	}
	fmt.Printf("seed (%d bytes): %s\n", len(seed), hex.EncodeToString(seed))

	// Derive Ed448 keypair from seed (same as circl's ed448.NewKeyFromSeed)
	privKey := ed448.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed448.PublicKey)
	fmt.Printf("Ed448 pubkey (%d bytes): %s\n", len(pubKey), hex.EncodeToString(pubKey))
	fmt.Printf("Ed448 privkey (%d bytes): %s\n", len(privKey), hex.EncodeToString(privKey))

	// Build a PeerInfo exactly like the Rust node does:
	info := &PeerInfo{
		PeerId:      []byte{0x12, 0x20, 0xAA, 0xBB},
		Timestamp:   1700000000000,
		Version:     []byte{2, 1, 0},
		PatchNumber: []byte{23},
		PublicKey:   []byte(pubKey),
		Capabilities: []*Capability{
			{ProtocolIdentifier: 0x00010001},
		},
	}

	// Step 1: encode with pubkey but nil signature (for signing)
	info.Signature = nil
	msgToSign, err := info.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("msg_to_sign (%d bytes): %s\n", len(msgToSign), hex.EncodeToString(msgToSign))

	// Step 2: sign with Ed448 (context = "" — same as go-libp2p's ed448.go:82)
	sig := ed448.Sign(privKey, msgToSign, "")
	fmt.Printf("signature (%d bytes): %s\n", len(sig), hex.EncodeToString(sig))

	// Step 3: re-encode with signature
	info.Signature = sig
	signedBytes, err := info.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("signed_peer_info (%d bytes): %s\n", len(signedBytes), hex.EncodeToString(signedBytes))

	// Step 4: verify — simulate validatePeerInfoSignature
	infoCopy := &PeerInfo{
		PeerId:       info.PeerId,
		Reachability: info.Reachability,
		Timestamp:    info.Timestamp,
		Version:      info.Version,
		PatchNumber:  info.PatchNumber,
		Capabilities: info.Capabilities,
		PublicKey:    info.PublicKey,
		// Signature is nil (excluded)
	}
	verifyMsg, err := infoCopy.ToCanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("verify_msg (%d bytes): %s\n", len(verifyMsg), hex.EncodeToString(verifyMsg))
	fmt.Printf("verify_msg == msg_to_sign: %v\n",
		hex.EncodeToString(verifyMsg) == hex.EncodeToString(msgToSign))

	ok := ed448.Verify(pubKey, verifyMsg, sig, "")
	fmt.Printf("Go signature verification: %v\n", ok)
	if !ok {
		t.Fatal("Go failed to verify its own signature!")
	}

	// Also verify through go-libp2p's crypto interface
	libp2pPub, err := crypto.UnmarshalEd448PublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	libp2pOk, err := libp2pPub.Verify(verifyMsg, sig)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("libp2p verification: %v\n", libp2pOk)

	// Ensure random key generation also works
	_, _, err = crypto.GenerateEd448Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
}
