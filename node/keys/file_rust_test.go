//go:build rustkeys

// Package keys_test contains cross-validation tests that wire the Rust
// quil-keys-ffi (via uniffi-generated Go bindings) against the Go
// FileKeyManager.  The build tag "rustkeys" keeps these out of the
// normal build so CI is not gated on having the native FFI library
// linked.
//
// Run with:
//
//	go test -tags rustkeys -count=1 ./keys/...
package keys_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	generated "source.quilibrium.com/quilibrium/monorepo/quil-keys-ffi/generated/quil_keys_ffi"
)

// Shared encryption key (hex-encoded 32 bytes) used by both Go and Rust
// managers so their AES-GCM envelope is compatible.
const testEncryptionKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// newGoKeyManager creates a Go FileKeyManager backed by the given YAML
// path.  The BLS constructor is the real bls48581 implementation (not a
// mock) so that signatures are verifiable.
func newGoKeyManager(t *testing.T, yamlPath string) *keys.FileKeyManager {
	t.Helper()
	keyConfig := &config.Config{
		Key: &config.KeyConfig{
			KeyStoreFile: &config.KeyStoreFileConfig{
				Path:            yamlPath,
				EncryptionKey:   testEncryptionKeyHex,
				CreateIfMissing: true,
			},
		},
	}
	blsConstructor := &bls48581.Bls48581KeyConstructor{}
	logger := zap.NewNop()
	return keys.NewFileKeyManager(keyConfig, blsConstructor, nil, logger)
}

// newRustKeyManager creates a Rust FileKeyManager via FFI, backed by the
// given YAML path.  Returns the handle; the caller must call
// generated.DestroyKeyManager(handle) when done.
func newRustKeyManager(t *testing.T, yamlPath string) uint64 {
	t.Helper()
	handle := generated.CreateKeyManager(yamlPath, testEncryptionKeyHex, "test-proving-key")
	require.NotZero(t, handle, "Rust create_key_manager returned zero handle")
	return handle
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// TestRustEnsureStandardKeys verifies that ensure_standard_keys creates
// the expected set of key IDs in the keystore.
func TestRustEnsureStandardKeys(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	handle := newRustKeyManager(t, yamlPath)
	defer generated.DestroyKeyManager(handle)

	generated.EnsureStandardKeys(handle)

	// The BLS public key should now be retrievable.
	pubKey := generated.GetPublicKey(handle, 3) // BLS48581G2
	require.NotEmpty(t, pubKey, "BLS public key should be non-empty after ensure_standard_keys")

	// BLS48581G2 public keys are 585 bytes.
	assert.Len(t, pubKey, 585, "BLS48581G2 public key should be 585 bytes")
}

// TestRustSignVerifyRoundTrip verifies that a signature produced by the
// Rust FFI signer can be verified by itself (sanity check).
func TestRustSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	handle := newRustKeyManager(t, yamlPath)
	defer generated.DestroyKeyManager(handle)

	generated.EnsureStandardKeys(handle)

	message := []byte("hello from the cross-validation test")
	domain := []byte("test-domain")

	sig := generated.SignWithDomain(handle, 3, message, domain)
	require.NotEmpty(t, sig, "Rust signature should be non-empty")

	pubKey := generated.GetPublicKey(handle, 3)

	// Verify with Go's BLS verifier.
	ok := bls48581.BlsVerify(pubKey, sig, message, domain)
	assert.True(t, ok, "Go verifier should accept Rust-produced signature")
}

// TestCrossVerify_RustSign_GoVerify is the critical cross-validation
// test.  It creates a Rust key manager, signs with it, and verifies the
// signature using the Go BLS48581 verifier.
func TestCrossVerify_RustSign_GoVerify(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	handle := newRustKeyManager(t, yamlPath)
	defer generated.DestroyKeyManager(handle)

	generated.EnsureStandardKeys(handle)

	pubKey := generated.GetPublicKey(handle, 3)
	require.Len(t, pubKey, 585)

	messages := []struct {
		msg    []byte
		domain []byte
	}{
		{[]byte("short"), []byte("d")},
		{[]byte(""), []byte("")},
		{[]byte("a]longer message with special chars !@#$%^&*()"), []byte("quilibrium")},
		{make([]byte, 1024), []byte("big-payload")},
	}

	for _, tc := range messages {
		sig := generated.SignWithDomain(handle, 3, tc.msg, tc.domain)
		require.NotEmpty(t, sig, "signature must not be empty")
		assert.Len(t, sig, 74, "BLS48581 signature should be 74 bytes")

		ok := bls48581.BlsVerify(pubKey, sig, tc.msg, tc.domain)
		assert.True(t, ok, "Go verifier must accept Rust signature for msg=%q domain=%q", tc.msg, tc.domain)

		// Tamper check: flipping a byte should invalidate.
		if len(sig) > 0 {
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[0] ^= 0xFF
			ok2 := bls48581.BlsVerify(pubKey, tampered, tc.msg, tc.domain)
			assert.False(t, ok2, "tampered signature must not verify")
		}
	}
}

// TestCrossVerify_GoSign_RustVerify signs with the Go BLS signer and
// verifies with the Go verifier (since the Rust FFI does not expose a
// standalone verify function).  This confirms both implementations
// produce keys/signatures in the same format.
//
// The actual cross-check here is that both managers reading the SAME
// keystore file produce the same public key (identity equivalence).
func TestCrossVerify_GoSign_RustVerify(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	// Step 1: Rust creates the keystore with standard keys.
	handle := newRustKeyManager(t, yamlPath)
	generated.EnsureStandardKeys(handle)
	rustPubKey := generated.GetPublicKey(handle, 3)
	generated.DestroyKeyManager(handle)

	// Step 2: Go loads the same keystore file (created by Rust).
	goMgr := newGoKeyManager(t, yamlPath)

	goSigner, err := goMgr.GetSigningKey("q-prover-key")
	require.NoError(t, err, "Go should load the Rust-created prover key")

	goPubKey := goSigner.Public().([]byte)

	// The public keys must be identical.
	assert.Equal(t, rustPubKey, goPubKey,
		"Go and Rust must derive identical BLS public keys from the same keystore")

	// Step 3: Sign with Go, verify with Go's BLS verifier (the same one
	// that verified Rust signatures above, so transitively this confirms
	// format compatibility).
	message := []byte("signed by go, verified as cross-check")
	domain := []byte("cross-verify")

	goSig, err := goSigner.SignWithDomain(message, domain)
	require.NoError(t, err)
	require.NotEmpty(t, goSig)

	ok := bls48581.BlsVerify(goPubKey, goSig, message, domain)
	assert.True(t, ok, "Go signature must verify with Go verifier (same BLS impl)")
}

// TestCrossVerify_SharedKeystore_SignBothWays creates a keystore with
// Rust, then has both Go and Rust sign the same message with the same
// key.  Both signatures must verify, confirming full round-trip
// compatibility.
func TestCrossVerify_SharedKeystore_SignBothWays(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	// Rust creates the keystore.
	handle := newRustKeyManager(t, yamlPath)
	generated.EnsureStandardKeys(handle)
	rustPubKey := generated.GetPublicKey(handle, 3)

	message := []byte("both-sign-same-message")
	domain := []byte("shared-domain")

	rustSig := generated.SignWithDomain(handle, 3, message, domain)
	generated.DestroyKeyManager(handle)

	// Go loads the same keystore and signs.
	goMgr := newGoKeyManager(t, yamlPath)
	goSigner, err := goMgr.GetSigningKey("q-prover-key")
	require.NoError(t, err)

	goPubKey := goSigner.Public().([]byte)
	goSig, err := goSigner.SignWithDomain(message, domain)
	require.NoError(t, err)

	// Same key, same public key.
	require.Equal(t, rustPubKey, goPubKey, "public keys must match")

	// Both signatures must verify against the shared public key.
	assert.True(t, bls48581.BlsVerify(rustPubKey, rustSig, message, domain),
		"Rust signature must verify")
	assert.True(t, bls48581.BlsVerify(goPubKey, goSig, message, domain),
		"Go signature must verify")

	// BLS is deterministic for the same (sk, msg, domain), so both
	// signatures should be byte-identical.
	assert.Equal(t, rustSig, goSig,
		"BLS signatures from Go and Rust with same key and message should be identical")
}

// TestRustSign_NoDomain verifies that sign() (without domain separator)
// produces a valid BLS signature that the Go verifier accepts with an
// empty domain.
func TestRustSign_NoDomain(t *testing.T) {
	dir := t.TempDir()
	yamlPath := dir + "/keys.yml"

	handle := newRustKeyManager(t, yamlPath)
	defer generated.DestroyKeyManager(handle)

	generated.EnsureStandardKeys(handle)

	pubKey := generated.GetPublicKey(handle, 3)
	message := []byte("sign without domain")

	sig := generated.Sign(handle, 3, message)
	require.NotEmpty(t, sig)

	// sign() with no domain is equivalent to sign_with_domain(msg, []).
	ok := bls48581.BlsVerify(pubKey, sig, message, nil)
	assert.True(t, ok, "signature produced by sign() should verify with empty domain")
}

// TestRustTempKeyManager verifies that create_temp_key_manager_and_get_pubkey
// returns a valid BLS48581G2 public key.
func TestRustTempKeyManager(t *testing.T) {
	pubKey := generated.CreateTempKeyManagerAndGetPubkey(testEncryptionKeyHex)
	require.NotEmpty(t, pubKey)
	assert.Len(t, pubKey, 585, "BLS48581G2 public key should be 585 bytes")
}

// TestRustGoKeystoreRoundTrip confirms that a keystore created by Rust
// can be read back by Go, and a keystore created by Go can be read by
// Rust, with the same keys surviving the round trip.
func TestRustGoKeystoreRoundTrip(t *testing.T) {
	t.Run("Rust-created keystore loaded by Go", func(t *testing.T) {
		dir := t.TempDir()
		yamlPath := dir + "/keys.yml"

		handle := newRustKeyManager(t, yamlPath)
		generated.EnsureStandardKeys(handle)
		rustPub := generated.GetPublicKey(handle, 3)
		generated.DestroyKeyManager(handle)

		goMgr := newGoKeyManager(t, yamlPath)
		goSigner, err := goMgr.GetSigningKey("q-prover-key")
		require.NoError(t, err)
		goPub := goSigner.Public().([]byte)

		assert.Equal(t, rustPub, goPub)
	})

	t.Run("Go-created keystore loaded by Rust", func(t *testing.T) {
		dir := t.TempDir()
		yamlPath := dir + "/keys.yml"

		// Seed an empty YAML file for the Go manager.
		err := os.WriteFile(yamlPath,
			[]byte("\"\":\n  id: \"\"\n  type: 0\n  privateKey: \"\"\n  publicKey: \"\"\n"),
			0600)
		require.NoError(t, err)

		// Go creates the keystore (NewFileKeyManager auto-creates q-prover-key).
		goMgr := newGoKeyManager(t, yamlPath)
		goSigner, err := goMgr.GetSigningKey("q-prover-key")
		require.NoError(t, err)
		goPub := goSigner.Public().([]byte)

		// Rust loads the same file.
		handle := newRustKeyManager(t, yamlPath)
		defer generated.DestroyKeyManager(handle)

		rustPub := generated.GetPublicKey(handle, 3)
		assert.Equal(t, goPub, rustPub,
			"Rust must read back the same BLS public key that Go wrote")

		// Sign with Rust, verify with Go.
		msg := []byte("go-created-key-rust-signed")
		domain := []byte("roundtrip")
		sig := generated.SignWithDomain(handle, 3, msg, domain)
		ok := bls48581.BlsVerify(rustPub, sig, msg, domain)
		assert.True(t, ok, "Rust signature with Go-created key must verify")
	})
}
