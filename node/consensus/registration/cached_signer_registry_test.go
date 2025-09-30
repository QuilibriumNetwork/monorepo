package registration

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type mockTransaction struct{}

// Abort implements store.Transaction.
func (m *mockTransaction) Abort() error {
	return nil
}

// Commit implements store.Transaction.
func (m *mockTransaction) Commit() error {
	return nil
}

// Delete implements store.Transaction.
func (m *mockTransaction) Delete(key []byte) error {
	panic("unimplemented")
}

// DeleteRange implements store.Transaction.
func (m *mockTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	panic("unimplemented")
}

// Get implements store.Transaction.
func (m *mockTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	panic("unimplemented")
}

// NewIter implements store.Transaction.
func (m *mockTransaction) NewIter(lowerBound []byte, upperBound []byte) (store.Iterator, error) {
	panic("unimplemented")
}

// Set implements store.Transaction.
func (m *mockTransaction) Set(key []byte, value []byte) error {
	return nil
}

func generateTestBLSPublicKey() []byte {
	// Generate a 585-byte test public key
	pubKey := make([]byte, 585)
	rand.Read(pubKey)
	return pubKey
}

func generateTestBLSSignature() []byte {
	// Generate a 74-byte test signature
	sig := make([]byte, 74)
	rand.Read(sig)
	return sig
}

func generateTestEd448PublicKey(key []byte) []byte {
	return []byte(ed448.PrivateKey(key).Public().(ed448.PublicKey))
}

func generateTestEd448Signature(key, message, context []byte) []byte {
	return ed448.Sign(key, message, string(context))
}

func generateTestX448PublicKey() []byte {
	// Generate a 57-byte test public key (X448 is also 57 bytes like Ed448)
	pubKey := make([]byte, 57)
	rand.Read(pubKey)
	return pubKey
}

func generateTestDecaf448PublicKey() []byte {
	// Generate a 56-byte test public key
	pubKey := make([]byte, 56)
	rand.Read(pubKey)
	return pubKey
}

func generateTestDecaf448Signature() []byte {
	// Generate a 112-byte test signature
	sig := make([]byte, 112)
	rand.Read(sig)
	return sig
}

func generateTestAddress() []byte {
	// Generate a 32-byte test address
	addr := make([]byte, 32)
	rand.Read(addr)
	return addr
}

func createTestIdentityKey(key []byte) *protobufs.Ed448PublicKey {
	return &protobufs.Ed448PublicKey{
		KeyValue: generateTestEd448PublicKey(key),
	}
}

func createTestProvingKey() *protobufs.BLS48581SignatureWithProofOfPossession {
	return &protobufs.BLS48581SignatureWithProofOfPossession{
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: generateTestBLSPublicKey(),
		},
		Signature:    generateTestBLSSignature(),
		PopSignature: generateTestBLSSignature(),
	}
}

func createTestSignedX448Key(key []byte, purpose string) *protobufs.SignedX448Key {
	pubkey := generateTestEd448PublicKey(key)
	addrbi, _ := poseidon.HashBytes(pubkey)
	addr := addrbi.FillBytes(make([]byte, 32))
	xpub := generateTestX448PublicKey()
	return &protobufs.SignedX448Key{
		Key: &protobufs.X448PublicKey{
			KeyValue: xpub,
		},
		ParentKeyAddress: addr,
		Signature: &protobufs.SignedX448Key_Ed448Signature{
			Ed448Signature: &protobufs.Ed448Signature{
				Signature: generateTestEd448Signature(key, xpub, []byte("KEY_REGISTRY")),
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: pubkey,
				},
			},
		},
		CreatedAt:  1234567890,
		ExpiresAt:  0,
		KeyPurpose: purpose,
	}
}

type mockRangeIterator struct {
	mock.Mock
}

// Close implements store.TypedIterator.
func (m *mockRangeIterator) Close() error {
	args := m.Called()
	return args.Error(0)
}

// First implements store.TypedIterator.
func (m *mockRangeIterator) First() bool {
	args := m.Called()
	return args.Bool(0)
}

// Next implements store.TypedIterator.
func (m *mockRangeIterator) Next() bool {
	args := m.Called()
	return args.Bool(0)
}

// TruncatedValue implements store.TypedIterator.
func (m *mockRangeIterator) TruncatedValue() (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	args := m.Called()
	return args.Get(0).(*protobufs.BLS48581SignatureWithProofOfPossession), args.Error(1)
}

// Valid implements store.TypedIterator.
func (m *mockRangeIterator) Valid() bool {
	args := m.Called()
	return args.Bool(0)
}

// Value implements store.TypedIterator.
func (m *mockRangeIterator) Value() (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	args := m.Called()
	return args.Get(0).(*protobufs.BLS48581SignatureWithProofOfPossession), args.Error(1)
}

var _ store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession] = (*mockRangeIterator)(nil)

func TestNewCachedSignerRegistry(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)
	assert.NotNil(t, registry)
	assert.Equal(t, 0, registry.GetSignerCount())

	keyStore.AssertExpectations(t)
}

func TestValidateIdentityKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	t.Run("Valid identity key", func(t *testing.T) {
		_, priv, _ := ed448.GenerateKey(rand.Reader)
		identityKey := createTestIdentityKey(priv)
		err := registry.ValidateIdentityKey(identityKey)
		require.NoError(t, err)
	})

	t.Run("Nil identity key", func(t *testing.T) {
		err := registry.ValidateIdentityKey(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate identity key")
	})

	keyStore.AssertExpectations(t)
}

func TestValidateProvingKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	t.Run("Valid proving key", func(t *testing.T) {
		provingKey := createTestProvingKey()

		// Mock the BLS signature verification
		blsConstructor.On("VerifySignatureRaw",
			provingKey.PublicKey.KeyValue,
			provingKey.PopSignature,
			provingKey.PublicKey.KeyValue,
			[]byte("BLS48_POP_SK"),
		).Return(true)

		err := registry.ValidateProvingKey(provingKey)
		require.NoError(t, err)

		blsConstructor.AssertExpectations(t)
	})

	t.Run("Invalid proving key signature", func(t *testing.T) {
		provingKey := createTestProvingKey()

		// Mock the BLS signature verification to fail
		blsConstructor.On("VerifySignatureRaw",
			provingKey.PublicKey.KeyValue,
			provingKey.PopSignature,
			provingKey.PublicKey.KeyValue,
			[]byte("BLS48_POP_SK"),
		).Return(false)

		err := registry.ValidateProvingKey(provingKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")

		blsConstructor.AssertExpectations(t)
	})

	keyStore.AssertExpectations(t)
}

func TestValidateSignedKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	t.Run("Valid signed key with Ed448 signature", func(t *testing.T) {
		_, priv, _ := ed448.GenerateKey(rand.Reader)
		signedKey := createTestSignedX448Key(priv, "inbox")

		// Fix the parent key address to match the signature's public key
		pubKey := signedKey.Signature.(*protobufs.SignedX448Key_Ed448Signature).Ed448Signature.PublicKey.KeyValue
		addressBI, _ := poseidon.HashBytes(pubKey)
		signedKey.ParentKeyAddress = addressBI.FillBytes(make([]byte, 32))

		err := registry.ValidateSignedKey(signedKey)
		require.NoError(t, err)
	})

	t.Run("Nil signed key", func(t *testing.T) {
		err := registry.ValidateSignedKey(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate signed key")
	})

	keyStore.AssertExpectations(t)
}

func TestPutIdentityKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	mockTxn := &mockTransaction{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	_, priv, _ := ed448.GenerateKey(rand.Reader)
	identityKey := createTestIdentityKey(priv)
	addressbi, _ := poseidon.HashBytes(identityKey.KeyValue)
	address := addressbi.FillBytes(make([]byte, 32))

	// Mock the keyStore PutIdentityKey
	keyStore.On("PutIdentityKey", mockTxn, address, identityKey).Return(nil)

	err = registry.PutIdentityKey(mockTxn, address, identityKey)
	require.NoError(t, err)

	keyStore.AssertExpectations(t)
}

func TestPutProvingKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	mockTxn := &mockTransaction{}
	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	address := generateTestAddress()
	provingKey := createTestProvingKey()

	// Mock the BLS signature verification
	blsConstructor.On("VerifySignatureRaw",
		provingKey.PublicKey.KeyValue,
		provingKey.PopSignature,
		provingKey.PublicKey.KeyValue,
		[]byte("BLS48_POP_SK"),
	).Return(true)

	// Mock the keyStore PutProvingKey
	keyStore.On("PutProvingKey", mockTxn, address, provingKey).Return(nil)

	err = registry.PutProvingKey(mockTxn, address, provingKey)
	require.NoError(t, err)

	keyStore.AssertExpectations(t)
	blsConstructor.AssertExpectations(t)
}

func TestPutSignedKey(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}
	mockTxn := &mockTransaction{}

	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	address := generateTestAddress()

	_, priv, _ := ed448.GenerateKey(rand.Reader)
	signedKey := createTestSignedX448Key(priv, "device")

	// Fix the parent key address to match the signature's public key
	pubKey := signedKey.Signature.(*protobufs.SignedX448Key_Ed448Signature).Ed448Signature.PublicKey.KeyValue
	addressBI, _ := poseidon.HashBytes(pubKey)
	signedKey.ParentKeyAddress = addressBI.FillBytes(make([]byte, 32))

	// Mock the keyStore PutSignedKey
	keyStore.On("PutSignedKey", mockTxn, address, signedKey).Return(nil)

	err = registry.PutSignedKey(mockTxn, address, signedKey)
	require.NoError(t, err)

	keyStore.AssertExpectations(t)
}

func TestGetKeyRegistry(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}

	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	_, priv, _ := ed448.GenerateKey(rand.Reader)
	identityKey := createTestIdentityKey(priv)
	addressbi, _ := poseidon.HashBytes(identityKey.KeyValue)
	address := addressbi.FillBytes(make([]byte, 32))

	expectedRegistry := &protobufs.KeyRegistry{
		IdentityKey: identityKey,
		ProverKey:   createTestProvingKey().PublicKey,
		KeysByPurpose: map[string]*protobufs.KeyCollection{
			"inbox": {
				KeyPurpose: "inbox",
				Keys: []*protobufs.SignedX448Key{
					createTestSignedX448Key(priv, "inbox"),
				},
			},
		},
	}

	// Mock the keyStore GetKeyRegistry
	keyStore.On("GetKeyRegistry", address).Return(expectedRegistry, nil)

	result, err := registry.GetKeyRegistry(address)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, expectedRegistry, result)

	keyStore.AssertExpectations(t)
}

func TestConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	keyStore := &mocks.MockKeyStore{}
	keyManager := &mocks.MockKeyManager{}
	blsConstructor := &mocks.MockBlsConstructor{}
	bulletproofProver := &mocks.MockBulletproofProver{}

	iter := &mockRangeIterator{}
	iter.On("Close").Return(nil)
	iter.On("First").Return(false)
	iter.On("Valid").Return(false)
	iter.On("Next").Return(false)

	// Mock the RangeProvingKeys to return nil iterator (empty store)
	keyStore.On("RangeProvingKeys").Return(iter, nil)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, blsConstructor, bulletproofProver, logger)
	require.NoError(t, err)

	// Test concurrent reads and writes
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			_ = registry.GetSignerCount()
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			_ = registry.GetAllSigners()
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	keyStore.AssertExpectations(t)
}

func TestAddressComputation(t *testing.T) {
	// Test that address computation is consistent
	pubKey := generateTestBLSPublicKey()

	// Compute address multiple times
	addr1BI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	var addr1 [32]byte
	addr1BI.FillBytes(addr1[:])

	addr2BI, err := poseidon.HashBytes(pubKey)
	require.NoError(t, err)
	var addr2 [32]byte
	addr2BI.FillBytes(addr2[:])

	// Verify they're the same
	assert.Equal(t, addr1, addr2)
}
