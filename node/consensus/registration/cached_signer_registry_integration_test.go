//go:build integrationtest
// +build integrationtest

package registration

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

func setupTestKeyStore(t *testing.T) *store.PebbleKeyStore {
	logger, _ := zap.NewDevelopment()
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	return store.NewPebbleKeyStore(tempDB, logger)
}

// Helper functions for generating real keys using concrete constructors

func generateRealIdentityKey(t *testing.T) (*protobufs.Ed448PublicKey, ed448.PrivateKey) {
	_, priv, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey := priv.Public().(ed448.PublicKey)
	return &protobufs.Ed448PublicKey{
		KeyValue: []byte(pubKey),
	}, priv
}

func generateRealProvingKey(t *testing.T, bc *bls48581.Bls48581KeyConstructor) (crypto.Signer, []byte) {
	// Generate a real BLS key with proof of possession
	privKey, pop, err := bc.New()
	require.NoError(t, err)

	return privKey, pop
}

func generateRealSignedX448Key(t *testing.T, signerPrivKey ed448.PrivateKey, purpose string) *protobufs.SignedX448Key {
	// Generate X448 key
	x448KeyBytes := make([]byte, 57)
	_, err := rand.Read(x448KeyBytes)
	require.NoError(t, err)

	x448Key := &protobufs.X448PublicKey{
		KeyValue: x448KeyBytes,
	}

	// Get signer public key
	signerPubKey := signerPrivKey.Public().(ed448.PublicKey)

	// Calculate parent key address
	addressBI, err := poseidon.HashBytes([]byte(signerPubKey))
	require.NoError(t, err)
	parentKeyAddress := addressBI.FillBytes(make([]byte, 32))

	// Sign the X448 key
	signature := ed448.Sign(signerPrivKey, x448KeyBytes, "KEY_REGISTRY")

	return &protobufs.SignedX448Key{
		Key:              x448Key,
		ParentKeyAddress: parentKeyAddress,
		Signature: &protobufs.SignedX448Key_Ed448Signature{
			Ed448Signature: &protobufs.Ed448Signature{
				Signature: signature,
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: []byte(signerPubKey),
				},
			},
		},
		CreatedAt:  1234567890,
		ExpiresAt:  0,
		KeyPurpose: purpose,
	}
}

// TestLoadExistingKeys tests loading keys from an existing store
func TestLoadExistingKeys(t *testing.T) {
	logger := zap.NewNop()
	keyStore := setupTestKeyStore(t)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bp := &bulletproofs.Decaf448BulletproofProver{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	// First populate the store with some test data
	txn, err := keyStore.NewTransaction()
	require.NoError(t, err)

	// Generate real keys for testing
	numKeys := 3
	var testProvingKeys []crypto.Signer
	var testIdentityKeys []*protobufs.Ed448PublicKey
	var testPrivKeys []ed448.PrivateKey
	var testPopSigs [][]byte

	for i := 0; i < numKeys; i++ {
		// Generate real identity key
		identityKey, privKey := generateRealIdentityKey(t)
		testIdentityKeys = append(testIdentityKeys, identityKey)
		testPrivKeys = append(testPrivKeys, privKey)

		// Generate real proving key
		provingKey, popsig := generateRealProvingKey(t, bc)
		testProvingKeys = append(testProvingKeys, provingKey)
		testPopSigs = append(testPopSigs, popsig)
	}

	// Store the keys
	for i, provingKey := range testProvingKeys {
		provingKeyAddressBI, _ := poseidon.HashBytes(provingKey.Public().([]byte))
		provingKeyAddress := provingKeyAddressBI.FillBytes(make([]byte, 32))

		identityKeyAddressBI, _ := poseidon.HashBytes(testIdentityKeys[i].KeyValue)
		identityKeyAddress := identityKeyAddressBI.FillBytes(make([]byte, 32))

		// Store proving key
		err := keyStore.PutProvingKey(txn, provingKeyAddress, &protobufs.BLS48581SignatureWithProofOfPossession{
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: provingKey.Public().([]byte),
			},
			PopSignature: testPopSigs[i],
			Signature:    testPopSigs[i],
		})
		require.NoError(t, err)

		// Store identity key
		err = keyStore.PutIdentityKey(txn, identityKeyAddress, testIdentityKeys[i])
		require.NoError(t, err)

		identitySig := generateTestEd448Signature(testPrivKeys[i], provingKey.Public().([]byte), []byte("KEY_REGISTRY"))
		provingSig, err := provingKey.SignWithDomain(testIdentityKeys[i].KeyValue, []byte("KEY_REGISTRY"))
		require.NoError(t, err)
		// Store cross signatures
		err = keyStore.PutCrossSignature(
			txn,
			identityKeyAddress,
			provingKeyAddress,
			identitySig,
			provingSig,
		)
		require.NoError(t, err)

		// Store a signed key using the real identity private key
		signedKey := generateRealSignedX448Key(t, testPrivKeys[i], "inbox")

		signedKeyAddressBI, _ := poseidon.HashBytes(signedKey.Key.KeyValue)
		signedKeyAddress := signedKeyAddressBI.FillBytes(make([]byte, 32))

		err = keyStore.PutSignedKey(txn, signedKeyAddress, signedKey)
		require.NoError(t, err)
	}

	err = txn.Commit()
	require.NoError(t, err)

	// Create the registry - it should load existing keys
	registry, err := NewCachedSignerRegistry(keyStore, keyManager, bc, bp, logger)
	require.NoError(t, err)
	assert.NotNil(t, registry)
	assert.Equal(t, len(testProvingKeys), registry.GetSignerCount())
}

// TestFullWorkflow tests the complete workflow of the registry
func TestFullWorkflow(t *testing.T) {
	logger := zap.NewNop()
	keyStore := setupTestKeyStore(t)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bp := &bulletproofs.Decaf448BulletproofProver{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, bc, bp, logger)
	require.NoError(t, err)

	// Start a transaction
	txn, err := keyStore.NewTransaction()
	require.NoError(t, err)

	// Step 1: Put an identity key
	identityKey, identityPrivKey := generateRealIdentityKey(t)
	identityKeyAddressBI, _ := poseidon.HashBytes(identityKey.KeyValue)
	identityKeyAddress := identityKeyAddressBI.FillBytes(make([]byte, 32))

	err = registry.PutIdentityKey(txn, identityKeyAddress, identityKey)
	require.NoError(t, err)

	// Step 2: Put a proving key
	provingKey, popSig := generateRealProvingKey(t, bc)
	provingKeyAddressBI, _ := poseidon.HashBytes(provingKey.Public().([]byte))
	provingKeyAddress := provingKeyAddressBI.FillBytes(make([]byte, 32))

	err = registry.PutProvingKey(txn, provingKeyAddress, &protobufs.BLS48581SignatureWithProofOfPossession{
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: provingKey.Public().([]byte),
		},
		Signature:    popSig,
		PopSignature: popSig,
	})
	require.NoError(t, err)

	// Step 3: Put cross signatures
	identitySig := generateTestEd448Signature(identityPrivKey, provingKey.Public().([]byte), []byte("KEY_REGISTRY"))
	provingSig, err := provingKey.SignWithDomain(identityKey.KeyValue, []byte("KEY_REGISTRY"))
	require.NoError(t, err)

	err = registry.PutCrossSignature(txn, identityKeyAddress, provingKeyAddress, identitySig, provingSig)
	require.NoError(t, err)

	// Step 4: Put a signed key
	signedKey := generateRealSignedX448Key(t, identityPrivKey, "inbox")
	signedKeyAddressBI, _ := poseidon.HashBytes(signedKey.Key.KeyValue)
	signedKeyAddress := signedKeyAddressBI.FillBytes(make([]byte, 32))

	err = keyStore.PutSignedKey(txn, signedKeyAddress, signedKey)
	require.NoError(t, err)

	// Commit the transaction
	err = txn.Commit()
	require.NoError(t, err)

	// Step 5: Get the key registry
	result, err := registry.GetKeyRegistry(identityKeyAddress)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, identityKey.KeyValue, result.IdentityKey.KeyValue)
	assert.Equal(t, provingKey.Public().([]byte), result.ProverKey.KeyValue)
	assert.Len(t, result.KeysByPurpose, 1)
	assert.Contains(t, result.KeysByPurpose, "inbox")
}

// TestValidationIntegration tests the validation flow
func TestValidationIntegration(t *testing.T) {
	logger := zap.NewNop()
	keyStore := setupTestKeyStore(t)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bp := &bulletproofs.Decaf448BulletproofProver{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, bc, bp, logger)
	require.NoError(t, err)

	t.Run("Invalid proving key rejected", func(t *testing.T) {
		// Create an invalid proving key (nil)
		err := registry.ValidateProvingKey(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate proving key")
	})

	t.Run("Invalid proving key signature rejected", func(t *testing.T) {
		// Create a proving key with invalid proof of possession
		// We'll create one with random bytes that won't pass BLS verification
		provingKey := &protobufs.BLS48581SignatureWithProofOfPossession{
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: make([]byte, 585), // Random bytes
			},
			Signature:    make([]byte, 74), // Random bytes
			PopSignature: make([]byte, 74), // Random bytes
		}
		rand.Read(provingKey.PublicKey.KeyValue)
		rand.Read(provingKey.Signature)
		rand.Read(provingKey.PopSignature)

		txn, err := keyStore.NewTransaction()
		require.NoError(t, err)

		address := generateTestAddress()
		err = registry.PutProvingKey(txn, address, provingKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature")

		_ = txn.Abort()
	})

	t.Run("Invalid signed key rejected", func(t *testing.T) {
		// Create a signed key with mismatched parent key address
		// Generate a random ed448 key pair
		_, randomPrivKey, err := ed448.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Create a signed key with this key
		signedKey := generateRealSignedX448Key(t, randomPrivKey, "device")

		// But set a different parent key address that doesn't match
		randomAddress := generateTestAddress()
		signedKey.ParentKeyAddress = randomAddress

		err = registry.ValidateSignedKey(signedKey)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate signed key")
	})
}

// TestCacheManagement tests cache management operations
func TestCacheManagement(t *testing.T) {
	logger := zap.NewNop()
	keyStore := setupTestKeyStore(t)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bp := &bulletproofs.Decaf448BulletproofProver{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	registry, err := NewCachedSignerRegistry(keyStore, keyManager, bc, bp, logger)
	require.NoError(t, err)

	// Initially empty
	assert.Equal(t, 0, registry.GetSignerCount())

	// Clear cache (should be no-op when empty)
	registry.ClearCache()
	assert.Equal(t, 0, registry.GetSignerCount())

	// Get all signers when empty
	signers := registry.GetAllSigners()
	assert.Len(t, signers, 0)
}

// BenchmarkCachedSignerRegistry benchmarks various operations
func BenchmarkCachedSignerRegistry(b *testing.B) {
	logger := zap.NewNop()
	tempDB := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	keyStore := store.NewPebbleKeyStore(tempDB, logger)
	bc := &bls48581.Bls48581KeyConstructor{}
	dc := &bulletproofs.Decaf448KeyConstructor{}
	bp := &bulletproofs.Decaf448BulletproofProver{}
	keyManager := keys.NewInMemoryKeyManager(bc, dc)

	registry, _ := NewCachedSignerRegistry(keyStore, keyManager, bc, bp, logger)

	b.Run("GetSignerCount", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = registry.GetSignerCount()
		}
	})

	b.Run("GetAllSigners", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = registry.GetAllSigners()
		}
	})
}
