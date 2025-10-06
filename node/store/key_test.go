package store

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tstore "source.quilibrium.com/quilibrium/monorepo/types/store"
)

func setupTestKeyStore(t *testing.T) *PebbleKeyStore {
	logger, _ := zap.NewDevelopment()
	tempDB := NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".test/store"}, 0)
	return NewPebbleKeyStore(tempDB, logger)
}

func generateRandomBytes(t *testing.T, size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func createTestEd448PublicKey(t *testing.T) *protobufs.Ed448PublicKey {
	return &protobufs.Ed448PublicKey{
		KeyValue: generateRandomBytes(t, 57),
	}
}

func createTestBLS48581SignatureWithProofOfPossession(t *testing.T) *protobufs.BLS48581SignatureWithProofOfPossession {
	return &protobufs.BLS48581SignatureWithProofOfPossession{
		Signature: generateRandomBytes(t, 74),
		PublicKey: &protobufs.BLS48581G2PublicKey{
			KeyValue: generateRandomBytes(t, 585),
		},
		PopSignature: generateRandomBytes(t, 74),
	}
}

func createTestSignedX448Key(t *testing.T, parentKeyAddress []byte, purpose string) *protobufs.SignedX448Key {
	return &protobufs.SignedX448Key{
		Key: &protobufs.X448PublicKey{
			KeyValue: generateRandomBytes(t, 57),
		},
		ParentKeyAddress: parentKeyAddress,
		Signature: &protobufs.SignedX448Key_Ed448Signature{
			Ed448Signature: &protobufs.Ed448Signature{
				Signature: generateRandomBytes(t, 114),
				PublicKey: createTestEd448PublicKey(t),
			},
		},
		CreatedAt:  uint64(time.Now().Unix()),
		ExpiresAt:  0,
		KeyPurpose: purpose,
	}
}

func TestPebbleKeyStore_IdentityKeys(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	address := generateRandomBytes(t, 32)
	identityKey := createTestEd448PublicKey(t)

	// Test putting identity key
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutIdentityKey(txn, address, identityKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Test getting identity key
	retrievedKey, err := store.GetIdentityKey(address)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(identityKey.KeyValue, retrievedKey.KeyValue))

	// Test non-existent key
	_, err = store.GetIdentityKey(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)
}

func TestPebbleKeyStore_ProvingKeys(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	address := generateRandomBytes(t, 32)
	provingKey := createTestBLS48581SignatureWithProofOfPossession(t)

	// Test putting proving key
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutProvingKey(txn, address, provingKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Test getting proving key
	retrievedKey, err := store.GetProvingKey(address)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(provingKey.Signature, retrievedKey.Signature))
	assert.True(t, bytes.Equal(provingKey.PublicKey.KeyValue, retrievedKey.PublicKey.KeyValue))

	// Test non-existent key
	_, err = store.GetProvingKey(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)
}

func TestPebbleKeyStore_CrossSignatures(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	identityKeyAddress := generateRandomBytes(t, 32)
	provingKeyAddress := generateRandomBytes(t, 32)
	identitySig := generateRandomBytes(t, 114)
	provingSig := generateRandomBytes(t, 74)

	// Test putting cross signatures
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutCrossSignature(txn, identityKeyAddress, provingKeyAddress, identitySig, provingSig)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Test getting cross signature by identity key
	crossSigData, err := store.GetCrossSignatureByIdentityKey(identityKeyAddress)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(provingKeyAddress, crossSigData[:32]))
	assert.True(t, bytes.Equal(identitySig, crossSigData[32:]))

	// Test getting cross signature by proving key
	crossSigData, err = store.GetCrossSignatureByProvingKey(provingKeyAddress)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(identityKeyAddress, crossSigData[:32]))
	assert.True(t, bytes.Equal(provingSig, crossSigData[32:]))

	// Test non-existent cross signatures
	_, err = store.GetCrossSignatureByIdentityKey(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)

	_, err = store.GetCrossSignatureByProvingKey(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)
}

func TestPebbleKeyStore_SignedKeys(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	parentKeyAddress := generateRandomBytes(t, 32)
	keyAddress := generateRandomBytes(t, 32)
	signedKey := createTestSignedX448Key(t, parentKeyAddress, "inbox")

	// Test putting signed key
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, keyAddress, signedKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Test getting signed key
	retrievedKey, err := store.GetSignedX448Key(keyAddress)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(signedKey.Key.KeyValue, retrievedKey.Key.KeyValue))
	assert.True(t, bytes.Equal(signedKey.ParentKeyAddress, retrievedKey.ParentKeyAddress))
	assert.Equal(t, signedKey.KeyPurpose, retrievedKey.KeyPurpose)

	// Test getting by parent
	keys, err := store.GetSignedX448KeysByParent(parentKeyAddress, "")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.True(t, bytes.Equal(signedKey.Key.KeyValue, keys[0].Key.KeyValue))

	// Test getting by parent and purpose
	keys, err = store.GetSignedX448KeysByParent(parentKeyAddress, "inbox")
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Test getting by parent and wrong purpose
	keys, err = store.GetSignedX448KeysByParent(parentKeyAddress, "device")
	require.NoError(t, err)
	assert.Len(t, keys, 0)

	// Test non-existent key
	_, err = store.GetSignedX448Key(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)
}

func TestPebbleKeyStore_SignedKeysMultiplePurposes(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	parentKeyAddress := generateRandomBytes(t, 32)

	// Create keys with different purposes
	purposes := []string{"inbox", "device", "pre", "spend", "view"}
	keyAddresses := make([][]byte, len(purposes))

	txn, err := store.NewTransaction()
	require.NoError(t, err)

	for i, purpose := range purposes {
		keyAddress := generateRandomBytes(t, 32)
		keyAddresses[i] = keyAddress
		signedKey := createTestSignedX448Key(t, parentKeyAddress, purpose)

		err = store.PutSignedX448Key(txn, keyAddress, signedKey)
		require.NoError(t, err)
	}

	err = txn.Commit()
	require.NoError(t, err)

	// Test getting all keys by parent
	keys, err := store.GetSignedX448KeysByParent(parentKeyAddress, "")
	require.NoError(t, err)
	assert.Len(t, keys, len(purposes))

	// Test getting keys by specific purpose
	for _, purpose := range purposes {
		keys, err = store.GetSignedX448KeysByParent(parentKeyAddress, purpose)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, purpose, keys[0].KeyPurpose)
	}
}

func TestPebbleKeyStore_DeleteSignedX448Key(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	parentKeyAddress := generateRandomBytes(t, 32)
	keyAddress := generateRandomBytes(t, 32)
	signedKey := createTestSignedX448Key(t, parentKeyAddress, "inbox")

	// Put the key
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, keyAddress, signedKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Verify it exists
	_, err = store.GetSignedX448Key(keyAddress)
	require.NoError(t, err)

	// Delete the key
	txn, err = store.NewTransaction()
	require.NoError(t, err)

	err = store.DeleteSignedX448Key(txn, keyAddress)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Verify it's deleted
	_, err = store.GetSignedX448Key(keyAddress)
	assert.ErrorIs(t, err, tstore.ErrNotFound)

	// Verify it's removed from parent index
	keys, err := store.GetSignedX448KeysByParent(parentKeyAddress, "")
	require.NoError(t, err)
	assert.Len(t, keys, 0)
}

func TestPebbleKeyStore_ExpiredKeys(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	parentKeyAddress := generateRandomBytes(t, 32)
	currentTime := uint64(time.Now().Unix())

	// Create expired key
	expiredKeyAddress := generateRandomBytes(t, 32)
	expiredKey := createTestSignedX448Key(t, parentKeyAddress, "inbox")
	expiredKey.ExpiresAt = currentTime - 3600 // Expired 1 hour ago

	// Create valid key
	validKeyAddress := generateRandomBytes(t, 32)
	validKey := createTestSignedX448Key(t, parentKeyAddress, "device")
	validKey.ExpiresAt = currentTime + 3600 // Expires in 1 hour

	// Create non-expiring key
	permanentKeyAddress := generateRandomBytes(t, 32)
	permanentKey := createTestSignedX448Key(t, parentKeyAddress, "spend")
	permanentKey.ExpiresAt = 0 // Never expires

	// Put all keys
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, expiredKeyAddress, expiredKey)
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, validKeyAddress, validKey)
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, permanentKeyAddress, permanentKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Reap expired keys
	err = store.ReapExpiredKeys()
	require.NoError(t, err)

	// Verify expired key is deleted
	_, err = store.GetSignedX448Key(expiredKeyAddress)
	assert.ErrorIs(t, err, tstore.ErrNotFound)

	// Verify valid keys remain
	_, err = store.GetSignedX448Key(validKeyAddress)
	require.NoError(t, err)

	_, err = store.GetSignedX448Key(permanentKeyAddress)
	require.NoError(t, err)
}

func TestPebbleKeyStore_GetKeyRegistry(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	// Create identity key
	identityKeyAddress := generateRandomBytes(t, 32)
	identityKey := createTestEd448PublicKey(t)

	// Create proving key
	provingKeyAddress := generateRandomBytes(t, 32)
	provingKey := createTestBLS48581SignatureWithProofOfPossession(t)

	// Create cross signatures
	identitySig := generateRandomBytes(t, 114)
	provingSig := generateRandomBytes(t, 74)

	// Create signed keys
	inboxKeyAddress := generateRandomBytes(t, 32)
	inboxKey := createTestSignedX448Key(t, identityKeyAddress, "inbox")

	deviceKeyAddress := generateRandomBytes(t, 32)
	deviceKey := createTestSignedX448Key(t, identityKeyAddress, "device")

	// Create a key signed by prover
	preKeyAddress := generateRandomBytes(t, 32)
	preKey := createTestSignedX448Key(t, provingKeyAddress, "pre")

	// Put everything
	txn, err := store.NewTransaction()
	require.NoError(t, err)

	err = store.PutIdentityKey(txn, identityKeyAddress, identityKey)
	require.NoError(t, err)

	err = store.PutProvingKey(txn, provingKeyAddress, provingKey)
	require.NoError(t, err)

	err = store.PutCrossSignature(txn, identityKeyAddress, provingKeyAddress, identitySig, provingSig)
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, inboxKeyAddress, inboxKey)
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, deviceKeyAddress, deviceKey)
	require.NoError(t, err)

	err = store.PutSignedX448Key(txn, preKeyAddress, preKey)
	require.NoError(t, err)

	err = txn.Commit()
	require.NoError(t, err)

	// Test GetKeyRegistry
	registry, err := store.GetKeyRegistry(identityKeyAddress)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// Verify identity key
	assert.NotNil(t, registry.IdentityKey)
	assert.True(t, bytes.Equal(identityKey.KeyValue, registry.IdentityKey.KeyValue))

	// Verify prover key
	assert.NotNil(t, registry.ProverKey)
	assert.True(t, bytes.Equal(provingKey.PublicKey.KeyValue, registry.ProverKey.KeyValue))

	// Verify cross signatures
	assert.NotNil(t, registry.IdentityToProver)
	assert.True(t, bytes.Equal(identitySig, registry.IdentityToProver.Signature))

	assert.NotNil(t, registry.ProverToIdentity)
	assert.True(t, bytes.Equal(provingSig, registry.ProverToIdentity.Signature))

	// Verify signed keys
	assert.Len(t, registry.KeysByPurpose, 3) // inbox, device, pre

	assert.NotNil(t, registry.KeysByPurpose["inbox"])
	assert.Len(t, registry.KeysByPurpose["inbox"].X448Keys, 1)
	assert.Equal(t, "inbox", registry.KeysByPurpose["inbox"].KeyPurpose)

	assert.NotNil(t, registry.KeysByPurpose["device"])
	assert.Len(t, registry.KeysByPurpose["device"].X448Keys, 1)
	assert.Equal(t, "device", registry.KeysByPurpose["device"].KeyPurpose)

	assert.NotNil(t, registry.KeysByPurpose["pre"])
	assert.Len(t, registry.KeysByPurpose["pre"].X448Keys, 1)
	assert.Equal(t, "pre", registry.KeysByPurpose["pre"].KeyPurpose)

	// Test GetKeyRegistryByProver
	registryByProver, err := store.GetKeyRegistryByProver(provingKeyAddress)
	require.NoError(t, err)
	require.NotNil(t, registryByProver)

	// Should be the same registry
	assert.True(t, bytes.Equal(registry.IdentityKey.KeyValue, registryByProver.IdentityKey.KeyValue))
	assert.True(t, bytes.Equal(registry.ProverKey.KeyValue, registryByProver.ProverKey.KeyValue))
}

func TestPebbleKeyStore_GetKeyRegistry_NotFound(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	// Test with non-existent identity key
	_, err := store.GetKeyRegistry(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)

	// Test with non-existent prover key
	_, err = store.GetKeyRegistryByProver(generateRandomBytes(t, 32))
	assert.ErrorIs(t, err, tstore.ErrNotFound)
}

func TestPebbleKeyStore_Iterators(t *testing.T) {
	store := setupTestKeyStore(t)
	defer store.db.Close()

	// Put multiple identity keys
	identityKeys := make(map[string]*protobufs.Ed448PublicKey)
	for i := 0; i < 3; i++ {
		address := generateRandomBytes(t, 32)
		key := createTestEd448PublicKey(t)
		identityKeys[string(address)] = key

		txn, err := store.NewTransaction()
		require.NoError(t, err)

		err = store.PutIdentityKey(txn, address, key)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)
	}

	// Test RangeIdentityKeys
	iter, err := store.RangeIdentityKeys()
	require.NoError(t, err)
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		key, err := iter.Value()
		require.NoError(t, err)
		count++

		// Verify key exists in our map
		found := false
		for _, origKey := range identityKeys {
			if bytes.Equal(origKey.KeyValue, key.KeyValue) {
				found = true
				break
			}
		}
		assert.True(t, found)
	}
	assert.Equal(t, len(identityKeys), count)

	// Put multiple proving keys
	provingKeys := make(map[string]*protobufs.BLS48581SignatureWithProofOfPossession)
	for i := 0; i < 3; i++ {
		address := generateRandomBytes(t, 32)
		key := createTestBLS48581SignatureWithProofOfPossession(t)
		provingKeys[string(address)] = key

		txn, err := store.NewTransaction()
		require.NoError(t, err)

		err = store.PutProvingKey(txn, address, key)
		require.NoError(t, err)

		err = txn.Commit()
		require.NoError(t, err)
	}

	// Test RangeProvingKeys
	iter2, err := store.RangeProvingKeys()
	require.NoError(t, err)
	defer iter2.Close()

	count = 0
	for iter2.First(); iter2.Valid(); iter2.Next() {
		key, err := iter2.Value()
		require.NoError(t, err)
		count++

		// Verify key exists in our map
		found := false
		for _, origKey := range provingKeys {
			if bytes.Equal(origKey.Signature, key.Signature) {
				found = true
				break
			}
		}
		assert.True(t, found)
	}
	assert.Equal(t, len(provingKeys), count)

	// Put multiple signed keys
	parentKeyAddress := generateRandomBytes(t, 32)
	signedKeys := make(map[string]*protobufs.SignedX448Key)

	txn, err := store.NewTransaction()
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		address := generateRandomBytes(t, 32)
		key := createTestSignedX448Key(t, parentKeyAddress, "test")
		signedKeys[string(address)] = key

		err = store.PutSignedX448Key(txn, address, key)
		require.NoError(t, err)
	}

	err = txn.Commit()
	require.NoError(t, err)

	// Test RangeSignedKeys
	iter3, err := store.RangeSignedX448Keys(parentKeyAddress, "test")
	require.NoError(t, err)
	defer iter3.Close()

	count = 0
	for iter3.First(); iter3.Valid(); iter3.Next() {
		key, err := iter3.Value()
		require.NoError(t, err)
		count++

		// Verify key exists in our map
		found := false
		for _, origKey := range signedKeys {
			if bytes.Equal(origKey.Key.KeyValue, key.Key.KeyValue) {
				found = true
				break
			}
		}
		assert.True(t, found)
	}
	assert.Equal(t, len(signedKeys), count)
}
