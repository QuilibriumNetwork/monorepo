package keys_test

import (
	"crypto"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
)

// setupTestFileKeyManager sets up a test environment for the FileKeyManager
func setupTestFileKeyManager(t *testing.T) (*keys.FileKeyManager, func()) {
	// Create a temporary file for the test
	tempFile, err := ioutil.TempFile("", "keystore-*.yaml")
	require.NoError(t, err)

	os.WriteFile(tempFile.Name(), []byte("\"\":\n  id: \"\"\n  type: 0\n  privateKey: \"\"\n  publicKey: \"\"\n"), 0644)

	// Create a test configuration
	keyConfig := &config.Config{
		Key: &config.KeyConfig{
			KeyStoreFile: &config.KeyStoreFileConfig{
				Path:            tempFile.Name(),
				EncryptionKey:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				CreateIfMissing: false,
			},
		},
	}

	// Create mock constructors for BLS and Decaf keys
	mockBLSConstructor := &mocks.MockBlsConstructor{}
	mockSigner := &mocks.MockBLSSigner{}
	mockSigner.On("Public").Return(crypto.PublicKey(make([]byte, 585)))
	mockSigner.On("Private").Return(make([]byte, 74))
	mockBLSConstructor.On("New").Return(mockSigner, make([]byte, 74), nil)
	mockDecafConstructor := &mocks.MockDecafConstructor{}

	// Initialize the FileKeyManager with test configuration
	logger := zap.NewNop()
	keyManager := keys.NewFileKeyManager(keyConfig, mockBLSConstructor, mockDecafConstructor, logger)

	// Return cleanup function
	cleanup := func() {
		os.Remove(tempFile.Name())
	}

	return keyManager, cleanup
}

func TestFileKeyManager_CreateGetSigningKey(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Test cases for creating and retrieving different types of signing keys
	testCases := []struct {
		name    string
		keyType qcrypto.KeyType
	}{
		{
			name:    "Ed448 key",
			keyType: qcrypto.KeyTypeEd448,
		},
		// {
		// 	name:    "BLS key in G1",
		// 	keyType: qcrypto.KeyTypeBLS48581G1,
		// },
		// {
		// 	name:    "BLS key in G2",
		// 	keyType: qcrypto.KeyTypeBLS48581G2,
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new signing key
			keyID := "test-signing-key-" + tc.name
			signer, _, err := keyManager.CreateSigningKey(keyID, tc.keyType)
			require.NoError(t, err)
			require.NotNil(t, signer)

			// Store the public key for later comparison
			originalPublicKey := signer.Public()

			// Retrieve the key using GetSigningKey
			retrievedSigner, err := keyManager.GetSigningKey(keyID)
			require.NoError(t, err)
			require.NotNil(t, retrievedSigner)

			// Verify the public key matches
			assert.Equal(t, originalPublicKey, retrievedSigner.Public())

			// Get the raw key and verify its properties
			rawKey, err := keyManager.GetRawKey(keyID)
			require.NoError(t, err)
			assert.Equal(t, keyID, rawKey.Id)
			assert.Equal(t, tc.keyType, rawKey.Type)
			assert.NotEmpty(t, rawKey.PublicKey)
			assert.NotEmpty(t, rawKey.PrivateKey)
		})
	}
}

func TestFileKeyManager_CreateGetAgreementKey(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Test cases for creating and retrieving different types of agreement keys
	testCases := []struct {
		name    string
		keyType qcrypto.KeyType
	}{
		{
			name:    "X448 key",
			keyType: qcrypto.KeyTypeX448,
		},
		// {
		// 	name:    "Decaf448 key",
		// 	keyType: qcrypto.KeyTypeDecaf448,
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new agreement key
			keyID := "test-agreement-key-" + tc.name
			agreement, err := keyManager.CreateAgreementKey(keyID, tc.keyType)
			require.NoError(t, err)
			require.NotNil(t, agreement)

			// Store the public key for later comparison
			originalPublicKey := agreement.Public()

			// Retrieve the key using GetAgreementKey
			retrievedAgreement, err := keyManager.GetAgreementKey(keyID)
			require.NoError(t, err)
			require.NotNil(t, retrievedAgreement)

			// Compare the public keys
			assert.Equal(t, originalPublicKey, retrievedAgreement.Public())

			// Get the raw key and verify its properties
			rawKey, err := keyManager.GetRawKey(keyID)
			require.NoError(t, err)
			assert.Equal(t, keyID, rawKey.Id)
			assert.Equal(t, tc.keyType, rawKey.Type)
			assert.NotEmpty(t, rawKey.PublicKey)
			assert.NotEmpty(t, rawKey.PrivateKey)
		})
	}
}

func TestFileKeyManager_DeleteKey(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Create a key
	keyID := "key-to-delete"
	signer, _, err := keyManager.CreateSigningKey(keyID, qcrypto.KeyTypeEd448)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Verify the key exists
	retrievedKey, err := keyManager.GetRawKey(keyID)
	require.NoError(t, err)
	require.NotNil(t, retrievedKey)

	// Delete the key
	err = keyManager.DeleteKey(keyID)
	require.NoError(t, err)

	// Verify the key no longer exists
	_, err = keyManager.GetRawKey(keyID)
	assert.Equal(t, keys.KeyNotFoundErr, err)
}

func TestFileKeyManager_ListKeys(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Create multiple keys
	keyIDs := []string{"key1", "key2", "key3"}
	for _, id := range keyIDs {
		signer, _, err := keyManager.CreateSigningKey(id, qcrypto.KeyTypeEd448)
		require.NoError(t, err)
		require.NotNil(t, signer)
	}

	// List all keys
	keys, err := keyManager.ListKeys()
	require.NoError(t, err)

	// Verify all keys are in the list (plus q-prover-key default)
	assert.Len(t, keys, len(keyIDs)+1)

	// Check that each key ID exists in the list
	foundIDs := make(map[string]bool)
	for _, key := range keys {
		foundIDs[key.Id] = true
	}

	for _, id := range keyIDs {
		assert.True(t, foundIDs[id], "Key ID %s not found in list", id)
	}
}

func TestFileKeyManager_PutRawKey(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Create a new key manually
	keyID := "manual-key"
	key := &tkeys.Key{
		Id:         keyID,
		Type:       qcrypto.KeyTypeEd448,
		PublicKey:  tkeys.ByteString([]byte("test-public-key")),
		PrivateKey: tkeys.ByteString([]byte("test-private-key")),
	}

	// Put the raw key
	err := keyManager.PutRawKey(key)
	require.NoError(t, err)

	// Retrieve the key
	retrievedKey, err := keyManager.GetRawKey(keyID)
	require.NoError(t, err)

	// Verify the key properties
	assert.Equal(t, keyID, retrievedKey.Id)
	assert.Equal(t, qcrypto.KeyTypeEd448, retrievedKey.Type)
	assert.Equal(t, tkeys.ByteString([]byte("test-public-key")), retrievedKey.PublicKey)
	assert.Equal(t, tkeys.ByteString([]byte("test-private-key")), retrievedKey.PrivateKey)
}

func TestFileKeyManager_UnsupportedKeyType(t *testing.T) {
	// Setup test environment
	keyManager, cleanup := setupTestFileKeyManager(t)
	defer cleanup()

	// Try to create a signing key with an unsupported type
	unsupportedType := qcrypto.KeyType(999) // Some unsupported key type
	_, _, err := keyManager.CreateSigningKey("unsupported", unsupportedType)
	assert.Equal(t, keys.UnsupportedKeyTypeErr, err)

	// Try to create an agreement key with an unsupported type
	_, err = keyManager.CreateAgreementKey("unsupported", unsupportedType)
	assert.Equal(t, keys.UnsupportedKeyTypeErr, err)
}

func TestFileKeyManager_SaveLoad(t *testing.T) {
	// Setup test environment
	tempFile, err := ioutil.TempFile("", "keystore-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	os.WriteFile(tempFile.Name(), []byte("\"\":\n  id: \"\"\n  type: 0\n  privateKey: \"\"\n  publicKey: \"\"\n"), 0644)

	// Create a test configuration
	keyConfig := &config.Config{
		Key: &config.KeyConfig{
			KeyStoreFile: &config.KeyStoreFileConfig{
				Path:            tempFile.Name(),
				EncryptionKey:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				CreateIfMissing: true,
			},
		},
	}

	// Create mock constructors for BLS and Decaf keys
	mockBLSConstructor := &mocks.MockBlsConstructor{}
	mockSigner := &mocks.MockBLSSigner{}
	mockSigner.On("Public").Return(crypto.PublicKey(make([]byte, 585)))
	mockSigner.On("Private").Return(make([]byte, 74))
	mockBLSConstructor.On("New").Return(mockSigner, make([]byte, 74), nil)
	mockBLSConstructor.On("FromBytes", mock.Anything, mock.Anything).Return(mockSigner, nil)
	mockDecafConstructor := &mocks.MockDecafConstructor{}
	logger := zap.NewNop()

	// Create first instance and add a key
	keyManager1 := keys.NewFileKeyManager(keyConfig, mockBLSConstructor, mockDecafConstructor, logger)
	keyID := "persistent-key"
	signer, _, err := keyManager1.CreateSigningKey(keyID, qcrypto.KeyTypeEd448)
	require.NoError(t, err)
	originalPublicKey := signer.Public()

	// Create a second instance (simulating process restart)
	keyManager2 := keys.NewFileKeyManager(keyConfig, mockBLSConstructor, mockDecafConstructor, logger)

	// Verify the key persisted and can be retrieved
	retrievedSigner, err := keyManager2.GetSigningKey(keyID)
	require.NoError(t, err)
	assert.Equal(t, originalPublicKey, retrievedSigner.Public())
}
