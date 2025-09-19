package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
	"source.quilibrium.com/quilibrium/monorepo/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type FileKeyManager struct {
	// needed due to historic artifact of peerkey
	keyConfig         *config.Config
	logger            *zap.Logger
	key               keys.ByteString
	store             map[string]keys.Key
	storeMx           sync.Mutex
	blsKeyConstructor qcrypto.BlsConstructor
	decafConstructor  qcrypto.DecafConstructor
}

var UnsupportedKeyTypeErr = errors.New("unsupported key type")
var KeyNotFoundErr = errors.New("key not found")

func NewFileKeyManager(
	keyConfig *config.Config,
	blsKeyConstructor qcrypto.BlsConstructor,
	decafConstructor qcrypto.DecafConstructor,
	logger *zap.Logger,
) *FileKeyManager {
	if keyConfig.Key.KeyStoreFile == nil {
		logger.Panic("key store config missing")
	}

	key, err := hex.DecodeString(keyConfig.Key.KeyStoreFile.EncryptionKey)
	if err != nil {
		logger.Panic("could not decode encryption key", zap.Error(err))
	}

	store := make(map[string]keys.Key)

	flag := os.O_RDONLY

	if keyConfig.Key.KeyStoreFile.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(
		keyConfig.Key.KeyStoreFile.Path,
		flag,
		os.FileMode(0600),
	)
	if err != nil {
		logger.Panic("could not open store", zap.Error(err))
	}

	defer file.Close()

	d := yaml.NewDecoder(file)

	if err := d.Decode(store); err != nil {
		logger.Panic("could not decode store", zap.Error(err))
	}

	keyManager := &FileKeyManager{
		keyConfig:         keyConfig,
		logger:            logger,
		key:               key,
		store:             store,
		blsKeyConstructor: blsKeyConstructor,
		decafConstructor:  decafConstructor,
	}

	_, err = keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		_, _, err = keyManager.CreateSigningKey(
			"q-prover-key",
			qcrypto.KeyTypeBLS48581G1,
		)
		if err != nil {
			logger.Panic("could not establish prover key", zap.Error(err))
		}
	}

	return keyManager
}

// ValidateSignature implements KeyManager.
func (f *FileKeyManager) ValidateSignature(
	keyType qcrypto.KeyType,
	publicKey []byte,
	message []byte,
	signature []byte,
	domain []byte,
) (bool, error) {
	switch keyType {
	case qcrypto.KeyTypeEd448:
		return ed448.Verify(
			ed448.PublicKey(publicKey),
			slices.Concat(domain, message),
			signature,
			"",
		), nil
	case qcrypto.KeyTypeBLS48581G1:
		fallthrough
	case qcrypto.KeyTypeBLS48581G2:
		return f.blsKeyConstructor.VerifySignatureRaw(
			publicKey,
			signature,
			message,
			domain,
		), nil
	case qcrypto.KeyTypeSecp256K1SHA256:
		digest := sha256.Sum256(slices.Concat(domain, message))
		pubkey, _, err := btcec.RecoverCompact(btcec.S256(), signature, digest[:])
		if err != nil {
			return false, errors.Wrap(err, "validate signature")
		}

		return bytes.Equal(publicKey, pubkey.SerializeCompressed()), nil
	case qcrypto.KeyTypeSecp256K1SHA3:
		digest := sha3.Sum256(slices.Concat(domain, message))
		pubkey, _, err := btcec.RecoverCompact(btcec.S256(), signature, digest[:])
		if err != nil {
			return false, errors.Wrap(err, "validate signature")
		}

		return bytes.Equal(publicKey, pubkey.SerializeCompressed()), nil
	case qcrypto.KeyTypeEd25519:
		return ed25519.Verify(
			ed25519.PublicKey(publicKey),
			slices.Concat(domain, message),
			signature,
		), nil
	}

	return false, nil
}

// CreateSigningKey implements KeyManager
func (f *FileKeyManager) CreateSigningKey(
	id string,
	keyType qcrypto.KeyType,
) (qcrypto.Signer, []byte, error) {
	if id == "q-peer-key" {
		return nil, nil, errors.Wrap(
			errors.New("invalid request"),
			"create signing key",
		)
	}

	switch keyType {
	case qcrypto.KeyTypeEd448:
		ed448Key, err := NewEd448Key()
		if err != nil {
			return nil, nil, errors.Wrap(err, "create signing key")
		}

		if err = f.save(
			id,
			keys.Key{
				Id:         id,
				Type:       keyType,
				PublicKey:  keys.ByteString(ed448Key.Public().([]byte)),
				PrivateKey: keys.ByteString(ed448Key.Private()),
			},
		); err != nil {
			return nil, nil, errors.Wrap(err, "create signing key")
		}

		return ed448Key, nil, nil
	case qcrypto.KeyTypeBLS48581G1:
		fallthrough
	case qcrypto.KeyTypeBLS48581G2:
		blskey, popk, err := f.blsKeyConstructor.New()
		if err != nil {
			return nil, nil, errors.Wrap(err, "create signing key")
		}

		if err = f.save(
			id,
			keys.Key{
				Id:         id,
				Type:       keyType,
				PublicKey:  keys.ByteString(blskey.Public().([]byte)),
				PrivateKey: keys.ByteString(blskey.Private()),
			},
		); err != nil {
			return nil, nil, errors.Wrap(err, "create signing key")
		}

		return blskey, popk, nil
		// case KeyTypePCAS:
		// 	_, privkey, err := addressing.GenerateKey(rand.Reader)
		// 	if err != nil {
		// 		return nil, errors.Wrap(err, "could not generate key")
		// 	}

		// 	if err = f.save(id, privkey); err != nil {
		// 		return nil, errors.Wrap(err, "could not save")
		// 	}

		// 	return privkey, nil
	}

	return nil, nil, UnsupportedKeyTypeErr
}

// CreateAgreementKey implements KeyManager
func (f *FileKeyManager) CreateAgreementKey(
	id string,
	keyType qcrypto.KeyType,
) (qcrypto.Agreement, error) {
	switch keyType {
	case qcrypto.KeyTypeX448:
		x448Key := NewX448Key()

		if err := f.save(
			id,
			keys.Key{
				Id:         id,
				Type:       qcrypto.KeyTypeX448,
				PublicKey:  x448Key.Public(),
				PrivateKey: x448Key.Private(),
			},
		); err != nil {
			return nil, errors.Wrap(err, "create agreement key")
		}

		return x448Key, nil
	case qcrypto.KeyTypeDecaf448:
		decafKey, err := f.decafConstructor.New()
		if err != nil {
			return nil, errors.Wrap(err, "create agreement key")
		}

		if err := f.save(
			id,
			keys.Key{
				Id:         id,
				Type:       qcrypto.KeyTypeDecaf448,
				PublicKey:  decafKey.Public(),
				PrivateKey: decafKey.Private(),
			},
		); err != nil {
			return nil, errors.Wrap(err, "create agreement key")
		}

		return decafKey, nil
	}

	return nil, UnsupportedKeyTypeErr
}

// GetAgreementKey implements KeyManager
func (f *FileKeyManager) GetAgreementKey(id string) (qcrypto.Agreement, error) {
	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case qcrypto.KeyTypeX448:
		x448Key, err := X448KeyFromBytes(key.PrivateKey)
		return x448Key, errors.Wrap(err, "get agreement key")
	case qcrypto.KeyTypeDecaf448:
		decafKey, err := f.decafConstructor.FromBytes(key.PrivateKey, key.PublicKey)
		return decafKey, errors.Wrap(err, "get agreement key")
	}

	return nil, UnsupportedKeyTypeErr
}

// GetRawKey implements KeyManager
func (f *FileKeyManager) GetRawKey(id string) (*keys.Key, error) {
	key, err := f.read(id)
	return &key, err
}

// GetSigningKey implements KeyManager
func (f *FileKeyManager) GetSigningKey(id string) (qcrypto.Signer, error) {
	if id == "q-peer-key" {
		key, err := hex.DecodeString(f.keyConfig.P2P.PeerPrivKey)
		if err != nil {
			return nil, err
		}

		// special case, peer key is stored as seed value
		privateKey := ed448.NewKeyFromSeed(key[:57])
		ed448Key, err := Ed448KeyFromBytes(privateKey, key[57:])
		return ed448Key, errors.Wrap(err, "get signing key")
	}

	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case qcrypto.KeyTypeEd448:
		ed448Key, err := Ed448KeyFromBytes(key.PrivateKey, key.PublicKey)
		return ed448Key, errors.Wrap(err, "get signing key")
	case qcrypto.KeyTypeBLS48581G1:
		fallthrough
	case qcrypto.KeyTypeBLS48581G2:
		blskey, err := f.blsKeyConstructor.FromBytes(key.PrivateKey, key.PublicKey)
		return blskey, errors.Wrap(err, "get signing key")
		// case KeyTypePCAS:
		// 	privkey := (addressing.PCAS)(key.PrivateKey)
		// 	return privkey, err
	}

	return nil, UnsupportedKeyTypeErr
}

// PutRawKey implements KeyManager
func (f *FileKeyManager) PutRawKey(key *keys.Key) error {
	return f.save(key.Id, *key)
}

// DeleteKey implements KeyManager
func (f *FileKeyManager) DeleteKey(id string) error {
	return f.delete(id)
}

// GetKey implements KeyManager
func (f *FileKeyManager) GetKey(id string) (key *keys.Key, err error) {
	storeKey, err := f.read(id)
	if err != nil {
		return nil, err
	}

	return &storeKey, nil
}

// ListKeys implements KeyManager
func (f *FileKeyManager) ListKeys() ([]*keys.Key, error) {
	keys := []*keys.Key{}

	for k := range f.store {
		if len(k) == 0 {
			continue
		}

		storeKey, err := f.read(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &storeKey)
	}

	return keys, nil
}

func (f *FileKeyManager) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (
	qcrypto.BlsAggregateOutput,
	error,
) {
	aggregate, err := f.blsKeyConstructor.Aggregate(publicKeys, signatures)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate")
	}

	return aggregate, nil
}

var _ keys.KeyManager = (*FileKeyManager)(nil)

func (f *FileKeyManager) save(id string, key keys.Key) error {
	encKey := []byte{}
	var err error
	if encKey, err = f.encrypt(key.PrivateKey); err != nil {
		return errors.Wrap(err, "could not encrypt")
	}

	f.storeMx.Lock()
	defer f.storeMx.Unlock()

	// Create a copy of the current store with the new key
	updatedStore := make(map[string]keys.Key)
	for k, v := range f.store {
		updatedStore[k] = v
	}
	updatedStore[id] = keys.Key{
		Id:         key.Id,
		Type:       key.Type,
		PublicKey:  key.PublicKey,
		PrivateKey: encKey,
	}

	// Create a temporary file in the same directory as the original
	originalPath := f.keyConfig.Key.KeyStoreFile.Path
	dir := filepath.Dir(originalPath)
	tempFile, err := ioutil.TempFile(dir, "keystore-*.tmp")
	if err != nil {
		return errors.Wrap(err, "could not create temporary file")
	}
	tempPath := tempFile.Name()

	// Ensure temporary file is removed in case of failure
	defer func() {
		tempFile.Close()
		// Only remove the temp file if it still exists (wasn't renamed)
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}()

	// Set proper permissions on the temporary file
	if err := os.Chmod(tempPath, 0600); err != nil {
		return errors.Wrap(err, "could not set file permissions")
	}

	// Write the updated store to the temporary file
	encoder := yaml.NewEncoder(tempFile)
	if err := encoder.Encode(updatedStore); err != nil {
		return errors.Wrap(err, "could not encode to temporary file")
	}

	// Ensure data is written to disk
	if err := tempFile.Sync(); err != nil {
		return errors.Wrap(err, "could not sync temporary file")
	}

	// Close the file before renaming
	if err := tempFile.Close(); err != nil {
		return errors.Wrap(err, "could not close temporary file")
	}

	// Atomically replace the original file with the new one
	if err := os.Rename(tempPath, originalPath); err != nil {
		return errors.Wrap(err, "could not replace key store file")
	}

	// Update the in-memory store only after successful file update
	f.store = updatedStore

	return nil
}

func (f *FileKeyManager) read(id string) (keys.Key, error) {
	f.storeMx.Lock()
	defer f.storeMx.Unlock()

	flag := os.O_RDONLY

	if f.keyConfig.Key.KeyStoreFile.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(
		f.keyConfig.Key.KeyStoreFile.Path,
		flag,
		os.FileMode(0600),
	)
	if err != nil {
		return keys.Key{}, errors.Wrap(err, "could not open store")
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	if err = d.Decode(f.store); err != nil {
		return keys.Key{}, errors.Wrap(err, "could not decode")
	}

	if _, ok := f.store[id]; !ok {
		return keys.Key{}, KeyNotFoundErr
	}

	data, err := f.decrypt(f.store[id].PrivateKey)
	if err != nil {
		return keys.Key{}, errors.Wrap(err, "could not decrypt")
	}

	key := keys.Key{
		Id:         f.store[id].Id,
		Type:       f.store[id].Type,
		PublicKey:  f.store[id].PublicKey,
		PrivateKey: data,
	}
	return key, nil
}

func (f *FileKeyManager) delete(id string) error {
	f.storeMx.Lock()
	defer f.storeMx.Unlock()

	// Check if the key exists in the store
	if _, exists := f.store[id]; !exists {
		return KeyNotFoundErr
	}

	// Create a copy of the store without the key to delete
	updatedStore := make(map[string]keys.Key)
	for k, v := range f.store {
		if k != id {
			updatedStore[k] = v
		}
	}

	// Create a temporary file in the same directory as the original
	originalPath := f.keyConfig.Key.KeyStoreFile.Path
	dir := filepath.Dir(originalPath)
	tempFile, err := ioutil.TempFile(dir, "keystore-*.tmp")
	if err != nil {
		return errors.Wrap(err, "could not create temporary file")
	}
	tempPath := tempFile.Name()

	// Ensure temporary file is removed in case of failure
	defer func() {
		tempFile.Close()
		// Only remove the temp file if it still exists (wasn't renamed)
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}()

	// Set proper permissions on the temporary file
	if err := os.Chmod(tempPath, 0600); err != nil {
		return errors.Wrap(err, "could not set file permissions")
	}

	// Write the updated store to the temporary file
	encoder := yaml.NewEncoder(tempFile)
	if err := encoder.Encode(updatedStore); err != nil {
		return errors.Wrap(err, "could not encode to temporary file")
	}

	// Ensure data is written to disk
	if err := tempFile.Sync(); err != nil {
		return errors.Wrap(err, "could not sync temporary file")
	}

	// Close the file before renaming
	if err := tempFile.Close(); err != nil {
		return errors.Wrap(err, "could not close temporary file")
	}

	// Atomically replace the original file with the new one
	if err := os.Rename(tempPath, originalPath); err != nil {
		return errors.Wrap(err, "could not replace key store file")
	}

	// Update the in-memory store only after successful file update
	f.store = updatedStore

	return nil
}

func (f *FileKeyManager) encrypt(data []byte) ([]byte, error) {
	iv := [12]byte{}
	rand.Read(iv[:])
	aesCipher, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct cipher")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct block")
	}

	ciphertext := []byte{}
	ciphertext = gcm.Seal(nil, iv[:], data, nil)
	ciphertext = append(append([]byte{}, iv[:]...), ciphertext...)

	return ciphertext, nil
}

func (f *FileKeyManager) decrypt(data []byte) ([]byte, error) {
	iv := data[:12]
	aesCipher, err := aes.NewCipher(f.key)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct cipher")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct block")
	}

	ciphertext := data[12:]
	plaintext, err := gcm.Open(nil, iv[:], ciphertext, nil)

	return plaintext, errors.Wrap(err, "could not decrypt ciphertext")
}
