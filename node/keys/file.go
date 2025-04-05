package keys

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

type FileKeyManager struct {
	keyStoreConfig *config.KeyStoreFileConfig
	logger         *zap.Logger
	key            ByteString
	store          map[string]Key
	storeMx        sync.Mutex
}

var UnsupportedKeyTypeErr = errors.New("unsupported key type")
var KeyNotFoundErr = errors.New("key not found")

func NewFileKeyManager(
	keyStoreConfig *config.KeyConfig,
	logger *zap.Logger,
) *FileKeyManager {
	if keyStoreConfig.KeyStoreFile == nil {
		logger.Panic("key store config missing")
	}

	key, err := hex.DecodeString(keyStoreConfig.KeyStoreFile.EncryptionKey)
	if err != nil {
		logger.Panic("could not decode encryption key", zap.Error(err))
	}

	store := make(map[string]Key)

	flag := os.O_RDONLY

	if keyStoreConfig.KeyStoreFile.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(
		keyStoreConfig.KeyStoreFile.Path,
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

	return &FileKeyManager{
		keyStoreConfig: keyStoreConfig.KeyStoreFile,
		logger:         logger,
		key:            key,
		store:          store,
	}
}

// CreateSigningKey implements KeyManager
func (f *FileKeyManager) CreateSigningKey(
	id string,
	keyType KeyType,
) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeEd448:
		pubkey, privkey, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "could not generate key")
		}

		if err = f.save(
			id,
			Key{
				Id:         id,
				Type:       keyType,
				PublicKey:  ByteString(pubkey),
				PrivateKey: ByteString(privkey),
			},
		); err != nil {
			return nil, errors.Wrap(err, "could not save")
		}

		return privkey, nil
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

	return nil, UnsupportedKeyTypeErr
}

// CreateAgreementKey implements KeyManager
func (f *FileKeyManager) CreateAgreementKey(
	id string,
	keyType KeyType,
) (curves.Scalar, error) {
	switch keyType {
	case KeyTypeX448:
		privkey := curves.ED448().Scalar.Random(rand.Reader)
		pubkey := curves.ED448().NewGeneratorPoint().Mul(privkey)

		if err := f.save(
			id,
			Key{
				Id:         id,
				Type:       KeyTypeX448,
				PublicKey:  pubkey.ToAffineCompressed(),
				PrivateKey: privkey.Bytes(),
			},
		); err != nil {
			return nil, errors.Wrap(err, "could not save")
		}

		return privkey, nil
	}

	return nil, UnsupportedKeyTypeErr
}

// GetAgreementKey implements KeyManager
func (f *FileKeyManager) GetAgreementKey(id string) (curves.Scalar, error) {
	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case KeyTypeX448:
		privkey, err := curves.ED448().NewScalar().SetBytes(key.PrivateKey)
		return privkey, err
	}

	return nil, UnsupportedKeyTypeErr
}

// GetRawKey implements KeyManager
func (f *FileKeyManager) GetRawKey(id string) (*Key, error) {
	key, err := f.read(id)
	return &key, err
}

// GetSigningKey implements KeyManager
func (f *FileKeyManager) GetSigningKey(id string) (crypto.Signer, error) {
	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case KeyTypeEd448:
		privkey := (ed448.PrivateKey)(key.PrivateKey)
		return privkey, err
		// case KeyTypePCAS:
		// 	privkey := (addressing.PCAS)(key.PrivateKey)
		// 	return privkey, err
	}

	return nil, UnsupportedKeyTypeErr
}

// PutRawKey implements KeyManager
func (f *FileKeyManager) PutRawKey(key *Key) error {
	return f.save(key.Id, *key)
}

// DeleteKey implements KeyManager
func (f *FileKeyManager) DeleteKey(id string) error {
	flag := os.O_RDWR

	if f.keyStoreConfig.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(f.keyStoreConfig.Path, flag, os.FileMode(0600))
	if err != nil {
		return errors.Wrap(err, "could not open store")
	}

	defer file.Close()

	d := yaml.NewEncoder(file)

	f.storeMx.Lock()
	delete(f.store, id)

	err = d.Encode(f.store)
	f.storeMx.Unlock()

	return errors.Wrap(err, "could not store")
}

// GetKey implements KeyManager
func (f *FileKeyManager) GetKey(id string) (key *Key, err error) {
	storeKey, err := f.read(id)
	if err != nil {
		return nil, err
	}

	return &storeKey, nil
}

// ListKeys implements KeyManager
func (f *FileKeyManager) ListKeys() ([]*Key, error) {
	keys := []*Key{}

	f.storeMx.Lock()
	for k := range f.store {
		storeKey, err := f.read(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &storeKey)
	}
	f.storeMx.Unlock()

	return keys, nil
}

var _ KeyManager = (*FileKeyManager)(nil)

func (f *FileKeyManager) save(id string, key Key) error {
	flag := os.O_RDWR

	if f.keyStoreConfig.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(f.keyStoreConfig.Path, flag, os.FileMode(0600))
	if err != nil {
		return errors.Wrap(err, "could not open store")
	}

	defer file.Close()

	d := yaml.NewEncoder(file)

	encKey := []byte{}
	if encKey, err = f.encrypt(key.PrivateKey); err != nil {
		return errors.Wrap(err, "could not encrypt")
	}

	f.storeMx.Lock()
	f.store[id] = Key{
		Id:         key.Id,
		Type:       key.Type,
		PublicKey:  key.PublicKey,
		PrivateKey: encKey,
	}

	err = d.Encode(f.store)
	f.storeMx.Unlock()

	return errors.Wrap(err, "could not store")
}

func (f *FileKeyManager) read(id string) (Key, error) {
	flag := os.O_RDONLY

	if f.keyStoreConfig.CreateIfMissing {
		flag |= os.O_CREATE
	}

	file, err := os.OpenFile(f.keyStoreConfig.Path, flag, os.FileMode(0600))
	if err != nil {
		return Key{}, errors.Wrap(err, "could not open store")
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	f.storeMx.Lock()
	if err = d.Decode(f.store); err != nil {
		f.storeMx.Unlock()
		return Key{}, errors.Wrap(err, "could not decode")
	}

	if _, ok := f.store[id]; !ok {
		f.storeMx.Unlock()
		return Key{}, KeyNotFoundErr
	}

	data, err := f.decrypt(f.store[id].PrivateKey)
	if err != nil {
		f.storeMx.Unlock()
		return Key{}, errors.Wrap(err, "could not decrypt")
	}

	key := Key{
		Id:         f.store[id].Id,
		Type:       f.store[id].Type,
		PublicKey:  f.store[id].PublicKey,
		PrivateKey: data,
	}
	f.storeMx.Unlock()
	return key, nil
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
