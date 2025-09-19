package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type InMemoryKeyManager struct {
	key               keys.ByteString
	store             map[string]keys.Key
	blsKeyConstructor qcrypto.BlsConstructor
	decafConstructor  qcrypto.DecafConstructor
}

// ValidateSignature implements KeyManager.
func (f *InMemoryKeyManager) ValidateSignature(
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

func NewInMemoryKeyManager(
	blsKeyConstructor qcrypto.BlsConstructor,
	decafConstructor qcrypto.DecafConstructor,
) *InMemoryKeyManager {
	store := make(map[string]keys.Key)

	return &InMemoryKeyManager{
		store:             store,
		blsKeyConstructor: blsKeyConstructor,
		decafConstructor:  decafConstructor,
	}
}

// CreateSigningKey implements KeyManager
func (f *InMemoryKeyManager) CreateSigningKey(
	id string,
	keyType qcrypto.KeyType,
) (qcrypto.Signer, []byte, error) {
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
func (f *InMemoryKeyManager) CreateAgreementKey(
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
			return nil, errors.Wrap(err, "could not save")
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
func (f *InMemoryKeyManager) GetAgreementKey(
	id string,
) (qcrypto.Agreement, error) {
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
func (f *InMemoryKeyManager) GetRawKey(id string) (*keys.Key, error) {
	key, err := f.read(id)
	return &key, err
}

// GetSigningKey implements KeyManager
func (f *InMemoryKeyManager) GetSigningKey(id string) (qcrypto.Signer, error) {
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
func (f *InMemoryKeyManager) PutRawKey(key *keys.Key) error {
	return f.save(key.Id, *key)
}

// DeleteKey implements KeyManager
func (f *InMemoryKeyManager) DeleteKey(id string) error {
	delete(f.store, id)

	return nil
}

// GetKey implements KeyManager
func (f *InMemoryKeyManager) GetKey(id string) (key *keys.Key, err error) {
	storeKey, err := f.read(id)
	if err != nil {
		return nil, err
	}

	return &storeKey, nil
}

// ListKeys implements KeyManager
func (f *InMemoryKeyManager) ListKeys() ([]*keys.Key, error) {
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

func (f *InMemoryKeyManager) Aggregate(
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

var _ keys.KeyManager = (*InMemoryKeyManager)(nil)

func (f *InMemoryKeyManager) save(id string, key keys.Key) error {
	f.store[id] = keys.Key{
		Id:         key.Id,
		Type:       key.Type,
		PublicKey:  key.PublicKey,
		PrivateKey: key.PrivateKey,
	}

	return nil
}

func (f *InMemoryKeyManager) read(id string) (keys.Key, error) {
	k, ok := f.store[id]
	if !ok {
		return keys.Key{}, errors.Wrap(KeyNotFoundErr, id)
	}

	return keys.Key{
		Id:         k.Id,
		Type:       k.Type,
		PublicKey:  k.PublicKey,
		PrivateKey: k.PrivateKey,
	}, nil
}
