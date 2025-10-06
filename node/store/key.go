package store

import (
	"encoding/binary"
	"math/big"
	"slices"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type PebbleKeyStore struct {
	db     store.KVDB
	logger *zap.Logger
}

type PebbleIdentityKeyIterator struct {
	i store.Iterator
}

type PebbleProvingKeyIterator struct {
	i store.Iterator
}

type PebbleSignedX448KeyIterator struct {
	i  store.Iterator
	db *PebbleKeyStore
}

type PebbleSignedDecaf448KeyIterator struct {
	i  store.Iterator
	db *PebbleKeyStore
}

var _ store.TypedIterator[*protobufs.Ed448PublicKey] = (*PebbleIdentityKeyIterator)(nil)
var _ store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession] = (*PebbleProvingKeyIterator)(nil)
var _ store.TypedIterator[*protobufs.SignedX448Key] = (*PebbleSignedX448KeyIterator)(nil)
var _ store.TypedIterator[*protobufs.SignedDecaf448Key] = (*PebbleSignedDecaf448KeyIterator)(nil)
var _ store.KeyStore = (*PebbleKeyStore)(nil)

// Identity key iterator methods
func (p *PebbleIdentityKeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleIdentityKeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleIdentityKeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleIdentityKeyIterator) Value() (
	*protobufs.Ed448PublicKey,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	key := &protobufs.Ed448PublicKey{}
	if err := proto.Unmarshal(value, key); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get identity key iterator value",
		)
	}

	return key, nil
}

func (p *PebbleIdentityKeyIterator) TruncatedValue() (
	*protobufs.Ed448PublicKey,
	error,
) {
	return p.Value()
}

func (p *PebbleIdentityKeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

// Proving key iterator methods
func (p *PebbleProvingKeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleProvingKeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleProvingKeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleProvingKeyIterator) Value() (
	*protobufs.BLS48581SignatureWithProofOfPossession,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	value := p.i.Value()
	sig := &protobufs.BLS48581SignatureWithProofOfPossession{}
	if err := proto.Unmarshal(value, sig); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get proving key iterator value",
		)
	}

	return sig, nil
}

func (p *PebbleProvingKeyIterator) TruncatedValue() (
	*protobufs.BLS48581SignatureWithProofOfPossession,
	error,
) {
	return p.Value()
}

func (p *PebbleProvingKeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

// Signed key iterator methods
func (p *PebbleSignedX448KeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleSignedX448KeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleSignedX448KeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleSignedX448KeyIterator) Value() (
	*protobufs.SignedX448Key,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	key := p.i.Key()[len(p.i.Key())-32:]

	signedKey, err := p.db.GetSignedX448Key(key)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get signed key iterator value",
		)
	}

	return signedKey, nil
}

func (p *PebbleSignedX448KeyIterator) TruncatedValue() (
	*protobufs.SignedX448Key,
	error,
) {
	return p.Value()
}

func (p *PebbleSignedX448KeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

func (p *PebbleSignedDecaf448KeyIterator) First() bool {
	return p.i.First()
}

func (p *PebbleSignedDecaf448KeyIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleSignedDecaf448KeyIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleSignedDecaf448KeyIterator) Value() (
	*protobufs.SignedDecaf448Key,
	error,
) {
	if !p.i.Valid() {
		return nil, store.ErrNotFound
	}

	key := p.i.Key()[len(p.i.Key())-32:]

	signedKey, err := p.db.GetSignedDecaf448Key(key)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, store.ErrInvalidData.Error()),
			"get signed key iterator value",
		)
	}

	return signedKey, nil
}

func (p *PebbleSignedDecaf448KeyIterator) TruncatedValue() (
	*protobufs.SignedDecaf448Key,
	error,
) {
	return p.Value()
}

func (p *PebbleSignedDecaf448KeyIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing iterator")
}

func NewPebbleKeyStore(db store.KVDB, logger *zap.Logger) *PebbleKeyStore {
	return &PebbleKeyStore{
		db,
		logger,
	}
}

func identityKeyKey(identityKey []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_IDENTITY}
	key = append(key, identityKey...)
	return key
}

func provingKeyKey(provingKey []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_PROVING}
	key = append(key, provingKey...)
	return key
}

func crossSignatureKey(
	signingAddress []byte,
) []byte {
	key := []byte{KEY_BUNDLE, KEY_CROSS_SIGNATURE}
	key = append(key, signingAddress...)
	return key
}

func signedX448KeyKey(address []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_ID}
	key = append(key, address...)
	return key
}

func signedX448KeyByParentKey(
	parentKeyAddress []byte,
	keyPurpose string,
	keyAddress []byte,
) []byte {
	purpose := make([]byte, 8)
	copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

	key := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT}
	key = append(key, parentKeyAddress...)
	key = append(key, purpose...)
	key = append(key, keyAddress...)
	return key
}

func signedX448KeyByPurposeKey(keyPurpose string, keyAddress []byte) []byte {
	purpose := make([]byte, 8)
	copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

	key := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PURPOSE}
	key = append(key, purpose...)
	key = append(key, keyAddress...)
	return key
}

func signedX448KeyExpiryKey(expiresAt uint64, keyAddress []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_EXPIRY}
	key = binary.BigEndian.AppendUint64(key, expiresAt)
	key = append(key, keyAddress...)
	return key
}

func signedDecaf448KeyKey(address []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_ID}
	key = append(key, address...)
	return key
}

func signedDecaf448KeyByParentKey(
	parentKeyAddress []byte,
	keyPurpose string,
	keyAddress []byte,
) []byte {
	purpose := make([]byte, 8)
	copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

	key := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT}
	key = append(key, parentKeyAddress...)
	key = append(key, purpose...)
	key = append(key, keyAddress...)
	return key
}

func signedDecaf448KeyByPurposeKey(keyPurpose string, keyAddress []byte) []byte {
	purpose := make([]byte, 8)
	copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

	key := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PURPOSE}
	key = append(key, purpose...)
	key = append(key, keyAddress...)
	return key
}

func signedDecaf448KeyExpiryKey(expiresAt uint64, keyAddress []byte) []byte {
	key := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_EXPIRY}
	key = binary.BigEndian.AppendUint64(key, expiresAt)
	key = append(key, keyAddress...)
	return key
}

func (p *PebbleKeyStore) NewTransaction() (store.Transaction, error) {
	return p.db.NewBatch(false), nil
}

// PutIdentityKey stores an identity key
func (p *PebbleKeyStore) PutIdentityKey(
	txn store.Transaction,
	address []byte,
	identityKey *protobufs.Ed448PublicKey,
) error {
	data, err := proto.Marshal(identityKey)
	if err != nil {
		return errors.Wrap(err, "put identity key")
	}

	if err := txn.Set(identityKeyKey(address), data); err != nil {
		return errors.Wrap(err, "put identity key")
	}

	return nil
}

// GetIdentityKey retrieves an identity key by address
func (p *PebbleKeyStore) GetIdentityKey(address []byte) (
	*protobufs.Ed448PublicKey,
	error,
) {
	value, closer, err := p.db.Get(identityKeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get identity key")
	}
	defer closer.Close()

	key := &protobufs.Ed448PublicKey{}
	if err := proto.Unmarshal(value, key); err != nil {
		return nil, errors.Wrap(err, "get identity key")
	}

	return key, nil
}

// PutProvingKey stores a proving key with proof of possession
func (p *PebbleKeyStore) PutProvingKey(
	txn store.Transaction,
	address []byte,
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	data, err := proto.Marshal(provingKey)
	if err != nil {
		return errors.Wrap(err, "put proving key")
	}

	if err := txn.Set(provingKeyKey(address), data); err != nil {
		return errors.Wrap(err, "put proving key")
	}

	return nil
}

// GetProvingKey retrieves a proving key by address
func (p *PebbleKeyStore) GetProvingKey(
	address []byte,
) (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	value, closer, err := p.db.Get(provingKeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get proving key")
	}
	defer closer.Close()

	sig := &protobufs.BLS48581SignatureWithProofOfPossession{}
	if err := proto.Unmarshal(value, sig); err != nil {
		return nil, errors.Wrap(err, "get proving key")
	}

	return sig, nil
}

// PutCrossSignature stores the cross signatures between identity and proving
// keys
func (p *PebbleKeyStore) PutCrossSignature(
	txn store.Transaction,
	identityKeyAddress []byte,
	provingKeyAddress []byte,
	identityKeySignatureOfProvingKey []byte,
	provingKeySignatureOfIdentityKey []byte,
) error {
	// Store identity to prover signature
	if err := txn.Set(
		crossSignatureKey(identityKeyAddress),
		slices.Concat(provingKeyAddress, identityKeySignatureOfProvingKey),
	); err != nil {
		return errors.Wrap(err, "put cross signature")
	}

	// Store prover to identity signature
	if err := txn.Set(
		crossSignatureKey(provingKeyAddress),
		slices.Concat(identityKeyAddress, provingKeySignatureOfIdentityKey),
	); err != nil {
		return errors.Wrap(err, "put cross signature")
	}

	return nil
}

// GetCrossSignatureByIdentityKey retrieves the cross signature for an identity
// key
func (p *PebbleKeyStore) GetCrossSignatureByIdentityKey(
	identityKeyAddress []byte,
) ([]byte, error) {
	prefix := crossSignatureKey(identityKeyAddress)
	value, closer, err := p.db.Get(prefix)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get cross signature by identity key")
	}
	defer closer.Close()

	payload := make([]byte, len(value))
	copy(payload, value)

	return payload, nil
}

// GetCrossSignatureByProvingKey retrieves the cross signature for a proving key
func (p *PebbleKeyStore) GetCrossSignatureByProvingKey(
	provingKeyAddress []byte,
) ([]byte, error) {
	prefix := crossSignatureKey(provingKeyAddress)
	value, closer, err := p.db.Get(prefix)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get cross signature by proving key")
	}
	defer closer.Close()

	payload := make([]byte, len(value))
	copy(payload, value)

	return payload, nil
}

// RangeProvingKeys returns an iterator over all proving keys
func (p *PebbleKeyStore) RangeProvingKeys() (
	store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
	error,
) {
	startKey := []byte{KEY_BUNDLE, KEY_PROVING}
	endKey := []byte{KEY_BUNDLE, KEY_PROVING + 1}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "range proving keys")
	}

	return &PebbleProvingKeyIterator{i: iter}, nil
}

// RangeIdentityKeys returns an iterator over all identity keys
func (p *PebbleKeyStore) RangeIdentityKeys() (
	store.TypedIterator[*protobufs.Ed448PublicKey],
	error,
) {
	startKey := []byte{KEY_BUNDLE, KEY_IDENTITY}
	endKey := []byte{KEY_BUNDLE, KEY_IDENTITY + 1}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "range identity keys")
	}

	return &PebbleIdentityKeyIterator{i: iter}, nil
}

// PutSignedX448Key stores a signed X448 key
func (p *PebbleKeyStore) PutSignedX448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedX448Key,
) error {
	data, err := proto.Marshal(key)
	if err != nil {
		return errors.Wrap(err, "put signed x448 key")
	}

	// Store by address
	if err := txn.Set(signedX448KeyKey(address), data); err != nil {
		return errors.Wrap(err, "put signed x448 key")
	}

	// Store by parent key index
	if err := txn.Set(
		signedX448KeyByParentKey(key.ParentKeyAddress, key.KeyPurpose, address),
		[]byte{0x01}, // Just a marker
	); err != nil {
		return errors.Wrap(err, "put signed x448 key")
	}

	// Store by purpose index
	if err := txn.Set(
		signedX448KeyByPurposeKey(key.KeyPurpose, address),
		[]byte{0x01}, // Just a marker
	); err != nil {
		return errors.Wrap(err, "put signed x448 key")
	}

	// Store by expiry if set
	if key.ExpiresAt > 0 {
		if err := txn.Set(
			signedX448KeyExpiryKey(key.ExpiresAt, address),
			[]byte{0x01}, // Just a marker
		); err != nil {
			return errors.Wrap(err, "put signed x448 key")
		}
	}

	return nil
}

// PutSignedDecaf448Key stores a signed Decaf448 key
func (p *PebbleKeyStore) PutSignedDecaf448Key(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedDecaf448Key,
) error {
	data, err := proto.Marshal(key)
	if err != nil {
		return errors.Wrap(err, "put signed decaf448 key")
	}

	// Store by address
	if err := txn.Set(signedDecaf448KeyKey(address), data); err != nil {
		return errors.Wrap(err, "put signed decaf448 key")
	}

	// Store by parent key index
	if err := txn.Set(
		signedDecaf448KeyByParentKey(key.ParentKeyAddress, key.KeyPurpose, address),
		[]byte{0x01}, // Just a marker
	); err != nil {
		return errors.Wrap(err, "put signed decaf448 key")
	}

	// Store by purpose index
	if err := txn.Set(
		signedDecaf448KeyByPurposeKey(key.KeyPurpose, address),
		[]byte{0x01}, // Just a marker
	); err != nil {
		return errors.Wrap(err, "put signed decaf448 key")
	}

	// Store by expiry if set
	if key.ExpiresAt > 0 {
		if err := txn.Set(
			signedDecaf448KeyExpiryKey(key.ExpiresAt, address),
			[]byte{0x01}, // Just a marker
		); err != nil {
			return errors.Wrap(err, "put signed decaf448 key")
		}
	}

	return nil
}

// GetSignedX448Key retrieves a signed key by address
func (p *PebbleKeyStore) GetSignedX448Key(
	address []byte,
) (*protobufs.SignedX448Key, error) {
	value, closer, err := p.db.Get(signedX448KeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get signed x448 key")
	}
	defer closer.Close()

	key := &protobufs.SignedX448Key{}
	if err := proto.Unmarshal(value, key); err != nil {
		return nil, errors.Wrap(err, "get signed x448 key")
	}

	return key, nil
}

// GetSignedDecaf448Key retrieves a signed key by address
func (p *PebbleKeyStore) GetSignedDecaf448Key(
	address []byte,
) (*protobufs.SignedDecaf448Key, error) {
	value, closer, err := p.db.Get(signedDecaf448KeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, errors.Wrap(err, "get signed decaf448 key")
	}
	defer closer.Close()

	key := &protobufs.SignedDecaf448Key{}
	if err := proto.Unmarshal(value, key); err != nil {
		return nil, errors.Wrap(err, "get signed decaf448 key")
	}

	return key, nil
}

// GetSignedX448KeysByParent retrieves all signed keys for a parent key,
// optionally filtered by purpose
func (p *PebbleKeyStore) GetSignedX448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedX448Key, error) {
	var prefix []byte
	if keyPurpose != "" {
		// Create prefix without keyId to get all keys of this purpose
		purpose := make([]byte, 8)
		copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

		prefix = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT}
		prefix = append(prefix, parentKeyAddress...)
		prefix = append(prefix, purpose...)
	} else {
		prefix = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT}
		prefix = append(prefix, parentKeyAddress...)
	}

	endPrefixBI := new(big.Int).SetBytes(prefix)
	endPrefixBI.Add(endPrefixBI, big.NewInt(1))

	iter, err := p.db.NewIter(prefix, endPrefixBI.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "get signed x448 keys by parent")
	}
	defer iter.Close()

	var keys []*protobufs.SignedX448Key
	for iter.First(); iter.Valid(); iter.Next() {
		keyAddress := iter.Key()[len(iter.Key())-32:]

		// Get the actual key data
		keyData, closer, err := p.db.Get(signedX448KeyKey(keyAddress))
		if err != nil {
			continue
		}

		key := &protobufs.SignedX448Key{}
		if err := proto.Unmarshal(keyData, key); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		keys = append(keys, key)
	}

	return keys, nil
}

// GetSignedDecaf448KeysByParent retrieves all signed keys for a parent key,
// optionally filtered by purpose
func (p *PebbleKeyStore) GetSignedDecaf448KeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedDecaf448Key, error) {
	var prefix []byte
	if keyPurpose != "" {
		// Create prefix without keyId to get all keys of this purpose
		purpose := make([]byte, 8)
		copy(purpose[:len(keyPurpose)], []byte(keyPurpose))

		prefix = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT}
		prefix = append(prefix, parentKeyAddress...)
		prefix = append(prefix, purpose...)
	} else {
		prefix = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT}
		prefix = append(prefix, parentKeyAddress...)
	}

	endPrefixBI := new(big.Int).SetBytes(prefix)
	endPrefixBI.Add(endPrefixBI, big.NewInt(1))

	iter, err := p.db.NewIter(prefix, endPrefixBI.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "get signed decaf448 keys by parent")
	}
	defer iter.Close()

	var keys []*protobufs.SignedDecaf448Key
	for iter.First(); iter.Valid(); iter.Next() {
		keyAddress := iter.Key()[len(iter.Key())-32:]

		// Get the actual key data
		keyData, closer, err := p.db.Get(signedDecaf448KeyKey(keyAddress))
		if err != nil {
			continue
		}

		key := &protobufs.SignedDecaf448Key{}
		if err := proto.Unmarshal(keyData, key); err != nil {
			closer.Close()
			continue
		}
		closer.Close()

		keys = append(keys, key)
	}

	return keys, nil
}

// DeleteSignedX448Key removes a signed key
func (p *PebbleKeyStore) DeleteSignedX448Key(
	txn store.Transaction,
	address []byte,
) error {
	// First get the key to extract metadata for index deletion
	value, closer, err := p.db.Get(signedX448KeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return store.ErrNotFound
		}
		return errors.Wrap(err, "delete signed x448 key")
	}
	defer closer.Close()

	key := &protobufs.SignedX448Key{}
	if err := proto.Unmarshal(value, key); err != nil {
		return errors.Wrap(err, "delete signed x448 key")
	}

	// Delete all indexes
	if err := txn.Delete(signedX448KeyKey(address)); err != nil {
		return errors.Wrap(err, "delete signed x448 key")
	}

	if err := txn.Delete(
		signedX448KeyByParentKey(key.ParentKeyAddress, key.KeyPurpose, address),
	); err != nil {
		return errors.Wrap(err, "delete signed x448 key")
	}

	if err := txn.Delete(
		signedX448KeyByPurposeKey(key.KeyPurpose, address),
	); err != nil {
		return errors.Wrap(err, "delete signed x448 key")
	}

	if key.ExpiresAt > 0 {
		if err := txn.Delete(
			signedX448KeyExpiryKey(key.ExpiresAt, address),
		); err != nil {
			return errors.Wrap(err, "delete signed x448 key")
		}
	}

	return nil
}

// DeleteSignedDecaf448Key removes a signed key
func (p *PebbleKeyStore) DeleteSignedDecaf448Key(
	txn store.Transaction,
	address []byte,
) error {
	// First get the key to extract metadata for index deletion
	value, closer, err := p.db.Get(signedDecaf448KeyKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return store.ErrNotFound
		}
		return errors.Wrap(err, "delete signed decaf448 key")
	}
	defer closer.Close()

	key := &protobufs.SignedDecaf448Key{}
	if err := proto.Unmarshal(value, key); err != nil {
		return errors.Wrap(err, "delete signed decaf448 key")
	}

	// Delete all indexes
	if err := txn.Delete(signedDecaf448KeyKey(address)); err != nil {
		return errors.Wrap(err, "delete signed decaf448 key")
	}

	if err := txn.Delete(
		signedDecaf448KeyByParentKey(key.ParentKeyAddress, key.KeyPurpose, address),
	); err != nil {
		return errors.Wrap(err, "delete signed decaf448 key")
	}

	if err := txn.Delete(
		signedDecaf448KeyByPurposeKey(key.KeyPurpose, address),
	); err != nil {
		return errors.Wrap(err, "delete signed decaf448 key")
	}

	if key.ExpiresAt > 0 {
		if err := txn.Delete(
			signedDecaf448KeyExpiryKey(key.ExpiresAt, address),
		); err != nil {
			return errors.Wrap(err, "delete signed decaf448 key")
		}
	}

	return nil
}

// ReapExpiredKeys removes all expired keys
func (p *PebbleKeyStore) ReapExpiredKeys() error {
	currentTime := uint64(time.Now().Unix())

	// Iterate through all keys with expiry
	prefix := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_EXPIRY}
	endPrefix := []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_EXPIRY + 1}
	iter, err := p.db.NewIter(prefix, endPrefix)
	if err != nil {
		return errors.Wrap(err, "reap expired keys")
	}
	defer iter.Close()

	txn, err := p.NewTransaction()
	if err != nil {
		return errors.Wrap(err, "reap expired keys")
	}

	deletedCount := 0
	for iter.First(); iter.Valid(); iter.Next() {
		indexKey := iter.Key()

		// Extract expiry time
		if len(indexKey) < len(prefix)+8 {
			continue
		}
		expiryTime := binary.BigEndian.Uint64(indexKey[len(prefix) : len(prefix)+8])

		// If not expired, we can stop (keys are sorted by expiry)
		if expiryTime > currentTime {
			break
		}

		// Extract key address
		keyAddress := indexKey[len(prefix)+8:]

		// Delete the key
		if err := p.DeleteSignedX448Key(txn, keyAddress); err != nil {
			p.logger.Warn("failed to delete expired key", zap.Error(err))
			continue
		}

		deletedCount++
	}

	// Iterate through all decaf keys with expiry
	decafPrefix := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_EXPIRY}
	decafEndPrefix := []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_EXPIRY + 1}
	decafIter, err := p.db.NewIter(decafPrefix, decafEndPrefix)
	if err != nil {
		return errors.Wrap(err, "reap expired keys")
	}
	defer decafIter.Close()
	for decafIter.First(); decafIter.Valid(); decafIter.Next() {
		indexKey := decafIter.Key()

		// Extract expiry time
		if len(indexKey) < len(prefix)+8 {
			continue
		}
		expiryTime := binary.BigEndian.Uint64(indexKey[len(prefix) : len(prefix)+8])

		// If not expired, we can stop (keys are sorted by expiry)
		if expiryTime > currentTime {
			break
		}

		// Extract key address
		keyAddress := indexKey[len(prefix)+8:]

		// Delete the key
		if err := p.DeleteSignedDecaf448Key(txn, keyAddress); err != nil {
			p.logger.Warn("failed to delete expired key", zap.Error(err))
			continue
		}

		deletedCount++
	}

	if deletedCount > 0 {
		if err := txn.Commit(); err != nil {
			return errors.Wrap(err, "reap expired keys")
		}
		p.logger.Info("reaped expired keys", zap.Int("count", deletedCount))
	}

	return nil
}

// GetKeyRegistry retrieves the complete key registry for an identity key
// address
func (p *PebbleKeyStore) GetKeyRegistry(
	identityKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	registry := &protobufs.KeyRegistry{
		KeysByPurpose: make(map[string]*protobufs.KeyCollection),
	}

	// Get identity key
	identityKey, err := p.GetIdentityKey(identityKeyAddress)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get key registry")
	} else {
		registry.IdentityKey = identityKey
	}

	// Find prover key via cross signatures
	crossSigData, err := p.GetCrossSignatureByIdentityKey(identityKeyAddress)
	if err == nil && len(crossSigData) > 0 {
		proverKeyAddress := crossSigData[:32]

		// Get the prover key
		proverKey, err := p.GetProvingKey(proverKeyAddress)
		if err == nil {
			registry.ProverKey = proverKey.PublicKey

			// Get the signatures
			registry.IdentityToProver = &protobufs.Ed448Signature{
				Signature: crossSigData[32:],
			}

			// Get reverse signature
			proverSigData, err := p.GetCrossSignatureByProvingKey(proverKeyAddress)
			if err == nil {
				registry.ProverToIdentity = &protobufs.BLS48581Signature{
					Signature: proverSigData[32:],
				}
			}
		}
	}

	// Get all signed keys by parent (identity key)
	allKeys, err := p.GetSignedX448KeysByParent(identityKeyAddress, "")
	if err == nil {
		// Group by purpose
		for _, key := range allKeys {
			if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
				registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
					KeyPurpose:   key.KeyPurpose,
					X448Keys:     []*protobufs.SignedX448Key{},
					Decaf448Keys: []*protobufs.SignedDecaf448Key{},
				}
			}
			registry.KeysByPurpose[key.KeyPurpose].X448Keys = append(
				registry.KeysByPurpose[key.KeyPurpose].X448Keys, key,
			)
			if registry.LastUpdated < key.CreatedAt {
				registry.LastUpdated = key.CreatedAt
			}
		}
	}

	// If we have a prover key, also get keys signed by it
	if registry.ProverKey != nil && len(crossSigData) > 0 {
		proverKeyAddress := crossSigData[:32]
		proverKeys, err := p.GetSignedX448KeysByParent(proverKeyAddress, "")
		if err == nil {
			for _, key := range proverKeys {
				if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
					registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
						KeyPurpose:   key.KeyPurpose,
						X448Keys:     []*protobufs.SignedX448Key{},
						Decaf448Keys: []*protobufs.SignedDecaf448Key{},
					}
				}
				registry.KeysByPurpose[key.KeyPurpose].X448Keys = append(
					registry.KeysByPurpose[key.KeyPurpose].X448Keys, key,
				)
				if registry.LastUpdated < key.CreatedAt {
					registry.LastUpdated = key.CreatedAt
				}
			}
		}
	}

	// Get all signed keys by parent (identity key)
	allDecafKeys, err := p.GetSignedDecaf448KeysByParent(identityKeyAddress, "")
	if err == nil {
		// Group by purpose
		for _, key := range allDecafKeys {
			if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
				registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
					KeyPurpose:   key.KeyPurpose,
					X448Keys:     []*protobufs.SignedX448Key{},
					Decaf448Keys: []*protobufs.SignedDecaf448Key{},
				}
			}
			registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys = append(
				registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys, key,
			)
			if registry.LastUpdated < key.CreatedAt {
				registry.LastUpdated = key.CreatedAt
			}
		}
	}

	// If we have a prover key, also get keys signed by it
	if registry.ProverKey != nil && len(crossSigData) > 0 {
		proverKeyAddress := crossSigData[:32]
		proverKeys, err := p.GetSignedDecaf448KeysByParent(proverKeyAddress, "")
		if err == nil {
			for _, key := range proverKeys {
				if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
					registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
						KeyPurpose:   key.KeyPurpose,
						X448Keys:     []*protobufs.SignedX448Key{},
						Decaf448Keys: []*protobufs.SignedDecaf448Key{},
					}
				}
				registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys = append(
					registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys, key,
				)
				if registry.LastUpdated < key.CreatedAt {
					registry.LastUpdated = key.CreatedAt
				}
			}
		}
	}

	return registry, nil
}

// GetKeyRegistryByProver retrieves the complete key registry for a prover key
// address
func (p *PebbleKeyStore) GetKeyRegistryByProver(
	proverKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	registry := &protobufs.KeyRegistry{
		KeysByPurpose: make(map[string]*protobufs.KeyCollection),
	}

	// Get identity key
	provingKey, err := p.GetProvingKey(proverKeyAddress)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, store.ErrNotFound
		}

		return nil, errors.Wrap(err, "get key registry")
	} else {
		registry.ProverKey = provingKey.PublicKey
	}

	// Find identity key via cross signatures
	crossSigData, err := p.GetCrossSignatureByProvingKey(proverKeyAddress)
	if err == nil && len(crossSigData) > 0 {
		identityKeyAddress := crossSigData[:32]

		// Get the identity key
		identityKey, err := p.GetIdentityKey(identityKeyAddress)
		if err == nil {
			registry.IdentityKey = identityKey

			// Get the signatures
			registry.IdentityToProver = &protobufs.Ed448Signature{
				Signature: crossSigData[32:],
			}

			// Get reverse signature
			proverSigData, err := p.GetCrossSignatureByProvingKey(proverKeyAddress)
			if err == nil {
				registry.ProverToIdentity = &protobufs.BLS48581Signature{
					Signature: proverSigData[32:],
				}
			}
		}
	}

	// Get all signed keys by parent (prover key)
	allKeys, err := p.GetSignedX448KeysByParent(proverKeyAddress, "")
	if err == nil {
		// Group by purpose
		for _, key := range allKeys {
			if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
				registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
					KeyPurpose:   key.KeyPurpose,
					X448Keys:     []*protobufs.SignedX448Key{},
					Decaf448Keys: []*protobufs.SignedDecaf448Key{},
				}
			}
			registry.KeysByPurpose[key.KeyPurpose].X448Keys = append(
				registry.KeysByPurpose[key.KeyPurpose].X448Keys, key,
			)
			if registry.LastUpdated < key.CreatedAt {
				registry.LastUpdated = key.CreatedAt
			}
		}
	}

	// If we have a prover key, also get keys signed by it
	if registry.ProverKey != nil && len(crossSigData) > 0 {
		proverKeyAddress := crossSigData[:32]
		proverKeys, err := p.GetSignedX448KeysByParent(proverKeyAddress, "")
		if err == nil {
			for _, key := range proverKeys {
				if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
					registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
						KeyPurpose:   key.KeyPurpose,
						X448Keys:     []*protobufs.SignedX448Key{},
						Decaf448Keys: []*protobufs.SignedDecaf448Key{},
					}
				}
				registry.KeysByPurpose[key.KeyPurpose].X448Keys = append(
					registry.KeysByPurpose[key.KeyPurpose].X448Keys, key,
				)
				if registry.LastUpdated < key.CreatedAt {
					registry.LastUpdated = key.CreatedAt
				}
			}
		}
	}

	// Get all signed keys by parent (prover key)
	allDecafKeys, err := p.GetSignedDecaf448KeysByParent(proverKeyAddress, "")
	if err == nil {
		// Group by purpose
		for _, key := range allDecafKeys {
			if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
				registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
					KeyPurpose:   key.KeyPurpose,
					X448Keys:     []*protobufs.SignedX448Key{},
					Decaf448Keys: []*protobufs.SignedDecaf448Key{},
				}
			}
			registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys = append(
				registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys, key,
			)
			if registry.LastUpdated < key.CreatedAt {
				registry.LastUpdated = key.CreatedAt
			}
		}
	}

	// If we have a prover key, also get keys signed by it
	if registry.ProverKey != nil && len(crossSigData) > 0 {
		proverKeyAddress := crossSigData[:32]
		proverKeys, err := p.GetSignedDecaf448KeysByParent(proverKeyAddress, "")
		if err == nil {
			for _, key := range proverKeys {
				if _, exists := registry.KeysByPurpose[key.KeyPurpose]; !exists {
					registry.KeysByPurpose[key.KeyPurpose] = &protobufs.KeyCollection{
						KeyPurpose:   key.KeyPurpose,
						X448Keys:     []*protobufs.SignedX448Key{},
						Decaf448Keys: []*protobufs.SignedDecaf448Key{},
					}
				}
				registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys = append(
					registry.KeysByPurpose[key.KeyPurpose].Decaf448Keys, key,
				)
				if registry.LastUpdated < key.CreatedAt {
					registry.LastUpdated = key.CreatedAt
				}
			}
		}
	}

	return registry, nil
}

// RangeSignedX448Keys returns an iterator over signed keys, optionally filtered
func (p *PebbleKeyStore) RangeSignedX448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	var startKey, endKey []byte

	if parentKeyAddress != nil && keyPurpose != "" {
		// Range for specific parent and purpose
		startKey = signedX448KeyByParentKey(
			parentKeyAddress,
			keyPurpose,
			[]byte{0x00},
		)
		endKey = signedX448KeyByParentKey(
			parentKeyAddress,
			keyPurpose,
			[]byte{0xff},
		)
	} else if parentKeyAddress != nil {
		// Range for specific parent, all purposes
		startKey = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT}
		startKey = append(startKey, parentKeyAddress...)
		endKey = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_PARENT}
		endKey = append(endKey, parentKeyAddress...)
		endKey = append(endKey, 0xff)
	} else if keyPurpose != "" {
		// Range for specific purpose, all parents
		startKey = signedX448KeyByPurposeKey(keyPurpose, []byte{0x00})
		endKey = signedX448KeyByPurposeKey(keyPurpose, []byte{0xff})
	} else {
		// Range all signed keys
		startKey = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_ID}
		endKey = []byte{KEY_BUNDLE, KEY_X448_SIGNED_KEY_BY_ID + 1}
	}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "range signed keys")
	}

	return &PebbleSignedX448KeyIterator{i: iter, db: p}, nil
}

// RangeSignedDecaf448Keys returns an iterator over signed keys, optionally
// filtered
func (p *PebbleKeyStore) RangeSignedDecaf448Keys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedDecaf448Key], error) {
	var startKey, endKey []byte

	if parentKeyAddress != nil && keyPurpose != "" {
		// Range for specific parent and purpose
		startKey = signedDecaf448KeyByParentKey(
			parentKeyAddress,
			keyPurpose,
			[]byte{0x00},
		)
		endKey = signedDecaf448KeyByParentKey(
			parentKeyAddress,
			keyPurpose,
			[]byte{0xff},
		)
	} else if parentKeyAddress != nil {
		// Range for specific parent, all purposes
		startKey = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT}
		startKey = append(startKey, parentKeyAddress...)
		endKey = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_PARENT}
		endKey = append(endKey, parentKeyAddress...)
		endKey = append(endKey, 0xff)
	} else if keyPurpose != "" {
		// Range for specific purpose, all parents
		startKey = signedDecaf448KeyByPurposeKey(keyPurpose, []byte{0x00})
		endKey = signedDecaf448KeyByPurposeKey(keyPurpose, []byte{0xff})
	} else {
		// Range all signed keys
		startKey = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_ID}
		endKey = []byte{KEY_BUNDLE, KEY_DECAF448_SIGNED_KEY_BY_ID + 1}
	}

	iter, err := p.db.NewIter(startKey, endKey)
	if err != nil {
		return nil, errors.Wrap(err, "range signed keys")
	}

	return &PebbleSignedDecaf448KeyIterator{i: iter, db: p}, nil
}
