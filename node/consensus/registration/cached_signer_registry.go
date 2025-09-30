package registration

import (
	"encoding/hex"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// SignerEntry represents a cached signer with their key information
type SignerEntry struct {
	Address     [32]byte
	KeyRegistry *protobufs.KeyRegistry
}

// CachedSignerRegistry manages a cache of signers with their keys
type CachedSignerRegistry struct {
	mu                sync.RWMutex
	cache             map[[32]byte]*SignerEntry
	keyStore          store.KeyStore
	keyManager        keys.KeyManager
	blsConstructor    crypto.BlsConstructor
	bulletproofProver crypto.BulletproofProver
	logger            *zap.Logger
}

// NewCachedSignerRegistry creates a new cached signer registry
func NewCachedSignerRegistry(
	keyStore store.KeyStore,
	keyManager keys.KeyManager,
	blsConstructor crypto.BlsConstructor,
	bulletproofProver crypto.BulletproofProver,
	logger *zap.Logger,
) (*CachedSignerRegistry, error) {
	registry := &CachedSignerRegistry{
		cache:             make(map[[32]byte]*SignerEntry),
		keyStore:          keyStore,
		keyManager:        keyManager,
		blsConstructor:    blsConstructor,
		bulletproofProver: bulletproofProver,
		logger:            logger,
	}

	// Initialize the cache by loading existing keys from the store
	if err := registry.loadExistingKeys(); err != nil {
		return nil, errors.Wrap(err, "new cached signer registry")
	}

	return registry, nil
}

// loadExistingKeys iterates over the key store and populates the cache
func (c *CachedSignerRegistry) loadExistingKeys() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Range over identity keys to build cache
	iter, err := c.keyStore.RangeProvingKeys()
	if err != nil {
		return errors.Wrap(err, "load existing keys")
	}

	// Handle nil iterator (e.g., in tests)
	if iter == nil {
		c.logger.Info("no iterator available, skipping key loading")
		return nil
	}

	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		provingKey, err := iter.Value()
		if err != nil {
			continue
		}

		provingKeyAddressBI, err := poseidon.HashBytes(
			provingKey.PublicKey.KeyValue,
		)
		if err != nil {
			continue
		}

		provingKeyAddress := provingKeyAddressBI.FillBytes(make([]byte, 32))

		// Get the full key registry
		registry, err := c.keyStore.GetKeyRegistryByProver(provingKeyAddress)
		if err != nil {
			c.logger.Warn(
				"failed to get key registry",
				zap.String(
					"address",
					hex.EncodeToString(provingKey.PublicKey.KeyValue),
				),
				zap.Error(err),
			)
			continue
		}

		// Create signer entry
		entry := &SignerEntry{
			Address:     [32]byte(provingKeyAddress),
			KeyRegistry: registry,
		}

		// Store in cache
		c.cache[[32]byte(provingKeyAddress)] = entry
		count++
	}

	c.logger.Info("loaded existing keys", zap.Int("count", count))
	return nil
}

// GetKeyRegistry retrieves the complete key registry for an identity key
// address
func (c *CachedSignerRegistry) GetKeyRegistry(
	identityKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	// First check cache
	addressBI, err := poseidon.HashBytes(identityKeyAddress)
	if err != nil {
		return nil, errors.Wrap(err, "get key registry")
	}

	var address [32]byte
	addressBI.FillBytes(address[:])

	c.mu.RLock()
	entry, exists := c.cache[address]
	c.mu.RUnlock()

	if exists && entry.KeyRegistry != nil {
		return entry.KeyRegistry, nil
	}

	// Not in cache, get from store
	registry, err := c.keyStore.GetKeyRegistry(identityKeyAddress)
	if err != nil {
		return nil, errors.Wrap(err, "get key registry")
	}

	// Update cache
	c.mu.Lock()
	c.cache[address] = &SignerEntry{
		Address:     address,
		KeyRegistry: registry,
	}
	c.mu.Unlock()

	return registry, nil
}

// GetKeyRegistryByProver retrieves the complete key registry for a prover key
// address
func (c *CachedSignerRegistry) GetKeyRegistryByProver(
	proverKeyAddress []byte,
) (*protobufs.KeyRegistry, error) {
	return c.keyStore.GetKeyRegistryByProver(proverKeyAddress)
}

// ValidateIdentityKey validates an Ed448 identity key
func (c *CachedSignerRegistry) ValidateIdentityKey(
	identityKey *protobufs.Ed448PublicKey,
) error {
	if err := identityKey.Validate(); err != nil {
		return errors.Wrap(err, "validate identity key")
	}

	return nil
}

// ValidateProvingKey validates a BLS48581 proving key with proof of possession
func (c *CachedSignerRegistry) ValidateProvingKey(
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	if err := provingKey.Validate(); err != nil {
		return errors.Wrap(err, "validate proving key")
	}

	if !c.blsConstructor.VerifySignatureRaw(
		provingKey.PublicKey.KeyValue,
		provingKey.PopSignature,
		provingKey.PublicKey.KeyValue,
		[]byte("BLS48_POP_SK"),
	) {
		return errors.Wrap(errors.New("invalid signature"), "validate proving key")
	}

	return nil
}

// ValidateSignedKey validates a signed X448 key
func (c *CachedSignerRegistry) ValidateSignedKey(
	signedKey *protobufs.SignedX448Key,
) error {
	// First validate the structure
	if err := signedKey.Validate(); err != nil {
		return errors.Wrap(err, "validate signed key")
	}

	// Then verify the signature using the appropriate verifier
	if err := signedKey.Verify(
		[]byte("KEY_REGISTRY"),
		c.blsConstructor,
		c.bulletproofProver,
	); err != nil {
		return errors.Wrap(err, "validate signed key")
	}

	return nil
}

// PutIdentityKey stores an identity key
func (c *CachedSignerRegistry) PutIdentityKey(
	txn store.Transaction,
	address []byte,
	identityKey *protobufs.Ed448PublicKey,
) error {
	// Validate the key
	if err := c.ValidateIdentityKey(identityKey); err != nil {
		return errors.Wrap(err, "put identity key")
	}

	// Store in the key store
	if err := c.keyStore.PutIdentityKey(txn, address, identityKey); err != nil {
		return errors.Wrap(err, "put identity key")
	}

	// Clear cache entry for this address so it's refreshed on next access
	c.mu.Lock()
	addressBI, _ := poseidon.HashBytes(address)
	var cacheAddr [32]byte
	addressBI.FillBytes(cacheAddr[:])
	delete(c.cache, cacheAddr)
	c.mu.Unlock()

	return nil
}

// PutProvingKey stores a proving key with proof of possession
func (c *CachedSignerRegistry) PutProvingKey(
	txn store.Transaction,
	address []byte,
	provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
) error {
	// Validate the key
	if err := c.ValidateProvingKey(provingKey); err != nil {
		return errors.Wrap(err, "put proving key")
	}

	// Store in the key store
	if err := c.keyStore.PutProvingKey(txn, address, provingKey); err != nil {
		return errors.Wrap(err, "put proving key")
	}

	return nil
}

// PutCrossSignature stores cross signatures between identity and proving keys
func (c *CachedSignerRegistry) PutCrossSignature(
	txn store.Transaction,
	identityKeyAddress []byte,
	provingKeyAddress []byte,
	identityKeySignatureOfProvingKey []byte,
	provingKeySignatureOfIdentityKey []byte,
) error {
	// Store in the key store
	err := c.keyStore.PutCrossSignature(
		txn,
		identityKeyAddress,
		provingKeyAddress,
		identityKeySignatureOfProvingKey,
		provingKeySignatureOfIdentityKey,
	)
	if err != nil {
		return errors.Wrap(err, "put cross signature")
	}

	// Clear cache entries for both addresses
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear cache for identity key
	addressBI, _ := poseidon.HashBytes(identityKeyAddress)
	var identityAddr [32]byte
	addressBI.FillBytes(identityAddr[:])
	delete(c.cache, identityAddr)

	// Clear cache for proving key
	provingBI, _ := poseidon.HashBytes(provingKeyAddress)
	var provingAddr [32]byte
	provingBI.FillBytes(provingAddr[:])
	delete(c.cache, provingAddr)

	return nil
}

// PutSignedKey stores a signed X448 key
func (c *CachedSignerRegistry) PutSignedKey(
	txn store.Transaction,
	address []byte,
	key *protobufs.SignedX448Key,
) error {
	// Validate the key
	if err := c.ValidateSignedKey(key); err != nil {
		return errors.Wrap(err, "put signed key")
	}

	// Store in the key store
	if err := c.keyStore.PutSignedKey(txn, address, key); err != nil {
		return errors.Wrap(err, "put signed key")
	}

	// Clear cache entries that might be affected
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear cache for parent key
	addressBI, _ := poseidon.HashBytes(key.ParentKeyAddress)
	var parentAddr [32]byte
	addressBI.FillBytes(parentAddr[:])
	delete(c.cache, parentAddr)

	return nil
}

// GetIdentityKey retrieves an identity key by address
func (c *CachedSignerRegistry) GetIdentityKey(
	address []byte,
) (*protobufs.Ed448PublicKey, error) {
	return c.keyStore.GetIdentityKey(address)
}

// GetProvingKey retrieves a proving key by address
func (c *CachedSignerRegistry) GetProvingKey(
	address []byte,
) (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	return c.keyStore.GetProvingKey(address)
}

// GetSignedKey retrieves a signed key by address
func (c *CachedSignerRegistry) GetSignedKey(
	address []byte,
) (*protobufs.SignedX448Key, error) {
	return c.keyStore.GetSignedKey(address)
}

// GetSignedKeysByParent retrieves all signed keys for a parent key
func (c *CachedSignerRegistry) GetSignedKeysByParent(
	parentKeyAddress []byte,
	keyPurpose string,
) ([]*protobufs.SignedX448Key, error) {
	return c.keyStore.GetSignedKeysByParent(parentKeyAddress, keyPurpose)
}

// RangeProvingKeys returns an iterator over all proving keys
func (c *CachedSignerRegistry) RangeProvingKeys() (
	store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
	error,
) {
	return c.keyStore.RangeProvingKeys()
}

// RangeIdentityKeys returns an iterator over all identity keys
func (c *CachedSignerRegistry) RangeIdentityKeys() (
	store.TypedIterator[*protobufs.Ed448PublicKey],
	error,
) {
	return c.keyStore.RangeIdentityKeys()
}

// RangeSignedKeys returns an iterator over signed keys
func (c *CachedSignerRegistry) RangeSignedKeys(
	parentKeyAddress []byte,
	keyPurpose string,
) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	return c.keyStore.RangeSignedKeys(parentKeyAddress, keyPurpose)
}

// GetAllSigners returns all cached signers
func (c *CachedSignerRegistry) GetAllSigners() map[[32]byte]*SignerEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create a copy of the map to avoid race conditions
	result := make(map[[32]byte]*SignerEntry, len(c.cache))
	for k, v := range c.cache {
		result[k] = v
	}

	return result
}

// GetSignerCount returns the number of cached signers
func (c *CachedSignerRegistry) GetSignerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// ClearCache clears the entire cache
func (c *CachedSignerRegistry) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[[32]byte]*SignerEntry)
}

var _ consensus.SignerRegistry = (*CachedSignerRegistry)(nil)
