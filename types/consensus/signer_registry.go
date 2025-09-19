package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// SignerRegistry manages the registry of signers and their keys
type SignerRegistry interface {
	// GetKeyRegistry retrieves the complete key registry for an identity key
	// address
	GetKeyRegistry(identityKeyAddress []byte) (*protobufs.KeyRegistry, error)

	// GetKeyRegistryByProver retrieves the complete key registry for a prover key
	// address
	GetKeyRegistryByProver(proverKeyAddress []byte) (
		*protobufs.KeyRegistry,
		error,
	)

	// ValidateIdentityKey validates an Ed448 identity key
	ValidateIdentityKey(identityKey *protobufs.Ed448PublicKey) error

	// ValidateProvingKey validates a BLS48581 proving key with proof of
	// possession
	ValidateProvingKey(
		provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
	) error

	// ValidateSignedKey validates a signed X448 key
	ValidateSignedKey(signedKey *protobufs.SignedX448Key) error

	// PutIdentityKey stores an identity key
	PutIdentityKey(
		txn store.Transaction,
		address []byte,
		identityKey *protobufs.Ed448PublicKey,
	) error

	// PutProvingKey stores a proving key with proof of possession
	PutProvingKey(
		txn store.Transaction,
		address []byte,
		provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
	) error

	// PutCrossSignature stores cross signatures between identity and proving keys
	PutCrossSignature(
		txn store.Transaction,
		identityKeyAddress []byte,
		provingKeyAddress []byte,
		identityKeySignatureOfProvingKey []byte,
		provingKeySignatureOfIdentityKey []byte,
	) error

	// PutSignedKey stores a signed X448 key
	PutSignedKey(
		txn store.Transaction,
		address []byte,
		key *protobufs.SignedX448Key,
	) error

	// GetIdentityKey retrieves an identity key by address
	GetIdentityKey(address []byte) (*protobufs.Ed448PublicKey, error)

	// GetProvingKey retrieves a proving key by address
	GetProvingKey(address []byte) (
		*protobufs.BLS48581SignatureWithProofOfPossession,
		error,
	)

	// GetSignedKey retrieves a signed key by address
	GetSignedKey(address []byte) (*protobufs.SignedX448Key, error)

	// GetSignedKeysByParent retrieves all signed keys for a parent key
	GetSignedKeysByParent(
		parentKeyAddress []byte,
		keyPurpose string, // Optional filter by purpose
	) ([]*protobufs.SignedX448Key, error)

	// RangeProvingKeys returns an iterator over all proving keys
	RangeProvingKeys() (
		store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
		error,
	)

	// RangeIdentityKeys returns an iterator over all identity keys
	RangeIdentityKeys() (
		store.TypedIterator[*protobufs.Ed448PublicKey],
		error,
	)

	// RangeSignedKeys returns an iterator over signed keys
	RangeSignedKeys(
		parentKeyAddress []byte, // Optional filter
		keyPurpose string, // Optional filter
	) (
		store.TypedIterator[*protobufs.SignedX448Key],
		error,
	)
}
