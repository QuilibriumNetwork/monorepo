package store

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type KeyStore interface {
	NewTransaction() (Transaction, error)

	// Identity key operations
	PutIdentityKey(
		txn Transaction,
		address []byte,
		identityKey *protobufs.Ed448PublicKey,
	) error
	GetIdentityKey(address []byte) (*protobufs.Ed448PublicKey, error)

	// Prover key operations
	PutProvingKey(
		txn Transaction,
		address []byte,
		provingKey *protobufs.BLS48581SignatureWithProofOfPossession,
	) error
	GetProvingKey(
		address []byte,
	) (*protobufs.BLS48581SignatureWithProofOfPossession, error)

	// Cross-signature operations
	PutCrossSignature(
		txn Transaction,
		identityKeyAddress []byte,
		provingKeyAddress []byte,
		identityKeySignatureOfProvingKey []byte,
		provingKeySignatureOfIdentityKey []byte,
	) error
	GetCrossSignatureByIdentityKey(identityKeyAddress []byte) ([]byte, error)
	GetCrossSignatureByProvingKey(provingKeyAddress []byte) ([]byte, error)

	// Signed X448 key operations (supports multiple keys per type)
	PutSignedKey(
		txn Transaction,
		address []byte,
		key *protobufs.SignedX448Key,
	) error
	GetSignedKey(
		address []byte,
	) (*protobufs.SignedX448Key, error)
	GetSignedKeysByParent(
		parentKeyAddress []byte,
		keyPurpose string, // Optional filter by purpose
	) ([]*protobufs.SignedX448Key, error)
	DeleteSignedKey(
		txn Transaction,
		address []byte,
	) error
	ReapExpiredKeys() error

	// Key registry operations (for querying complete state)
	GetKeyRegistry(
		identityKeyAddress []byte,
	) (*protobufs.KeyRegistry, error)
	GetKeyRegistryByProver(
		proverKeyAddress []byte,
	) (*protobufs.KeyRegistry, error)

	// Range operations
	RangeProvingKeys() (
		TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession],
		error,
	)
	RangeIdentityKeys() (
		TypedIterator[*protobufs.Ed448PublicKey],
		error,
	)
	RangeSignedKeys(
		parentKeyAddress []byte, // Optional filter
		keyPurpose string, // Optional filter
	) (
		TypedIterator[*protobufs.SignedX448Key],
		error,
	)
}
