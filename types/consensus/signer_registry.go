package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// SignerRegistry manages the registry of signers and their keys
type SignerRegistry interface {
	// GetSigner retrieves a signer entry by address
	GetSigner(address [32]byte) (interface{}, error)

	// GetSignerByPublicKey retrieves a signer entry by BLS public key
	GetSignerByPublicKey(publicKey []byte) (interface{}, error)

	// ValidateProvingKey validates a proving key announcement
	ValidateProvingKey(provingKey *protobufs.ProvingKeyAnnouncement) error

	// ValidateKeyBundle validates a key bundle announcement
	ValidateKeyBundle(bundle *protobufs.KeyBundleAnnouncement) error

	// IncludeProvingKey includes a proving key with an inclusion commitment
	IncludeProvingKey(
		inclusionCommitment *protobufs.InclusionCommitment,
		txn store.Transaction,
	) error

	// StageProvingKey stages a proving key for later inclusion
	StageProvingKey(provingKey *protobufs.ProvingKeyAnnouncement) error

	// PutKeyBundle stores a key bundle with inclusion commitment
	PutKeyBundle(
		provingKey []byte,
		keyBundle *protobufs.InclusionCommitment,
		txn store.Transaction,
	) error

	// GetProvingKey retrieves a proving key by its public key bytes
	GetProvingKey(provingKey []byte) (*protobufs.InclusionCommitment, error)

	// GetLatestKeyBundle retrieves the latest key bundle for a proving key
	GetLatestKeyBundle(provingKey []byte) (*protobufs.InclusionCommitment, error)

	// GetKeyBundle retrieves a specific key bundle at a frame number
	GetKeyBundle(
		provingKey []byte,
		frameNumber uint64,
	) (*protobufs.InclusionCommitment, error)

	// GetStagedProvingKey retrieves a staged proving key
	GetStagedProvingKey(provingKey []byte) (
		*protobufs.ProvingKeyAnnouncement,
		error,
	)
}
