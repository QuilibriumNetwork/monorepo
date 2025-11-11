package models

type Identity = string

// Unique defines important attributes for distinguishing relative basis of
// items.
type Unique interface {
	// Identity provides the relevant identity of the given Unique.
	Identity() Identity
	// Clone should provide a shallow clone of the Unique.
	Clone() Unique
	// GetRank indicates the ordinal basis of comparison.
	GetRank() uint64
	// Source provides the relevant identity of who issued the given Unique.
	Source() Identity
	// GetTimestamp provides the relevant timestamp of the given Unique.
	GetTimestamp() uint64
	// GetSignature provides the signature of the given Unique (if present).
	GetSignature() []byte
}

type WeightedIdentity interface {
	PublicKey() []byte
	Identity() Identity
	Weight() uint64
}
