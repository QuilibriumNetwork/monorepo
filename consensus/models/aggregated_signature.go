package models

// AggregatedSignature provides a generic interface over an aggregatable
// signature type
type AggregatedSignature interface {
	// GetSignature returns the aggregated signature in raw canonical bytes
	GetSignature() []byte
	// GetPubKey returns the public key in raw canonical bytes
	GetPubKey() []byte
	// GetBitmask returns the bitmask of the signers in the signature, in matching
	// order to the clique's prover set (in ascending ring order).
	GetBitmask() []byte
}

// AggregatedSigner provides a generic interface over an aggregatable signature
// scheme. Embeds the validation-only methods.
type AggregatedSigner interface {
	AggregatedSignatureValidator
	// AggregateSignatures produces an AggregatedSignature object, expecting
	// public keys and signatures to be in matching order, with nil slices for
	// bitmask entries that are not present. The order should be aligned to the
	// clique's prover set (in ascending ring order).
	AggregateSignatures(
		publicKeys [][]byte,
		signatures [][]byte,
	) (AggregatedSignature, error)
	// SignWithContext produces an AggregatedSignature object, optionally taking
	// an existing AggregatedSignature and builds on top of it.
	SignWithContext(
		aggregatedSignature AggregatedSignature,
		bitmaskIndex int,
		privateKey []byte,
		message []byte,
		context []byte,
	) (AggregatedSignature, error)
}

// AggregatedSignatureValidator provides a generic interface over aggregated
// signature validation.
type AggregatedSignatureValidator interface {
	// VerifySignature validates the AggregatedSignature, with a binary pass/fail
	// result.
	VerifySignature(
		aggregatedSignature AggregatedSignature,
		message []byte,
		context []byte,
	) bool
}
