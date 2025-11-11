package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// WeightedSignatureAggregator aggregates signatures of the same signature
// scheme and the same message from different signers. The public keys and
// message are agreed upon upfront. It is also recommended to only aggregate
// signatures generated with keys representing equivalent security-bit level.
// Furthermore, a weight [unsigned int64] is assigned to each signer ID. The
// WeightedSignatureAggregator internally tracks the total weight of all
// collected signatures. Implementations must be concurrency safe.
type WeightedSignatureAggregator interface {
	// Verify verifies the signature under the stored public keys and message.
	// Expected errors during normal operations:
	//  - model.InvalidSignerError if signerID is invalid (not a consensus
	//    participant)
	//  - model.ErrInvalidSignature if signerID is valid but signature is
	//    cryptographically invalid
	Verify(signerID models.Identity, sig []byte) error

	// TrustedAdd adds a signature to the internal set of signatures and adds the
	// signer's weight to the total collected weight, iff the signature is _not_ a
	// duplicate. The total weight of all collected signatures (excluding
	// duplicates) is returned regardless of any returned error.
	// Expected errors during normal operations:
	//  - model.InvalidSignerError if signerID is invalid (not a consensus
	//    participant)
	//  - model.DuplicatedSignerError if the signer has been already added
	TrustedAdd(signerID models.Identity, sig []byte) (
		totalWeight uint64,
		exception error,
	)

	// TotalWeight returns the total weight presented by the collected signatures.
	TotalWeight() uint64

	// Aggregate aggregates the signatures and returns the aggregated consensus.
	// The function performs a final verification and errors if the aggregated
	// signature is invalid. This is required for the function safety since
	// `TrustedAdd` allows adding invalid signatures.
	// The function errors with:
	//   - model.InsufficientSignaturesError if no signatures have been added yet
	//   - model.InvalidSignatureIncludedError if:
	//     -- some signature(s), included via TrustedAdd, fail to deserialize
	//        (regardless of the aggregated public key)
	//     -- or all signatures deserialize correctly but some signature(s),
	//        included via TrustedAdd, are invalid (while aggregated public key is
	//        valid)
	//   - model.InvalidAggregatedKeyError if all signatures deserialize correctly
	//     but the signer's proving public keys sum up to an invalid key (BLS
	//     identity public key). Any aggregated signature would fail the
	//     cryptographic verification under the identity public key and therefore
	//     such signature is considered invalid. Such scenario can only happen if
	//     proving public keys of signers were forged to add up to the identity
	//     public key. Under the assumption that all proving key PoPs are valid,
	//     this error case can only happen if all signers are malicious and
	//     colluding. If there is at least one honest signer, there is a
	//     negligible probability that the aggregated key is identity.
	//
	// The function is thread-safe.
	Aggregate() ([]models.WeightedIdentity, models.AggregatedSignature, error)
}

// TimeoutSignatureAggregator aggregates timeout signatures for one particular
// rank. When instantiating a TimeoutSignatureAggregator, the following
// information is supplied:
//   - The rank for which the aggregator collects timeouts.
//   - For each replicas that is authorized to send a timeout at this particular
//     rank: the node ID, public proving keys, and weight
//
// Timeouts for other ranks or from non-authorized replicas are rejected.
// In their TimeoutStates, replicas include a signature over the pair (rank,
// newestQCRank), where `rank` is the rank number the timeout is for and
// `newestQCRank` is the rank of the newest QC known to the replica.
// TimeoutSignatureAggregator collects these signatures, internally tracks the
// total weight of all collected signatures. Note that in general the signed
// messages are different, which makes the aggregation a comparatively expensive
// operation. Upon calling `Aggregate`, the TimeoutSignatureAggregator
// aggregates all valid signatures collected up to this point. The aggregate
// signature is guaranteed to be correct, as only valid signatures are accepted
// as inputs.
// TimeoutSignatureAggregator internally tracks the total weight of all
// collected signatures. Implementations must be concurrency safe.
type TimeoutSignatureAggregator interface {
	// VerifyAndAdd verifies the signature under the stored public keys and adds
	// the signature and the corresponding highest QC to the internal set.
	// Internal set and collected weight is modified iff signature _is_ valid.
	// The total weight of all collected signatures (excluding duplicates) is
	// returned regardless of any returned error.
	// Expected errors during normal operations:
	//  - model.InvalidSignerError if signerID is invalid (not a consensus
	//    participant)
	//  - model.DuplicatedSignerError if the signer has been already added
	//  - model.ErrInvalidSignature if signerID is valid but signature is
	//    cryptographically invalid
	VerifyAndAdd(
		signerID models.Identity,
		sig []byte,
		newestQCRank uint64,
	) (totalWeight uint64, exception error)

	// TotalWeight returns the total weight presented by the collected signatures.
	TotalWeight() uint64

	// Rank returns the rank that this instance is aggregating signatures for.
	Rank() uint64

	// Aggregate aggregates the signatures and returns with additional data.
	// Aggregated signature will be returned as SigData of timeout certificate.
	// Caller can be sure that resulting signature is valid.
	// Expected errors during normal operations:
	//  - model.InsufficientSignaturesError if no signatures have been added yet
	Aggregate() (
		signersInfo []TimeoutSignerInfo,
		aggregatedSig models.AggregatedSignature,
		exception error,
	)
}

// TimeoutSignerInfo is a helper structure that stores the QC ranks that each
// signer contributed to a TC. Used as result of
// TimeoutSignatureAggregator.Aggregate()
type TimeoutSignerInfo struct {
	NewestQCRank uint64
	Signer       models.Identity
}

// StateSignatureData is an intermediate struct for Packer to pack the
// aggregated signature data into raw bytes or unpack from raw bytes.
type StateSignatureData struct {
	Signers   []models.WeightedIdentity
	Signature []byte
}

// Packer packs aggregated signature data into raw bytes to be used in state
// header.
type Packer interface {
	// Pack serializes the provided StateSignatureData into a precursor format of
	// a QC. rank is the rank of the state that the aggregated signature is for.
	// sig is the aggregated signature data.
	// Expected error returns during normal operations:
	//  * none; all errors are symptoms of inconsistent input data or corrupted
	//    internal state.
	Pack(rank uint64, sig *StateSignatureData) (
		signerIndices []byte,
		sigData []byte,
		err error,
	)

	// Unpack de-serializes the provided signature data.
	// sig is the aggregated signature data
	// It returns:
	//  - (sigData, nil) if successfully unpacked the signature data
	//  - (nil, model.InvalidFormatError) if failed to unpack the signature data
	Unpack(signerIdentities []models.WeightedIdentity, sigData []byte) (
		*StateSignatureData,
		error,
	)
}
