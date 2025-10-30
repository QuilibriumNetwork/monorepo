package consensus

import "source.quilibrium.com/quilibrium/monorepo/consensus/models"

// Verifier is the component responsible for the cryptographic integrity of
// votes, proposals and QC's against the state they are signing.
type Verifier[VoteT models.Unique] interface {
	// VerifyVote checks the cryptographic validity of a vote's `SigData` w.r.t.
	// the rank and stateID. It is the responsibility of the calling code to
	// ensure that `voter` is authorized to vote.
	// Return values:
	//  * nil if `sigData` is cryptographically valid
	//  * models.InvalidFormatError if the signature has an incompatible format.
	//  * models.ErrInvalidSignature is the signature is invalid
	//  * unexpected errors should be treated as symptoms of bugs or uncovered
	//    edge cases in the logic (i.e. as fatal)
	VerifyVote(vote *VoteT) error

	// VerifyQC checks the cryptographic validity of a QC's `SigData` w.r.t. the
	// given rank and stateID. It is the responsibility of the calling code to
	// ensure that all `signers` are authorized, without duplicates.
	// Return values:
	//  * nil if `sigData` is cryptographically valid
	//  * models.InvalidFormatError if `sigData` has an incompatible format
	//  * models.InsufficientSignaturesError if `signers is empty.
	//    Depending on the order of checks in the higher-level logic this error
	//    might be an indicator of a external byzantine input or an internal bug.
	//  * models.ErrInvalidSignature if a signature is invalid
	//  * unexpected errors should be treated as symptoms of bugs or uncovered
	//	  edge cases in the logic (i.e. as fatal)
	VerifyQuorumCertificate(quorumCertificate models.QuorumCertificate) error

	// VerifyTimeoutCertificate checks cryptographic validity of the TC's
	// `sigData` w.r.t. the given rank. It is the responsibility of the calling
	// code to ensure that all `signers` are authorized, without duplicates.
	// Return values:
	//  * nil if `sigData` is cryptographically valid
	//  * models.InsufficientSignaturesError if `signers is empty.
	//  * models.InvalidFormatError if `signers`/`highQCRanks` have differing
	//    lengths
	//  * models.ErrInvalidSignature if a signature is invalid
	//  * unexpected errors should be treated as symptoms of bugs or uncovered
	//	  edge cases in the logic (i.e. as fatal)
	VerifyTimeoutCertificate(timeoutCertificate models.TimeoutCertificate) error
}
