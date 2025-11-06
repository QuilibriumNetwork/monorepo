package verification

import (
	"encoding/binary"
	"fmt"
	"slices"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// MakeVoteMessage generates the message we have to sign in order to be able
// to verify signatures without having the full state. To that effect, each data
// structure that is signed contains the sometimes redundant rank number and
// state ID; this allows us to create the signed message and verify the signed
// message without having the full state contents.
func MakeVoteMessage(
	filter []byte,
	rank uint64,
	stateID models.Identity,
) []byte {
	return slices.Concat(
		filter,
		binary.BigEndian.AppendUint64(
			slices.Clone([]byte(stateID)),
			rank,
		),
	)
}

// MakeTimeoutMessage generates the message we have to sign in order to be able
// to contribute to Active Pacemaker protocol. Each replica signs with the
// highest QC rank known to that replica.
func MakeTimeoutMessage(
	filter []byte,
	rank uint64,
	newestQCRank uint64,
) []byte {
	msg := make([]byte, 16)
	binary.BigEndian.PutUint64(msg[:8], rank)
	binary.BigEndian.PutUint64(msg[8:], newestQCRank)

	return slices.Concat(filter, msg)
}

// verifyAggregatedSignatureOneMessage encapsulates the logic of verifying an
// aggregated signature under the same message. Proofs of possession of all
// input keys are assumed to be valid (checked by the protocol). This logic is
// commonly used across the different implementations of `consensus.Verifier`.
// In this context, all signatures apply to states.
// Return values:
//   - nil if `aggregatedSig` is valid against the public keys and message.
//   - models.InsufficientSignaturesError if `pubKeys` is empty or nil.
//   - models.ErrInvalidSignature if the signature is invalid against the public
//     keys and message.
//   - unexpected errors should be treated as symptoms of bugs or uncovered
//     edge cases in the logic (i.e. as fatal)
func verifyAggregatedSignatureOneMessage(
	validator consensus.SignatureAggregator,
	aggregatedSig models.AggregatedSignature,
	dsTag []byte,
	msg []byte, // message to verify against
) error {
	valid := validator.VerifySignatureRaw(
		aggregatedSig.GetPubKey(),
		aggregatedSig.GetSignature(),
		msg,
		dsTag,
	)
	if !valid {
		return fmt.Errorf(
			"invalid aggregated signature: %w",
			models.ErrInvalidSignature,
		)
	}
	return nil
}

// verifyTCSignatureManyMessages checks cryptographic validity of the TC's
// signature w.r.t. multiple messages and public keys.  Proofs of possession of
// all input keys are assumed to be valid (checked by the protocol). This logic
// is commonly used across the different implementations of
// `consensus.Verifier`. It is the responsibility of the calling code to ensure
// that all `pks` are authorized, without duplicates. The caller must also make
// sure the `hasher` passed is non nil and has 128-bytes outputs.
// Return values:
//   - nil if `sigData` is cryptographically valid
//   - models.InsufficientSignaturesError if `pks` is empty.
//   - models.InvalidFormatError if `pks`/`highQCRanks` have differing lengths
//   - models.ErrInvalidSignature if a signature is invalid
//   - unexpected errors should be treated as symptoms of bugs or uncovered
//     edge cases in the logic (i.e. as fatal)
func verifyTCSignatureManyMessages(
	validator consensus.SignatureAggregator,
	filter []byte,
	pks [][]byte,
	sigData []byte,
	rank uint64,
	highQCRanks []uint64,
	dsTag []byte,
) error {
	if len(pks) != len(highQCRanks) {
		return models.NewInvalidFormatErrorf("public keys and highQCRanks mismatch")
	}

	messages := make([][]byte, 0, len(pks))
	for i := 0; i < len(pks); i++ {
		messages = append(
			messages,
			MakeTimeoutMessage(filter, rank, highQCRanks[i]),
		)
	}

	valid := validator.VerifySignatureMultiMessage(
		pks,
		sigData,
		messages,
		dsTag,
	)
	if !valid {
		return fmt.Errorf(
			"invalid aggregated TC signature for rank %d: %w",
			rank,
			models.ErrInvalidSignature,
		)
	}
	return nil
}
