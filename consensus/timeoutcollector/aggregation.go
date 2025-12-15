package timeoutcollector

import (
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/verification"
)

// signerInfo holds information about a signer, its public key and weight
type signerInfo struct {
	pk     []byte
	weight uint64
}

// sigInfo holds signature and high QC rank submitted by some signer
type sigInfo struct {
	sig          []byte
	newestQCRank uint64
}

// TimeoutSignatureAggregator implements consensus.TimeoutSignatureAggregator.
// It performs timeout specific BLS aggregation over multiple distinct messages.
// We perform timeout signature aggregation for some concrete rank, utilizing
// the protocol specification that timeouts sign the message:
// hash(rank, newestQCRank), where newestQCRank can have different values
// for different replicas.
// Rank and the identities of all authorized replicas are specified when the
// TimeoutSignatureAggregator is instantiated. Each signer is allowed to sign at
// most once. Aggregation uses BLS scheme. Mitigation against rogue attacks is
// done using Proof Of Possession (PoP). Implementation is only safe under the
// assumption that all proofs of possession (PoP) of the public keys are valid.
// This module does not perform the PoPs validity checks, it assumes
// verification was done outside the module. Implementation is thread-safe.
type TimeoutSignatureAggregator struct {
	lock          sync.RWMutex
	filter        []byte
	dsTag         []byte
	aggregator    consensus.SignatureAggregator
	idToInfo      map[models.Identity]signerInfo // auxiliary map to lookup signer weight and public key (only gets updated by constructor)
	idToSignature map[models.Identity]sigInfo    // signatures indexed by the signer ID
	totalWeight   uint64                         // total accumulated weight
	rank          uint64                         // rank for which we are aggregating signatures
}

var _ consensus.TimeoutSignatureAggregator = (*TimeoutSignatureAggregator)(nil)

// NewTimeoutSignatureAggregator returns a multi message signature aggregator
// initialized with a predefined rank for which we aggregate signatures, list of
// identities, their respective public keys and a domain separation tag. The
// identities represent the list of all authorized signers. The constructor does
// not verify PoPs of input public keys, it assumes verification was done
// outside this module.
// The constructor errors if:
// - the list of identities is empty
// - if one of the keys is not a valid public key.
//
// A multi message sig aggregator is used for aggregating timeouts for a single
// rank only. A new instance should be used for each signature aggregation task
// in the protocol.
func NewTimeoutSignatureAggregator(
	aggregator consensus.SignatureAggregator,
	filter []byte,
	rank uint64, // rank for which we are aggregating signatures
	ids []models.WeightedIdentity, // list of all authorized signers
	dsTag []byte, // domain separation tag used by the signature
) (*TimeoutSignatureAggregator, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf(
			"number of participants must be larger than 0, got %d",
			len(ids),
		)
	}

	// build the internal map for a faster look-up
	idToInfo := make(map[models.Identity]signerInfo)
	for _, id := range ids {
		idToInfo[id.Identity()] = signerInfo{
			pk:     id.PublicKey(),
			weight: id.Weight(),
		}
	}

	return &TimeoutSignatureAggregator{
		aggregator:    aggregator,
		filter:        filter, // buildutils:allow-slice-alias static value
		dsTag:         dsTag,  // buildutils:allow-slice-alias static value
		idToInfo:      idToInfo,
		idToSignature: make(map[models.Identity]sigInfo),
		rank:          rank,
	}, nil
}

// VerifyAndAdd verifies the signature under the stored public keys and adds
// signature with corresponding newest QC rank to the internal set. Internal set
// and collected weight is modified iff the signer ID is not a duplicate and
// signature _is_ valid. The total weight of all collected signatures (excluding
// duplicates) is returned regardless of any returned error.
// Expected errors during normal operations:
//   - models.InvalidSignerError if signerID is invalid (not a consensus
//     participant)
//   - models.DuplicatedSignerError if the signer has been already added
//   - models.ErrInvalidSignature if signerID is valid but signature is
//     cryptographically invalid
//
// The function is thread-safe.
func (a *TimeoutSignatureAggregator) VerifyAndAdd(
	signerID models.Identity,
	sig []byte,
	newestQCRank uint64,
) (totalWeight uint64, exception error) {
	info, ok := a.idToInfo[signerID]
	if !ok {
		return a.TotalWeight(), models.NewInvalidSignerErrorf(
			"%x is not an authorized signer",
			signerID,
		)
	}

	// to avoid expensive signature verification we will proceed with double lock
	// style check
	if a.hasSignature(signerID) {
		return a.TotalWeight(), models.NewDuplicatedSignerErrorf(
			"signature from %x was already added",
			signerID,
		)
	}

	msg := verification.MakeTimeoutMessage(a.filter, a.rank, newestQCRank)
	valid := a.aggregator.VerifySignatureRaw(info.pk, sig, msg, a.dsTag)
	if !valid {
		return a.TotalWeight(), fmt.Errorf(
			"invalid signature from %s: %w",
			signerID,
			models.ErrInvalidSignature,
		)
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	if _, duplicate := a.idToSignature[signerID]; duplicate {
		return a.totalWeight, models.NewDuplicatedSignerErrorf(
			"signature from %x was already added",
			signerID,
		)
	}

	a.idToSignature[signerID] = sigInfo{
		sig:          sig, // buildutils:allow-slice-alias static value for call lifetime
		newestQCRank: newestQCRank,
	}
	a.totalWeight += info.weight

	return a.totalWeight, nil
}

func (a *TimeoutSignatureAggregator) hasSignature(
	signerID models.Identity,
) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()
	_, found := a.idToSignature[signerID]
	return found
}

// TotalWeight returns the total weight presented by the collected signatures.
// The function is thread-safe
func (a *TimeoutSignatureAggregator) TotalWeight() uint64 {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.totalWeight
}

// Rank returns rank for which aggregation happens
// The function is thread-safe
func (a *TimeoutSignatureAggregator) Rank() uint64 {
	return a.rank
}

// Aggregate aggregates the signatures and returns the aggregated consensus.
// The resulting aggregated signature is guaranteed to be valid, as all
// individual signatures are pre-validated before their addition. Expected
// errors during normal operations:
//   - models.InsufficientSignaturesError if no signatures have been added yet
//
// This function is thread-safe
func (a *TimeoutSignatureAggregator) Aggregate() (
	[]consensus.TimeoutSignerInfo,
	models.AggregatedSignature,
	error,
) {
	a.lock.RLock()
	defer a.lock.RUnlock()

	sharesNum := len(a.idToSignature)
	signatures := make([][]byte, 0, sharesNum)
	publicKeys := make([][]byte, 0, sharesNum)
	signersData := make([]consensus.TimeoutSignerInfo, 0, sharesNum)
	for id, info := range a.idToSignature {
		publicKeys = append(publicKeys, a.idToInfo[id].pk)
		signatures = append(signatures, info.sig)
		signersData = append(signersData, consensus.TimeoutSignerInfo{
			NewestQCRank: info.newestQCRank,
			Signer:       id,
		})
	}

	if sharesNum == 0 {
		return nil, nil, models.NewInsufficientSignaturesErrorf(
			"cannot aggregate an empty list of signatures",
		)
	}

	aggSignature, err := a.aggregator.Aggregate(publicKeys, signatures)
	if err != nil {
		// any other error here is a symptom of an internal bug
		return nil, nil, fmt.Errorf(
			"unexpected internal error during BLS signature aggregation: %w",
			err,
		)
	}

	return signersData, aggSignature, nil
}
