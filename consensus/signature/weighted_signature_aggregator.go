package signature

import (
	"errors"
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// signerInfo holds information about a signer, its weight and index
type signerInfo struct {
	weight uint64
	pk     []byte
	index  int
}

// WeightedSignatureAggregator implements consensus.WeightedSignatureAggregator.
// It is a wrapper around consensus.SignatureAggregatorSameMessage, which
// implements a mapping from node IDs (as used by HotStuff) to index-based
// addressing of authorized signers (as used by SignatureAggregatorSameMessage).
//
// Similarly to module/consensus.SignatureAggregatorSameMessage, this module
// assumes proofs of possession (PoP) of all identity public keys are valid.
type WeightedSignatureAggregator struct {
	aggregator  consensus.SignatureAggregator
	ids         []models.WeightedIdentity
	idToInfo    map[models.Identity]signerInfo
	totalWeight uint64
	dsTag       []byte
	message     []byte
	lock        sync.RWMutex

	// collectedSigs tracks the Identities of all nodes whose signatures have been
	// collected so far. The reason for tracking the duplicate signers at this
	// module level is that having no duplicates is a Hotstuff constraint, rather
	// than a cryptographic aggregation constraint.
	collectedSigs map[models.Identity][]byte
}

var _ consensus.WeightedSignatureAggregator = (*WeightedSignatureAggregator)(nil)

// NewWeightedSignatureAggregator returns a weighted aggregator initialized with
// a list of identities, their respective public keys, a message and a
// domain separation tag. The identities represent the list of all possible
// signers. This aggregator is only safe if PoPs of all identity keys are valid.
// This constructor does not verify the PoPs but assumes they have been
// validated outside this module.
// The constructor errors if:
// - the list of identities is empty
// - if the length of keys does not match the length of identities
// - if one of the keys is not a valid public key.
//
// A weighted aggregator is used for one aggregation only. A new instance should
// be used for each signature aggregation task in the protocol.
func NewWeightedSignatureAggregator(
	ids []models.WeightedIdentity,
	pks [][]byte, // list of corresponding public keys used for signature verifications
	message []byte, // message to get an aggregated signature for
	dsTag []byte, // domain separation tag used by the signature
	aggregator consensus.SignatureAggregator,
) (*WeightedSignatureAggregator, error) {
	if len(ids) != len(pks) {
		return nil, fmt.Errorf("keys length %d and identities length %d do not match", len(pks), len(ids))
	}

	// build the internal map for a faster look-up
	idToInfo := make(map[models.Identity]signerInfo)
	for i, id := range ids {
		idToInfo[id.Identity()] = signerInfo{
			weight: id.Weight(),
			pk:     pks[i],
			index:  i,
		}
	}

	return &WeightedSignatureAggregator{
		dsTag:         dsTag, // buildutils:allow-slice-alias static value
		ids:           ids,   // buildutils:allow-slice-alias dynamic value constructed by caller
		idToInfo:      idToInfo,
		aggregator:    aggregator,
		message:       message, // buildutils:allow-slice-alias static value for call lifetime
		collectedSigs: make(map[models.Identity][]byte),
	}, nil
}

// Verify verifies the signature under the stored public keys and message.
// Expected errors during normal operations:
//   - models.InvalidSignerError if signerID is invalid (not a consensus
//     participant)
//   - models.ErrInvalidSignature if signerID is valid but signature is
//     cryptographically invalid
//
// The function is thread-safe.
func (w *WeightedSignatureAggregator) Verify(
	signerID models.Identity,
	sig []byte,
) error {
	info, ok := w.idToInfo[signerID]
	if !ok {
		return models.NewInvalidSignerErrorf(
			"%x is not an authorized signer",
			signerID,
		)
	}

	ok = w.aggregator.VerifySignatureRaw(info.pk, sig, w.message, w.dsTag)
	if !ok {
		return fmt.Errorf(
			"invalid signature %x from %x (pk: %x, msg: %x, dsTag: %x): %w",
			sig,
			signerID,
			info.pk,
			w.message,
			w.dsTag,
			models.ErrInvalidSignature,
		)
	}
	return nil
}

// TrustedAdd adds a signature to the internal set of signatures and adds the
// signer's weight to the total collected weight, iff the signature is _not_ a
// duplicate.
//
// The total weight of all collected signatures (excluding duplicates) is
// returned regardless of any returned error.
// The function errors with:
//   - models.InvalidSignerError if signerID is invalid (not a consensus
//     participant)
//   - models.DuplicatedSignerError if the signer has been already added
//
// The function is thread-safe.
func (w *WeightedSignatureAggregator) TrustedAdd(
	signerID models.Identity,
	sig []byte,
) (uint64, error) {
	info, found := w.idToInfo[signerID]
	if !found {
		return w.TotalWeight(), models.NewInvalidSignerErrorf(
			"%x is not an authorized signer",
			signerID,
		)
	}

	// atomically update the signatures pool and the total weight
	w.lock.Lock()
	defer w.lock.Unlock()

	// check for repeated occurrence of signerID
	if _, duplicate := w.collectedSigs[signerID]; duplicate {
		return w.totalWeight, models.NewDuplicatedSignerErrorf(
			"signature from %x was already added",
			signerID,
		)
	}

	w.collectedSigs[signerID] = sig // buildutils:allow-slice-alias static value for call lifetime
	w.totalWeight += info.weight

	return w.totalWeight, nil
}

// TotalWeight returns the total weight presented by the collected signatures.
// The function is thread-safe
func (w *WeightedSignatureAggregator) TotalWeight() uint64 {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return w.totalWeight
}

// Aggregate aggregates the signatures and returns the aggregated consensus.
// The function performs a final verification and errors if the aggregated
// signature is invalid. This is required for the function safety since
// `TrustedAdd` allows adding invalid signatures. The function errors with:
//   - models.InsufficientSignaturesError if no signatures have been added yet
//   - models.InvalidSignatureIncludedError if:
//   - some signature(s), included via TrustedAdd, fail to deserialize
//     (regardless of the aggregated public key)
//     -- or all signatures deserialize correctly but some signature(s),
//     included via TrustedAdd, are invalid (while aggregated public key is
//     valid)
//     -- models.InvalidAggregatedKeyError if all signatures deserialize
//     correctly but the signer's proving public keys sum up to an invalid
//     key (BLS identity public key). Any aggregated signature would fail the
//     cryptographic verification under the identity public key and therefore
//     such signature is considered invalid. Such scenario can only happen if
//     proving public keys of signers were forged to add up to the identity
//     public key. Under the assumption that all proving key PoPs are valid,
//     this error case can only happen if all signers are malicious and
//     colluding. If there is at least one honest signer, there is a
//     negligible probability that the aggregated key is identity.
//
// The function is thread-safe.
func (w *WeightedSignatureAggregator) Aggregate() (
	[]models.WeightedIdentity,
	models.AggregatedSignature,
	error,
) {
	w.lock.Lock()
	defer w.lock.Unlock()

	pks := [][]byte{}
	signerIDs := []models.WeightedIdentity{}
	sigs := [][]byte{}
	for id, sig := range w.collectedSigs {
		signerIDs = append(signerIDs, w.ids[w.idToInfo[id].index])
		pks = append(pks, w.idToInfo[id].pk)
		sigs = append(sigs, sig)
	}
	if len(sigs) == 0 {
		return nil, nil, models.NewInsufficientSignaturesError(
			errors.New("no signatures"),
		)
	}

	aggSignature, err := w.aggregator.Aggregate(pks, sigs)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"unexpected error during signature aggregation: %w",
			err,
		)
	}

	return signerIDs, aggSignature, nil
}
