package token

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	hgstate "source.quilibrium.com/quilibrium/monorepo/node/execution/state/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// MintTransactionInput is an input specific to the Mint flow where a token
// intrinsic is configured as Mintable, and the input is a proof corresponding
// to the specific MintStrategy outlined in the token's configuration. Mint
// input values are public.
type MintTransactionInput struct {
	// Public input values:

	// The minted quantity.
	Value *big.Int
	// The constructed commitment to the input balance.
	Commitment []byte
	// The underlying signature authorizing the mint and proving validity. Note:
	// when minting a token with a MintWithSignature behavior, this signature
	// corresponds to the minting party, the authorizing signature is in the
	// Proofs collection.
	Signature []byte
	// The proofs of various attributes of the token. May contain additional
	// information to prove adjacent transactions in other app shards
	// (MintWithPayment). Must verify against the transaction's multiproofs for
	// full end-to-end verification.
	Proofs [][]byte
	// The AdditionalReference value, if a non-divisible token and authority
	// mint is specified.
	AdditionalReference []byte
	// The key used to encrypt the AdditionalReference value, if a
	// non-divisible token and authority mint is specified.
	AdditionalReferenceKey []byte

	// Private input values:

	// Relevant information for the given mint type.
	contextData []byte
	// The signing operation which sets the signature, after the outputs are
	// generated.
	signOp func(transcript []byte) error
	// The ephemeral private key value
	ephemeralKey []byte
}

func NewMintTransactionInput(
	value *big.Int,
	contextData []byte,
) (*MintTransactionInput, error) {
	return &MintTransactionInput{
		Value:       value,
		contextData: contextData,
	}, nil
}

func (i *MintTransactionInput) Prove(
	tx *MintTransaction,
	index int,
) ([]byte, error) {
	if tx.config.Behavior&Mintable == 0 {
		return nil, errors.Wrap(errors.New("invalid type"), "prove input")
	}

	var blind []byte
	var err error

	switch tx.config.MintStrategy.MintBehavior {
	case MintWithProof:
		switch tx.config.MintStrategy.ProofBasis {
		case ProofOfMeaningfulWork:
			if blind, err = i.proveWithProofOfMeaningfulWork(tx); err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
		case VerkleMultiproofWithSignature:
			if blind, err = i.proveWithVerkleMultiproofSignature(tx); err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
		}
	case MintWithAuthority:
		if blind, err = i.proveWithMintWithAuthority(tx); err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
	case MintWithSignature:
		if blind, err = i.proveWithMintWithSignature(tx); err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
	case MintWithPayment:
		if blind, err = i.proveWithMintWithPayment(tx); err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
	}

	return blind, nil
}

// proveWithMintWithPayment proves the mint's validity under MintWithPayment
// flows. Imparts no unique expectations in the associated output – outputs
// from this flow have standard sumchecks and bulletproofs.
func (i *MintTransactionInput) proveWithMintWithPayment(
	tx *MintTransaction,
) ([]byte, error) {
	isFreeMint := tx.config.MintStrategy.FeeBasis == nil ||
		tx.config.MintStrategy.FeeBasis.Type == NoFeeBasis ||
		tx.config.MintStrategy.FeeBasis.Baseline == nil ||
		tx.config.MintStrategy.FeeBasis.Baseline.Cmp(big.NewInt(0)) == 0

	// context data:
	// [<payment tx bytes> |] <payment tx blind> | <ek> | <vpk> | <spk>
	if len(i.contextData) < 224 {
		return nil, errors.Wrap(
			errors.New("invalid context data"),
			"prove with mint with payment",
		)
	}

	if !isFreeMint {
		paymentTx := &PendingTransaction{}
		if err := paymentTx.FromBytes(
			i.contextData[:len(i.contextData)-224],
			QUIL_TOKEN_CONFIGURATION,
			tx.hypergraph,
			tx.bulletproofProver,
			tx.inclusionProver,
			tx.verEnc,
			tx.decafConstructor,
			tx.keyRing,
			"",
			tx.rdfMultiprover,
		); err != nil {
			return nil, errors.Wrap(err, "prove with mint with payment")
		}
	} else {
		if len(i.contextData) != 224 {
			return nil, errors.Wrap(
				errors.New("invalid context data"),
				"prove with mint with payment",
			)
		}
	}

	i.Proofs = append(i.Proofs, i.contextData)

	// Proof of mint with payment is a little tricky: we need to establish a blind
	// but we also need to impart a linear correlation to the fee, if applicable.
	// Expecting this from context will allow us to do both the standard
	// token-level bulletproof and sumcheck, but additionally have a binding
	// sumcheck against the paid QUIL (scaled by fee).
	//        Sumcheck of same tokens: Σ(C_in) = Σ(C_out) + Σ(fees)
	//        Sumcheck of swapped tokens: Σ(C_in) = Σ(C_out)*Baseline + Σ(fees)
	// The trick is: C_in  = amt * G + mask * H
	//               C_out = amt * G + mask * (1 / Baseline) * H
	// The scaling is constant, so you can apply the baseline as a scalar factor
	// and the rate of exchange balances out.
	syntheticBlind, err := tx.decafConstructor.NewFromScalar(
		i.contextData[len(i.contextData)-224 : len(i.contextData)-168],
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)
	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	if !isFreeMint {
		conversionRate := tx.config.MintStrategy.FeeBasis.Baseline
		rateLI := conversionRate.FillBytes(make([]byte, 56))
		slices.Reverse(rateLI)
		rate, err := tx.decafConstructor.NewFromScalar(rateLI)
		if err != nil {
			return nil, errors.Wrap(err, "prove with mint with payment")
		}

		invRate, err := rate.InverseScalar()
		if err != nil {
			return nil, errors.Wrap(err, "prove with mint with payment")
		}

		syntheticBlind, err = syntheticBlind.ScalarMult(invRate.Private())
		if err != nil {
			return nil, errors.Wrap(err, "prove with mint with payment")
		}

		raisedBlind, err = invRate.AgreeWith(raisedBlind)
		if err != nil {
			return nil, errors.Wrap(err, "prove with mint with payment")
		}
	}

	i.Commitment, err = balancePoint.Add(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid view key"),
			"prove with mint with payment",
		)
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid spend key"),
			"prove with mint with payment",
		)
	}

	// Instead of the normal rVK, we use the raised blind because the purpose of
	// the one-time key is to provide both blinding of the consumed outputs
	// (which don't exist) as well as unforgeable linkability to the view key
	// (which does).
	shared, err := viewKey.AgreeWithAndHashToScalar(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with payment")
	}

	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			balance,
			syntheticBlind.Private(),
		)

		return nil
	}

	return syntheticBlind.Private(), nil
}

// proveWithMintWithSignature proves the mint's validity under MintWithSignature
// flows. Associated outputs must have the authorized key image, generated from
// the provided one-time private key, in addition to standard bulletproofs and
// sum checks.
func (i *MintTransactionInput) proveWithMintWithSignature(
	tx *MintTransaction,
) ([]byte, error) {
	if tx.config.MintStrategy.Authority == nil ||
		tx.config.MintStrategy.Authority.PublicKey == nil {
		return nil, errors.Wrap(
			errors.New("invalid input"),
			"prove with mint with signature",
		)
	}

	// context data:
	// <value> | <image> | <signature> | <one-time-private-key>
	if len(i.contextData) < 144 {
		return nil, errors.Wrap(
			errors.New("invalid context data"),
			"prove with mint with signature",
		)
	}

	i.Proofs = append(i.Proofs, i.contextData[:len(i.contextData)-56])

	// Mint with signature flow requires the creation of a fresh synthetic blind,
	// subject to the minter. The one time key comes from the authority, the image
	// provides complete binding to the input for the minter.
	syntheticBlind, err := tx.decafConstructor.New()
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(i.contextData[0:32])

	if checkBalance.Cmp(i.Value) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid value"),
			"prove with mint with verkle multiproof signature",
		)
	}

	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)
	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	i.Commitment, err = balancePoint.Add(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid view key"),
			"prove with mint with signature",
		)
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid spend key"),
			"prove with mint with signature",
		)
	}

	oneTimeKey, err := tx.decafConstructor.NewFromScalar(
		i.contextData[len(i.contextData)-56:],
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	image, err := shared.Add(spendKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with signature")
	}

	if !bytes.Equal(image, i.Proofs[0][32:88]) {
		return nil, errors.Wrap(
			errors.New("authorization for different key"),
			"prove with mint with signature",
		)
	}

	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			balance,
			syntheticBlind.Private(),
		)

		return nil
	}

	return syntheticBlind.Private(), nil
}

// proveWithMintWithAuthority proves the mint's validity under MintWithAuthority
// flows. Associated outputs must have the authorized key image, generated from
// the provided one-time private key, in addition to standard bulletproofs and
// sum checks. The difference from MintWithSignature is that the correlated
// output may have a different key image from what is proven in the signature
// of the mint input – which must be derived from the mint authority.
func (i *MintTransactionInput) proveWithMintWithAuthority(
	tx *MintTransaction,
) ([]byte, error) {
	if tx.config.MintStrategy.Authority == nil ||
		tx.config.MintStrategy.Authority.PublicKey == nil {
		return nil, errors.Wrap(
			errors.New("invalid input"),
			"prove with mint with authority",
		)
	}

	// context data:
	// <value> | <image> | <signature> | <one-time-private-key>
	if len(i.contextData) < 144 {
		return nil, errors.Wrap(
			errors.New("invalid context data"),
			"prove with mint with authority",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(i.contextData[0:32])

	if checkBalance.Cmp(i.Value) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid value"),
			"prove with mint with verkle multiproof signature",
		)
	}

	i.Proofs = append(i.Proofs, i.contextData[:len(i.contextData)-56])

	// Mint with authority flow requires the creation of a fresh synthetic blind,
	// subject to the minter. The one time key comes from the authority, the image
	// provides complete binding to the input for the minter.
	syntheticBlind, err := tx.decafConstructor.New()
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)
	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	i.Commitment, err = balancePoint.Add(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid view key"),
			"prove with mint with authority",
		)
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid spend key"),
			"prove with mint with authority",
		)
	}

	oneTimeKey, err := tx.decafConstructor.NewFromScalar(
		i.contextData[len(i.contextData)-56:],
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	image, err := shared.Add(spendKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "prove with mint with authority")
	}

	if !bytes.Equal(image, i.Proofs[0][32:88]) {
		return nil, errors.Wrap(
			errors.New("authorization for different key"),
			"prove with mint with authority",
		)
	}

	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			balance,
			syntheticBlind.Private(),
		)

		return nil
	}

	return syntheticBlind.Private(), nil
}

// proveWithVerkleMultiproofSignature proves the mint's validity under
// MintWithVerkleMultiproofSignature flows. Associated outputs must have the
// authorized key image, generated from the provided one-time private key,
// in addition to standard bulletproofs and sum checks. The difference from
// MintWithSignature is that the proof payload is a multiproof to the verkle
// root of an authorized key image concatenated with the authorized amount.
func (i *MintTransactionInput) proveWithVerkleMultiproofSignature(
	tx *MintTransaction,
) ([]byte, error) {
	if tx.config.MintStrategy.VerkleRoot == nil {
		return nil, errors.Wrap(
			errors.New("invalid input"),
			"prove with mint with verkle multiproof signature",
		)
	}

	// context data:
	// <traversal proof with multiproof> | <amount> | <image> |
	//     <one-time-private key>
	if len(i.contextData) < 144 {
		return nil, errors.Wrap(
			errors.New("invalid context data"),
			"prove with mint with verkle multiproof signature",
		)
	}

	traversalProof := &qcrypto.TraversalProof{}
	if err := traversalProof.FromBytes(
		i.contextData[:len(i.contextData)-144],
		tx.inclusionProver,
	); err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	i.Proofs = append(i.Proofs, i.contextData[:len(i.contextData)-56])

	// Mint with verkle multiproof flow requires the creation of a fresh
	// synthetic blind, subject to the minter. The one time key comes from the
	// creator of the verkle root, the image provides complete binding to the
	// input for the minter and is part of the verkle tree being proven on.
	syntheticBlind, err := tx.decafConstructor.New()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(
		i.contextData[len(i.contextData)-144 : len(i.contextData)-112],
	)

	if checkBalance.Cmp(i.Value) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid value"),
			"prove with mint with verkle multiproof signature",
		)
	}

	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)
	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	i.Commitment, err = balancePoint.Add(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid view key"),
			"prove with mint with verkle multiproof signature",
		)
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid spend key"),
			"prove with mint with verkle multiproof signature",
		)
	}

	oneTimeKey, err := tx.decafConstructor.NewFromScalar(
		i.contextData[len(i.contextData)-56:],
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey.Public())
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	image, err := spendKey.Add(shared.Public())
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with verkle multiproof signature",
		)
	}

	if !bytes.Equal(image, i.Proofs[0][len(i.Proofs[0])-56:]) {
		return nil, errors.Wrap(
			errors.New("authorization for different key"),
			"prove with mint with verkle multiproof signature",
		)
	}

	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			balance,
			syntheticBlind.Private(),
		)

		return nil
	}

	return syntheticBlind.Private(), nil
}

// proveWithProofOfMeaningfulWork proves the mint's validity under
// MintWithProofOfMeaningfulWork flows. Associated outputs must have the
// authorized prover as the recipient, the input proof must contain the relevant
// multiproof to the current state of the prover's reward set in the prover
// metadata.
func (i *MintTransactionInput) proveWithProofOfMeaningfulWork(
	tx *MintTransaction,
) ([]byte, error) {
	if tx.config.MintStrategy.ProofBasis != ProofOfMeaningfulWork {
		return nil, errors.Wrap(
			errors.New("invalid input"),
			"prove with mint with proof of meaningful work",
		)
	}

	prover, err := tx.keyRing.GetSigningKey(
		"q-prover-key",
		crypto.KeyTypeBLS48581G1,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	// Delegated rewards: if context data is given, use the address provided in it
	// to establish the traversal. The context is the prover address, the
	// signature is the delegated prover key.
	pubKey := prover.Public().([]byte)
	var address []byte
	if len(i.contextData) != 32 {
		addressBI, err := poseidon.HashBytes(pubKey)
		if err != nil {
			return nil, errors.Wrap(
				err,
				"prove with mint with proof of meaningful work",
			)
		}
		address = addressBI.FillBytes(make([]byte, 32))
	} else {
		address = i.contextData
	}

	proverRootDomain := [32]byte(tx.Domain)
	rewardAddress := address
	if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) {
		// Special case: PoMW mints under QUIL use global records for proofs
		proverRootDomain = intrinsics.GLOBAL_INTRINSIC_ADDRESS
		derivedRewardAddress, err := poseidon.HashBytes(
			slices.Concat(QUIL_TOKEN_ADDRESS[:], address),
		)
		if err != nil {
			return nil, errors.Wrap(
				err,
				"prove with mint with proof of meaningful work",
			)
		}

		rewardAddress = derivedRewardAddress.FillBytes(make([]byte, 32))
	}

	proof, err := tx.hypergraph.CreateTraversalProof(
		proverRootDomain,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		[][]byte{slices.Concat(
			proverRootDomain[:],
			rewardAddress,
		)},
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	if len(proof.SubProofs) != 1 {
		return nil, errors.Wrap(
			errors.New("unexpected proof length"),
			"prove with mint with proof of meaningful work",
		)
	}

	proofBytes, err := proof.ToBytes()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	i.Proofs = append(i.Proofs, proofBytes)

	proverData, err := tx.hypergraph.GetVertexData([64]byte(slices.Concat(
		proverRootDomain[:],
		rewardAddress,
	)))
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	checkBalanceBytes, err := proverData.Get([]byte{1 << 2})
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	// Mint with proof of meaningful work flow requires the creation of a fresh
	// synthetic blind, subject to the minter. The key image must be signed by the
	// prover key to provide binding.
	syntheticBlind, err := tx.decafConstructor.New()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(checkBalanceBytes)

	if checkBalance.Cmp(i.Value) != 0 {
		return nil, errors.Wrap(
			errors.New("invalid value"),
			"prove with mint with proof of meaningful work",
		)
	}

	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)
	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	i.Commitment, err = balancePoint.Add(raisedBlind)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid view key"),
			"prove with mint with proof of meaningful work",
		)
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		nil,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(
			errors.New("invalid spend key"),
			"prove with mint with proof of meaningful work",
		)
	}

	oneTimeKey, err := tx.decafConstructor.New()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey.Public())
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	i.ephemeralKey = oneTimeKey.Public()

	image, err := shared.Add(spendKey.Public())
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	signature, err := prover.SignWithDomain(image, tx.Domain[:])
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}

	i.Proofs = append(
		i.Proofs,
		slices.Concat(address, prover.Public().([]byte), signature),
	)

	poly := proverData.Root.(*qcrypto.VectorCommitmentBranchNode).GetPolynomial()
	commit := proverData.Root.Commit(tx.inclusionProver, false)
	multiproof := tx.inclusionProver.ProveMultiple(
		[][]byte{commit, commit},
		[][]byte{poly, poly},
		[]uint64{0, 1},
		64,
	)
	multiproofBytes, err := multiproof.ToBytes()
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove with mint with proof of meaningful work",
		)
	}
	i.Proofs = append(i.Proofs, multiproofBytes)

	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			balance,
			syntheticBlind.Private(),
		)

		return nil
	}

	return syntheticBlind.Private(), nil
}

func (i *MintTransactionInput) Verify(
	frameNumber uint64,
	index int,
	outputTranscript []byte,
	tx *MintTransaction,
) (bool, error) {
	if tx.config.Behavior&Mintable == 0 {
		return false, errors.Wrap(errors.New("invalid type"), "verify input")
	}

	if len(i.Commitment) != 56 {
		return false, errors.Wrap(
			errors.New("invalid commitment length"),
			"verify input",
		)
	}

	if tx.config.Behavior&Divisible == 0 {
		if i.Value.Cmp(big.NewInt(1)) != 0 {
			return false, errors.Wrap(
				errors.New("non-divisible token with non-unitary mint value"),
				"verify input",
			)
		}
		if tx.config.MintStrategy.Authority != nil {
			if len(i.AdditionalReference) != 64 {
				return false, errors.Wrap(
					errors.New("non-divisible token with no reference encryption key"),
					"verify input",
				)
			}
			if len(i.AdditionalReferenceKey) != 56 {
				return false, errors.Wrap(
					errors.New("non-divisible token with no reference key encryption key"),
					"verify input",
				)
			}
		} else {
			if len(i.AdditionalReference) != 0 {
				return false, errors.Wrap(
					errors.New("non-divisible non-authorative token with no reference encryption key"),
					"verify input",
				)
			}
			if len(i.AdditionalReferenceKey) != 0 {
				return false, errors.Wrap(
					errors.New("non-divisible non-authorative token with no reference key encryption key"),
					"verify input",
				)
			}
		}
	}

	switch tx.config.MintStrategy.MintBehavior {
	case MintWithProof:
		switch tx.config.MintStrategy.ProofBasis {
		case ProofOfMeaningfulWork:
			if err := i.verifyWithProofOfMeaningfulWork(
				tx,
				outputTranscript,
			); err != nil {
				return false, errors.Wrap(err, "verify input")
			}
		case VerkleMultiproofWithSignature:
			if err := i.verifyWithVerkleMultiproofSignature(
				tx,
				outputTranscript,
			); err != nil {
				return false, errors.Wrap(err, "verify input")
			}
		case NoProofBasis:
			return false, errors.Wrap(errors.New("invalid type"), "verify input")
		default:
			return false, errors.Wrap(errors.New("invalid type"), "verify input")
		}
	case MintWithAuthority:
		if err := i.verifyWithMintWithAuthority(tx, outputTranscript); err != nil {
			return false, errors.Wrap(err, "verify input")
		}
	case MintWithSignature:
		if err := i.verifyWithMintWithSignature(tx, outputTranscript); err != nil {
			return false, errors.Wrap(err, "verify input")
		}
	case MintWithPayment:
		if err := i.verifyWithMintWithPayment(
			frameNumber,
			outputTranscript,
			tx,
			index,
		); err != nil {
			return false, errors.Wrap(err, "verify input")
		}
	default:
		return false, errors.Wrap(errors.New("invalid type"), "verify input")
	}

	return true, nil
}

func (i *MintTransactionInput) verifyWithMintWithPayment(
	frameNumber uint64,
	outputTranscript []byte,
	tx *MintTransaction,
	index int,
) error {
	if len(i.Proofs) != 1 {
		return errors.Wrap(
			errors.New("invalid proofs length"),
			"verify with mint with payment",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Proofs[0])
	if err != nil {
		return errors.Wrap(err, "verify with mint with payment")
	}

	_, err = tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	)))
	if err == nil {
		return errors.Wrap(
			errors.New("already spent"),
			"verify with mint with payment",
		)
	}

	isFreeMint := tx.config.MintStrategy.FeeBasis == nil ||
		tx.config.MintStrategy.FeeBasis.Type == NoFeeBasis ||
		tx.config.MintStrategy.FeeBasis.Baseline == nil ||
		tx.config.MintStrategy.FeeBasis.Baseline.Cmp(big.NewInt(0)) == 0

	if !isFreeMint {
		if len(i.Proofs[0]) < 224 {
			return errors.Wrap(
				errors.New("invalid proof length"),
				"verify with mint with payment",
			)
		}
	} else {
		if len(i.Proofs[0]) != 224 {
			return errors.Wrap(
				errors.New("invalid proof length"),
				"verify with mint with payment",
			)
		}
	}

	syntheticBlind, err := tx.decafConstructor.NewFromScalar(
		i.Proofs[0][len(i.Proofs[0])-224 : len(i.Proofs[0])-168],
	)
	if err != nil {
		return errors.Wrap(err, "verify with mint with payment")
	}
	balance := i.Value.FillBytes(make([]byte, 56))
	slices.Reverse(balance)

	balancePoint, err := tx.decafConstructor.NewFromScalar(balance)
	if err != nil {
		return errors.Wrap(err, "verify with mint with payment")
	}

	raisedBlind, err := syntheticBlind.AgreeWith(
		tx.decafConstructor.AltGenerator(),
	)
	if err != nil {
		return errors.Wrap(err, "verify with mint with payment")
	}

	if !isFreeMint {
		conversionRate := tx.config.MintStrategy.FeeBasis.Baseline
		rateLI := conversionRate.FillBytes(make([]byte, 56))
		slices.Reverse(rateLI)
		rate, err := tx.decafConstructor.NewFromScalar(rateLI)
		if err != nil {
			return errors.Wrap(err, "prove with mint with payment")
		}

		invRate, err := rate.InverseScalar()
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		raisedBlind, err = invRate.AgreeWith(raisedBlind)
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}
	}

	check, err := balancePoint.Add(raisedBlind)
	if err != nil {
		return errors.Wrap(err, "verify with mint with payment")
	}

	if !bytes.Equal(check, i.Commitment) {
		return errors.Wrap(
			errors.New("commitment mismatch"),
			"verify with mint with payment",
		)
	}

	if !isFreeMint {
		paymentTx := &PendingTransaction{}
		if err := paymentTx.FromBytes(
			i.contextData[:len(i.contextData)-224],
			QUIL_TOKEN_CONFIGURATION,
			tx.hypergraph,
			tx.bulletproofProver,
			tx.inclusionProver,
			tx.verEnc,
			tx.decafConstructor,
			tx.keyRing,
			"", // rdf schema is not required for verification
			tx.rdfMultiprover,
		); err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		if valid, err := paymentTx.Verify(frameNumber); err != nil || !valid {
			return errors.Wrap(err, "verify with mint with payment")
		}

		if len(paymentTx.Outputs) <= index {
			return errors.Wrap(
				errors.New("transaction output index mismatch"),
				"verify with mint with payment",
			)
		}

		conversionRate := tx.config.MintStrategy.FeeBasis.Baseline
		rateLI := conversionRate.FillBytes(make([]byte, 56))
		slices.Reverse(rateLI)
		rate, err := tx.decafConstructor.NewFromScalar(rateLI)
		if err != nil {
			return errors.Wrap(err, "prove with mint with payment")
		}

		scaledCheck, err := rate.AgreeWith(check)
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		if !bytes.Equal(scaledCheck, paymentTx.Outputs[index].Commitment) {
			return errors.Wrap(
				errors.New("output commitment mismatch"),
				"verify with mint with payment",
			)
		}

		ephemeralKey, err := tx.decafConstructor.NewFromScalar(
			i.contextData[len(i.contextData)-168 : len(i.contextData)-112],
		)
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		rvk, err := ephemeralKey.AgreeWithAndHashToScalar(
			i.contextData[len(i.contextData)-112 : len(i.contextData)-56],
		)
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		checkVK, err := rvk.Add(i.contextData[len(i.contextData)-56:])
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		if !bytes.Equal(
			paymentTx.Outputs[index].ToOutput.VerificationKey,
			checkVK,
		) {
			return errors.Wrap(
				errors.New("invalid proof"),
				"verify with mint with payment",
			)
		}

		paymentAddress, err := poseidon.HashBytes(
			i.contextData[len(i.contextData)-112:],
		)
		if err != nil {
			return errors.Wrap(err, "verify with mint with payment")
		}

		if !bytes.Equal(
			tx.config.MintStrategy.PaymentAddress,
			paymentAddress.FillBytes(make([]byte, 32)),
		) {
			return errors.Wrap(
				errors.New("payment address match failure"),
				"verify with mint with payment",
			)
		}

		if !bytes.Equal(
			paymentTx.Outputs[index].RefundOutput.VerificationKey,
			paymentTx.Outputs[index].ToOutput.VerificationKey,
		) {
			return errors.Wrap(
				errors.New("payment is not abandoned"),
				"verify with mint with payment",
			)
		}
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return errors.Wrap(
			errors.New("invalid commitment"),
			"verify with mint with payment",
		)
	}

	if valid := tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	); !valid {
		return errors.Wrap(
			errors.New("invalid signature"),
			"verify with mint with payment",
		)
	}

	return nil
}

func (i *MintTransactionInput) verifyWithMintWithSignature(
	tx *MintTransaction,
	outputTranscript []byte,
) error {
	if len(i.Proofs) != 1 {
		return errors.Wrap(
			errors.New("invalid proofs length"),
			"verify with mint with signature",
		)
	}

	sigSize := 0
	switch tx.config.MintStrategy.Authority.KeyType {
	case crypto.KeyTypeEd448:
		sigSize = 114
	case crypto.KeyTypeBLS48581G1:
		fallthrough
	case crypto.KeyTypeBLS48581G2: // Pubkey is G2, Signature is G1
		sigSize = 74
	case crypto.KeyTypeEd25519:
		sigSize = 64
	case crypto.KeyTypeSecp256K1SHA256:
		fallthrough
	case crypto.KeyTypeSecp256K1SHA3:
		sigSize = 64
	default:
		return errors.Wrap(
			errors.New("invalid key type"),
			"verify with mint with signature",
		)
	}
	if len(i.Proofs[0]) != 88+sigSize {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"verify with mint with signature",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Proofs[0])
	if err != nil {
		return errors.Wrap(err, "verify with mint with signature")
	}

	_, err = tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	)))
	if err == nil {
		return errors.Wrap(
			errors.New("already spent"),
			"verify with mint with signature",
		)
	}

	if valid, err := tx.keyRing.ValidateSignature(
		tx.config.MintStrategy.Authority.KeyType,
		tx.config.MintStrategy.Authority.PublicKey,
		i.Proofs[0][:88],
		i.Proofs[0][88:],
		tx.Domain[:],
	); err != nil || !valid {
		return errors.Wrap(
			errors.New("invalid signature from authority"),
			"verify with mint with signature",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(i.Proofs[0][0:32])

	if checkBalance.Cmp(i.Value) != 0 {
		return errors.Wrap(
			errors.New("invalid value"),
			"verify with mint with signature",
		)
	}

	if !bytes.Equal(i.Proofs[0][32:88], i.Signature[(56*4):(56*5)]) {
		return errors.Wrap(
			errors.New("invalid key image"),
			"verify with mint with signature",
		)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return errors.Wrap(
			errors.New("invalid commitment"),
			"verify with mint with signature",
		)
	}

	if valid := tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	); !valid {
		return errors.Wrap(
			errors.New("invalid signature"),
			"verify with mint with signature",
		)
	}

	return nil
}

func (i *MintTransactionInput) verifyWithMintWithAuthority(
	tx *MintTransaction,
	outputTranscript []byte,
) error {
	if len(i.Proofs) != 1 {
		return errors.Wrap(
			errors.New("invalid proofs length"),
			"verify with mint with authority",
		)
	}

	sigSize := 0
	switch tx.config.MintStrategy.Authority.KeyType {
	case crypto.KeyTypeEd448:
		sigSize = 114
	case crypto.KeyTypeBLS48581G1:
		fallthrough
	case crypto.KeyTypeBLS48581G2: // Pubkey is G2, Signature is G1
		sigSize = 74
	case crypto.KeyTypeEd25519:
		sigSize = 64
	case crypto.KeyTypeSecp256K1SHA256:
		fallthrough
	case crypto.KeyTypeSecp256K1SHA3:
		sigSize = 64
	default:
		return errors.Wrap(
			errors.New("invalid key type"),
			"verify with mint with authority",
		)
	}
	if len(i.Proofs[0]) != 88+sigSize {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"verify with mint with authority",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(i.Proofs[0][0:32])

	if checkBalance.Cmp(i.Value) != 0 {
		return errors.Wrap(
			errors.New("invalid value"),
			"verify with mint with authority",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Proofs[0])
	if err != nil {
		return errors.Wrap(err, "verify with mint with authority")
	}

	_, err = tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	)))
	if err == nil {
		return errors.Wrap(
			errors.New("already spent"),
			"verify with mint with authority",
		)
	}

	if valid, err := tx.keyRing.ValidateSignature(
		tx.config.MintStrategy.Authority.KeyType,
		tx.config.MintStrategy.Authority.PublicKey,
		i.Proofs[0][:88],
		i.Proofs[0][88:],
		tx.Domain[:],
	); err != nil || !valid {
		return errors.Wrap(
			errors.New("invalid signature from authority"),
			"verify with mint with authority",
		)
	}

	if !bytes.Equal(i.Proofs[0][32:88], i.Signature[(56*4):(56*5)]) {
		return errors.Wrap(
			errors.New("invalid key image"),
			"verify with mint with authority",
		)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return errors.Wrap(
			errors.New("invalid commitment"),
			"verify with mint with authority",
		)
	}

	if valid := tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	); !valid {
		return errors.Wrap(
			errors.New("invalid signature"),
			"verify with mint with authority",
		)
	}

	return nil
}

func (i *MintTransactionInput) verifyWithVerkleMultiproofSignature(
	tx *MintTransaction,
	outputTranscript []byte,
) error {
	if len(i.Proofs) != 1 {
		return errors.Wrap(
			errors.New("invalid proofs length"),
			"verify with mint with verkle multiproof signature",
		)
	}

	// proof data:
	// <traversal proof with multiproof> | <amount> | <image>
	if len(i.Proofs[0]) < 88 {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"verify with mint with verkle multiproof signature",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Proofs[0])
	if err != nil {
		return errors.Wrap(err, "verify with mint with verkle multiproof signature")
	}

	_, err = tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	)))
	if err == nil {
		return errors.Wrap(
			errors.New("already spent"),
			"verify with mint with verkle multiproof signature",
		)
	}

	checkBalance := big.NewInt(0)
	checkBalance.SetBytes(i.Proofs[0][len(i.Proofs[0])-88 : len(i.Proofs[0])-56])

	if checkBalance.Cmp(i.Value) != 0 {
		return errors.Wrap(
			errors.New("invalid value"),
			"verify with mint with verkle multiproof signature",
		)
	}

	traversalProof := &qcrypto.TraversalProof{}
	if err := traversalProof.FromBytes(
		i.Proofs[0][:len(i.Proofs[0])-88],
		tx.inclusionProver,
	); err != nil {
		return errors.Wrap(err, "verify with mint with verkle multiproof signature")
	}

	if !qcrypto.VerifyTreeTraversalProof(
		tx.inclusionProver,
		tx.config.MintStrategy.VerkleRoot,
		traversalProof,
	) {
		return errors.Wrap(
			errors.New("invalid traversal proof"),
			"verify with mint with verkle multiproof signature",
		)
	}

	if !bytes.Equal(
		traversalProof.SubProofs[0].Ys[len(traversalProof.SubProofs[0].Ys)-1],
		i.Proofs[0][len(i.Proofs[0])-88:],
	) {
		return errors.Wrap(
			errors.New("invalid traversal proof value"),
			"verify with mint with verkle multiproof signature",
		)
	}

	if !bytes.Equal(
		i.Proofs[0][len(i.Proofs[0])-56:],
		i.Signature[(56*4):(56*5)],
	) {
		return errors.Wrap(
			errors.New("invalid key image"),
			"verify with mint with verkle multiproof signature",
		)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return errors.Wrap(
			errors.New("invalid commitment"),
			"verify with mint with verkle multiproof signature",
		)
	}

	if valid := tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	); !valid {
		return errors.Wrap(
			errors.New("invalid signature"),
			"verify with mint with verkle multiproof signature",
		)
	}

	return nil
}

func (i *MintTransactionInput) verifyWithProofOfMeaningfulWork(
	tx *MintTransaction,
	outputTranscript []byte,
) error {
	if len(i.Proofs) != 3 {
		return errors.Wrap(
			errors.New("invalid proofs length"),
			"verify with mint with proof of meaningful work",
		)
	}

	// proof data:
	// 0: <traversal proof> - verifies length by deserialization
	// 1: <prover address> | <delegated prover pubkey> | <delegated prover sig>
	// 2: <multiproof> - verifies length by deserialization
	if len(i.Proofs[1]) < 32+585+74 {
		return errors.Wrap(
			errors.New("invalid proof length"),
			"verify with mint with verkle multiproof signature",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Proofs[0])
	if err != nil {
		return errors.Wrap(err, "verify with mint with proof of meaningful work")
	}

	_, err = tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	)))
	if err == nil {
		return errors.Wrap(
			errors.New("already spent"),
			"verify with mint with proof of meaningful work",
		)
	}

	traversalProof := &qcrypto.TraversalProof{}
	if err := traversalProof.FromBytes(
		i.Proofs[0],
		tx.inclusionProver,
	); err != nil {
		return errors.Wrap(err, "verify with mint with proof of meaningful work")
	}

	delegatedAddressBI, err := poseidon.HashBytes(i.Proofs[1][32 : 585+32])
	if err != nil {
		return errors.Wrap(
			err,
			"verify with mint with proof of meaningful work",
		)
	}

	proverRootDomain := [32]byte(tx.Domain)
	var rewardRoot []byte
	if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) {
		// Special case: PoMW mints under QUIL use global records for proofs
		proverRootDomain = intrinsics.GLOBAL_INTRINSIC_ADDRESS
		delegatedAddressBI, err = poseidon.HashBytes(
			slices.Concat(
				QUIL_TOKEN_ADDRESS[:],
				delegatedAddressBI.FillBytes(make([]byte, 32)),
			),
		)
		if err != nil {
			return errors.Wrap(
				err,
				"verify with mint with proof of meaningful work",
			)
		}

		frame, err := tx.clockStore.GetGlobalClockFrame(
			binary.BigEndian.Uint64(tx.Outputs[0].FrameNumber),
		)
		if err != nil {
			return errors.Wrap(
				err,
				"verify with mint with proof of meaningful work",
			)
		}

		rewardRoot = frame.Header.ProverTreeCommitment
	} else {
		// Normal case: use our own record of commitments
		roots, err := tx.hypergraph.GetShardCommits(
			binary.BigEndian.Uint64(tx.Outputs[0].FrameNumber),
			tx.Domain[:],
		)
		if err != nil {
			return errors.Wrap(
				err,
				"verify with mint with proof of meaningful work",
			)
		}

		rewardRoot = roots[0]
	}

	// Verify the membership proof of the prover:
	if valid, err := tx.hypergraph.VerifyTraversalProof(
		proverRootDomain,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		rewardRoot,
		traversalProof,
	); err != nil || !valid {
		return errors.Wrap(
			errors.New("invalid traversal proof"),
			"verify with mint with proof of meaningful work",
		)
	}

	pubkey := i.Proofs[1][32 : 585+32]
	signature := i.Proofs[1][585+32:]

	// Verify the state proof of the address:
	if valid, err := i.verifyProof(
		tx.hypergraph,
		[][]byte{
			i.Proofs[1][:32],
			i.Value.FillBytes(make([]byte, 32)),
		},
		i.Proofs[2],
		traversalProof,
		[]int{0, 1},
		[][]byte{nil, nil},
	); err != nil || !valid {
		return errors.Wrap(
			errors.New("invalid multiproof"),
			"verify with mint with proof of meaningful work",
		)
	}

	// Verify the address derivation to the traversal proof:
	h := sha512.New()
	h.Write([]byte{0})
	h.Write(slices.Concat(
		proverRootDomain[:],
		delegatedAddressBI.FillBytes(make([]byte, 32)),
	))
	h.Write(traversalProof.SubProofs[0].Ys[len(traversalProof.SubProofs[0].Ys)-1])

	if !bytes.Equal(
		h.Sum(nil),
		traversalProof.SubProofs[0].Commits[len(
			traversalProof.SubProofs[0].Commits,
		)-1],
	) {
		return errors.Wrap(
			errors.New("invalid traversal proof value"),
			"verify with mint with proof of meaningful work",
		)
	}

	if valid, err := tx.keyRing.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubkey,
		i.Signature[(56*4):(56*5)],
		signature,
		tx.Domain[:],
	); err != nil || !valid {
		return errors.Wrap(
			errors.New("invalid key image"),
			"verify with mint with proof of meaningful work",
		)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return errors.Wrap(
			errors.New("invalid commitment"),
			"verify with mint with proof of meaningful work",
		)
	}

	if valid := tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	); !valid {
		return errors.Wrap(
			errors.New("invalid signature"),
			"verify with mint with proof of meaningful work",
		)
	}

	return nil
}

func (i *MintTransactionInput) verifyProof(
	hg hypergraph.Hypergraph,
	data [][]byte,
	proof []byte,
	txMultiproof *qcrypto.TraversalProof,
	indices []int,
	keys [][]byte,
) (bool, error) {
	commits := [][]byte{} // same value, but needs to repeat
	evaluations := [][]byte{}
	uindices := []uint64{}
	for i, d := range data {
		h := sha512.New()
		h.Write([]byte{0})
		if keys[i] == nil {
			h.Write([]byte{byte(indices[i]) << 2})
		} else {
			h.Write(keys[i])
		}
		h.Write(d)
		out := h.Sum(nil)
		evaluations = append(evaluations, out)
		commits = append(
			commits,
			txMultiproof.SubProofs[0].Ys[len(txMultiproof.SubProofs[0].Ys)-1],
		)
		uindices = append(uindices, uint64(indices[i]))
	}

	mp := hg.GetProver().NewMultiproof()
	if err := mp.FromBytes(proof); err != nil {
		return false, errors.Wrap(err, "verify proof")
	}

	if valid := hg.GetProver().VerifyMultiple(
		commits,
		evaluations,
		uindices,
		64,
		mp.GetMulticommitment(),
		mp.GetProof(),
	); !valid {
		return false, errors.Wrap(
			errors.New("invalid proof"),
			"verify input",
		)
	}

	return true, nil
}

// MintTransactionOutput is the output specific to a MintTransaction. When
// encoded as the finalized state of the token intrinsic operation, produces a
// coin:Coin.
type MintTransactionOutput struct {
	// Public output values:

	// The frame number this output is created on
	FrameNumber []byte
	// The commitment to the balance
	Commitment []byte // Raw commitment value is stored
	// The output entries corresponding to the serialized coin:Coin
	RecipientOutput RecipientBundle

	// Private output values used for construction of public values:

	// The underlying quantity used to generate the output
	value *big.Int
}

func NewMintTransactionOutput(
	value *big.Int,
	recipientViewPubkey []byte,
	recipientSpendPubkey []byte,
) (*MintTransactionOutput, error) {
	return &MintTransactionOutput{
		value: value,
		RecipientOutput: RecipientBundle{
			recipientView:  recipientViewPubkey,
			recipientSpend: recipientSpendPubkey,
		},
	}, nil
}

func (o *MintTransactionOutput) Prove(
	res crypto.RangeProofResult,
	index int,
	tx *MintTransaction,
	frameNumber uint64,
) error {
	o.Commitment = res.Commitment[index*56 : (index+1)*56]
	blind := slices.Clone(res.Blinding[index*56 : (index+1)*56])

	var r crypto.DecafAgreement
	var err error
	if tx.config.MintStrategy.MintBehavior == MintWithSignature {
		r, err = tx.decafConstructor.NewFromScalar(
			tx.Inputs[index].contextData[len(tx.Inputs[index].contextData)-56:],
		)
		if err != nil {
			return errors.Wrap(err, "prove output")
		}
	} else {
		r, err = tx.decafConstructor.New()
		if err != nil {
			return errors.Wrap(err, "prove output")
		}
	}

	shared, err := r.AgreeWithAndHashToScalar(o.RecipientOutput.recipientView)
	if err != nil {
		return errors.Wrap(err, "prove output")
	}

	blindMask := make([]byte, 56)
	coinMask := make([]byte, 56)
	shake := sha3.NewCShake256([]byte{}, []byte("blind"))
	shake.Write(shared.Public())
	shake.Read(blindMask)

	shake = sha3.NewCShake256([]byte{}, []byte("coin"))
	shake.Write(shared.Public())
	shake.Read(coinMask)

	for i := range blindMask {
		blind[i] ^= blindMask[i]
	}

	rawBalance := o.value.FillBytes(make([]byte, 56))
	slices.Reverse(rawBalance)

	for i := range rawBalance {
		rawBalance[i] = rawBalance[i] ^ coinMask[i]
	}

	o.RecipientOutput.Mask = blind
	o.RecipientOutput.CoinBalance = rawBalance

	o.RecipientOutput.OneTimeKey = r.Public()
	o.RecipientOutput.VerificationKey, err = shared.Add(
		o.RecipientOutput.recipientSpend,
	)
	if err != nil {
		return errors.Wrap(err, "prove output")
	}

	o.FrameNumber = binary.BigEndian.AppendUint64(nil, frameNumber)

	return nil
}

func (o *MintTransactionOutput) Verify(
	frameNumber uint64,
	index int,
	tx *MintTransaction,
) (bool, error) {
	if frameNumber <= binary.BigEndian.Uint64(o.FrameNumber) {
		return false, errors.Wrap(
			errors.New("invalid frame number"),
			"verify output",
		)
	}

	if len(tx.Inputs) <= index {
		return false, errors.Wrap(
			errors.New("invalid index"),
			"verify output",
		)
	}

	switch tx.config.MintStrategy.MintBehavior {
	case MintWithSignature:
		if !bytes.Equal(
			o.RecipientOutput.VerificationKey,
			tx.Inputs[index].Proofs[0][32:88],
		) {
			return false, errors.Wrap(
				errors.New("invalid image"),
				"verify output",
			)
		}
	}

	if len(o.Commitment) != 56 ||
		len(o.RecipientOutput.OneTimeKey) != 56 ||
		len(o.RecipientOutput.VerificationKey) != 56 ||
		len(o.RecipientOutput.CoinBalance) != 56 {
		return false, errors.Wrap(
			errors.New("invalid commitment, verification key, or coin balance"),
			"verify output",
		)
	}

	if len(o.RecipientOutput.Mask) != 56 {
		return false, errors.Wrap(errors.New("missing mask"), "verify output")
	}

	return true, nil
}

// MintTransaction defines the intrinsic execution for converting a
// collection of configuration-specific inputs into coin:Coin outputs. Only
// works with tokens which have Mintable flows enabled in configuration.
type MintTransaction struct {
	Domain            [32]byte
	Inputs            []*MintTransactionInput
	Outputs           []*MintTransactionOutput
	Fees              []*big.Int
	RangeProof        []byte
	hypergraph        hypergraph.Hypergraph
	bulletproofProver crypto.BulletproofProver
	inclusionProver   crypto.InclusionProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	keyRing           keys.KeyRing
	config            *TokenIntrinsicConfiguration

	// RDF schema support
	rdfHypergraphSchema string
	rdfMultiprover      *schema.RDFMultiprover
	clockStore          store.ClockStore
}

func NewMintTransaction(
	domain [32]byte,
	inputs []*MintTransactionInput,
	outputs []*MintTransactionOutput,
	fees []*big.Int,
	config *TokenIntrinsicConfiguration,
	hypergraph hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
	keyRing keys.KeyRing,
	rdfHypergraphSchema string,
	rdfMultiprover *schema.RDFMultiprover,
	clockStore store.ClockStore,
) *MintTransaction {
	return &MintTransaction{
		Domain:              domain,
		Inputs:              inputs,
		Outputs:             outputs,
		Fees:                fees,
		hypergraph:          hypergraph,
		bulletproofProver:   bulletproofProver,
		inclusionProver:     inclusionProver,
		verEnc:              verEnc,
		decafConstructor:    decafConstructor,
		keyRing:             keyRing,
		config:              config,
		rdfHypergraphSchema: rdfHypergraphSchema,
		rdfMultiprover:      rdfMultiprover,
		clockStore:          clockStore,
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (tx *MintTransaction) GetCost() (*big.Int, error) {
	size := big.NewInt(int64(len(tx.Domain)))
	size.Add(size, big.NewInt(int64(len(tx.RangeProof))))
	for _, o := range tx.Outputs {
		size.Add(size, big.NewInt(8)) // frame number
		size.Add(size, big.NewInt(int64(len(o.Commitment))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.CoinBalance))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.Mask))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.OneTimeKey))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.VerificationKey))))
		if tx.config.Behavior&Divisible == 0 {
			size.Add(size, big.NewInt(110))
		}
	}
	return size, nil
}

func (tx *MintTransaction) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

// GetWriteAddresses implements intrinsics.IntrinsicOperation.
func (tx *MintTransaction) GetWriteAddresses(frameNumber uint64) (
	[][]byte,
	error,
) {
	addresses := [][]byte{}

	// Each output creates a new coin, which is written to an address based on
	// the verification key hash
	for _, output := range tx.Outputs {
		if output.RecipientOutput.VerificationKey != nil {
			spendCheckBI, err := poseidon.HashBytes(
				output.RecipientOutput.VerificationKey,
			)
			if err == nil {
				outputAddress := slices.Concat(
					tx.Domain[:],
					spendCheckBI.FillBytes(make([]byte, 32)),
				)
				addresses = append(addresses, outputAddress)
			}
		}
	}

	// For ProofOfMeaningfulWork, we also write to update the prover's reward
	// balance
	if tx.config.MintStrategy != nil &&
		tx.config.MintStrategy.MintBehavior == MintWithProof &&
		tx.config.MintStrategy.ProofBasis == ProofOfMeaningfulWork {

		for i := range tx.Inputs {
			proverRootDomain := [32]byte(tx.Domain)
			rewardAddress := []byte{}
			if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) {
				// Special case: PoMW mints under QUIL use global records for proofs
				proverRootDomain = intrinsics.GLOBAL_INTRINSIC_ADDRESS
				rewardAddressBI, err := poseidon.HashBytes(slices.Concat(
					QUIL_TOKEN_ADDRESS[:],
					tx.Inputs[i].Proofs[1][:32],
				))
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}
				rewardAddress = rewardAddressBI.FillBytes(make([]byte, 32))
			}

			addresses = append(addresses, slices.Concat(
				proverRootDomain[:],
				rewardAddress,
			))
		}
	}

	return addresses, nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (tx *MintTransaction) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	hypergraphState, ok := state.(*hgstate.HypergraphState)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid state type"), "materialize")
	}

	// First, update prover metadata for ProofOfMeaningfulWork
	if tx.config.MintStrategy != nil &&
		tx.config.MintStrategy.MintBehavior == MintWithProof &&
		tx.config.MintStrategy.ProofBasis == ProofOfMeaningfulWork {

		for i := 0; i < len(tx.Inputs); i++ {
			proverRootDomain := [32]byte(tx.Domain)
			rewardAddress := tx.Inputs[i].Proofs[1][:32]
			if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) {
				// Special case: PoMW mints under QUIL use global records for proofs
				proverRootDomain = intrinsics.GLOBAL_INTRINSIC_ADDRESS
				rewardAddressBI, err := poseidon.HashBytes(slices.Concat(
					QUIL_TOKEN_ADDRESS[:],
					tx.Inputs[i].Proofs[1][:32],
				))
				if err != nil {
					return nil, errors.Wrap(err, "materialize")
				}
				rewardAddress = rewardAddressBI.FillBytes(make([]byte, 32))
			}

			// Get current prover state
			vertex, err := state.Get(
				proverRootDomain[:],
				rewardAddress,
				hgstate.VertexAddsDiscriminator,
			)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

			var proverTree *qcrypto.VectorCommitmentTree
			var ok bool
			proverTree, ok = vertex.(*qcrypto.VectorCommitmentTree)
			if !ok || proverTree == nil {
				return nil, errors.Wrap(
					errors.New("invalid object returned for vertex"),
					"materialize",
				)
			}

			// Get current balance
			currentBalanceData, err := proverTree.Get([]byte{1 << 2})
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

			currentBalance := big.NewInt(0)
			currentBalance.SetBytes(currentBalanceData)

			// Calculate total minted value
			totalMinted := big.NewInt(0)
			for _, input := range tx.Inputs {
				totalMinted.Add(totalMinted, input.Value)
			}

			if currentBalance.Cmp(totalMinted) < 0 {
				return nil, errors.Wrap(
					errors.New("insufficient prover balance"),
					"materialize",
				)
			}

			// Subtract from prover balance
			newBalance := new(big.Int).Sub(currentBalance, totalMinted)

			// Set new balance at index 1
			newBalanceBytes := newBalance.FillBytes(make([]byte, 32))
			if err := proverTree.Insert(
				[]byte{1 << 2},
				newBalanceBytes,
				nil,
				big.NewInt(32),
			); err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

			// Create materialized state for prover update
			proverUpdate := hypergraphState.NewVertexAddMaterializedState(
				proverRootDomain,
				[32]byte(rewardAddress),
				frameNumber,
				nil,
				proverTree,
			)

			// Set the state
			err = hypergraphState.Set(
				proverRootDomain[:],
				rewardAddress,
				hgstate.VertexAddsDiscriminator,
				frameNumber,
				proverUpdate,
			)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}
		}
	}

	refs := []*qcrypto.VectorCommitmentLeafNode{}

	if tx.config.Behavior&Divisible == 0 {
		if tx.config.MintStrategy.Authority == nil {
			addrefsVertex, err := state.Get(
				tx.Domain[:],
				TOKEN_ADDITIONAL_REFRENCES_ADDRESS[:],
				hgstate.VertexAddsDiscriminator,
			)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

			var addrefsTree *qcrypto.VectorCommitmentTree
			var ok bool
			addrefsTree, ok = addrefsVertex.(*qcrypto.VectorCommitmentTree)
			if !ok || addrefsTree == nil {
				return nil, errors.Wrap(
					errors.New("invalid object returned for vertex"),
					"materialize",
				)
			}

			if addrefsTree.GetSize().Cmp(big.NewInt(0)) == 0 {
				return nil, errors.Wrap(
					errors.New("missing additional references"),
					"materialize",
				)
			}

			for i := 0; i < len(tx.Outputs); i++ {
				newRefs := qcrypto.GetNPreloadedLeaves(addrefsTree.Root, 2)
				if len(newRefs) != 2 {
					return nil, errors.Wrap(
						errors.New("missing additional references"),
						"materialize",
					)
				}

				addrefsTree.Delete(newRefs[0].Key)
				addrefsTree.Delete(newRefs[1].Key)
				refs = append(refs, newRefs...)
			}

			// Set the state
			err = hypergraphState.Set(
				tx.Domain[:],
				TOKEN_ADDITIONAL_REFRENCES_ADDRESS[:],
				hgstate.VertexAddsDiscriminator,
				frameNumber,
				hypergraphState.NewVertexAddMaterializedState(
					tx.Domain,
					TOKEN_ADDITIONAL_REFRENCES_ADDRESS,
					frameNumber,
					nil,
					addrefsTree,
				),
			)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}
		}
	}

	// Now create coins for each output
	for i, output := range tx.Outputs {
		if output.RecipientOutput.VerificationKey == nil {
			return nil, errors.Wrap(
				errors.New("missing verification key"),
				"materialize",
			)
		}

		// Create the coin tree
		coinTree := &qcrypto.VectorCommitmentTree{}

		// Get the type discriminator for coin:Coin
		coinTypeBI, err := poseidon.HashBytes(
			slices.Concat(tx.Domain[:], []byte("coin:Coin")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
		coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

		// Insert type at 0xff..ff
		if err := coinTree.Insert(
			bytes.Repeat([]byte{0xff}, 32),
			coinTypeBytes,
			nil,
			big.NewInt(32),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Insert coin data according to schema:
		// 0: FrameNumber (8 bytes)
		if err := coinTree.Insert(
			[]byte{0},
			output.FrameNumber,
			nil,
			big.NewInt(8),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 1: Commitment (56 bytes)
		if err := coinTree.Insert(
			[]byte{1 << 2},
			output.Commitment,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 2: OneTimeKey (56 bytes)
		if err := coinTree.Insert(
			[]byte{2 << 2},
			output.RecipientOutput.OneTimeKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 3: VerificationKey (56 bytes)
		if err := coinTree.Insert(
			[]byte{3 << 2},
			output.RecipientOutput.VerificationKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 4: CoinBalance (56 bytes)
		if err := coinTree.Insert(
			[]byte{4 << 2},
			output.RecipientOutput.CoinBalance,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 5: Mask (56 bytes)
		if err := coinTree.Insert(
			[]byte{5 << 2},
			output.RecipientOutput.Mask,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// 6-7: AdditionalReference (if non-divisible)
		if tx.config.Behavior&Divisible == 0 {
			if tx.config.MintStrategy.Authority == nil {
				for j := 0; j < 2; j++ {
					additionalReferenceValue := slices.Clone(refs[i*2+j].Value)

					if err := coinTree.Insert(
						[]byte{byte((6 + j) << 2)},
						additionalReferenceValue,
						nil,
						big.NewInt(int64(len(additionalReferenceValue))),
					); err != nil {
						return nil, errors.Wrap(err, "materialize")
					}
				}
			} else {
				if err := coinTree.Insert(
					[]byte{byte(6 << 2)},
					tx.Inputs[i].AdditionalReference,
					nil,
					big.NewInt(int64(len(tx.Inputs[i].AdditionalReference))),
				); err != nil {
					return nil, errors.Wrap(err, "materialize")
				}
				if err := coinTree.Insert(
					[]byte{byte(7 << 2)},
					tx.Inputs[i].AdditionalReferenceKey,
					nil,
					big.NewInt(int64(len(tx.Inputs[i].AdditionalReferenceKey))),
				); err != nil {
					return nil, errors.Wrap(err, "materialize")
				}
			}
		}

		commit := coinTree.Commit(tx.inclusionProver, false)
		outAddrBI, err := poseidon.HashBytes(commit)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		outputAddress := outAddrBI.FillBytes(make([]byte, 32))

		// Create materialized state for coin
		coinState := hypergraphState.NewVertexAddMaterializedState(
			tx.Domain,
			[32]byte(outputAddress),
			frameNumber,
			nil,
			coinTree,
		)

		// Set the state
		err = hypergraphState.Set(
			tx.Domain[:],
			outputAddress,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			coinState,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	for i := 0; i < len(tx.Inputs); i++ {
		spentAddressBI, err := poseidon.HashBytes(tx.Inputs[i].Proofs[0])
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		spentAddress := spentAddressBI.FillBytes(make([]byte, 32))

		// Create spent marker
		spentTree := &qcrypto.VectorCommitmentTree{}
		if err := spentTree.Insert(
			[]byte{0},
			[]byte{0x01},
			nil,
			big.NewInt(0),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Create materialized state for spend
		spentState := hypergraphState.NewVertexAddMaterializedState(
			tx.Domain,
			[32]byte(spentAddress),
			frameNumber,
			nil,
			spentTree,
		)

		// Set the state
		err = hypergraphState.Set(
			tx.Domain[:],
			spentAddress,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			spentState,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	return hypergraphState, nil
}

func (tx *MintTransaction) Prove(frameNumber uint64) error {
	if tx.config.MintStrategy == nil ||
		tx.config.MintStrategy.MintBehavior == NoMintBehavior {
		return errors.Wrap(errors.New("token is not mintable"), "prove")
	}

	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 ||
		len(tx.Inputs) > 100 || len(tx.Outputs) > 100 {
		return errors.Wrap(
			errors.New("invalid quantity of inputs, outputs, or proofs"),
			"prove",
		)
	}

	values := []*big.Int{}
	for _, o := range tx.Outputs {
		values = append(values, o.value)
	}

	blinds := []byte{}
	for i, input := range tx.Inputs {
		blind, err := input.Prove(tx, i)
		if err != nil {
			return errors.Wrap(err, "prove")
		}

		blinds = append(blinds, blind...)
	}

	res, err := tx.bulletproofProver.GenerateRangeProofFromBig(
		values,
		blinds,
		128,
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	if len(res.Commitment) != len(tx.Outputs)*56 {
		return errors.Wrap(errors.New("invalid range proof"), "prove")
	}

	for i, o := range tx.Outputs {
		if err := o.Prove(res, i, tx, frameNumber); err != nil {
			return errors.Wrap(err, "prove")
		}
	}

	challenge, err := tx.GetChallenge()
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	for _, input := range tx.Inputs {
		if err := input.signOp(challenge); err != nil {
			return errors.Wrap(err, "prove")
		}
	}

	tx.RangeProof = res.Proof

	return nil
}

func (tx *MintTransaction) GetChallenge() ([]byte, error) {
	transcript := []byte{}
	for _, input := range tx.Inputs {
		for _, proof := range input.Proofs {
			transcript = append(transcript, proof...)
		}
	}
	transcript = append(transcript, tx.Domain[:]...)
	for _, o := range tx.Outputs {
		transcript = append(transcript, o.Commitment...)
		transcript = append(transcript, o.FrameNumber...)
		if len(o.RecipientOutput.AdditionalReference) == 64 {
			transcript = append(transcript, o.RecipientOutput.AdditionalReference...)
			transcript = append(
				transcript,
				o.RecipientOutput.AdditionalReferenceKey...,
			)
		}
		transcript = append(transcript, o.RecipientOutput.CoinBalance...)
		transcript = append(transcript, o.RecipientOutput.Mask...)
		transcript = append(transcript, o.RecipientOutput.OneTimeKey...)
		transcript = append(transcript, o.RecipientOutput.VerificationKey...)
	}

	challenge, err := tx.decafConstructor.HashToScalar(transcript)
	return challenge.Private(), errors.Wrap(err, "get challenge")
}

// Verifies the mint transaction's validity at the given frame number. If
// invalid, also provides the associated error.
func (tx *MintTransaction) Verify(frameNumber uint64) (bool, error) {
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 ||
		len(tx.Inputs) > 100 || len(tx.Outputs) > 100 {
		return false, errors.Wrap(
			errors.New("invalid quantity of inputs, outputs, or proofs"),
			"verify",
		)
	}

	for _, fee := range tx.Fees {
		if fee == nil ||
			new(big.Int).Lsh(big.NewInt(1), uint(128)).Cmp(fee) < 0 ||
			new(big.Int).Cmp(fee) > 0 {
			return false, errors.Wrap(errors.New("invalid fees"), "verify")
		}
	}

	if tx.config.Behavior&Divisible == 0 && len(tx.Inputs) != len(tx.Outputs) {
		return false, errors.Wrap(
			errors.New("non-divisible token has mismatching inputs and outputs"),
			"verify",
		)
	}

	challenge, err := tx.GetChallenge()
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	inputs := [][]byte{}
	check := map[string]struct{}{}
	for i, input := range tx.Inputs {
		if valid, err := input.Verify(
			frameNumber,
			i,
			challenge,
			tx,
		); !valid {
			return false, errors.Wrap(err, "verify")
		}

		if _, ok := check[string(input.Signature[(56*4):(56*5)])]; ok {
			return false, errors.Wrap(
				errors.New("attempted double-spend"),
				"verify",
			)
		}
		check[string(input.Signature[(56*4):(56*5)])] = struct{}{}
		inputs = append(inputs, input.Commitment)
	}

	commitment := make([]byte, len(tx.Outputs)*56)
	commitments := [][]byte{}
	for i, o := range tx.Outputs {
		if valid, err := o.Verify(frameNumber, i, tx); !valid {
			return false, errors.Wrap(err, "verify")
		}

		spendCheckBI, err := poseidon.HashBytes(o.RecipientOutput.VerificationKey)
		if err != nil {
			return false, errors.Wrap(err, "verify")
		}

		_, err = tx.hypergraph.GetVertex([64]byte(
			slices.Concat(tx.Domain[:], spendCheckBI.FillBytes(make([]byte, 32))),
		))
		if err == nil {
			return false, errors.Wrap(
				errors.New("invalid verification key"),
				"verify",
			)
		}

		copy(commitment[i*56:(i+1)*56], tx.Outputs[i].Commitment[:])
		commitments = append(commitments, tx.Outputs[i].Commitment)
	}

	if !tx.bulletproofProver.VerifyRangeProof(tx.RangeProof, commitment, 128) {
		return false, errors.Wrap(errors.New("invalid range proof"), "verify")
	}

	// There are no fees in the sumcheck, either because QUIL token native mint
	// is free, or because the carried fee has no basis in the denomination being
	// minted.
	if !tx.bulletproofProver.SumCheck(
		inputs,
		[]*big.Int{},
		commitments,
		[]*big.Int{},
	) {
		return false, errors.Wrap(errors.New("invalid sum check"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*MintTransaction)(nil)
