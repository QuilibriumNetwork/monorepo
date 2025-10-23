package token

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

const FRAME_2_1_CUTOVER = 244200
const FRAME_2_1_EXTENDED_ENROLL_END = 252840
const FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END = FRAME_2_1_EXTENDED_ENROLL_END + 360

// used to skip frame-based checks, for tests
var BEHAVIOR_PASS = false

// using ed448 derivation process of seed = [57]byte{0x00..}
var publicReadKey, _ = hex.DecodeString("2cf07ca8d9ab1a4bb0902e25a9b90759dd54d881f54d52a76a17e79bf0361c325650f12746e4337ffb5940e7665ad7bf83f44af98d964bbe")

// TransactionInput is an input specific to the Transaction flow, where a token
// intrinsic is either configured as Acceptable, and the input is thus a
// pending:PendingTransaction, or not Acceptable, and the input is thus a
// coin:Coin.
type TransactionInput struct {
	// Public input values:

	// The constructed commitment to the input balance.
	Commitment []byte
	// The underlying signature authorizing spend and proving validity.
	Signature []byte
	// The proofs of various attributes of the token. Must verify against the
	// transaction's multiproofs for full end-to-end verification.
	Proofs [][]byte

	// Private input values used for construction of public values:

	// The address of the input value
	address []byte
	// The underlying input value
	value *big.Int
	// The signing operation which sets the signature, after the outputs are
	// generated.
	signOp func(transcript []byte) error
}

func NewTransactionInput(address []byte) (*TransactionInput, error) {
	return &TransactionInput{
		address: address,
	}, nil
}

func (i *TransactionInput) Prove(tx *Transaction, index int) ([]byte, error) {
	_, err := tx.hypergraph.GetVertex([64]byte(i.address))
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	tree, err := tx.hypergraph.GetVertexData([64]byte(i.address))
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	fnData, err := tree.Get([]byte{0})
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	frameNumber := uint64(0)
	if len(fnData) != 8 {
		return nil, errors.Wrap(errors.New("invalid frame number"), "prove input")
	} else {
		frameNumber = binary.BigEndian.Uint64(fnData[:8])
	}

	var blind []byte

	if bytes.Equal(i.address[:32], QUIL_TOKEN_ADDRESS) &&
		frameNumber <= FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END && !BEHAVIOR_PASS {
		return nil, errors.Wrap(errors.New("invalid action"), "prove input")
	}

	coinTypeBI, err := poseidon.HashBytes(
		slices.Concat(i.address[:32], []byte("coin:Coin")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

	pendingTypeBI, err := poseidon.HashBytes(
		slices.Concat(i.address[:32], []byte("pending:PendingTransaction")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	pendingTypeBytes := pendingTypeBI.FillBytes(make([]byte, 32))

	checkType, err := tree.Get(bytes.Repeat([]byte{0xff}, 32))
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	commitmentIndex := 1 << 2
	oneTimeKeyIndex := 2 << 2
	keyImageIndex := 3 << 2
	coinBalanceIndex := 4 << 2
	blindIndex := 5 << 2
	addRef1Index := 6 << 2
	addRef2Index := 7 << 2

	if !bytes.Equal(coinTypeBytes, checkType) &&
		tx.config.Behavior&Acceptable == 0 {
		return nil, errors.Wrap(
			errors.New("invalid type for address"),
			"prove input",
		)
	}

	if tx.config.Behavior&Acceptable != 0 {
		if !bytes.Equal(pendingTypeBytes, checkType) {
			return nil, errors.Wrap(
				errors.New(
					fmt.Sprintf(
						"invalid type for address: %x, expected %x",
						checkType,
						pendingTypeBytes,
					),
				),
				"prove input",
			)
		}

		commitmentIndex = 1 << 2
		oneTimeKeyIndex = 2 << 2
		keyImageIndex = 4 << 2
		coinBalanceIndex = 6 << 2
		blindIndex = 8 << 2
		addRef1Index = 10 << 2
		addRef2Index = 11 << 2

		// R
		oneTimeKey, err := tree.Get([]byte{byte(oneTimeKeyIndex)})
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		// VK
		possibleViewKey, err := tx.keyRing.GetAgreementKey(
			"q-view-key",
			i.address,
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
		if !ok {
			return nil, errors.Wrap(errors.New("invalid view key"), "prove input")
		}

		// SK
		possibleSpendKey, err := tx.keyRing.GetAgreementKey(
			"q-spend-key",
			i.address,
			crypto.KeyTypeDecaf448,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
		if !ok {
			return nil, errors.Wrap(errors.New("invalid spend key"), "prove input")
		}

		// rVK
		shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		checkKeyImage, err := shared.Add(spendKey.Public())
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		keyImage, err := tree.Get([]byte{byte(keyImageIndex)})
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		if !bytes.Equal(checkKeyImage, keyImage) {
			oneTimeKeyIndex = 3 << 2
			keyImageIndex = 5 << 2
			coinBalanceIndex = 7 << 2
			blindIndex = 9 << 2
			addRef1Index = 12 << 2
			addRef2Index = 13 << 2
		}
	}

	// C
	commitment, err := tree.Get([]byte{byte(commitmentIndex)})
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	// R
	oneTimeKey, err := tree.Get([]byte{byte(oneTimeKeyIndex)})
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	// VK
	possibleViewKey, err := tx.keyRing.GetAgreementKey(
		"q-view-key",
		i.address,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	viewKey, ok := possibleViewKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid view key"), "prove input")
	}

	// SK
	possibleSpendKey, err := tx.keyRing.GetAgreementKey(
		"q-spend-key",
		i.address,
		crypto.KeyTypeDecaf448,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	spendKey, ok := possibleSpendKey.(crypto.DecafAgreement)
	if !ok {
		return nil, errors.Wrap(errors.New("invalid spend key"), "prove input")
	}

	// rVK
	shared, err := viewKey.AgreeWithAndHashToScalar(oneTimeKey)
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	coinBalanceData, err := tree.Get([]byte{byte(coinBalanceIndex)})
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	blindData, err := tree.Get([]byte{byte(blindIndex)})
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
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
		blindData[i] ^= blindMask[i]
	}

	blind = blindData

	balance := make([]byte, len(coinBalanceData))

	for i := range coinBalanceData {
		balance[len(balance)-i-1] = coinBalanceData[i] ^ coinMask[i]
		coinBalanceData[i] ^= coinMask[i]
	}

	// If non-divisible, outputs should be aligned input-relative
	if tx.config.Behavior&Divisible == 0 {
		addRef, err := tree.Get([]byte{byte(addRef1Index)})
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
		addRefKey, err := tree.Get([]byte{byte(addRef2Index)})
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		tx.Outputs[index].rawAdditionalReference = addRef
		tx.Outputs[index].rawAdditionalReferenceKey = addRefKey
	}

	i.value = new(big.Int).SetBytes(balance)
	i.signOp = func(transcript []byte) error {
		i.Signature = tx.bulletproofProver.SignHidden(
			shared.Private(),
			spendKey.Private(),
			transcript,
			coinBalanceData,
			blindData,
		)

		return nil
	}

	if tx.rdfMultiprover == nil || tx.rdfHypergraphSchema == "" {
		return nil, errors.Wrap(
			errors.New("RDF multiprover not available"),
			"prove input",
		)
	}

	if tx.config.Behavior&Acceptable == 0 {
		// coin:Coin inputs
		fields := []string{
			"coin:Coin.Commitment",
			"coin:Coin.VerificationKey",
		}
		if tx.config.Behavior&Divisible == 0 {
			fields = append(
				fields,
				"coin:Coin.AdditionalReference",
				"coin:Coin.AdditionalReferenceKey",
			)
		}
		typeIndex := uint64(63)
		multiproof, err := tx.rdfMultiprover.ProveWithType(
			tx.rdfHypergraphSchema,
			fields,
			tree,
			&typeIndex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
		multiproofBytes, err := multiproof.ToBytes()
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
		i.Proofs = [][]byte{multiproofBytes}
		if tx.config.Behavior&Divisible == 0 {
			addref, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"coin:Coin",
				"AdditionalReference",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
			addrefkey, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"coin:Coin",
				"AdditionalReferenceKey",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
			i.Proofs = append(i.Proofs, slices.Concat(addref, addrefkey))
		}
	} else {
		// pending:PendingTransaction inputs
		fields := []string{
			"pending:PendingTransaction.Commitment",
			"pending:PendingTransaction.ToVerificationKey",
			"pending:PendingTransaction.RefundVerificationKey",
		}

		if tx.config.Behavior&Divisible == 0 {
			fields = append(
				fields,
				"pending:PendingTransaction.ToAdditionalReference",
				"pending:PendingTransaction.ToAdditionalReferenceKey",
				"pending:PendingTransaction.RefundAdditionalReference",
				"pending:PendingTransaction.RefundAdditionalReferenceKey",
			)
		}

		// Add expiration field if needed
		if tx.config.Behavior&Expirable != 0 {
			fields = append(fields, "pending:PendingTransaction.Expiration")
		}

		typeIndex := uint64(63)
		multiproof, err := tx.rdfMultiprover.ProveWithType(
			tx.rdfHypergraphSchema,
			fields,
			tree,
			&typeIndex,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		multiproofBytes, err := multiproof.ToBytes()
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
		i.Proofs = [][]byte{multiproofBytes}

		// Get expiration value if needed
		var exp []byte = nil
		if tx.config.Behavior&Expirable != 0 {
			exp, err = tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"pending:PendingTransaction",
				"Expiration",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
		}

		if exp != nil {
			i.Proofs = append(i.Proofs, exp)
		}

		// To, so refund
		if keyImageIndex>>2 == 4 {
			refundImage, err := tree.Get([]byte{5 << 2})
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}

			i.Proofs = append(i.Proofs, []byte{2}, refundImage)
		} else { // Refund, so to
			toImage, err := tree.Get([]byte{4 << 2})
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}

			i.Proofs = append(i.Proofs, []byte{1}, toImage)
		}

		if tx.config.Behavior&Divisible == 0 {
			addref, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"pending:PendingTransaction",
				"ToAdditionalReference",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
			addrefkey, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"pending:PendingTransaction",
				"ToAdditionalReferenceKey",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
			i.Proofs = append(i.Proofs, slices.Concat(addref, addrefkey))
		}
	}

	i.Commitment = commitment

	return blind, nil
}

// Verifies an input's signature, if a QUIL transaction, allows legacy
// verification. If invalid, has an associated error.
func (i *TransactionInput) Verify(
	frameNumber uint64,
	tx *Transaction,
	transcript []byte,
	checkLegacy bool,
	txMultiproof *qcrypto.TraversalProof,
	index int,
) (bool, error) {
	if len(i.Commitment) != 56 {
		return false, errors.Wrap(
			errors.New("invalid commitment length"),
			"verify input",
		)
	}

	if len(i.Signature) != 336 {
		return false, errors.Wrap(
			errors.New("invalid signature length"),
			"verify input",
		)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return false, errors.Wrap(
			errors.New("invalid commitment"),
			"verify input",
		)
	}

	spendCheckBI, err := poseidon.HashBytes(i.Signature[56*4 : 56*5])
	if err != nil {
		return false, errors.Wrap(
			errors.New("invalid address"),
			"verify input",
		)
	}

	// Key has been committed to hypergraph, Coin is already spent
	if v, err := tx.hypergraph.GetVertex([64]byte(slices.Concat(
		tx.Domain[:],
		spendCheckBI.FillBytes(make([]byte, 32)),
	))); err == nil && v != nil {
		return false, errors.Wrap(err, "verify input")
	}

	addRefDelta := 0
	if tx.config.Behavior&Divisible == 0 {
		addRefDelta++
		if len(i.Proofs[len(i.Proofs)-1]) != 64+56 {
			return false, errors.Wrap(
				errors.New("invalid proof"),
				"verify input",
			)
		}
	}

	if len(i.Proofs) == 1+addRefDelta {
		if tx.config.Behavior&Acceptable != 0 {
			return false, errors.Wrap(
				errors.New(fmt.Sprintf("invalid proof length: %d", len(i.Proofs))),
				"verify input",
			)
		}

		coinTypeBI, err := poseidon.HashBytes(
			slices.Concat(tx.Domain[:], []byte("coin:Coin")),
		)
		if err != nil {
			return false, errors.Wrap(err, "verify input")
		}

		inputs := [][]byte{
			i.Signature[56*5 : 56*6],
			i.Signature[56*4 : 56*5],
		}
		indices := []int{1, 3}
		if tx.config.Behavior&Divisible == 0 {
			inputs = append(inputs, i.Proofs[1][:64], i.Proofs[1][64:])
			indices = append(indices, 6, 7)
		}
		indices = append(indices, 63)

		coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

		inputs = append(inputs, coinTypeBytes)
		keys := make([][]byte, len(inputs))
		keys[len(keys)-1] = bytes.Repeat([]byte{0xff}, 32)
		if valid, err := i.verifyProof(
			tx.hypergraph,
			inputs,
			i.Proofs[0],
			txMultiproof,
			indices,
			keys,
			index,
		); err != nil || !valid {
			return false, err
		}
	} else {
		if tx.config.Behavior&Acceptable == 0 {
			return false, errors.Wrap(
				errors.New(fmt.Sprintf("invalid proof length: %d", len(i.Proofs))),
				"verify input",
			)
		}

		pendingTypeBI, err := poseidon.HashBytes(
			slices.Concat(tx.Domain[:], []byte("pending:PendingTransaction")),
		)
		if err != nil {
			return false, errors.Wrap(err, "verify input")
		}

		pendingTypeBytes := pendingTypeBI.FillBytes(make([]byte, 32))

		indices := []int{1, 4, 5}
		data := [][]byte{i.Signature[56*5 : 56*6]}

		offset := 0
		expiration := uint64(0)
		if tx.config.Behavior&Expirable != 0 {
			offset = 1
			proofIndex := 10
			if len(i.Proofs) != 4+addRefDelta {
				return false, errors.Wrap(
					errors.New(fmt.Sprintf("invalid proof length: %d", len(i.Proofs))),
					"verify input",
				)
			}
			if tx.config.Behavior&Divisible == 0 {
				indices = append(indices, 10, 11, 12, 13)
				proofIndex = 14
			}

			expiration = binary.BigEndian.Uint64(i.Proofs[1])
			indices = append(indices, proofIndex)
		} else {
			if len(i.Proofs) != 3+addRefDelta {
				return false, errors.Wrap(
					errors.New(fmt.Sprintf("invalid proof length: %d", len(i.Proofs))),
					"verify input",
				)
			}
		}

		altCheckBI, err := poseidon.HashBytes(i.Proofs[offset+2])
		if err != nil {
			return false, errors.Wrap(
				errors.New("invalid address"),
				"verify input",
			)
		}

		// Key has been committed to hypergraph, Pending is already spent
		if v, err := tx.hypergraph.GetVertex([64]byte(slices.Concat(
			tx.Domain[:],
			altCheckBI.FillBytes(make([]byte, 32)),
		))); err == nil && v != nil {
			return false, errors.Wrap(err, "verify input")
		}

		isTo := bytes.Equal(i.Proofs[offset+1], []byte{2})

		if isTo {
			data = append(data, i.Signature[56*4:56*5], i.Proofs[offset+2])
		} else {
			if frameNumber < expiration {
				return false, errors.Wrap(
					errors.New("not expired"),
					"verify input",
				)
			}

			data = append(data, i.Proofs[offset+2], i.Signature[56*4:56*5])
		}

		if tx.config.Behavior&Divisible == 0 {
			data = append(
				data,
				i.Proofs[offset+3][:64],
				i.Proofs[offset+3][64:],
				i.Proofs[offset+3][:64],
				i.Proofs[offset+3][64:],
			)
		}

		if tx.config.Behavior&Expirable != 0 {
			data = append(data, i.Proofs[1])
		}
		data = append(data, pendingTypeBytes)

		indices = append(indices, 63)
		keys := [][]byte{}
		for i := 0; i < len(data)-1; i++ {
			keys = append(keys, nil)
		}
		keys = append(keys, bytes.Repeat([]byte{0xff}, 32))

		if valid, err := i.verifyProof(
			tx.hypergraph,
			data,
			i.Proofs[0],
			txMultiproof,
			indices,
			keys,
			index,
		); err != nil || !valid {
			return false, errors.Wrap(err, "verify input")
		}
	}

	return tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		transcript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	), nil
}

func (i *TransactionInput) verifyProof(
	hg hypergraph.Hypergraph,
	data [][]byte,
	proof []byte,
	txMultiproof *qcrypto.TraversalProof,
	indices []int,
	keys [][]byte,
	index int,
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
			txMultiproof.SubProofs[index].Ys[len(txMultiproof.SubProofs[index].Ys)-1],
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

// RecipientBundle is the bundle of values that represents a recipient's output.
type RecipientBundle struct {
	// Public output values:

	// The public key used to derive shared secret for mask and balance.
	OneTimeKey []byte // Raw pubkey value is stored
	// The public key used to verify spend output.
	VerificationKey []byte // Raw pubkey value is stored
	// The encrypted underlying masked balance of the coin.
	CoinBalance []byte
	// The encrypted mask.
	Mask []byte
	// The address value optionally used for non-divisible/interchangeable units.
	AdditionalReference []byte
	// The key associated with the AdditionalReference, present if
	// AdditionalReference is present
	AdditionalReferenceKey []byte

	// Private output values use for construction of public values:

	// The public view key of the recipient
	recipientView []byte
	// The public spend key of the recipient
	recipientSpend []byte
}

// TransactionOutput is the output specific to a Transaction. When encoded as
// the finalized state of the token intrinsic operation, produces a coin:Coin.
type TransactionOutput struct {
	// Public output values:

	// The frame number this output is created on
	FrameNumber []byte
	// The commitment to the balance
	Commitment []byte // Raw commitment value is stored
	// The output entries corresponding to the serialized coin:Coin
	RecipientOutput RecipientBundle

	// Private output values use for construction of public values:

	// The underlying quantity used to generate the output
	value *big.Int
	// The underlying raw additionalReference value mapped from input, if present
	rawAdditionalReference []byte
	// The underlying raw additionalReferenceKey value mapped from input, if
	// present
	rawAdditionalReferenceKey []byte
}

func NewTransactionOutput(
	value *big.Int,
	recipientViewPubkey []byte,
	recipientSpendPubkey []byte,
) (*TransactionOutput, error) {
	return &TransactionOutput{
		value: value,
		RecipientOutput: RecipientBundle{
			recipientView:  recipientViewPubkey,
			recipientSpend: recipientSpendPubkey,
		},
	}, nil
}

func (o *TransactionOutput) Prove(
	res crypto.RangeProofResult,
	index int,
	tx *Transaction,
	frameNumber uint64,
) error {
	o.Commitment = res.Commitment[index*56 : (index+1)*56]
	blind := slices.Clone(res.Blinding[index*56 : (index+1)*56])
	r, err := tx.decafConstructor.New()
	if err != nil {
		return errors.Wrap(err, "prove output")
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

	// TODO(2.1.1+): there's some other options we can pursue here, leaving this
	// section a bare copy until then.
	if tx.config.Behavior&Divisible == 0 {
		addRef := slices.Clone(tx.Outputs[index].rawAdditionalReference)
		addRefKey := slices.Clone(tx.Outputs[index].rawAdditionalReferenceKey)

		tx.Outputs[index].RecipientOutput.AdditionalReference = addRef
		tx.Outputs[index].RecipientOutput.AdditionalReferenceKey = addRefKey
	}

	o.FrameNumber = binary.BigEndian.AppendUint64(nil, frameNumber)

	return nil
}

func (o *TransactionOutput) Verify(
	frameNumber uint64,
	config *TokenIntrinsicConfiguration,
) (bool, error) {
	if frameNumber <= binary.BigEndian.Uint64(o.FrameNumber) {
		return false, errors.Wrap(
			errors.New("invalid frame number"),
			"verify output",
		)
	}

	if len(o.Commitment) != 56 ||
		len(o.RecipientOutput.VerificationKey) != 56 ||
		len(o.RecipientOutput.CoinBalance) != 56 {
		return false, errors.Wrap(
			errors.New("invalid commitment, verification key, or coin balance"),
			"verify output",
		)
	}

	if config.Behavior&Divisible == 0 {
		if len(o.RecipientOutput.AdditionalReference) != 64 {
			return false, errors.Wrap(
				errors.New("missing additional reference for non-divisible coin"),
				"verify output",
			)
		}

		if len(o.RecipientOutput.AdditionalReferenceKey) != 56 {
			return false, errors.Wrap(
				errors.New("missing additional reference key for non-divisible coin"),
				"verify output",
			)
		}
	}

	if len(o.RecipientOutput.Mask) != 56 {
		return false, errors.Wrap(errors.New("missing mask"), "verify output")
	}

	return true, nil
}

// Transaction defines the intrinsic execution for converting a collection of
// coin:Coin or pending:PendingTransaction inputs into coin:Coin outputs,
// depending on configuration. If the token has Acceptable flows enabled,
// expects inputs of type pending:PendingTransaction in configuration, otherwise
// expects coin:Coin inputs.
type Transaction struct {
	Domain              [32]byte
	Inputs              []*TransactionInput
	Outputs             []*TransactionOutput
	Fees                []*big.Int
	RangeProof          []byte
	TraversalProof      *qcrypto.TraversalProof
	hypergraph          hypergraph.Hypergraph
	bulletproofProver   crypto.BulletproofProver
	inclusionProver     crypto.InclusionProver
	verEnc              crypto.VerifiableEncryptor
	decafConstructor    crypto.DecafConstructor
	keyRing             keys.KeyRing
	config              *TokenIntrinsicConfiguration
	rdfHypergraphSchema string
	rdfMultiprover      *schema.RDFMultiprover
}

func NewTransaction(
	domain [32]byte,
	inputs []*TransactionInput,
	outputs []*TransactionOutput,
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
) *Transaction {
	return &Transaction{
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
	}
}

// GetCost implements intrinsics.IntrinsicOperation.
func (tx *Transaction) GetCost() (*big.Int, error) {
	size := big.NewInt(int64(len(tx.Domain)))
	size.Add(size, big.NewInt(int64(len(tx.RangeProof))))

	pb, err := tx.TraversalProof.ToBytes()
	if err != nil {
		return nil, errors.Wrap(err, "get cost")
	}
	size.Add(size, big.NewInt(int64(len(pb))))

	for _, o := range tx.Outputs {
		size.Add(size, big.NewInt(8)) // frame number
		size.Add(size, big.NewInt(int64(len(o.Commitment))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.CoinBalance))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.Mask))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.OneTimeKey))))
		size.Add(size, big.NewInt(int64(len(o.RecipientOutput.VerificationKey))))
		if len(o.RecipientOutput.AdditionalReference) == 64 {
			size.Add(size, big.NewInt(120))
		}
	}

	return size, nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (tx *Transaction) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	ms := state.(*hgstate.HypergraphState)

	// Create the coin type hash
	coinTypeBI, err := poseidon.HashBytes(
		slices.Concat(tx.Domain[:], []byte("coin:Coin")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "materialize")
	}
	coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

	// For each output, create a coin
	for _, output := range tx.Outputs {
		// Create coin tree
		coinTree := &qcrypto.VectorCommitmentTree{}

		// Index 0: FrameNumber
		if err := coinTree.Insert(
			[]byte{0},
			output.FrameNumber,
			nil,
			big.NewInt(8),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 1: Commitment
		if err := coinTree.Insert(
			[]byte{1 << 2},
			output.Commitment,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 2: OneTimeKey
		if err := coinTree.Insert(
			[]byte{2 << 2},
			output.RecipientOutput.OneTimeKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 3: VerificationKey
		if err := coinTree.Insert(
			[]byte{3 << 2},
			output.RecipientOutput.VerificationKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 4: CoinBalance (encrypted)
		if err := coinTree.Insert(
			[]byte{4 << 2},
			output.RecipientOutput.CoinBalance,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 5: Mask (encrypted)
		if err := coinTree.Insert(
			[]byte{5 << 2},
			output.RecipientOutput.Mask,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Index 6 & 7: Additional references (for non-divisible tokens)
		if len(output.RecipientOutput.AdditionalReference) == 64 &&
			len(output.RecipientOutput.AdditionalReferenceKey) == 56 {
			if err := coinTree.Insert(
				[]byte{6 << 2},
				output.RecipientOutput.AdditionalReference,
				nil,
				big.NewInt(56),
			); err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

			if err := coinTree.Insert(
				[]byte{7 << 2},
				output.RecipientOutput.AdditionalReferenceKey,
				nil,
				big.NewInt(56),
			); err != nil {
				return nil, errors.Wrap(err, "materialize")
			}
		}

		// Type marker at max index
		if err := coinTree.Insert(
			bytes.Repeat([]byte{0xff}, 32),
			coinTypeBytes,
			nil,
			big.NewInt(32),
		); err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		// Compute address and add to state
		commit := coinTree.Commit(tx.inclusionProver, false)
		outAddrBI, err := poseidon.HashBytes(commit)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}

		coinAddress := outAddrBI.FillBytes(make([]byte, 32))

		// Create materialized state for coin
		coinState := ms.NewVertexAddMaterializedState(
			tx.Domain,
			[32]byte(coinAddress),
			frameNumber,
			nil,
			coinTree,
		)

		// Set the state
		err = ms.Set(
			tx.Domain[:],
			coinAddress,
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			coinState,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	// Mark inputs as spent
	for _, input := range tx.Inputs {
		if len(input.Signature) == 336 {
			// Standard format
			verificationKey := input.Signature[56*4 : 56*5]
			spendCheckBI, err := poseidon.HashBytes(verificationKey)
			if err != nil {
				return nil, errors.Wrap(err, "materialize")
			}

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

			spentAddress := spendCheckBI.FillBytes(make([]byte, 32))

			// Create materialized state for spend
			spentState := ms.NewVertexAddMaterializedState(
				tx.Domain,
				[32]byte(spentAddress),
				frameNumber,
				nil,
				spentTree,
			)

			// Set the state
			err = ms.Set(
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
	}

	return ms, nil
}

func (tx *Transaction) Prove(frameNumber uint64) error {
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

	addresses := [][]byte{}
	blinds := []byte{}
	for i, input := range tx.Inputs {
		blind, err := input.Prove(tx, i)
		if err != nil {
			return errors.Wrap(err, "prove")
		}

		addresses = append(addresses, input.address)
		blinds = append(blinds, blind...)
	}

	res, err := tx.bulletproofProver.GenerateRangeProofFromBig(
		values,
		blinds,
		128,
	)
	if err != nil {
		return err
	}

	if len(res.Commitment) != len(tx.Outputs)*56 ||
		len(res.Blinding) != len(tx.Outputs)*56 {
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
	tx.TraversalProof, err = tx.hypergraph.CreateTraversalProof(
		tx.Domain,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		addresses,
	)

	if err != nil {
		return errors.Wrap(err, "prove")
	}

	return nil
}

func (tx *Transaction) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (tx *Transaction) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	// Create the coin type hash
	coinTypeBI, err := poseidon.HashBytes(
		slices.Concat(tx.Domain[:], []byte("coin:Coin")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}
	coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

	addresses := [][]byte{}

	// For each output, create a coin
	for _, output := range tx.Outputs {
		// Create coin tree
		coinTree := &qcrypto.VectorCommitmentTree{}

		// Index 0: FrameNumber
		if err := coinTree.Insert(
			[]byte{0},
			output.FrameNumber,
			nil,
			big.NewInt(8),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 1: Commitment
		if err := coinTree.Insert(
			[]byte{1 << 2},
			output.Commitment,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 2: OneTimeKey
		if err := coinTree.Insert(
			[]byte{2 << 2},
			output.RecipientOutput.OneTimeKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 3: VerificationKey
		if err := coinTree.Insert(
			[]byte{3 << 2},
			output.RecipientOutput.VerificationKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 4: CoinBalance (encrypted)
		if err := coinTree.Insert(
			[]byte{4 << 2},
			output.RecipientOutput.CoinBalance,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 5: Mask (encrypted)
		if err := coinTree.Insert(
			[]byte{5 << 2},
			output.RecipientOutput.Mask,
			nil,
			big.NewInt(56),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Index 6 & 7: Additional references (for non-divisible tokens)
		if len(output.RecipientOutput.AdditionalReference) == 64 &&
			len(output.RecipientOutput.AdditionalReferenceKey) == 56 {
			if err := coinTree.Insert(
				[]byte{6 << 2},
				output.RecipientOutput.AdditionalReference,
				nil,
				big.NewInt(56),
			); err != nil {
				return nil, errors.Wrap(err, "get write addresses")
			}

			if err := coinTree.Insert(
				[]byte{7 << 2},
				output.RecipientOutput.AdditionalReferenceKey,
				nil,
				big.NewInt(56),
			); err != nil {
				return nil, errors.Wrap(err, "get write addresses")
			}
		}

		// Type marker at max index
		if err := coinTree.Insert(
			bytes.Repeat([]byte{0xff}, 32),
			coinTypeBytes,
			nil,
			big.NewInt(32),
		); err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		// Compute address and add to state
		commit := coinTree.Commit(tx.inclusionProver, false)
		outAddrBI, err := poseidon.HashBytes(commit)
		if err != nil {
			return nil, errors.Wrap(err, "get write addresses")
		}

		coinAddress := outAddrBI.FillBytes(make([]byte, 32))

		addresses = append(addresses, slices.Concat(
			tx.Domain[:],
			coinAddress,
		))
	}

	// Mark inputs as spent
	for _, input := range tx.Inputs {
		if len(input.Signature) == 336 {
			// Standard format
			verificationKey := input.Signature[56*4 : 56*5]
			spendCheckBI, err := poseidon.HashBytes(verificationKey)
			if err != nil {
				return nil, errors.Wrap(err, "get write addresses")
			}

			// Create spent marker
			spentTree := &qcrypto.VectorCommitmentTree{}
			if err := spentTree.Insert(
				[]byte{0},
				[]byte{0x01},
				nil,
				big.NewInt(0),
			); err != nil {
				return nil, errors.Wrap(err, "get write addresses")
			}

			spentAddress := spendCheckBI.FillBytes(make([]byte, 32))

			addresses = append(addresses, slices.Concat(
				tx.Domain[:],
				spentAddress,
			))
		}
	}

	return addresses, nil
}

func (tx *Transaction) GetChallenge() ([]byte, error) {
	transcript := []byte{}
	transcript = append(transcript, tx.Domain[:]...)
	for _, o := range tx.Outputs {
		transcript = append(transcript, o.Commitment...)
		transcript = append(transcript, o.FrameNumber...)
		transcript = append(transcript, o.RecipientOutput.CoinBalance...)
		transcript = append(transcript, o.RecipientOutput.Mask...)
		transcript = append(transcript, o.RecipientOutput.OneTimeKey...)
		transcript = append(transcript, o.RecipientOutput.VerificationKey...)
		if len(o.RecipientOutput.AdditionalReference) == 64 {
			transcript = append(transcript, o.RecipientOutput.AdditionalReference...)
			transcript = append(
				transcript,
				o.RecipientOutput.AdditionalReferenceKey...,
			)
		}
	}

	challenge, err := tx.decafConstructor.HashToScalar(transcript)
	return challenge.Private(), errors.Wrap(err, "get challenge")
}

// Verifies the transaction's validity at the given frame number. If invalid,
// also provides the associated error.
func (tx *Transaction) Verify(frameNumber uint64) (bool, error) {
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 ||
		len(tx.Inputs) > 100 || len(tx.Outputs) > 100 ||
		len(tx.Inputs) != len(tx.TraversalProof.SubProofs) {
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
			tx,
			challenge,
			bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS),
			tx.TraversalProof,
			i,
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
		if valid, err := o.Verify(frameNumber, tx.config); !valid {
			return false, errors.Wrap(err, "verify")
		}

		if tx.config.Behavior&Divisible == 0 {
			if !bytes.Equal(
				o.RecipientOutput.AdditionalReference,
				tx.Inputs[i].Proofs[len(tx.Inputs[i].Proofs)-1][:64],
			) || !bytes.Equal(
				o.RecipientOutput.AdditionalReferenceKey,
				tx.Inputs[i].Proofs[len(tx.Inputs[i].Proofs)-1][64:],
			) {
				return false, errors.Wrap(errors.New("invalid reference"), "verify")
			}
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

	roots, err := tx.hypergraph.GetShardCommits(
		binary.BigEndian.Uint64(tx.Outputs[0].FrameNumber),
		tx.Domain[:],
	)
	if err != nil {
		return false, errors.Wrap(err, "verify")
	}

	valid, err := tx.hypergraph.VerifyTraversalProof(
		tx.Domain,
		hypergraph.VertexAtomType,
		hypergraph.AddsPhaseType,
		roots[0],
		tx.TraversalProof,
	)
	if err != nil || !valid {
		return false, errors.Wrap(err, "verify")
	}

	if !tx.bulletproofProver.VerifyRangeProof(tx.RangeProof, commitment, 128) {
		return false, errors.Wrap(errors.New("invalid range proof"), "verify")
	}

	sumcheckFees := []*big.Int{}
	if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) {
		sumcheckFees = append(sumcheckFees, tx.Fees...)
	}

	if !tx.bulletproofProver.SumCheck(
		inputs,
		[]*big.Int{},
		commitments,
		sumcheckFees,
	) {
		return false, errors.Wrap(errors.New("invalid sum check"), "verify")
	}

	return true, nil
}

var _ intrinsics.IntrinsicOperation = (*Transaction)(nil)
