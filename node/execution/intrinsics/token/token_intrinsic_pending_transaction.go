package token

import (
	"bytes"
	gcrypto "crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
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

// PendingTransactionInput is an input specific to the PendingTransaction flow
// where a token intrinsic is configured as Acceptable, and the input is thus a
// coin:Coin.
type PendingTransactionInput struct {
	// Public input values:

	// The constructed commitment to the input balance.
	Commitment []byte
	// The underlying signature authorizing spend and proving validity. When
	// spending a pre-2.1 coin for the QUIL token, this signature has a special
	// legacy format so existing wallets can generate the signatures as an exit
	// hatch. See legacyVerify for more details.
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

func NewPendingTransactionInput(address []byte) (
	*PendingTransactionInput,
	error,
) {
	return &PendingTransactionInput{
		address: address,
	}, nil
}

func (i *PendingTransactionInput) Prove(
	tx *PendingTransaction,
	index int,
) ([]byte, error) {
	if tx.config.Behavior&Acceptable == 0 {
		return nil, errors.Wrap(errors.New("invalid type"), "prove input")
	}

	_, err := tx.hypergraph.GetVertex([64]byte(i.address))
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	tree, err := tx.hypergraph.GetVertexData([64]byte(i.address))
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	// Detect: large data packing or compact representation?
	fnData, err := tree.Get([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		fnData, err = tree.Get([]byte{0})
	}
	if err != nil {
		return nil, errors.Wrap(err, "prove input")
	}

	frameNumber := uint64(0)
	// Legacy
	if len(fnData) != 8 {
		fnEncrypted := tx.verEnc.FromBytes(fnData)
		if fnEncrypted == nil || fnEncrypted.GetStatement() == nil {
			return nil, errors.Wrap(
				errors.Wrap(state.ErrInvalidData, "coin:FrameNumber"),
				"prove input",
			)
		}

		// Useful trick: legacy transactions are packed in a specific way with no
		// commitments/additional values conformant to the standard, we have to
		// distinguish these, but the frame number works and there's no mixture
		fnPacked := tx.verEnc.Decrypt(
			[]crypto.VerEnc{fnEncrypted},
			publicReadKey,
		)
		if len(fnPacked) == 0 {
			return nil, errors.Wrap(
				errors.Wrap(state.ErrInvalidData, "decrypt: coin:FrameNumber"),
				"prove input",
			)
		}
		frameNumber = binary.LittleEndian.Uint64(fnPacked[:8])
	} else {
		frameNumber = binary.BigEndian.Uint64(fnData[:8])
	}

	var blind []byte

	if bytes.Equal(i.address[:32], QUIL_TOKEN_ADDRESS) &&
		frameNumber <= FRAME_2_1_CUTOVER && !BEHAVIOR_PASS {
		// Structurally, the composition of the pre-2.1 packed tree is:
		// 0x0000000000000000 - FrameNumber
		// 0x0000000000000001 - CoinBalance
		// 0x0000000000000002 - ImplicitOwnerAddress
		// 0x0000000000000003 - Domain (empty)
		// 0x0000000000000004+ - Intersection
		balanceData, err := tree.Get([]byte{0, 0, 0, 0, 0, 0, 0, 1})
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}
		balanceEncrypted := tx.verEnc.FromBytes(balanceData)
		if balanceEncrypted == nil {
			return nil, errors.Wrap(state.ErrInvalidData, "prove input")
		}
		coinBalanceBytes := tx.verEnc.Decrypt(
			[]crypto.VerEnc{balanceEncrypted},
			[]byte(publicReadKey),
		)

		// We do this process essentially in a similar pattern to what minting does,
		// because we need to establish three things: a new blind value, synthetic
		// commitment, and then from the linear relationship of the constructed
		// bulletproof for outputs, an additional transcript vector in the
		// signature's message.
		syntheticBlind, err := tx.decafConstructor.New()
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		blindData := slices.Clone(syntheticBlind.Private())

		blind = blindData

		coinBalanceBytes = append(
			coinBalanceBytes,
			bytes.Repeat([]byte{0x00}, 56-len(coinBalanceBytes))...,
		)

		balance := slices.Clone(coinBalanceBytes)
		slices.Reverse(balance)

		balancePoint, err := tx.decafConstructor.NewFromScalar(coinBalanceBytes)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		i.value = new(big.Int).SetBytes(balance)

		raisedBlind, err := syntheticBlind.AgreeWith(
			tx.decafConstructor.AltGenerator(),
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		i.Commitment, err = balancePoint.Add(raisedBlind)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		sk, err := tx.keyRing.GetSigningKey("q-peer-key", crypto.KeyTypeEd448)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		i.signOp = func(transcript []byte) error {
			challengeBI, err := poseidon.HashBytes(transcript)
			if err != nil {
				return errors.Wrap(err, "prove input")
			}

			challenge := challengeBI.FillBytes(make([]byte, 32))

			// Somewhat of a kludge, but as an easy transition step for existing
			// signing tools, we incorporate the transcript vector as the "recipient"
			// under the previous message construction.
			legacyPayload := []byte(
				"transfer" + string(i.address[32:]) + string(challenge),
			)

			i.Signature, err = sk.Sign(rand.Reader, legacyPayload, gcrypto.Hash(0))
			if err != nil {
				return errors.Wrap(err, "prove input")
			}

			i.Signature = slices.Concat(
				i.address[32:],
				sk.Public().([]byte),
				raisedBlind,
				i.Signature,
			)

			return nil
		}
	} else {
		// RDF multiprover _must_ be available for non-legacy coins
		if tx.rdfMultiprover == nil || tx.rdfHypergraphSchema == "" {
			return nil, errors.Wrap(
				errors.New("RDF multiprover not available"),
				"prove input",
			)
		}

		coinTypeBI, err := poseidon.HashBytes(
			slices.Concat(i.address[:32], []byte("coin:Coin")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

		checkType, err := tree.Get(bytes.Repeat([]byte{0xff}, 32))
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		if !bytes.Equal(coinTypeBytes, checkType) {
			return nil, errors.Wrap(
				errors.New("invalid type for address"),
				"prove input",
			)
		}

		// Use RDFMultiprover to get field values
		// C
		commitment, err := tx.rdfMultiprover.Get(
			tx.rdfHypergraphSchema,
			"coin:Coin",
			"Commitment",
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		// R
		oneTimeKey, err := tx.rdfMultiprover.Get(
			tx.rdfHypergraphSchema,
			"coin:Coin",
			"OneTimeKey",
			tree,
		)
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

		coinBalanceData, err := tx.rdfMultiprover.Get(
			tx.rdfHypergraphSchema,
			"coin:Coin",
			"CoinBalance",
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove input")
		}

		blindData, err := tx.rdfMultiprover.Get(
			tx.rdfHypergraphSchema,
			"coin:Coin",
			"Mask",
			tree,
		)
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
			// and also the reference
			addRef, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"coin:Coin",
				"AdditionalReference",
				tree,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove input")
			}
			addRefKey, err := tx.rdfMultiprover.Get(
				tx.rdfHypergraphSchema,
				"coin:Coin",
				"AdditionalReferenceKey",
				tree,
			)
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

		i.Commitment = commitment

		// For coin:Coin inputs, prove commitment and verification key
		fields := []string{"coin:Coin.Commitment", "coin:Coin.VerificationKey"}

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
			i.Proofs = append(
				i.Proofs,
				slices.Concat(
					tx.Outputs[index].rawAdditionalReference,
					tx.Outputs[index].rawAdditionalReferenceKey,
				),
			)
		}
	}

	return blind, nil
}

// Verifies an input's signature, if a QUIL transaction, allows legacy
// verification. If invalid, has an associated error.
func (i *PendingTransactionInput) Verify(
	frameNumber uint64,
	tx *PendingTransaction,
	outputTranscript []byte,
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

	if len(i.Signature) == 259 {
		return i.legacyVerify(tx, outputTranscript, checkLegacy)
	}

	if !bytes.Equal(i.Commitment, i.Signature[(56*5):(56*6)]) {
		return false, errors.Wrap(
			errors.New("invalid commitment"),
			"verify input",
		)
	}

	if len(i.Signature) != 336 {
		return false, errors.Wrap(
			errors.New("invalid signature length"),
			"verify input",
		)
	}

	addrefDelta := 0
	if tx.config.Behavior&Divisible == 0 {
		addrefDelta++
	}

	if len(i.Proofs) != 1+addrefDelta {
		return false, errors.Wrap(
			errors.New(fmt.Sprintf("invalid proof length: %d", len(i.Proofs))),
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
		return false, errors.Wrap(errors.New("already spent"), "verify input")
	}

	if tx.config.Behavior&Acceptable == 0 {
		return false, errors.Wrap(errors.New("invalid proof"), "verify input")
	}

	coinTypeBI, err := poseidon.HashBytes(
		slices.Concat(tx.Domain[:], []byte("coin:Coin")),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify input")
	}

	coinTypeBytes := coinTypeBI.FillBytes(make([]byte, 32))

	data := [][]byte{
		i.Signature[56*5 : 56*6],
		i.Signature[56*4 : 56*5],
	}
	indices := []int{1, 3}
	keys := [][]byte{nil, nil}

	if tx.config.Behavior&Divisible == 0 {
		data = append(data, i.Proofs[1][:64], i.Proofs[1][64:])
		indices = append(indices, 6, 7)
		keys = append(keys, nil, nil)
	}

	data = append(data, coinTypeBytes)
	indices = append(indices, 63)
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
		return false, err
	}

	return tx.bulletproofProver.VerifyHidden(
		i.Signature[(56*0):(56*1)],
		outputTranscript,
		i.Signature[(56*1):(56*2)],
		i.Signature[(56*2):(56*3)],
		i.Signature[(56*3):(56*4)],
		i.Signature[(56*4):(56*5)],
		i.Signature[(56*5):(56*6)],
	), nil
}

func (i *PendingTransactionInput) verifyProof(
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

	if len(indices) != len(data) {
		return false, errors.Wrap(
			errors.New("indices data length mismatch"),
			"verify proof",
		)
	}

	if len(txMultiproof.SubProofs[index].Ys) == 0 {
		return false, errors.Wrap(errors.New("invalid multiproof"), "verify proof")
	}

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

func (i *PendingTransactionInput) legacyVerify(
	tx *PendingTransaction,
	transcript []byte,
	checkLegacy bool,
) (bool, error) {
	if !checkLegacy {
		return false, errors.Wrap(errors.New("not legacy"), "verify legacy")
	}

	spendCheckBI, err := poseidon.HashBytes(i.Signature[:32])
	if err != nil {
		return false, errors.Wrap(
			errors.New("invalid address"),
			"verify input",
		)
	}

	// Image has been committed to hypergraph, Coin is already spent
	if v, err := tx.hypergraph.GetVertex([64]byte(slices.Concat(
		QUIL_TOKEN_ADDRESS,
		spendCheckBI.FillBytes(make([]byte, 32)),
	))); err == nil && v != nil {
		return false, errors.Wrap(err, "verify input")
	}

	_, err = tx.hypergraph.GetVertex(
		[64]byte(slices.Concat(QUIL_TOKEN_ADDRESS, i.Signature[:32])),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	data, err := tx.hypergraph.GetVertexData(
		[64]byte(slices.Concat(QUIL_TOKEN_ADDRESS, i.Signature[:32])),
	)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	encrypted := hypergraph.VertexTreeToEncrypted(tx.verEnc, data)
	fnPacked := tx.verEnc.Decrypt(
		[]crypto.VerEnc{encrypted[0]},
		[]byte(publicReadKey),
	)
	if len(fnPacked) == 0 {
		return false, errors.Wrap(
			errors.New("could not decode encrypted frame number"),
			"verify legacy",
		)
	}

	frameNumber := binary.LittleEndian.Uint64(fnPacked[:8])
	if frameNumber > FRAME_2_1_CUTOVER {
		return false, errors.Wrap(
			errors.New("frame number is past cutover"),
			"verify legacy",
		)
	}

	raisedBlind := i.Signature[89:145]

	challengeBI, err := poseidon.HashBytes(transcript)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	challenge := challengeBI.FillBytes(make([]byte, 32))

	legacyPayload := []byte(
		"transfer" + string(i.Signature[:32]) + string(challenge),
	)
	if !ed448.Verify(i.Signature[32:89], legacyPayload, i.Signature[145:], "") {
		return false, errors.Wrap(
			errors.New("invalid signature"),
			"verify legacy",
		)
	}

	amountBytes := tx.verEnc.Decrypt(
		[]crypto.VerEnc{encrypted[1]},
		[]byte(publicReadKey),
	)
	amountBytes = append(
		amountBytes,
		bytes.Repeat([]byte{0x00}, 56-len(amountBytes))...,
	)

	amountScalar, err := tx.decafConstructor.NewFromScalar(amountBytes)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	commitmentCheck, err := amountScalar.Add(raisedBlind)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	if !bytes.Equal(commitmentCheck, i.Commitment) {
		return false, errors.Wrap(
			errors.New("invalid commitment"),
			"verify legacy",
		)
	}

	legacyAddress := tx.verEnc.Decrypt(
		[]crypto.VerEnc{encrypted[2]},
		[]byte(publicReadKey),
	)[1:33]
	slices.Reverse(legacyAddress)

	pk, err := pcrypto.UnmarshalEd448PublicKey(i.Signature[32:89])
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	addr, err := poseidon.HashBytes(i.Signature[32:89])
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return false, errors.Wrap(err, "verify legacy")
	}

	if !(bytes.Equal(addr.FillBytes(make([]byte, 32)), legacyAddress) ||
		bytes.Equal(altAddr.FillBytes(make([]byte, 32)), legacyAddress)) {
		return false, errors.Wrap(errors.New("address check"), "verify legacy")
	}

	return true, nil
}

// PendingTransactionOutput is the output specific to a PendingTransaction. When
// encoded as the finalized state of the token intrinsic operation, produces a
// pending:PendingTransaction.
type PendingTransactionOutput struct {
	// Public output values:

	// The frame number this output is created on
	FrameNumber []byte
	// The commitment to the balance
	Commitment []byte // Raw commitment value is stored
	// The output entries corresponding to the serialized
	// pending:PendingTransaction for the recipient
	ToOutput RecipientBundle
	// The output entries corresponding to the serialized
	// pending:PendingTransaction for the refund account
	RefundOutput RecipientBundle
	// If Expirable, denotes the frame at which the refund account may perform
	// the transfer.
	Expiration uint64

	// Private output values use for construction of public values:

	// The underlying quantity used to generate the output
	value *big.Int
	// The underlying raw additionalReference value mapped from input, if present
	rawAdditionalReference []byte
	// The underlying raw additionalReferenceKey value mapped from input, if
	// present
	rawAdditionalReferenceKey []byte

	// Additional values generated during proof creation, used for interlocking
	// proofs of multiplexed transactions:

	// The unmasked blind value
	blind []byte

	// The ephemeral private key value
	ephemeralKey []byte
}

func NewPendingTransactionOutput(
	value *big.Int,
	toViewPubkey []byte,
	toSpendPubkey []byte,
	refundViewPubkey []byte,
	refundSpendPubkey []byte,
	expiration uint64,
) (*PendingTransactionOutput, error) {
	return &PendingTransactionOutput{
		value: value,
		ToOutput: RecipientBundle{
			recipientView:  toViewPubkey,
			recipientSpend: toSpendPubkey,
		},
		RefundOutput: RecipientBundle{
			recipientView:  refundViewPubkey,
			recipientSpend: refundSpendPubkey,
		},
		Expiration: expiration,
	}, nil
}

func (o *PendingTransactionOutput) Prove(
	res crypto.RangeProofResult,
	index int,
	tx *PendingTransaction,
	frameNumber uint64,
) error {
	o.Commitment = res.Commitment[index*56 : (index+1)*56]

	// To
	{
		blind := slices.Clone(res.Blinding[index*56 : (index+1)*56])
		o.blind = slices.Clone(res.Blinding[index*56 : (index+1)*56])
		r, err := tx.decafConstructor.New()
		if err != nil {
			return errors.Wrap(err, "prove output")
		}

		o.ephemeralKey = r.Private()

		shared, err := r.AgreeWithAndHashToScalar(o.ToOutput.recipientView)
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

		o.ToOutput.Mask = blind
		o.ToOutput.CoinBalance = rawBalance

		o.ToOutput.OneTimeKey = r.Public()
		o.ToOutput.VerificationKey, err = shared.Add(
			o.ToOutput.recipientSpend,
		)
		if err != nil {
			return errors.Wrap(err, "prove output")
		}

		if tx.config.Behavior&Divisible == 0 {
			ref := slices.Clone(o.rawAdditionalReference)
			refKey := slices.Clone(o.rawAdditionalReferenceKey)

			o.ToOutput.AdditionalReference = ref
			o.ToOutput.AdditionalReferenceKey = refKey
		}
	}

	// Refund
	if bytes.Equal(o.ToOutput.recipientView, o.RefundOutput.recipientView) &&
		bytes.Equal(o.ToOutput.recipientSpend, o.RefundOutput.recipientSpend) {
		o.RefundOutput = o.ToOutput
	} else {
		blind := slices.Clone(res.Blinding[index*56 : (index+1)*56])
		r, err := tx.decafConstructor.New()
		if err != nil {
			return errors.Wrap(err, "prove output")
		}
		shared, err := r.AgreeWithAndHashToScalar(o.RefundOutput.recipientView)
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

		o.RefundOutput.Mask = blind
		o.RefundOutput.CoinBalance = rawBalance

		o.RefundOutput.OneTimeKey = r.Public()
		o.RefundOutput.VerificationKey, err = shared.Add(
			o.RefundOutput.recipientSpend,
		)
		if err != nil {
			return errors.Wrap(err, "prove output")
		}

		if tx.config.Behavior&Divisible == 0 {
			ref := slices.Clone(o.rawAdditionalReference)
			refKey := slices.Clone(o.rawAdditionalReferenceKey)

			o.RefundOutput.AdditionalReference = ref
			o.RefundOutput.AdditionalReferenceKey = refKey
		}
	}

	o.FrameNumber = binary.BigEndian.AppendUint64(nil, frameNumber)

	return nil
}

func (o *PendingTransactionOutput) Verify(
	frameNumber uint64,
	config *TokenIntrinsicConfiguration,
) (bool, error) {
	if frameNumber <= binary.BigEndian.Uint64(o.FrameNumber) {
		return false, errors.Wrap(
			errors.New(fmt.Sprintf(
				"invalid frame number: output: %d, actual: %d",
				binary.BigEndian.Uint64(o.FrameNumber),
				frameNumber,
			)),
			"verify output",
		)
	}

	if len(o.Commitment) != 56 ||
		len(o.ToOutput.OneTimeKey) != 56 ||
		len(o.ToOutput.VerificationKey) != 56 ||
		len(o.ToOutput.CoinBalance) != 56 ||
		len(o.RefundOutput.OneTimeKey) != 56 ||
		len(o.RefundOutput.VerificationKey) != 56 ||
		len(o.RefundOutput.CoinBalance) != 56 {
		return false, errors.Wrap(
			errors.New("invalid commitment, verification key, or coin balance"),
			"verify output",
		)
	}

	if config.Behavior&Divisible == 0 {
		if len(o.ToOutput.AdditionalReference) != 64 {
			return false, errors.Wrap(
				errors.New("missing additional reference for non-divisible coin"),
				"verify output",
			)
		}

		if len(o.ToOutput.AdditionalReferenceKey) != 56 {
			return false, errors.Wrap(
				errors.New("missing additional reference key for non-divisible coin"),
				"verify output",
			)
		}
		if len(o.RefundOutput.AdditionalReference) != 64 {
			return false, errors.Wrap(
				errors.New("missing additional reference for non-divisible coin"),
				"verify output",
			)
		}

		if len(o.RefundOutput.AdditionalReferenceKey) != 56 {
			return false, errors.Wrap(
				errors.New("missing additional reference key for non-divisible coin"),
				"verify output",
			)
		}
		if !bytes.Equal(
			o.ToOutput.AdditionalReference,
			o.RefundOutput.AdditionalReference,
		) || !bytes.Equal(
			o.ToOutput.AdditionalReferenceKey,
			o.RefundOutput.AdditionalReferenceKey,
		) {
			return false, errors.Wrap(
				errors.New("invalid reference"),
				"verify output",
			)
		}
	}

	if len(o.ToOutput.Mask) != 56 || len(o.RefundOutput.Mask) != 56 {
		return false, errors.Wrap(errors.New("missing mask"), "verify output")
	}

	return true, nil
}

// GetBlind returns the unmasked blind, only accessible for outputs created by
// the prover (but not deserialized from bytes).
func (o *PendingTransactionOutput) GetBlind() []byte {
	return o.blind
}

// GetEphemeralKey returns the private ephemeral key, only accessible for
// outputs created by the prover (but not deserialized from bytes).
func (o *PendingTransactionOutput) GetEphemeralKey() []byte {
	return o.ephemeralKey
}

// PendingTransaction defines the intrinsic execution for converting a
// collection of coin:Coin inputs into pending:PendingTransaction outputs. Only
// works with tokens which have Acceptable flows enabled in configuration.
type PendingTransaction struct {
	Domain            [32]byte
	Inputs            []*PendingTransactionInput
	Outputs           []*PendingTransactionOutput
	Fees              []*big.Int
	RangeProof        []byte
	TraversalProof    *qcrypto.TraversalProof
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

	// Cache for computed pending transaction trees and addresses
	cachedTrees     []*qcrypto.VectorCommitmentTree
	cachedAddresses [][]byte
}

func NewPendingTransaction(
	domain [32]byte,
	inputs []*PendingTransactionInput,
	outputs []*PendingTransactionOutput,
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
) *PendingTransaction {
	return &PendingTransaction{
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

// buildPendingTransactionTrees builds and caches the pending transaction trees
// and their addresses
func (tx *PendingTransaction) buildPendingTransactionTrees() error {
	if tx.cachedTrees != nil {
		// Already built
		return nil
	}

	// Create the pending transaction type hash
	pendingTypeBI, err := poseidon.HashBytes(
		slices.Concat(tx.Domain[:], []byte("pending:PendingTransaction")),
	)
	if err != nil {
		return errors.Wrap(err, "build pending transaction trees")
	}
	pendingTypeBytes := pendingTypeBI.FillBytes(make([]byte, 32))

	tx.cachedTrees = make([]*qcrypto.VectorCommitmentTree, 0, len(tx.Outputs))
	tx.cachedAddresses = make([][]byte, 0, len(tx.Outputs)+len(tx.Inputs))

	// For each output, create pending transaction tree
	for _, output := range tx.Outputs {
		// Create PendingTransaction tree
		pendingTree := &qcrypto.VectorCommitmentTree{}

		// Index 0: FrameNumber
		if err := pendingTree.Insert(
			[]byte{0},
			output.FrameNumber,
			nil,
			big.NewInt(8),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 1: Commitment
		if err := pendingTree.Insert(
			[]byte{1 << 2},
			output.Commitment,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 2: To OneTimeKey
		if err := pendingTree.Insert(
			[]byte{2 << 2},
			output.ToOutput.OneTimeKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 3: Refund OneTimeKey
		if err := pendingTree.Insert(
			[]byte{3 << 2},
			output.RefundOutput.OneTimeKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 4: To VerificationKey
		if err := pendingTree.Insert(
			[]byte{4 << 2},
			output.ToOutput.VerificationKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 5: Refund VerificationKey
		if err := pendingTree.Insert(
			[]byte{5 << 2},
			output.RefundOutput.VerificationKey,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 6: To CoinBalance
		if err := pendingTree.Insert(
			[]byte{6 << 2},
			output.ToOutput.CoinBalance,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 7: Refund CoinBalance
		if err := pendingTree.Insert(
			[]byte{7 << 2},
			output.RefundOutput.CoinBalance,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 8: To Mask
		if err := pendingTree.Insert(
			[]byte{8 << 2},
			output.ToOutput.Mask,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 9: Refund Mask
		if err := pendingTree.Insert(
			[]byte{9 << 2},
			output.RefundOutput.Mask,
			nil,
			big.NewInt(56),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Index 10 - 14: Additional references (for non-divisible tokens) +
		// Expiration
		if len(output.ToOutput.AdditionalReference) == 64 {
			if err := pendingTree.Insert(
				[]byte{10 << 2},
				output.ToOutput.AdditionalReference,
				nil,
				big.NewInt(56),
			); err != nil {
				return errors.Wrap(err, "build pending transaction trees")
			}

			if err := pendingTree.Insert(
				[]byte{11 << 2},
				output.ToOutput.AdditionalReferenceKey,
				nil,
				big.NewInt(56),
			); err != nil {
				return errors.Wrap(err, "build pending transaction trees")
			}

			if err := pendingTree.Insert(
				[]byte{12 << 2},
				output.RefundOutput.AdditionalReference,
				nil,
				big.NewInt(56),
			); err != nil {
				return errors.Wrap(err, "build pending transaction trees")
			}

			if err := pendingTree.Insert(
				[]byte{13 << 2},
				output.RefundOutput.AdditionalReferenceKey,
				nil,
				big.NewInt(56),
			); err != nil {
				return errors.Wrap(err, "build pending transaction trees")
			}

			if tx.config.Behavior&Expirable != 0 {
				// Index 14: Expiration
				expirationBytes := binary.BigEndian.AppendUint64(nil, output.Expiration)
				if err := pendingTree.Insert(
					[]byte{14 << 2},
					expirationBytes,
					nil,
					big.NewInt(8),
				); err != nil {
					return errors.Wrap(err, "build pending transaction trees")
				}
			}
		} else if tx.config.Behavior&Expirable != 0 {
			// Index 10: Expiration
			expirationBytes := binary.BigEndian.AppendUint64(nil, output.Expiration)
			if err := pendingTree.Insert(
				[]byte{10 << 2},
				expirationBytes,
				nil,
				big.NewInt(8),
			); err != nil {
				return errors.Wrap(err, "build pending transaction trees")
			}
		}

		// Type marker at max index
		if err := pendingTree.Insert(
			bytes.Repeat([]byte{0xff}, 32),
			pendingTypeBytes,
			nil,
			big.NewInt(32),
		); err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Compute address from tree commit
		commit := pendingTree.Commit(tx.inclusionProver, false)
		outAddrBI, err := poseidon.HashBytes(commit)
		if err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}
		outAddr := slices.Concat(
			tx.Domain[:],
			outAddrBI.FillBytes(make([]byte, 32)),
		)

		tx.cachedTrees = append(tx.cachedTrees, pendingTree)
		tx.cachedAddresses = append(tx.cachedAddresses, outAddr)
	}

	// Add spent marker addresses for inputs
	for _, input := range tx.Inputs {
		var spendCheckBI *big.Int
		var err error

		if len(input.Signature) == 259 {
			// Legacy format
			spendCheckBI, err = poseidon.HashBytes(input.Signature[:32])
		} else if len(input.Signature) == 336 {
			// Standard format
			spendCheckBI, err = poseidon.HashBytes(input.Signature[56*4 : 56*5])
		}

		if err != nil {
			return errors.Wrap(err, "build pending transaction trees")
		}

		// Spent marker address
		spentAddress := slices.Concat(
			tx.Domain[:],
			spendCheckBI.FillBytes(make([]byte, 32)),
		)
		tx.cachedAddresses = append(tx.cachedAddresses, spentAddress)
	}

	return nil
}

// GetCost implements intrinsics.IntrinsicOperation.
func (tx *PendingTransaction) GetCost() (*big.Int, error) {
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
		size.Add(size, big.NewInt(int64(len(o.RefundOutput.CoinBalance))))
		size.Add(size, big.NewInt(int64(len(o.RefundOutput.Mask))))
		size.Add(size, big.NewInt(int64(len(o.RefundOutput.OneTimeKey))))
		size.Add(size, big.NewInt(int64(len(o.RefundOutput.VerificationKey))))
		for len(o.RefundOutput.AdditionalReference) == 64 {
			size.Add(size, big.NewInt(120))
		}

		size.Add(size, big.NewInt(int64(len(o.ToOutput.CoinBalance))))
		size.Add(size, big.NewInt(int64(len(o.ToOutput.Mask))))
		size.Add(size, big.NewInt(int64(len(o.ToOutput.OneTimeKey))))
		size.Add(size, big.NewInt(int64(len(o.ToOutput.VerificationKey))))
		for len(o.ToOutput.AdditionalReference) == 64 {
			size.Add(size, big.NewInt(120))
		}
	}

	return size, nil
}

// Materialize implements intrinsics.IntrinsicOperation.
func (tx *PendingTransaction) Materialize(
	frameNumber uint64,
	state state.State,
) (state.State, error) {
	ms := state.(*hgstate.HypergraphState)

	// Build the trees if not already built
	if err := tx.buildPendingTransactionTrees(); err != nil {
		return nil, errors.Wrap(err, "materialize")
	}

	// Create pending transactions using cached trees
	for i, tree := range tx.cachedTrees {
		// Create materialized state for pending transaction
		pendingState := ms.NewVertexAddMaterializedState(
			[32]byte(tx.cachedAddresses[i][:32]),
			[32]byte(tx.cachedAddresses[i][32:]),
			frameNumber,
			nil,
			tree,
		)

		// Set the state
		err := ms.Set(
			tx.cachedAddresses[i][:32],
			tx.cachedAddresses[i][32:],
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			pendingState,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	// Mark inputs as spent - these are the addresses after the output addresses
	// in the cache
	outputCount := len(tx.Outputs)
	for i := outputCount; i < len(tx.cachedAddresses); i++ {
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
		spentState := ms.NewVertexAddMaterializedState(
			tx.Domain,
			[32]byte(tx.cachedAddresses[i][32:]),
			frameNumber,
			nil,
			spentTree,
		)

		// Set the state
		err := ms.Set(
			tx.cachedAddresses[i][:32],
			tx.cachedAddresses[i][32:],
			hgstate.VertexAddsDiscriminator,
			frameNumber,
			spentState,
		)
		if err != nil {
			return nil, errors.Wrap(err, "materialize")
		}
	}

	return ms, nil
}

func (tx *PendingTransaction) Prove(frameNumber uint64) error {
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

func (tx *PendingTransaction) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (tx *PendingTransaction) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	addresses := [][]byte{}

	// Build the trees if not already built
	if err := tx.buildPendingTransactionTrees(); err != nil {
		return nil, errors.Wrap(err, "get write addresses")
	}

	// Add pending transactions using cached trees
	for i := range tx.cachedTrees {
		addresses = append(addresses, tx.cachedAddresses[i])
	}

	return addresses, nil
}

func (tx *PendingTransaction) GetChallenge() ([]byte, error) {
	transcript := []byte{}
	transcript = append(transcript, tx.Domain[:]...)
	for _, o := range tx.Outputs {
		transcript = append(transcript, o.Commitment...)
		transcript = binary.BigEndian.AppendUint64(transcript, o.Expiration)
		transcript = append(transcript, o.FrameNumber...)
		if len(o.ToOutput.AdditionalReference) == 64 {
			transcript = append(transcript, o.ToOutput.AdditionalReference...)
			transcript = append(transcript, o.ToOutput.AdditionalReferenceKey...)
		}
		transcript = append(transcript, o.ToOutput.CoinBalance...)
		transcript = append(transcript, o.ToOutput.Mask...)
		transcript = append(transcript, o.ToOutput.OneTimeKey...)
		transcript = append(transcript, o.ToOutput.VerificationKey...)
		if len(o.RefundOutput.AdditionalReference) == 64 {
			transcript = append(transcript, o.RefundOutput.AdditionalReference...)
			transcript = append(transcript, o.RefundOutput.AdditionalReferenceKey...)
		}
		transcript = append(transcript, o.RefundOutput.CoinBalance...)
		transcript = append(transcript, o.RefundOutput.Mask...)
		transcript = append(transcript, o.RefundOutput.OneTimeKey...)
		transcript = append(transcript, o.RefundOutput.VerificationKey...)
	}

	challenge, err := tx.decafConstructor.HashToScalar(transcript)
	return challenge.Private(), errors.Wrap(err, "get challenge")
}

// Verifies the pending transaction's validity at the given frame number. If
// invalid, also provides the associated error.
func (tx *PendingTransaction) Verify(frameNumber uint64) (bool, error) {
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

		if bytes.Equal(tx.Domain[:], QUIL_TOKEN_ADDRESS) &&
			len(input.Signature) == 259 {
			if _, ok := check[string(input.Signature[:32])]; ok {
				return false, errors.Wrap(
					errors.New("attempted double-spend"),
					"verify",
				)
			}
			check[string(input.Signature[:32])] = struct{}{}
			inputs = append(inputs, input.Commitment)
		} else {
			if _, ok := check[string(input.Signature[(56*4):(56*5)])]; ok {
				return false, errors.Wrap(
					errors.New("attempted double-spend"),
					"verify",
				)
			}
			check[string(input.Signature[(56*4):(56*5)])] = struct{}{}
			inputs = append(inputs, input.Commitment)
		}
	}

	commitment := make([]byte, len(tx.Outputs)*56)
	commitments := [][]byte{}
	for i, o := range tx.Outputs {
		if valid, err := o.Verify(frameNumber, tx.config); !valid {
			return false, errors.Wrap(err, "verify")
		}

		spendCheckBI, err := poseidon.HashBytes(o.RefundOutput.VerificationKey)
		if err != nil {
			return false, errors.Wrap(err, "verify")
		}

		_, err = tx.hypergraph.GetVertex([64]byte(
			slices.Concat(tx.Domain[:], spendCheckBI.FillBytes(make([]byte, 32))),
		))
		if err == nil {
			return false, errors.Wrap(
				errors.New("invalid refund verification key"),
				"verify",
			)
		}

		spendCheckBI, err = poseidon.HashBytes(o.ToOutput.VerificationKey)
		if err != nil {
			return false, errors.Wrap(err, "verify")
		}

		_, err = tx.hypergraph.GetVertex([64]byte(
			slices.Concat(tx.Domain[:], spendCheckBI.FillBytes(make([]byte, 32))),
		))
		if err == nil {
			return false, errors.Wrap(
				errors.New("invalid to verification key"),
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
		return false, errors.Wrap(errors.New(
			fmt.Sprintf("invalid traversal proof: %v", err),
		), "verify")
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

var _ intrinsics.IntrinsicOperation = (*PendingTransaction)(nil)
