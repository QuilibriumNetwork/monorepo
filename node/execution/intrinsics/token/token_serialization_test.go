package token

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestRecipientBundleSerialization(t *testing.T) {
	// Create a recipient bundle instance
	bundle := &RecipientBundle{
		OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
		VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
		CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
		Mask:            append([]byte("mask"), make([]byte, 52)...),
	}

	// Serialize the bundle
	bytes, err := bundle.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newBundle := &RecipientBundle{}
	err = newBundle.FromBytes(bytes)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, bundle.OneTimeKey, newBundle.OneTimeKey)
	assert.Equal(t, bundle.VerificationKey, newBundle.VerificationKey)
	assert.Equal(t, bundle.CoinBalance, newBundle.CoinBalance)
	assert.Equal(t, bundle.Mask, newBundle.Mask)
}

func TestTransactionOutputSerialization(t *testing.T) {
	// Create a transaction output
	output := &TransactionOutput{
		FrameNumber: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Commitment:  append([]byte("commitment"), make([]byte, 46)...),
		RecipientOutput: RecipientBundle{
			OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
			VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
			CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
			Mask:            append([]byte("mask"), make([]byte, 52)...),
		},
		value: big.NewInt(1), // set to verify non-propagation
	}

	// Serialize the output
	bytes, err := output.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newOutput := &TransactionOutput{}
	err = newOutput.FromBytes(bytes)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, output.RecipientOutput.OneTimeKey, newOutput.RecipientOutput.OneTimeKey)
	assert.Equal(t, output.RecipientOutput.VerificationKey, newOutput.RecipientOutput.VerificationKey)
	assert.Equal(t, output.RecipientOutput.CoinBalance, newOutput.RecipientOutput.CoinBalance)
	assert.Equal(t, output.RecipientOutput.Mask, newOutput.RecipientOutput.Mask)

	// Verify fields are not set.
	assert.Nil(t, newOutput.value)
}

func TestTransactionInputSerialization(t *testing.T) {
	// Create a transaction input
	address := [64]byte{}
	copy(address[:], []byte("test-address-for-transaction-input-serialization-test"))
	input := &TransactionInput{
		Commitment: append([]byte("commitment"), make([]byte, 46)...),
		Signature:  []byte("signature"),
		Proofs: [][]byte{
			[]byte("proof1"),
			[]byte("proof2"),
		},
		address: []byte("should not appear"),
		value:   big.NewInt(111),
	}

	// Serialize the input
	bytes, err := input.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newInput := &TransactionInput{}
	err = newInput.FromBytes(bytes)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, input.Commitment, newInput.Commitment)
	assert.Equal(t, input.Signature, newInput.Signature)
	assert.Equal(t, input.Proofs, newInput.Proofs)
	assert.Nil(t, newInput.address)
	assert.Nil(t, newInput.value)
}

func TestPendingTransactionSerialization(t *testing.T) {
	// Setup mocks
	hg := &mocks.MockHypergraph{}
	bp := &mocks.MockBulletproofProver{}
	ip := &mocks.MockInclusionProver{}
	ve := &mocks.MockVerifiableEncryptor{}
	km := &mocks.MockKeyManager{}

	// Create input
	input := &PendingTransactionInput{
		Commitment: append([]byte("commitment"), make([]byte, 46)...),
		Signature:  []byte("signature"),
		Proofs: [][]byte{
			[]byte("proof1"),
			[]byte("proof2"),
		},
		address: []byte("dontpropagate"),
	}

	// Create mock recipient
	dc := &mocks.MockDecafConstructor{}

	// Create output
	output := &PendingTransactionOutput{
		FrameNumber: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Commitment:  append([]byte("commitment"), make([]byte, 46)...),
		ToOutput: RecipientBundle{
			OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
			VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
			CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
			Mask:            append([]byte("mask"), make([]byte, 52)...),
			recipientView:   []byte("view"),
			recipientSpend:  []byte("spend"),
		},
		RefundOutput: RecipientBundle{
			OneTimeKey:      append([]byte("oonetimekey"), make([]byte, 45)...),
			VerificationKey: append([]byte("overificationkey"), make([]byte, 40)...),
			CoinBalance:     append([]byte("ocoinbalance"), make([]byte, 44)...),
			Mask:            append([]byte("omask"), make([]byte, 51)...),
			recipientView:   []byte("otherview"),
			recipientSpend:  []byte("otherspend"),
		},
		Expiration: 1010101,
		value:      big.NewInt(111),
	}

	// Setup proof for transaction
	mockProof := &qcrypto.TraversalProof{
		Multiproof: &mocks.MockMultiproof{},
		SubProofs: []qcrypto.TraversalSubProof{{
			Commits: [][]byte{[]byte("commit1"), []byte("commit2")},
			Ys:      [][]byte{[]byte("y1"), []byte("y2")},
			Paths:   [][]uint64{{1, 2}, {3, 4}},
		}},
	}

	// Setup mocks for proof serialization
	multiproof := &mocks.MockMultiproof{}
	multiproof.On("ToBytes").Return([]byte("multiproof-bytes"), nil)
	multiproof.On("GetMulticommitment").Return([]byte("multicommitment"))
	multiproof.On("GetProof").Return([]byte("proof-data"))
	multiproof.On("FromBytes", mock.Anything).Return(nil)
	mockProof.Multiproof = multiproof

	// Create proof for inputs
	ip.On("NewMultiproof").Return(multiproof)

	// Create RDF multiprover for testing
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	// Create pending transaction
	pending := &PendingTransaction{
		Domain:         [32]byte(QUIL_TOKEN_ADDRESS),
		Inputs:         []*PendingTransactionInput{input},
		Outputs:        []*PendingTransactionOutput{output},
		Fees:           []*big.Int{big.NewInt(1)},
		RangeProof:     []byte("range-proof"),
		TraversalProof: mockProof,
		config: &TokenIntrinsicConfiguration{
			Behavior: Mintable | Divisible,
			MintStrategy: &TokenMintStrategy{
				MintBehavior: MintWithProof,
				ProofBasis:   ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(1000000000),
			Name:   "Test Token",
			Symbol: "TEST",
		},
	}

	// Serialize pending transaction
	bytes, err := pending.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newPending := &PendingTransaction{}
	err = newPending.FromBytes(bytes, pending.config, hg, bp, ip, ve, dc, keys.ToKeyRing(km, true), "", rdfMultiprover)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, 1, len(newPending.Inputs))
	assert.Nil(t, newPending.Inputs[0].address)
	assert.Nil(t, newPending.Inputs[0].value)
	assert.Equal(t, pending.Inputs[0].Commitment, newPending.Inputs[0].Commitment)
	assert.Equal(t, pending.Inputs[0].Proofs[0], newPending.Inputs[0].Proofs[0])
	assert.Equal(t, pending.Inputs[0].Proofs[1], newPending.Inputs[0].Proofs[1])
	assert.Equal(t, pending.Inputs[0].Signature, newPending.Inputs[0].Signature)

	assert.Equal(t, 1, len(newPending.Outputs))
	assert.Nil(t, newPending.Outputs[0].value)

	assert.Equal(t, pending.Outputs[0].FrameNumber, newPending.Outputs[0].FrameNumber)
	assert.Equal(t, pending.Outputs[0].Commitment, newPending.Outputs[0].Commitment)
	assert.Equal(t, 0, len(newPending.Outputs[0].ToOutput.AdditionalReference))
	assert.Equal(t, pending.Outputs[0].ToOutput.CoinBalance, newPending.Outputs[0].ToOutput.CoinBalance)
	assert.Equal(t, pending.Outputs[0].ToOutput.Mask, newPending.Outputs[0].ToOutput.Mask)
	assert.Equal(t, pending.Outputs[0].ToOutput.OneTimeKey, newPending.Outputs[0].ToOutput.OneTimeKey)
	assert.Equal(t, pending.Outputs[0].ToOutput.VerificationKey, newPending.Outputs[0].ToOutput.VerificationKey)
	assert.Equal(t, 0, len(newPending.Outputs[0].RefundOutput.AdditionalReference))
	assert.Equal(t, pending.Outputs[0].RefundOutput.CoinBalance, newPending.Outputs[0].RefundOutput.CoinBalance)
	assert.Equal(t, pending.Outputs[0].RefundOutput.Mask, newPending.Outputs[0].RefundOutput.Mask)
	assert.Equal(t, pending.Outputs[0].RefundOutput.OneTimeKey, newPending.Outputs[0].RefundOutput.OneTimeKey)
	assert.Equal(t, pending.Outputs[0].RefundOutput.VerificationKey, newPending.Outputs[0].RefundOutput.VerificationKey)
	assert.Nil(t, newPending.Outputs[0].ToOutput.recipientView)
	assert.Nil(t, newPending.Outputs[0].ToOutput.recipientSpend)
	assert.Nil(t, newPending.Outputs[0].RefundOutput.recipientView)
	assert.Nil(t, newPending.Outputs[0].RefundOutput.recipientSpend)
	assert.Equal(t, pending.Outputs[0].Expiration, newPending.Outputs[0].Expiration)
	assert.Equal(t, pending.RangeProof[0], newPending.RangeProof[0])
	assert.Equal(t, 1, len(newPending.TraversalProof.SubProofs))
	out, err := pending.TraversalProof.ToBytes()
	require.NoError(t, err)
	newout, err := newPending.TraversalProof.ToBytes()
	require.NoError(t, err)
	assert.Equal(t, out, newout)

	assert.Equal(t, pending.Fees[0].String(), newPending.Fees[0].String())

	// Verify injected values
	assert.NotNil(t, newPending.hypergraph)
	assert.NotNil(t, newPending.bulletproofProver)
	assert.NotNil(t, newPending.inclusionProver)
	assert.NotNil(t, newPending.decafConstructor)
}

func TestTransactionSerialization(t *testing.T) {
	// Setup mocks
	hg := &mocks.MockHypergraph{}
	bp := &mocks.MockBulletproofProver{}
	ip := &mocks.MockInclusionProver{}
	ve := &mocks.MockVerifiableEncryptor{}
	km := &mocks.MockKeyRing{}

	// Setup proof for transaction
	mockProof := &qcrypto.TraversalProof{
		Multiproof: &mocks.MockMultiproof{},
		SubProofs: []qcrypto.TraversalSubProof{{
			Commits: [][]byte{[]byte("commit1"), []byte("commit2")},
			Ys:      [][]byte{[]byte("y1"), []byte("y2")},
			Paths:   [][]uint64{{1, 2}, {3, 4}},
		}},
	}

	// Setup mocks for proof serialization
	multiproof := &mocks.MockMultiproof{}
	multiproof.On("ToBytes").Return([]byte("multiproof-bytes"), nil)
	multiproof.On("GetMulticommitment").Return([]byte("multicommitment"))
	multiproof.On("GetProof").Return([]byte("proof-data"))
	mockProof.Multiproof = multiproof

	// Create proof for inputs
	ip.On("NewMultiproof").Return(multiproof)
	multiproof.On("FromBytes", mock.Anything).Return(nil)

	// Create RDF multiprover for testing
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	// Create input
	input := &TransactionInput{
		Commitment: []byte("commitment"),
		Signature:  []byte("signature"),
		Proofs: [][]byte{
			[]byte("proof1"),
			[]byte("proof2"),
		},
		address: []byte("dontpropagate"),
		value:   big.NewInt(111),
	}

	// Create mock recipient
	dc := &mocks.MockDecafConstructor{}

	// Create output
	output := &TransactionOutput{
		FrameNumber: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Commitment:  append([]byte("commitment"), make([]byte, 46)...),
		RecipientOutput: RecipientBundle{
			OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
			VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
			CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
			Mask:            append([]byte("mask"), make([]byte, 52)...),
			recipientView:   []byte("view"),
			recipientSpend:  []byte("spend"),
		},
		value: big.NewInt(111),
	}

	// Create transaction
	tx := &Transaction{
		Domain:         [32]byte(QUIL_TOKEN_ADDRESS),
		Inputs:         []*TransactionInput{input},
		Outputs:        []*TransactionOutput{output},
		Fees:           []*big.Int{big.NewInt(2)},
		RangeProof:     []byte("range-proof"),
		TraversalProof: mockProof,
		config: &TokenIntrinsicConfiguration{
			Behavior: Mintable | Divisible | Burnable,
			MintStrategy: &TokenMintStrategy{
				MintBehavior: MintWithProof,
				ProofBasis:   ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(2000000000),
			Name:   "Transaction Test Token",
			Symbol: "TTT",
		},
		hypergraph:        hg,
		bulletproofProver: bp,
		inclusionProver:   ip,
		verEnc:            ve,
		decafConstructor:  dc,
		keyRing:           km,
	}

	// Serialize transaction
	bytes, err := tx.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newTx := &Transaction{}
	err = newTx.FromBytes(bytes, tx.config, hg, bp, ip, ve, dc, km, "", rdfMultiprover)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, tx.Domain, newTx.Domain)

	assert.Equal(t, 1, len(newTx.Inputs))
	assert.Nil(t, newTx.Inputs[0].address)
	assert.Nil(t, newTx.Inputs[0].value)

	assert.Equal(t, 1, len(newTx.Outputs))
	assert.Nil(t, newTx.Outputs[0].value)

	assert.Equal(t, 0, len(newTx.Outputs[0].RecipientOutput.AdditionalReference))
	assert.Equal(t, tx.Outputs[0].RecipientOutput.CoinBalance, newTx.Outputs[0].RecipientOutput.CoinBalance)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.Mask, newTx.Outputs[0].RecipientOutput.Mask)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.OneTimeKey, newTx.Outputs[0].RecipientOutput.OneTimeKey)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.VerificationKey, newTx.Outputs[0].RecipientOutput.VerificationKey)
	assert.Nil(t, newTx.Outputs[0].RecipientOutput.recipientView)
	assert.Nil(t, newTx.Outputs[0].RecipientOutput.recipientSpend)

	assert.Equal(t, tx.config.Behavior, newTx.config.Behavior)
	assert.Equal(t, tx.config.Name, newTx.config.Name)
	assert.Equal(t, tx.config.Symbol, newTx.config.Symbol)
	assert.Equal(t, tx.config.Units.String(), newTx.config.Units.String())
	assert.Equal(t, tx.config.MintStrategy.MintBehavior, newTx.config.MintStrategy.MintBehavior)
	assert.Equal(t, tx.config.MintStrategy.ProofBasis, newTx.config.MintStrategy.ProofBasis)

	// Verify input proof was properly reconstructed
	assert.Nil(t, newTx.Inputs[0].address)
	assert.Nil(t, newTx.Inputs[0].value)
	assert.Equal(t, tx.Inputs[0].Commitment, newTx.Inputs[0].Commitment)
	assert.Equal(t, tx.Inputs[0].Proofs[0], newTx.Inputs[0].Proofs[0])
	assert.Equal(t, tx.Inputs[0].Proofs[1], newTx.Inputs[0].Proofs[1])
	assert.Equal(t, tx.Inputs[0].Signature, newTx.Inputs[0].Signature)
	assert.Equal(t, tx.RangeProof[0], newTx.RangeProof[0])
	assert.Equal(t, 1, len(newTx.TraversalProof.SubProofs))
	out, err := tx.TraversalProof.ToBytes()
	require.NoError(t, err)
	newout, err := newTx.TraversalProof.ToBytes()
	require.NoError(t, err)
	assert.Equal(t, out, newout)

	// Verify injected values
	assert.NotNil(t, newTx.hypergraph)
	assert.NotNil(t, newTx.bulletproofProver)
	assert.NotNil(t, newTx.inclusionProver)
	assert.NotNil(t, newTx.verEnc)
	assert.NotNil(t, newTx.decafConstructor)
	assert.NotNil(t, newTx.keyRing)
}

func TestTraversalProofSerialization(t *testing.T) {
	// Setup multiproof mock
	multiproof := &mocks.MockMultiproof{}
	multiproof.On("ToBytes").Return([]byte("serialized-multiproof"), nil)
	multiproof.On("GetMulticommitment").Return([]byte("multicommitment-data"))
	multiproof.On("GetProof").Return([]byte("proof-data"))

	// Create inclusion prover mock for deserialization
	ip := &mocks.MockInclusionProver{}
	ip.On("NewMultiproof").Return(multiproof)
	multiproof.On("FromBytes", mock.Anything).Return(nil)

	// Create a traversal proof
	proof := &qcrypto.TraversalProof{
		Multiproof: multiproof,
		SubProofs: []qcrypto.TraversalSubProof{{
			Commits: [][]byte{
				[]byte("commit1"),
				[]byte("commit2"),
				[]byte("commit3"),
			},
			Ys: [][]byte{
				[]byte("y1"),
				[]byte("y2"),
				[]byte("y3"),
			},
			Paths: [][]uint64{
				{1, 2, 3},
				{4, 5, 6},
			},
		}},
	}

	// Serialize the proof
	bytes, err := proof.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newProof := &qcrypto.TraversalProof{}
	err = newProof.FromBytes(bytes, ip)
	require.NoError(t, err)

	// Verify fields match
	assert.NotNil(t, newProof.Multiproof)
	assert.Equal(t, 3, len(newProof.SubProofs[0].Commits))
	assert.Equal(t, 3, len(newProof.SubProofs[0].Ys))
	assert.Equal(t, 2, len(newProof.SubProofs[0].Paths))

	// Verify specific values
	for i, commit := range proof.SubProofs[0].Commits {
		assert.Equal(t, commit, newProof.SubProofs[0].Commits[i])
	}

	for i, y := range proof.SubProofs[0].Ys {
		assert.Equal(t, y, newProof.SubProofs[0].Ys[i])
	}

	// Check paths
	assert.Equal(t, uint64(1), newProof.SubProofs[0].Paths[0][0])
	assert.Equal(t, uint64(2), newProof.SubProofs[0].Paths[0][1])
	assert.Equal(t, uint64(3), newProof.SubProofs[0].Paths[0][2])
	assert.Equal(t, uint64(4), newProof.SubProofs[0].Paths[1][0])
	assert.Equal(t, uint64(5), newProof.SubProofs[0].Paths[1][1])
	assert.Equal(t, uint64(6), newProof.SubProofs[0].Paths[1][2])
}

func TestMintTransactionInputSerialization(t *testing.T) {
	// Create a mint transaction input
	input := &MintTransactionInput{
		Value:      big.NewInt(1000),
		Commitment: append([]byte("commitment"), make([]byte, 46)...),
		Signature:  []byte("signature-data"),
		Proofs: [][]byte{
			[]byte("proof1"),
			[]byte("proof2"),
		},
		contextData: []byte("should not appear"),
	}

	// Serialize the input
	bytes, err := input.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newInput := &MintTransactionInput{}
	err = newInput.FromBytes(bytes)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, input.Value.String(), newInput.Value.String())
	assert.Equal(t, input.Commitment, newInput.Commitment)
	assert.Equal(t, input.Signature, newInput.Signature)
	assert.Equal(t, input.Proofs, newInput.Proofs)
	assert.Nil(t, newInput.contextData)
}

func TestMintTransactionOutputSerialization(t *testing.T) {
	// Create a mint transaction output
	output := &MintTransactionOutput{
		FrameNumber: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Commitment:  append([]byte("commitment"), make([]byte, 46)...),
		RecipientOutput: RecipientBundle{
			OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
			VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
			CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
			Mask:            append([]byte("mask"), make([]byte, 52)...),
		},
		value: big.NewInt(1000), // set to verify non-propagation
	}

	// Serialize the output
	bytes, err := output.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Deserialize and verify
	newOutput := &MintTransactionOutput{}
	err = newOutput.FromBytes(bytes)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, output.FrameNumber, newOutput.FrameNumber)
	assert.Equal(t, output.Commitment, newOutput.Commitment)
	assert.Equal(t, output.RecipientOutput.OneTimeKey, newOutput.RecipientOutput.OneTimeKey)
	assert.Equal(t, output.RecipientOutput.VerificationKey, newOutput.RecipientOutput.VerificationKey)
	assert.Equal(t, output.RecipientOutput.CoinBalance, newOutput.RecipientOutput.CoinBalance)
	assert.Equal(t, output.RecipientOutput.Mask, newOutput.RecipientOutput.Mask)

	// Verify fields are not set
	assert.Nil(t, newOutput.value)
}

func TestMintTransactionSerialization(t *testing.T) {
	// Setup mocks
	hg := &mocks.MockHypergraph{}
	bp := &mocks.MockBulletproofProver{}
	ip := &mocks.MockInclusionProver{}
	ve := &mocks.MockVerifiableEncryptor{}
	km := &mocks.MockKeyRing{}
	dc := &mocks.MockDecafConstructor{}

	// Create input
	input := &MintTransactionInput{
		Value:      big.NewInt(1000),
		Commitment: append([]byte("commitment"), make([]byte, 46)...),
		Signature:  []byte("signature"),
		Proofs: [][]byte{
			[]byte("proof1"),
			[]byte("proof2"),
		},
		contextData: []byte("should not appear"),
	}

	// Create output
	output := &MintTransactionOutput{
		FrameNumber: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Commitment:  append([]byte("commitment"), make([]byte, 46)...),
		RecipientOutput: RecipientBundle{
			OneTimeKey:      append([]byte("onetimekey"), make([]byte, 46)...),
			VerificationKey: append([]byte("verificationkey"), make([]byte, 41)...),
			CoinBalance:     append([]byte("coinbalance"), make([]byte, 45)...),
			Mask:            append([]byte("mask"), make([]byte, 52)...),
			recipientView:   append([]byte("view"), make([]byte, 52)...),
			recipientSpend:  append([]byte("spend"), make([]byte, 51)...),
		},
		value: big.NewInt(1000),
	}

	// Create mint transaction
	tx := &MintTransaction{
		Domain:     [32]byte(QUIL_TOKEN_ADDRESS),
		Inputs:     []*MintTransactionInput{input},
		Outputs:    []*MintTransactionOutput{output},
		Fees:       []*big.Int{big.NewInt(10)},
		RangeProof: []byte("range-proof"),
		config: &TokenIntrinsicConfiguration{
			Behavior: Mintable | Divisible | Burnable,
			MintStrategy: &TokenMintStrategy{
				MintBehavior: MintWithProof,
				ProofBasis:   ProofOfMeaningfulWork,
			},
			Units:  big.NewInt(1000000000),
			Name:   "MintTest Token",
			Symbol: "MTT",
		},
		hypergraph:        hg,
		bulletproofProver: bp,
		inclusionProver:   ip,
		verEnc:            ve,
		decafConstructor:  dc,
		keyRing:           km,
	}

	// Serialize transaction
	bytes, err := tx.ToBytes()
	require.NoError(t, err)
	require.NotNil(t, bytes)

	// Create RDF multiprover for testing
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	// Deserialize and verify
	newTx := &MintTransaction{}
	err = newTx.FromBytes(bytes, tx.config, hg, bp, ip, ve, dc, km, "", rdfMultiprover)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, tx.Domain, newTx.Domain)
	assert.Equal(t, 1, len(newTx.Inputs))
	assert.Equal(t, 1, len(newTx.Outputs))
	assert.Equal(t, tx.Inputs[0].Value.String(), newTx.Inputs[0].Value.String())
	assert.Equal(t, tx.Inputs[0].Commitment, newTx.Inputs[0].Commitment)
	assert.Equal(t, tx.Inputs[0].Signature, newTx.Inputs[0].Signature)
	assert.Equal(t, tx.Inputs[0].Proofs[0], newTx.Inputs[0].Proofs[0])
	assert.Equal(t, tx.Inputs[0].Proofs[1], newTx.Inputs[0].Proofs[1])
	assert.Nil(t, newTx.Inputs[0].contextData)

	assert.Equal(t, tx.Outputs[0].FrameNumber, newTx.Outputs[0].FrameNumber)
	assert.Equal(t, tx.Outputs[0].Commitment, newTx.Outputs[0].Commitment)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.OneTimeKey, newTx.Outputs[0].RecipientOutput.OneTimeKey)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.VerificationKey, newTx.Outputs[0].RecipientOutput.VerificationKey)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.CoinBalance, newTx.Outputs[0].RecipientOutput.CoinBalance)
	assert.Equal(t, tx.Outputs[0].RecipientOutput.Mask, newTx.Outputs[0].RecipientOutput.Mask)
	assert.Nil(t, newTx.Outputs[0].value)
	assert.Nil(t, newTx.Outputs[0].RecipientOutput.recipientView)
	assert.Nil(t, newTx.Outputs[0].RecipientOutput.recipientSpend)

	assert.Equal(t, tx.RangeProof, newTx.RangeProof)
	assert.Equal(t, tx.Fees[0].String(), newTx.Fees[0].String())

	// Verify injected values
	assert.NotNil(t, newTx.hypergraph)
	assert.NotNil(t, newTx.bulletproofProver)
	assert.NotNil(t, newTx.inclusionProver)
	assert.NotNil(t, newTx.verEnc)
	assert.NotNil(t, newTx.decafConstructor)
	assert.NotNil(t, newTx.keyRing)
	assert.NotNil(t, newTx.config)
}

func TestInvalidSerialization(t *testing.T) {
	// Test with truncated data to ensure error handling works properly

	// Create a recipient bundle and serialize it
	bundle := &RecipientBundle{
		OneTimeKey:      []byte("one-time-key-data"),
		VerificationKey: []byte("verification-key-data"),
		CoinBalance:     []byte("amount-data"),
		Mask:            []byte("mask-data"),
	}

	bytes, err := bundle.ToBytes()
	require.NoError(t, err)

	// Test with truncated data
	truncatedBytes := bytes[:len(bytes)/2]
	newBundle := &RecipientBundle{}
	err = newBundle.FromBytes(truncatedBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "from bytes")

	// Test with empty data
	emptyBundle := &RecipientBundle{}
	err = emptyBundle.FromBytes([]byte{})
	assert.Error(t, err)

	// Test with corrupted data
	corruptedBytes := bytes
	if len(corruptedBytes) > 0 {
		corruptedBytes[0] = corruptedBytes[0] ^ 0xFF // Flip all bits in first byte
	}
	corruptedBundle := &RecipientBundle{}
	err = corruptedBundle.FromBytes(corruptedBytes)
	// Could be error or not depending on where corruption is, but should not panic
	if err != nil {
		assert.Contains(t, err.Error(), "from bytes")
	}
}

func TestInvalidMintTransactionSerialization(t *testing.T) {
	// Setup mocks
	hg := &mocks.MockHypergraph{}
	bp := &mocks.MockBulletproofProver{}
	ip := &mocks.MockInclusionProver{}
	ve := &mocks.MockVerifiableEncryptor{}
	km := &mocks.MockKeyRing{}
	dc := &mocks.MockDecafConstructor{}

	config := &TokenIntrinsicConfiguration{
		Behavior: Mintable | Divisible,
		MintStrategy: &TokenMintStrategy{
			MintBehavior: MintWithProof,
			ProofBasis:   ProofOfMeaningfulWork,
		},
		Units:  big.NewInt(1000000000),
		Name:   "MintTest Token",
		Symbol: "MTT",
	}

	// Create a valid mint transaction
	tx := &MintTransaction{
		Domain:     [32]byte{1, 2, 3, 4},
		Inputs:     []*MintTransactionInput{{Value: big.NewInt(100), Commitment: []byte("commitment")}},
		Outputs:    []*MintTransactionOutput{{FrameNumber: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		Fees:       []*big.Int{big.NewInt(10)},
		RangeProof: []byte("proof"),
		config:     config,
	}

	// Serialize transaction
	bytes, err := tx.ToBytes()
	require.NoError(t, err)

	// Test with wrong transaction type
	corruptedBytes := make([]byte, len(bytes))
	copy(corruptedBytes, bytes)
	// Type is at the beginning (first 4 bytes in big endian), change it to PendingTransactionType
	binary.BigEndian.PutUint32(corruptedBytes[0:4], protobufs.PendingTransactionType)
	// Create RDF multiprover for testing
	parser := &schema.TurtleRDFParser{}
	rdfMultiprover := schema.NewRDFMultiprover(parser, ip)

	newTx := &MintTransaction{}
	err = newTx.FromBytes(corruptedBytes, config, hg, bp, ip, ve, dc, km, "", rdfMultiprover)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")

	// Test with truncated data
	truncatedBytes := bytes[:len(bytes)/2]
	newTx = &MintTransaction{}
	err = newTx.FromBytes(truncatedBytes, config, hg, bp, ip, ve, dc, km, "", rdfMultiprover)
	assert.Error(t, err)
}
