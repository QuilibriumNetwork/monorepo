package token

import (
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	nodekeys "source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

// TransactionBuilder helps construct and prove token transactions
type TransactionBuilder struct {
	keyManager        keys.KeyManager
	keyRing           keys.KeyRing
	hypergraph        hypergraph.Hypergraph
	bulletproofProver crypto.BulletproofProver
	inclusionProver   crypto.InclusionProver
	verEnc            crypto.VerifiableEncryptor
	decafConstructor  crypto.DecafConstructor
	rdfMultiprover    *schema.RDFMultiprover
	rdfSchema         string
	domain            [32]byte
	config            *token.TokenIntrinsicConfiguration
}

// NewTransactionBuilder creates a new transaction builder
func NewTransactionBuilder(
	keyManager keys.KeyManager,
	hg hypergraph.Hypergraph,
	bulletproofProver crypto.BulletproofProver,
	inclusionProver crypto.InclusionProver,
	verEnc crypto.VerifiableEncryptor,
	decafConstructor crypto.DecafConstructor,
) (*TransactionBuilder, error) {
	var domain [32]byte
	copy(domain[:], token.QUIL_TOKEN_ADDRESS[:32])

	rdfSchema, err := token.PrepareRDFSchemaFromConfig(
		token.QUIL_TOKEN_ADDRESS,
		token.QUIL_TOKEN_CONFIGURATION,
	)
	if err != nil {
		return nil, errors.Wrap(err, "new transaction builder")
	}

	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		inclusionProver,
	)

	keyRing := nodekeys.ToKeyRing(keyManager, false)

	return &TransactionBuilder{
		keyManager:        keyManager,
		keyRing:           keyRing,
		hypergraph:        hg,
		bulletproofProver: bulletproofProver,
		inclusionProver:   inclusionProver,
		verEnc:            verEnc,
		decafConstructor:  decafConstructor,
		rdfMultiprover:    rdfMultiprover,
		rdfSchema:         rdfSchema,
		domain:            domain,
		config:            token.QUIL_TOKEN_CONFIGURATION,
	}, nil
}

// BuildTransferTransaction builds a transfer transaction from a coin to a
// recipient. The coin is consumed entirely and a single output is created.
func (tb *TransactionBuilder) BuildTransferTransaction(
	coinAddress []byte,
	amount *big.Int,
	recipientViewKey []byte,
	recipientSpendKey []byte,
) (*token.Transaction, error) {
	input, err := token.NewTransactionInput(coinAddress)
	if err != nil {
		return nil, errors.Wrap(err, "build transfer transaction")
	}

	output, err := token.NewTransactionOutput(
		amount,
		recipientViewKey,
		recipientSpendKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "build transfer transaction")
	}

	tx := token.NewTransaction(
		tb.domain,
		[]*token.TransactionInput{input},
		[]*token.TransactionOutput{output},
		[]*big.Int{big.NewInt(0)},
		tb.config,
		tb.hypergraph,
		tb.bulletproofProver,
		tb.inclusionProver,
		tb.verEnc,
		tb.decafConstructor,
		tb.keyRing,
		tb.rdfSchema,
		tb.rdfMultiprover,
	)

	return tx, nil
}

// BuildSplitTransaction builds a transaction that splits a coin into multiple
// outputs, all sent to the same recipient.
func (tb *TransactionBuilder) BuildSplitTransaction(
	coinAddress []byte,
	amounts []*big.Int,
	recipientViewKey []byte,
	recipientSpendKey []byte,
) (*token.Transaction, error) {
	input, err := token.NewTransactionInput(coinAddress)
	if err != nil {
		return nil, errors.Wrap(err, "build split transaction")
	}

	outputs := make([]*token.TransactionOutput, len(amounts))
	fees := make([]*big.Int, len(amounts))
	for i, amt := range amounts {
		output, err := token.NewTransactionOutput(
			amt,
			recipientViewKey,
			recipientSpendKey,
		)
		if err != nil {
			return nil, errors.Wrap(err, "build split transaction")
		}
		outputs[i] = output
		fees[i] = big.NewInt(0)
	}

	tx := token.NewTransaction(
		tb.domain,
		[]*token.TransactionInput{input},
		outputs,
		fees,
		tb.config,
		tb.hypergraph,
		tb.bulletproofProver,
		tb.inclusionProver,
		tb.verEnc,
		tb.decafConstructor,
		tb.keyRing,
		tb.rdfSchema,
		tb.rdfMultiprover,
	)

	return tx, nil
}

// BuildMergeTransaction builds a transaction that merges multiple coins into a
// single output.
func (tb *TransactionBuilder) BuildMergeTransaction(
	coinAddresses [][]byte,
	totalAmount *big.Int,
	recipientViewKey []byte,
	recipientSpendKey []byte,
) (*token.Transaction, error) {
	inputs := make([]*token.TransactionInput, len(coinAddresses))
	for i, addr := range coinAddresses {
		input, err := token.NewTransactionInput(addr)
		if err != nil {
			return nil, errors.Wrap(err, "build merge transaction")
		}
		inputs[i] = input
	}

	output, err := token.NewTransactionOutput(
		totalAmount,
		recipientViewKey,
		recipientSpendKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "build merge transaction")
	}

	tx := token.NewTransaction(
		tb.domain,
		inputs,
		[]*token.TransactionOutput{output},
		[]*big.Int{big.NewInt(0)},
		tb.config,
		tb.hypergraph,
		tb.bulletproofProver,
		tb.inclusionProver,
		tb.verEnc,
		tb.decafConstructor,
		tb.keyRing,
		tb.rdfSchema,
		tb.rdfMultiprover,
	)

	return tx, nil
}

// BuildPendingTransaction builds a pending transaction (for the Acceptable
// token flow) from a coin to a recipient with a refund address.
func (tb *TransactionBuilder) BuildPendingTransaction(
	coinAddress []byte,
	amount *big.Int,
	toViewKey []byte,
	toSpendKey []byte,
	refundViewKey []byte,
	refundSpendKey []byte,
	expirationFrame uint64,
) (*token.PendingTransaction, error) {
	input, err := token.NewPendingTransactionInput(coinAddress)
	if err != nil {
		return nil, errors.Wrap(err, "build pending transaction")
	}

	output, err := token.NewPendingTransactionOutput(
		amount,
		toViewKey,
		toSpendKey,
		refundViewKey,
		refundSpendKey,
		expirationFrame,
	)
	if err != nil {
		return nil, errors.Wrap(err, "build pending transaction")
	}

	pendingConfig := &token.TokenIntrinsicConfiguration{
		Behavior:     tb.config.Behavior,
		MintStrategy: tb.config.MintStrategy,
		Units:        tb.config.Units,
		Supply:       tb.config.Supply,
		Name:         tb.config.Name,
		Symbol:       tb.config.Symbol,
	}

	tx := token.NewPendingTransaction(
		tb.domain,
		[]*token.PendingTransactionInput{input},
		[]*token.PendingTransactionOutput{output},
		[]*big.Int{big.NewInt(0)},
		pendingConfig,
		tb.hypergraph,
		tb.bulletproofProver,
		tb.inclusionProver,
		tb.verEnc,
		tb.decafConstructor,
		tb.keyRing,
		tb.rdfSchema,
		tb.rdfMultiprover,
	)

	return tx, nil
}

// BuildAcceptTransaction builds a transaction that accepts a pending
// transaction, consuming the pending tx and creating a coin for the recipient.
func (tb *TransactionBuilder) BuildAcceptTransaction(
	pendingTxAddress []byte,
	amount *big.Int,
	recipientViewKey []byte,
	recipientSpendKey []byte,
) (*token.Transaction, error) {
	input, err := token.NewTransactionInput(pendingTxAddress)
	if err != nil {
		return nil, errors.Wrap(err, "build accept transaction")
	}

	output, err := token.NewTransactionOutput(
		amount,
		recipientViewKey,
		recipientSpendKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "build accept transaction")
	}

	acceptConfig := &token.TokenIntrinsicConfiguration{
		Behavior:     token.Acceptable,
		MintStrategy: tb.config.MintStrategy,
		Units:        tb.config.Units,
		Supply:       tb.config.Supply,
		Name:         tb.config.Name,
		Symbol:       tb.config.Symbol,
	}

	tx := token.NewTransaction(
		tb.domain,
		[]*token.TransactionInput{input},
		[]*token.TransactionOutput{output},
		[]*big.Int{big.NewInt(0)},
		acceptConfig,
		tb.hypergraph,
		tb.bulletproofProver,
		tb.inclusionProver,
		tb.verEnc,
		tb.decafConstructor,
		tb.keyRing,
		tb.rdfSchema,
		tb.rdfMultiprover,
	)

	return tx, nil
}

// BuildRejectTransaction builds a transaction that rejects a pending
// transaction, returning the coin to the refund address.
func (tb *TransactionBuilder) BuildRejectTransaction(
	pendingTxAddress []byte,
	amount *big.Int,
	refundViewKey []byte,
	refundSpendKey []byte,
) (*token.Transaction, error) {
	return tb.BuildAcceptTransaction(
		pendingTxAddress,
		amount,
		refundViewKey,
		refundSpendKey,
	)
}

// ProveTransaction proves a transaction and returns the protobuf.
func (tb *TransactionBuilder) ProveTransaction(
	tx *token.Transaction,
	frameNumber uint64,
) (*protobufs.Transaction, error) {
	if err := tx.Prove(frameNumber); err != nil {
		return nil, errors.Wrap(err, "prove transaction")
	}

	return tx.ToProtobuf(), nil
}

// ProvePendingTransaction proves a pending transaction and returns the
// protobuf.
func (tb *TransactionBuilder) ProvePendingTransaction(
	tx *token.PendingTransaction,
	frameNumber uint64,
) (*protobufs.PendingTransaction, error) {
	if err := tx.Prove(frameNumber); err != nil {
		return nil, errors.Wrap(err, "prove pending transaction")
	}

	return tx.ToProtobuf(), nil
}
