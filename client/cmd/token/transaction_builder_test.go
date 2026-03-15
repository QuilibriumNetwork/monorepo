package token

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
)

func newTestTransactionBuilder(t *testing.T) *TransactionBuilder {
	t.Helper()
	km := newMockKeyManager()
	tb, err := NewTransactionBuilder(
		km,
		nil, // hypergraph — not used during Build*
		&mockBulletproofProver{},
		&mockInclusionProver{},
		&mockVerifiableEncryptor{},
		&mockDecafConstructor{},
	)
	require.NoError(t, err)
	return tb
}

func TestNewTransactionBuilder(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	var expectedDomain [32]byte
	copy(expectedDomain[:], token.QUIL_TOKEN_ADDRESS[:32])
	assert.Equal(t, expectedDomain, tb.domain)
	assert.NotNil(t, tb.rdfMultiprover)
	assert.NotEmpty(t, tb.rdfSchema)
	assert.NotNil(t, tb.config)
	assert.NotNil(t, tb.keyRing)
}

func TestBuildTransferTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	coinAddr := make([]byte, 64)
	coinAddr[0] = 0xAA
	amount := big.NewInt(1000000)
	viewKey := make([]byte, 56)
	spendKey := make([]byte, 56)

	tx, err := tb.BuildTransferTransaction(coinAddr, amount, viewKey, spendKey)
	require.NoError(t, err)
	require.NotNil(t, tx)

	assert.Len(t, tx.Inputs, 1)
	assert.Len(t, tx.Outputs, 1)
	assert.Equal(t, tb.domain, tx.Domain)
	assert.Len(t, tx.Fees, 1)
	assert.Equal(t, int64(0), tx.Fees[0].Int64())
}

func TestBuildSplitTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	coinAddr := make([]byte, 64)
	amounts := []*big.Int{
		big.NewInt(100),
		big.NewInt(200),
		big.NewInt(300),
	}
	viewKey := make([]byte, 56)
	spendKey := make([]byte, 56)

	tx, err := tb.BuildSplitTransaction(coinAddr, amounts, viewKey, spendKey)
	require.NoError(t, err)
	require.NotNil(t, tx)

	assert.Len(t, tx.Inputs, 1)
	assert.Len(t, tx.Outputs, 3)
	assert.Len(t, tx.Fees, 3)
	for _, fee := range tx.Fees {
		assert.Equal(t, int64(0), fee.Int64())
	}
}

func TestBuildMergeTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	coinAddrs := [][]byte{
		make([]byte, 64),
		make([]byte, 64),
		make([]byte, 64),
	}
	coinAddrs[0][0] = 0x01
	coinAddrs[1][0] = 0x02
	coinAddrs[2][0] = 0x03

	total := big.NewInt(600)
	viewKey := make([]byte, 56)
	spendKey := make([]byte, 56)

	tx, err := tb.BuildMergeTransaction(coinAddrs, total, viewKey, spendKey)
	require.NoError(t, err)
	require.NotNil(t, tx)

	assert.Len(t, tx.Inputs, 3)
	assert.Len(t, tx.Outputs, 1)
	assert.Len(t, tx.Fees, 1)
	assert.Equal(t, int64(0), tx.Fees[0].Int64())
}

func TestBuildPendingTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	coinAddr := make([]byte, 64)
	amount := big.NewInt(500)
	toView := make([]byte, 56)
	toSpend := make([]byte, 56)
	refundView := make([]byte, 56)
	refundSpend := make([]byte, 56)
	expiration := uint64(1000)

	ptx, err := tb.BuildPendingTransaction(
		coinAddr, amount,
		toView, toSpend,
		refundView, refundSpend,
		expiration,
	)
	require.NoError(t, err)
	require.NotNil(t, ptx)

	assert.Len(t, ptx.Inputs, 1)
	assert.Len(t, ptx.Outputs, 1)
	assert.Equal(t, expiration, ptx.Outputs[0].Expiration)
	assert.Equal(t, tb.domain, ptx.Domain)
}

func TestBuildAcceptTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	pendingAddr := make([]byte, 64)
	amount := big.NewInt(500)
	viewKey := make([]byte, 56)
	spendKey := make([]byte, 56)

	tx, err := tb.BuildAcceptTransaction(pendingAddr, amount, viewKey, spendKey)
	require.NoError(t, err)
	require.NotNil(t, tx)

	assert.Len(t, tx.Inputs, 1)
	assert.Len(t, tx.Outputs, 1)
	assert.Len(t, tx.Fees, 1)
}

func TestBuildRejectTransaction(t *testing.T) {
	tb := newTestTransactionBuilder(t)

	pendingAddr := make([]byte, 64)
	amount := big.NewInt(500)
	refundView := make([]byte, 56)
	refundSpend := make([]byte, 56)

	tx, err := tb.BuildRejectTransaction(pendingAddr, amount, refundView, refundSpend)
	require.NoError(t, err)
	require.NotNil(t, tx)

	// BuildRejectTransaction delegates to BuildAcceptTransaction
	assert.Len(t, tx.Inputs, 1)
	assert.Len(t, tx.Outputs, 1)
}
