package token

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// ---------------------------------------------------------------------------
// parseAccount tests
// ---------------------------------------------------------------------------

func TestParseAccount_Valid(t *testing.T) {
	viewHex := strings.Repeat("ab", 56)
	spendHex := strings.Repeat("cd", 56)
	account := "0x" + viewHex + ":0x" + spendHex

	vk, sk, err := parseAccount(account)
	require.NoError(t, err)
	assert.Len(t, vk, 56)
	assert.Len(t, sk, 56)
	assert.Equal(t, byte(0xab), vk[0])
	assert.Equal(t, byte(0xcd), sk[0])
}

func TestParseAccount_ValidWithoutPrefix(t *testing.T) {
	viewHex := strings.Repeat("ab", 56)
	spendHex := strings.Repeat("cd", 56)
	account := viewHex + ":" + spendHex

	vk, sk, err := parseAccount(account)
	require.NoError(t, err)
	assert.Len(t, vk, 56)
	assert.Len(t, sk, 56)
}

func TestParseAccount_MissingColon(t *testing.T) {
	_, _, err := parseAccount("abcdef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "viewkey:spendkey")
}

func TestParseAccount_BadViewKeyHex(t *testing.T) {
	_, _, err := parseAccount("ZZZZ:abcd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "view key")
}

func TestParseAccount_BadSpendKeyHex(t *testing.T) {
	_, _, err := parseAccount("abcd:ZZZZ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spend key")
}

// ---------------------------------------------------------------------------
// parseCoinAddress tests
// ---------------------------------------------------------------------------

func TestParseCoinAddress_ValidWithPrefix(t *testing.T) {
	addrHex := strings.Repeat("ef", 64)
	addr, err := parseCoinAddress("0x" + addrHex)
	require.NoError(t, err)
	assert.Len(t, addr, 64)
	assert.Equal(t, byte(0xef), addr[0])
}

func TestParseCoinAddress_ValidWithoutPrefix(t *testing.T) {
	addrHex := strings.Repeat("ef", 64)
	addr, err := parseCoinAddress(addrHex)
	require.NoError(t, err)
	assert.Len(t, addr, 64)
}

func TestParseCoinAddress_WrongLength(t *testing.T) {
	_, err := parseCoinAddress("0x" + strings.Repeat("ab", 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "64-byte")
}

func TestParseCoinAddress_BadHex(t *testing.T) {
	_, err := parseCoinAddress("0x" + strings.Repeat("ZZ", 64))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hex")
}

// ---------------------------------------------------------------------------
// isCoinAddress tests
// ---------------------------------------------------------------------------

func TestIsCoinAddress_ValidWithPrefix(t *testing.T) {
	addr := "0x" + strings.Repeat("ab", 64)
	assert.True(t, isCoinAddress(addr))
}

func TestIsCoinAddress_ValidWithoutPrefix(t *testing.T) {
	addr := strings.Repeat("ab", 64)
	assert.True(t, isCoinAddress(addr))
}

func TestIsCoinAddress_TooShort(t *testing.T) {
	assert.False(t, isCoinAddress("0xabcd"))
}

func TestIsCoinAddress_NonHex(t *testing.T) {
	addr := strings.Repeat("ZZ", 64)
	assert.False(t, isCoinAddress(addr))
}

func TestIsCoinAddress_DecimalAmount(t *testing.T) {
	assert.False(t, isCoinAddress("1.5"))
}

// ---------------------------------------------------------------------------
// getCoinBalance tests
// ---------------------------------------------------------------------------

func TestGetCoinBalance_FoundInTransactions(t *testing.T) {
	coinAddr := make([]byte, 64)
	coinAddr[0] = 0xBB
	balance := big.NewInt(42000).Bytes()

	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			Transactions: []*protobufs.MaterializedTransaction{
				{Address: coinAddr, RawBalance: balance},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	bal, err := getCoinBalance(client, vk, sk, coinAddr)
	require.NoError(t, err)
	assert.Equal(t, int64(42000), bal.Int64())
}

func TestGetCoinBalance_FoundInPendingTransactions(t *testing.T) {
	coinAddr := make([]byte, 64)
	coinAddr[0] = 0xCC
	balance := big.NewInt(99000).Bytes()

	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			PendingTransactions: []*protobufs.MaterializedPendingTransaction{
				{Address: coinAddr, RawBalance: balance},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	bal, err := getCoinBalance(client, vk, sk, coinAddr)
	require.NoError(t, err)
	assert.Equal(t, int64(99000), bal.Int64())
}

func TestGetCoinBalance_NotFound(t *testing.T) {
	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			Transactions: []*protobufs.MaterializedTransaction{
				{Address: make([]byte, 64), RawBalance: big.NewInt(1).Bytes()},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	searchAddr := make([]byte, 64)
	searchAddr[0] = 0xFF

	_, err := getCoinBalance(client, vk, sk, searchAddr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// findCoinForAmount tests
// ---------------------------------------------------------------------------

func TestFindCoinForAmount_ExactMatch(t *testing.T) {
	addr1 := make([]byte, 64)
	addr1[0] = 0x01
	addr2 := make([]byte, 64)
	addr2[0] = 0x02

	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			Transactions: []*protobufs.MaterializedTransaction{
				{Address: addr1, RawBalance: big.NewInt(100).Bytes()},
				{Address: addr2, RawBalance: big.NewInt(200).Bytes()},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	addr, bal, err := findCoinForAmount(client, vk, sk, big.NewInt(200))
	require.NoError(t, err)
	assert.Equal(t, int64(200), bal.Int64())
	assert.Equal(t, byte(0x02), addr[0])
}

func TestFindCoinForAmount_SmallestSufficient(t *testing.T) {
	addr1 := make([]byte, 64)
	addr1[0] = 0x01
	addr2 := make([]byte, 64)
	addr2[0] = 0x02
	addr3 := make([]byte, 64)
	addr3[0] = 0x03

	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			Transactions: []*protobufs.MaterializedTransaction{
				{Address: addr1, RawBalance: big.NewInt(50).Bytes()},
				{Address: addr2, RawBalance: big.NewInt(500).Bytes()},
				{Address: addr3, RawBalance: big.NewInt(300).Bytes()},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	addr, bal, err := findCoinForAmount(client, vk, sk, big.NewInt(150))
	require.NoError(t, err)
	// Should pick addr3 (300) as smallest coin >= 150
	assert.Equal(t, int64(300), bal.Int64())
	assert.Equal(t, byte(0x03), addr[0])
}

func TestFindCoinForAmount_NoSufficientCoin(t *testing.T) {
	addr1 := make([]byte, 64)
	client := &mockNodeServiceClient{
		tokensByAcctResp: &protobufs.GetTokensByAccountResponse{
			Transactions: []*protobufs.MaterializedTransaction{
				{Address: addr1, RawBalance: big.NewInt(10).Bytes()},
			},
		},
	}

	vk := newMockAgreement(make([]byte, 56), make([]byte, 56))
	sk := newMockAgreement(make([]byte, 56), make([]byte, 56))

	_, _, err := findCoinForAmount(client, vk, sk, big.NewInt(1000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sufficient balance")
}

// ---------------------------------------------------------------------------
// parseCoinAddress round-trip with hex
// ---------------------------------------------------------------------------

func TestParseCoinAddress_RoundTrip(t *testing.T) {
	original := make([]byte, 64)
	for i := range original {
		original[i] = byte(i)
	}
	hexStr := "0x" + hex.EncodeToString(original)

	parsed, err := parseCoinAddress(hexStr)
	require.NoError(t, err)
	assert.Equal(t, original, parsed)
}
