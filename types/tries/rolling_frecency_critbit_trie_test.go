package tries_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

func TestSerializers(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}
	for i := 0; i < 100; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		addr, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		v := uint64(i)
		a := addr.Bytes()
		b := make([]byte, 32)
		copy(b[32-len(a):], addr.Bytes())

		tree.Add(b, v)
	}

	newTree := &tries.RollingFrecencyCritbitTrie{}
	buf, err := tree.Serialize()
	assert.NoError(t, err)
	err = newTree.Deserialize(buf)
	assert.NoError(t, err)
}

func TestCritbitReinit(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}
	set := [][]byte{}
	for i := 0; i < 1024; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		set = append(set, seed)
		tree.Add(seed, 14)
		assert.True(t, tree.Contains(seed))
		tree.Remove(seed)
		assert.False(t, tree.Contains(seed))
	}
	for i := 0; i < 1024; i++ {
		tree.Add(set[i], 14)
	}
	near := tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
	assert.Equal(t, 1024, len(near))
	for i := 0; i < 1024; i++ {
		tree.Remove(set[i])
		assert.False(t, tree.Contains(set[i]))
		near = tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
		assert.Equal(t, 1024-i-1, len(near))
	}
	near = tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
	assert.Equal(t, 0, len(near))
}

func TestFindNearestAndApproximateNeighborsModuloDistance(t *testing.T) {
	modulus := ff.Modulus()

	tree := &tries.RollingFrecencyCritbitTrie{}

	zeroBytes := make([]byte, 32)
	tree.Add(zeroBytes, 1)

	twoBeforeModulusBytes := make([]byte, 32)
	twoBeforeModulus := new(big.Int).Sub(modulus, big.NewInt(3))
	twoBeforeModulusBytes = twoBeforeModulus.FillBytes(twoBeforeModulusBytes)
	tree.Add(twoBeforeModulusBytes, 2)

	for i := 0; i < 998; i++ {
		randBytes := make([]byte, 32)
		rand.Read(randBytes)
		b, _ := poseidon.HashBytes(randBytes)
		tree.Add(b.FillBytes(make([]byte, 32)), uint64(i+3))
	}

	modMinusOne := new(big.Int).Sub(modulus, big.NewInt(1))
	searchBytes := make([]byte, 32)
	searchBytes = modMinusOne.FillBytes(searchBytes)

	results := tree.FindNearestAndApproximateNeighbors(searchBytes)
	require.NotEmpty(t, results, "Expected to find neighbors")

	firstResult := results[0]
	secondResult := results[1]

	assert.Equal(t, zeroBytes, firstResult.Key, "Expected the zero entry to be closest due to modular distance")

	assert.Equal(t, twoBeforeModulusBytes, secondResult.Key, "Expected the entry two before modulus to be second closest")

	zeroDistance := new(big.Int).Sub(modulus, modMinusOne)
	assert.Equal(t, int64(1), zeroDistance.Int64(), "Distance from modulus-1 to 0 should be 1")

	beforeModDistance := new(big.Int).Sub(modMinusOne, twoBeforeModulus)
	assert.Equal(t, int64(2), beforeModDistance.Int64(), "Distance from modulus-1 to modulus-3 should be 2")
}

func TestEqualModuloDistanceTiebreaker(t *testing.T) {
	modulus := ff.Modulus()

	tree := &tries.RollingFrecencyCritbitTrie{}

	entries := make(map[string]*big.Int)
	entryBytes := make(map[string][]byte)

	for i := 1; i <= 6; i++ {
		key := fmt.Sprintf("M-%d", i)
		value := new(big.Int).Sub(modulus, big.NewInt(int64(i)))
		entries[key] = value

		bytes := make([]byte, 32)
		bytes = value.FillBytes(bytes)
		entryBytes[key] = bytes
		tree.Add(bytes, uint64(i))
	}

	for i := 1; i <= 6; i++ {
		key := fmt.Sprintf("%d", i)
		value := big.NewInt(int64(i))
		entries[key] = value

		bytes := make([]byte, 32)
		bytes = value.FillBytes(bytes)
		entryBytes[key] = bytes
		tree.Add(bytes, uint64(i+6))
	}

	testCases := []struct {
		name          string
		searchPoint   *big.Int
		expectedOrder []string
	}{
		{
			name:          "Search at M-3",
			searchPoint:   new(big.Int).Sub(modulus, big.NewInt(3)),
			expectedOrder: []string{"M-3", "M-4", "M-2", "M-5", "M-1", "M-6"},
		},
		{
			name:          "Search at 3",
			searchPoint:   big.NewInt(3),
			expectedOrder: []string{"3", "2", "4", "1", "5", "6"},
		},
		{
			name:          "Search at M (equivalent to 0)",
			searchPoint:   new(big.Int).Set(modulus),
			expectedOrder: []string{"1", "M-1", "2", "M-2", "3", "M-3"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			searchBytes := make([]byte, 32)
			searchBytes = tc.searchPoint.FillBytes(searchBytes)

			results := tree.FindNearestAndApproximateNeighbors(searchBytes)
			require.NotEmpty(t, results, "Should find neighbors")

			for i, expectedKey := range tc.expectedOrder {
				if i >= len(results) {
					break
				}

				actualBytes := results[i].Key
				var foundKey string
				found := false

				for key, b := range entryBytes {
					if bytes.Equal(actualBytes, b) {
						foundKey = key
						found = true
						break
					}
				}

				require.True(t, found, "Result at position %d (%x) not found in our test entries", i, actualBytes)
				assert.Equal(t, expectedKey, foundKey, "At position %d, expected %s but got %s", i, expectedKey, foundKey)

				if i > 0 {
					prevBytes := results[i-1].Key
					currBytes := results[i].Key
					prevVal := new(big.Int).SetBytes(prevBytes)
					currVal := new(big.Int).SetBytes(currBytes)

					prevDist := calculateModularDistance(tc.searchPoint, prevVal, modulus)
					currDist := calculateModularDistance(tc.searchPoint, currVal, modulus)

					if prevDist.Cmp(currDist) == 0 {
						assert.True(t, prevVal.Cmp(currVal) < 0,
							"For equal distances (%s), lower value should come first, but %s came before %s",
							prevDist.String(), foundKey, tc.expectedOrder[i-1])
					}
				}
			}
		})
	}
}

func calculateModularDistance(a, b, modulus *big.Int) *big.Int {
	diff := new(big.Int).Sub(a, b)
	diff.Abs(diff)

	modComp := new(big.Int).Sub(modulus, diff)

	if diff.Cmp(modComp) < 0 {
		return diff
	}
	return modComp
}
