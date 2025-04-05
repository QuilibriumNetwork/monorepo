package p2p

import (
	"math/big"
	"sort"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

func GetOnesIndices(input []byte) []int {
	var indices []int
	for i, b := range input {
		for j := 0; j < 8; j++ {
			if (b>>j)&1 == 1 {
				indices = append(indices, i*8+j)
			}
		}
	}
	return indices
}

// GetBloomFilter returns a bloom filter based on the data, however
// it assumes bitLength is a multiple of 32. If the filter size is not
// conformant, this will generate biased indices.
func GetBloomFilter(data []byte, bitLength int, k int) []byte {
	size := big.NewInt(int64(bitLength)).BitLen() - 1
	digest := sha3.Sum256(data)
	output := make([]byte, bitLength/8)
	outputBI := big.NewInt(0)
	digestBI := new(big.Int).SetBytes(digest[:])
	for i := 0; i < k; i++ {
		position := uint(0)
		for j := size * i; j < size*(i+1); j++ {
			position = position<<1 | (digestBI.Bit(j))
		}
		if outputBI.Bit(int(position)) != 1 {
			outputBI.SetBit(outputBI, int(position), 1)
		} else if k < size {
			// we need to extend the search
			k++
		}
	}
	outputBI.FillBytes(output)
	return output
}

// GetBloomFilterIndices returns the indices of a bloom filter, in increasing
// order, assuming bitLength is a multiple of 32 as in GetBloomFilter.
func GetBloomFilterIndices(data []byte, bitLength int, k int) []byte {
	logger := utils.GetLogger().With(zap.String("stage", "get-bloom-filter-indices"))
	size := big.NewInt(int64(bitLength)).BitLen() - 1
	h := sha3.NewShake256()
	_, err := h.Write(data)
	if err != nil {
		logger.Panic("could not write to hash", zap.Error(err))
	}

	digest := make([]byte, size*k)
	_, err = h.Read(digest)
	if err != nil {
		logger.Panic("could not read from hash", zap.Error(err))
	}

	indices := []string{}
	for i := 0; i < k; i++ {
		position := make([]byte, size/8)
		for j := (size / 8) * i; j < (size/8)*(i+1); j++ {
			position[j%(size/8)] = digest[j]
		}
		found := false
		for _, ext := range indices {
			if ext == string(position) {
				k++
				found = true
				break
			}
		}
		if !found {
			p := sort.SearchStrings(indices, string(position))
			if len(indices) > p {
				indices = append(indices[:p+1], indices[p:]...)
				indices[p] = string(position)
			} else {
				indices = append(indices, string(position))
			}
		}
	}

	output := ""
	for _, idx := range indices {
		output += idx
	}
	return []byte(output)
}
