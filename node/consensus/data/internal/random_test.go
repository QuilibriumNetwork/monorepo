package internal_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data/internal"
)

type mockWeighted struct {
	item   int64
	weight float64
}

var _ internal.Weighted[int64] = (*mockWeighted)(nil)

// GetWeight implements Weighted[int64].
func (m mockWeighted) GetItem() int64 {
	return m.item
}

// GetWeight implements Weighted[int64].
func (m mockWeighted) GetWeight() float64 {
	return m.weight
}

func TestWeightedSampleWithoutReplacementWithSource(t *testing.T) {
	items := []mockWeighted{
		{item: 0, weight: 0.1},
		{item: 1, weight: 0.2},
		{item: 2, weight: 0.4},
		{item: 3, weight: 0.6},
		{item: 4, weight: 0.8},
		{item: 5, weight: 1.0},
	}

	frequencies := [6]int{}
	random := rand.New(rand.NewSource(0))
	for i := 0; i < 10_000; i++ {
		sample := internal.WeightedSampleWithoutReplacementWithSource(items, 3, random)
		seen := [6]bool{}
		for _, item := range sample {
			assert.False(t, seen[item])
			frequencies[item]++
			seen[item] = true
		}
	}

	for i := 0; i < 6; i++ {
		assert.Greater(t, frequencies[i], 0)
		if i > 0 {
			assert.Greater(t, frequencies[i], frequencies[i-1])
		}
		t.Logf("item %d: %d", i, frequencies[i])
	}
}
