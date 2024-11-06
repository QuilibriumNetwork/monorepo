package internal

import (
	"math"
	"math/rand"
	"sort"
)

// Weighted is an interface for items that have a weight.
type Weighted[T any] interface {
	GetItem() T
	GetWeight() float64
}

type weightedSort[T any] struct {
	items   []T
	weights []float64
}

var _ sort.Interface = (*weightedSort[any])(nil)

// Len implements sort.Interface.
func (w weightedSort[T]) Len() int {
	return len(w.items)
}

// Less implements sort.Interface.
func (w weightedSort[T]) Less(i, j int) bool {
	return w.weights[i] >= w.weights[j]
}

// Swap implements sort.Interface.
func (w weightedSort[T]) Swap(i, j int) {
	w.items[i], w.items[j] = w.items[j], w.items[i]
	w.weights[i], w.weights[j] = w.weights[j], w.weights[i]
}

// WeightedSampleWithoutReplacementWithSource samples without replacement
// from a list of weighted items using a given random source.
// Based on work by Efraimidis and Spirakis.
func WeightedSampleWithoutReplacementWithSource[T any, W Weighted[T]](
	items []W,
	sampleSize int,
	random *rand.Rand,
) []T {
	ws := weightedSort[T]{
		items:   make([]T, len(items)),
		weights: make([]float64, len(items)),
	}
	for i, item := range items {
		ws.items[i] = item.GetItem()
		ws.weights[i] = math.Pow(random.Float64(), 1.0/item.GetWeight())
	}
	sort.Sort(ws)
	return ws.items[:sampleSize]
}

// WeightedSampleWithoutReplacement samples without replacement from a list
// of weighted items.
func WeightedSampleWithoutReplacement[T any, W Weighted[T]](
	items []W,
	sampleSize int,
) []T {
	return WeightedSampleWithoutReplacementWithSource(
		items,
		sampleSize,
		rand.New(rand.NewSource(rand.Int63())),
	)
}
