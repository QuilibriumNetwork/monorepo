package tries

import (
	"bytes"
	"encoding/gob"
	"math/big"
	"sort"
	"sync"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/utils"
)

type RollingFrecencyCritbitTrie struct {
	Trie *Tree
	mu   sync.RWMutex
}

func (t *RollingFrecencyCritbitTrie) Serialize() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(t.Trie); err != nil {
		return nil, errors.Wrap(err, "serialize")
	}

	return b.Bytes(), nil
}

func (t *RollingFrecencyCritbitTrie) Deserialize(buf []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(buf) == 0 {
		return nil
	}

	var b bytes.Buffer
	b.Write(buf)
	dec := gob.NewDecoder(&b)

	if err := dec.Decode(&t.Trie); err != nil {
		if t.Trie == nil {
			t.Trie = New()
		}
	}

	return nil
}

func (t *RollingFrecencyCritbitTrie) Contains(address []byte) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	_, ok := t.Trie.Get(address)
	return ok
}

func (t *RollingFrecencyCritbitTrie) Get(
	address []byte,
) Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	p, ok := t.Trie.Get(address)
	if !ok {
		return Value{
			EarliestFrame: 0,
			LatestFrame:   0,
			Count:         0,
		}
	}

	return p.(Value)
}

func (t *RollingFrecencyCritbitTrie) FindNearest(
	address []byte,
) Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}

	find := t.FindNearestAndApproximateNeighbors(address)
	if len(find) == 0 {
		return Value{}
	}

	return find[0]
}

func (t *RollingFrecencyCritbitTrie) FindNearestAndApproximateNeighbors(
	address []byte,
) []Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ret := []Value{}
	if t.Trie == nil {
		t.Trie = New()
	}

	t.Trie.Walk(func(k []byte, v interface{}) bool {
		ret = append(ret, v.(Value))
		return false
	})

	// Get Poseidon modulus
	modulus := ff.Modulus()

	// Convert target address to big.Int
	targetInt := new(big.Int).SetBytes(address)

	// Pre-calculate modular distances for all elements
	type valueWithDist struct {
		value Value
		dist  *big.Int
		key   *big.Int // Store key as big.Int for comparison
	}

	valuesWithDist := make([]valueWithDist, len(ret))
	for i, val := range ret {
		keyInt := new(big.Int).SetBytes(val.Key)

		dist := utils.AbsoluteModularMinimumDistance(targetInt, keyInt, modulus)

		valuesWithDist[i] = valueWithDist{
			value: val,
			dist:  dist,
			key:   keyInt,
		}
	}

	// Sort by modular distance first, then by key value (for tie-breaking)
	sort.Slice(valuesWithDist, func(i, j int) bool {
		// First compare by distance
		cmp := valuesWithDist[i].dist.Cmp(valuesWithDist[j].dist)
		if cmp != 0 {
			return cmp < 0 // Sort by distance ascending
		}

		// If distances are equal, sort by key value (lower value first)
		return valuesWithDist[i].key.Cmp(valuesWithDist[j].key) < 0
	})

	// Extract sorted values
	result := make([]Value, len(valuesWithDist))
	for i, vwd := range valuesWithDist {
		result[i] = vwd.value
	}

	return result
}

func (t *RollingFrecencyCritbitTrie) Add(
	address []byte,
	latestFrame uint64,
) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Trie == nil {
		t.Trie = New()
	}

	i, ok := t.Trie.Get(address)
	var v Value
	if !ok {
		v = Value{
			Key:           address,
			EarliestFrame: latestFrame,
			LatestFrame:   latestFrame,
			Count:         0,
		}
	} else {
		v = i.(Value)
	}
	v.LatestFrame = latestFrame
	t.Trie.Insert(address, v)
}

func (t *RollingFrecencyCritbitTrie) Remove(address []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	t.Trie.Delete(address)
}
