package keyedcollector

import (
	"fmt"
	"sync"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// RecordTraits specifies how to extract attributes from a record that are
// required by the collector infrastructure.
type RecordTraits[RecordT any] struct {
	Sequence func(*RecordT) uint64
	Identity func(*RecordT) models.Identity
	Equals   func(*RecordT, *RecordT) bool
}

func (t RecordTraits[RecordT]) validate() error {
	switch {
	case t.Sequence == nil:
		return fmt.Errorf("sequence accessor is required")
	case t.Identity == nil:
		return fmt.Errorf("identity accessor is required")
	case t.Equals == nil:
		return fmt.Errorf("equality comparator is required")
	default:
		return nil
	}
}

// RecordCache stores the first record per identity for a particular sequence.
// Subsequent duplicates are ignored, while conflicting records produce a
// ConflictingRecordError.
type RecordCache[RecordT any] struct {
	lock     sync.RWMutex
	sequence uint64
	entries  map[models.Identity]*RecordT
	traits   RecordTraits[RecordT]
}

func NewRecordCache[RecordT any](
	sequence uint64,
	traits RecordTraits[RecordT],
) *RecordCache[RecordT] {
	return &RecordCache[RecordT]{
		sequence: sequence,
		entries:  make(map[models.Identity]*RecordT),
		traits:   traits,
	}
}

func (c *RecordCache[RecordT]) Sequence() uint64 { return c.sequence }

// Add stores the record in the cache, returning ErrRepeatedRecord when the
// record already exists (same identity and equal contents) and
// ConflictingRecordError when the record already exists but with different
// contents. When an error is returned the record is not stored.
func (c *RecordCache[RecordT]) Add(record *RecordT) error {
	if c.traits.Sequence(record) != c.sequence {
		return ErrRecordForDifferentSequence
	}

	identity := c.traits.Identity(record)

	c.lock.Lock()
	defer c.lock.Unlock()

	if existing, ok := c.entries[identity]; ok {
		if c.traits.Equals(existing, record) {
			return ErrRepeatedRecord
		}
		return NewConflictingRecordError(existing, record)
	}

	c.entries[identity] = record
	return nil
}

// Get returns the stored record for the given identity.
func (c *RecordCache[RecordT]) Get(
	identity models.Identity,
) (*RecordT, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	record, ok := c.entries[identity]
	return record, ok
}

// Size returns the number of cached records.
func (c *RecordCache[RecordT]) Size() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return len(c.entries)
}

// All returns a snapshot of all cached records.
func (c *RecordCache[RecordT]) All() []*RecordT {
	c.lock.RLock()
	defer c.lock.RUnlock()
	result := make([]*RecordT, 0, len(c.entries))
	for _, record := range c.entries {
		result = append(result, record)
	}
	return result
}

// Remove deletes the record from the cache.
func (c *RecordCache[RecordT]) Remove(record *RecordT) {
	if record == nil {
		return
	}
	identity := c.traits.Identity(record)
	c.lock.Lock()
	delete(c.entries, identity)
	c.lock.Unlock()
}
