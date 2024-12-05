package store

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"sort"
	"sync"

	"github.com/cockroachdb/pebble"
)

type InMemKVDB struct {
	open       bool
	sortedKeys []string
	store      map[string][]byte
	storeMx    sync.Mutex
}

type Operation int

const (
	SetOperation Operation = iota
	DeleteOperation
)

type InMemKVDBOperation struct {
	op    Operation
	key   []byte
	value []byte
}

type InMemKVDBTransaction struct {
	id      int
	changes []InMemKVDBOperation
	db      *InMemKVDB
}

type InMemKVDBIterator struct {
	db    *InMemKVDB
	start []byte
	end   []byte
	pos   int
	open  bool
}

func (i *InMemKVDBIterator) Key() []byte {
	if !i.open {
		return nil
	}
	i.db.storeMx.Lock()
	if _, ok := i.db.store[i.db.sortedKeys[i.pos]]; !ok {
		return nil
	}
	i.db.storeMx.Unlock()

	return []byte(i.db.sortedKeys[i.pos])
}

func (i *InMemKVDBIterator) First() bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	found := false
	idx := sort.SearchStrings(i.db.sortedKeys, string(i.start))
	final := sort.SearchStrings(i.db.sortedKeys, string(i.end))
	if idx < final {
		i.pos = idx
		found = true
	}
	i.db.storeMx.Unlock()

	return found
}

func (i *InMemKVDBIterator) Next() bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	found := false
	if _, ok := i.db.store[i.db.sortedKeys[i.pos]]; ok {
		final := sort.SearchStrings(i.db.sortedKeys, string(i.end))
		if i.pos < final {
			i.pos = i.pos + 1
			found = true
		}
	}
	i.db.storeMx.Unlock()

	return found
}

func (i *InMemKVDBIterator) Last() bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	found := false
	final := sort.SearchStrings(i.db.sortedKeys, string(i.end))
	if len(i.db.sortedKeys) == final ||
		!bytes.Equal([]byte(i.db.sortedKeys[final]), i.end) {
		final--
	}
	i.pos = final
	found = true
	i.db.storeMx.Unlock()

	return found
}

func (i *InMemKVDBIterator) Prev() bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	found := false
	if _, ok := i.db.store[i.db.sortedKeys[i.pos]]; ok {
		start := sort.SearchStrings(i.db.sortedKeys, string(i.start))
		if i.pos-1 > start {
			i.pos = i.pos - 1
			found = true
		}
	}
	i.db.storeMx.Unlock()

	return found
}

func (i *InMemKVDBIterator) Valid() bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	start := sort.SearchStrings(i.db.sortedKeys, string(i.start))
	final := sort.SearchStrings(i.db.sortedKeys, string(i.end))
	i.db.storeMx.Unlock()

	return i.pos < final && i.pos >= start
}

func (i *InMemKVDBIterator) Value() []byte {
	if !i.open {
		return nil
	}

	i.db.storeMx.Lock()
	value := i.db.store[i.db.sortedKeys[i.pos]]
	i.db.storeMx.Unlock()

	return value
}

func (i *InMemKVDBIterator) Close() error {
	if !i.open {
		return errors.New("already closed iterator")
	}

	i.open = false
	return nil
}

func (i *InMemKVDBIterator) SeekLT(lt []byte) bool {
	if !i.open {
		return false
	}
	i.db.storeMx.Lock()
	found := false
	if _, ok := i.db.store[i.db.sortedKeys[i.pos]]; ok {
		idx := sort.SearchStrings(i.db.sortedKeys, string(lt))
		start := sort.SearchStrings(i.db.sortedKeys, string(i.start))
		if idx >= start {
			i.pos = idx + 1
			found = true
		}
	}
	i.db.storeMx.Unlock()

	return found
}

func (t *InMemKVDBTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	if !t.db.open {
		return nil, nil, errors.New("inmem db closed")
	}

	for _, c := range t.changes {
		if bytes.Equal(c.key, key) {
			return c.value, io.NopCloser(nil), nil
		}
	}

	t.db.storeMx.Lock()
	b, ok := t.db.store[string(key)]
	t.db.storeMx.Unlock()
	if !ok {
		return nil, nil, pebble.ErrNotFound
	}
	return b, io.NopCloser(nil), nil
}

func (t *InMemKVDBTransaction) Set(key []byte, value []byte) error {
	if !t.db.open {
		return errors.New("inmem db closed")
	}
	t.changes = append(t.changes, InMemKVDBOperation{
		op:    SetOperation,
		key:   key,
		value: value,
	})

	return nil
}

func (t *InMemKVDBTransaction) Commit() error {
	if !t.db.open {
		return errors.New("inmem db closed")
	}

	var err error
loop:
	for _, op := range t.changes {
		switch op.op {
		case SetOperation:
			err = t.db.Set(op.key, op.value)
			if err != nil {
				break loop
			}
		case DeleteOperation:
			err = t.db.Delete(op.key)
			if err != nil {
				break loop
			}
		}
	}

	return err
}

func (t *InMemKVDBTransaction) Delete(key []byte) error {
	if !t.db.open {
		return errors.New("inmem db closed")
	}

	t.changes = append(t.changes, InMemKVDBOperation{
		op:  DeleteOperation,
		key: key,
	})

	return nil
}

func (t *InMemKVDBTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	Iterator,
	error,
) {
	if !t.db.open {
		return nil, errors.New("inmem db closed")
	}

	return &InMemKVDBIterator{
		open:  true,
		db:    t.db,
		start: lowerBound,
		end:   upperBound,
		pos:   -1,
	}, nil
}

func (t *InMemKVDBTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	if !t.db.open {
		return errors.New("inmem db closed")
	}

	iter, err := t.NewIter(lowerBound, upperBound)
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		t.changes = append(t.changes, InMemKVDBOperation{
			op:  DeleteOperation,
			key: iter.Key(),
		})
	}

	return nil
}

func (t *InMemKVDBTransaction) Abort() error {
	return nil
}

func NewInMemKVDB() *InMemKVDB {
	return &InMemKVDB{
		open:       true,
		store:      map[string][]byte{},
		sortedKeys: []string{},
	}
}

func (d *InMemKVDB) Get(key []byte) ([]byte, io.Closer, error) {
	if !d.open {
		return nil, nil, errors.New("inmem db closed")
	}

	d.storeMx.Lock()
	b, ok := d.store[string(key)]
	d.storeMx.Unlock()
	if !ok {
		return nil, nil, pebble.ErrNotFound
	}
	return b, io.NopCloser(nil), nil
}

func (d *InMemKVDB) Set(key, value []byte) error {
	if !d.open {
		return errors.New("inmem db closed")
	}

	d.storeMx.Lock()
	_, ok := d.store[string(key)]
	if !ok {
		i := sort.SearchStrings(d.sortedKeys, string(key))
		if len(d.sortedKeys) > i {
			d.sortedKeys = append(d.sortedKeys[:i+1], d.sortedKeys[i:]...)
			d.sortedKeys[i] = string(key)
		} else {
			d.sortedKeys = append(d.sortedKeys, string(key))
		}
	}
	d.store[string(key)] = value

	d.storeMx.Unlock()
	return nil
}

func (d *InMemKVDB) Delete(key []byte) error {
	if !d.open {
		return errors.New("inmem db closed")
	}

	d.storeMx.Lock()
	_, ok := d.store[string(key)]
	if ok {
		i := sort.SearchStrings(d.sortedKeys, string(key))
		if len(d.sortedKeys)-1 > i {
			d.sortedKeys = append(d.sortedKeys[:i], d.sortedKeys[i+1:]...)
		} else {
			d.sortedKeys = d.sortedKeys[:i]
		}
	}
	delete(d.store, string(key))
	d.storeMx.Unlock()
	return nil
}

func (d *InMemKVDB) NewBatch(indexed bool) Transaction {
	if !d.open {
		return nil
	}

	id := rand.Int()
	return &InMemKVDBTransaction{
		id:      id,
		db:      d,
		changes: []InMemKVDBOperation{},
	}
}

func (d *InMemKVDB) NewIter(lowerBound []byte, upperBound []byte) (Iterator, error) {
	if !d.open {
		return nil, errors.New("inmem db closed")
	}

	return &InMemKVDBIterator{
		open:  true,
		db:    d,
		start: lowerBound,
		end:   upperBound,
		pos:   -1,
	}, nil
}

func (d *InMemKVDB) Compact(start, end []byte, parallelize bool) error {
	if !d.open {
		return errors.New("inmem db closed")
	}

	return nil
}

func (d *InMemKVDB) Close() error {
	if !d.open {
		return errors.New("inmem db closed")
	}

	d.open = false
	return nil
}

func (d *InMemKVDB) DeleteRange(start, end []byte) error {
	if !d.open {
		return errors.New("inmem db closed")
	}

	iter, err := d.NewIter(start, end)
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		err = d.Delete(iter.Key())
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *InMemKVDB) CompactAll() error {
	return nil
}

var _ KVDB = (*InMemKVDB)(nil)
