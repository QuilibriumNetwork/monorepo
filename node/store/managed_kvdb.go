package store

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

var errManagedKVDBClosed = errors.New("managed kvdb closed")

// managedKVDB wraps a KVDB and keeps track of in-flight operations so Close()
// waits until all references are released. This prevents panics when iterators
// or point-lookups race with a snapshot being torn down.
type managedKVDB struct {
	inner  store.KVDB
	wg     sync.WaitGroup
	closed atomic.Bool
}

func newManagedKVDB(inner store.KVDB) *managedKVDB {
	return &managedKVDB{inner: inner}
}

func (m *managedKVDB) ref() error {
	if m.closed.Load() {
		return errManagedKVDBClosed
	}
	m.wg.Add(1)
	if m.closed.Load() {
		m.wg.Done()
		return errManagedKVDBClosed
	}
	return nil
}

func (m *managedKVDB) deref() {
	m.wg.Done()
}

func (m *managedKVDB) Get(key []byte) ([]byte, io.Closer, error) {
	if err := m.ref(); err != nil {
		return nil, nil, err
	}

	value, closer, err := m.inner.Get(key)
	if err != nil || closer == nil {
		m.deref()
		return value, nil, err
	}

	return value, &managedCloser{
		parent: m,
		inner:  closer,
	}, nil
}

func (m *managedKVDB) Set(key, value []byte) error {
	if err := m.ref(); err != nil {
		return err
	}
	defer m.deref()
	return m.inner.Set(key, value)
}

func (m *managedKVDB) Delete(key []byte) error {
	if err := m.ref(); err != nil {
		return err
	}
	defer m.deref()
	return m.inner.Delete(key)
}

func (m *managedKVDB) NewBatch(indexed bool) store.Transaction {
	if err := m.ref(); err != nil {
		return &closedTransaction{err: err}
	}
	return &managedTxn{
		parent: m,
		inner:  m.inner.NewBatch(indexed),
	}
}

func (m *managedKVDB) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	if err := m.ref(); err != nil {
		return nil, err
	}

	iter, err := m.inner.NewIter(lowerBound, upperBound)
	if err != nil {
		m.deref()
		return nil, err
	}

	return &managedIterator{
		parent: m,
		inner:  iter,
	}, nil
}

func (m *managedKVDB) Compact(start, end []byte, parallelize bool) error {
	if err := m.ref(); err != nil {
		return err
	}
	defer m.deref()
	return m.inner.Compact(start, end, parallelize)
}

func (m *managedKVDB) CompactAll() error {
	if err := m.ref(); err != nil {
		return err
	}
	defer m.deref()
	return m.inner.CompactAll()
}

func (m *managedKVDB) DeleteRange(start, end []byte) error {
	if err := m.ref(); err != nil {
		return err
	}
	defer m.deref()
	return m.inner.DeleteRange(start, end)
}

func (m *managedKVDB) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	m.wg.Wait()
	return m.inner.Close()
}

type managedCloser struct {
	parent *managedKVDB
	inner  io.Closer
	once   sync.Once
}

func (c *managedCloser) Close() error {
	var err error
	c.once.Do(func() {
		err = c.inner.Close()
		c.parent.deref()
	})
	return err
}

type managedIterator struct {
	parent *managedKVDB
	inner  store.Iterator
	once   sync.Once
}

func (i *managedIterator) Close() error {
	var err error
	i.once.Do(func() {
		err = i.inner.Close()
		i.parent.deref()
	})
	return err
}

func (i *managedIterator) Key() []byte          { return i.inner.Key() }
func (i *managedIterator) First() bool          { return i.inner.First() }
func (i *managedIterator) Next() bool           { return i.inner.Next() }
func (i *managedIterator) Prev() bool           { return i.inner.Prev() }
func (i *managedIterator) Valid() bool          { return i.inner.Valid() }
func (i *managedIterator) Value() []byte        { return i.inner.Value() }
func (i *managedIterator) SeekLT(b []byte) bool { return i.inner.SeekLT(b) }
func (i *managedIterator) SeekGE(b []byte) bool { return i.inner.SeekGE(b) }
func (i *managedIterator) Last() bool           { return i.inner.Last() }

type managedTxn struct {
	parent *managedKVDB
	inner  store.Transaction
	once   sync.Once
}

func (t *managedTxn) finish() {
	t.once.Do(func() {
		t.parent.deref()
	})
}

func (t *managedTxn) Get(key []byte) ([]byte, io.Closer, error) {
	return t.inner.Get(key)
}

func (t *managedTxn) Set(key []byte, value []byte) error {
	return t.inner.Set(key, value)
}

func (t *managedTxn) Commit() error {
	defer t.finish()
	return t.inner.Commit()
}

func (t *managedTxn) Delete(key []byte) error {
	return t.inner.Delete(key)
}

func (t *managedTxn) Abort() error {
	defer t.finish()
	return t.inner.Abort()
}

func (t *managedTxn) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return t.inner.NewIter(lowerBound, upperBound)
}

func (t *managedTxn) DeleteRange(lowerBound []byte, upperBound []byte) error {
	return t.inner.DeleteRange(lowerBound, upperBound)
}

type closedTransaction struct {
	err error
}

func (c *closedTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return nil, nil, c.err
}

func (c *closedTransaction) Set(key []byte, value []byte) error {
	return c.err
}

func (c *closedTransaction) Commit() error {
	return c.err
}

func (c *closedTransaction) Delete(key []byte) error {
	return c.err
}

func (c *closedTransaction) Abort() error {
	return c.err
}

func (c *closedTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return nil, c.err
}

func (c *closedTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return c.err
}
