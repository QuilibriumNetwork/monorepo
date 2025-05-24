package store

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
	"github.com/erigontech/mdbx-go/mdbx"
	"github.com/golang/snappy"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

// compressValue compresses a byte slice using zlib compression
// It adds a header to identify the value as compressed
func compressValue(value []byte) ([]byte, error) {
	if value == nil {
		return value, nil
	}
	var b bytes.Buffer
	w := snappy.NewBufferedWriter(&b)

	if _, err := w.Write(value); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decompressValue decompresses a byte slice if it was compressed
// It checks for the compression header to determine if decompression is needed
func decompressValue(value []byte) ([]byte, error) {
	// Handle nil or empty values
	if value == nil {
		return value, nil
	}

	// Create a zlib reader
	r := snappy.NewReader(bytes.NewReader(value))

	// Read the decompressed data
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

type MDBXDB struct {
	env  *mdbx.Env
	dbis map[byte]mdbx.DBI
}

// this is ugly but I did not find a better way
var created = false
var readTxs atomic.Int32
var writeTxs atomic.Int32

const GB = 1 << 30
const MB = 1 << 20

// erigon defaults, should be tuned to quil
const READERS_LIMIT = 32_000
const RP_AUGMENT_LIMIT = 1_000_000
const MAP_SIZE = 2000 * GB
const GROWTH_STEP = 2 * GB
const PAGE_SIZE = 4096

const DEFAULT_TABLE = "default" // we use only one for now

func NewMDBXDB(config *config.DBConfig) *MDBXDB {
	if created {
		panic("do not create two instances")
	}
	created = true
	env, err := mdbx.NewEnv(mdbx.Default)
	if err != nil {
		panic(err)
	}

	// Configs
	if err = env.SetOption(mdbx.OptMaxDB, 300); err != nil {
		panic(err)
	}
	if err = env.SetOption(mdbx.OptMaxReaders, READERS_LIMIT); err != nil {
		panic(err)
	}
	if err = env.SetOption(mdbx.OptRpAugmentLimit, RP_AUGMENT_LIMIT); err != nil {
		panic(err)
	}
	os.MkdirAll(config.Path, os.ModePerm)
	if err = env.SetGeometry(-1, -1, int(MAP_SIZE), int(GROWTH_STEP), -1, int(PAGE_SIZE)); err != nil {
		panic(err)
	}

	// Open the environment
	flags := uint(mdbx.NoReadahead) | mdbx.Durable
	if err := env.Open(config.Path, flags, 0664); err != nil {
		panic(err)
	}

	// Open the default database. Other databases are opened using OpenDB)
	db := &MDBXDB{env: env, dbis: make(map[byte]mdbx.DBI)}
	db.dbis[0] = db.OpenDB(DEFAULT_TABLE)
	for i := byte(1); i < 255; i++ {
		db.dbis[i] = db.OpenDB(strconv.Itoa(int(i)))
	}
	return db
}

func (m *MDBXDB) OpenDB(name string) mdbx.DBI {
	var dbi mdbx.DBI
	var err error
	err = m.env.Update(func(txn *mdbx.Txn) error {
		dbi, err = txn.OpenDBI(name, mdbx.Create, nil, nil)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return dbi
}

// KVDB interface implementation
func (m *MDBXDB) Get(key []byte) ([]byte, io.Closer, error) {
	var result []byte
	var err error
	err = m.env.View(func(txn *mdbx.Txn) error {
		val, err := txn.Get(m.dbis[key[0]], key)
		if err != nil {
			if mdbx.IsNotFound(err) {
				return pebble.ErrNotFound
			}
			return err
		}
		result = make([]byte, len(val))
		copy(result, val)
		return err
	})

	// Decompress the value if it was compressed
	if result != nil {
		result, err = decompressValue(result)
		if err != nil {
			return nil, nil, err
		}
	}

	// no closer, the transaction is already closed
	return result, noopClose{}, err
}

func (m *MDBXDB) Set(key, value []byte) error {
	if writeTxs.Load() > 1 {
		panic("another tx is writing")
	}

	// Compress the value before storing
	compressedValue, err := compressValue(value)
	if err != nil {
		return err
	}

	return m.env.Update(func(txn *mdbx.Txn) error {
		return txn.Put(m.dbis[key[0]], key, compressedValue, mdbx.Upsert)
	})
}

func (m *MDBXDB) Delete(key []byte) error {
	if writeTxs.Load() > 1 {
		panic("another tx is writing")
	}
	return m.env.Update(func(txn *mdbx.Txn) error {
		return txn.Del(m.dbis[key[0]], key, nil)
	})
}

func (m *MDBXDB) NewBatch(indexed bool) Transaction {
	// MDBX doesn't have a direct equivalent to Pebble's indexed batch
	// We'll use a regular transaction for both cases
	return &MDBXBatch{
		db: m,
	}
}

func (m *MDBXDB) NewTransaction() Transaction {
	txn, err := m.env.BeginTxn(nil, 0)
	if writeTxs.Load() > 1 {
		panic("another tx is writing")
	}
	writeTxs.Add(1)
	runtime.LockOSThread()
	if err != nil {
		writeTxs.Add(-1)
		runtime.UnlockOSThread()
		panic(err)
	}

	return &MDBXTransaction{
		txn: txn,
		db:  m,
	}
}

func (m *MDBXDB) NewIter(lowerBound []byte, upperBound []byte) (Iterator, error) {
	txn, err := m.env.BeginTxn(nil, mdbx.Readonly)
	runtime.LockOSThread()
	readTxs.Add(1)
	if err != nil {
		runtime.UnlockOSThread()
		readTxs.Add(-1)
		return nil, err
	}

	cursor, err := txn.OpenCursor(m.dbis[lowerBound[0]])
	if err != nil {
		txn.Abort()
		runtime.UnlockOSThread()
		readTxs.Add(-1)
		return nil, err
	}

	return &MDBXIterator{
		txn:        txn,
		cursor:     cursor,
		lowerBound: lowerBound,
		upperBound: upperBound,
		valid:      false,
		txOwner:    true,
	}, nil
}

func (m *MDBXDB) Compact(start, end []byte, parallelize bool) error {
	// MDBX handles compaction differently than Pebble
	// We can use env.Copy2fd to create a compacted copy, but for now
	// we'll just return nil as MDBX handles this internally
	return nil
}

func (m *MDBXDB) CompactAll() error {
	// MDBX handles compaction differently than Pebble
	// For now, we'll just return nil as MDBX handles this internally
	return nil
}

func (m *MDBXDB) Close() error {
	m.env.Close()
	return nil
}

func (m *MDBXDB) DeleteRange(start, end []byte) error {
	tx := m.NewBatch(false)
	err := tx.DeleteRange(start, end)
	if err != nil {
		tx.Abort()
		return err
	}
	tx.Commit()
	return nil
}

// Ensure MDBXDB implements KVDB interface
var _ KVDB = (*MDBXDB)(nil)

// Transaction implementation
type MDBXTransaction struct {
	txn *mdbx.Txn
	db  *MDBXDB
}

func (t *MDBXTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	val, err := t.txn.Get(t.db.dbis[key[0]], key)
	if err != nil {
		if mdbx.IsNotFound(err) {
			return nil, nil, pebble.ErrNotFound
		}
		return nil, nil, err
	}

	// Copy the value since it's only valid during the transaction
	result := make([]byte, len(val))
	copy(result, val)

	// Decompress the value if it was compressed
	result, err = decompressValue(result)
	if err != nil {
		return nil, nil, err
	}

	return result, io.NopCloser(nil), nil
}

func (t *MDBXTransaction) Set(key []byte, value []byte) error {
	// Compress the value before storing
	compressedValue, err := compressValue(value)
	if err != nil {
		return err
	}

	return t.txn.Put(t.db.dbis[key[0]], key, compressedValue, 0)
}

func (t *MDBXTransaction) Commit() error {
	// we drop latency here, but it should be saved as metric
	_, err := t.txn.Commit()
	runtime.UnlockOSThread()
	writeTxs.Add(-1)
	return err
}

func (t *MDBXTransaction) Delete(key []byte) error {
	return t.txn.Del(t.db.dbis[key[0]], key, nil)
}

func (t *MDBXTransaction) Abort() error {
	t.txn.Abort()
	runtime.UnlockOSThread()
	writeTxs.Add(-1)
	return nil
}

func (t *MDBXTransaction) NewIter(lowerBound []byte, upperBound []byte) (Iterator, error) {
	return t.NewIterCustom(lowerBound, upperBound)
}

func (t *MDBXTransaction) NewIterCustom(lowerBound []byte, upperBound []byte) (*MDBXIterator, error) {
	cursor, err := t.txn.OpenCursor(t.db.dbis[lowerBound[0]])
	if err != nil {
		return nil, err
	}

	var key, value []byte
	if lowerBound == nil {
		key, value, err = cursor.Get(nil, nil, mdbx.First)
	} else {
		key, value, err = cursor.Get(lowerBound, nil, mdbx.SetRange)
	}
	if err != nil {
		return nil, err
	}

	return &MDBXIterator{
		txn:        t.txn,
		cursor:     cursor,
		lowerBound: lowerBound,
		upperBound: upperBound,
		valid:      upperBound == nil || bytes.Compare(key, upperBound) < 0,
		key:        key,
		value:      value,
		txOwner:    false,
	}, nil
}

func (t *MDBXTransaction) DeleteRange(lowerBound []byte, upperBound []byte) error {
	iter, err := t.NewIterCustom(lowerBound, upperBound)
	defer iter.Close()
	if err != nil {
		return err
	}
	for iter.First(); iter.Valid(); iter.Next() {
		err = iter.txn.Del(t.db.dbis[lowerBound[0]], iter.key, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// Ensure MDBXTransaction implements Transaction interface
var _ Transaction = (*MDBXTransaction)(nil)

// Iterator implementation
type MDBXIterator struct {
	txn        *mdbx.Txn
	cursor     *mdbx.Cursor
	lowerBound []byte
	upperBound []byte
	key        []byte
	value      []byte
	valid      bool
	txOwner    bool
}

func (i *MDBXIterator) Key() []byte {
	if !i.valid {
		return nil
	}
	return i.key
}

func (i *MDBXIterator) First() bool {
	var err error
	var k, v []byte

	if i.lowerBound == nil {
		k, v, err = i.cursor.Get(nil, nil, mdbx.First)
	} else {
		k, v, err = i.cursor.Get(i.lowerBound, nil, mdbx.SetRange)
	}

	if err != nil {
		i.valid = false
		return false
	}

	// Check if key is within upper bound
	if i.upperBound != nil && bytes.Compare(k, i.upperBound) >= 0 {
		i.valid = false
		return false
	}
	v, err = decompressValue(v)
	if err != nil {
		i.valid = false
		return false
	}

	i.key = k
	i.value = v
	i.valid = true
	return true
}

func (i *MDBXIterator) Next() bool {
	if !i.valid {
		return false
	}

	k, v, err := i.cursor.Get(nil, nil, mdbx.Next)
	if err != nil {
		i.valid = false
		return false
	}

	// Check if key is within upper bound
	if i.upperBound != nil && bytes.Compare(k, i.upperBound) >= 0 {
		i.valid = false
		return false
	}
	v, err = decompressValue(v)
	if err != nil {
		i.valid = false
		return false
	}

	i.key = k
	i.value = v
	return true
}

func (i *MDBXIterator) Prev() bool {
	if !i.valid {
		return false
	}

	k, v, err := i.cursor.Get(nil, nil, mdbx.Prev)
	if err != nil {
		i.valid = false
		return false
	}

	// Check if key is within lower bound
	if i.lowerBound != nil && bytes.Compare(k, i.lowerBound) < 0 {
		i.valid = false
		return false
	}
	v, err = decompressValue(v)
	if err != nil {
		i.valid = false
		return false
	}

	i.key = k
	i.value = v
	return true
}

func (i *MDBXIterator) Valid() bool {
	return i.valid
}

func (i *MDBXIterator) Value() []byte {
	if !i.valid {
		return nil
	}
	return i.value
}

func (i *MDBXIterator) Close() error {
	i.valid = false
	i.cursor.Close()
	if i.txOwner {
		i.txn.Abort()
		readTxs.Add(-1)
		runtime.UnlockOSThread()
	}
	return nil
}

func (i *MDBXIterator) SeekLT(target []byte) bool {
	if target == nil {
		return i.Last()
	}

	// First try to find the exact key
	k, v, err := i.cursor.Get(target, nil, mdbx.SetRange)
	if err != nil {
		// If not found, try to find the last key
		return i.Last()
	}

	// If we found the exact key, move to the previous one
	if bytes.Compare(k, target) == 0 {
		k, v, err = i.cursor.Get(nil, nil, mdbx.Prev)
		if err != nil {
			i.valid = false
			return false
		}
	} else {
		// If we found a key greater than target, move to the previous one
		k, v, err = i.cursor.Get(nil, nil, mdbx.Prev)
		if err != nil {
			i.valid = false
			return false
		}
	}

	// Check if key is within lower bound
	if i.lowerBound != nil && bytes.Compare(k, i.lowerBound) < 0 {
		i.valid = false
		return false
	}
	v, err = decompressValue(v)
	if err != nil {
		i.valid = false
		return false
	}

	i.key = k
	i.value = v
	i.valid = true
	return true
}

func (i *MDBXIterator) Last() bool {
	var err error
	var k, v []byte

	if i.upperBound == nil {
		k, v, err = i.cursor.Get(nil, nil, mdbx.Last)
	} else {
		// Position at or before upper bound
		k, v, err = i.cursor.Get(i.upperBound, nil, mdbx.SetRange)
		if err != nil {
			// If upper bound is beyond last key, get the last key
			k, v, err = i.cursor.Get(nil, nil, mdbx.Last)
			if err != nil {
				i.valid = false
				return false
			}
		} else if bytes.Compare(k, i.upperBound) >= 0 {
			// If we found the upper bound or beyond, move to previous
			k, v, err = i.cursor.Get(nil, nil, mdbx.Prev)
			if err != nil {
				i.valid = false
				return false
			}
		}
	}
	v, err = decompressValue(v)
	if err != nil {
		i.valid = false
		return false
	}

	if err != nil {
		i.valid = false
		return false
	}

	// Check if key is within lower bound
	if i.lowerBound != nil && bytes.Compare(k, i.lowerBound) < 0 {
		i.valid = false
		return false
	}

	i.key = k
	i.value = v
	i.valid = true
	return true
}

// Ensure MDBXIterator implements Iterator interface
var _ Iterator = (*MDBXIterator)(nil)

// Helper for closing transactions
type txnCloser struct {
	txn *mdbx.Txn
}

func (c txnCloser) Close() error {
	c.txn.Abort()
	return nil
}

type noopClose struct{}

func (n noopClose) Close() error {
	return nil
}

type MDBXBatch struct {
	db         *MDBXDB
	operations []BatchOperation
}

// Abort implements Transaction.
func (m *MDBXBatch) Abort() error {
	m.operations = nil
	return nil
}

// Commit implements Transaction.
func (m *MDBXBatch) Commit() error {
	err := m.db.env.Update(func(tx *mdbx.Txn) error {
		var err error
		for _, op := range m.operations {
			switch op.opcode {
			case Set:
				err = tx.Put(m.db.dbis[op.operand1[0]], op.operand1, op.operand2, mdbx.Upsert)
			case Delete:
				err = tx.Del(m.db.dbis[op.operand1[0]], op.operand1, nil)
			case DeleteRange:
				cursor, err := tx.OpenCursor(m.db.dbis[op.operand1[0]])
				if err != nil {
					return err
				}
				key, _, err := cursor.Get(op.operand1, nil, mdbx.SetRange)
				if err != nil {
					return err
				}
				for bytes.Compare(key, op.operand1) >= 0 && bytes.Compare(key, op.operand2) < 0 {
					err = cursor.Del(mdbx.Current)
					if err != nil {
						return err
					}
					key, _, err = cursor.Get(nil, nil, mdbx.Next)
					if err != nil {
						return err
					}
				}
				cursor.Close()
			}
			if err != nil {
				return err
			}
		}
		return err
	})
	m.operations = nil
	return err
}

// Delete implements Transaction.
func (m *MDBXBatch) Delete(key []byte) error {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	m.operations = append(m.operations, BatchOperation{opcode: Delete, operand1: keyCopy})
	return nil
}

// DeleteRange implements Transaction.
func (m *MDBXBatch) DeleteRange(lowerBound []byte, upperBound []byte) error {
	lowCopy := make([]byte, len(lowerBound))
	copy(lowCopy, lowerBound)
	upCopy := make([]byte, len(upperBound))
	copy(upCopy, upperBound)
	m.operations = append(m.operations, BatchOperation{opcode: DeleteRange, operand1: lowCopy, operand2: upCopy})
	return nil
}

// Get implements Transaction.
func (m *MDBXBatch) Get(key []byte) ([]byte, io.Closer, error) {
	panic("unimplemented")
}

// NewIter implements Transaction.
func (m *MDBXBatch) NewIter(lowerBound []byte, upperBound []byte) (Iterator, error) {
	return m.db.NewIter(lowerBound, upperBound)
}

// Set implements Transaction.
func (m *MDBXBatch) Set(key []byte, value []byte) error {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	valueCopy, err := compressValue(value)
	if err != nil {
		return err
	}
	m.operations = append(m.operations, BatchOperation{opcode: Set, operand1: keyCopy, operand2: valueCopy})
	return nil
}

var _ Transaction = (*MDBXBatch)(nil)

type BatchOperation struct {
	opcode   uint8
	operand1 []byte
	operand2 []byte
}

const (
	Set = iota
	Delete
	DeleteRange
)
