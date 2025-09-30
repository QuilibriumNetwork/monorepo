package store

import (
	"context"

	"github.com/cockroachdb/pebble"
	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// shim structs for go-datastore
type batch struct {
	b  *transaction
	db store.KVDB
}

type transaction struct {
	tx store.Transaction
}

type PeerstoreDatastore struct {
	db store.KVDB
}

var _ ds.Datastore = (*PeerstoreDatastore)(nil)
var _ ds.TxnDatastore = (*PeerstoreDatastore)(nil)
var _ ds.Txn = (*transaction)(nil)
var _ ds.PersistentDatastore = (*PeerstoreDatastore)(nil)
var _ ds.Batching = (*PeerstoreDatastore)(nil)
var _ ds.Batch = (*batch)(nil)

func NewPeerstoreDatastore(db store.KVDB) (*PeerstoreDatastore, error) {
	ds := PeerstoreDatastore{
		db: db,
	}
	return &ds, nil
}

func (d *PeerstoreDatastore) Put(
	ctx context.Context,
	key ds.Key,
	value []byte,
) (err error) {
	return d.db.Set(
		append([]byte{PEERSTORE}, key.Bytes()...),
		value,
	)
}

func (d *PeerstoreDatastore) Sync(ctx context.Context, prefix ds.Key) error {
	return nil
}

func (d *PeerstoreDatastore) Get(
	ctx context.Context,
	key ds.Key,
) (value []byte, err error) {
	val, closer, err := d.db.Get(append([]byte{PEERSTORE}, key.Bytes()...))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, ds.ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()

	out := make([]byte, len(val))
	copy(out[:], val[:])

	return val, nil
}

func (d *PeerstoreDatastore) Has(
	ctx context.Context,
	key ds.Key,
) (exists bool, err error) {
	if _, err := d.Get(ctx, key); err != nil {
		if err == ds.ErrNotFound {
			return false, nil
		}
		return false, errors.Wrap(err, "has")
	}

	return true, nil
}

func (d *PeerstoreDatastore) GetSize(
	ctx context.Context,
	key ds.Key,
) (size int, err error) {
	return ds.GetBackedSize(ctx, d, key)
}

func (d *PeerstoreDatastore) Delete(
	ctx context.Context,
	key ds.Key,
) (err error) {
	return d.db.Delete(append([]byte{PEERSTORE}, key.Bytes()...))
}

func (d *PeerstoreDatastore) Query(ctx context.Context, q dsq.Query) (
	dsq.Results,
	error,
) {
	rnge := []byte{PEERSTORE}

	qNaive := q
	prefix := ds.NewKey(q.Prefix).String()
	if prefix != "/" {
		rnge = append(rnge, []byte(prefix+"/")...)
		qNaive.Prefix = ""
	}

	i, err := d.db.NewIter(rnge, nil)
	if err != nil {
		return nil, errors.Wrap(err, "query")
	}

	next := i.Next
	if len(q.Orders) > 0 {
		switch q.Orders[0].(type) {
		case dsq.OrderByKey, *dsq.OrderByKey:
			qNaive.Orders = nil
			i.First()
		case dsq.OrderByKeyDescending, *dsq.OrderByKeyDescending:
			next = func() bool {
				next = i.Prev
				return i.Last()
			}
			qNaive.Orders = nil
		default:
			i.First()
		}
	} else {
		i.First()
	}
	r := dsq.ResultsFromIterator(q, dsq.Iterator{
		Next: func() (dsq.Result, bool) {
			if !next() {
				return dsq.Result{}, false
			}
			k := string(i.Key()[1:])
			e := dsq.Entry{Key: k, Size: len(i.Value())}

			if !q.KeysOnly {
				buf := make([]byte, len(i.Value()))
				copy(buf, i.Value())
				e.Value = buf
			}
			return dsq.Result{Entry: e}, true
		},
		Close: func() error {
			return i.Close()
		},
	})
	return dsq.NaiveQueryApply(qNaive, r), nil
}

func (d *PeerstoreDatastore) DiskUsage(ctx context.Context) (uint64, error) {
	return 0, nil
}

// Closing is not done here:
func (d *PeerstoreDatastore) Close() (err error) {
	return nil
}

func (d *PeerstoreDatastore) Batch(ctx context.Context) (ds.Batch, error) {
	return &batch{
		b:  &transaction{tx: d.db.NewBatch(false)},
		db: d.db,
	}, nil
}

func (d *PeerstoreDatastore) NewTransaction(
	ctx context.Context,
	readOnly bool,
) (ds.Txn, error) {
	tx := d.db.NewBatch(false)
	return &transaction{tx}, nil
}

func (b *batch) Put(ctx context.Context, key ds.Key, value []byte) error {
	b.b.Put(ctx, key, value)
	return nil
}

func (b *batch) Commit(ctx context.Context) error {
	return b.b.Commit(ctx)
}

func (b *batch) Delete(ctx context.Context, key ds.Key) error {
	b.b.Delete(ctx, key)
	return nil
}

func (t *transaction) Commit(ctx context.Context) error {
	return t.tx.Commit()
}

func (t *transaction) Discard(ctx context.Context) {
	t.tx.Abort()
}

func (t *transaction) Get(
	ctx context.Context,
	key ds.Key,
) (value []byte, err error) {
	b, closer, err := t.tx.Get(append([]byte{PEERSTORE}, key.Bytes()...))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, ds.ErrNotFound
		}
		return nil, errors.Wrap(err, "get")
	}
	defer closer.Close()

	out := make([]byte, len(b))
	copy(out[:], b[:])

	return b, nil
}

func (t *transaction) Put(ctx context.Context, key ds.Key, value []byte) error {
	return t.tx.Set(append([]byte{PEERSTORE}, key.Bytes()...), value)
}

func (t *transaction) Has(ctx context.Context, key ds.Key) (
	exists bool,
	err error,
) {
	if _, err := t.Get(ctx, key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}

		return false, errors.Wrap(err, "has")
	}

	return true, nil
}

func (t *transaction) GetSize(
	ctx context.Context,
	key ds.Key,
) (size int, err error) {
	return ds.GetBackedSize(ctx, t, key)
}

func (t *transaction) Delete(ctx context.Context, key ds.Key) (err error) {
	return t.tx.Delete(append([]byte{PEERSTORE}, key.Bytes()...))
}

func (t *transaction) Query(ctx context.Context, q dsq.Query) (
	dsq.Results,
	error,
) {
	rnge := []byte{PEERSTORE}
	qNaive := q
	prefix := ds.NewKey(q.Prefix).String()
	if prefix != "/" {
		rnge = append(rnge, []byte(prefix+"/")...)
		qNaive.Prefix = ""
	}

	i, err := t.tx.NewIter(rnge, nil)
	if err != nil {
		return nil, errors.Wrap(err, "query")
	}

	next := i.Next
	if len(q.Orders) > 0 {
		switch q.Orders[0].(type) {
		case dsq.OrderByKey, *dsq.OrderByKey:
			qNaive.Orders = nil
		case dsq.OrderByKeyDescending, *dsq.OrderByKeyDescending:
			next = func() bool {
				next = i.Prev
				return i.Last()
			}
			qNaive.Orders = nil
		default:
		}
	}
	r := dsq.ResultsFromIterator(q, dsq.Iterator{
		Next: func() (dsq.Result, bool) {
			if !next() {
				return dsq.Result{}, false
			}
			k := string(i.Key()[1:])
			e := dsq.Entry{Key: k, Size: len(i.Value())}

			if !q.KeysOnly {
				buf := make([]byte, len(i.Value()))
				copy(buf, i.Value())
				e.Value = buf
			}
			return dsq.Result{Entry: e}, true
		},
		Close: func() error {
			return i.Close()
		},
	})
	return dsq.NaiveQueryApply(qNaive, r), nil
}
