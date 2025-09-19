package store

import (
	"fmt"
	"io"
	"os"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type PebbleDB struct {
	db *pebble.DB
}

func NewPebbleDB(
	logger *zap.Logger,
	config *config.DBConfig,
	coreId uint,
) *PebbleDB {
	opts := &pebble.Options{
		MemTableSize:          64 << 20,
		MaxOpenFiles:          1000,
		L0CompactionThreshold: 8,
		L0StopWritesThreshold: 32,
		LBaseMaxBytes:         64 << 20,
	}

	if config.InMemoryDONOTUSE {
		logger.Warn(
			"IN MEMORY DATABASE OPTION ENABLED - THIS WILL NOT SAVE TO DISK",
		)
		opts.FS = vfs.NewMem()
	}

	path := config.Path
	if coreId > 0 && len(config.WorkerPaths) > int(coreId-1) {
		path = config.WorkerPaths[coreId-1]
	} else if coreId > 0 {
		path = fmt.Sprintf(config.WorkerPathPrefix, coreId)
	}

	storeType := "store"
	if coreId > 0 {
		storeType = "worker store"
	}

	if _, err := os.Stat(path); os.IsNotExist(err) && !config.InMemoryDONOTUSE {
		logger.Warn(
			fmt.Sprintf("%s not found, creating", storeType),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)

		if err := os.MkdirAll(path, 0755); err != nil {
			logger.Error(
				fmt.Sprintf("%s could not be created, terminating", storeType),
				zap.Error(err),
				zap.String("path", path),
				zap.Uint("core_id", coreId),
			)
			os.Exit(1)
		}
	} else {
		logger.Info(
			fmt.Sprintf("%s found", storeType),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)
	}

	db, err := pebble.Open(path, opts)
	if err != nil {
		logger.Error(
			fmt.Sprintf("failed to open %s", storeType),
			zap.Error(err),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)
		os.Exit(1)
	}

	return &PebbleDB{db}
}

func (p *PebbleDB) Get(key []byte) ([]byte, io.Closer, error) {
	return p.db.Get(key)
}

func (p *PebbleDB) Set(key, value []byte) error {
	return p.db.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) Delete(key []byte) error {
	return p.db.Delete(key, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) NewBatch(indexed bool) store.Transaction {
	if indexed {
		return &PebbleTransaction{
			b: p.db.NewIndexedBatch(),
		}
	} else {
		return &PebbleTransaction{
			b: p.db.NewBatch(),
		}
	}
}

func (p *PebbleDB) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return p.db.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (p *PebbleDB) Compact(start, end []byte, parallelize bool) error {
	return p.db.Compact(start, end, parallelize)
}

func (p *PebbleDB) Close() error {
	return p.db.Close()
}

func (p *PebbleDB) DeleteRange(start, end []byte) error {
	return p.db.DeleteRange(start, end, &pebble.WriteOptions{Sync: true})
}

func (p *PebbleDB) CompactAll() error {
	iter, err := p.db.NewIter(nil)
	if err != nil {
		return errors.Wrap(err, "compact all")
	}

	var first, last []byte
	if iter.First() {
		first = append(first, iter.Key()...)
	}
	if iter.Last() {
		last = append(last, iter.Key()...)
	}
	if err := iter.Close(); err != nil {
		return errors.Wrap(err, "compact all")
	}

	if err := p.Compact(first, last, false); err != nil {
		return errors.Wrap(err, "compact all")
	}

	return nil
}

var _ store.KVDB = (*PebbleDB)(nil)

type PebbleTransaction struct {
	b *pebble.Batch
}

func (t *PebbleTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return t.b.Get(key)
}

func (t *PebbleTransaction) Set(key []byte, value []byte) error {
	return t.b.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Commit() error {
	return t.b.Commit(&pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Delete(key []byte) error {
	return t.b.Delete(key, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Abort() error {
	return t.b.Close()
}

func (t *PebbleTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return t.b.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (t *PebbleTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return t.b.DeleteRange(
		lowerBound,
		upperBound,
		&pebble.WriteOptions{Sync: true},
	)
}

var _ store.Transaction = (*PebbleTransaction)(nil)

func rightAlign(data []byte, size int) []byte {
	l := len(data)

	if l == size {
		return data
	}

	if l > size {
		return data[l-size:]
	}

	pad := make([]byte, size)
	copy(pad[size-l:], data)
	return pad
}
