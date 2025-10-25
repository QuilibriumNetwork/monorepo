package store

import (
	"encoding/binary"
	"encoding/hex"
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

// pebbleMigrations contains ordered migration steps. New migrations append to
// the end.
var pebbleMigrations = []func(*pebble.Batch) error{
	migration_2_1_0_4,
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

	pebbleDB := &PebbleDB{db}
	if err := pebbleDB.migrate(logger); err != nil {
		logger.Error(
			fmt.Sprintf("failed to migrate %s", storeType),
			zap.Error(err),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)
		pebbleDB.Close()
		os.Exit(1)
	}

	return pebbleDB
}

func (p *PebbleDB) migrate(logger *zap.Logger) error {
	currentVersion := uint64(len(pebbleMigrations))

	var storedVersion uint64
	var foundVersion bool

	value, closer, err := p.db.Get([]byte{MIGRATION})
	switch {
	case err == pebble.ErrNotFound:
		// missing version implies zero
	case err != nil:
		return errors.Wrap(err, "load migration version")
	default:
		foundVersion = true
		if len(value) != 8 {
			if closer != nil {
				_ = closer.Close()
			}
			return errors.Errorf(
				"invalid migration version length: %d",
				len(value),
			)
		}
		storedVersion = binary.BigEndian.Uint64(value)
		if closer != nil {
			if err := closer.Close(); err != nil {
				logger.Warn("failed to close migration version reader", zap.Error(err))
			}
		}
	}

	if storedVersion > currentVersion {
		return errors.Errorf(
			"store migration version %d ahead of binary %d – running a migrated db "+
				"with an earlier version can cause irreparable corruption, shutting down",
			storedVersion,
			currentVersion,
		)
	}

	needsUpdate := !foundVersion || storedVersion < currentVersion
	if !needsUpdate {
		logger.Info("no pebble store migrations required")
		return nil
	}

	batch := p.db.NewBatch()
	for i := int(storedVersion); i < len(pebbleMigrations); i++ {
		logger.Warn(
			"performing pebble store migration",
			zap.Int("from_version", int(storedVersion)),
			zap.Int("to_version", int(storedVersion+1)),
		)
		if err := pebbleMigrations[i](batch); err != nil {
			batch.Close()
			logger.Error("migration failed", zap.Error(err))
			return errors.Wrapf(err, "apply migration %d", i+1)
		}
		logger.Info(
			"migration step completed",
			zap.Int("from_version", int(storedVersion)),
			zap.Int("to_version", int(storedVersion+1)),
		)
	}

	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], currentVersion)
	if err := batch.Set([]byte{MIGRATION}, versionBuf[:], nil); err != nil {
		batch.Close()
		return errors.Wrap(err, "set migration version")
	}

	if err := batch.Commit(&pebble.WriteOptions{Sync: true}); err != nil {
		batch.Close()
		return errors.Wrap(err, "commit migration batch")
	}

	if currentVersion != storedVersion {
		logger.Info(
			"applied pebble store migrations",
			zap.Uint64("from_version", storedVersion),
			zap.Uint64("to_version", currentVersion),
		)
	} else {
		logger.Info(
			"initialized pebble store migration version",
			zap.Uint64("version", currentVersion),
		)
	}

	return nil
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

// Resolves all the variations of store issues from any series of upgrade steps
// in 2.1.0.1->2.1.0.3
func migration_2_1_0_4(b *pebble.Batch) error {
	// batches don't use this but for backcompat the parameter is required
	wo := &pebble.WriteOptions{}

	frame_start, _ := hex.DecodeString("0000000000000003b9e8")
	frame_end, _ := hex.DecodeString("0000000000000003b9ec")
	err := b.DeleteRange(frame_start, frame_end, wo)
	if err != nil {
		return errors.Wrap(err, "frame removal")
	}

	frame_first_index, _ := hex.DecodeString("0010")
	frame_last_index, _ := hex.DecodeString("0020")
	err = b.Delete(frame_first_index, wo)
	if err != nil {
		return errors.Wrap(err, "frame first index removal")
	}

	err = b.Delete(frame_last_index, wo)
	if err != nil {
		return errors.Wrap(err, "frame last index removal")
	}

	shard_commits_hex := []string{
		"090000000000000000e0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"090000000000000000e1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"090000000000000000e2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"090000000000000000e3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for _, shard_commit_hex := range shard_commits_hex {
		shard_commit, _ := hex.DecodeString(shard_commit_hex)
		err = b.Delete(shard_commit, wo)
		if err != nil {
			return errors.Wrap(err, "shard commit removal")
		}
	}

	vertex_adds_tree_start, _ := hex.DecodeString("0902000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	vertex_adds_tree_end, _ := hex.DecodeString("0902000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(vertex_adds_tree_start, vertex_adds_tree_end, wo)
	if err != nil {
		return errors.Wrap(err, "vertex adds tree removal")
	}

	hyperedge_adds_tree_start, _ := hex.DecodeString("0903000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	hyperedge_adds_tree_end, _ := hex.DecodeString("0903000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(hyperedge_adds_tree_start, hyperedge_adds_tree_end, wo)
	if err != nil {
		return errors.Wrap(err, "hyperedge adds tree removal")
	}

	vertex_adds_by_path_start, _ := hex.DecodeString("0922000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	vertex_adds_by_path_end, _ := hex.DecodeString("0922000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(vertex_adds_by_path_start, vertex_adds_by_path_end, wo)
	if err != nil {
		return errors.Wrap(err, "vertex adds by path removal")
	}

	hyperedge_adds_by_path_start, _ := hex.DecodeString("0923000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	hyperedge_adds_by_path_end, _ := hex.DecodeString("0923000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(hyperedge_adds_by_path_start, hyperedge_adds_by_path_end, wo)
	if err != nil {
		return errors.Wrap(err, "hyperedge adds by path removal")
	}

	vertex_adds_change_record_start, _ := hex.DecodeString("0942000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	vertex_adds_change_record_end, _ := hex.DecodeString("0942000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	hyperedge_adds_change_record_start, _ := hex.DecodeString("0943000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	hyperedge_adds_change_record_end, _ := hex.DecodeString("0943000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(vertex_adds_change_record_start, vertex_adds_change_record_end, wo)
	if err != nil {
		return errors.Wrap(err, "vertex adds change record removal")
	}

	err = b.DeleteRange(hyperedge_adds_change_record_start, hyperedge_adds_change_record_end, wo)
	if err != nil {
		return errors.Wrap(err, "hyperedge adds change record removal")
	}

	vertex_data_start, _ := hex.DecodeString("09f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	vertex_data_end, _ := hex.DecodeString("09f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.DeleteRange(vertex_data_start, vertex_data_end, wo)
	if err != nil {
		return errors.Wrap(err, "vertex data removal")
	}

	vertex_add_root, _ := hex.DecodeString("09fc000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	hyperedge_add_root, _ := hex.DecodeString("09fe000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	err = b.Delete(vertex_add_root, wo)
	if err != nil {
		return errors.Wrap(err, "vertex add root removal")
	}

	err = b.Delete(hyperedge_add_root, wo)
	if err != nil {
		return errors.Wrap(err, "hyperedge add root removal")
	}

	return nil
}
