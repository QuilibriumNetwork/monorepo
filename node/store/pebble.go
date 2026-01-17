package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	pebblev1 "github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type PebbleDB struct {
	db     *pebble.DB
	config *config.DBConfig
}

func (p *PebbleDB) DB() *pebble.DB {
	return p.db
}

// pebbleMigrations contains ordered migration steps. New migrations append to
// the end.
var pebbleMigrations = []func(*pebble.Batch, *pebble.DB) error{
	migration_2_1_0_4,
	migration_2_1_0_5,
	migration_2_1_0_8,
	migration_2_1_0_81,
	migration_2_1_0_10,
	migration_2_1_0_10,
	migration_2_1_0_11,
	migration_2_1_0_14,
	migration_2_1_0_141,
	migration_2_1_0_142,
	migration_2_1_0_143,
	migration_2_1_0_144,
	migration_2_1_0_145,
	migration_2_1_0_146,
	migration_2_1_0_147,
	migration_2_1_0_148,
	migration_2_1_0_149,
	migration_2_1_0_1410,
	migration_2_1_0_1411,
	migration_2_1_0_15,
	migration_2_1_0_151,
	migration_2_1_0_152,
	migration_2_1_0_153,
	migration_2_1_0_154,
	migration_2_1_0_155,
	migration_2_1_0_156,
	migration_2_1_0_157,
	migration_2_1_0_158,
	migration_2_1_0_159,
	migration_2_1_0_17,
	migration_2_1_0_171,
	migration_2_1_0_172,
	migration_2_1_0_172,
	migration_2_1_0_173,
	migration_2_1_0_18,
	migration_2_1_0_181,
	migration_2_1_0_182,
	migration_2_1_0_183,
	migration_2_1_0_184,
	migration_2_1_0_185,
	migration_2_1_0_186,
	migration_2_1_0_187,
	migration_2_1_0_188,
	migration_2_1_0_189,
	migration_2_1_0_1810,
	migration_2_1_0_1811,
	migration_2_1_0_1812,
	migration_2_1_0_1813,
	migration_2_1_0_1814,
	migration_2_1_0_1815,
	migration_2_1_0_1816,
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
		FormatMajorVersion:    pebble.FormatNewest,
	}

	if config.InMemoryDONOTUSE {
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
	if err != nil && shouldAttemptLegacyOpen(err, config.InMemoryDONOTUSE) {
		logger.Warn(
			fmt.Sprintf(
				"failed to open %s with pebble v2, trying legacy open",
				storeType,
			),
			zap.Error(err),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)
		if compatErr := ensurePebbleLegacyCompatibility(
			path,
			storeType,
			coreId,
			logger,
		); compatErr == nil {
			logger.Info(
				fmt.Sprintf(
					"legacy pebble open succeeded, retrying %s with pebble v2",
					storeType,
				),
				zap.String("path", path),
				zap.Uint("core_id", coreId),
			)
			db, err = pebble.Open(path, opts)
		} else {
			logger.Error(
				fmt.Sprintf("legacy pebble open failed for %s", storeType),
				zap.Error(compatErr),
				zap.String("path", path),
				zap.Uint("core_id", coreId),
			)
		}
	}
	if err != nil {
		logger.Error(
			fmt.Sprintf("failed to open %s", storeType),
			zap.Error(err),
			zap.String("path", path),
			zap.Uint("core_id", coreId),
		)
		os.Exit(1)
	}

	pebbleDB := &PebbleDB{db, config}
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

// shouldAttemptLegacyOpen determines whether the error from pebble.Open is due
// to an outdated on-disk format. Only those cases benefit from temporarily
// opening with the legacy Pebble version.
func shouldAttemptLegacyOpen(err error, inMemory bool) bool {
	if err == nil || inMemory {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "format major version") &&
		strings.Contains(msg, "no longer supported")
}

// ensurePebbleLegacyCompatibility attempts to open the database with the
// previous Pebble v1.1.5 release. Older stores that have not yet been opened
// by Pebble v2 will be updated during this open/close cycle, allowing the
// subsequent Pebble v2 open to succeed without manual intervention.
func ensurePebbleLegacyCompatibility(
	path string,
	storeType string,
	coreId uint,
	logger *zap.Logger,
) error {
	legacyOpts := &pebblev1.Options{
		MemTableSize:          64 << 20,
		MaxOpenFiles:          1000,
		L0CompactionThreshold: 8,
		L0StopWritesThreshold: 32,
		LBaseMaxBytes:         64 << 20,
		FormatMajorVersion:    pebblev1.FormatNewest,
	}
	legacyDB, err := pebblev1.Open(path, legacyOpts)
	if err != nil {
		return err
	}
	if err := legacyDB.Close(); err != nil {
		return err
	}
	logger.Info(
		fmt.Sprintf("legacy pebble open and close completed for %s", storeType),
		zap.String("path", path),
		zap.Uint("core_id", coreId),
	)
	return nil
}

func (p *PebbleDB) migrate(logger *zap.Logger) error {
	if p.config.InMemoryDONOTUSE {
		return nil
	}

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

	batch := p.db.NewIndexedBatch()
	for i := int(storedVersion); i < len(pebbleMigrations); i++ {
		logger.Warn(
			"performing pebble store migration",
			zap.Int("from_version", int(storedVersion)),
			zap.Int("to_version", int(storedVersion+1)),
		)
		if err := pebbleMigrations[i](batch, p.db); err != nil {
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
	return p.db.Compact(context.TODO(), start, end, parallelize)
	// return p.db.Compact(start, end, parallelize)
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
func migration_2_1_0_4(b *pebble.Batch, db *pebble.DB) error {
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

func migration_2_1_0_5(b *pebble.Batch, db *pebble.DB) error {
	// We just re-run it again
	return migration_2_1_0_4(b, db)
}

func migration_2_1_0_8(b *pebble.Batch, db *pebble.DB) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_81(b *pebble.Batch, db *pebble.DB) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_10(b *pebble.Batch, db *pebble.DB) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_11(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_14(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_141(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_142(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_143(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_144(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_145(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_146(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_147(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_148(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_14(b, db)
}

func migration_2_1_0_149(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_1410(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_149(b, db)
}

func migration_2_1_0_1411(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_149(b, db)
}

func migration_2_1_0_15(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_151(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_152(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_153(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_154(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_155(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_156(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_157(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_158(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_159(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_15(b, db)
}

func migration_2_1_0_17(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_171(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_172(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_173(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_18(b *pebble.Batch, db *pebble.DB) error {
	// Global shard key: L1={0,0,0}, L2=0xff*32
	globalShardKey := tries.ShardKey{
		L1: [3]byte{},
		L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
	}
	// Next shard key (for exclusive upper bound): L1={0,0,1}, L2=0x00*32
	nextShardKey := tries.ShardKey{
		L1: [3]byte{0, 0, 1},
		L2: [32]byte{},
	}

	// Delete vertex data for global domain
	// Vertex data keys: {0x09, 0xF0, domain[32], address[32]}
	// Start: {0x09, 0xF0, 0xff*32} (prefix for global domain)
	// End: {0x09, 0xF1} (next prefix type, ensures we capture all addresses)
	if err := b.DeleteRange(
		hypergraphVertexDataKey(globalShardKey.L2[:]),
		[]byte{HYPERGRAPH_SHARD, VERTEX_DATA + 1},
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete vertex adds tree nodes
	if err := b.DeleteRange(
		hypergraphVertexAddsTreeNodeKey(globalShardKey, []byte{}),
		hypergraphVertexAddsTreeNodeKey(nextShardKey, []byte{}),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete vertex adds tree nodes by path
	if err := b.DeleteRange(
		hypergraphVertexAddsTreeNodeByPathKey(globalShardKey, []int{}),
		hypergraphVertexAddsTreeNodeByPathKey(nextShardKey, []int{}),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete hyperedge adds tree nodes
	if err := b.DeleteRange(
		hypergraphHyperedgeAddsTreeNodeKey(globalShardKey, []byte{}),
		hypergraphHyperedgeAddsTreeNodeKey(nextShardKey, []byte{}),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete hyperedge adds tree nodes by path
	if err := b.DeleteRange(
		hypergraphHyperedgeAddsTreeNodeByPathKey(globalShardKey, []int{}),
		hypergraphHyperedgeAddsTreeNodeByPathKey(nextShardKey, []int{}),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete vertex adds tree root
	if err := b.DeleteRange(
		hypergraphVertexAddsTreeRootKey(globalShardKey),
		hypergraphVertexAddsTreeRootKey(nextShardKey),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	// Delete hyperedge adds tree root
	if err := b.DeleteRange(
		hypergraphHyperedgeAddsTreeRootKey(globalShardKey),
		hypergraphHyperedgeAddsTreeRootKey(nextShardKey),
		&pebble.WriteOptions{},
	); err != nil {
		return err
	}

	return nil
}

func migration_2_1_0_181(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_18(b, db)
}

func migration_2_1_0_182(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_183(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_184(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_185(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_186(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_187(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_188(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_189(b *pebble.Batch, db *pebble.DB) error {
	return nil
}

func migration_2_1_0_1810(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

func migration_2_1_0_1811(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

func migration_2_1_0_1812(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

func migration_2_1_0_1813(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

func migration_2_1_0_1814(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

func migration_2_1_0_1815(b *pebble.Batch, db *pebble.DB) error {
	return migration_2_1_0_189(b, db)
}

// migration_2_1_0_1816 recalculates commitments for the global prover trees
// to fix potential corruption from earlier versions of sync.
func migration_2_1_0_1816(b *pebble.Batch, db *pebble.DB) error {
	// Check if already done
	doneKey := []byte{HYPERGRAPH_SHARD, HYPERGRAPH_GLOBAL_PROVER_RECALC_DONE}
	if _, closer, err := b.Get(doneKey); err == nil {
		closer.Close()
		return nil // Already done
	}

	// Global prover shard key: L1={0,0,0}, L2=0xff*32
	globalShardKey := tries.ShardKey{
		L1: [3]byte{},
		L2: [32]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
	}

	// Initialize prover (logger can be nil for migrations)
	prover := bls48581.NewKZGInclusionProver(nil)

	// Create hypergraph store using the batch
	hgStore := NewPebbleHypergraphStore(nil, &PebbleDB{db: db}, nil, nil, prover)

	// Load and recalculate each tree for the global prover shard
	treeTypes := []struct {
		setType   string
		phaseType string
		rootKey   func(tries.ShardKey) []byte
	}{
		{
			string(hypergraph.VertexAtomType),
			string(hypergraph.AddsPhaseType),
			hypergraphVertexAddsTreeRootKey,
		},
		{
			string(hypergraph.VertexAtomType),
			string(hypergraph.RemovesPhaseType),
			hypergraphVertexRemovesTreeRootKey,
		},
		{
			string(hypergraph.HyperedgeAtomType),
			string(hypergraph.AddsPhaseType),
			hypergraphHyperedgeAddsTreeRootKey,
		},
		{
			string(hypergraph.HyperedgeAtomType),
			string(hypergraph.RemovesPhaseType),
			hypergraphHyperedgeRemovesTreeRootKey,
		},
	}

	for _, tt := range treeTypes {
		rootData, closer, err := b.Get(tt.rootKey(globalShardKey))
		if err != nil {
			// No root for this tree, skip
			continue
		}
		data := slices.Clone(rootData)
		closer.Close()

		if len(data) == 0 {
			continue
		}

		var node tries.LazyVectorCommitmentNode
		switch data[0] {
		case tries.TypeLeaf:
			node, err = tries.DeserializeLeafNode(hgStore, bytes.NewReader(data[1:]))
		case tries.TypeBranch:
			pathLength := binary.BigEndian.Uint32(data[1:5])
			node, err = tries.DeserializeBranchNode(
				hgStore,
				bytes.NewReader(data[5+(pathLength*4):]),
				false,
			)
			if err != nil {
				return errors.Wrapf(
					err,
					"deserialize %s %s branch",
					tt.setType,
					tt.phaseType,
				)
			}

			fullPrefix := []int{}
			for i := range pathLength {
				fullPrefix = append(
					fullPrefix,
					int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
				)
			}
			branch := node.(*tries.LazyVectorCommitmentBranchNode)
			branch.FullPrefix = fullPrefix
		default:
			continue // Unknown type, skip
		}

		if err != nil {
			return errors.Wrapf(
				err,
				"deserialize %s %s root",
				tt.setType,
				tt.phaseType,
			)
		}

		// Create tree and force recalculation
		tree := &tries.LazyVectorCommitmentTree{
			Root:            node,
			SetType:         tt.setType,
			PhaseType:       tt.phaseType,
			ShardKey:        globalShardKey,
			Store:           hgStore,
			CoveredPrefix:   nil,
			InclusionProver: prover,
		}

		// Force full recalculation of commitments
		tree.Commit(true)
	}

	// Mark migration as done
	if err := b.Set(doneKey, []byte{0x01}, &pebble.WriteOptions{}); err != nil {
		return errors.Wrap(err, "mark global prover recalc done")
	}

	return nil
}

// pebbleBatchDB wraps a *pebble.Batch to implement store.KVDB for use in migrations
type pebbleBatchDB struct {
	b *pebble.Batch
}

func (p *pebbleBatchDB) Get(key []byte) ([]byte, io.Closer, error) {
	return p.b.Get(key)
}

func (p *pebbleBatchDB) Set(key, value []byte) error {
	return p.b.Set(key, value, &pebble.WriteOptions{})
}

func (p *pebbleBatchDB) Delete(key []byte) error {
	return p.b.Delete(key, &pebble.WriteOptions{})
}

func (p *pebbleBatchDB) NewBatch(indexed bool) store.Transaction {
	// Migrations don't need nested transactions; return a wrapper around the same
	// batch
	return &pebbleBatchTransaction{b: p.b}
}

func (p *pebbleBatchDB) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return p.b.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (p *pebbleBatchDB) Compact(start, end []byte, parallelize bool) error {
	return nil // No-op for batch
}

func (p *pebbleBatchDB) Close() error {
	return nil // Don't close the batch here
}

func (p *pebbleBatchDB) DeleteRange(start, end []byte) error {
	return p.b.DeleteRange(start, end, &pebble.WriteOptions{})
}

func (p *pebbleBatchDB) CompactAll() error {
	return nil // No-op for batch
}

var _ store.KVDB = (*pebbleBatchDB)(nil)

// pebbleBatchTransaction wraps a *pebble.Batch to implement store.Transaction
type pebbleBatchTransaction struct {
	b *pebble.Batch
}

func (t *pebbleBatchTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return t.b.Get(key)
}

func (t *pebbleBatchTransaction) Set(key []byte, value []byte) error {
	return t.b.Set(key, value, &pebble.WriteOptions{})
}

func (t *pebbleBatchTransaction) Commit() error {
	return nil // Don't commit; the migration batch handles this
}

func (t *pebbleBatchTransaction) Delete(key []byte) error {
	return t.b.Delete(key, &pebble.WriteOptions{})
}

func (t *pebbleBatchTransaction) Abort() error {
	return nil // Can't abort part of a batch
}

func (t *pebbleBatchTransaction) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return t.b.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (t *pebbleBatchTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return t.b.DeleteRange(lowerBound, upperBound, &pebble.WriteOptions{})
}

var _ store.Transaction = (*pebbleBatchTransaction)(nil)

type pebbleSnapshotDB struct {
	snap *pebble.Snapshot
}

func (p *pebbleSnapshotDB) Get(key []byte) ([]byte, io.Closer, error) {
	return p.snap.Get(key)
}

func (p *pebbleSnapshotDB) Set(key, value []byte) error {
	return errors.New("pebble snapshot is read-only")
}

func (p *pebbleSnapshotDB) Delete(key []byte) error {
	return errors.New("pebble snapshot is read-only")
}

func (p *pebbleSnapshotDB) NewBatch(indexed bool) store.Transaction {
	return &snapshotTransaction{}
}

func (p *pebbleSnapshotDB) NewIter(lowerBound []byte, upperBound []byte) (
	store.Iterator,
	error,
) {
	return p.snap.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
}

func (p *pebbleSnapshotDB) Compact(start, end []byte, parallelize bool) error {
	return errors.New("pebble snapshot is read-only")
}

func (p *pebbleSnapshotDB) Close() error {
	return p.snap.Close()
}

func (p *pebbleSnapshotDB) DeleteRange(start, end []byte) error {
	return errors.New("pebble snapshot is read-only")
}

func (p *pebbleSnapshotDB) CompactAll() error {
	return errors.New("pebble snapshot is read-only")
}

var _ store.KVDB = (*pebbleSnapshotDB)(nil)

type snapshotTransaction struct{}

func (s *snapshotTransaction) Get(key []byte) ([]byte, io.Closer, error) {
	return nil, nil, errors.New("pebble snapshot transaction is read-only")
}

func (s *snapshotTransaction) Set(key []byte, value []byte) error {
	return errors.New("pebble snapshot transaction is read-only")
}

func (s *snapshotTransaction) Commit() error {
	return errors.New("pebble snapshot transaction is read-only")
}

func (s *snapshotTransaction) Delete(key []byte) error {
	return errors.New("pebble snapshot transaction is read-only")
}

func (s *snapshotTransaction) Abort() error {
	return nil
}

func (s *snapshotTransaction) NewIter(
	lowerBound []byte,
	upperBound []byte,
) (store.Iterator, error) {
	return nil, errors.New("pebble snapshot transaction is read-only")
}

func (s *snapshotTransaction) DeleteRange(
	lowerBound []byte,
	upperBound []byte,
) error {
	return errors.New("pebble snapshot transaction is read-only")
}

var _ store.Transaction = (*snapshotTransaction)(nil)
