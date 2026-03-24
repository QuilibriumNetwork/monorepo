package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	pebblev1 "github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global/compat"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

type PebbleDB struct {
	db     *pebble.DB
	config *config.Config
}

func (p *PebbleDB) DB() *pebble.DB {
	return p.db
}

// pebbleMigrations contains ordered migration steps. New migrations append to
// the end.
var pebbleMigrations = []func(*pebble.Batch, *pebble.DB, *config.Config) error{
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
	migration_2_1_0_1817,
	migration_2_1_0_1818,
	migration_2_1_0_1819,
	migration_2_1_0_1820,
	migration_2_1_0_1821,
	migration_2_1_0_1822,
	migration_2_1_0_1823,
	migration_2_1_0_1824,
	migration_2_1_0_22,
}

func NewPebbleDB(
	logger *zap.Logger,
	cfg *config.Config,
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

	if cfg.DB.InMemoryDONOTUSE {
		opts.FS = vfs.NewMem()
	}

	path := cfg.DB.Path
	if coreId > 0 && len(cfg.DB.WorkerPaths) > int(coreId-1) {
		path = cfg.DB.WorkerPaths[coreId-1]
	} else if coreId > 0 {
		path = fmt.Sprintf(cfg.DB.WorkerPathPrefix, coreId)
	}

	storeType := "store"
	if coreId > 0 {
		storeType = "worker store"
	}

	if _, err := os.Stat(path); os.IsNotExist(err) && !cfg.DB.InMemoryDONOTUSE {
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
	if err != nil && shouldAttemptLegacyOpen(err, cfg.DB.InMemoryDONOTUSE) {
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

	pebbleDB := &PebbleDB{db, cfg}
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
	if p.config.DB.InMemoryDONOTUSE {
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
		if err := pebbleMigrations[i](batch, p.db, p.config); err != nil {
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
func migration_2_1_0_4(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
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

func migration_2_1_0_5(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	// We just re-run it again
	return migration_2_1_0_4(b, db, cfg)
}

func migration_2_1_0_8(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_81(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_10(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	// these migration entries exist solely to advance migration number so all
	// nodes are consistent
	return nil
}

func migration_2_1_0_11(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_14(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_141(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_142(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_143(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_144(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_145(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_146(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_147(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_148(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_14(b, db, cfg)
}

func migration_2_1_0_149(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1410(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_149(b, db, cfg)
}

func migration_2_1_0_1411(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_149(b, db, cfg)
}

func migration_2_1_0_15(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_151(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_152(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_153(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_154(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_155(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_156(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_157(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_158(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_159(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return migration_2_1_0_15(b, db, cfg)
}

func migration_2_1_0_17(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_171(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_172(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_173(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_18(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_181(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_182(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_183(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_184(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_185(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_186(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_187(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_188(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_189(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1810(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1811(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1812(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1813(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1814(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1815(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1816(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1817(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1818(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

// doMigration1818 performs the actual migration work for migration_2_1_0_1818.
// It uses the sync protocol to repair corrupted tree data by syncing to an
// in-memory instance and back.
func doMigration1818(db *pebble.DB, cfg *config.Config) error {
	logger := zap.L()

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

	prover := bls48581.NewKZGInclusionProver(logger)

	// Create hypergraph from actual DB
	actualDBWrapper := &PebbleDB{db: db}
	actualStore := NewPebbleHypergraphStore(cfg.DB, actualDBWrapper, logger, nil, prover)

	actualHG, err := actualStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "load actual hypergraph")
	}
	actualHGCRDT := actualHG.(*hgcrdt.HypergraphCRDT)

	// Create in-memory pebble DB directly (bypassing NewPebbleDB to avoid cycle)
	memOpts := &pebble.Options{
		MemTableSize:       64 << 20,
		FormatMajorVersion: pebble.FormatNewest,
		FS:                 vfs.NewMem(),
	}
	memDB, err := pebble.Open("", memOpts)
	if err != nil {
		return errors.Wrap(err, "open in-memory pebble")
	}
	defer memDB.Close()

	memDBWrapper := &PebbleDB{db: memDB}
	memStore := NewPebbleHypergraphStore(cfg.DB, memDBWrapper, logger, nil, prover)
	memHG, err := memStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "load in-memory hypergraph")
	}
	memHGCRDT := memHG.(*hgcrdt.HypergraphCRDT)

	// Phase 1: Sync from actual DB to in-memory
	// Get the current root from actual DB
	actualRoot := actualHGCRDT.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, false)
	if actualRoot == nil {
		logger.Info("migration 1818: no data in global prover shard, skipping")
		return nil
	}

	// Publish snapshot on actual hypergraph
	actualHGCRDT.PublishSnapshot(actualRoot)

	// Set up gRPC server backed by actual hypergraph
	const bufSize = 1 << 20
	actualLis := bufconn.Listen(bufSize)
	actualGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(actualGRPCServer, actualHGCRDT)
	go func() { _ = actualGRPCServer.Serve(actualLis) }()
	defer actualGRPCServer.Stop()

	// Create client connection to actual hypergraph server
	actualDialer := func(context.Context, string) (net.Conn, error) {
		return actualLis.Dial()
	}
	actualConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(actualDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	if err != nil {
		return errors.Wrap(err, "dial actual hypergraph")
	}
	defer actualConn.Close()

	actualClient := protobufs.NewHypergraphComparisonServiceClient(actualConn)

	// Sync from actual to in-memory for all phases
	phases := []protobufs.HypergraphPhaseSet{
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
	}

	for _, phase := range phases {
		stream, err := actualClient.PerformSync(context.Background())
		if err != nil {
			return errors.Wrapf(err, "create sync stream for phase %v", phase)
		}
		_, err = memHGCRDT.SyncFrom(stream, globalShardKey, phase, nil)
		if err != nil {
			logger.Warn("sync from actual to memory failed", zap.Error(err), zap.Any("phase", phase))
		}
		_ = stream.CloseSend()
	}

	// Commit in-memory to get root
	memRoot := memHGCRDT.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, false)
	logger.Info("migration 1818: synced to in-memory",
		zap.String("actual_root", hex.EncodeToString(actualRoot)),
		zap.String("mem_root", hex.EncodeToString(memRoot)),
	)

	// Stop the actual server before wiping data
	actualGRPCServer.Stop()
	actualConn.Close()

	// Phase 2: Wipe tree data for global prover shard from actual DB
	treePrefixes := []byte{
		VERTEX_ADDS_TREE_NODE,
		VERTEX_REMOVES_TREE_NODE,
		HYPEREDGE_ADDS_TREE_NODE,
		HYPEREDGE_REMOVES_TREE_NODE,
		VERTEX_ADDS_TREE_NODE_BY_PATH,
		VERTEX_REMOVES_TREE_NODE_BY_PATH,
		HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		VERTEX_ADDS_CHANGE_RECORD,
		VERTEX_REMOVES_CHANGE_RECORD,
		HYPEREDGE_ADDS_CHANGE_RECORD,
		HYPEREDGE_REMOVES_CHANGE_RECORD,
		VERTEX_ADDS_TREE_ROOT,
		VERTEX_REMOVES_TREE_ROOT,
		HYPEREDGE_ADDS_TREE_ROOT,
		HYPEREDGE_REMOVES_TREE_ROOT,
	}

	for _, prefix := range treePrefixes {
		start, end := shardRangeBounds(prefix, globalShardKey)
		if err := db.DeleteRange(start, end, &pebble.WriteOptions{Sync: true}); err != nil {
			return errors.Wrapf(err, "delete range for prefix 0x%02x", prefix)
		}
	}

	logger.Info("migration 1818: wiped tree data from actual DB")

	// Reload actual hypergraph after wipe
	actualStore2 := NewPebbleHypergraphStore(cfg.DB, actualDBWrapper, logger, nil, prover)
	actualHG2, err := actualStore2.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "reload actual hypergraph after wipe")
	}
	actualHGCRDT2 := actualHG2.(*hgcrdt.HypergraphCRDT)

	// Phase 3: Sync from in-memory back to actual DB
	// Publish snapshot on in-memory hypergraph
	memHGCRDT.PublishSnapshot(memRoot)

	// Set up gRPC server backed by in-memory hypergraph
	memLis := bufconn.Listen(bufSize)
	memGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(memGRPCServer, memHGCRDT)
	go func() { _ = memGRPCServer.Serve(memLis) }()
	defer memGRPCServer.Stop()

	// Create client connection to in-memory hypergraph server
	memDialer := func(context.Context, string) (net.Conn, error) {
		return memLis.Dial()
	}
	memConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(memDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	if err != nil {
		return errors.Wrap(err, "dial in-memory hypergraph")
	}
	defer memConn.Close()

	memClient := protobufs.NewHypergraphComparisonServiceClient(memConn)

	// Sync from in-memory to actual for all phases
	for _, phase := range phases {
		stream, err := memClient.PerformSync(context.Background())
		if err != nil {
			return errors.Wrapf(err, "create sync stream for phase %v (reverse)", phase)
		}
		_, err = actualHGCRDT2.SyncFrom(stream, globalShardKey, phase, nil)
		if err != nil {
			logger.Warn("sync from memory to actual failed", zap.Error(err), zap.Any("phase", phase))
		}
		_ = stream.CloseSend()
	}

	// Final commit
	finalRoot := actualHGCRDT2.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, true)
	logger.Info("migration 1818: completed",
		zap.String("final_root", hex.EncodeToString(finalRoot)),
	)

	return nil
}

func migration_2_1_0_1819(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1820(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

func migration_2_1_0_1821(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return nil
}

// doMigration1821 performs the actual work for migration_2_1_0_1821.
func doMigration1821(db *pebble.DB, cfg *config.Config) error {
	logger := zap.L()

	// Global intrinsic address: 32 bytes of 0xff
	globalIntrinsicAddress := [32]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	prover := bls48581.NewKZGInclusionProver(logger)

	// Create hypergraph from actual DB
	dbWrapper := &PebbleDB{db: db}
	hgStore := NewPebbleHypergraphStore(cfg.DB, dbWrapper, logger, nil, prover)

	hg, err := hgStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "load hypergraph")
	}
	hgCRDT := hg.(*hgcrdt.HypergraphCRDT)

	// Get shard key for the global intrinsic domain
	// L1 is computed from bloom filter indices of the domain
	globalShardKey := tries.ShardKey{
		L1: [3]byte(up2p.GetBloomFilterIndices(globalIntrinsicAddress[:], 256, 3)),
		L2: globalIntrinsicAddress,
	}

	// Create a transaction for the deletions
	txn, err := hgStore.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "create transaction")
	}

	// Get the vertex data iterator for the global intrinsic domain
	iter := hgCRDT.GetVertexDataIterator(globalIntrinsicAddress)
	defer iter.Close()

	deletedCount := 0
	totalCount := 0

	for valid := iter.First(); valid; valid = iter.Next() {
		totalCount++

		tree := iter.Value()
		if tree == nil {
			continue
		}

		// Check if this is an empty tree (spent merge marker)
		// Spent markers have Root == nil or GetSize() == 0
		if tree.Root == nil || tree.GetSize().Sign() == 0 {
			// This is a spent marker - delete it
			// The Key() returns the full 64-byte vertex ID (domain + address)
			key := iter.Key()
			if len(key) < 64 {
				continue
			}

			var vertexID [64]byte
			copy(vertexID[:], key[:64])

			if err := hgCRDT.DeleteVertexAdd(txn, globalShardKey, vertexID); err != nil {
				logger.Warn("failed to delete spent marker",
					zap.String("vertex_id", hex.EncodeToString(vertexID[:])),
					zap.Error(err),
				)
				continue
			}

			deletedCount++

			// Log progress every 1000 deletions
			if deletedCount%1000 == 0 {
				logger.Info("migration 1821: progress",
					zap.Int("deleted", deletedCount),
					zap.Int("examined", totalCount),
				)
			}
		}
	}

	// Commit the transaction
	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "commit transaction")
	}

	logger.Info("migration 1821: completed",
		zap.Int("deleted_spent_markers", deletedCount),
		zap.Int("total_examined", totalCount),
	)

	return nil
}

// migration_2_1_0_1822 rebuilds the global prover shard tree to fix potential
// corruption from transaction bypass bugs in SaveRoot and Commit.
func migration_2_1_0_1822(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return doMigration1818(db, cfg)
}

// migration_2_1_0_1823 rebuilds the global prover shard tree to fix potential
// corruption from transaction bypass bugs in SaveRoot and Commit.
func migration_2_1_0_1823(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return doMigration1818(db, cfg)
}

// migration_2_1_0_1824 rebuilds both vertex adds and hyperedge adds trees for
// the global prover shard to fix divergence from the materialize/commit race.
func migration_2_1_0_1824(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	return doMigration1824(db, cfg)
}

// doMigration1824 rebuilds the global prover shard's vertex adds and hyperedge
// adds trees by syncing to an in-memory instance and back. Unlike doMigration1818
// which only checked vertex adds, this migration ensures both trees are rebuilt.
func doMigration1824(db *pebble.DB, cfg *config.Config) error {
	logger := zap.L()

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

	prover := bls48581.NewKZGInclusionProver(logger)

	// Create hypergraph from actual DB
	actualDBWrapper := &PebbleDB{db: db}
	actualStore := NewPebbleHypergraphStore(cfg.DB, actualDBWrapper, logger, nil, prover)

	actualHG, err := actualStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "load actual hypergraph")
	}
	actualHGCRDT := actualHG.(*hgcrdt.HypergraphCRDT)

	// Create in-memory pebble DB directly (bypassing NewPebbleDB to avoid cycle)
	memOpts := &pebble.Options{
		MemTableSize:       64 << 20,
		FormatMajorVersion: pebble.FormatNewest,
		FS:                 vfs.NewMem(),
	}
	memDB, err := pebble.Open("", memOpts)
	if err != nil {
		return errors.Wrap(err, "open in-memory pebble")
	}
	defer memDB.Close()

	memDBWrapper := &PebbleDB{db: memDB}
	memStore := NewPebbleHypergraphStore(cfg.DB, memDBWrapper, logger, nil, prover)
	memHG, err := memStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "load in-memory hypergraph")
	}
	memHGCRDT := memHG.(*hgcrdt.HypergraphCRDT)

	// Phase 1: Sync from actual DB to in-memory
	// Check both vertex adds and hyperedge adds roots
	actualVertexRoot := actualHGCRDT.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, false)
	actualHyperedgeRoot := actualHGCRDT.GetHyperedgeAddsSet(globalShardKey).GetTree().Commit(nil, false)

	if actualVertexRoot == nil && actualHyperedgeRoot == nil {
		logger.Info("migration 1824: no data in global prover shard, skipping")
		return nil
	}

	// Use whichever root is available for the snapshot
	snapshotRoot := actualVertexRoot
	if snapshotRoot == nil {
		snapshotRoot = actualHyperedgeRoot
	}
	actualHGCRDT.PublishSnapshot(snapshotRoot)

	// Set up gRPC server backed by actual hypergraph
	const bufSize = 1 << 20
	actualLis := bufconn.Listen(bufSize)
	actualGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(actualGRPCServer, actualHGCRDT)
	go func() { _ = actualGRPCServer.Serve(actualLis) }()
	defer actualGRPCServer.Stop()

	// Create client connection to actual hypergraph server
	actualDialer := func(context.Context, string) (net.Conn, error) {
		return actualLis.Dial()
	}
	actualConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(actualDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	if err != nil {
		return errors.Wrap(err, "dial actual hypergraph")
	}
	defer actualConn.Close()

	actualClient := protobufs.NewHypergraphComparisonServiceClient(actualConn)

	// Sync from actual to in-memory for vertex adds and hyperedge adds
	phases := []protobufs.HypergraphPhaseSet{
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
	}

	for _, phase := range phases {
		stream, err := actualClient.PerformSync(context.Background())
		if err != nil {
			return errors.Wrapf(err, "create sync stream for phase %v", phase)
		}
		_, err = memHGCRDT.SyncFrom(stream, globalShardKey, phase, nil)
		if err != nil {
			logger.Warn("sync from actual to memory failed", zap.Error(err), zap.Any("phase", phase))
		}
		_ = stream.CloseSend()
	}

	// Commit in-memory to get roots
	memVertexRoot := memHGCRDT.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, false)
	memHyperedgeRoot := memHGCRDT.GetHyperedgeAddsSet(globalShardKey).GetTree().Commit(nil, false)
	logger.Info("migration 1824: synced to in-memory",
		zap.String("actual_vertex_root", hex.EncodeToString(actualVertexRoot)),
		zap.String("mem_vertex_root", hex.EncodeToString(memVertexRoot)),
		zap.String("actual_hyperedge_root", hex.EncodeToString(actualHyperedgeRoot)),
		zap.String("mem_hyperedge_root", hex.EncodeToString(memHyperedgeRoot)),
	)

	// Stop the actual server before wiping data
	actualGRPCServer.Stop()
	actualConn.Close()

	// Phase 2: Wipe tree data for global prover shard from actual DB
	// Only wipe vertex adds and hyperedge adds (not removes)
	treePrefixes := []byte{
		VERTEX_ADDS_TREE_NODE,
		VERTEX_ADDS_TREE_NODE_BY_PATH,
		VERTEX_ADDS_CHANGE_RECORD,
		VERTEX_ADDS_TREE_ROOT,
		HYPEREDGE_ADDS_TREE_NODE,
		HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		HYPEREDGE_ADDS_CHANGE_RECORD,
		HYPEREDGE_ADDS_TREE_ROOT,
	}

	for _, prefix := range treePrefixes {
		start, end := shardRangeBounds(prefix, globalShardKey)
		if err := db.DeleteRange(start, end, &pebble.WriteOptions{Sync: true}); err != nil {
			return errors.Wrapf(err, "delete range for prefix 0x%02x", prefix)
		}
	}

	logger.Info("migration 1824: wiped vertex adds and hyperedge adds tree data from actual DB")

	// Reload actual hypergraph after wipe
	actualStore2 := NewPebbleHypergraphStore(cfg.DB, actualDBWrapper, logger, nil, prover)
	actualHG2, err := actualStore2.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "reload actual hypergraph after wipe")
	}
	actualHGCRDT2 := actualHG2.(*hgcrdt.HypergraphCRDT)

	// Phase 3: Sync from in-memory back to actual DB
	memSnapshotRoot := memVertexRoot
	if memSnapshotRoot == nil {
		memSnapshotRoot = memHyperedgeRoot
	}
	memHGCRDT.PublishSnapshot(memSnapshotRoot)

	// Set up gRPC server backed by in-memory hypergraph
	memLis := bufconn.Listen(bufSize)
	memGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(memGRPCServer, memHGCRDT)
	go func() { _ = memGRPCServer.Serve(memLis) }()
	defer memGRPCServer.Stop()

	// Create client connection to in-memory hypergraph server
	memDialer := func(context.Context, string) (net.Conn, error) {
		return memLis.Dial()
	}
	memConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(memDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	if err != nil {
		return errors.Wrap(err, "dial in-memory hypergraph")
	}
	defer memConn.Close()

	memClient := protobufs.NewHypergraphComparisonServiceClient(memConn)

	// Sync from in-memory to actual for vertex adds and hyperedge adds
	for _, phase := range phases {
		stream, err := memClient.PerformSync(context.Background())
		if err != nil {
			return errors.Wrapf(err, "create sync stream for phase %v (reverse)", phase)
		}
		_, err = actualHGCRDT2.SyncFrom(stream, globalShardKey, phase, nil)
		if err != nil {
			logger.Warn("sync from memory to actual failed", zap.Error(err), zap.Any("phase", phase))
		}
		_ = stream.CloseSend()
	}

	// Final commit
	finalVertexRoot := actualHGCRDT2.GetVertexAddsSet(globalShardKey).GetTree().Commit(nil, true)
	finalHyperedgeRoot := actualHGCRDT2.GetHyperedgeAddsSet(globalShardKey).GetTree().Commit(nil, true)
	logger.Info("migration 1824: completed",
		zap.String("final_vertex_root", hex.EncodeToString(finalVertexRoot)),
		zap.String("final_hyperedge_root", hex.EncodeToString(finalHyperedgeRoot)),
	)

	return nil
}

// migration_2_1_0_22 repairs provers that were incorrectly evicted by the buggy
// EvictInactiveProvers code that didn't exempt global provers or halt periods.
// For global provers (empty ConfirmationFilter): resets Status, KickFrameNumber,
// Seniority, and LastActiveFrameNumber to genesis values.
// For non-global kicked provers: removes the prover and allocation records.
func migration_2_1_0_22(b *pebble.Batch, db *pebble.DB, cfg *config.Config) error {
	if cfg == nil || cfg.P2P == nil || cfg.P2P.Network != 0 {
		return nil
	}
	return doMigration22(db, cfg)
}

// globalRDFSchema is inlined here because importing globalintrinsics would
// create an import cycle through test files.
const globalRDFSchema = `BASE <https://types.quilibrium.com/schema-repository/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX qcl: <https://types.quilibrium.com/qcl/>
PREFIX prover: <https://types.quilibrium.com/schema-repository/global/prover/>
PREFIX allocation: <https://types.quilibrium.com/schema-repository/global/allocation/>
PREFIX reward: <https://types.quilibrium.com/schema-repository/global/reward/>

prover:Prover a rdfs:Class.
prover:PublicKey a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 585;
  qcl:order 0;
  rdfs:range prover:Prover.
prover:Status a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 1;
  rdfs:range prover:Prover.
prover:AvailableStorage a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 2;
  rdfs:range prover:Prover.
prover:Seniority a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 3;
  rdfs:range prover:Prover.
prover:KickFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 4;
  rdfs:range prover:Prover.

allocation:ProverAllocation a rdfs:Class.
allocation:Prover a rdfs:Property;
  rdfs:domain prover:Prover;
  qcl:order 0;
  rdfs:range allocation:ProverAllocation.
allocation:Status a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 1;
  qcl:order 1;
  rdfs:range allocation:ProverAllocation.
allocation:ConfirmationFilter a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 2;
  rdfs:range allocation:ProverAllocation.
allocation:RejectionFilter a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 64;
  qcl:order 3;
  rdfs:range allocation:ProverAllocation.
allocation:JoinFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 4;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 5;
  rdfs:range allocation:ProverAllocation.
allocation:PauseFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 6;
  rdfs:range allocation:ProverAllocation.
allocation:ResumeFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 7;
  rdfs:range allocation:ProverAllocation.
allocation:KickFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 8;
  rdfs:range allocation:ProverAllocation.
allocation:JoinConfirmFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 9;
  rdfs:range allocation:ProverAllocation.
allocation:JoinRejectFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 10;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveConfirmFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 11;
  rdfs:range allocation:ProverAllocation.
allocation:LeaveRejectFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 12;
  rdfs:range allocation:ProverAllocation.
allocation:LastActiveFrameNumber a rdfs:Property;
  rdfs:domain qcl:Uint;
  qcl:size 8;
  qcl:order 13;
  rdfs:range allocation:ProverAllocation.

reward:ProverReward a rdfs:Class.
reward:DelegateAddress a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 0;
  rdfs:range reward:ProverReward.
reward:Balance a rdfs:Property;
  rdfs:domain qcl:ByteArray;
  qcl:size 32;
  qcl:order 1;
  rdfs:range reward:ProverReward.
`

func doMigration22(db *pebble.DB, cfg *config.Config) error {
	logger := zap.L()
	logger.Info("migration 22: repairing incorrectly evicted provers")

	globalIntrinsicAddress := intrinsics.GLOBAL_INTRINSIC_ADDRESS

	prover := bls48581.NewKZGInclusionProver(logger)
	rdfMultiprover := schema.NewRDFMultiprover(
		&schema.TurtleRDFParser{},
		prover,
	)

	dbWrapper := &PebbleDB{db: db}
	hgStore := NewPebbleHypergraphStore(cfg.DB, dbWrapper, logger, nil, prover)
	hg, err := hgStore.LoadHypergraph(nil, 0)
	if err != nil {
		return errors.Wrap(err, "migration 22: load hypergraph")
	}
	hgCRDT := hg.(*hgcrdt.HypergraphCRDT)

	globalShardKey := tries.ShardKey{
		L1: [3]byte(up2p.GetBloomFilterIndices(globalIntrinsicAddress[:], 256, 3)),
		L2: globalIntrinsicAddress,
	}

	// Compute genesis seniority: all genesis provers share the beacon's
	// aggregated seniority value.
	if err := compat.RebuildPeerSeniority(0); err != nil {
		return errors.Wrap(err, "migration 22: rebuild peer seniority")
	}

	// Beacon Ed448 key from mainnet_genesis.json
	beaconEd448Key, err := base64.StdEncoding.DecodeString(
		"ImqaBAzHM61pHODoywHu2a6FIOqoXKY/RECZuOXjDfds8DBxtA0g+4hCfOgwiti2TpOF8AH7xH0A",
	)
	if err != nil {
		return errors.Wrap(err, "migration 22: decode beacon ed448 key")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(beaconEd448Key)
	if err != nil {
		return errors.Wrap(err, "migration 22: unmarshal beacon ed448 key")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return errors.Wrap(err, "migration 22: derive peer id")
	}

	genesisSeniority := compat.GetAggregatedSeniority([]string{peerId.String()})
	seniorityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seniorityBytes, genesisSeniority.Uint64())
	logger.Info("migration 22: computed genesis seniority",
		zap.Uint64("seniority", genesisSeniority.Uint64()),
	)

	// Phase 1: Iterate all vertices and identify kicked provers/allocations.
	// Collect everything first, then close the iterator before making
	// modifications to avoid Pebble iterator invalidation.
	type kickedProverInfo struct {
		vertexID [64]byte
		tree     *tries.VectorCommitmentTree
	}

	type kickedAllocInfo struct {
		vertexID           [64]byte
		tree               *tries.VectorCommitmentTree
		proverRef          []byte
		confirmationFilter []byte
	}

	kickedProvers := map[string]*kickedProverInfo{}
	kickedAllocs := map[string]*kickedAllocInfo{}

	iter := hgCRDT.GetVertexDataIterator(globalIntrinsicAddress)

	for valid := iter.First(); valid; valid = iter.Next() {
		tree := iter.Value()
		if tree == nil || tree.Root == nil || tree.GetSize().Sign() == 0 {
			continue
		}

		key := iter.Key()
		if len(key) < 64 {
			continue
		}

		var vertexID [64]byte
		copy(vertexID[:], key[:64])
		vertexAddr := string(key[32:64])

		// Try as prover:Prover
		statusBytes, err := rdfMultiprover.Get(
			globalRDFSchema,
			"prover:Prover",
			"Status",
			tree,
		)
		if err == nil && len(statusBytes) > 0 && statusBytes[0] == 4 {
			kickedProvers[vertexAddr] = &kickedProverInfo{
				vertexID: vertexID,
				tree:     tree,
			}
			continue
		}

		// Try as allocation:ProverAllocation
		allocStatus, err := rdfMultiprover.Get(
			globalRDFSchema,
			"allocation:ProverAllocation",
			"Status",
			tree,
		)
		if err == nil && len(allocStatus) > 0 && allocStatus[0] == 4 {
			proverRef, _ := rdfMultiprover.Get(
				globalRDFSchema,
				"allocation:ProverAllocation",
				"Prover",
				tree,
			)
			confirmFilter, _ := rdfMultiprover.Get(
				globalRDFSchema,
				"allocation:ProverAllocation",
				"ConfirmationFilter",
				tree,
			)
			kickedAllocs[vertexAddr] = &kickedAllocInfo{
				vertexID:           vertexID,
				tree:               tree,
				proverRef:          proverRef,
				confirmationFilter: confirmFilter,
			}
		}
	}

	iter.Close()

	logger.Info("migration 22: scan complete",
		zap.Int("kicked_provers", len(kickedProvers)),
		zap.Int("kicked_allocations", len(kickedAllocs)),
	)

	if len(kickedProvers) == 0 && len(kickedAllocs) == 0 {
		logger.Info("migration 22: no kicked provers found, nothing to do")
		return nil
	}

	// Phase 2: Classify provers as global vs non-global based on their
	// allocations' ConfirmationFilter.
	emptyFilter := make([]byte, 64)
	globalProverAddrs := map[string]bool{}

	for _, alloc := range kickedAllocs {
		if len(alloc.confirmationFilter) == 0 ||
			bytes.Equal(alloc.confirmationFilter, emptyFilter) {
			globalProverAddrs[string(alloc.proverRef)] = true
		}
	}

	// Phase 3: Apply repairs.
	txn, err := hgStore.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "migration 22: create transaction")
	}

	zeroBytes := make([]byte, 8) // frame number 0

	// 3a: Reset global provers to genesis state.
	resetCount := 0
	for addr, p := range kickedProvers {
		if !globalProverAddrs[addr] {
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"prover:Prover",
			"Status",
			[]byte{1}, // Active
			p.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset prover status", zap.Error(err))
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"prover:Prover",
			"KickFrameNumber",
			zeroBytes,
			p.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset prover kick frame", zap.Error(err))
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"prover:Prover",
			"Seniority",
			seniorityBytes,
			p.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset prover seniority", zap.Error(err))
			continue
		}

		// Save modified vertex data
		if err := hgCRDT.SetVertexData(txn, p.vertexID, p.tree); err != nil {
			logger.Warn("migration 22: failed to save prover vertex data", zap.Error(err))
			continue
		}

		// Update the atom in the adds tree with recomputed commitment
		newCommitment := p.tree.Commit(prover, false)
		vertex := hgcrdt.NewVertex(
			globalIntrinsicAddress,
			[32]byte(p.vertexID[32:]),
			newCommitment,
			p.tree.GetSize(),
		)
		if err := hgCRDT.AddVertex(txn, vertex); err != nil {
			logger.Warn("migration 22: failed to update prover atom", zap.Error(err))
			continue
		}

		resetCount++
		logger.Info("migration 22: reset global prover",
			zap.String("address", hex.EncodeToString(p.vertexID[32:])),
		)
	}

	// Reset global prover allocations.
	allocResetCount := 0
	for _, alloc := range kickedAllocs {
		if !globalProverAddrs[string(alloc.proverRef)] {
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"allocation:ProverAllocation",
			"Status",
			[]byte{1}, // Active
			alloc.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset allocation status", zap.Error(err))
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"allocation:ProverAllocation",
			"KickFrameNumber",
			zeroBytes,
			alloc.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset allocation kick frame", zap.Error(err))
			continue
		}

		if err := rdfMultiprover.Set(
			globalRDFSchema,
			globalIntrinsicAddress[:],
			"allocation:ProverAllocation",
			"LastActiveFrameNumber",
			zeroBytes,
			alloc.tree,
		); err != nil {
			logger.Warn("migration 22: failed to reset allocation last active frame", zap.Error(err))
			continue
		}

		if err := hgCRDT.SetVertexData(txn, alloc.vertexID, alloc.tree); err != nil {
			logger.Warn("migration 22: failed to save allocation vertex data", zap.Error(err))
			continue
		}

		newCommitment := alloc.tree.Commit(prover, false)
		vertex := hgcrdt.NewVertex(
			globalIntrinsicAddress,
			[32]byte(alloc.vertexID[32:]),
			newCommitment,
			alloc.tree.GetSize(),
		)
		if err := hgCRDT.AddVertex(txn, vertex); err != nil {
			logger.Warn("migration 22: failed to update allocation atom", zap.Error(err))
			continue
		}

		allocResetCount++
		logger.Info("migration 22: reset global prover allocation",
			zap.String("address", hex.EncodeToString(alloc.vertexID[32:])),
		)
	}

	// 3b: Delete non-global kicked provers and their allocations.
	deleteCount := 0
	for addr, p := range kickedProvers {
		if globalProverAddrs[addr] {
			continue
		}

		if err := hgCRDT.DeleteVertexAdd(txn, globalShardKey, p.vertexID); err != nil {
			logger.Warn("migration 22: failed to delete prover vertex",
				zap.String("address", hex.EncodeToString(p.vertexID[32:])),
				zap.Error(err),
			)
		} else {
			deleteCount++
			logger.Info("migration 22: deleted non-global prover",
				zap.String("address", hex.EncodeToString(p.vertexID[32:])),
			)
		}
	}

	allocDeleteCount := 0
	for _, alloc := range kickedAllocs {
		if globalProverAddrs[string(alloc.proverRef)] {
			continue
		}

		if err := hgCRDT.DeleteVertexAdd(txn, globalShardKey, alloc.vertexID); err != nil {
			logger.Warn("migration 22: failed to delete allocation vertex",
				zap.String("address", hex.EncodeToString(alloc.vertexID[32:])),
				zap.Error(err),
			)
		} else {
			allocDeleteCount++
		}
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "migration 22: commit transaction")
	}

	logger.Info("migration 22: completed",
		zap.Int("global_provers_reset", resetCount),
		zap.Int("global_allocs_reset", allocResetCount),
		zap.Int("non_global_provers_deleted", deleteCount),
		zap.Int("non_global_allocs_deleted", allocDeleteCount),
	)

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
