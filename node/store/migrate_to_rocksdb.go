//go:build rocksdb

package store

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/linxGnu/grocksdb"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// MigrateToRocksDB performs an in-place migration from a Pebble
// database to a RocksDB database. Opens Pebble read-only, iterates
// all entries, and writes them directly to RocksDB.
//
// Requires no extra disk space beyond the new RocksDB directory
// (which grows as data is written). After migration, the old Pebble
// directory can be deleted.
//
// For a 775GB database, expect ~2-4 hours depending on disk speed.
func MigrateToRocksDB(pebblePath string, rocksdbPath string) error {
	fmt.Printf("=== Pebble → RocksDB Migration ===\n")
	fmt.Printf("source (pebble): %s\n", pebblePath)
	fmt.Printf("target (rocksdb): %s\n", rocksdbPath)

	// Verify paths
	if _, err := os.Stat(pebblePath); os.IsNotExist(err) {
		return fmt.Errorf("pebble database does not exist: %s", pebblePath)
	}
	if pebblePath == rocksdbPath {
		return fmt.Errorf("source and target paths must be different")
	}

	// Open Pebble read-only
	fmt.Println("opening pebble database (read-only)...")
	pebbleOpts := &pebble.Options{
		ReadOnly:           true,
		FormatMajorVersion: pebble.FormatNewest,
	}
	pdb, err := pebble.Open(pebblePath, pebbleOpts)
	if err != nil {
		return errors.Wrap(err, "open pebble database")
	}
	defer pdb.Close()
	fmt.Println("pebble opened successfully")

	// Create RocksDB target directory
	if err := os.MkdirAll(rocksdbPath, 0755); err != nil {
		return errors.Wrap(err, "create rocksdb directory")
	}

	// Open RocksDB with settings matching the Rust node
	fmt.Println("opening rocksdb database...")
	rdb, err := openRocksDB(rocksdbPath)
	if err != nil {
		return errors.Wrap(err, "open rocksdb database")
	}
	defer rdb.Close()
	fmt.Println("rocksdb opened successfully")

	// Iterate Pebble and write to RocksDB in batches
	fmt.Println("starting migration...")
	startTime := time.Now()

	iter, err := pdb.NewIter(nil)
	if err != nil {
		return errors.Wrap(err, "create pebble iterator")
	}
	defer iter.Close()

	const batchSize = 10000
	wo := grocksdb.NewDefaultWriteOptions()
	wo.SetSync(false) // Don't sync each batch — we'll sync at the end
	defer wo.Destroy()

	batch := grocksdb.NewWriteBatch()
	defer batch.Destroy()

	var (
		entryCount  uint64
		totalBytes  uint64
		batchCount  int
		lastReport  time.Time
	)

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		val, err := iter.ValueAndErr()
		if err != nil {
			return errors.Wrapf(err, "read value at entry %d", entryCount)
		}

		// Translate values that Go stores in canonical bytes but Rust
		// expects as protobuf. Identified by key prefix:
		// - 0x00 0x0B = QuorumCertificate (canonical → proto)
		// - 0x00 0x0C = TimeoutCertificate (canonical → proto)
		// - 0x00 0x0D = ProposalVote (canonical → proto)
		// - 0x00 0x0E = TimeoutVote (canonical → proto)
		// - 0x00 0x06 = PeerSeniority (gob → JSON)
		outVal := val
		if len(key) >= 2 && key[0] == CLOCK_FRAME {
			switch key[1] {
			case CLOCK_QUORUM_CERTIFICATE,
				CLOCK_TIMEOUT_CERTIFICATE:
				// Canonical bytes → protobuf. These types have
				// ToCanonicalBytes/FromCanonicalBytes in Go. We
				// decode from canonical, re-encode as proto.
				translated, translateErr := translateQCCanonicalToProto(val)
				if translateErr == nil {
					outVal = translated
				}
			case CLOCK_PROPOSAL_VOTE:
				translated, translateErr := translateVoteCanonicalToProto(val)
				if translateErr == nil {
					outVal = translated
				}
			case CLOCK_TIMEOUT_VOTE:
				translated, translateErr := translateTimeoutVoteCanonicalToProto(val)
				if translateErr == nil {
					outVal = translated
				}
			case CLOCK_SHARD_FRAME_SENIORITY_SHARD:
				translated, translateErr := translateSeniorityGobToJSON(val)
				if translateErr == nil {
					outVal = translated
				}
			}
		}

		batch.Put(key, outVal)
		batchCount++
		totalBytes += uint64(len(key) + len(val))

		if batchCount >= batchSize {
			if err := rdb.Write(wo, batch); err != nil {
				return errors.Wrapf(err, "write batch at entry %d", entryCount)
			}
			entryCount += uint64(batchCount)
			batch.Clear()
			batchCount = 0

			// Progress report every 5 seconds
			if time.Since(lastReport) > 5*time.Second {
				elapsed := time.Since(startTime)
				rate := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
				fmt.Printf(
					"  %d entries, %s data, %.1f MB/s, %s elapsed\n",
					entryCount, formatBytes(totalBytes), rate,
					elapsed.Round(time.Second),
				)
				lastReport = time.Now()
			}
		}
	}

	if err := iter.Error(); err != nil {
		return errors.Wrap(err, "pebble iterator error")
	}

	// Flush remaining
	if batchCount > 0 {
		if err := rdb.Write(wo, batch); err != nil {
			return errors.Wrap(err, "write final batch")
		}
		entryCount += uint64(batchCount)
	}

	elapsed := time.Since(startTime)
	fmt.Printf(
		"\nmigration complete: %d entries, %s data, %s elapsed\n",
		entryCount, formatBytes(totalBytes),
		elapsed.Round(time.Second),
	)

	// Compact the RocksDB database
	fmt.Println("compacting rocksdb (this may take a while for large databases)...")
	compactStart := time.Now()
	rdb.CompactRange(grocksdb.Range{Start: nil, Limit: nil})
	fmt.Printf("compaction complete in %s\n", time.Since(compactStart).Round(time.Second))

	// Final sync
	woSync := grocksdb.NewDefaultWriteOptions()
	woSync.SetSync(true)
	emptyBatch := grocksdb.NewWriteBatch()
	rdb.Write(woSync, emptyBatch)
	emptyBatch.Destroy()
	woSync.Destroy()

	fmt.Printf("\n=== Migration Successful ===\n")
	fmt.Printf("You can now:\n")
	fmt.Printf("  1. Update your config to point db.path to: %s\n", rocksdbPath)
	fmt.Printf("  2. Start the Rust node: quil-node --config <config-dir>\n")
	fmt.Printf("  3. After verifying, delete the old Pebble directory: %s\n", pebblePath)

	return nil
}

// MigrateToRocksDBFromConfig resolves paths from config and migrates.
func MigrateToRocksDBFromConfig(cfg *config.Config, rocksdbPath string) error {
	pebblePath := cfg.DB.Path
	if pebblePath == "" {
		return fmt.Errorf("no database path in config")
	}
	return MigrateToRocksDB(pebblePath, rocksdbPath)
}

// openRocksDB opens a RocksDB database with settings matching the
// Rust node's configuration (quil-store/src/rocksdb_store.rs).
func openRocksDB(path string) (*grocksdb.DB, error) {
	bbto := grocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetBlockCache(grocksdb.NewLRUCache(256 << 20)) // 256MB block cache

	opts := grocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)
	opts.SetWriteBufferSize(64 << 20)               // 64MB memtable (matches Rust)
	opts.SetMaxOpenFiles(1000)                        // matches Rust
	opts.SetLevel0FileNumCompactionTrigger(8)         // matches Rust
	opts.SetLevel0SlowdownWritesTrigger(16)           // matches Rust
	opts.SetLevel0StopWritesTrigger(32)               // matches Rust
	opts.SetCompression(grocksdb.SnappyCompression)   // matches Rust (snappy feature)
	opts.SetBlockBasedTableFactory(bbto)

	// For bulk import: increase parallelism and disable WAL
	opts.IncreaseParallelism(4)
	opts.SetMaxBackgroundJobs(4)

	db, err := grocksdb.OpenDb(opts, path)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// translateQCCanonicalToProto decodes a QuorumCertificate from Go's
// canonical bytes format and re-encodes as protobuf for Rust.
func translateQCCanonicalToProto(canonicalBytes []byte) ([]byte, error) {
	qc := &protobufs.QuorumCertificate{}
	if err := qc.FromCanonicalBytes(canonicalBytes); err != nil {
		return nil, err
	}
	return proto.Marshal(qc)
}

// translateVoteCanonicalToProto decodes a ProposalVote from Go's
// canonical bytes format and re-encodes as protobuf for Rust.
func translateVoteCanonicalToProto(canonicalBytes []byte) ([]byte, error) {
	vote := &protobufs.ProposalVote{}
	if err := vote.FromCanonicalBytes(canonicalBytes); err != nil {
		return nil, err
	}
	return proto.Marshal(vote)
}

// translateTimeoutVoteCanonicalToProto decodes a TimeoutState from Go's
// canonical bytes format and re-encodes as protobuf for Rust.
func translateTimeoutVoteCanonicalToProto(canonicalBytes []byte) ([]byte, error) {
	ts := &protobufs.TimeoutState{}
	if err := ts.FromCanonicalBytes(canonicalBytes); err != nil {
		return nil, err
	}
	return proto.Marshal(ts)
}

// translateSeniorityGobToJSON converts Go's gob-encoded peer seniority
// map to JSON for the Rust node (which reads seniority as JSON).
func translateSeniorityGobToJSON(gobData []byte) ([]byte, error) {
	var m map[string]uint64
	buf := bytes.NewBuffer(gobData)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}
