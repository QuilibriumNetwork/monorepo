//go:build rocksdb

package store

import (
	"bytes"
	"encoding/binary"
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
	p2putil "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// Rust-side per-node tree layout (see
// `crates/quil-store/src/encoding.rs:79-114`). Tree nodes the Go node
// stored under `[HYPERGRAPH_SHARD, {0x02|0x12|0x03|0x13, ...}]` get
// rewritten here so the Rust node — which only reads these prefixes —
// finds them. Per-vertex leaf values get split out into the
// per-vertex keyspace.
const (
	rustHGTreeBlobPrefix   = 0x2F
	rustHGVertexDataPrefix = 0x30
	rustHGTreeNodeByKey    = 0x33
	rustHGTreeNodeByPath   = 0x34
	rustSetByteVertex      = 0x00
	rustSetByteHyperedge   = 0x01
	rustPhaseByteAdds      = 0x00
	rustPhaseByteRemoves   = 0x01
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
		entryCount uint64
		totalBytes uint64
		batchCount int
		lastReport time.Time
	)

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		val, err := iter.ValueAndErr()
		if err != nil {
			return errors.Wrapf(err, "read value at entry %d", entryCount)
		}

		// Vertex-data entries (`[0x09, 0xF0, id]`) carry the actual
		// vertex sub-tree (SerializeNonLazyTree) that the Rust
		// prover registry walks. Translate to Rust's per-vertex
		// keyspace at `[0x30, set, phase, l1, l2, id]`.
		if vdOps, ok := translateVertexDataKV(key, val); ok {
			for _, op := range vdOps {
				batch.Put(op.key, op.val)
				totalBytes += uint64(len(op.key) + len(op.val))
			}
			batchCount++
			if batchCount >= batchSize {
				if err := rdb.Write(wo, batch); err != nil {
					return errors.Wrapf(err, "write batch at entry %d", entryCount)
				}
				entryCount += uint64(batchCount)
				batch.Clear()
				batchCount = 0
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
			continue
		}

		// Tree-node entries get rewritten into Rust's per-node layout
		// (see `translateTreeNodeKV`). The Go-format entry is NOT
		// also copied — Rust never reads it.
		if treeOps, ok := translateTreeNodeKV(key, val); ok {
			for _, op := range treeOps {
				batch.Put(op.key, op.val)
				totalBytes += uint64(len(op.key) + len(op.val))
			}
			batchCount++
			if batchCount >= batchSize {
				if err := rdb.Write(wo, batch); err != nil {
					return errors.Wrapf(err, "write batch at entry %d", entryCount)
				}
				entryCount += uint64(batchCount)
				batch.Clear()
				batchCount = 0
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
			continue
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
			case CLOCK_QUORUM_CERTIFICATE:
				// Canonical bytes → protobuf. QuorumCertificate has its
				// own canonical type prefix; the translator validates it
				// and re-emits the proto encoding the Rust node expects.
				translated, translateErr := translateQCCanonicalToProto(val)
				if translateErr == nil {
					outVal = translated
				}
			case CLOCK_TIMEOUT_CERTIFICATE:
				// Canonical bytes → protobuf. TimeoutCertificate has a
				// different canonical type prefix from QuorumCertificate
				// and needs its own translator — passing TC bytes through
				// translateQCCanonicalToProto used to silently fail and
				// leave the value as raw canonical bytes, which the Rust
				// `get_timeout_certificate` then failed to decode.
				translated, translateErr := translateTCCanonicalToProto(val)
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
	opts.SetMaxOpenFiles(1000)                      // matches Rust
	opts.SetLevel0FileNumCompactionTrigger(8)       // matches Rust
	opts.SetLevel0SlowdownWritesTrigger(16)         // matches Rust
	opts.SetLevel0StopWritesTrigger(32)             // matches Rust
	opts.SetCompression(grocksdb.SnappyCompression) // matches Rust (snappy feature)
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

// translateTCCanonicalToProto decodes a TimeoutCertificate from Go's
// canonical bytes format and re-encodes as protobuf for Rust.
func translateTCCanonicalToProto(canonicalBytes []byte) ([]byte, error) {
	tc := &protobufs.TimeoutCertificate{}
	if err := tc.FromCanonicalBytes(canonicalBytes); err != nil {
		return nil, err
	}
	return proto.Marshal(tc)
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

// =====================================================================
// Per-node tree translation: Go pebble layout → Rust rocksdb layout.
//
// Go's tree backing store writes each radix-trie node into TWO Pebble
// indexes under the HYPERGRAPH_SHARD (0x09) prefix:
//
//   by-key:  [0x09, {0x02|0x12|0x03|0x13}, l1(3), l2(32), node_key]
//            value = [type] [pathLen + fullPrefix (branches only)]
//                    [SerializeLeafNode | SerializeBranchNode(false)]
//   by-path: [0x09, {0x22|0x32|0x23|0x33}, l1(3), l2(32), path_i32_BE]
//            value = the by-key key (a pointer)
//
// Rust's per-node lazy tree (`crates/quil-tries/src/lazy_tree.rs`)
// reads/writes a parallel layout:
//
//   by-key:  [0x33, set_byte, phase_byte, l1(3), l2(32), node_key]
//            value = serialize_node_solo(...)  — no fullPrefix prefix,
//                    leaf values stripped (they live in the per-vertex
//                    keyspace at [0x30, ...]).
//   by-path: [0x34, set_byte, phase_byte, l1(3), l2(32), path_i32_BE]
//            value = the corresponding Rust by-key key.
//
// `translateTreeNodeKV` does the rewrite for one source entry; the
// migration loop calls it instead of `batch.Put(key, val)` when the
// source key matches a tree-node prefix.
//
// For leaves, the translator also returns a separate (key, value) pair
// to write into the per-vertex keyspace — that's where the actual
// leaf payload bytes live after migration. Rust's lazy tree pulls
// them through `load_vertex_underlying_raw` when serving `get`.
// =====================================================================

// classifyTreeNodeKey returns the Rust set/phase byte pair for a
// Pebble tree-node sub-prefix and whether the entry is the by-path
// index. Returns ok=false if the sub-prefix is not a tree-node
// discriminator (so the caller can fall through to byte-faithful
// copy for other 0x09 sub-entries — shard commits, alt-shard
// indexes, etc.).
func classifyTreeNodeKey(subPrefix byte) (
	setByte byte,
	phaseByte byte,
	isByPath bool,
	ok bool,
) {
	switch subPrefix {
	case VERTEX_ADDS_TREE_NODE:
		return rustSetByteVertex, rustPhaseByteAdds, false, true
	case VERTEX_REMOVES_TREE_NODE:
		return rustSetByteVertex, rustPhaseByteRemoves, false, true
	case HYPEREDGE_ADDS_TREE_NODE:
		return rustSetByteHyperedge, rustPhaseByteAdds, false, true
	case HYPEREDGE_REMOVES_TREE_NODE:
		return rustSetByteHyperedge, rustPhaseByteRemoves, false, true
	case VERTEX_ADDS_TREE_NODE_BY_PATH:
		return rustSetByteVertex, rustPhaseByteAdds, true, true
	case VERTEX_REMOVES_TREE_NODE_BY_PATH:
		return rustSetByteVertex, rustPhaseByteRemoves, true, true
	case HYPEREDGE_ADDS_TREE_NODE_BY_PATH:
		return rustSetByteHyperedge, rustPhaseByteAdds, true, true
	case HYPEREDGE_REMOVES_TREE_NODE_BY_PATH:
		return rustSetByteHyperedge, rustPhaseByteRemoves, true, true
	}
	return 0, 0, false, false
}

// treeNodeKV is one (key, value) pair to write into RocksDB for a
// translated tree-node entry. A single source entry can produce up to
// two destination entries (e.g. by-key tree node + per-vertex leaf
// value, or by-key + by-path).
type treeNodeKV struct {
	key []byte
	val []byte
}

// translateTreeNodeKV maps a Go-format tree-node Pebble entry to its
// Rust equivalent. Returns ok=false (with nil ops) when `key` is not a
// tree-node entry — the caller should copy it byte-faithfully.
//
// On success, `ops` contains 1-2 entries to write to RocksDB. The
// caller must NOT also write the source `(key, val)` pair —
// translated tree-node entries replace their Go-format originals.
func translateTreeNodeKV(key []byte, val []byte) (ops []treeNodeKV, ok bool) {
	// Tree-node keys live under HYPERGRAPH_SHARD with one of eight
	// known sub-prefix bytes. Anything shorter than [shard, sub,
	// l1(3), l2(32)] can't be a tree-node entry.
	const minTreeNodeKeyLen = 2 + 3 + 32
	if len(key) < minTreeNodeKeyLen || key[0] != HYPERGRAPH_SHARD {
		return nil, false
	}
	setByte, phaseByte, isByPath, ok := classifyTreeNodeKey(key[1])
	if !ok {
		return nil, false
	}
	l1 := key[2:5]
	l2 := key[5:37]
	tail := key[37:]

	if isByPath {
		// By-path entry. The Pebble value is the Go by-key key
		// (`keyFn(shardKey, key)` form); we translate it to the Rust
		// by-key key shape so the Rust lazy walker can deref it.
		if len(val) < minTreeNodeKeyLen || val[0] != HYPERGRAPH_SHARD {
			return nil, false
		}
		vSetByte, vPhaseByte, vIsByPath, vOk := classifyTreeNodeKey(val[1])
		if !vOk || vIsByPath {
			// Pointer should always be a by-key key, never a by-path one.
			return nil, false
		}
		// Rewrite by-path key + value.
		dstKey := make([]byte, 0, 3+len(l1)+len(l2)+len(tail))
		dstKey = append(dstKey, rustHGTreeNodeByPath, setByte, phaseByte)
		dstKey = append(dstKey, l1...)
		dstKey = append(dstKey, l2...)
		dstKey = append(dstKey, tail...)

		dstVal := make([]byte, 0, 3+3+32+len(val[37:]))
		dstVal = append(dstVal, rustHGTreeNodeByKey, vSetByte, vPhaseByte)
		dstVal = append(dstVal, val[2:5]...)
		dstVal = append(dstVal, val[5:37]...)
		dstVal = append(dstVal, val[37:]...)
		return []treeNodeKV{{key: dstKey, val: dstVal}}, true
	}

	// By-key entry. Parse Go's per-node value format and re-emit
	// as Rust solo.
	rustVal, leafKey, leafValue, err := translateGoNodeToRustSolo(val)
	if err != nil {
		// Don't fail the migration on a single malformed entry;
		// fall back to byte-faithful copy of the original. The Rust
		// node won't read this key (it looks at [0x33, ...] only),
		// so the unconverted entry becomes a harmless orphan.
		return nil, false
	}

	dstKey := make([]byte, 0, 3+len(l1)+len(l2)+len(tail))
	dstKey = append(dstKey, rustHGTreeNodeByKey, setByte, phaseByte)
	dstKey = append(dstKey, l1...)
	dstKey = append(dstKey, l2...)
	dstKey = append(dstKey, tail...)
	ops = []treeNodeKV{{key: dstKey, val: rustVal}}

	// Note: the tree-leaf's `value` field in Go is an Atom encoding
	// (`AtomFromBytes` at `hypergraph/atom.go:14-66`), NOT the
	// vertex's sub-tree blob. The actual sub-tree (which is what the
	// Rust registry walks via `for_each_vertex_underlying`) lives at
	// `[0x09, VERTEX_DATA(0xF0), id]` and is translated separately
	// in `translateVertexDataKV`. We intentionally do NOT write the
	// atom bytes anywhere — Rust doesn't need them.
	_ = leafKey
	_ = leafValue
	return ops, true
}

// translateVertexDataKV maps Go's per-vertex sub-tree entries
// (`[HYPERGRAPH_SHARD(0x09), VERTEX_DATA(0xF0), id(64)]`, value =
// `tries.SerializeNonLazyTree(vertex_subtree)`) into Rust's
// per-vertex keyspace at `[0x30, set=0, phase=0, l1(3), l2(32), id]`.
//
// `id = appAddress(32) || dataAddress(32)`. The shard key falls out
// of `id`: `l2 = appAddress`, `l1 =
// p2p.GetBloomFilterIndices(appAddress, 256, 3)` — matching
// `types/hypergraph/addressing.go:23`.
//
// Returns ok=false when the source key isn't a vertex-data entry,
// so the caller can fall back to byte-faithful copy.
func translateVertexDataKV(key []byte, val []byte) (ops []treeNodeKV, ok bool) {
	const wantPrefixLen = 2 // HYPERGRAPH_SHARD + VERTEX_DATA
	const idLen = 64
	if len(key) != wantPrefixLen+idLen {
		return nil, false
	}
	if key[0] != HYPERGRAPH_SHARD || key[1] != VERTEX_DATA {
		return nil, false
	}
	id := key[wantPrefixLen:]
	appAddress := id[:32]
	bloom := p2putil.GetBloomFilterIndices(appAddress, 256, 3)
	if len(bloom) != 3 {
		return nil, false
	}

	dstKey := make([]byte, 0, 3+3+32+idLen)
	dstKey = append(dstKey, rustHGVertexDataPrefix, rustSetByteVertex, rustPhaseByteAdds)
	dstKey = append(dstKey, bloom...)
	dstKey = append(dstKey, appAddress...) // l2
	dstKey = append(dstKey, id...)         // vk

	// Value bytes are Go's `SerializeNonLazyTree(vertex_subtree)`,
	// which `quil_tries::deserialize_go_tree` reads directly. No
	// translation needed.
	return []treeNodeKV{{key: dstKey, val: val}}, true
}

// translateGoNodeToRustSolo parses Go's per-node Pebble value (as
// written by `PebbleHypergraphStore.InsertNode` /
// `SerializeBranchNode(false)` for branches, `SerializeLeafNode` for
// leaves) and re-emits it in Rust's `serialize_node_solo` format.
//
// Returns the Rust solo bytes plus, for leaves only, the leaf's key
// and value bytes (so the caller can write them to the per-vertex
// keyspace).
//
// Go branch on disk:
//
//	[TypeBranch (1)]
//	[pathLength u32 BE]
//	[fullPrefix i32 BE × pathLength]
//	[prefix_len u32 BE]
//	[prefix i32 BE × prefix_len]
//	[commitment_len u64 BE][commitment]
//	[size_len u64 BE][size bytes (unsigned, big.Int.Bytes())]
//	[leaf_count i64 BE]
//	[longest_branch i32 BE]
//
// Go leaf on disk:
//
//	[TypeLeaf (1)]
//	[key_len u64 BE][key]
//	[value_len u64 BE][value]
//	[hash_target_len u64 BE][hash_target]
//	[commitment_len u64 BE][commitment]
//	[size_len u64 BE][size bytes (unsigned)]
//
// Rust solo strips: (a) the [pathLength + fullPrefix] prefix on
// branches (Rust's walker computes full_prefix from descent path);
// (b) the `value` field on leaves (Rust reads via the per-vertex
// keyspace).
func translateGoNodeToRustSolo(val []byte) (
	rustBytes []byte,
	leafKey []byte,
	leafValue []byte,
	err error,
) {
	if len(val) < 1 {
		return nil, nil, nil, fmt.Errorf("empty tree-node value")
	}
	switch val[0] {
	case 1: // TypeLeaf
		buf := bytes.NewBuffer(val[1:])
		key, kerr := readLenPrefixedU64(buf)
		if kerr != nil {
			return nil, nil, nil, kerr
		}
		value, verr := readLenPrefixedU64(buf)
		if verr != nil {
			return nil, nil, nil, verr
		}
		hashTarget, herr := readLenPrefixedU64(buf)
		if herr != nil {
			return nil, nil, nil, herr
		}
		commitment, cerr := readLenPrefixedU64(buf)
		if cerr != nil {
			return nil, nil, nil, cerr
		}
		size, serr := readLenPrefixedU64(buf)
		if serr != nil {
			return nil, nil, nil, serr
		}
		// Re-emit as Rust solo: type, key, EMPTY value, hash_target,
		// commitment, size. Size needs unsigned→signed conversion
		// (Rust uses `BigInt::from_signed_bytes_be`).
		rustSize := goUnsignedToRustSignedBigInt(size)
		out := bytes.NewBuffer(make([]byte, 0, 1+len(key)+len(hashTarget)+len(commitment)+len(rustSize)+40))
		out.WriteByte(1)
		writeLenPrefixedU64(out, key)
		writeLenPrefixedU64(out, nil) // strip value
		writeLenPrefixedU64(out, hashTarget)
		writeLenPrefixedU64(out, commitment)
		writeLenPrefixedU64(out, rustSize)
		return out.Bytes(), key, value, nil

	case 2: // TypeBranch
		buf := bytes.NewBuffer(val[1:])
		// Skip pathLength + fullPrefix — Rust's walker rebuilds
		// full_prefix from its descent path, so it isn't on disk in
		// the Rust layout.
		var pathLen uint32
		if err := binary.Read(buf, binary.BigEndian, &pathLen); err != nil {
			return nil, nil, nil, errors.Wrap(err, "branch pathLen")
		}
		if buf.Len() < int(pathLen)*4 {
			return nil, nil, nil, fmt.Errorf("branch fullPrefix truncated")
		}
		buf.Next(int(pathLen) * 4)
		// Now read the SerializeBranchNode(false) body: prefix_len +
		// prefix + commitment + size + leaf_count + longest_branch.
		var prefixLen uint32
		if err := binary.Read(buf, binary.BigEndian, &prefixLen); err != nil {
			return nil, nil, nil, errors.Wrap(err, "branch prefixLen")
		}
		if buf.Len() < int(prefixLen)*4 {
			return nil, nil, nil, fmt.Errorf("branch prefix truncated")
		}
		prefixBytes := make([]byte, int(prefixLen)*4)
		if _, err := buf.Read(prefixBytes); err != nil {
			return nil, nil, nil, errors.Wrap(err, "branch prefix bytes")
		}
		commitment, cerr := readLenPrefixedU64(buf)
		if cerr != nil {
			return nil, nil, nil, cerr
		}
		size, serr := readLenPrefixedU64(buf)
		if serr != nil {
			return nil, nil, nil, serr
		}
		// Read leaf_count (i64 BE) and longest_branch (i32 BE) as raw
		// bytes; we forward them unchanged.
		if buf.Len() < 8+4 {
			return nil, nil, nil, fmt.Errorf("branch trailer truncated")
		}
		leafCount := buf.Next(8)
		longestBranch := buf.Next(4)

		rustSize := goUnsignedToRustSignedBigInt(size)
		out := bytes.NewBuffer(make([]byte, 0, 1+4+len(prefixBytes)+len(commitment)+len(rustSize)+12+40))
		out.WriteByte(2)
		binary.Write(out, binary.BigEndian, prefixLen)
		out.Write(prefixBytes)
		writeLenPrefixedU64(out, commitment)
		writeLenPrefixedU64(out, rustSize)
		out.Write(leafCount)
		out.Write(longestBranch)
		return out.Bytes(), nil, nil, nil
	}
	return nil, nil, nil, fmt.Errorf("unknown tree node type byte: %d", val[0])
}

func readLenPrefixedU64(buf *bytes.Buffer) ([]byte, error) {
	if buf.Len() < 8 {
		return nil, fmt.Errorf("len-prefixed: header truncated")
	}
	var n uint64
	if err := binary.Read(buf, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if uint64(buf.Len()) < n {
		return nil, fmt.Errorf("len-prefixed: body truncated (need %d, have %d)", n, buf.Len())
	}
	out := make([]byte, n)
	if _, err := buf.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeLenPrefixedU64(buf *bytes.Buffer, data []byte) {
	var n uint64 = uint64(len(data))
	binary.Write(buf, binary.BigEndian, n)
	if n > 0 {
		buf.Write(data)
	}
}

// goUnsignedToRustSignedBigInt converts Go's `big.Int.Bytes()` output
// (unsigned absolute-value big-endian) to the format Rust's
// `BigInt::from_signed_bytes_be` expects: a signed big-endian
// encoding. For non-negative values these differ only when the high
// bit of the leading byte is set — Rust would interpret that as
// negative, so we prepend a `0x00` byte to keep the sign positive.
//
// Sizes in Quilibrium are always non-negative, so the negative-input
// case never arises here.
func goUnsignedToRustSignedBigInt(unsigned []byte) []byte {
	if len(unsigned) == 0 {
		return unsigned
	}
	// Strip leading zeros first (defensive — Go's Bytes() never
	// emits them but the caller may have built the slice some other
	// way).
	i := 0
	for i < len(unsigned)-1 && unsigned[i] == 0 {
		i++
	}
	trimmed := unsigned[i:]
	if trimmed[0]&0x80 != 0 {
		// High bit set: Rust would read this as negative. Prepend 0
		// to widen the encoding.
		out := make([]byte, len(trimmed)+1)
		out[0] = 0
		copy(out[1:], trimmed)
		return out
	}
	return trimmed
}
