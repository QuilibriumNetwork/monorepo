// Shared storage encodings and operations. Instantiating the same methods
// on both backends keeps tentative state byte-compatible with durable state.
macro_rules! impl_hypergraph_storage {
    ($store:ty, $txn:ty) => {
        impl $store {
            /// Load a previously stored tree blob, or `Ok(None)` if no blob exists
            /// for the given key.
            pub fn load_tree_blob(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
            ) -> Result<Option<Vec<u8>>> {
                let key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
                self.db
                    .get(&key)
                    .map_err(|e| QuilError::Store(e.to_string()))
            }

            /// Transaction-aware variant of [`save_vertex_underlying`]: stages the
            /// write into `txn`'s batch so vertex content becomes durable
            /// atomically with the tree nodes and shard commit of the surrounding
            /// transaction. Errors for an unrecognized txn type rather than writing
            /// outside the transaction (see [`RocksTxn::from_dyn`]).
            pub fn save_vertex_underlying_txn(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
                bytes: &[u8],
            ) -> Result<()> {
                let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&key, bytes);
                Ok(())
            }

            /// Load one vertex's `underlying_data`, or `Ok(None)` if absent.
            pub fn load_vertex_underlying(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
            ) -> Result<Option<Vec<u8>>> {
                let key = hypergraph_vertex_data_key(set_type, phase_type, shard_key, vertex_key);
                self.db
                    .get(&key)
                    .map_err(|e| QuilError::Store(e.to_string()))
            }

            /// Prune superseded MVCC blob versions of one `(set, phase, shard)` keyspace
            /// to `watermark`: per vertex keep the greatest version ≤ `watermark` (the
            /// value readable AT the watermark) and every version above it, deleting the
            /// strictly-older ones. Staged into `txn`; at most `budget` deletions, which
            /// it decrements. Returns the number deleted.
            ///
            /// Streams in key order holding one vertex's versions at a time. That is
            /// exact only for fixed 64-byte vertex keys, whose versions are contiguous;
            /// any other key is left alone.
            fn prune_blob_versions(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                watermark: u64,
                budget: &mut usize,
            ) -> Result<usize> {
                const VERTEX_KEY: usize = 64;
                let sprefix = crate::encoding::hypergraph_vertex_data_v2_shard_prefix(
                    set_type, phase_type, shard_key,
                );
                let mut deleted = 0usize;
                let mut current: Option<Vec<u8>> = None;
                let mut versions: Vec<(u64, Vec<u8>)> = Vec::new();
                let mut flush = |versions: &mut Vec<(u64, Vec<u8>)>, budget: &mut usize| -> Result<()> {
                    let floor = versions.iter().map(|(v, _)| *v).filter(|v| *v <= watermark).max();
                    if let Some(floor) = floor {
                        for (_, key) in versions.iter().filter(|(v, _)| *v < floor) {
                            if *budget == 0 {
                                break;
                            }
                            txn.delete(key)?;
                            *budget -= 1;
                            deleted += 1;
                        }
                    }
                    versions.clear();
                    Ok(())
                };
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &sprefix,
                    rocksdb::Direction::Forward,
                )) {
                    if *budget == 0 {
                        break;
                    }
                    let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&sprefix) {
                        break;
                    }
                    if k.len() != sprefix.len() + VERTEX_KEY + 8 {
                        continue;
                    }
                    let vk = &k[sprefix.len()..k.len() - 8];
                    if current.as_deref() != Some(vk) {
                        flush(&mut versions, budget)?;
                        current = Some(vk.to_vec());
                    }
                    versions.push((u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap()), k.to_vec()));
                }
                flush(&mut versions, budget)?;
                Ok(deleted)
            }

            /// Read the whole `root → (version, frame)` index, grouped by tree.
            fn indexed_trees(
                &self,
            ) -> Result<HashMap<crate::retention::TreeKey, Vec<crate::retention::IndexEntry>>> {
                let first = [crate::encoding::HG_ROOT_VERSION];
                let mut trees: HashMap<crate::retention::TreeKey, Vec<crate::retention::IndexEntry>> =
                    HashMap::new();
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &first,
                    rocksdb::Direction::Forward,
                )) {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.first() != Some(&crate::encoding::HG_ROOT_VERSION) {
                        break;
                    }
                    // key = [0x35][set][phase][shard_id(var)][root(32)]; value = ver(8)‖frame(8)
                    if k.len() < 1 + 1 + 1 + 32 || v.len() != 16 {
                        continue;
                    }
                    trees.entry((k[1], k[2], k[3..k.len() - 32].to_vec())).or_default().push((
                        k.to_vec(),
                        u64::from_be_bytes(v[..8].try_into().unwrap()),
                        u64::from_be_bytes(v[8..16].try_into().unwrap()),
                    ));
                }
                Ok(trees)
            }

            /// Apply a retention plan's index and blob deletions in one transaction.
            fn apply_prune_plan(
                &self,
                txn: &dyn Transaction,
                plan: &crate::retention::PrunePlan,
                mut blob_budget: usize,
            ) -> Result<()> {
                for key in &plan.delete_roots {
                    txn.delete(key)?;
                }
                for ((set_b, phase_b, app), watermark) in &plan.blobs {
                    let (Some(set_s), Some(phase_s)) = (byte_set_str(*set_b), byte_phase_str(*phase_b)) else {
                        continue;
                    };
                    let shard = ShardKey {
                        l1: quil_hypergraph::addressing::get_bloom_filter_indices(app, 256, 3),
                        l2: *app,
                    };
                    self.prune_blob_versions(txn, set_s, phase_s, &shard, *watermark, &mut blob_budget)?;
                }
                Ok(())
            }

            /// Page fixed domain/address keys from a single RocksDB snapshot. Two
            /// ordered cursors replace the full-shard MVCC deduplication map. Variable
            /// length keys are outside this API and are skipped, including interleaved
            /// versioned keys. Byte accounting charges 64 key bytes plus each blob.
            pub fn page_vertex_underlying_fixed(
                &self,
                set_type: &str,
                phase_type: &str,
                shard: &ShardKey,
                domain: &[u8; 32],
                after: Option<&[u8; 32]>,
                limits: quil_types::store::VertexPageLimits,
            ) -> Result<quil_types::store::VertexDataPage> {
                page_fixed_vertices_at_snapshot(
                    &self.db.snapshot(),
                    set_type,
                    phase_type,
                    shard,
                    domain,
                    after,
                    limits,
                    &|_| false,
                )
            }
        }
        impl HypergraphStore for $store {
            fn clear_shard_underlying(&self, shard: &ShardKey) -> Result<()> {
                let txn = self.new_transaction_backend(false)?;
                for (set, phase) in [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")] {
                    for lower in [
                        crate::encoding::hypergraph_vertex_data_prefix(set, phase, shard),
                        crate::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, shard),
                    ] {
                        let upper = prefix_range_upper_bound(&lower).ok_or_else(|| QuilError::Store("unbounded shard reset range".into()))?;
                        txn.delete_range(&lower, &upper)?;
                    }
                }
                txn.commit()
            }

            fn backing_store_identity(&self) -> Option<quil_types::store::BackingStoreIdentity> {
                Some(self.backing_store_identity_backend())
            }

            fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
                self.new_transaction_backend(_indexed)
            }

            fn get_node_by_key(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                key: &[u8],
            ) -> Result<Option<Vec<u8>>> {
                // The `[0xFF; 32]` "root sentinel" key is the legacy whole-tree
                // backend's handshake — it expects `load_tree_blob` to return
                // the entire serialized tree under prefix 0x2F. The per-node
                // lazy backend doesn't use that sentinel: it walks via
                // `get_node_by_path` from the empty path. We keep the sentinel
                // route working so any caller still on the old API path picks
                // up the tree, but new callers should not rely on it.
                if key == [0xFFu8; 32] {
                    return self.load_tree_blob(set_type, phase_type, shard_key);
                }
                // Per-node lookup at `[0x33, set, phase, l1, l2, key]`.
                let db_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
                self.db
                    .get(&db_key)
                    .map_err(|e| QuilError::Store(e.to_string()))
            }

            fn get_node_by_path(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                path: &[i32],
            ) -> Result<Option<Vec<u8>>> {
                // SeekGE on the by-path index. Prefix-compressed branches mean
                // the deepest covering node may live at a path longer than
                // `path` itself — its by-path key starts with the requested
                // path bytes. So we seek to `requested_path_key` and check the
                // first entry that still has the `prefix` (per-shard) byte
                // sequence as its prefix.
                let prefix = hypergraph_tree_node_by_path_prefix(set_type, phase_type, shard_key);
                let requested = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
                let mut iter = self.db.raw_iterator();
                iter.seek(&requested);
                iter.status().map_err(|e| QuilError::Store(e.to_string()))?;
                if !iter.valid() {
                    return Ok(None);
                }
                let found_key = match iter.key() {
                    Some(k) => k.to_vec(),
                    None => return Ok(None),
                };
                if !found_key.starts_with(&prefix) {
                    return Ok(None);
                }
                // The found key must also extend `requested` — otherwise we've
                // walked PAST the requested subtree to an unrelated path.
                if !found_key.starts_with(&requested) {
                    return Ok(None);
                }
                // Value is the by-key key for that node — deref to fetch.
                let by_key = match iter.value() {
                    Some(v) => v.to_vec(),
                    None => return Ok(None),
                };
                self.db
                    .get(&by_key)
                    .map_err(|e| QuilError::Store(e.to_string()))
            }

            fn insert_node(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                key: &[u8],
                path: &[i32],
                data: &[u8],
            ) -> Result<()> {
                // Root sentinel keeps its legacy blob route for backward compat.
                if key == [0xFFu8; 32] {
                    let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
                    <$txn>::for_store(txn, &self.db)?
                        .batch
                        .lock()
                        .unwrap()
                        .put(&db_key, data);
                    return Ok(());
                }
                // Per-node: write the by-key entry and the by-path pointer
                // atomically. Pointer value is the by-key key — the lazy
                // walker SeekGEs the by-path index and then `Get`s the by-key
                // entry. This is exactly Go's dual-index scheme.
                let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
                let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
                let mut batch = <$txn>::for_store(txn, &self.db)?.batch.lock().unwrap();
                batch.put(&by_key, data);
                batch.put(&by_path, &by_key);
                Ok(())
            }

            fn save_root(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                data: &[u8],
            ) -> Result<()> {
                let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&db_key, data);
                Ok(())
            }

            fn delete_node(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                key: &[u8],
                path: &[i32],
            ) -> Result<()> {
                if key == [0xFFu8; 32] {
                    let db_key = hypergraph_tree_blob_key(set_type, phase_type, shard_key);
                    <$txn>::for_store(txn, &self.db)?
                        .batch
                        .lock()
                        .unwrap()
                        .delete(&db_key);
                    return Ok(());
                }
                let by_key = hypergraph_tree_node_by_key(set_type, phase_type, shard_key, key);
                let by_path = hypergraph_tree_node_by_path(set_type, phase_type, shard_key, path);
                let mut batch = <$txn>::for_store(txn, &self.db)?.batch.lock().unwrap();
                batch.delete(&by_key);
                batch.delete(&by_path);
                Ok(())
            }

            fn set_covered_prefix(&self, prefix: &[i32]) -> Result<()> {
                // Go serializes `[]int` as a series of big-endian int64s via
                // `binary.Write(buf, BigEndian, []int64{...})` — mirror that
                // exactly so a future Rust-reads-Go-data path stays compatible.
                let mut buf = Vec::with_capacity(prefix.len() * 8);
                for &p in prefix {
                    buf.extend_from_slice(&(p as i64).to_be_bytes());
                }
                let key = crate::encoding::hypergraph_covered_prefix_key();
                self.db
                    .put(&key, &buf)
                    .map_err(|e| QuilError::Store(e.to_string()))
            }

            fn set_shard_commit(
                &self,
                txn: &dyn Transaction,
                frame_number: u64,
                phase_type: &str,
                set_type: &str,
                shard_address: &[u8],
                commitment: &[u8],
            ) -> Result<()> {
                let key =
                    hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&key, commitment);
                Ok(())
            }

            fn get_shard_commit(
                &self,
                frame_number: u64,
                phase_type: &str,
                set_type: &str,
                shard_address: &[u8],
            ) -> Result<Vec<u8>> {
                let key =
                    hypergraph_shard_commit_key(frame_number, phase_type, set_type, shard_address);
                self.db
                    .get(&key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                    .ok_or_else(|| QuilError::NotFound("shard commit not found".into()))
            }

            fn delete_shard_commits(&self, frame_number: u64, shard_address: &[u8]) -> Result<()> {
                // All four (phase_type, set_type) pairs that `commit` caches per
                // shard — matches the PHASES table in `HypergraphCrdt::commit`.
                for (phase_type, set_type) in [
                    ("adds", "vertex"),
                    ("removes", "vertex"),
                    ("adds", "hyperedge"),
                    ("removes", "hyperedge"),
                ] {
                    let key = hypergraph_shard_commit_key(
                        frame_number,
                        phase_type,
                        set_type,
                        shard_address,
                    );
                    self.db
                        .delete(&key)
                        .map_err(|e| QuilError::Store(e.to_string()))?;
                }
                Ok(())
            }

            fn get_root_commits(
                &self,
                frame_number: u64,
            ) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> {
                let prefix = hypergraph_shard_commit_frame_prefix(frame_number);
                let iter = self.db.iterator(rocksdb::IteratorMode::From(
                    &prefix,
                    rocksdb::Direction::Forward,
                ));
                let prefix_len = prefix.len();
                let mut result: HashMap<ShardKey, Vec<Vec<u8>>> = HashMap::new();
                for entry in iter {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&prefix) {
                        break;
                    }
                    // Key layout past the prefix: [commit_type(1), shard_address(32)]
                    // Skip keys that don't have exactly commit_type + 32-byte address.
                    if k.len() != prefix_len + 1 + 32 {
                        continue;
                    }
                    let commit_type = k[prefix_len];
                    let shard_address = &k[prefix_len + 1..];
                    let Some(commit_idx) = commit_type
                        .checked_sub(HG_VERTEX_ADDS_SHARD_COMMIT)
                        .map(usize::from)
                    else {
                        continue;
                    };
                    if commit_idx >= 4 {
                        continue;
                    }
                    // Derive L1 bloom filter from L2 (shard_address) via
                    // SHAKE256-based GetBloomFilterIndices(addr, 256, 3),
                    // matching Go's `node/store/hypergraph.go:2083` and
                    // `quil_hypergraph::addressing::get_bloom_filter_indices`.
                    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
                        shard_address,
                        256,
                        3,
                    );
                    let mut l2 = [0u8; 32];
                    l2.copy_from_slice(shard_address);
                    let sk = ShardKey { l1, l2 };
                    let commits = result.entry(sk).or_insert_with(|| vec![vec![]; 4]);
                    commits[commit_idx] = v.to_vec();
                }
                Ok(result)
            }

            fn load_vertex_underlying_raw(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
            ) -> Result<Option<Vec<u8>>> {
                // Latest = MVCC read at u64::MAX (falls back to the legacy keyspace).
                self.load_vertex_underlying_at(
                    set_type,
                    phase_type,
                    shard_key,
                    vertex_key,
                    u64::MAX,
                )
            }

            fn save_vertex_underlying(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
                data: &[u8],
            ) -> Result<()> {
                Self::save_vertex_underlying_txn(
                    self, txn, set_type, phase_type, shard_key, vertex_key, data,
                )
            }

            fn save_vertex_underlying_versioned(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
                data: &[u8],
                version: u64,
            ) -> Result<()> {
                let key = crate::encoding::hypergraph_vertex_data_v2_key(
                    set_type, phase_type, shard_key, vertex_key, version,
                );
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&key, data);
                Ok(())
            }

            fn delete_vertex_underlying_versions_from(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
                first: u64,
            ) -> Result<()> {
                let vk_prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
                    set_type, phase_type, shard_key, vertex_key,
                );
                let from = crate::encoding::hypergraph_vertex_data_v2_key(
                    set_type, phase_type, shard_key, vertex_key, first,
                );
                let mut stale = Vec::new();
                for entry in self.db.iterator(rocksdb::IteratorMode::From(&from, rocksdb::Direction::Forward)) {
                    let (k, _) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.len() != vk_prefix.len() + 8 || !k.starts_with(&vk_prefix) {
                        break;
                    }
                    stale.push(k.into_vec());
                }
                let staged = <$txn>::for_store(txn, &self.db)?;
                let mut batch = staged.batch.lock().unwrap();
                for key in stale {
                    batch.delete(&key);
                }
                Ok(())
            }

            fn load_vertex_underlying_at(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                vertex_key: &[u8],
                version: u64,
            ) -> Result<Option<Vec<u8>>> {
                // MVCC: reverse-seek to `vk_prefix ‖ V`; the first (largest ≤ V) key that
                // still shares `vk_prefix` is the latest write with version ≤ V. Version
                // is a fixed 8-byte non-inverted suffix, so a matching key has length
                // exactly `vk_prefix.len() + 8`.
                let vk_prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
                    set_type, phase_type, shard_key, vertex_key,
                );
                let seek = crate::encoding::hypergraph_vertex_data_v2_key(
                    set_type, phase_type, shard_key, vertex_key, version,
                );
                let mut iter = self.db.iterator(rocksdb::IteratorMode::From(
                    &seek,
                    rocksdb::Direction::Reverse,
                ));
                if let Some(entry) = iter.next() {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.len() == vk_prefix.len() + 8 && k.starts_with(&vk_prefix) {
                        return Ok(Some(v.into_vec()));
                    }
                }
                // Legacy fallback: an un-migrated (unversioned) blob written before the
                // version dimension existed. The next commit re-writes it versioned.
                self.load_vertex_underlying(set_type, phase_type, shard_key, vertex_key)
            }

            fn page_vertex_underlying_fixed(
                &self,
                set_type: &str,
                phase_type: &str,
                shard: &ShardKey,
                domain: &[u8; 32],
                after: Option<&[u8; 32]>,
                limits: quil_types::store::VertexPageLimits,
            ) -> Result<quil_types::store::VertexDataPage> {
                Self::page_vertex_underlying_fixed(
                    self, set_type, phase_type, shard, domain, after, limits,
                )
            }

            fn for_each_vertex_underlying(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_key: &ShardKey,
                callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
            ) -> Result<usize> {
                use std::collections::{HashMap, HashSet};
                // v2 (versioned) keyspace: keep the LATEST version per vertex_key. Keys
                // may interleave across variable-length vertex keys, so accumulate into a
                // map rather than assume per-key contiguity.
                let v2_prefix = crate::encoding::hypergraph_vertex_data_v2_shard_prefix(
                    set_type, phase_type, shard_key,
                );
                let mut latest: HashMap<Vec<u8>, (u64, Vec<u8>)> = HashMap::new();
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &v2_prefix,
                    rocksdb::Direction::Forward,
                )) {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&v2_prefix) {
                        break;
                    }
                    if k.len() < v2_prefix.len() + 8 {
                        continue;
                    }
                    let vk = k[v2_prefix.len()..k.len() - 8].to_vec();
                    let ver = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
                    match latest.get_mut(&vk) {
                        Some((mv, mb)) if ver > *mv => {
                            *mv = ver;
                            *mb = v.into_vec();
                        }
                        Some(_) => {}
                        None => {
                            latest.insert(vk, (ver, v.into_vec()));
                        }
                    }
                }
                let mut count = 0usize;
                let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(latest.len());
                for (vk, (_ver, blob)) in latest {
                    seen.insert(vk.clone());
                    callback(vk, blob);
                    count += 1;
                }
                // Legacy (unversioned) keyspace fills any vertex not yet re-written v2.
                let old_prefix =
                    crate::encoding::hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &old_prefix,
                    rocksdb::Direction::Forward,
                )) {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&old_prefix) {
                        break;
                    }
                    if k.len() <= old_prefix.len() {
                        continue;
                    }
                    let vk = k[old_prefix.len()..].to_vec();
                    if seen.contains(&vk) {
                        continue;
                    }
                    callback(vk, v.into_vec());
                    count += 1;
                }
                Ok(count)
            }

            fn put_root_version(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                shard_id: &[u8],
                root_hash: &[u8],
                version: u64,
                frame_number: u64,
            ) -> Result<()> {
                // Repeated roots collapse to the LATEST (version, frame): a `put` keyed by
                // root overwrites, and commits happen in version order, so the last write
                // for a recurring root wins.
                let key = crate::encoding::hypergraph_root_version_key(
                    set_type, phase_type, shard_id, root_hash,
                );
                let mut val = Vec::with_capacity(16);
                val.extend_from_slice(&version.to_be_bytes());
                val.extend_from_slice(&frame_number.to_be_bytes());
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&key, &val);
                Ok(())
            }

            fn get_root_version(
                &self,
                set_type: &str,
                phase_type: &str,
                shard_id: &[u8],
                root_hash: &[u8],
            ) -> Result<Option<(u64, u64)>> {
                let key = crate::encoding::hypergraph_root_version_key(
                    set_type, phase_type, shard_id, root_hash,
                );
                match self
                    .db
                    .get(&key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                {
                    Some(v) if v.len() == 16 => Ok(Some((
                        u64::from_be_bytes(v[..8].try_into().unwrap()),
                        u64::from_be_bytes(v[8..16].try_into().unwrap()),
                    ))),
                    _ => Ok(None),
                }
            }

            fn put_app_manifest(
                &self,
                txn: &dyn Transaction,
                set_type: &str,
                phase_type: &str,
                app_address: &[u8],
                app_root: &[u8],
                entries: &[(Vec<u8>, [u8; 32], u64)],
                frame_number: u64,
            ) -> Result<()> {
                // frame(u64) ‖ count(u32) then per entry: prefix_len(u16) ‖ prefix ‖
                // sub_root(32) ‖ ver(u64). The leading frame lets the pruner drop stale
                // manifests by age without re-deriving each aggregate root's version.
                let key = crate::encoding::hypergraph_app_manifest_key(
                    set_type,
                    phase_type,
                    app_address,
                    app_root,
                );
                let mut val = Vec::new();
                val.extend_from_slice(&frame_number.to_be_bytes());
                val.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for (prefix, root, ver) in entries {
                    val.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
                    val.extend_from_slice(prefix);
                    val.extend_from_slice(root);
                    val.extend_from_slice(&ver.to_be_bytes());
                }
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&key, &val);
                Ok(())
            }

            fn get_app_manifest(
                &self,
                set_type: &str,
                phase_type: &str,
                app_address: &[u8],
                app_root: &[u8],
            ) -> Result<Option<Vec<(Vec<u8>, [u8; 32], u64)>>> {
                let key = crate::encoding::hypergraph_app_manifest_key(
                    set_type,
                    phase_type,
                    app_address,
                    app_root,
                );
                let raw = match self
                    .db
                    .get(&key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                {
                    Some(v) => v,
                    None => return Ok(None),
                };
                // Skip the leading frame(u64) — retained only for the pruner.
                let mut p = 8usize;
                if raw.len() < p {
                    return Err(QuilError::Store("manifest: short frame".into()));
                }
                let rd_u32 = |b: &[u8], p: &mut usize| -> Option<u32> {
                    if *p + 4 > b.len() {
                        return None;
                    }
                    let v = u32::from_be_bytes(b[*p..*p + 4].try_into().unwrap());
                    *p += 4;
                    Some(v)
                };
                let n = rd_u32(&raw, &mut p)
                    .ok_or_else(|| QuilError::Store("manifest: short".into()))?;
                if n as usize > raw.len().saturating_sub(p) / 42 {
                    return Err(QuilError::Store(
                        "manifest: count exceeds remaining entries".into(),
                    ));
                }
                let mut out = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    if p + 2 > raw.len() {
                        return Err(QuilError::Store("manifest: short prefix_len".into()));
                    }
                    let plen = u16::from_be_bytes(raw[p..p + 2].try_into().unwrap()) as usize;
                    p += 2;
                    if p + plen + 32 + 8 > raw.len() {
                        return Err(QuilError::Store("manifest: short entry".into()));
                    }
                    let prefix = raw[p..p + plen].to_vec();
                    p += plen;
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&raw[p..p + 32]);
                    p += 32;
                    let ver = u64::from_be_bytes(raw[p..p + 8].try_into().unwrap());
                    p += 8;
                    out.push((prefix, root, ver));
                }
                Ok(Some(out))
            }

            fn prune_versioned(&self, cull_frame: u64) -> Result<Vec<(Vec<u8>, usize, u64)>> {
                // One cull frame for every tree. Trees whose versions do not rise
                // with their frames are left alone (see `crate::retention`).
                let plan = crate::retention::plan_prune(self.indexed_trees()?, |_| Some(cull_frame), |_| None);
                let txn = self.new_transaction(false)?;
                self.apply_prune_plan(txn.as_ref(), &plan, usize::MAX)?;

                // Prune stale split-app manifests (frame < cull_frame).
                let mf_first = [crate::encoding::HG_APP_MANIFEST];
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &mf_first,
                    rocksdb::Direction::Forward,
                )) {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.first() != Some(&crate::encoding::HG_APP_MANIFEST) {
                        break;
                    }
                    if v.len() < 8 {
                        continue;
                    }
                    let frame = u64::from_be_bytes(v[..8].try_into().unwrap());
                    if frame < cull_frame {
                        txn.delete(&k)?;
                    }
                }

                txn.commit()?;
                Ok(plan.trees)
            }

            fn clear_root_versions(&self, shard_id: &[u8]) -> Result<usize> {
                let mut deleted = 0usize;
                for (set, phase) in [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")] {
                    deleted += self.clear_phase_root_versions(set, phase, shard_id)?;
                }
                Ok(deleted)
            }

            fn clear_phase_root_versions(&self, set: &str, phase: &str, shard_id: &[u8]) -> Result<usize> {
                let txn = self.new_transaction(false)?;
                let mut deleted = 0usize;
                // An empty root leaves the tree's own prefix; only keys of exactly
                // this id plus a 32-byte root belong to it, not longer ids it prefixes.
                let prefix = crate::encoding::hypergraph_root_version_key(set, phase, shard_id, &[]);
                for entry in self.db.iterator(rocksdb::IteratorMode::From(
                    &prefix,
                    rocksdb::Direction::Forward,
                )) {
                    let (k, _) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&prefix) {
                        break;
                    }
                    if k.len() == prefix.len() + 32 {
                        txn.delete(&k)?;
                        deleted += 1;
                    }
                }
                txn.commit()?;
                Ok(deleted)
            }

            fn prune_versioned_retaining(
                &self,
                retain_frames: u64,
                max_blob_deletes: usize,
                head: &dyn Fn(&[u8], usize) -> Option<u64>,
            ) -> Result<Vec<(Vec<u8>, usize, u64)>> {
                // Each tree keeps the last `retain_frames` of its OWN frames, so trees
                // committed under different frame sequences never cull each other.
                let plan = crate::retention::plan_prune(self.indexed_trees()?, |newest| {
                    newest.checked_sub(retain_frames)
                }, |(set, phase, shard_id)| head(shard_id, usize::from(*set) * 2 + usize::from(*phase)));
                let txn = self.new_transaction(false)?;
                self.apply_prune_plan(txn.as_ref(), &plan, max_blob_deletes)?;
                txn.commit()?;
                Ok(plan.trees)
            }

            fn apply_snapshot(&self, db_path: &str) -> Result<()> {
                self.apply_snapshot_backend(db_path)
            }

            fn set_alt_shard_commit(
                &self,
                txn: &dyn Transaction,
                frame_number: u64,
                shard_address: &[u8],
                va: &[u8],
                vr: &[u8],
                ha: &[u8],
                hr: &[u8],
            ) -> Result<()> {
                // Validate root sizes — Go accepts 64 (raw) or 74 (KZG-with-proof).
                for (name, root) in [
                    ("vertex_adds", va),
                    ("vertex_removes", vr),
                    ("hyperedge_adds", ha),
                    ("hyperedge_removes", hr),
                ] {
                    if root.len() != 64 && root.len() != 74 {
                        return Err(QuilError::InvalidArgument(format!(
                            "alt shard commit {name} root must be 64 or 74 bytes, got {}",
                            root.len()
                        )));
                    }
                }

                // Serialize as length-prefixed values (1-byte len + data for each of
                // the four roots) — matches `SetAltShardCommit` at
                // node/store/hypergraph.go:2425.
                let mut value = Vec::with_capacity(4 + va.len() + vr.len() + ha.len() + hr.len());
                for root in [va, vr, ha, hr] {
                    value.push(root.len() as u8);
                    value.extend_from_slice(root);
                }

                let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
                let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
                let index_key = hypergraph_alt_shard_address_index_key(shard_address);

                // Consult existing latest-frame so we only overwrite with a newer one.
                let should_update_latest = match self
                    .db
                    .get(&latest_key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                {
                    Some(bytes) if bytes.len() == 8 => {
                        let existing = u64::from_be_bytes(bytes.as_slice().try_into().unwrap());
                        frame_number > existing
                    }
                    _ => true,
                };

                let mut batch = <$txn>::for_store(txn, &self.db)?.batch.lock().unwrap();
                batch.put(&commit_key, &value);
                if should_update_latest {
                    batch.put(&latest_key, frame_number.to_be_bytes());
                }
                batch.put(&index_key, &[] as &[u8]);
                Ok(())
            }

            fn get_latest_alt_shard_commit(
                &self,
                shard_address: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
                let latest_key = hypergraph_alt_shard_commit_latest_key(shard_address);
                let latest = self
                    .db
                    .get(&latest_key)
                    .map_err(|e| QuilError::Store(e.to_string()))?;
                let frame_number = match latest {
                    Some(bytes) if bytes.len() == 8 => {
                        u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
                    }
                    _ => return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new())),
                };
                let commit_key = hypergraph_alt_shard_commit_key(frame_number, shard_address);
                let value = self
                    .db
                    .get(&commit_key)
                    .map_err(|e| QuilError::Store(e.to_string()))?
                    .ok_or_else(|| QuilError::NotFound("alt shard commit not found".into()))?;

                // Decode four length-prefixed roots.
                let mut cursor = 0usize;
                let mut parts = Vec::with_capacity(4);
                for _ in 0..4 {
                    if cursor >= value.len() {
                        return Err(QuilError::Serialization(
                            "alt shard commit value truncated".into(),
                        ));
                    }
                    let len = value[cursor] as usize;
                    cursor += 1;
                    if cursor + len > value.len() {
                        return Err(QuilError::Serialization(
                            "alt shard commit length prefix overruns buffer".into(),
                        ));
                    }
                    parts.push(value[cursor..cursor + len].to_vec());
                    cursor += len;
                }
                Ok((
                    parts.remove(0),
                    parts.remove(0),
                    parts.remove(0),
                    parts.remove(0),
                ))
            }

            fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> {
                let prefix = hypergraph_alt_shard_address_prefix();
                let prefix_len = prefix.len();
                let iter = self.db.iterator(rocksdb::IteratorMode::From(
                    &prefix,
                    rocksdb::Direction::Forward,
                ));
                let mut out = Vec::new();
                for entry in iter {
                    let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if !k.starts_with(&prefix) {
                        break;
                    }
                    if k.len() > prefix_len {
                        out.push(k[prefix_len..].to_vec());
                    }
                }
                Ok(out)
            }
            fn reap_old_changesets(&self, txn: &dyn Transaction, frame_number: u64) -> Result<()> {
                <$txn>::for_store(txn, &self.db)?;
                // Mirror Go's `ReapOldChangesets` (`node/store/hypergraph.go:1830`):
                // (1) enumerate every shard for which a `VERTEX_ADDS_TREE_ROOT`
                // exists, then (2) for each of the four change-record discriminators
                // delete all entries for that shard with `frame_number` < `frame_number`.
                if frame_number == 0 {
                    return Ok(());
                }
                let (start, end) = crate::encoding::hypergraph_tree_roots_iter_bounds();
                let mut shard_keys: Vec<Vec<u8>> = Vec::new();
                let iter = self.db.iterator(rocksdb::IteratorMode::From(
                    &start,
                    rocksdb::Direction::Forward,
                ));
                for entry in iter {
                    let (k, _v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.as_ref() >= end.as_slice() {
                        break;
                    }
                    // Strip the [HYPERGRAPH_SHARD, change_type] prefix.
                    if k.len() <= 2 {
                        continue;
                    }
                    shard_keys.push(k[2..].to_vec());
                }

                let change_types = [
                    crate::encoding::HG_VERTEX_ADDS_CHANGE_RECORD,
                    crate::encoding::HG_VERTEX_REMOVES_CHANGE_RECORD,
                    crate::encoding::HG_HYPEREDGE_ADDS_CHANGE_RECORD,
                    crate::encoding::HG_HYPEREDGE_REMOVES_CHANGE_RECORD,
                ];
                for change_type in change_types {
                    for sk in &shard_keys {
                        let mut start_key = Vec::with_capacity(2 + sk.len() + 8);
                        start_key.push(crate::encoding::HYPERGRAPH_SHARD);
                        start_key.push(change_type);
                        start_key.extend_from_slice(sk);
                        start_key.extend_from_slice(&0u64.to_be_bytes());
                        let mut end_key = Vec::with_capacity(2 + sk.len() + 8);
                        end_key.push(crate::encoding::HYPERGRAPH_SHARD);
                        end_key.push(change_type);
                        end_key.extend_from_slice(sk);
                        end_key.extend_from_slice(&frame_number.to_be_bytes());
                        txn.delete_range(&start_key, &end_key)?;
                    }
                }
                Ok(())
            }
            fn track_change(
                &self,
                txn: &dyn Transaction,
                key: &[u8],
                old_value: Option<&[u8]>,
                frame_number: u64,
                phase_type: &str,
                set_type: &str,
                shard_key: &ShardKey,
            ) -> Result<()> {
                // Mirror Go's `TrackChange` (`node/store/hypergraph.go:1714`):
                // write the serialized `oldValue` tree blob (empty if `nil`) under
                // a per-(set/phase/shard/frame/key) change-record key.
                let change_key = crate::encoding::hypergraph_change_record_key(
                    set_type,
                    phase_type,
                    shard_key,
                    frame_number,
                    key,
                )
                .ok_or_else(|| {
                    QuilError::InvalidArgument(format!(
                        "track_change: unknown set/phase pair ({}, {})",
                        set_type, phase_type,
                    ))
                })?;
                let value: &[u8] = old_value.unwrap_or(&[]);
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .put(&change_key, value);
                Ok(())
            }
            fn get_changes(
                &self,
                frame_start: u64,
                frame_end: u64,
                phase_type: &str,
                set_type: &str,
                shard_key: &ShardKey,
            ) -> Result<Vec<ChangeRecord>> {
                // Mirror Go's `GetChanges` (`node/store/hypergraph.go:1886`):
                // range-scan `[HYPERGRAPH_SHARD, change_type, l1, l2,
                // frame_start..=frame_end]`, parse the suffix into frame + key,
                // and return the records reversed for rollback-friendly order.
                let change_type = crate::encoding::change_record_type_byte(set_type, phase_type)
                    .ok_or_else(|| {
                        QuilError::InvalidArgument(format!(
                            "get_changes: unknown set/phase pair ({}, {})",
                            set_type, phase_type,
                        ))
                    })?;
                let mut start_key = Vec::with_capacity(2 + 3 + 32 + 8);
                start_key.push(crate::encoding::HYPERGRAPH_SHARD);
                start_key.push(change_type);
                start_key.extend_from_slice(&shard_key.l1);
                start_key.extend_from_slice(&shard_key.l2);
                start_key.extend_from_slice(&frame_start.to_be_bytes());

                let mut end_key = Vec::with_capacity(2 + 3 + 32 + 8);
                end_key.push(crate::encoding::HYPERGRAPH_SHARD);
                end_key.push(change_type);
                end_key.extend_from_slice(&shard_key.l1);
                end_key.extend_from_slice(&shard_key.l2);
                // Go's iterator is exclusive-end with `frameEnd + 1`. Saturate
                // on overflow rather than wrap to 0 — wrapping would produce a
                // key strictly less than `start_key` and immediately terminate
                // the scan, silently returning no changes.
                end_key.extend_from_slice(&frame_end.saturating_add(1).to_be_bytes());

                let header_len = 2 + 3 + 32;
                let mut changes: Vec<ChangeRecord> = Vec::new();
                let iter = self.db.iterator(rocksdb::IteratorMode::From(
                    &start_key,
                    rocksdb::Direction::Forward,
                ));
                for entry in iter {
                    let (k, v) = entry.map_err(|e| QuilError::Store(e.to_string()))?;
                    if k.as_ref() >= end_key.as_slice() {
                        break;
                    }
                    if k.len() < header_len + 8 {
                        continue;
                    }
                    let frame_number =
                        u64::from_be_bytes(k[header_len..header_len + 8].try_into().unwrap());
                    let original_key = k[header_len + 8..].to_vec();
                    let old_value = if v.is_empty() { None } else { Some(v.to_vec()) };
                    changes.push(ChangeRecord {
                        key: original_key,
                        old_value,
                        frame: frame_number,
                    });
                }
                changes.reverse();
                Ok(changes)
            }
            fn untrack_change(
                &self,
                txn: &dyn Transaction,
                key: &[u8],
                frame_number: u64,
                phase_type: &str,
                set_type: &str,
                shard_key: &ShardKey,
            ) -> Result<()> {
                // Mirror Go's `UntrackChange` (`node/store/hypergraph.go:1961`).
                let change_key = crate::encoding::hypergraph_change_record_key(
                    set_type,
                    phase_type,
                    shard_key,
                    frame_number,
                    key,
                )
                .ok_or_else(|| {
                    QuilError::InvalidArgument(format!(
                        "untrack_change: unknown set/phase pair ({}, {})",
                        set_type, phase_type,
                    ))
                })?;
                <$txn>::for_store(txn, &self.db)?
                    .batch
                    .lock()
                    .unwrap()
                    .delete(&change_key);
                Ok(())
            }

            fn capture_tree_snapshot(&self) -> Result<Option<Arc<dyn SnapshotReadable>>> {
                self.capture_tree_snapshot_backend()
            }
        }
    };
}
impl_hypergraph_storage!(RocksHypergraphStore, RocksTxn);
impl_hypergraph_storage!(OverlayHypergraphStore, OverlayTxn);
