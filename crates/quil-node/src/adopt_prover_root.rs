//! `--adopt-prover-root <master store>`: offline repair of an archive whose
//! GLOBAL prover shard diverged from the rest of the committee at the same head.
//!
//! Use it when archives stopped at the same head disagree on the prover root
//! and a minority store did not execute its head frame (it recorded no request
//! outcomes for it) yet holds a prover tree no frame sequence produces, i.e.
//! a state adopted from a peer rather than computed. This tool replaces such a
//! store's GLOBAL prover shard with the one a healthy archive holds, through
//! the same root-addressed sync the node runs
//! (`forest_sync::sync_single_shard_verified`): the peer's tree is authenticated
//! against the requested root before anything is installed, and only records
//! that differ are written.
//!
//! The root must be the state after this store's head frame (the peer's
//! `resolve_root` frame must equal the head), so a repair cannot move the store
//! to another frame's state. Only the prover shard changes; the cursor, frames
//! and every other shard stay.
//!
//! - Without `--adopt-commit` nothing is written: the root is pulled into
//!   memory and every record and phase that would change is listed.
//! - With it, the store is opened for writing (refused while its node runs,
//!   which holds the lock) and pulled into directly, once. Head markers an old
//!   reset left on emptied phases are dropped first (the sync's strict root
//!   read refuses them), and afterwards every phase is checked against the
//!   peer. A pull that stops part way is safe to rerun: installs are atomic
//!   chunks and the rerun resumes.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use quil_types::store::ClockStore as _;
use sha2::{Digest as _, Sha256};

const PROVER_SHARD: [u8; 32] = [0xff; 32];
const PHASES: [(&str, &str); 4] =
    [("vertex", "adds"), ("vertex", "removes"), ("hyperedge", "adds"), ("hyperedge", "removes")];

pub struct AdoptArgs<'a> {
    pub store: &'a Path,
    pub from: &'a str,
    pub root: &'a str,
    pub commit: bool,
    /// Accept a root the peer holds at a frame other than this store's head
    /// (localnet testing only).
    pub any_frame: bool,
}

pub async fn run_adopt_prover_root(
    args: AdoptArgs<'_>,
    config: &quil_config::Config,
    config_dir: &Path,
    network: u8,
) -> anyhow::Result<()> {
    let target: [u8; 32] = hex::decode(args.root)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("--adopt-root must be 32 bytes of hex"))?;
    if args.from.is_empty() {
        anyhow::bail!("--adopt-from <ip:port> is required");
    }
    let falcon_key = crate::query_shards::falcon_identity(config, config_dir)?;
    let shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: PROVER_SHARD };
    let started = Instant::now();
    let elapsed = || format!("{:.0}s", started.elapsed().as_secs_f64());

    println!("=== ADOPT GLOBAL PROVER ROOT ({}) ===", if args.commit { "commit" } else { "dry run" });
    println!("store:  {}", args.store.display());
    println!("from:   {}", args.from);
    println!("target: {}", hex::encode(target));

    let db = if args.commit {
        quil_store::RocksDb::open(args.store)
            .map_err(|e| anyhow::anyhow!("open {} for writing (is its node stopped?): {e}", args.store.display()))?
    } else {
        quil_store::RocksDb::open_for_read_only(args.store)
            .map_err(|e| anyhow::anyhow!("open {} read-only: {e}", args.store.display()))?
    };
    let raw = db.inner();
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
    let local = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        Arc::new(quil_tries::ShaInclusionProver),
    ));
    quil_forest_migrate::install_forest_boot(local.as_ref(), hg_store.as_ref(), false, network == 0);
    let clock = quil_store::RocksClockStore::new(raw.clone());
    let head = clock.get_latest_global_clock_frame()?.header.map(|h| h.frame_number).unwrap_or(0);
    let cursor = clock.get_global_materialized_cursor();
    let before = listing(&local, &shard)?;
    let orphaned = local.orphaned_phase_heads(&PROVER_SHARD)?;
    println!("head:   {head} (materialized cursor {cursor:?})");
    println!("local:  {} ({} records)", hex::encode(local.compute_shard_root("vertex", "adds", &shard)), before.len());
    for (index, (set, phase)) in PHASES.iter().enumerate().skip(1) {
        println!("        phase {index} ({set} {phase}) {}", hex::encode(local.compute_shard_root(set, phase, &shard)));
    }
    for (phase, version) in &orphaned {
        println!("        phase {phase}: head marker names version {version}, whose tree an old reset emptied (the sync refuses it; --adopt-commit drops it)");
    }

    // What the peer holds: the target's frame, and each phase's head.
    let mut client = quil_rpc::ArchiveClient::connect_mtls(args.from, &falcon_key)
        .await
        .map_err(|e| anyhow::anyhow!("connect {}: {e}", args.from))?;
    let (_, frame) = client
        .resolve_root(PROVER_SHARD.to_vec(), 0, target.to_vec())
        .await
        .map_err(|e| anyhow::anyhow!("resolve_root on {}: {e}", args.from))?
        .ok_or_else(|| anyhow::anyhow!("{} does not hold the prover shard at {} (never, or pruned)", args.from, hex::encode(target)))?;
    println!("peer:   holds the target at frame {frame}");
    if frame != head {
        if !args.any_frame {
            anyhow::bail!("the peer holds this root as the state after frame {frame}, but this store's head is {head}; refusing to move the store to another frame's state");
        }
        println!("        (frame differs from the head; accepted by --adopt-any-frame)");
    }
    let mut peer_phases = [[0u8; 32]; 4];
    peer_phases[0] = target;
    for (index, phase) in peer_phases.iter_mut().enumerate().skip(1) {
        if let Some((_, root)) = client
            .get_forest_head(PROVER_SHARD.to_vec(), index as u32)
            .await
            .map_err(|e| anyhow::anyhow!("get_forest_head phase {index} on {}: {e}", args.from))?
        {
            *phase = root.try_into().map_err(|_| anyhow::anyhow!("peer phase {index} head is not 32 bytes"))?;
        }
    }
    let differing_phases = |crdt: &quil_hypergraph::HypergraphCrdt| -> Vec<(usize, [u8; 32])> {
        PHASES.iter().enumerate()
            .map(|(index, (set, phase))| (index, crdt.compute_shard_root(set, phase, &shard).as_slice().try_into().unwrap_or([0u8; 32])))
            .filter(|(index, root)| *root != peer_phases[*index] && !(is_empty_root(root) && is_empty_root(&peer_phases[*index])))
            .collect()
    };
    let differing = differing_phases(&local);
    if differing.is_empty() && orphaned.is_empty() {
        println!("\nthe store already matches the peer in every phase; nothing to do.");
        return Ok(());
    }
    for (index, root) in &differing {
        let (set, phase) = PHASES[*index];
        println!("        phase {index} ({set} {phase}) differs: {} -> {}", hex::encode(root), hex::encode(peer_phases[*index]));
    }

    if !args.commit {
        // Preview: pull the target into memory and list every record that
        // would change. This walks the peer's whole tree, one request per
        // node, so it can take a while over a long link.
        println!("\n[{}] pulling the target into memory to list the changes…", elapsed());
        let memory_db = quil_store::RocksDb::open_in_memory()
            .map_err(|e| anyhow::anyhow!("open in-memory db: {e}"))?;
        let memory_store = Arc::new(quil_store::RocksHypergraphStore::new(memory_db.inner()));
        let memory = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            memory_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        memory.set_forest(quil_forest::Forest::with_namespace(memory_store.raw_db(), quil_store::FOREST_NAMESPACE.to_vec()));
        crate::forest_sync::sync_single_shard_verified(args.from, &falcon_key, memory.clone(), &PROVER_SHARD, &target)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{} did not serve a tree that verifies against {}", args.from, hex::encode(target)))?;
        let changes = diff(&before, &listing(&memory, &shard)?);
        println!("[{}] {} record(s) differ from the target:", elapsed(), changes.len());
        for line in &changes {
            println!("  {line}");
        }
        println!("\ndry run: nothing written. Stop the node, back up its store, and rerun with --adopt-commit.");
        return Ok(());
    }

    for (phase, version) in local.drop_orphaned_phase_heads(&PROVER_SHARD)? {
        println!("dropped phase {phase}'s orphaned head marker (version {version})");
    }
    println!("\n[{}] pulling the target into the store (progress is logged as it goes)…", elapsed());
    let installed = crate::forest_sync::sync_single_shard_verified(args.from, &falcon_key, local.clone(), &PROVER_SHARD, &target)
        .await?
        .ok_or_else(|| anyhow::anyhow!("the pull did not verify against the target; nothing past the last complete chunk was installed, rerun to resume"))?;
    let after = listing(&local, &shard)?;
    let changes = diff(&before, &after);
    println!("[{}] {} record(s) changed:", elapsed(), changes.len());
    for line in &changes {
        println!("  {line}");
    }
    let still = differing_phases(&local);
    if !still.is_empty() {
        for (index, root) in &still {
            println!("  phase {index} is {} but the peer holds {}", hex::encode(root), hex::encode(peer_phases[*index]));
        }
        anyhow::bail!("after installing, {} phase(s) still differ from the peer; rerun, or restore the backup", still.len());
    }
    println!("\nadopted: the store's prover root is now {} and every phase matches the peer (peer frame {installed}, head {head}).",
        hex::encode(target));
    Ok(())
}

/// An empty tree's root: all zeros, or the JMT placeholder.
fn is_empty_root(root: &[u8; 32]) -> bool {
    root == &[0u8; 32] || root == b"SPARSE_MERKLE_PLACEHOLDER_HASH__"
}

/// Every GLOBAL prover-shard record: address → (length, sha256).
fn listing(
    crdt: &quil_hypergraph::HypergraphCrdt,
    shard: &quil_types::store::ShardKey,
) -> anyhow::Result<BTreeMap<Vec<u8>, (usize, [u8; 32])>> {
    let mut records = BTreeMap::new();
    crdt.for_each_vertex_underlying_shard("vertex", "adds", shard, &mut |key, blob| {
        let address = key[key.len().saturating_sub(32)..].to_vec();
        records.insert(address, (blob.len(), Sha256::digest(&blob).into()));
    })?;
    Ok(records)
}

/// The records that differ: `changed|added|removed <address> <length>`.
fn diff(
    from: &BTreeMap<Vec<u8>, (usize, [u8; 32])>,
    to: &BTreeMap<Vec<u8>, (usize, [u8; 32])>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (address, record) in to {
        match from.get(address) {
            Some(old) if old == record => {}
            Some(old) => lines.push(format!("changed {} {} -> {} bytes", hex::encode(address), old.0, record.0)),
            None => lines.push(format!("added   {} {} bytes", hex::encode(address), record.0)),
        }
    }
    for (address, record) in from {
        if !to.contains_key(address) {
            lines.push(format!("removed {} {} bytes", hex::encode(address), record.0));
        }
    }
    lines
}
