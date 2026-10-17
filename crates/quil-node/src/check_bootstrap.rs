//! `--check-bootstrap`: diagnose the consensus bootstrap root.
//!
//! The global consensus event loop roots its forks tree on the frame the
//! latest persisted QC certifies, looked up via
//! `get_global_clock_frame_candidate(qc.frame_number, qc.selector)`. The
//! forks root is then keyed by `Poseidon(root_frame.output)`, while the
//! leader resolves its parent by `qc.selector` (= Go's
//! `Poseidon(certified_frame.output)`). If those differ the leader can
//! never find its parent and silently skips every proposal —
//! `"leader skipping: parent state not in forks tree"` — and the chain
//! halts in perpetual timeouts.
//!
//! This probe replays exactly that lookup against the on-disk store and
//! reports whether the root the bootstrap would build matches the QC the
//! pacemaker is pinned to — and, if not, whether the candidate key is
//! absent (silent fallback at `clock.rs:556`) or present-but-mismatched.
//! Read-only; opens the DB, prints a verdict, exits.

use std::path::Path;

use quil_types::store::ClockStore;

fn poseidon_hex(output: &[u8]) -> String {
    match quil_crypto::poseidon::hash_bytes_to_32(output) {
        Ok(h) => hex::encode(h),
        Err(e) => format!("<poseidon error: {e}>"),
    }
}

pub fn run_check_bootstrap(db_path: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if db_path.as_os_str().is_empty() {
        std::path::PathBuf::from(&config.db.path)
    } else {
        db_path.to_path_buf()
    };
    if path.as_os_str().is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Bootstrap root consistency check ===");
    println!("target (rocksdb): {}", path.display());

    let db = quil_store::RocksDb::open(&path)
        .map_err(|e| anyhow::anyhow!("open rocksdb {}: {e}", path.display()))?;
    let inner = db.inner();
    let clock = quil_store::RocksClockStore::new(inner.clone());

    // 1. The persisted latest QC — what the pacemaker seeds and what the
    //    leader resolves its parent by.
    let qc = clock
        .get_latest_quorum_certificate(&[])
        .map_err(|e| anyhow::anyhow!("get_latest_quorum_certificate: {e}"))?;
    let selector = qc.selector.clone();
    println!("\n[latest QC]");
    println!("  rank          : {}", qc.rank);
    println!("  frame_number  : {}", qc.frame_number);
    println!("  selector      : {}", hex::encode(&selector));

    // 2. Is the candidate key physically present in the store?
    let cand_key = quil_store::encoding::clock_global_frame_candidate_key(qc.frame_number, &selector);
    let cand_present = inner
        .get(&cand_key)
        .map_err(|e| anyhow::anyhow!("raw get candidate key: {e}"))?;
    println!("\n[candidate key  00 0F <frame BE> <selector>]");
    println!("  key           : {}", hex::encode(&cand_key));
    match &cand_present {
        Some(v) => println!("  present       : YES ({} bytes)", v.len()),
        None => println!("  present       : NO  (bootstrap will silently fall back — clock.rs:556)"),
    }

    // 3. Replay the exact bootstrap lookup and key the forks root the way
    //    `build_genesis_certified_state` does: Poseidon(frame.output).
    println!("\n[bootstrap lookup  get_global_clock_frame_candidate(frame, selector)]");
    let bootstrap_frame = clock.get_global_clock_frame_candidate(qc.frame_number, &selector);
    let root_identity = match &bootstrap_frame {
        Ok(frame) => {
            let h = frame.header.as_ref();
            let fnum = h.map(|h| h.frame_number).unwrap_or(0);
            let rank = h.map(|h| h.rank).unwrap_or(0);
            let output = h.map(|h| h.output.as_slice()).unwrap_or(&[]);
            println!("  returned frame: frame_number={fnum} rank={rank} output_len={}", output.len());
            let id = poseidon_hex(output);
            println!("  Poseidon(output) [forks-root identity] : {id}");
            Some(id)
        }
        Err(e) => {
            println!("  ERROR         : {e}");
            None
        }
    };

    // 4. Canonical frame at that number (what the silent fallback returns).
    println!("\n[canonical frame  get_global_clock_frame(frame)]");
    match clock.get_global_clock_frame(qc.frame_number) {
        Ok(frame) => {
            let output = frame.header.as_ref().map(|h| h.output.as_slice()).unwrap_or(&[]);
            println!("  Poseidon(output): {}", poseidon_hex(output));
        }
        Err(e) => println!("  ERROR         : {e} (no canonical frame at {})", qc.frame_number),
    }

    // 5. Any candidates physically near the head (helps locate the real
    //    certified frame if it landed under a different number/selector).
    let lo = qc.frame_number.saturating_sub(2);
    let hi = qc.frame_number.saturating_add(2);
    println!("\n[candidates in range {lo}..={hi}]");
    match clock.range_global_clock_frame_candidates(lo, hi, 32) {
        Ok(frames) if !frames.is_empty() => {
            for frame in &frames {
                if let Some(h) = frame.header.as_ref() {
                    println!(
                        "  frame={} rank={} Poseidon(output)={}",
                        h.frame_number,
                        h.rank,
                        poseidon_hex(&h.output)
                    );
                }
            }
        }
        Ok(_) => println!("  (none — backend stores no candidate range, or none present)"),
        Err(e) => println!("  ERROR         : {e}"),
    }

    // 6. Verdict.
    println!("\n=== Verdict ===");
    match root_identity.as_deref() {
        Some(id) if id == hex::encode(&selector) => {
            println!("  CONSISTENT: forks-root identity == QC selector.");
            println!("  The bootstrap root matches the QC. The halt is NOT here — re-check the");
            println!("  leader's other skip paths (NoVote / already-proposed).");
        }
        Some(id) => {
            println!("  MISMATCH (this is the halt):");
            println!("    forks-root identity = {id}");
            println!("    QC selector         = {}", hex::encode(&selector));
            if cand_present.is_some() {
                println!("  Candidate key IS present but its output does not hash to the selector —");
                println!("  the stored candidate is wrong/corrupt for this selector.");
            } else {
                println!("  Candidate key is ABSENT — the bootstrap silently fell back to the");
                println!("  canonical frame (clock.rs:556), which is a different frame. The");
                println!("  QC-certified head frame was not carried into the store.");
            }
            std::process::exit(2);
        }
        None => {
            println!("  Could not load any bootstrap frame for the latest QC — the certified");
            println!("  head frame is missing entirely from the store.");
            std::process::exit(2);
        }
    }

    Ok(())
}
