//! One-shot maintenance tool: regenerate the devnet node keystores with Falcon
//! `q-prover-key`s (the network identity post-Falcon-migration) and re-cut every
//! config that depends on the derived values.
//!
//! Pre-migration the devnet fixtures held BLS prover keys (`type: 2`) and their
//! network peer-ids were Ed448-derived. After the Falcon peer-id migration a
//! node's network identity IS its Falcon `q-prover-key`, so three things must be
//! regenerated together to keep the devnet self-consistent:
//!   1. each prover node's `keys.yml` `q-prover-key` → a fresh Falcon key;
//!   2. `p2p.announceListenMultiaddr`'s `/p2p/<peer-id>` → the Falcon-derived id;
//!   3. `engine.genesisSeed` → the concatenation of the 4 archive Falcon prover
//!      pubkeys (897 B each), which IS the devnet genesis prover set
//!      (`resolve_testnet_prover_keys`).
//!
//! The proxy keeps its Ed448 gossip identity (its peer-id is unchanged, so the
//! `bootstrapPeers` entries that point at it stay valid) and is not a prover, so
//! its keystore is left alone.
//!
//! Run from the repo root: `cargo run -p devnet --bin regen-keystores`.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Nodes that own a Falcon prover key (everything but the proxy).
const PROVER_NODES: &[&str] = &[
    "archive-1",
    "archive-2",
    "archive-3",
    "archive-4",
    "client-1",
];
/// Genesis provers for the devnet: the 4 archives. `client-1` joins at runtime
/// via ProverJoin (that's what the enrollment monitor asserts), so it is NOT in
/// the genesis seed.
const GENESIS_NODES: &[&str] = &["archive-1", "archive-2", "archive-3", "archive-4"];
/// Every config that must carry the (identical) genesis seed.
const ALL_CONFIGS: &[&str] = &[
    "archive-1",
    "archive-2",
    "archive-3",
    "archive-4",
    "client-1",
    "proxy",
];

fn cfg_dir(name: &str) -> PathBuf {
    PathBuf::from("crates/devnet/config").join(format!("{name}-config"))
}

fn read_config_yaml(name: &str) -> Result<serde_yaml::Value> {
    let p = cfg_dir(name).join("config.yml");
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    serde_yaml::from_str(&s).with_context(|| format!("parse {}", p.display()))
}

fn encryption_key(v: &serde_yaml::Value) -> Result<String> {
    v.get("key")
        .and_then(|k| k.get("keyManagerFile"))
        .and_then(|k| k.get("encryptionKey"))
        .and_then(|k| k.as_str())
        .map(str::to_string)
        .context("config.yml has no key.keyManagerFile.encryptionKey")
}

/// Base58btc (`Qm…`) peer-id for a Falcon public key.
fn falcon_peer_id_base58(pubkey: &[u8]) -> Result<String> {
    let mh = quil_p2p::peer_id_from_falcon_pubkey(pubkey);
    let pid = quil_p2p::PeerId::from_bytes(&mh).context("peer-id from falcon multihash")?;
    Ok(pid.to_base58())
}

/// Replace the (possibly folded, multi-line) `genesisSeed:` value with a single
/// unquoted-hex line, preserving the key's indentation and the rest of the file.
fn replace_genesis_seed(text: &str, new_hex: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut lines = text.lines().peekable();
    let mut replaced = false;
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("genesisSeed:") {
            let indent = &line[..line.len() - trimmed.len()];
            out.push_str(indent);
            out.push_str("genesisSeed: ");
            out.push_str(new_hex);
            out.push('\n');
            replaced = true;
            // Skip the folded continuation: blank lines or lines indented
            // deeper than the key itself.
            while let Some(next) = lines.peek() {
                let nt = next.trim_start();
                let nindent = next.len() - nt.len();
                if nt.is_empty() || nindent > indent.len() {
                    lines.next();
                } else {
                    break;
                }
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        bail!("no genesisSeed key found");
    }
    Ok(out)
}

/// Set `engine.consensusCommittee` (Falcon pubkey hexes) and
/// `engine.consensusCommitteePeerIds` (base58, parallel order) under `engine:`.
/// These gate CW global consensus — without them the committee is empty and no
/// frames are produced. Idempotent: strips any existing blocks, then inserts
/// fresh ones immediately after the `genesisSeed:` line (same 2-space indent).
fn set_committee_config(text: &str, pubkeys_hex: &[String], peer_ids: &[String]) -> Result<String> {
    // Build the two YAML list blocks.
    let mut block = String::new();
    block.push_str("  consensusCommittee:\n");
    for pk in pubkeys_hex {
        block.push_str("    - ");
        block.push_str(pk);
        block.push('\n');
    }
    block.push_str("  consensusCommitteePeerIds:\n");
    for pid in peer_ids {
        block.push_str("    - ");
        block.push_str(pid);
        block.push('\n');
    }

    // Strip existing consensusCommittee / consensusCommitteePeerIds blocks: the
    // key line (any indent) plus its following deeper-indented list items.
    let mut stripped = String::with_capacity(text.len());
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        if t.starts_with("consensusCommittee:") || t.starts_with("consensusCommitteePeerIds:") {
            let indent = line.len() - t.len();
            while let Some(next) = lines.peek() {
                let nt = next.trim_start();
                let nindent = next.len() - nt.len();
                if nt.is_empty() || nindent > indent {
                    lines.next();
                } else {
                    break;
                }
            }
            continue;
        }
        stripped.push_str(line);
        stripped.push('\n');
    }

    // Insert the fresh block right after the genesisSeed line.
    let mut out = String::with_capacity(stripped.len() + block.len());
    let mut inserted = false;
    for line in stripped.lines() {
        out.push_str(line);
        out.push('\n');
        if !inserted && line.trim_start().starts_with("genesisSeed:") {
            out.push_str(&block);
            inserted = true;
        }
    }
    if !inserted {
        bail!("no genesisSeed key found to anchor committee insertion");
    }
    Ok(out)
}

/// Replace the peer-id after the last `/p2p/` on the `announceListenMultiaddr`
/// line with `new_pid`.
fn replace_announce_peer_id(text: &str, new_pid: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut replaced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("announceListenMultiaddr:") {
            if let Some(idx) = line.rfind("/p2p/") {
                out.push_str(&line[..idx + "/p2p/".len()]);
                out.push_str(new_pid);
                out.push('\n');
                replaced = true;
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        bail!("no announceListenMultiaddr /p2p/ segment found");
    }
    Ok(out)
}

fn main() -> Result<()> {
    if !cfg_dir("archive-1").join("config.yml").exists() {
        bail!("run from the repo root (crates/devnet/config not found)");
    }

    // 1. Regenerate each prover node's Falcon q-prover-key.
    let mut falcon_pub: HashMap<String, Vec<u8>> = HashMap::new();
    for &name in PROVER_NODES {
        let cfg = read_config_yaml(name)?;
        let enc = encryption_key(&cfg)?;
        let keys_path = cfg_dir(name).join("keys.yml");
        let fkm = quil_keys::FileKeyManager::new(
            keys_path.clone(),
            &enc,
            "q-prover-key".to_string(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .with_context(|| format!("open keystore for {name}"))?;
        // Overwrites the old (BLS type-2) q-prover-key entry in place and
        // re-saves keys.yml with a Falcon (type-8) key.
        let pk = fkm
            .create_falcon_key("q-prover-key")
            .with_context(|| format!("create falcon q-prover-key for {name}"))?;
        if pk.len() != quil_crypto::FALCON_PUBLIC_KEY_LEN {
            bail!("{name}: unexpected falcon pubkey len {}", pk.len());
        }
        println!(
            "  {name}: new Falcon q-prover-key  pubkey={}…  peer-id={}",
            &hex::encode(&pk[..6]),
            falcon_peer_id_base58(&pk)?
        );
        falcon_pub.insert(name.to_string(), pk);
    }

    // 2. Build the genesis seed = concat of the 4 archive Falcon pubkeys.
    let mut seed = Vec::with_capacity(GENESIS_NODES.len() * quil_crypto::FALCON_PUBLIC_KEY_LEN);
    for &name in GENESIS_NODES {
        seed.extend_from_slice(&falcon_pub[name]);
    }
    let genesis_seed_hex = hex::encode(&seed);
    println!(
        "\n  genesisSeed: {} archive keys = {} bytes",
        GENESIS_NODES.len(),
        seed.len()
    );

    // The CW GLOBAL consensus committee = the 4 archives, as parallel arrays of
    // Falcon pubkey hex + base58 peer-id (same order). Read from config, NOT the
    // genesis tree, so every node must carry them or the committee resolves empty.
    let committee_pubkeys_hex: Vec<String> = GENESIS_NODES
        .iter()
        .map(|n| hex::encode(&falcon_pub[*n]))
        .collect();
    let committee_peer_ids: Vec<String> = GENESIS_NODES
        .iter()
        .map(|n| falcon_peer_id_base58(&falcon_pub[*n]))
        .collect::<Result<_>>()?;
    println!(
        "  consensusCommittee: {} archive members",
        committee_pubkeys_hex.len()
    );

    // 3. Re-cut every config: genesis seed + committee everywhere, announce
    // peer-id per node.
    for &name in ALL_CONFIGS {
        let path = cfg_dir(name).join("config.yml");
        let mut text = std::fs::read_to_string(&path)?;

        // genesisSeed: present in prover + proxy configs; tolerate absence.
        match replace_genesis_seed(&text, &genesis_seed_hex) {
            Ok(t) => text = t,
            Err(e) => println!("  {name}: genesisSeed not updated ({e})"),
        }

        // Global consensus committee (all configs, anchored after genesisSeed).
        match set_committee_config(&text, &committee_pubkeys_hex, &committee_peer_ids) {
            Ok(t) => text = t,
            Err(e) => println!("  {name}: consensusCommittee not set ({e})"),
        }

        if let Some(pk) = falcon_pub.get(name) {
            let pid = falcon_peer_id_base58(pk)?;
            text = replace_announce_peer_id(&text, &pid)
                .with_context(|| format!("update announce peer-id for {name}"))?;
        }

        std::fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
        println!("  {name}: config.yml re-cut");
    }

    println!(
        "\nDone. Regenerated {} keystores + configs.",
        PROVER_NODES.len()
    );
    Ok(())
}
