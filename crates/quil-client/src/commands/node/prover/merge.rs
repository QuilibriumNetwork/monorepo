//! `qclient node prover merge` — merge prover seniority configs.
//!
//! Port of `client/cmd/node/prover/proverMerge.go`.
//!
//! Two modes:
//! - default: append the additional config dirs to the primary config's
//!   `engine.multisigProverEnrollmentPaths` and save.
//! - `--dry-run`: estimate the effective seniority score from the four
//!   premainnet retro datasets, matched by peer id.
//!
//! The retro datasets are ~60 MB, so they are loaded at runtime rather
//! than embedded in the binary. They are looked up under
//! `$QUIL_PREMAINNET_DATA` (if set), else the crate's `data/premainnet`
//! directory. (Go embeds them via `go:embed`; the byte-for-byte score
//! math is preserved.)

use std::path::PathBuf;

use serde::Deserialize;

use quil_p2p::ed448_identity::Ed448Identity;

/// Frames-per-day base used by the retro score formulas (`10*6*60*24`).
const FRAMES_PER_DAY: u64 = 10 * 6 * 60 * 24;

#[derive(Debug, Deserialize)]
struct FirstRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
    reward: String,
}

#[derive(Debug, Deserialize)]
struct SecondRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
    #[serde(rename = "janPresence", default)]
    jan: bool,
    #[serde(rename = "febPresence", default)]
    feb: bool,
    #[serde(rename = "marPresence", default)]
    mar: bool,
    #[serde(rename = "aprPresence", default)]
    apr: bool,
    #[serde(rename = "mayPresence", default)]
    may: bool,
}

#[derive(Debug, Deserialize)]
struct Retro {
    #[serde(rename = "peerId")]
    peer_id: String,
}

fn premainnet_dir() -> PathBuf {
    if let Ok(p) = std::env::var("QUIL_PREMAINNET_DATA") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/premainnet")
}

fn load_json<T: for<'de> Deserialize<'de>>(name: &str) -> anyhow::Result<Vec<T>> {
    let path = premainnet_dir().join(name);
    let data = std::fs::read(&path).map_err(|e| {
        anyhow::anyhow!(
            "read {}: {e} (set QUIL_PREMAINNET_DATA to the premainnet dataset dir)",
            path.display()
        )
    })?;
    Ok(serde_json::from_slice(&data)?)
}

/// Peer id (base58 `Qm…`) for a node config directory.
fn peer_id_for_config(dir: &str) -> anyhow::Result<String> {
    let cfg = quil_config::load_config(std::path::Path::new(dir))
        .map_err(|e| anyhow::anyhow!("invalid config directory: {dir}: {e}"))?;
    let id = Ed448Identity::from_config_hex(&cfg.p2p.peer_priv_key)
        .map_err(|e| anyhow::anyhow!("derive peer id for {dir}: {e}"))?;
    Ok(id.peer_id_base58())
}

pub fn run(configs: &[String], dry_run: bool) -> anyhow::Result<()> {
    if configs.len() <= 1 {
        anyhow::bail!("missing configs");
    }
    let primary = &configs[0];
    let others = &configs[1..];

    // Collect peer ids for the primary + all additional configs.
    let mut peer_ids = vec![peer_id_for_config(primary)?];
    for p in others {
        if !std::path::Path::new(p).is_absolute() {
            println!("{p} is not an absolute path");
        }
        peer_ids.push(peer_id_for_config(p)?);
    }

    if dry_run {
        dry_run_score(&peer_ids)
    } else {
        merge_configs(primary, others)
    }
}

fn dry_run_score(peer_ids: &[String]) -> anyhow::Result<()> {
    let member = |pid: &str| peer_ids.iter().any(|p| p == pid);

    let first: Vec<FirstRetro> = load_json("first_retro.json")?;
    let second: Vec<SecondRetro> = load_json("second_retro.json")?;
    let third: Vec<Retro> = load_json("third_retro.json")?;
    let fourth: Vec<Retro> = load_json("fourth_retro.json")?;

    let mut highest_first = 0u64;
    for f in &first {
        if !member(&f.peer_id) {
            continue;
        }
        // These rewards have no decimals, so the integer shortcut matches Go.
        let max = 157208i64;
        let actual: i64 = f.reward.parse().map_err(|_| anyhow::anyhow!("bad reward {:?}", f.reward))?;
        if actual == 0 {
            continue;
        }
        // s = (10*6*60*24*92) / (max/actual)  — integer division, as in Go.
        let denom = (max / actual) as u64;
        if denom == 0 {
            continue;
        }
        let s = (FRAMES_PER_DAY * 92) / denom;
        highest_first = highest_first.max(s);
    }

    let mut highest_second = 0u64;
    for f in &second {
        if !member(&f.peer_id) {
            continue;
        }
        let mut amt = 0u64;
        if f.jan {
            amt += FRAMES_PER_DAY * 31;
        }
        if f.feb {
            amt += FRAMES_PER_DAY * 29;
        }
        if f.mar {
            amt += FRAMES_PER_DAY * 31;
        }
        if f.apr {
            amt += FRAMES_PER_DAY * 30;
        }
        if f.may {
            amt += FRAMES_PER_DAY * 31;
        }
        highest_second = highest_second.max(amt);
    }

    let highest_third = if third.iter().any(|f| member(&f.peer_id)) {
        FRAMES_PER_DAY * 30
    } else {
        0
    };
    let highest_fourth = if fourth.iter().any(|f| member(&f.peer_id)) {
        FRAMES_PER_DAY * 31
    } else {
        0
    };

    println!(
        "Effective seniority score: {}",
        highest_first + highest_second + highest_third + highest_fourth
    );
    Ok(())
}

fn merge_configs(primary: &str, others: &[String]) -> anyhow::Result<()> {
    let dir = std::path::Path::new(primary);
    let mut cfg = quil_config::load_config(dir)
        .map_err(|e| anyhow::anyhow!("invalid config directory: {primary}: {e}"))?;
    for p in others {
        cfg.engine.multisig_prover_enrollment_paths.push(p.clone());
    }
    quil_config::save_config(dir, &cfg).map_err(|e| anyhow::anyhow!("save config: {e}"))?;
    Ok(())
}
