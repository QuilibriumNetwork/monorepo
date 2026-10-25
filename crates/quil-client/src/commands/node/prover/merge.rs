//! `qclient node prover merge` — merge prover seniority configs.
//!
//! Port of `client/cmd/node/prover/proverMerge.go`.
//!
//! Two modes:
//! - default: append the additional config dirs to the primary config's
//!   `engine.multisigProverEnrollmentPaths` and save.
//! - `--dry-run`: estimate the effective seniority score from the four
//!   premainnet retro datasets, matched by peer id; then simulate, against
//!   the local node's GLOBAL state, the seniority succession of the prover
//!   the configs' peer keys name to this node's prover: the predecessor,
//!   its seniority, last activity and allocations, the quiet period, the
//!   resulting seniority, and every condition that blocks it.
//!
//! The retro datasets are ~60 MB, so they are loaded at runtime rather
//! than embedded in the binary. They are looked up under
//! `$QUIL_PREMAINNET_DATA` (if set), else the crate's `data/premainnet`
//! directory. (Go embeds them via `go:embed`; the byte-for-byte score
//! math is preserved.)

use std::path::PathBuf;

use serde::Deserialize;

use quil_p2p::ed448_identity::Ed448Identity;
use quil_types::proto::node::{GetHyperedgeDataRequest, GetNodeInfoRequest, GetVertexDataRequest};
use quil_execution::global_intrinsic::seniority_succession::{
    plan_submissions, retro_parts, GlobalReader, GlobalSnapshot, PredecessorState, Submissions,
    SuccessionCandidate, TargetStanding,
};
use quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;

use crate::context::GlobalArgs;

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

pub fn run(configs: &[String]) -> anyhow::Result<()> {
    if configs.len() <= 1 {
        anyhow::bail!("missing configs");
    }
    let primary = &configs[0];
    let others = &configs[1..];
    // Every config must name a peer key.
    peer_keys(configs)?;
    merge_configs(primary, others)
}

/// The peer id and Ed448 public key of each config, warning about relative
/// paths as the merge does.
fn peer_keys(configs: &[String]) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut keys = Vec::with_capacity(configs.len());
    for (index, dir) in configs.iter().enumerate() {
        if index > 0 && !std::path::Path::new(dir).is_absolute() {
            println!("{dir} is not an absolute path");
        }
        keys.push(peer_key(dir)?);
    }
    Ok(keys)
}

fn peer_key(dir: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let cfg = quil_config::load_config(std::path::Path::new(dir))
        .map_err(|e| anyhow::anyhow!("invalid config directory: {dir}: {e}"))?;
    let id = Ed448Identity::from_config_hex(&cfg.p2p.peer_priv_key)
        .map_err(|e| anyhow::anyhow!("derive peer id for {dir}: {e}"))?;
    Ok((id.peer_id_base58(), id.public_key.clone()))
}

/// The keys the node submits with: the primary config's peer key and its
/// `engine.multisigProverEnrollmentPaths`, in the node's order, then any
/// further configs given (which the merge would enroll), without repeats.
fn node_keys(configs: &[String]) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let primary = quil_config::load_config(std::path::Path::new(&configs[0]))
        .map_err(|e| anyhow::anyhow!("invalid config directory: {}: {e}", configs[0]))?;
    let mut dirs: Vec<String> = vec![configs[0].clone()];
    dirs.extend(primary.engine.multisig_prover_enrollment_paths.iter().cloned());
    dirs.extend(configs[1..].iter().cloned());
    let mut keys: Vec<(String, Vec<u8>)> = Vec::new();
    for dir in &dirs {
        let key = peer_key(dir)?;
        if !keys.iter().any(|(_, known)| *known == key.1) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// `--dry-run`: the retro estimate of the configs' peer keys, then what the
/// node would submit under the seniority succession rules, read from the
/// local node.
pub async fn dry_run(global: GlobalArgs, configs: &[String]) -> anyhow::Result<()> {
    if configs.is_empty() {
        anyhow::bail!("missing configs");
    }
    let given = peer_keys(configs)?;
    let peer_ids: Vec<String> = given.iter().map(|(peer, _)| peer.clone()).collect();
    if let Err(error) = dry_run_score(&peer_ids) {
        println!("Effective seniority score: unavailable ({error})");
    }
    println!();
    let keys = node_keys(configs)?;
    let pc = super::ProverCtx::load(global)?;
    match simulate_with_node(&pc, &keys).await {
        Ok(rendered) => print!("{rendered}"),
        Err(error) => println!("Seniority succession: not simulated ({error})"),
    }
    Ok(())
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

/// `…` and the last six characters of `id`, as logs name peers and provers.
fn tail(id: &str) -> String {
    format!("…{}", &id[id.len().saturating_sub(6)..])
}

fn prover_name(address: &[u8; 32]) -> String {
    tail(&hex::encode(address))
}

fn standing_text(standing: &TargetStanding) -> String {
    match standing {
        TargetStanding::Fresh => "unconsumed".into(),
        TargetStanding::Own => "already counts for this prover".into(),
        TargetStanding::Other(prover) => format!("counts for {}", prover_name(prover)),
        TargetStanding::Unusable(reason) => format!("unusable: {reason}"),
    }
}

/// The plan as the dry run prints it: what the node would submit with
/// `peers`' keys at GLOBAL frame `frame` (`plan_submissions`, which the
/// node submits from). `missing_links`: predecessors whose allocation links
/// the node did not return.
pub(crate) fn render_plan(
    frame: u64,
    prover: &[u8; 32],
    peers: &[String],
    plan: &Submissions,
    missing_links: &[[u8; 32]],
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    let _ = writeln!(out, "Seniority merges and successions at GLOBAL frame {frame} (epoch {epoch}):");
    let Some(seniority) = plan.seniority else {
        let _ = writeln!(out, "  This prover:  {}, no prover record on GLOBAL; it must join first.", prover_name(prover));
        return out;
    };
    let _ = writeln!(out, "  This prover:  {}, seniority {seniority}", prover_name(prover));
    if let Some(kick) = plan.kicked {
        let _ = writeln!(out, "  This prover was kicked at frame {kick}; it takes no merge or succession.");
        return out;
    }
    for (peer, (_, standing)) in peers.iter().zip(&plan.keys) {
        let _ = writeln!(out, "  Peer key {}: {}", tail(peer), standing_text(standing));
    }
    match &plan.merge {
        Some(merge) => {
            let _ = writeln!(
                out,
                "  Merge:        {} peer key{}, adds {}; the node submits it with its next seniority merge proposal",
                merge.keys.len(),
                if merge.keys.len() == 1 { "" } else { "s" },
                merge.increment
            );
        }
        None => {
            let _ = writeln!(out, "  Merge:        none (no unconsumed peer key adds seniority)");
        }
    }
    for candidate in &plan.successions {
        render_succession(&mut out, candidate, missing_links.contains(&candidate.predecessor));
    }
    out
}

fn render_succession(out: &mut String, candidate: &SuccessionCandidate, missing_links: bool) {
    use std::fmt::Write;
    let preview = &candidate.preview;
    let _ = writeln!(
        out,
        "  Succession from {} ({} peer key{}):",
        prover_name(&candidate.predecessor),
        candidate.moving,
        if candidate.moving == 1 { "" } else { "s" }
    );
    match &preview.predecessor {
        None => {
            let _ = writeln!(out, "    Predecessor:  no prover record");
        }
        Some(predecessor) => {
            let _ = writeln!(
                out,
                "    Predecessor:  seniority {}, last activity at frame {}",
                predecessor.seniority, preview.end_frame,
            );
            render_allocations(out, predecessor, preview.frame);
            if missing_links {
                let _ = writeln!(
                    out,
                    "    Note:         the node returned no allocation links for it; a node without \
                     hyperedge full_data returns none, so shard allocations may be missing"
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "    Quiet period: {} frames since its last activity ({} required)",
        preview.frame.saturating_sub(preview.end_frame),
        preview.quiet_frames,
    );
    let amounts = &preview.amounts;
    let _ = writeln!(
        out,
        "    Moves:        {} from the predecessor (accrual {}), {} to this prover",
        amounts.debit, amounts.accrual, amounts.credit,
    );
    let _ = writeln!(
        out,
        "    Result:       this prover {} -> {}, predecessor {} -> {}",
        preview.successor_seniority,
        preview.new_seniority,
        preview.predecessor_seniority(),
        preview.predecessor_seniority().saturating_sub(amounts.debit),
    );
    if candidate.submits() {
        let _ = writeln!(out, "    Blocking conditions: none; the node submits it with its next seniority merge proposal.");
    } else {
        let _ = writeln!(out, "    Blocking conditions:");
        for blocker in &preview.blockers {
            let _ = writeln!(out, "      - {blocker}");
        }
    }
}

fn render_allocations(out: &mut String, predecessor: &PredecessorState, frame: u64) {
    use std::fmt::Write;
    if predecessor.allocations.is_empty() {
        let _ = writeln!(out, "    Allocations:  none recorded");
        return;
    }
    let _ = writeln!(out, "    Allocations:  {}", predecessor.allocations.len());
    let mut allocations: Vec<_> = predecessor.allocations.iter().collect();
    allocations.sort_by(|a, b| a.confirmation_filter.cmp(&b.confirmation_filter));
    for allocation in allocations {
        let shard = if allocation.confirmation_filter.is_empty() {
            "global".to_string()
        } else {
            format!("shard {}", hex::encode(&allocation.confirmation_filter))
        };
        let _ = writeln!(out, "      {shard}: {:?}", allocation.effective_status(frame));
    }
}

/// GLOBAL reads served from what was fetched so far; a read of anything not
/// fetched yet is recorded and answered as absent, so the plan runs again
/// once it is fetched.
#[derive(Default)]
struct Prefetch {
    snapshot: GlobalSnapshot,
    fetched_vertices: std::collections::HashSet<[u8; 32]>,
    fetched_hyperedges: std::collections::HashSet<[u8; 32]>,
    wanted_vertices: std::cell::RefCell<std::collections::BTreeSet<[u8; 32]>>,
    wanted_hyperedges: std::cell::RefCell<std::collections::BTreeSet<[u8; 32]>>,
}

impl GlobalReader for Prefetch {
    fn vertex(&self, address: &[u8; 32]) -> quil_types::error::Result<Option<Vec<u8>>> {
        if !self.fetched_vertices.contains(address) {
            self.wanted_vertices.borrow_mut().insert(*address);
            return Ok(None);
        }
        self.snapshot.vertex(address)
    }

    fn hyperedge(&self, address: &[u8; 32]) -> quil_types::error::Result<Option<Vec<u8>>> {
        if !self.fetched_hyperedges.contains(address) {
            self.wanted_hyperedges.borrow_mut().insert(*address);
            return Ok(None);
        }
        self.snapshot.hyperedge(address)
    }
}

/// Fetching rounds, each fetching the reads the plan asked for and could
/// not yet answer (markers, then predecessors, then their allocations); a
/// few suffice, the bound only stops a node that keeps answering new ones.
const PREFETCH_ROUNDS: usize = 80;

/// Read what the plan needs from the local node over RPC, then render it
/// at the frame after the node's GLOBAL head, with the node's epoch length.
async fn simulate_with_node(pc: &super::ProverCtx, keys: &[(String, Vec<u8>)]) -> anyhow::Result<String> {
    let mut client = pc.connect().await?;
    let info = client
        .get_node_info(tonic::Request::new(GetNodeInfoRequest::default()))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    if info.epoch_length_frames > 0 {
        quil_types::consensus::set_epoch_length_frames(info.epoch_length_frames);
    }
    quil_types::consensus::init_seniority_succession_epoch(pc.node_config.p2p.network);
    let signer = pc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key: {e}"))?;
    let prover = quil_crypto::poseidon::hash_bytes_to_32(signer.public_key())
        .map_err(|e| anyhow::anyhow!("prover address: {e}"))?;
    let frame = info.last_global_head_frame.saturating_add(1);
    let public_keys: Vec<Vec<u8>> = keys.iter().map(|(_, key)| key.clone()).collect();
    let peers: Vec<String> = keys.iter().map(|(peer, _)| peer.clone()).collect();

    let mut reads = Prefetch::default();
    for _ in 0..PREFETCH_ROUNDS {
        let plan = plan_submissions(&reads, frame, &prover, &public_keys, &retro_parts)?;
        let vertices = std::mem::take(&mut *reads.wanted_vertices.borrow_mut());
        let hyperedges = std::mem::take(&mut *reads.wanted_hyperedges.borrow_mut());
        if vertices.is_empty() && hyperedges.is_empty() {
            let missing_links: Vec<[u8; 32]> = plan
                .successions
                .iter()
                .map(|candidate| candidate.predecessor)
                .filter(|predecessor| !reads.snapshot.hyperedges.contains_key(predecessor))
                .collect();
            return Ok(render_plan(frame, &prover, &peers, &plan, &missing_links));
        }
        for address in vertices {
            if let Some(blob) = fetch_vertex(&mut client, &address).await? {
                reads.snapshot.vertices.insert(address, blob);
            }
            reads.fetched_vertices.insert(address);
        }
        for address in hyperedges {
            let blob = fetch_hyperedge(&mut client, &address).await?;
            if !blob.is_empty() {
                reads.snapshot.hyperedges.insert(address, blob);
            }
            reads.fetched_hyperedges.insert(address);
        }
    }
    anyhow::bail!("GLOBAL reads did not settle after {PREFETCH_ROUNDS} rounds")
}

type NodeClient = quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>;

fn global_id(address: &[u8; 32]) -> Vec<u8> {
    let mut id = GLOBAL_INTRINSIC_ADDRESS.to_vec();
    id.extend_from_slice(address);
    id
}

async fn fetch_vertex(client: &mut NodeClient, address: &[u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
    let response = client
        .get_vertex_data(tonic::Request::new(GetVertexDataRequest {
            address: global_id(address),
            full_data: true,
            ..Default::default()
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get vertex data: {e}"))?
        .into_inner();
    Ok(Some(response.raw_data).filter(|blob| !blob.is_empty()))
}

/// A prover's hyperedge, which links its allocations; empty when absent or
/// when the node predates `full_data` on hyperedge reads.
async fn fetch_hyperedge(client: &mut NodeClient, address: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    Ok(client
        .get_hyperedge_data(tonic::Request::new(GetHyperedgeDataRequest {
            address: global_id(address),
            full_data: true,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get hyperedge data: {e}"))?
        .into_inner()
        .raw_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::global_intrinsic::materialize::{
        allocation_address, create_allocation_vertex_tree, create_prover_vertex_tree, create_spent_merge_tree,
        extend_prover_allocation_hyperedge_blob, prover_address_from_pubkey, spent_join_merge_address,
    };
    use quil_execution::global_schema::write_field;
    use quil_execution::prover_registry::vertex_tree_to_blob;
    use quil_types::consensus::set_seniority_succession_epoch_for_thread;

    /// The first frame of epoch 1,250.
    const F: u64 = 900_000;
    const PEER: &str = "QmFixturePeerKeyOfTheOldNode2xYz9Q";

    fn key(byte: u8) -> Vec<u8> {
        vec![byte; 897]
    }

    fn address(byte: u8) -> [u8; 32] {
        prover_address_from_pubkey(&key(byte)).unwrap()
    }

    /// GLOBAL as a node would return it: this prover Y (key 0xB2) with
    /// 100,000; the old prover X (key 0xA1) with 5,000,000, last active 10,000
    /// frames ago on a data shard it no longer re-confirms; the peer key's
    /// join marker naming X.
    fn snapshot() -> GlobalSnapshot {
        let mut snapshot = GlobalSnapshot::default();
        let mut x = create_prover_vertex_tree(&key(0xA1), 5_000_000).unwrap();
        write_field(&mut x, "prover:Prover", "LastSeniorityFrameNumber", &(F - 10_000).to_be_bytes()).unwrap();
        snapshot.vertices.insert(address(0xA1), vertex_tree_to_blob(&x));
        let y = create_prover_vertex_tree(&key(0xB2), 100_000).unwrap();
        snapshot.vertices.insert(address(0xB2), vertex_tree_to_blob(&y));
        let marker = create_spent_merge_tree(&address(0xA1)).unwrap();
        snapshot.vertices.insert(spent_join_merge_address(&[0x11; 57]).unwrap(), vertex_tree_to_blob(&marker));
        add_allocation(&mut snapshot, &[0x5A; 32], 1, &[
            ("JoinFrameNumber", F - 100_000),
            ("Epoch", 1_240),
            ("LastSignedFrameNumber", F - 10_000),
        ]);
        snapshot
    }

    fn add_allocation(snapshot: &mut GlobalSnapshot, filter: &[u8], status: u8, fields: &[(&str, u64)]) {
        let at = allocation_address(&key(0xA1), filter).unwrap();
        let mut tree = create_allocation_vertex_tree(&address(0xA1), filter, 0).unwrap();
        write_field(&mut tree, "allocation:ProverAllocation", "Status", &[status]).unwrap();
        for (field, value) in fields {
            write_field(&mut tree, "allocation:ProverAllocation", field, &value.to_be_bytes()).unwrap();
        }
        snapshot.vertices.insert(at, vertex_tree_to_blob(&tree));
        let existing = snapshot.hyperedges.get(&address(0xA1)).cloned().unwrap_or_default();
        let hyperedge = extend_prover_allocation_hyperedge_blob(&existing, &[(at, &tree)]).unwrap();
        snapshot.hyperedges.insert(address(0xA1), hyperedge);
    }

    /// The peer key is worth 5,000,000 in the first retro epoch.
    fn fixture_retro(keys: &[Vec<u8>]) -> [u64; 5] {
        if keys.iter().any(|key| key[0] == 0x11) { [5_000_000, 0, 0, 0, 0] } else { [0; 5] }
    }

    fn simulate(snapshot: &GlobalSnapshot, missing_links: &[[u8; 32]]) -> String {
        let plan = plan_submissions(snapshot, F, &address(0xB2), &[vec![0x11; 57]], &fixture_retro).unwrap();
        let rendered = render_plan(F, &address(0xB2), &[PEER.to_string()], &plan, missing_links);
        // The dry run's output for the fixture, for review.
        println!("{rendered}");
        rendered
    }

    #[test]
    fn the_dry_run_shows_an_eligible_succession() {
        set_seniority_succession_epoch_for_thread(Some(1_200));
        let (x, y) = (prover_name(&address(0xA1)), prover_name(&address(0xB2)));
        let shard = hex::encode([0x5A; 32]);
        let peer = tail(PEER);
        assert_eq!(simulate(&snapshot(), &[]), format!(
            "Seniority merges and successions at GLOBAL frame 900000 (epoch 1250):\n\
             \x20 This prover:  {y}, seniority 100000\n\
             \x20 Peer key {peer}: counts for {x}\n\
             \x20 Merge:        none (no unconsumed peer key adds seniority)\n\
             \x20 Succession from {x} (1 peer key):\n\
             \x20   Predecessor:  seniority 5000000, last activity at frame 890000\n\
             \x20   Allocations:  1\n\
             \x20     shard {shard}: ExpiredEpoch\n\
             \x20   Quiet period: 10000 frames since its last activity (1440 required)\n\
             \x20   Moves:        5000000 from the predecessor (accrual 0), 5000000 to this prover\n\
             \x20   Result:       this prover 100000 -> 5100000, predecessor 5000000 -> 0\n\
             \x20   Blocking conditions: none; the node submits it with its next seniority merge proposal.\n"
        ));
    }

    #[test]
    fn the_dry_run_lists_every_blocking_condition() {
        set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        let mut snapshot = snapshot();
        add_allocation(&mut snapshot, &[0x6B; 32], 2, &[("PauseFrameNumber", F - 500)]);
        let (x, y) = (prover_name(&address(0xA1)), prover_name(&address(0xB2)));
        let (data, paused) = (hex::encode([0x5A; 32]), hex::encode([0x6B; 32]));
        let peer = tail(PEER);
        assert_eq!(simulate(&snapshot, &[address(0xA1)]), format!(
            "Seniority merges and successions at GLOBAL frame 900000 (epoch 1250):\n\
             \x20 This prover:  {y}, seniority 100000\n\
             \x20 Peer key {peer}: counts for {x}\n\
             \x20 Merge:        none (no unconsumed peer key adds seniority)\n\
             \x20 Succession from {x} (1 peer key):\n\
             \x20   Predecessor:  seniority 5000000, last activity at frame 899500\n\
             \x20   Allocations:  2\n\
             \x20     shard {data}: ExpiredEpoch\n\
             \x20     shard {paused}: Paused\n\
             \x20   Note:         the node returned no allocation links for it; a node without hyperedge full_data returns none, so shard allocations may be missing\n\
             \x20   Quiet period: 500 frames since its last activity (1440 required)\n\
             \x20   Moves:        5000000 from the predecessor (accrual 0), 5000000 to this prover\n\
             \x20   Result:       this prover 100000 -> 5100000, predecessor 5000000 -> 0\n\
             \x20   Blocking conditions:\n\
             \x20     - seniority succession is not active on this network (no activation epoch is set)\n\
             \x20     - the predecessor's allocation on shard {paused} is Paused\n\
             \x20     - the predecessor was active too recently: 940 more frames without activity (until frame 900940)\n"
        ));
    }

    #[test]
    fn the_dry_run_proposes_a_merge_of_an_unconsumed_key() {
        set_seniority_succession_epoch_for_thread(Some(1_200));
        let mut snapshot = snapshot();
        snapshot.vertices.remove(&spent_join_merge_address(&[0x11; 57]).unwrap());
        let rendered = simulate(&snapshot, &[]);
        assert!(rendered.contains(&format!("Peer key {}: unconsumed\n", tail(PEER))));
        assert!(rendered.ends_with(
            "  Merge:        1 peer key, adds 5000000; the node submits it with its next seniority merge proposal\n"
        ));
    }
}
