//! `--gen0-preflight <store>`: READ-ONLY generation-zero readiness report for a
//! STOPPED node.
//!
//! Opens the master store and any worker stores read-only (a point-in-time
//! view of a stopped store; never a copy) and writes one JSON line per
//! registered application shard, between a header line naming the checkpoint
//! every line is bound to and a summary line. Per shard it reports what the
//! migration needs:
//!
//! * **committee and certificate compatibility**: the eligible committee that
//!   generation zero would register, the registry's active set (non-Falcon keys
//!   make them differ), and whether the local head frame's epoch-0 certificate
//!   verifies against the eligible committee;
//! * **roots**: the committed state roots of the store holding the shard, and
//!   its materialized cursor against its head frame;
//! * **history availability**: the outgoing-history records (fee total,
//!   settlements, spends, accumulator digest) of the last `window` frames, which
//!   a member needs to vote its generation-0 seal (frames anchored below the
//!   relay activation frame need none);
//! * **handoff status**: session, legacy tip, managed application, and, on an
//!   archive (whose grid is authoritative), whether the grid still registers
//!   the filter;
//! * **blockers**.
//!
//! Memory is bounded by the prover registry scan (one row per allocation), the
//! shard list, and one shard's window at a time; output streams line by line.
//! A resumed run (`resume_after`) must present the checkpoint it resumes
//! (`expect_checkpoint`): results from different store states are never mixed.
//!
//! **Live stores** (`live`): each store is opened read-only beside the running
//! node, taking no lock, as the point-in-time view of its files and WAL at
//! open; nothing is written. Every table file is opened up front, so the
//! node's compactions cannot remove one the view still reads. (A RocksDB
//! secondary instance was not usable: it supports no snapshots, which the clock
//! store's frame reads take.) The node keeps writing, so the checkpoint moves
//! between runs: a live run is repeated whole, never resumed.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use quil_execution::global_intrinsic::handoff::{self, legacy, schedule};
use quil_execution::hypergraph_state::HypergraphState;
use quil_types::store::{ClockStore, ShardsStore};
use serde_json::json;
use sha2::{Digest as _, Sha256};

pub struct Options {
    pub workers: Vec<PathBuf>,
    /// Frames of outgoing history checked below each shard's head.
    pub window: u64,
    /// Skip shards whose filter sorts at or before this one (hex).
    pub resume_after: Option<Vec<u8>>,
    /// Refuse to run unless the stores are at this checkpoint (hex).
    pub expect_checkpoint: Option<String>,
    pub network: u8,
    /// The stores belong to an archive that is not a committee member. It
    /// votes no seal, and sequenced ingest materializes only the application
    /// frames GLOBAL referenced, so its cursor and history lag its clock head:
    /// those are reported as notes, not blockers.
    pub archive: bool,
    /// The stores belong to a running node (see the module docs).
    pub live: bool,
}

/// One opened store: the master (GLOBAL state, registry, grid) or a worker
/// (application frames, history records, application state).
pub struct Store {
    pub label: String,
    _db: quil_store::RocksDb,
    raw: quil_forest::CoordinatedDb,
    clock: quil_store::RocksClockStore,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
}

impl Store {
    pub fn open_read_only(label: &str, path: &Path, network: u8) -> anyhow::Result<Self> {
        let db = quil_store::RocksDb::open_for_read_only(path)
            .map_err(|e| anyhow::anyhow!("open {} read-only: {e}", path.display()))?;
        Ok(Self::from_db(label, db, network))
    }

    /// Open a running node's store: read-only, no lock, every file held open.
    pub fn open_live(label: &str, path: &Path, network: u8) -> anyhow::Result<Self> {
        let db = quil_store::RocksDb::open_for_read_only_live(path)
            .map_err(|e| anyhow::anyhow!("open {} read-only beside its node: {e}", path.display()))?;
        Ok(Self::from_db(label, db, network))
    }

    pub fn from_db(label: &str, db: quil_store::RocksDb, network: u8) -> Self {
        let raw = db.inner();
        let hg = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg.as_ref(), false, network == 0);
        Self { label: label.to_string(), clock: quil_store::RocksClockStore::new(raw.clone()), raw, crdt, _db: db }
    }
}

/// The eligible committee generation zero would register for `(filter, frame)`
/// and the size of the registry's active set there.
pub type CommitteeSource<'a> = dyn Fn(&[u8], u64) -> (Vec<Vec<u8>>, usize) + 'a;

/// Evidence for a head certificate the rebuilt committee rejects.
pub trait Diagnose {
    /// Named candidate committees (Falcon keys) to try the certificate
    /// against, each one a hypothesis about how its committee was formed.
    fn candidates(&self, filter: &[u8], anchor: u64) -> Vec<(&'static str, Vec<Vec<u8>>)>;
    /// The latest `LastActiveFrameNumber` on `filter`'s allocations. GLOBAL
    /// stamps it when it accepts a header their holders signed, and also at
    /// every join confirm and epoch re-confirm, so it shows recent activity,
    /// not acceptance on its own.
    fn last_activity(&self, filter: &[u8]) -> Option<u64>;
    /// Who signed `certificate` (in `namespace`), found among every registered
    /// prover's key, with each signer's allocations and their effective status
    /// at `anchor`.
    fn signers(&self, _certificate: &[u8], _namespace: &[u8], _anchor: u64) -> serde_json::Value {
        serde_json::Value::Null
    }
    /// What the diagnostics could read, for the report's header line.
    fn describe(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// The node's own view beside the committed-state scan: the prover registry
/// the legacy committees were formed from, and neighbouring filters' members
/// (a split or merge moves allocations between a parent and its children).
struct NodeDiagnose<'a> {
    scan: &'a quil_execution::prover_registry::CommittedProverScan,
    registry: Result<quil_execution::prover_registry::SharedProverRegistry, String>,
    /// Every registered prover: `(address, public key)`.
    provers: Vec<(Vec<u8>, Vec<u8>)>,
}

/// One allocation as `<filter suffix>:<raw status>/<effective status at the
/// anchor>/epoch <registered epoch>/confirmed <join confirm frame>`.
fn describe_allocation(allocation: &quil_types::consensus::ProverAllocationInfo, anchor: u64) -> String {
    let filter = &allocation.confirmation_filter;
    let suffix = match filter.len() {
        0 => "global".to_string(),
        32 => "app".to_string(),
        n if n > 32 => hex::encode(&filter[32..]),
        _ => hex::encode(filter),
    };
    format!(
        "{suffix}:{:?}/{:?}/epoch {}/confirmed {}",
        allocation.status,
        allocation.effective_status(anchor),
        allocation.epoch,
        allocation.join_confirm_frame_number,
    )
}

/// Sorted, unique Falcon keys: the only keys a Simplex committee can hold.
fn falcon_keys(keys: impl IntoIterator<Item = Vec<u8>>) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = keys
        .into_iter()
        .filter(|key| quil_cw_consensus::falcon_base::FalconPublicKey::from_bytes(key).is_some())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Shallower filters holding `filter`'s range, nearest first.
fn ancestors(filter: &[u8]) -> Vec<Vec<u8>> {
    let Some((app, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) else { return Vec::new() };
    (1..bits.len()).rev().map(|depth| quil_forest::encode_shard_bit_path(&app, &bits[..depth])).collect()
}

/// The two filters one level below `filter`.
fn children(filter: &[u8]) -> Vec<Vec<u8>> {
    let Some((app, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) else { return Vec::new() };
    [false, true]
        .map(|bit| quil_forest::encode_shard_bit_path(&app, &[bits.as_slice(), &[bit]].concat()))
        .to_vec()
}

impl Diagnose for NodeDiagnose<'_> {
    fn candidates(&self, filter: &[u8], anchor: u64) -> Vec<(&'static str, Vec<Vec<u8>>)> {
        let active = |filter: &[u8]| schedule::desired_members(self.scan, filter, anchor);
        let allocated = |filter: &[u8]| -> Vec<Vec<u8>> {
            self.scan.all_on_filter(filter).into_iter().map(|(key, _)| key).collect()
        };
        let ancestors = ancestors(filter);
        let parent = ancestors.first().cloned();
        let mut out = Vec::new();
        if let Ok(registry) = &self.registry {
            use quil_types::consensus::ProverRegistry as _;
            let members = registry.get_active_provers(filter, anchor).unwrap_or_default();
            out.push(("registry_at_anchor", falcon_keys(members.into_iter().map(|prover| prover.public_key))));
        }
        out.push(("all_allocations", falcon_keys(allocated(filter))));
        if let Some(parent) = parent.as_ref() {
            out.push(("with_parent_at_anchor", falcon_keys([active(filter), active(parent)].concat())));
            out.push(("with_parent_all_allocations", falcon_keys([allocated(filter), allocated(parent)].concat())));
        }
        if ancestors.len() > 1 {
            let all: Vec<Vec<u8>> = std::iter::once(filter.to_vec()).chain(ancestors).flat_map(|f| active(&f)).collect();
            out.push(("with_ancestors_at_anchor", falcon_keys(all)));
        }
        let below: Vec<Vec<u8>> = children(filter).iter().flat_map(|child| active(child)).collect();
        if !below.is_empty() {
            out.push(("with_children_at_anchor", falcon_keys([active(filter), below].concat())));
        }
        out
    }

    fn last_activity(&self, filter: &[u8]) -> Option<u64> {
        use quil_types::consensus::ProverRegistry as _;
        let provers = self.registry.as_ref().ok()?.get_provers(filter).ok()?;
        provers
            .iter()
            .flat_map(|prover| prover.allocations.iter())
            .filter(|allocation| allocation.confirmation_filter == filter)
            .map(|allocation| allocation.last_active_frame_number)
            .max()
    }

    fn signers(&self, certificate: &[u8], namespace: &[u8], anchor: u64) -> serde_json::Value {
        use quil_types::consensus::ProverRegistry as _;
        let keys: Vec<Vec<u8>> = self.provers.iter().map(|(_, key)| key.clone()).collect();
        let Some(found) = quil_cw_consensus::app_cert::identify_signers(certificate, namespace, &keys) else {
            return json!("undecodable certificate");
        };
        let signers: Vec<serde_json::Value> = found
            .iter()
            .map(|(index, key)| {
                let address = self.provers.iter().find(|(_, known)| known == key).map(|(address, _)| address);
                let allocations: Option<Vec<String>> = address
                    .and_then(|address| self.registry.as_ref().ok()?.get_prover_info(address).ok().flatten())
                    .map(|info| info.allocations.iter().map(|allocation| describe_allocation(allocation, anchor)).collect());
                json!({ "index": index, "prover": address.map(|address| hex8(address)), "allocations": allocations })
            })
            .collect();
        json!({ "identified": found.len(), "signers": signers })
    }

    fn describe(&self) -> serde_json::Value {
        json!({ "registered_provers": self.provers.len(), "registry": match &self.registry {
            Ok(_) => "refreshed from the master store".to_string(),
            Err(error) => format!("unavailable: {error}"),
        } })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub checkpoint: String,
    pub shards: usize,
    pub ready: usize,
    pub blocked: usize,
    pub managed: usize,
    /// Shards with no session and no legacy history: nothing to migrate.
    pub without_history: usize,
    /// Legacy frames of a filter the archive's grid no longer registers:
    /// GLOBAL registers generation zero only for grid shards.
    pub off_grid: usize,
    /// Legacy shards with nothing blocking them whose head is anchored in an
    /// earlier epoch than the census: GLOBAL waits for a head certified in the
    /// registering epoch, so these are not registered yet.
    pub pending: usize,
}

fn hex8(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

/// The shards to report, sorted, and the registered grid (what GLOBAL
/// reconciles): the grid and every shard any store holds frames of. A regular
/// node's master keeps its grid read-only, so its workers' shards are found in
/// their clock stores.
fn shard_filters(stores: &[&Store]) -> anyhow::Result<(Vec<Vec<u8>>, std::collections::HashSet<Vec<u8>>)> {
    let shards = quil_store::RocksShardsStore::new(stores[0].raw.clone());
    let grid: std::collections::HashSet<Vec<u8>> = shards
        .range_app_shards()?
        .into_iter()
        .filter(|row| row.shard_key.len() >= 35)
        .map(|row| quil_forest::shard_prefix_to_filter(&row.shard_key[3..35], &row.prefix))
        .collect();
    let mut filters: Vec<Vec<u8>> = grid.iter().cloned().collect();
    use quil_store::encoding as e;
    let prefix = [e::CLOCK_FRAME, e::INDEX_LATEST | e::CLOCK_SHARD_FRAME];
    for store in stores {
        let mut it = store.raw.raw_iterator();
        it.seek(prefix);
        while let Some(key) = it.key() {
            if !key.starts_with(&prefix) {
                break;
            }
            let filter = &key[prefix.len()..];
            if (32..=quil_cw_consensus::handoff::MAX_FILTER_BYTES).contains(&filter.len()) {
                filters.push(filter.to_vec());
            }
            it.next();
        }
    }
    filters.sort();
    filters.dedup();
    Ok((filters, grid))
}

/// The GLOBAL head, cursor and every store's sequence number, hashed: a stopped
/// store keeps it; any write changes it.
fn checkpoint(master: &Store, stores: &[&Store]) -> (String, serde_json::Value) {
    let head = master.clock.get_latest_global_clock_frame().ok().and_then(|f| f.header);
    let (number, output) = head.map_or((0, Vec::new()), |h| (h.frame_number, h.output));
    let cursor = master.clock.get_global_materialized_cursor();
    let mut hash = Sha256::new();
    hash.update(b"quil/gen0-preflight/checkpoint/v1");
    hash.update(number.to_be_bytes());
    hash.update(&output);
    hash.update(cursor.unwrap_or(u64::MAX).to_be_bytes());
    let mut sequences = Vec::new();
    for store in stores {
        let sequence = store.raw.latest_sequence_number();
        hash.update((store.label.len() as u64).to_be_bytes());
        hash.update(store.label.as_bytes());
        hash.update(sequence.to_be_bytes());
        sequences.push(json!({ "store": store.label, "sequence": sequence }));
    }
    let id = hex::encode(hash.finalize());
    let detail = json!({
        "global_head": number,
        "global_head_output": hex8(&output),
        "global_cursor": cursor,
        "stores": sequences,
    });
    (id, detail)
}

/// Outgoing-history records a frame must hold for the history root. A frame
/// anchored below the relay activation frame relays nothing and needs none:
/// the mainnet build wrote no such records.
fn missing_history(store: &Store, filter: &[u8], frame: u64) -> Vec<&'static str> {
    use quil_store::encoding as e;
    if quil_engine::app_engine::legacy_relay_frame(&store.clock, filter, frame) {
        return Vec::new();
    }
    let checks: [(&str, Vec<u8>); 4] = [
        ("fee_total", e::clock_shard_frame_fee_total_key(filter, frame)),
        ("settlements", e::clock_shard_frame_settlements_key(filter, frame)),
        ("spends", e::clock_shard_frame_spends_key(filter, frame)),
        ("accumulator", e::clock_shard_frame_accumulator_key(filter, frame)),
    ];
    checks
        .into_iter()
        .filter(|(_, key)| !matches!(store.raw.get(key), Ok(Some(_))))
        .map(|(name, _)| name)
        .collect()
}

/// A head whose committee no candidate reproduces has its signers named when
/// it is anchored within this many epochs of the census.
const IDENTIFY_EPOCHS: u64 = 3;

/// One shard's report and its blockers.
pub fn shard_report(
    master: &Store,
    stores: &[&Store],
    committee: &CommitteeSource<'_>,
    census_frame: u64,
    filter: &[u8],
    in_grid: Option<bool>,
    window: u64,
    archive: bool,
    diagnose: Option<&dyn Diagnose>,
) -> anyhow::Result<(serde_json::Value, Vec<String>)> {
    let global = HypergraphState::new(master.crdt.clone());
    let mut blockers = Vec::new();
    // Member-readiness items a non-member archive reports for information.
    let mut notes: Vec<String> = Vec::new();

    // Handoff status.
    let head_session = handoff::head(&global, filter)?;
    let session = match &head_session {
        Some(session) => {
            let status = handoff::status(&global, &session.id()?)?;
            json!({ "generation": session.generation, "members": session.members.len(),
                    "base_frame": session.base_frame, "status": format!("{status:?}") })
        }
        None => serde_json::Value::Null,
    };
    let tip = legacy::tip(&global, filter)?;
    let managed = handoff::manages_application(&global, filter)?;

    // The store holding the shard's highest local frame.
    let holder = stores
        .iter()
        .filter_map(|store| store.clock.get_latest_shard_clock_frame(filter).ok().map(|frame| (store, frame)))
        .max_by_key(|(_, frame)| frame.header.as_ref().map_or(0, |h| h.frame_number));
    let (eligible, registry_active) = committee(filter, census_frame);
    // Only a shard with legacy history migrates: no session yet, and local
    // frames or a legacy tip. Managed shards and member-less, frameless shards
    // (a deep split's spine) have nothing to migrate, and neither has a filter
    // the (authoritative) grid no longer registers.
    let history = holder.is_some() || tip.is_some();
    let off_grid = head_session.is_none() && history && in_grid == Some(false);
    let migrates = head_session.is_none() && history && !off_grid;
    let status = match (&head_session, migrates) {
        (Some(_), _) => "managed",
        (None, true) => "legacy",
        (None, false) if off_grid => "off-grid",
        (None, false) => "no-legacy-history",
    };
    if off_grid {
        notes.push("not in the registered grid: GLOBAL never registers it as generation zero".into());
    }
    if migrates && eligible.is_empty() {
        blockers.push("no eligible committee: generation zero cannot be registered".into());
    }
    if migrates && registry_active != eligible.len() {
        blockers.push(format!(
            "registry active set ({registry_active}) differs from the eligible Falcon committee ({}): \
             the certifying committee would not be the registered one",
            eligible.len()
        ));
    }

    let mut local = serde_json::Value::Null;
    let mut d4_pending = false;
    if let Some((store, frame)) = holder {
        let header = frame.header.clone().unwrap_or_default();
        let number = header.frame_number;
        // The registering-epoch rule, as `handoff_legacy::migrate` applies it:
        // GLOBAL registers a shard only from a tip anchored in the registering
        // epoch. Before activation no tip is recorded, so the local head
        // stands in for it.
        let tip_anchor = tip.as_ref().map_or(header.global_frame_number, |tip| tip.anchor);
        use quil_types::consensus::epoch_for_frame;
        d4_pending = migrates && epoch_for_frame(tip_anchor) != epoch_for_frame(census_frame);
        if d4_pending {
            notes.push(format!(
                "pending (D4): head anchored in epoch {}, before the census epoch {}; GLOBAL registers it only \
                 from a head certified in the registering epoch, and checks that head's committee then",
                epoch_for_frame(tip_anchor), epoch_for_frame(census_frame),
            ));
        }
        let certificate = header
            .public_key_signature_bls48581
            .as_ref()
            .and_then(|sig| quil_cw_consensus::app_cert::unwrap_cert_from_header(&sig.signature));
        let (kind, compatible) = match certificate {
            Some(cert) => match quil_cw_consensus::app_cert::unverified_finalization_epoch(cert) {
                Some(0) => {
                    let namespace = [b"appshard".as_slice(), filter].concat();
                    let digest = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
                    let verifies = |members: &[Vec<u8>]| {
                        quil_cw_consensus::app_cert::check_finalization(cert, members, &namespace, digest)
                            .map(|_| ())
                            .map_err(|reason| format!("{reason:?}"))
                    };
                    let at_census = verifies(&eligible);
                    let at_anchor = verifies(&committee(filter, header.global_frame_number).0);
                    // Decoding is bounded by the rebuilt committee's size, so an
                    // `Encoding` failure hides how many members really signed.
                    let signers = quil_cw_consensus::app_cert::unverified_signers(cert)
                        .map(|(committee, signed)| json!({ "committee": committee, "signed": signed }));
                    if migrates && !d4_pending {
                        if let Err(reason) = &at_census {
                            blockers.push(format!(
                                "head certificate does not verify against the eligible committee: {reason}"
                            ));
                        }
                    }
                    // Which committee did sign it? Each candidate is exact or
                    // fails: a certificate verifies only against its committee.
                    let search = match diagnose {
                        Some(diagnose) if at_anchor.is_err() => {
                            let tried: Vec<_> = diagnose
                                .candidates(filter, header.global_frame_number)
                                .into_iter()
                                .map(|(name, members)| {
                                    let result = verifies(&members).err().unwrap_or_else(|| "verifies".into());
                                    (name, json!({ "size": members.len(), "result": result }))
                                })
                                .collect();
                            let matched: Vec<&str> = tried.iter()
                                .filter(|(_, tried)| tried["result"] == "verifies")
                                .map(|(name, _)| *name)
                                .collect();
                            let tried: serde_json::Map<_, _> =
                                tried.into_iter().map(|(name, tried)| (name.to_string(), tried)).collect();
                            // Naming the signers checks every registered key against
                            // every signature: only for heads recent enough that
                            // their committee still bears on registration.
                            let recent = epoch_for_frame(header.global_frame_number) + IDENTIFY_EPOCHS
                                >= epoch_for_frame(census_frame);
                            let signers = if matched.is_empty() && recent {
                                diagnose.signers(cert, &namespace, header.global_frame_number)
                            } else {
                                serde_json::Value::Null
                            };
                            json!({ "candidates": tried, "matched": matched, "signers": signers })
                        }
                        _ => serde_json::Value::Null,
                    };
                    ("cw-epoch-0 (legacy namespace)".to_string(),
                     json!({ "eligible_committee": at_census.err().unwrap_or_else(|| "verifies".into()),
                             "committee_at_anchor": at_anchor.err().unwrap_or_else(|| "verifies".into()),
                             "certificate_signers": signers,
                             "committee_search": search }))
                }
                Some(epoch) => (format!("cw-session-epoch-{epoch}"), serde_json::Value::Null),
                None => ("cw-malformed".into(), serde_json::Value::Null),
            },
            None if header.public_key_signature_bls48581.is_some() => {
                if migrates {
                    blockers.push("head is certified by a legacy aggregate signature, not a Simplex epoch-0 \
                                   certificate: the legacy committee cannot seal as generation zero".into());
                }
                ("bls-aggregate".into(), serde_json::Value::Null)
            }
            None => ("none".into(), serde_json::Value::Null),
        };

        let cursor = store
            .crdt
            .read_frame_cursor(&quil_store::encoding::consensus_materialized_cursor_key(filter))
            .ok();
        if cursor != Some(number) && migrates {
            let item = format!(
                "materialized cursor {cursor:?} is not the head frame {number}: a seal needs its checkpoint materialized"
            );
            if archive { notes.push(item) } else { blockers.push(item) }
        }
        let roots = match store.crdt.capture_committed_shard(filter) {
            Ok(snapshot) => json!(snapshot.roots.iter().map(|root| hex8(root)).collect::<Vec<_>>()),
            Err(error) => json!(format!("unavailable: {error}")),
        };

        // History of the last `window` frames (frame 0 is never materialized).
        let first = number.saturating_sub(window.saturating_sub(1)).max(1);
        let (mut checked, mut missing, mut first_missing) = (0u64, 0u64, None);
        for frame in first..=number {
            checked += 1;
            let absent = missing_history(store, filter, frame);
            if !absent.is_empty() {
                missing += 1;
                first_missing.get_or_insert(json!({ "frame": frame, "records": absent }));
            }
        }
        if missing > 0 && migrates {
            let item = format!(
                "{missing} of the last {checked} frames lack outgoing-history records: this node cannot vote a \
                 generation-0 seal until they are recovered"
            );
            if archive { notes.push(item) } else { blockers.push(item) }
        }
        local = json!({
            "store": store.label,
            "head_frame": number,
            "head_anchor": header.global_frame_number,
            "head_age_frames": census_frame.saturating_sub(header.global_frame_number),
            "head_view": header.rank,
            "certificate": kind,
            "compatibility": compatible,
            "materialized_cursor": cursor,
            "committed_roots": roots,
            "history": { "window": checked, "frames_missing_records": missing, "first_missing": first_missing },
        });
    } else if migrates {
        blockers.push("legacy tip but no local frames of this shard in the given stores".into());
    }

    let report = json!({
        "filter": hex::encode(filter),
        "status": status,
        "in_grid": in_grid,
        "d4_pending": d4_pending,
        "global_last_activity": diagnose.and_then(|diagnose| diagnose.last_activity(filter)),
        "handoff": {
            "managed_application": managed,
            "head_session": session,
            "legacy_tip": tip.map(|t| json!({ "frame": t.checkpoint.frame, "anchor": t.anchor })),
        },
        "committee": { "eligible": eligible.len(), "registry_active": registry_active },
        "local": local,
        "blockers": blockers,
        "notes": notes,
    });
    Ok((report, blockers))
}

/// Run the preflight over opened stores, writing JSON lines to `out`.
#[cfg(test)]
pub fn run_with(
    master: &Store,
    workers: &[Store],
    committee: &CommitteeSource<'_>,
    options: &Options,
    out: &mut dyn Write,
) -> anyhow::Result<Summary> {
    run_diagnosed(master, workers, committee, None, options, out)
}

/// [`run_with`], adding committee and GLOBAL-acceptance evidence per shard.
pub fn run_diagnosed(
    master: &Store,
    workers: &[Store],
    committee: &CommitteeSource<'_>,
    diagnose: Option<&dyn Diagnose>,
    options: &Options,
    out: &mut dyn Write,
) -> anyhow::Result<Summary> {
    let stores: Vec<&Store> = std::iter::once(master).chain(workers.iter()).collect();
    let (id, detail) = checkpoint(master, &stores);
    if let Some(expected) = options.expect_checkpoint.as_ref() {
        if !expected.eq_ignore_ascii_case(&id) {
            anyhow::bail!("stores are at checkpoint {id}, not {expected}: restart the preflight from the beginning");
        }
    }
    let census_frame = detail["global_head"].as_u64().unwrap_or(0);
    // Application state has lived in unified per-application trees since the
    // cutover. A view left in the per-shard layout resolves only the genesis
    // paths, and reads empty trees there.
    let unified = census_frame >= quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame();
    for store in &stores {
        store.crdt.set_unified_tree(unified);
    }
    let (filters, grid) = shard_filters(&stores)?;
    let relay_activation_frame = quil_execution::token_intrinsic::global_commit::relay_activation_frame();
    writeln!(out, "{}", json!({ "gen0_preflight": { "checkpoint": id, "detail": detail,
        "window": options.window, "shards": filters.len(), "unified_tree": unified,
        "census_epoch": quil_types::consensus::epoch_for_frame(census_frame),
        "diagnostics": diagnose.map(|diagnose| diagnose.describe()),
        "relay_activation_frame": relay_activation_frame.to_string(),
        "resume_after": options.resume_after.as_ref().map(hex::encode) } }))?;
    let mut summary = Summary { checkpoint: id, ..Default::default() };
    for filter in filters {
        if options.resume_after.as_ref().is_some_and(|after| filter <= *after) {
            continue;
        }
        // Only an archive's grid is authoritative: a regular's lists no
        // shard its workers found after a split.
        let in_grid = options.archive.then(|| grid.contains(&filter));
        let (report, blockers) = shard_report(
            master, &stores, committee, census_frame, &filter, in_grid, options.window, options.archive, diagnose,
        )?;
        summary.shards += 1;
        match report["status"].as_str() {
            Some("managed") => summary.managed += 1,
            Some("legacy") if blockers.is_empty() && report["d4_pending"] == true => summary.pending += 1,
            Some("legacy") if blockers.is_empty() => summary.ready += 1,
            Some("legacy") => summary.blocked += 1,
            Some("off-grid") => summary.off_grid += 1,
            _ => summary.without_history += 1,
        }
        writeln!(out, "{report}")?;
    }
    writeln!(out, "{}", json!({ "summary": { "checkpoint": summary.checkpoint, "shards": summary.shards,
        "ready": summary.ready, "blocked": summary.blocked, "already_managed": summary.managed,
        "without_legacy_history": summary.without_history, "off_grid": summary.off_grid,
        "pending_d4": summary.pending } }))?;
    Ok(summary)
}

/// The CLI entry: open everything read-only (`live`: beside the running
/// node) and report to stdout.
pub fn run(master_path: &Path, options: &Options) -> anyhow::Result<Summary> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_to(master_path, options, &mut out)
}

pub fn run_to(master_path: &Path, options: &Options, out: &mut dyn Write) -> anyhow::Result<Summary> {
    if options.live && options.expect_checkpoint.is_some() {
        anyhow::bail!("a live preflight cannot resume: the running node moves its checkpoint; rerun it whole");
    }
    let open = |label: &str, path: &Path| match options.live {
        true => Store::open_live(label, path, options.network),
        false => Store::open_read_only(label, path, options.network),
    };
    let master = open("master", master_path)?;
    let workers = options
        .workers
        .iter()
        .enumerate()
        .map(|(i, path)| open(&format!("worker{}:{}", i + 1, path.display()), path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let scan = quil_execution::prover_registry::CommittedProverScan::try_scan(&master.crdt)?;
    let committee = |filter: &[u8], frame: u64| {
        (schedule::desired_members(&scan, filter, frame), scan.active_on_filter(filter, frame).len())
    };
    let registry = quil_execution::prover_registry::SharedProverRegistry::new();
    let refreshed = registry
        .refresh_from_store(&quil_store::RocksHypergraphStore::new(master.raw.clone()))
        .map(|()| registry)
        .map_err(|error| error.to_string());
    let provers = quil_execution::prover_registry::all_provers_with_allocations_committed(&master.crdt)
        .into_iter()
        .map(|(address, key, _)| (address, key))
        .collect();
    let diagnose = NodeDiagnose { scan: &scan, registry: refreshed, provers };
    run_diagnosed(&master, &workers, &committee, Some(&diagnose), options, out)
}

/// The GLOBAL prover shard's committed records, read-only: one sorted line
/// per record (`address length sha256`) and a closing summary with the count
/// and a digest over every line. Two archives whose prover roots differ are
/// compared by diffing these files; `show` decodes chosen addresses field by
/// field (`field key -> value`, hex) instead.
pub fn prover_shard_dump(
    path: &Path,
    network: u8,
    live: bool,
    show: &[Vec<u8>],
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let store = if live { Store::open_live("master", path, network)? } else { Store::open_read_only("master", path, network)? };
    let global_shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    store.crdt.for_each_vertex_underlying_shard("vertex", "adds", &global_shard, &mut |key, blob| {
        records.push((key, blob));
    })?;
    records.sort();
    let head = store.clock.get_latest_global_clock_frame().ok().and_then(|f| f.header).map(|h| h.frame_number);
    if !show.is_empty() {
        for (key, blob) in &records {
            let address = &key[key.len().saturating_sub(32)..];
            if !show.iter().any(|wanted| wanted.as_slice() == address) {
                continue;
            }
            let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(blob);
            let fields: Vec<serde_json::Value> = tree
                .leaves()
                .into_iter()
                .map(|(field, value)| json!([hex::encode(field), hex::encode(value)]))
                .collect();
            writeln!(out, "{}", json!({ "address": hex::encode(address), "length": blob.len(), "fields": fields }))?;
        }
        return Ok(());
    }
    let mut all = Sha256::new();
    for (key, blob) in &records {
        let line = format!("{} {} {}", hex::encode(&key[key.len().saturating_sub(32)..]), blob.len(), hex::encode(Sha256::digest(blob)));
        all.update(line.as_bytes());
        all.update(b"\n");
        writeln!(out, "{line}")?;
    }
    // The prover root is the vertex-adds phase, which headers bind. The other
    // three phases (the prover-to-allocation hyperedges, removals) are not
    // bound, so compare them across archives here.
    // A head marker an old reset left on an emptied phase reads as zeros
    // above but stops this build's commits until the master drops it at boot.
    let orphaned: Vec<String> = store.crdt.orphaned_phase_heads(&global_shard.l2)?
        .iter()
        .map(|(phase, version)| format!("{phase}@{version}"))
        .collect();
    writeln!(out, "# head {:?} cursor {:?} records {} digest {} prover_root {} vertex_removes {} hyperedge_adds {} hyperedge_removes {} orphaned_heads [{}]",
        head,
        store.clock.get_global_materialized_cursor(),
        records.len(),
        hex::encode(all.finalize()),
        hex::encode(store.crdt.compute_shard_root("vertex", "adds", &global_shard)),
        hex::encode(store.crdt.compute_shard_root("vertex", "removes", &global_shard)),
        hex::encode(store.crdt.compute_shard_root("hyperedge", "adds", &global_shard)),
        hex::encode(store.crdt.compute_shard_root("hyperedge", "removes", &global_shard)),
        orphaned.join(","))?;
    Ok(())
}

/// Read-only history of the last GLOBAL frames in this store (a master store
/// path), for archives that disagree on a head's state:
/// - per frame: the parent prover root its header binds, the forest version
///   holding that root here, and every request with its kind, identity and
///   the outcome this node recorded when it executed it;
/// - per record in `records`: each value it held after each of those frames,
///   read from the retained forest version the next header binds (the head's
///   own from the live root).
///
/// The frames are finalized and identical everywhere, so two archives whose
/// outcomes or record values part at some frame name where their execution
/// diverged. `from` defaults to seven frames below the head.
pub fn global_frame_history(
    path: &Path,
    network: u8,
    live: bool,
    from: Option<u64>,
    records: &[Vec<u8>],
    out: &mut impl Write,
) -> anyhow::Result<()> {
    use prost::Message as _;
    use quil_types::store::HypergraphStore as _;
    let store = if live { Store::open_live("master", path, network)? } else { Store::open_read_only("master", path, network)? };
    let head = store.clock.get_latest_global_clock_frame()?.header.map(|h| h.frame_number).unwrap_or(0);
    let from = from.unwrap_or(head.saturating_sub(7)).min(head);
    let hg_store = quil_store::RocksHypergraphStore::new(store.raw.clone());
    let global_shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
    let version_of = |root: &[u8]| -> Option<u64> {
        hg_store.get_root_version("vertex", "adds", &global_shard.l2, root).ok().flatten().map(|(version, _)| version)
    };
    // (state after frame, forest version holding it)
    let mut states: Vec<(u64, Option<u64>)> = Vec::new();
    for number in from..=head {
        let frame = store.clock.get_global_clock_frame(number)?;
        let header = frame.header.clone().unwrap_or_default();
        let parent_version = version_of(&header.prover_tree_commitment);
        states.push((number.saturating_sub(1), parent_version));
        let outcomes = store.clock.get_global_clock_frame_outcomes(number).unwrap_or_default();
        let requests: Vec<serde_json::Value> = frame
            .requests
            .iter()
            .enumerate()
            .map(|(index, bundle)| {
                let outcome = outcomes.get(index);
                json!({
                    "index": index,
                    "sha256": hex8(&Sha256::digest(bundle.encode_to_vec())),
                    "requests": bundle.requests.iter().filter_map(|r| r.request.as_ref()).map(describe_request).collect::<Vec<_>>(),
                    "outcome": outcome.map(|o| format!("{:?}", o.status)),
                    "error": outcome.map(|o| o.error.as_str()).filter(|e| !e.is_empty()),
                })
            })
            .collect();
        writeln!(out, "{}", json!({
            "frame": number,
            "prover": hex8(&header.prover),
            "parent_prover_root": hex::encode(&header.prover_tree_commitment),
            "parent_version": parent_version,
            "outcomes_recorded": outcomes.len(),
            "requests": requests,
        }))?;
    }
    let live_root = store.crdt.compute_shard_root("vertex", "adds", &global_shard);
    states.push((head, version_of(&live_root)));
    for address in records {
        let mut vertex = global_shard.l2.to_vec();
        vertex.extend_from_slice(address);
        let mut previous: Option<Vec<u8>> = None;
        for &(after_frame, version) in &states {
            let Some(version) = version else {
                writeln!(out, "{}", json!({ "record": hex::encode(address), "after_frame": after_frame, "version": null }))?;
                continue;
            };
            let blob = hg_store.load_vertex_underlying_at("vertex", "adds", &global_shard, &vertex, version)?.unwrap_or_default();
            if previous.as_ref() == Some(&blob) {
                continue;
            }
            let fields: Vec<serde_json::Value> = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob)
                .leaves()
                .into_iter()
                .map(|(field, value)| {
                    let value = if value.len() > 64 {
                        format!("{} bytes sha256 {}", value.len(), hex8(&Sha256::digest(&value)))
                    } else {
                        hex::encode(&value)
                    };
                    json!([hex::encode(field), value])
                })
                .collect();
            writeln!(out, "{}", json!({
                "record": hex::encode(address),
                "after_frame": after_frame,
                "version": version,
                "length": blob.len(),
                "fields": fields,
            }))?;
            previous = Some(blob);
        }
    }
    Ok(())
}

/// A GLOBAL request's kind and the identities that tell two archives'
/// outcomes apart: the prover, its shards, a shard frame's anchor and signers.
/// A confirm or reject also shows its deprecated single filter, which older
/// clients still set.
#[allow(deprecated)]
fn describe_request(request: &quil_types::proto::global::message_request::Request) -> serde_json::Value {
    use quil_types::proto::global::message_request::Request;
    let prover_of = |public_key: &[u8]| {
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(public_key)
            .map(hex::encode)
            .unwrap_or_default()
    };
    let hexes = |values: &[Vec<u8>]| values.iter().map(hex::encode).collect::<Vec<_>>();
    let signer = |signature: &Option<quil_types::proto::keys::Bls48581AddressedSignature>| {
        signature.as_ref().map(|s| hex::encode(&s.address)).unwrap_or_default()
    };
    match request {
        Request::Join(op) => json!({
            "kind": "join",
            "prover": op.public_key_signature_bls48581.as_ref()
                .and_then(|s| s.public_key.as_ref())
                .map(|k| prover_of(&k.key_value))
                .unwrap_or_default(),
            "filters": hexes(&op.filters),
            "frame": op.frame_number,
            "merge_targets": op.merge_targets.len(),
        }),
        Request::Leave(op) => json!({ "kind": "leave", "prover": signer(&op.public_key_signature_bls48581), "filters": hexes(&op.filters), "frame": op.frame_number }),
        Request::Pause(op) => json!({ "kind": "pause", "prover": signer(&op.public_key_signature_bls48581), "filters": [hex::encode(&op.filter)], "frame": op.frame_number }),
        Request::Resume(op) => json!({ "kind": "resume", "prover": signer(&op.public_key_signature_bls48581), "filters": [hex::encode(&op.filter)], "frame": op.frame_number }),
        Request::Confirm(op) => json!({
            "kind": "confirm",
            "prover": signer(&op.public_key_signature_bls48581),
            "filters": hexes(&op.filters),
            "filter": hex::encode(&op.filter),
            "frame": op.frame_number,
            "leaf_roots": op.leaf_roots.len(),
        }),
        Request::Reject(op) => json!({
            "kind": "reject",
            "prover": signer(&op.public_key_signature_bls48581),
            "filters": hexes(&op.filters),
            "filter": hex::encode(&op.filter),
            "frame": op.frame_number,
        }),
        Request::Kick(op) => json!({ "kind": "kick", "kicked": prover_of(&op.kicked_prover_public_key), "frame": op.frame_number }),
        Request::Update(op) => json!({ "kind": "update", "prover": signer(&op.public_key_signature_bls48581) }),
        Request::SeniorityMerge(op) => json!({ "kind": "seniority_merge", "prover": signer(&op.public_key_signature_bls48581), "targets": op.merge_targets.len() }),
        Request::ShardSplit(op) => json!({ "kind": "shard_split", "parent": hex::encode(&op.shard_address), "children": hexes(&op.proposed_shards), "frame": op.frame_number }),
        Request::ShardMerge(op) => json!({ "kind": "shard_merge", "parent": hex::encode(&op.parent_address), "children": hexes(&op.shard_addresses), "frame": op.frame_number }),
        Request::Shard(header) => json!({
            "kind": "shard",
            "address": hex::encode(&header.address),
            "frame": header.frame_number,
            "global_frame": header.global_frame_number,
            "prover": hex8(&header.prover),
            "bitmask": header.public_key_signature_bls48581.as_ref().map(|s| hex::encode(&s.bitmask)).unwrap_or_default(),
            "storage_attestation": header.storage_attestation.len(),
        }),
        other => json!({ "kind": request_kind(other) }),
    }
}

fn request_kind(request: &quil_types::proto::global::message_request::Request) -> &'static str {
    use quil_types::proto::global::message_request::Request;
    match request {
        Request::Join(_) => "join",
        Request::Leave(_) => "leave",
        Request::Pause(_) => "pause",
        Request::Resume(_) => "resume",
        Request::Confirm(_) => "confirm",
        Request::Reject(_) => "reject",
        Request::Kick(_) => "kick",
        Request::Update(_) => "update",
        Request::TokenDeploy(_) => "token_deploy",
        Request::TokenUpdate(_) => "token_update",
        Request::HypergraphDeploy(_) => "hypergraph_deploy",
        Request::HypergraphUpdate(_) => "hypergraph_update",
        Request::VertexAdd(_) => "vertex_add",
        Request::VertexRemove(_) => "vertex_remove",
        Request::HyperedgeAdd(_) => "hyperedge_add",
        Request::HyperedgeRemove(_) => "hyperedge_remove",
        Request::ComputeDeploy(_) => "compute_deploy",
        Request::ComputeUpdate(_) => "compute_update",
        Request::CodeDeploy(_) => "code_deploy",
        Request::CodeExecute(_) => "code_execute",
        Request::CodeFinalize(_) => "code_finalize",
        Request::Shard(_) => "shard",
        Request::AltShardUpdate(_) => "alt_shard_update",
        Request::SeniorityMerge(_) => "seniority_merge",
        Request::ShardSplit(_) => "shard_split",
        Request::ShardMerge(_) => "shard_merge",
        Request::TokenOperation(_) => "token_operation",
        Request::CommitteeHandoff(_) => "committee_handoff",
    }
}

/// What a node restarting on this store binds into the next GLOBAL header,
/// as it seeds them at startup from the forest (state through the
/// materialized cursor): the GLOBAL prover shard's root and a digest of the
/// 256 global commitments (which carry the subtree sizes). The world size
/// needs the node's size index, which a read-only open does not load.
fn next_frame_binds(crdt: &quil_hypergraph::HypergraphCrdt) -> serde_json::Value {
    let global_shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
    let mut commitments = Sha256::new();
    for commitment in crdt.global_commitments() {
        commitments.update((commitment.len() as u64).to_be_bytes());
        commitments.update(&commitment);
    }
    json!({
        "prover_root": hex::encode(crdt.compute_shard_root("vertex", "adds", &global_shard)),
        "global_commitments_sha256": hex::encode(commitments.finalize()),
    })
}

/// Read-only evidence for a GLOBAL halt, from one store:
/// - the head frame;
/// - the parent state the next frame must bind (prover root, commitments);
/// - candidates stored above the head (proposals nobody finalized);
/// - GLOBAL's committee at the head and at the next frame, with quorum;
/// - every GLOBAL allocation's status.
///
/// Run it on every archive stopped at the same head and compare: parent
/// records that differ are a fork no restart resolves; a committee below
/// quorum cannot finalize.
pub fn global_halt_report(path: &Path, network: u8, live: bool, out: &mut impl Write) -> anyhow::Result<()> {
    use quil_types::consensus::ProverRegistry as _;
    let store = if live { Store::open_live("master", path, network)? } else { Store::open_read_only("master", path, network)? };
    let head = store.clock.get_latest_global_clock_frame()?;
    let header = head.header.clone().unwrap_or_default();
    let number = header.frame_number;
    let next = number + 1;
    let candidates: Vec<serde_json::Value> = store
        .clock
        .range_global_clock_frame_candidates(next, next + 63, 256)?
        .iter()
        .filter_map(|frame| frame.header.as_ref())
        .map(|h| json!({
            "frame": h.frame_number,
            "rank": h.rank,
            "prover": hex8(&h.prover),
            "output": hex8(&h.output),
            "parent": hex8(&h.parent_selector),
            "prover_tree_commitment": hex::encode(&h.prover_tree_commitment),
        }))
        .collect();
    let registry = quil_execution::prover_registry::SharedProverRegistry::new();
    registry.refresh_from_store(&quil_store::RocksHypergraphStore::new(store.raw.clone()))?;
    let committee = |frame: u64| -> anyhow::Result<serde_json::Value> {
        let mut members: Vec<String> = registry
            .get_active_provers(&[], frame)?
            .iter()
            .map(|p| hex::encode(&p.address))
            .collect();
        members.sort();
        let size = members.len();
        Ok(json!({ "frame": frame, "size": size, "quorum": size - size.saturating_sub(1) / 3, "members": members }))
    };
    let mut allocations: Vec<serde_json::Value> = registry
        .get_provers(&[])?
        .iter()
        .flat_map(|prover| {
            prover.allocations.iter().filter(|a| a.confirmation_filter.is_empty()).map(move |a| json!({
                "prover": hex::encode(&prover.address),
                "prover_status": format!("{:?}", prover.status),
                "status": format!("{:?}", a.status),
                "effective_at_next": format!("{:?}", a.effective_status(next)),
                "epoch": a.epoch,
                "confirmed": a.join_confirm_frame_number,
                "leave_frame": a.leave_frame_number,
                "kick_frame": a.kick_frame_number,
                "last_active": a.last_active_frame_number,
            }))
        })
        .collect();
    allocations.sort_by_key(|a| a["prover"].as_str().unwrap_or_default().to_string());
    writeln!(out, "{}", json!({ "global_halt": {
        "store": path.display().to_string(),
        "epoch_length": quil_types::consensus::epoch_length_frames(),
        "head": {
            "frame": number,
            "epoch": quil_types::consensus::epoch_for_frame(number),
            "rank": header.rank,
            "prover": hex::encode(&header.prover),
            "output": hex8(&header.output),
            "parent": hex8(&header.parent_selector),
            "prover_tree_commitment": hex::encode(&header.prover_tree_commitment),
            "timestamp": header.timestamp,
        },
        "materialized_cursor": store.clock.get_global_materialized_cursor(),
        "next_frame_binds": next_frame_binds(&store.crdt),
        "candidates_above_head": candidates,
        "committee_at_head": committee(number)?,
        "committee_at_next": committee(next)?,
        "global_allocations": allocations,
    }}))?;
    Ok(())
}

#[cfg(test)]
#[path = "gen0_preflight_tests.rs"]
mod tests;
