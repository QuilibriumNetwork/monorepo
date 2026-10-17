//! Synthetic legacy stores: a master with the grid and GLOBAL records, a
//! worker with application frames certified in the legacy namespace (real
//! Falcon epoch-0 finalizations) and their outgoing-history records.
use super::*;
use quil_cw_consensus::{
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{sha256::Digest, Signer as _},
    _utils::{ordered::Set, N3f1},
    app_cert::{encode_finalization, wrap_cert_for_header},
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
};
use quil_types::proto::global::{AppShardFrame, FrameHeader};
use quil_types::store::KvDb as _;

const NETWORK: u8 = 1;

fn keys() -> Vec<FalconPrivateKey> {
    (0..4)
        .map(|_| {
            use quil_types::crypto::Signer as _;
            let signer = quil_crypto::FalconSigner::generate();
            FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap()
        })
        .collect()
}

fn members(keys: &[FalconPrivateKey]) -> Vec<Vec<u8>> {
    let mut members: Vec<_> = keys.iter().map(|key| key.public_key().as_ref().to_vec()).collect();
    members.sort();
    members
}

/// An epoch-0 finalization of `digest` by `keys` in `filter`'s legacy namespace.
fn legacy_certificate(filter: &[u8], keys: &[FalconPrivateKey], view: u64, digest: [u8; 32]) -> Vec<u8> {
    let namespace = [b"appshard".as_slice(), filter].concat();
    let proposal = Proposal::new(Round::new(Epoch::new(0), View::new(view)), View::new(view - 1), Digest(digest));
    let participants: Set<_> = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
    let schemes: Vec<Generic<Namespace>> = keys
        .iter()
        .cloned()
        .map(|key| Generic::signer(&namespace, participants.clone(), key).unwrap())
        .collect();
    let quorum = keys.len() - (keys.len() - 1) / 3;
    let votes: Vec<_> = schemes[..quorum]
        .iter()
        .map(|s| s.sign::<SimplexFalconScheme, Digest>(Subject::Finalize { proposal: &proposal }).unwrap())
        .collect();
    let certificate = schemes[0].assemble::<SimplexFalconScheme, _, N3f1>(votes).unwrap();
    encode_finalization(&Finalization { proposal, certificate })
}

struct Fixture {
    _dirs: Vec<tempfile::TempDir>,
    master: Store,
    worker: Store,
    filter: Vec<u8>,
    keys: Vec<FalconPrivateKey>,
}

fn open(dirs: &mut Vec<tempfile::TempDir>, label: &str) -> Store {
    let dir = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(dir.path()).unwrap();
    dirs.push(dir);
    Store::from_db(label, db, NETWORK)
}

/// A master whose grid registers one whole-application shard, and a worker
/// holding its frames 1..=`head` with complete history.
fn fixture(head: u64) -> Fixture {
    let mut dirs = Vec::new();
    let master = open(&mut dirs, "master");
    let worker = open(&mut dirs, "worker");
    let app = [0x71u8; 32];
    let filter = app.to_vec();
    let shards = quil_store::RocksShardsStore::new(master.raw.clone());
    let batch = master._db.new_batch(false).unwrap();
    let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
    shard_key.extend_from_slice(&app);
    shards
        .put_app_shard(batch.as_ref(), &quil_types::store::ShardInfo {
            shard_key, prefix: Vec::new(), size: Vec::new(), data_shards: 0, commitment: Vec::new(),
        })
        .unwrap();
    batch.commit().unwrap();
    let fixture = Fixture { _dirs: dirs, master, worker, filter, keys: keys() };
    for frame in 1..=head {
        put_frame(&fixture, frame, &fixture.keys, true);
    }
    fixture
}

/// Store frame `number` (certified by `keys`) and, if `history`, its records
/// and cursor in the worker.
fn put_frame(fixture: &Fixture, number: u64, keys: &[FalconPrivateKey], history: bool) {
    put_frame_of(fixture, &fixture.filter, number, keys, history)
}

fn put_frame_of(fixture: &Fixture, filter: &[u8], number: u64, keys: &[FalconPrivateKey], history: bool) {
    let output = vec![number as u8; 32];
    let digest = quil_crypto::poseidon::hash_bytes_to_32(&output).unwrap();
    let mut frame = AppShardFrame {
        header: Some(FrameHeader {
            address: filter.to_vec(),
            frame_number: number,
            rank: number + 10,
            global_frame_number: 5,
            output,
            ..Default::default()
        }),
        ..Default::default()
    };
    frame.header.as_mut().unwrap().public_key_signature_bls48581 = Some(quil_types::proto::keys::Bls48581AggregateSignature {
        public_key: None,
        signature: wrap_cert_for_header(&legacy_certificate(filter, keys, number + 10, digest)),
        bitmask: Vec::new(),
    });
    let selector = digest.to_vec();
    let clock = &fixture.worker.clock;
    let txn = clock.new_transaction(false).unwrap();
    clock.stage_shard_clock_frame(&selector, &frame, txn.as_ref()).unwrap();
    txn.commit().unwrap();
    let txn = clock.new_transaction(false).unwrap();
    clock.commit_shard_clock_frame(filter, number, &selector, txn.as_ref(), false).unwrap();
    txn.commit().unwrap();
    if history {
        use quil_store::encoding as e;
        let records = vec![
            (e::clock_shard_frame_fee_total_key(filter, number), vec![0u8; 16]),
            (e::clock_shard_frame_settlements_key(filter, number), Vec::new()),
            (e::clock_shard_frame_spends_key(filter, number), Vec::new()),
            (e::clock_shard_frame_accumulator_key(filter, number), Vec::new()),
        ];
        fixture
            .worker
            .crdt
            .commit_with_frame_cursor_and_records(number, &e::consensus_materialized_cursor_key(filter), &records)
            .unwrap();
    }
}

fn options() -> Options {
    Options { workers: Vec::new(), window: 8, resume_after: None, expect_checkpoint: None, network: NETWORK, archive: false, live: false }
}

fn run(fixture: &Fixture, committee: &CommitteeSource<'_>, options: &Options) -> (Summary, Vec<serde_json::Value>) {
    let mut out = Vec::new();
    let summary = run_with(&fixture.master, std::slice::from_ref(&fixture.worker), committee, options, &mut out)
        .unwrap();
    let lines = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (summary, lines)
}

#[test]
fn a_live_legacy_shard_with_its_committee_and_history_is_ready() {
    let fixture = fixture(12);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (summary, lines) = run(&fixture, &committee, &options());
    assert_eq!((summary.shards, summary.ready, summary.blocked), (1, 1, 0), "{lines:?}");
    let shard = &lines[1];
    assert_eq!(shard["local"]["head_frame"], 12);
    assert_eq!(shard["local"]["certificate"], "cw-epoch-0 (legacy namespace)");
    assert_eq!(shard["local"]["compatibility"]["eligible_committee"], "verifies");
    assert_eq!(shard["local"]["history"]["window"], 8);
    assert_eq!(shard["local"]["history"]["frames_missing_records"], 0);
    assert_eq!(shard["local"]["materialized_cursor"], 12);
    assert_eq!(shard["local"]["compatibility"]["certificate_signers"], serde_json::json!({ "committee": 4, "signed": 3 }));
    assert!(lines.last().unwrap()["summary"].is_object());
}

/// A head signed under a larger committee than the rebuilt one cannot even be
/// decoded against it; the report says how large the signing committee was.
#[test]
fn a_head_signed_by_a_larger_committee_reports_its_size() {
    let fixture = fixture(3);
    let mut larger = fixture.keys.clone();
    larger.extend(keys().into_iter().take(2));
    put_frame(&fixture, 4, &larger, true);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (_, lines) = run(&fixture, &committee, &options());
    let compatibility = &lines[1]["local"]["compatibility"];
    assert_eq!(compatibility["eligible_committee"], "Encoding", "{compatibility}");
    assert_eq!(compatibility["certificate_signers"], serde_json::json!({ "committee": 6, "signed": 5 }));
}

/// Frames anchored below the relay activation frame were made by the mainnet
/// build, which wrote no outgoing-history records: none are missing.
#[test]
fn frames_before_relay_activation_need_no_history_records() {
    use quil_execution::token_intrinsic::global_commit::set_relay_activation_frame_for_thread;
    let fixture = fixture(12);
    put_frame(&fixture, 13, &fixture.keys, false);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    // Every fixture frame is anchored at GLOBAL frame 5.
    set_relay_activation_frame_for_thread(Some(6));
    let (_, lines) = run(&fixture, &committee, &options());
    set_relay_activation_frame_for_thread(None);
    assert_eq!(lines[0]["gen0_preflight"]["relay_activation_frame"], "6");
    assert_eq!(lines[1]["local"]["history"]["frames_missing_records"], 0, "{lines:?}");
    let (_, lines) = run(&fixture, &committee, &options());
    assert_eq!(lines[1]["local"]["history"]["frames_missing_records"], 1, "relaying frames still need theirs");
}

/// Each blocker the migration cannot proceed past is named.
#[test]
fn committee_certificate_history_and_cursor_blockers_are_reported() {
    let fixture = fixture(12);
    // A frame certified by another committee, without its history records:
    // the head moves past the materialized cursor.
    let others = keys();
    put_frame(&fixture, 13, &others, false);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 5);
    let (summary, lines) = run(&fixture, &committee, &options());
    assert_eq!((summary.ready, summary.blocked), (0, 1));
    let blockers: Vec<String> = serde_json::from_value(lines[1]["blockers"].clone()).unwrap();
    let text = blockers.join("\n");
    for expected in ["registry active set (5)", "does not verify against the eligible committee",
                     "materialized cursor Some(12) is not the head frame 13", "1 of the last 8 frames lack"] {
        assert!(text.contains(expected), "missing {expected:?} in {text}");
    }
    assert_eq!(lines[1]["local"]["history"]["first_missing"]["frame"], 13);

    let nobody = |_: &[u8], _: u64| (Vec::new(), 0);
    let (_, lines) = run(&fixture, &nobody, &options());
    assert!(lines[1]["blockers"].to_string().contains("no eligible committee"));
}

/// A registered generation-0 source and a legacy tip show in the report; a
/// managed shard is counted apart and not blocked on legacy readiness.
#[test]
fn handoff_status_and_legacy_tips_are_reported() {
    let fixture = fixture(4);
    let global = HypergraphState::new(fixture.master.crdt.clone());
    let tip = legacy::LegacyTip {
        checkpoint: quil_cw_consensus::handoff::Checkpoint {
            frame: 4, view: 14, digest: [4; 32], state_roots: [[0; 32]; 4], history_root: [0; 32],
        },
        anchor: 5,
    };
    legacy::record_tip(&global, 1, &fixture.filter, &tip).unwrap();
    global.commit().unwrap();
    global.abort();
    fixture.master.crdt
        .commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (summary, lines) = run(&fixture, &committee, &options());
    assert_eq!(lines[1]["handoff"]["legacy_tip"]["frame"], 4);
    assert_eq!(lines[1]["handoff"]["legacy_tip"]["anchor"], 5);
    assert_eq!(summary.ready, 1);
}

/// Every line is bound to one checkpoint: a store that changed refuses a
/// resumed run, and a resumed run skips what the interrupted one reported.
#[test]
fn a_resumed_run_is_bound_to_its_checkpoint() {
    let fixture = fixture(3);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (first, lines) = run(&fixture, &committee, &options());
    let (again, _) = run(&fixture, &committee, &options());
    assert_eq!(first.checkpoint, again.checkpoint, "an unchanged store keeps its checkpoint");
    assert_eq!(lines[0]["gen0_preflight"]["checkpoint"], first.checkpoint.as_str());

    let resumed = Options {
        resume_after: Some(fixture.filter.clone()),
        expect_checkpoint: Some(first.checkpoint.clone()),
        ..options()
    };
    let (skipped, _) = run(&fixture, &committee, &resumed);
    assert_eq!(skipped.shards, 0, "the reported shard is not repeated");

    put_frame(&fixture, 4, &fixture.keys, true);
    let mut out = Vec::new();
    let error = run_with(&fixture.master, std::slice::from_ref(&fixture.worker), &committee, &resumed, &mut out)
        .unwrap_err();
    assert!(error.to_string().contains("restart the preflight"), "{error}");
}

/// A regular node's master lists only its registered grid: shards its
/// workers hold are found in their clock stores. A registered shard with no
/// frames and no tip (a deep split's spine) has nothing to migrate and blocks
/// nothing; a managed shard is not held to legacy readiness.
#[test]
fn worker_shards_are_discovered_and_only_legacy_shards_can_block() {
    let fixture = fixture(3);
    let mut child = fixture.filter.clone();
    child.extend_from_slice(&[0, 1, 0]);
    for frame in 1..=3 {
        put_frame_of(&fixture, &child, frame, &fixture.keys, true);
    }
    let spine = [0x72u8; 32];
    let shards = quil_store::RocksShardsStore::new(fixture.master.raw.clone());
    let batch = fixture.master._db.new_batch(false).unwrap();
    let mut shard_key = quil_hypergraph::addressing::get_bloom_filter_indices(&spine, 256, 3).to_vec();
    shard_key.extend_from_slice(&spine);
    shards
        .put_app_shard(batch.as_ref(), &quil_types::store::ShardInfo {
            shard_key, prefix: Vec::new(), size: Vec::new(), data_shards: 0, commitment: Vec::new(),
        })
        .unwrap();
    batch.commit().unwrap();
    let eligible = members(&fixture.keys);
    let committee = move |filter: &[u8], _: u64| {
        if filter == spine.as_slice() { (Vec::new(), 0) } else { (eligible.clone(), 4) }
    };
    let (summary, lines) = run(&fixture, &committee, &options());
    let by_filter = |filter: &[u8]| lines.iter().find(|line| line["filter"] == hex::encode(filter)).unwrap().clone();
    assert_eq!(by_filter(&child)["status"], "legacy", "found through the worker's clock store");
    assert_eq!(by_filter(&child)["local"]["head_frame"], 3);
    assert_eq!(by_filter(&spine)["status"], "no-legacy-history");
    assert_eq!(by_filter(&spine)["blockers"], serde_json::json!([]));
    assert_eq!(by_filter(&child)["in_grid"], serde_json::Value::Null, "a regular's grid is not authoritative");
    assert_eq!((summary.shards, summary.ready, summary.blocked, summary.without_history), (3, 2, 0, 1));

    // An archive's grid is authoritative: GLOBAL never registers a filter it
    // no longer lists as generation zero, whatever frames the filter left.
    let (archive, lines) = run(&fixture, &committee, &Options { archive: true, ..options() });
    let on_archive = |filter: &[u8]| lines.iter().find(|line| line["filter"] == hex::encode(filter)).unwrap().clone();
    assert_eq!(on_archive(&child)["status"], "off-grid");
    assert_eq!(on_archive(&child)["in_grid"], false);
    assert_eq!(on_archive(&child)["blockers"], serde_json::json!([]));
    assert_eq!(on_archive(&fixture.filter)["in_grid"], true);
    assert_eq!((archive.ready, archive.blocked, archive.off_grid, archive.without_history), (1, 0, 1, 1));
}

/// A non-member archive's cursor and history lag its clock head (sequenced
/// ingest materializes only frames GLOBAL referenced). It votes no seal, so
/// those items are notes, not blockers; the same store as a member blocks.
#[test]
fn an_archive_reports_member_readiness_as_notes_not_blockers() {
    let fixture = fixture(12);
    put_frame(&fixture, 13, &fixture.keys, false);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (member, _) = run(&fixture, &committee, &options());
    assert_eq!(member.blocked, 1, "a member cannot vote a seal over missing history");
    let (archive, lines) = run(&fixture, &committee, &Options { archive: true, ..options() });
    assert_eq!((archive.ready, archive.blocked), (1, 0), "{lines:?}");
    let notes = lines[1]["notes"].to_string();
    assert!(notes.contains("materialized cursor Some(12) is not the head frame 13"), "{notes}");
    assert!(notes.contains("1 of the last 8 frames lack"), "{notes}");
}

/// A live preflight reads a running node's stores beside it: the primaries
/// stay open and writable, the view includes their unflushed writes (the WAL)
/// and the frame reads that take snapshots work, and a live run refuses to
/// resume (its checkpoint moves).
#[test]
fn a_live_preflight_reads_open_primaries_read_only() {
    let fixture = fixture(6);
    let master_path = fixture._dirs[0].path().to_path_buf();
    let worker_path = fixture._dirs[1].path().to_path_buf();
    let options = Options { workers: vec![worker_path], live: true, ..options() };
    // A GLOBAL head in the (still open) master: its read takes a snapshot.
    fixture.master.clock.put_global_frame(&quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: 9, output: vec![1; 516], ..Default::default()
        }),
        requests: Vec::new(),
    }, None).unwrap();
    let mut out = Vec::new();
    let summary = run_to(&master_path, &options, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(summary.shards, 1, "{text}");
    let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(header["gen0_preflight"]["detail"]["global_head"], 9, "the GLOBAL head is read through the live view");
    let shard: serde_json::Value = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
    assert_eq!(shard["local"]["head_frame"], 6, "the worker's frames seen through its secondary");
    assert_eq!(shard["local"]["materialized_cursor"], 6);
    // The CLI diagnoses through the node's own registry. This store has no
    // provers, so the head is rejected and every candidate is tried.
    assert_eq!(header["gen0_preflight"]["diagnostics"]["registry"], "refreshed from the master store");
    let candidates = &shard["local"]["compatibility"]["committee_search"]["candidates"];
    for name in ["registry_at_anchor", "all_allocations"] {
        assert_eq!(candidates[name]["size"], 0, "{name}: {candidates}");
    }
    assert_eq!(shard["global_last_activity"], serde_json::Value::Null, "no allocation was ever active");
    assert_eq!(shard["local"]["compatibility"]["committee_search"]["signers"]["identified"], 0,
        "no registered prover signed it");

    // The primary keeps writing; a new live run sees it after catching up.
    put_frame(&fixture, 7, &fixture.keys, true);
    let mut out = Vec::new();
    run_to(&master_path, &options, &mut out).unwrap();
    let shard: serde_json::Value = serde_json::from_str(String::from_utf8(out).unwrap().lines().nth(1).unwrap()).unwrap();
    assert_eq!(shard["local"]["head_frame"], 7);

    let resumed = Options { expect_checkpoint: Some(summary.checkpoint), ..options };
    let error = run_to(&master_path, &resumed, &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("cannot resume"), "{error}");
}

/// Advance the master's GLOBAL head (the census frame) to `frame`.
fn put_global_head(fixture: &Fixture, frame: u64) {
    fixture.master.clock.put_global_frame(&quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: frame, output: vec![1; 516], ..Default::default()
        }),
        requests: Vec::new(),
    }, None).unwrap();
}

/// GLOBAL registers a shard only from a head anchored in the registering
/// epoch. A head from an earlier epoch is pending, not blocked: its
/// certifying committee may since have changed, and nothing registers it.
#[test]
fn a_head_from_an_earlier_epoch_is_pending_not_blocked() {
    let fixture = fixture(12);
    put_frame(&fixture, 13, &keys(), true);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let (same_epoch, lines) = run(&fixture, &committee, &options());
    assert_eq!((same_epoch.blocked, same_epoch.pending), (1, 0), "{lines:?}");
    assert!(lines[1]["blockers"].to_string().contains("does not verify against the eligible committee"));

    // Every fixture head is anchored at GLOBAL frame 5, in epoch 0.
    put_global_head(&fixture, 3 * quil_types::consensus::epoch_length_frames() + 1);
    let (later, lines) = run(&fixture, &committee, &options());
    assert_eq!((later.ready, later.blocked, later.pending), (0, 0, 1), "{lines:?}");
    assert_eq!(lines[0]["gen0_preflight"]["census_epoch"], 3);
    assert_eq!(lines[1]["d4_pending"], true);
    assert_eq!(lines[1]["blockers"], serde_json::json!([]));
    assert!(lines[1]["notes"].to_string().contains("pending (D4): head anchored in epoch 0"), "{}", lines[1]);
    assert_eq!(lines[1]["local"]["compatibility"]["eligible_committee"], "Quorum", "the mismatch is still shown");
}

struct Candidates {
    wrong: Vec<Vec<u8>>,
    right: Vec<Vec<u8>>,
}

impl Diagnose for Candidates {
    fn candidates(&self, _: &[u8], anchor: u64) -> Vec<(&'static str, Vec<Vec<u8>>)> {
        assert_eq!(anchor, 5, "candidates are formed at the head's anchor");
        vec![("wrong", self.wrong.clone()), ("right", self.right.clone())]
    }
    fn last_activity(&self, _: &[u8]) -> Option<u64> {
        Some(42)
    }
    fn signers(&self, certificate: &[u8], namespace: &[u8], anchor: u64) -> serde_json::Value {
        let pool = [self.wrong.clone(), self.right.clone()].concat();
        let found = quil_cw_consensus::app_cert::identify_signers(certificate, namespace, &pool).unwrap();
        serde_json::json!({ "anchor": anchor, "identified": found.len(),
                            "all_right": found.iter().all(|(_, key)| self.right.contains(key)) })
    }
    fn describe(&self) -> serde_json::Value {
        serde_json::json!("test")
    }
}

/// A head the rebuilt committee rejects is tried against each candidate
/// committee; exactly the one that signed it verifies. The report also carries
/// GLOBAL's last acceptance of the shard.
#[test]
fn a_rejected_head_names_the_candidate_committee_that_signed_it() {
    let fixture = fixture(12);
    let others = keys();
    put_frame(&fixture, 13, &others, true);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let diagnose = Candidates { wrong: eligible.clone(), right: members(&others) };
    let mut out = Vec::new();
    run_diagnosed(&fixture.master, std::slice::from_ref(&fixture.worker), &committee, Some(&diagnose), &options(), &mut out)
        .unwrap();
    let lines: Vec<serde_json::Value> = String::from_utf8(out).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(lines[0]["gen0_preflight"]["diagnostics"], "test");
    let search = &lines[1]["local"]["compatibility"]["committee_search"];
    assert_eq!(search["matched"], serde_json::json!(["right"]), "{search}");
    assert_eq!(search["candidates"]["wrong"]["result"], "Quorum");
    assert_eq!(search["candidates"]["right"], serde_json::json!({ "size": 4, "result": "verifies" }));
    assert_eq!(lines[1]["global_last_activity"], 42);
    assert_eq!(search["signers"], serde_json::Value::Null, "a matched committee needs no signer search");

    // A head that verifies needs no search.
    put_frame(&fixture, 14, &fixture.keys, true);
    let mut out = Vec::new();
    run_diagnosed(&fixture.master, std::slice::from_ref(&fixture.worker), &committee, Some(&diagnose), &options(), &mut out)
        .unwrap();
    let shard: serde_json::Value = serde_json::from_str(String::from_utf8(out).unwrap().lines().nth(1).unwrap()).unwrap();
    assert_eq!(shard["local"]["compatibility"]["committee_search"], serde_json::Value::Null);
}

/// Neighbouring filters in the unified encoding: ancestors nearest first,
/// then the two children.
#[test]
fn neighbouring_filters_follow_the_bit_path() {
    let app = [0x71u8; 32];
    let at = |bits: &[bool]| quil_forest::encode_shard_bit_path(&app, bits);
    let filter = at(&[true, false, true]);
    assert_eq!(ancestors(&filter), vec![at(&[true, false]), at(&[true])]);
    assert_eq!(children(&filter), vec![at(&[true, false, true, false]), at(&[true, false, true, true])]);
    assert!(ancestors(&app).is_empty(), "a whole-application filter has no ancestor");
}

/// When no candidate committee reproduces a recent head's certificate, its
/// signers are named from every key the diagnostics know.
#[test]
fn an_unmatched_recent_head_names_its_signers() {
    let fixture = fixture(12);
    let others = keys();
    put_frame(&fixture, 13, &others, true);
    let eligible = members(&fixture.keys);
    let committee = |_: &[u8], _: u64| (eligible.clone(), 4);
    let diagnose = Candidates { wrong: eligible.clone(), right: members(&others) };
    struct NoMatch<'a>(&'a Candidates);
    impl Diagnose for NoMatch<'_> {
        fn candidates(&self, _: &[u8], _: u64) -> Vec<(&'static str, Vec<Vec<u8>>)> {
            vec![("wrong", self.0.wrong.clone())]
        }
        fn last_activity(&self, _: &[u8]) -> Option<u64> { None }
        fn signers(&self, certificate: &[u8], namespace: &[u8], anchor: u64) -> serde_json::Value {
            self.0.signers(certificate, namespace, anchor)
        }
    }
    let mut out = Vec::new();
    run_diagnosed(&fixture.master, std::slice::from_ref(&fixture.worker), &committee, Some(&NoMatch(&diagnose)), &options(), &mut out)
        .unwrap();
    let shard: serde_json::Value = serde_json::from_str(String::from_utf8(out).unwrap().lines().nth(1).unwrap()).unwrap();
    let signers = &shard["local"]["compatibility"]["committee_search"]["signers"];
    assert_eq!(signers["identified"], 3, "{signers}");
    assert_eq!(signers["all_right"], true);
    assert_eq!(signers["anchor"], 5);

    // A head anchored more than IDENTIFY_EPOCHS before the census is not searched.
    put_global_head(&fixture, (IDENTIFY_EPOCHS + 1) * quil_types::consensus::epoch_length_frames());
    let mut out = Vec::new();
    run_diagnosed(&fixture.master, std::slice::from_ref(&fixture.worker), &committee, Some(&NoMatch(&diagnose)), &options(), &mut out)
        .unwrap();
    let shard: serde_json::Value = serde_json::from_str(String::from_utf8(out).unwrap().lines().nth(1).unwrap()).unwrap();
    assert_eq!(shard["local"]["compatibility"]["committee_search"]["signers"], serde_json::Value::Null);
}

/// The GLOBAL halt report, read-only beside the node: the head, what the next
/// frame binds, a stored candidate above the head, and the (empty) committee.
#[test]
fn the_global_halt_report_names_the_head_candidates_and_committee() {
    let fixture = fixture(1);
    let master_path = fixture._dirs[0].path().to_path_buf();
    put_global_head(&fixture, 9);
    fixture.master.clock.put_global_clock_frame_candidate(&quil_types::proto::global::GlobalFrame {
        header: Some(quil_types::proto::global::GlobalFrameHeader {
            frame_number: 10, rank: 12, output: vec![2; 516], prover: vec![0xAB; 32], ..Default::default()
        }),
        requests: Vec::new(),
    }, &quil_execution::testing::NoopTxn).unwrap();
    let mut out = Vec::new();
    super::global_halt_report(&master_path, NETWORK, true, &mut out).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let report = &report["global_halt"];
    assert_eq!(report["head"]["frame"], 9, "{report}");
    assert_eq!(report["candidates_above_head"][0]["frame"], 10);
    assert_eq!(report["candidates_above_head"][0]["rank"], 12);
    assert_eq!(report["committee_at_next"]["frame"], 10);
    assert_eq!(report["committee_at_next"]["size"], 0, "no provers are registered");
    assert_eq!(report["next_frame_binds"]["global_commitments_sha256"].as_str().map(str::len), Some(64));
    assert!(report["next_frame_binds"]["prover_root"].is_string());
}

/// The prover-record listing ends with a summary a second archive's listing
/// can be compared against; `show` prints nothing for an absent address.
#[test]
fn the_prover_shard_listing_ends_with_a_comparable_summary() {
    let fixture = fixture(1);
    let master_path = fixture._dirs[0].path().to_path_buf();
    put_global_head(&fixture, 9);
    let mut out = Vec::new();
    super::prover_shard_dump(&master_path, NETWORK, true, &[], &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let summary = text.lines().last().unwrap();
    assert!(summary.starts_with("# head Some(9)"), "{summary}");
    assert!(summary.contains(" records 0 digest "), "{summary}");
    assert!(summary.ends_with(" orphaned_heads []"), "{summary}");
    for phase in [" prover_root ", " vertex_removes ", " hyperedge_adds ", " hyperedge_removes "] {
        assert!(summary.contains(phase), "the summary names every phase root: {summary}");
    }
    let mut shown = Vec::new();
    super::prover_shard_dump(&master_path, NETWORK, true, &[vec![0xAB; 32]], &mut shown).unwrap();
    assert!(shown.is_empty());
}
