use super::*;

use std::collections::HashSet;

use quil_types::proto::global::{GlobalFrameHeader, MessageBundle, MessageRequest};
use quil_types::proto::keys::Bls48581AggregateSignature;
use quil_types::store::RequestStatus::{Failed, Rejected, Skipped, Succeeded};

fn filter(tag: u8) -> Vec<u8> {
    let mut f = vec![0x11; 32];
    f.push(tag);
    f
}

/// An app frame header of shard `tag`, fee 10, signed by 5 of 7 (as the
/// fake reader below reads `CWCT ‖ committee ‖ signed`).
fn header(tag: u8, app_frame: u64) -> FrameHeader {
    FrameHeader {
        address: filter(tag),
        frame_number: app_frame,
        rank: app_frame + 100,
        fee_total: 10u128.to_be_bytes().to_vec(),
        public_key_signature_bls48581: Some(Bls48581AggregateSignature {
            signature: [b"CWCT".as_slice(), &[7, 5]].concat(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn bundle(request: Request) -> MessageBundle {
    MessageBundle {
        requests: vec![MessageRequest { request: Some(request), ..Default::default() }],
        ..Default::default()
    }
}

fn shard(h: FrameHeader) -> MessageBundle {
    bundle(Request::Shard(h))
}

/// A `committee_handoff` whose fake drain payload is `tag ‖ app frames`.
fn handoff(payload: &[u8]) -> MessageBundle {
    bundle(Request::CommitteeHandoff(payload.to_vec()))
}

fn frame_at(n: u64, timestamp: i64, requests: Vec<MessageBundle>) -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader { frame_number: n, timestamp, ..Default::default() }),
        requests,
    }
}

fn frame(n: u64, requests: Vec<MessageBundle>) -> GlobalFrame {
    frame_at(n, n as i64 * 15_500, requests)
}

fn outcome(status: RequestStatus) -> RequestOutcome {
    RequestOutcome { status, error: String::new() }
}

const NO_OUTCOMES: &[RequestOutcome] = &[];

fn ok(n: usize) -> Vec<RequestOutcome> {
    vec![outcome(Succeeded); n]
}

fn fake_signers(cert: &[u8]) -> Option<(usize, usize)> {
    match cert {
        [committee, signed] => Some((*committee as usize, *signed as usize)),
        _ => None,
    }
}

fn fake_drains(payload: &[u8]) -> Vec<(Vec<u8>, u64)> {
    match payload.split_first() {
        Some((tag, frames)) => frames.iter().map(|f| (filter(*tag), *f as u64)).collect(),
        None => Vec::new(),
    }
}

fn index(start: u64) -> ProductionIndex {
    ProductionIndex::new(start, Decoders { signers: fake_signers, drains: fake_drains })
}

/// Index empty GLOBAL frames through `through`.
fn empty_through(idx: &mut ProductionIndex, through: u64) {
    for n in idx.next_frame()..=through {
        assert!(idx.apply(&frame(n, Vec::new()), Some(NO_OUTCOMES)));
    }
}

struct World {
    grid: GridView,
    active: HashMap<Vec<u8>, u64>,
    halted: BTreeSet<Vec<u8>>,
    committed: HashMap<Vec<u8>, Committed>,
}

/// Live shards as `(tag, active members)`.
fn world(shards: &[(u8, u64)]) -> World {
    let set: BTreeSet<Vec<u8>> = shards.iter().map(|(t, _)| filter(*t)).collect();
    World {
        grid: GridView { source: GridSource::LocalStore, live: set.clone(), grid: Some(set), unavailable: None },
        active: shards.iter().map(|(t, a)| (filter(*t), *a)).collect(),
        halted: BTreeSet::new(),
        committed: HashMap::new(),
    }
}

fn report_of(view: &IndexView, head: u64, w: &World) -> ProductionReport {
    assemble(
        view,
        &Inputs {
            head_frame: head,
            grid: &w.grid,
            active: Some((head, &w.active)),
            halted: &w.halted,
            committed: &w.committed,
            quil: crate::handlers::quil_str,
        },
    )
}

fn report(idx: &ProductionIndex, w: &World) -> ProductionReport {
    report_of(&idx.view(), idx.indexed_through().unwrap_or(0), w)
}

fn entry(r: &ProductionReport, tag: u8) -> &ShardProduction {
    let f = hex::encode(filter(tag));
    r.shards.iter().find(|s| s.filter == f).expect("live shard in the report")
}

#[derive(Default)]
struct MemSource {
    frames: HashMap<u64, (GlobalFrame, Vec<RequestOutcome>)>,
}

impl FrameSource for MemSource {
    fn frame(&self, n: u64) -> quil_types::error::Result<Option<GlobalFrame>> {
        Ok(self.frames.get(&n).map(|(f, _)| f.clone()))
    }

    fn outcomes(&self, n: u64) -> Vec<RequestOutcome> {
        self.frames.get(&n).map(|(_, o)| o.clone()).unwrap_or_default()
    }
}

#[test]
fn rejected_failed_and_skipped_headers_are_not_applied() {
    let mut idx = index(1);
    let f1 = frame(1, vec![shard(header(1, 10)), shard(header(1, 11)), shard(header(1, 12))]);
    idx.apply(&f1, Some(&[outcome(Rejected), outcome(Failed), outcome(Skipped)][..]));
    let v = idx.view();
    let s = &v.shards[&filter(1)];
    assert_eq!((s.window.applied, s.window.inclusions, s.window.not_applied), (0, 0, 3));
    assert_eq!(s.last, None, "an unapplied header is never the last applied one");

    idx.apply(&frame(2, vec![shard(header(1, 10))]), Some(ok(1).as_slice()));
    let v = idx.view();
    let s = &v.shards[&filter(1)];
    assert_eq!((s.window.applied, s.window.not_applied), (1, 3));
    assert_eq!(s.last.map(|l| (l.app_frame, l.global_frame)), Some((10, 2)));
}

#[test]
fn a_repeated_app_frame_counts_once() {
    let mut idx = index(1);
    idx.apply(&frame(1, vec![shard(header(1, 10)), shard(header(1, 10))]), Some(ok(2).as_slice()));
    idx.apply(&frame(2, vec![shard(header(1, 10)), shard(header(1, 9))]), Some(ok(2).as_slice()));
    let v = idx.view();
    let s = &v.shards[&filter(1)];
    assert_eq!((s.window.applied, s.window.inclusions, s.window.fees), (1, 4, 10));
    assert_eq!(s.last.map(|l| (l.app_frame, l.global_frame)), Some((10, 1)));

    idx.apply(&frame(3, vec![shard(header(1, 11))]), Some(ok(1).as_slice()));
    let v = idx.view();
    let s = &v.shards[&filter(1)];
    assert_eq!((s.window.applied, s.window.inclusions, s.window.fees), (2, 5, 20));
}

#[test]
fn outcome_less_frames_wait_then_count_unknown() {
    let mut src = MemSource::default();
    for n in 1..=300u64 {
        let outcomes = if n == 250 { Vec::new() } else { ok(1) };
        if n != 251 {
            src.frames.insert(n, (frame(n, vec![shard(header(1, n))]), outcomes));
        }
    }
    let w = world(&[(1, 4)]);
    let mut idx = index(1);

    let mut calls = 0;
    let a = idx.advance(&src, 300, u64::MAX, &mut || {
        calls += 1;
        Some(260)
    });
    assert_eq!((a.indexed, a.waiting, a.outcome_less.len(), a.missing.len()), (249, Some(250), 0, 0));
    assert_eq!(calls, 1, "the materialized frame is read once, when a frame waits");
    assert_eq!(idx.indexed_through(), Some(249));
    assert_eq!(entry(&report(&idx, &w), 1).class, Class::Producing);

    let a = idx.advance(&src, 300, u64::MAX, &mut || Some(281));
    assert_eq!((a.indexed, a.waiting), (0, Some(250)), "within the grace the cursor stops");

    let a = idx.advance(&src, 300, u64::MAX, &mut || Some(282));
    assert_eq!((a.outcome_less.clone(), a.waiting, a.materialized), (vec![250], Some(251), Some(282)), "a gap waits as well");
    let a = idx.advance(&src, 300, u64::MAX, &mut || Some(283));
    assert_eq!((a.missing.clone(), a.waiting), (vec![251], None));
    assert_eq!(idx.indexed_through(), Some(300));

    let v = idx.view();
    assert!(!v.window_complete, "a missing frame leaves the window incomplete");
    assert_eq!((v.missing_frames, v.outcome_less_frames), (1, 1));
    let s = &v.shards[&filter(1)];
    assert_eq!((s.window.unknown, s.window.applied), (1, 238));
    let r = report(&idx, &w);
    assert_eq!(entry(&r, 1).class, Class::Producing, "applied app frames are positive evidence in an incomplete window");
    let c = &r.summary.classes;
    assert_eq!((c.producing, c.no_data, c.staffed_not_producing), (1, 0, 0));
    assert_eq!(entry(&report(&idx, &world(&[(2, 4)])), 2).class, Class::NoData, "no claim without one, never a stall");
}

#[test]
fn classes_apply_in_order() {
    assert_eq!(classify(false, 3, 0, 9), Class::Producing, "an applied app frame needs no complete window");
    assert_eq!(classify(false, 0, 0, 9), Class::NoData);
    assert_eq!(classify(false, 0, 0, 0), Class::NoData);
    assert_eq!(classify(true, 1, 5, 0), Class::Producing, "an applied app frame outranks unknown headers");
    assert_eq!(classify(true, 0, 1, 9), Class::NoData);
    assert_eq!(classify(true, 0, 0, 3), Class::BelowQuorum);
    assert_eq!(classify(true, 0, 0, 4), Class::StaffedNotProducing);

    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(3, 1))]), Some(ok(1).as_slice()));
    assert!(idx.window_complete());
    let r = report(&idx, &world(&[(1, 4), (2, 3), (3, 0)]));
    let classes: Vec<Class> = [1, 2, 3].iter().map(|t| entry(&r, *t).class).collect();
    assert_eq!(classes, vec![Class::StaffedNotProducing, Class::BelowQuorum, Class::Producing]);
    let c = &r.summary.classes;
    assert_eq!((r.summary.live_shards, c.no_data, c.producing, c.below_quorum, c.staffed_not_producing), (3, 0, 1, 1, 1));

    let mut short = index(1);
    empty_through(&mut short, 239);
    assert_eq!(entry(&report(&short, &world(&[(1, 4)])), 1).class, Class::NoData, "239 of 240 frames");
}

#[test]
fn inclusions_leave_the_window_but_the_last_applied_frame_stays() {
    let mut idx = index(1);
    idx.apply(&frame(1, vec![shard(header(1, 10))]), Some(ok(1).as_slice()));
    empty_through(&mut idx, 240);
    assert_eq!(idx.view().shards[&filter(1)].window.applied, 1);

    empty_through(&mut idx, 241);
    let r = report(&idx, &world(&[(1, 4)]));
    let e = entry(&r, 1);
    assert_eq!((e.applied_in_window, e.class), (0, Class::StaffedNotProducing));
    assert_eq!((e.last_applied_app_frame, e.last_applied_global_frame), (Some(10), Some(1)));

    // Kept as long as a restart's rebuild would recall it, then dropped.
    empty_through(&mut idx, REBUILD_FRAMES);
    assert!(idx.view().shards[&filter(1)].last.is_some());
    empty_through(&mut idx, REBUILD_FRAMES + 1);
    assert!(!idx.view().shards.contains_key(&filter(1)));
}

#[test]
fn off_grid_filters_count_apart() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 5)), shard(header(9, 5))]), Some(ok(2).as_slice()));
    let r = report(&idx, &world(&[(1, 4)]));
    assert_eq!(r.shards.len(), 1);
    assert_eq!((r.summary.off_grid_inclusions_in_window, r.summary.applied_in_window), (Some(1), 1));
    assert_eq!(entry(&r, 1).class, Class::Producing);
}

#[test]
fn the_frame_interval_is_the_median_of_header_timestamps() {
    let mut idx = index(1);
    for (n, ts) in [(1, 0), (2, 15_500), (3, 31_000), (4, 47_000)] {
        idx.apply(&frame_at(n, ts, Vec::new()), Some(NO_OUTCOMES));
    }
    assert_eq!(idx.median_frame_interval_ms(), Some(15_500));
    // A missing frame has no timestamp: the pairs around it are skipped.
    idx.apply_missing(5);
    idx.apply(&frame_at(6, 1_000_000, Vec::new()), Some(NO_OUTCOMES));
    assert_eq!(idx.median_frame_interval_ms(), Some(15_500));
}

#[test]
fn signers_come_from_the_certificate_or_the_legacy_bitmask() {
    let mut legacy = header(2, 1);
    legacy.public_key_signature_bls48581 =
        Some(Bls48581AggregateSignature { signature: vec![1, 2], bitmask: vec![0b1011, 0b1], ..Default::default() });
    let mut unreadable = header(3, 1);
    unreadable.public_key_signature_bls48581 =
        Some(Bls48581AggregateSignature { signature: b"CWCT\x01\x02\x03".to_vec(), ..Default::default() });
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 1)), shard(legacy), shard(unreadable)]), Some(ok(3).as_slice()));
    let r = report(&idx, &world(&[(1, 4), (2, 4), (3, 4)]));
    let signers = |t| (entry(&r, t).signers_last, entry(&r, t).committee_last);
    assert_eq!(signers(1), (Some(5), Some(7)));
    assert_eq!(signers(2), (Some(4), None), "legacy: bitmask popcount, no committee size");
    assert_eq!(signers(3), (None, None));
    assert_eq!(cw_signers(b"not a certificate"), None);
}

#[test]
fn drain_headers_count_apart_from_production() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(
        &frame(240, vec![handoff(&[1, 10, 11]), handoff(&[2, 20]), handoff(&[2, 21])]),
        Some(&[outcome(Succeeded), outcome(Succeeded), outcome(Rejected)][..]),
    );
    idx.apply(&frame(241, vec![shard(header(1, 11)), handoff(&[1, 11, 12])]), Some(ok(2).as_slice()));
    let r = report(&idx, &world(&[(1, 4), (2, 4)]));
    let (a, b) = (entry(&r, 1), entry(&r, 2));
    assert_eq!((a.applied_in_window, a.drained_in_window, a.class), (1, 3, Class::Producing));
    assert_eq!((b.applied_in_window, b.drained_in_window, b.class), (0, 1, Class::StaffedNotProducing));
    assert_eq!(r.summary.drained_in_window, 4);
}

#[test]
fn the_snapshot_is_rebuilt_after_an_advance_and_refreshed_while_waiting() {
    let t0 = Instant::now();
    assert!(snapshot_due(false, None, t0), "the first snapshot");
    assert!(snapshot_due(true, Some(t0), t0), "the view changed");
    assert!(!snapshot_due(false, Some(t0), t0 + Duration::from_secs(14)));
    assert!(snapshot_due(false, Some(t0), t0 + SNAPSHOT_REFRESH));

    let w = world(&[(1, 4)]);
    let snapshot = Snapshot::new(report_of(&IndexView { indexed_through: Some(6), ..Default::default() }, 9, &w));
    assert_eq!(snapshot.body.last(), Some(&b'\n'));
    let body: serde_json::Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!((body["head_frame"].as_u64(), body["indexed_through"].as_u64()), (Some(9), Some(6)));
}

#[test]
fn the_grid_digest_is_the_archive_shard_list_digest() {
    // Expected values computed apart from this code (Python hashlib):
    // sha256 over sorted u32-BE-length-prefixed filters, first 4 bytes.
    let filters: BTreeSet<Vec<u8>> = [filter(0x00), filter(0x01), [vec![0x11; 32], vec![0x3f, 0x02]].concat(), vec![0xaa; 32]]
        .into_iter()
        .collect();
    assert_eq!(grid_digest(&filters), "34fb3075");
    assert_eq!(grid_digest(&BTreeSet::new()), "e3b0c442");
}

#[test]
fn the_response_selects_shards_and_keeps_its_shape() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(3, 7))]), Some(ok(1).as_slice()));
    let mut w = world(&[(1, 4), (2, 3), (3, 5)]);
    w.halted.insert(filter(2));
    assert_eq!(w.grid.source, GridSource::LocalStore);
    w.committed.insert(filter(3), Committed { app_head: 7, generation: 2, members: 5 });
    let r = report(&idx, &w);

    let producing = r.response(Some(Class::Producing), None);
    assert_eq!(producing.shards.len(), 1);
    assert_eq!(producing.summary.live_shards, 3, "the summary covers every live shard");
    let two = hex::encode(filter(2));
    let one = r.response(None, Some(two.as_str()));
    assert_eq!((one.shards.len(), one.shards[0].class, one.shards[0].coverage_halt), (1, Class::BelowQuorum, true));
    assert!(r.response(None, Some("ff")).shards.is_empty());
    assert_eq!(r.response(None, None).shards.len(), 3);

    let f3 = hex::encode(filter(3));
    assert_eq!(
        serde_json::to_string(entry(&r, 3)).unwrap(),
        format!(
            r#"{{"filter":"{f3}","class":"producing","last_applied_app_frame":7,"last_applied_global_frame":240,"last_applied_rank":107,"signers_last":5,"committee_last":7,"committed_app_head":7,"session_generation":2,"session_members":5,"active_members":5,"applied_in_window":1,"inclusions_in_window":1,"not_applied_in_window":0,"unknown_outcome_in_window":0,"drained_in_window":0,"fees_relayed_in_window_quil":"0.00000000125","coverage_halt":false}}"#
        )
    );
    let body = serde_json::to_string(&r.response(Some(Class::Producing), None)).unwrap();
    assert!(
        body.starts_with(r#"{"head_frame":240,"indexed_through":240,"window_frames":240,"window_complete":true,"index_waiting_frame":null,"median_frame_interval_ms":15500,"stored_head_frame":null,"stored_head_timestamp_ms":null,"as_of_frame":240,"as_of_timestamp_ms":3720000,"lag_frames":0,"stale":false,"stale_reason":null,"values_known":true,"built_at_ms":0,"summary":{"live_shards":3,"classes":{"no_data":0,"producing":1,"below_quorum":1,"staffed_not_producing":1},"#),
        "{body}"
    );
}

#[test]
fn a_lagging_index_keeps_its_classes_flagged_stale() {
    // Stored and materialized frames end at 300; the received head is 340,
    // past frame 301 by more than the grace.
    let mut src = MemSource::default();
    for n in 1..=300u64 {
        let requests = if n % 10 == 0 { vec![shard(header(1, n))] } else { Vec::new() };
        let outcomes = ok(requests.len());
        src.frames.insert(n, (frame(n, requests), outcomes));
    }
    let mut idx = index(1);
    let a = idx.advance(&src, 340, u64::MAX, &mut || Some(300));
    assert_eq!((idx.indexed_through(), a.waiting), (Some(300), Some(301)));
    let mut stall = StallTracker::default();
    assert_eq!(stall.observe(a.waiting, 340, Instant::now()), Some(StallEvent::Started { frame: 301 }));
    let mut view = idx.view();
    view.waiting_frame = stall.waiting_frame();

    let r = report_of(&view, 340, &world(&[(1, 4), (2, 4), (3, 2)]));
    let classes: Vec<Class> = [1, 2, 3].iter().map(|t| entry(&r, *t).class).collect();
    assert_eq!(classes, vec![Class::Producing, Class::StaffedNotProducing, Class::BelowQuorum]);
    let c = &r.summary.classes;
    assert_eq!((r.summary.live_shards, c.no_data, c.producing, c.below_quorum, c.staffed_not_producing), (3, 0, 1, 1, 1));
    assert_eq!(r.summary.applied_in_window, 24);
    let w = &r.window;
    assert!(!w.window_complete, "the window still reads incomplete while the index waits");
    assert_eq!((w.index_waiting_frame, w.as_of_frame, w.lag_frames), (Some(301), Some(300), Some(40)));
    assert!(w.stale && w.values_known);
    assert_eq!(
        serde_json::to_string(w).unwrap(),
        r#"{"head_frame":340,"indexed_through":300,"window_frames":240,"window_complete":false,"index_waiting_frame":301,"median_frame_interval_ms":15500,"stored_head_frame":null,"stored_head_timestamp_ms":null,"as_of_frame":300,"as_of_timestamp_ms":4650000,"lag_frames":40,"stale":true,"stale_reason":"the index waits for GLOBAL frame 301, not stored or not materialized although the head passed it by the grace; indexed through frame 300","values_known":true,"built_at_ms":0}"#
    );
    let stats = serde_json::to_value(r.stats()).unwrap();
    assert_eq!((stats["stale"].as_bool(), stats["as_of_frame"].as_u64(), stats["classes"]["producing"].as_u64()), (Some(true), Some(300), Some(1)));

    // Within the grace nothing is stale.
    let fresh = report_of(&idx.view(), 310, &world(&[(1, 4)]));
    assert_eq!((fresh.window.stale, fresh.window.lag_frames, fresh.window.window_complete), (false, Some(10), true));
}

#[test]
fn stale_flags_a_catch_up_an_early_wait_and_an_old_census() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 1))]), Some(ok(1).as_slice()));
    let w = world(&[(1, 4), (2, 4)]);
    let at = |head| report_of(&idx.view(), head, &w).window;
    assert!(!at(240 + OUTCOME_GRACE).stale, "within the grace");
    let jump = at(241 + OUTCOME_GRACE);
    assert_eq!((jump.stale, jump.lag_frames, jump.stale_reason.as_deref()), (true, Some(33), Some("the index trails the head by 33 frames: catching up")));

    let early = report_of(&IndexView { waiting_frame: Some(5), ..Default::default() }, 40, &w).window;
    assert!(early.stale && early.stale_reason.unwrap().ends_with("; nothing indexed yet"), "a wait before any frame is indexed");

    let view = idx.view();
    let inputs = |active| Inputs {
        head_frame: 240,
        grid: &w.grid,
        active,
        halted: &w.halted,
        committed: &w.committed,
        quil: crate::handlers::quil_str,
    };
    let old = assemble(&view, &inputs(Some((238, &w.active))));
    assert_eq!(
        (old.window.stale, old.window.values_known, old.window.stale_reason.as_deref()),
        (true, true, Some("the prover census is from frame 238: the prover snapshot could not be rebuilt since"))
    );
}

#[test]
fn without_a_census_only_producing_classifies_and_the_values_are_unknown() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 1))]), Some(ok(1).as_slice()));
    let w = world(&[(1, 4), (2, 4), (3, 0)]);
    let r = assemble(
        &idx.view(),
        &Inputs { head_frame: 240, grid: &w.grid, active: None, halted: &w.halted, committed: &w.committed, quil: crate::handlers::quil_str },
    );
    let classes: Vec<Class> = [1, 2, 3].iter().map(|t| entry(&r, *t).class).collect();
    assert_eq!(classes, vec![Class::Producing, Class::NoData, Class::NoData], "no census: no below_quorum claim");
    assert!(!r.window.values_known && r.window.stale);
    assert_eq!(r.unknown_reason.as_deref(), Some(NO_PROVERS));

    // The registry unreadable on the first read: no live set, values unknown.
    let none = World {
        grid: GridView { unavailable: Some(NO_REGISTRY), ..Default::default() },
        active: HashMap::new(),
        halted: BTreeSet::new(),
        committed: HashMap::new(),
    };
    let r = report_of(&idx.view(), 240, &none);
    assert_eq!((r.window.values_known, r.unknown_reason.as_deref(), r.summary.grid_unavailable), (false, Some(NO_REGISTRY), Some(NO_REGISTRY)));
}

/// A grid cache answer listing shards 1 and 2 with data (and one empty QUIL
/// grid shard, so the grid is the cache's).
fn cache_with_two_shards() -> HashMap<Vec<u8>, (u64, u64)> {
    HashMap::from([(filter(1), (100, 1)), (filter(2), (100, 1)), (quil_filter(&[0, 7, 9]), (0, 0))])
}

/// An explorer over an in-memory store holding GLOBAL frames 0..=`stored`
/// (shard 1 applies an app frame in every tenth), received head `head`,
/// its grid from the archive-cache answer in `grid` and an empty registry.
fn memory_state(stored: u64, head: u64, grid: Arc<parking_lot::Mutex<Option<HashMap<Vec<u8>, (u64, u64)>>>>) -> crate::ExplorerState {
    let db = quil_store::RocksDb::open_in_memory().expect("an in-memory store");
    let raw = db.inner();
    let clock = quil_store::RocksClockStore::new(raw.clone());
    for n in 0..=stored {
        let requests = if n > 0 && n % 10 == 0 { vec![shard(header(1, n))] } else { Vec::new() };
        let outcomes = ok(requests.len());
        clock.put_global_frame(&frame(n, requests), None).expect("store a frame");
        if !outcomes.is_empty() {
            clock.put_global_clock_frame_outcomes(n, &outcomes).expect("store its outcomes");
        }
    }
    let hg = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg as Arc<dyn quil_types::store::HypergraphStore>,
        Arc::new(quil_tries::ShaInclusionProver),
    ));
    crate::ExplorerState::new(
        Arc::new(clock),
        crdt,
        Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
        Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
        Arc::new(quil_store::RocksShardsStore::new(raw)),
        None,
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        Arc::new(crate::RecentMessageRing::new(16)),
        Arc::new(std::sync::atomic::AtomicU64::new(head)),
    )
    .with_archive_grid(Arc::new(move || grid.lock().clone()))
}

#[test]
fn an_indexer_restarted_with_its_history_file_reads_no_row_it_saved() {
    let tmp = history::persist::TempPath::new("indexer");
    let grid = Arc::new(parking_lot::Mutex::new(Some(cache_with_two_shards())));
    let run = |indexer: &mut Indexer, state: &crate::ExplorerState| {
        for _ in 0..200 {
            indexer.tick(state, 3_000);
            if indexer.backfill.as_ref().is_some_and(|plan| plan.is_done()) {
                return;
            }
        }
        panic!("the backfill did not complete");
    };
    // Rows 960 through 2940 backfilled, 3000 live.
    let state = memory_state(3_000, 3_000, grid.clone()).with_history_file(tmp.0.clone(), 0);
    let mut first = Indexer::default();
    run(&mut first, &state);
    assert_eq!((first.backfill.as_ref().unwrap().frames, state.production_history.read().len()), (2_941, 35));
    assert!(tmp.0.exists(), "saved once the live row is recorded");
    first.saver.save_at_shutdown(state.history_file.as_ref().unwrap(), &state.production_history);

    // A restart over the same frames.
    let restarted = memory_state(3_000, 3_000, grid).with_history_file(tmp.0.clone(), 0);
    let source = StoreSource(restarted.clock_store.as_ref());
    history::persist::restore(restarted.history_file.as_ref().unwrap(), &source, &restarted.production_history);
    assert_eq!(restarted.production_history.read().len(), 35);
    let mut second = Indexer::default();
    run(&mut second, &restarted);
    let plan = second.backfill.as_ref().unwrap();
    assert_eq!((plan.frames, plan.rows), (0, 0), "every row below the live one restored");
    let (before, after) = (state.production_history.read(), restarted.production_history.read());
    assert_eq!(
        before.final_rows().map(|r| r.frame).collect::<Vec<_>>(),
        after.final_rows().map(|r| r.frame).collect::<Vec<_>>()
    );
}

fn served(state: &crate::ExplorerState) -> Arc<Snapshot> {
    state.production_snapshot.read().clone().expect("a snapshot")
}

#[test]
fn an_indexer_tick_behind_the_head_keeps_classifying_flagged_stale() {
    // Frames stored through 300, the received head at 340: the index waits
    // for 301 beyond the grace.
    let grid = Arc::new(parking_lot::Mutex::new(Some(cache_with_two_shards())));
    let state = memory_state(300, 340, grid.clone());
    let mut indexer = Indexer::default();
    let tick = indexer.tick(&state, 340);
    assert_eq!((tick.through, tick.advance.waiting, tick.stall), (Some(300), Some(301), Some(StallEvent::Started { frame: 301 })));
    assert_eq!(tick.unknown, None);
    let snapshot = served(&state);
    let r = &snapshot.report;
    // The registry is empty: shard 2, without an applied frame, is below
    // quorum over the window through 300, not no_data.
    assert_eq!((entry(r, 1).class, entry(r, 2).class), (Class::Producing, Class::BelowQuorum));
    let w = &r.window;
    assert_eq!((w.window_complete, w.index_waiting_frame, w.as_of_frame, w.lag_frames), (false, Some(301), Some(300), Some(40)));
    assert!(w.stale && w.values_known);
    assert_eq!((w.stored_head_frame, w.stored_head_timestamp_ms), (Some(300), Some(300 * 15_500)));
    assert!(w.built_at_ms > 0);
    let body: serde_json::Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!((body["stale"].as_bool(), body["summary"]["classes"]["below_quorum"].as_u64()), (Some(true), Some(1)));

    // The task restarts (a fresh indexer) while the grid cannot be read:
    // the previous snapshot's values serve on, flagged stale as of 300.
    *grid.lock() = None;
    let tick = Indexer::default().tick(&state, 345);
    let reason = tick.unknown.expect("the census inputs are unreadable");
    assert!(reason.starts_with("no archive shard-info refresh"), "{reason}");
    assert!(!reason.contains("waits for GLOBAL frame"), "the log reason carries no index wait");
    let carried = served(&state);
    let (w, s) = (&carried.report.window, &carried.report.summary);
    assert_eq!((w.head_frame, w.as_of_frame, w.lag_frames, w.values_known, w.stale), (345, Some(300), Some(45), true, true));
    assert_eq!((s.live_shards, s.classes.producing, s.classes.below_quorum), (2, 1, 1));
    assert!(w.stale_reason.as_deref().unwrap().ends_with("serving the last known values, as of frame 300"));
}

#[test]
fn an_indexer_tick_assesses_eviction_at_its_head() {
    let grid = Arc::new(parking_lot::Mutex::new(Some(cache_with_two_shards())));
    let state = memory_state(300, 300, grid);
    let mut indexer = Indexer::default();
    // The first tick builds the snapshot, which makes the assessment.
    indexer.tick(&state, 300);
    let first = state.eviction.read().clone().expect("an assessment");
    assert_eq!(first.frame, 300);
    // A tick at the same head keeps it.
    indexer.tick(&state, 300);
    assert!(Arc::ptr_eq(&first, state.eviction.read().as_ref().unwrap()));
    // A new head, not stored yet: no snapshot build is due, and the tick
    // still assesses it, so requests need not.
    let tick = indexer.tick(&state, 301);
    assert!(tick.build.is_none());
    assert_eq!(state.eviction.read().as_ref().map(|e| e.frame), Some(301));
}

#[test]
fn an_applied_app_frame_is_producing_in_a_short_window() {
    let mut idx = index(1);
    empty_through(&mut idx, 9);
    idx.apply(&frame(10, vec![shard(header(1, 1))]), Some(ok(1).as_slice()));
    assert!(!idx.window_complete());
    let r = report(&idx, &world(&[(1, 4), (2, 4), (3, 0)]));
    let classes: Vec<Class> = [1, 2, 3].iter().map(|t| entry(&r, *t).class).collect();
    assert_eq!(classes, vec![Class::Producing, Class::NoData, Class::NoData]);
}

#[test]
fn an_unknown_live_set_serves_the_last_known_values_flagged_stale() {
    // Registry filters off the grid and no grid shard holding data: an
    // empty live set, a failed read, never a network without shards.
    let off = grid_from_cache(&[filter(1)], Some(HashMap::from([(quil_filter(&[0, 7, 9]), (0, 0))])));
    assert_eq!((off.live.len(), off.unavailable), (0, Some(NO_LIVE)));

    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 1))]), Some(ok(1).as_slice()));
    let known = report(&idx, &world(&[(1, 4), (2, 3)]));
    assert!(known.window.values_known && !known.window.stale);

    empty_through(&mut idx, 250);
    let lost = World { grid: off, active: HashMap::new(), halted: BTreeSet::new(), committed: HashMap::new() };
    let unknown = report_of(&idx.view(), 252, &lost);
    assert!(!unknown.window.values_known && unknown.window.stale);
    let reason = format!("values unknown: {NO_LIVE}");
    assert_eq!(unknown.window.stale_reason.as_deref(), Some(reason.as_str()));
    let first = unknown.clone().or_last_known(None);
    assert!(!first.window.values_known && first.window.stale, "never known: placeholders, flagged");

    let served = unknown.or_last_known(Some(&known));
    let (w, s) = (&served.window, &served.summary);
    assert_eq!((w.head_frame, w.indexed_through, w.as_of_frame, w.lag_frames), (252, Some(250), Some(240), Some(12)));
    assert!(w.stale && w.values_known);
    let carried = format!("{reason}; serving the last known values, as of frame 240");
    assert_eq!(w.stale_reason.as_deref(), Some(carried.as_str()));
    assert_eq!((s.live_shards, s.classes.producing, s.classes.below_quorum, served.shards.len()), (2, 1, 1, 2));

    // A later failed build carries the same values on; a build that reads
    // the live set serves its own again.
    let again = report_of(&idx.view(), 260, &lost).or_last_known(Some(&served));
    assert_eq!((again.window.as_of_frame, again.window.lag_frames, again.summary.live_shards), (Some(240), Some(20), 2));
    let back = report_of(&idx.view(), 260, &world(&[(1, 4)])).or_last_known(Some(&served));
    assert_eq!((back.window.as_of_frame, back.window.stale, back.summary.live_shards), (Some(250), false, 1));
}

#[test]
fn advancing_caps_the_frames_per_tick() {
    let mut src = MemSource::default();
    for n in 1..=100 {
        src.frames.insert(n, (frame(n, Vec::new()), Vec::new()));
    }
    let mut idx = index(1);
    assert_eq!(idx.advance(&src, 100, MAX_FRAMES_PER_TICK, &mut || None).indexed, 32);
    assert_eq!(idx.indexed_through(), Some(32));
    assert_eq!(idx.advance(&src, 100, MAX_FRAMES_PER_TICK, &mut || None).indexed, 32);
    assert_eq!(idx.indexed_through(), Some(64));
}

#[test]
fn a_short_outcome_list_leaves_the_uncovered_headers_unknown() {
    let mut idx = index(1);
    let f = frame(1, vec![shard(header(1, 5)), shard(header(2, 5)), shard(header(3, 5))]);
    idx.apply(&f, Some(&[outcome(Rejected), outcome(Succeeded)][..]));
    let v = idx.view();
    let counts = |t| {
        let w = &v.shards[&filter(t)].window;
        (w.not_applied, w.applied, w.unknown)
    };
    assert_eq!((counts(1), counts(2), counts(3)), ((1, 0, 0), (0, 1, 0), (0, 0, 1)));
    assert_eq!((v.outcome_less_frames, v.missing_frames), (1, 0));
}

#[test]
fn an_outcome_less_frame_blanks_only_its_shards() {
    let mut idx = index(1);
    empty_through(&mut idx, 99);
    idx.apply(&frame(100, vec![shard(header(3, 1))]), Some(ok(1).as_slice()));
    empty_through(&mut idx, 240);
    idx.apply(&frame(241, vec![shard(header(2, 5)), shard(header(3, 2))]), None);
    let r = report(&idx, &world(&[(1, 4), (2, 4), (3, 4)]));
    assert!(r.window.window_complete, "outcomes missing in one frame keep the window complete");
    let classes: Vec<Class> = [1, 2, 3].iter().map(|t| entry(&r, *t).class).collect();
    assert_eq!(classes, vec![Class::StaffedNotProducing, Class::NoData, Class::Producing]);
    assert_eq!((r.summary.outcome_less_frames_in_window, r.summary.unknown_outcome_in_window), (1, 2));
}

#[test]
fn a_missing_frame_blanks_shards_without_an_applied_frame_until_it_leaves_the_window() {
    let mut idx = index(1);
    empty_through(&mut idx, 239);
    idx.apply(&frame(240, vec![shard(header(1, 1))]), Some(ok(1).as_slice()));
    idx.apply_missing(241);
    let w = world(&[(1, 4), (2, 4)]);
    let r = report(&idx, &w);
    assert!(!r.window.window_complete);
    assert_eq!(r.summary.missing_frames_in_window, 1);
    assert_eq!((entry(&r, 1).class, entry(&r, 2).class), (Class::Producing, Class::NoData));
    assert!(!r.window.stale, "a missing frame is no lag");
    empty_through(&mut idx, 241 + WINDOW_FRAMES);
    assert_eq!(entry(&report(&idx, &w), 2).class, Class::StaffedNotProducing);
}

/// GLOBAL frame `n` of the restart scenario, with its outcomes.
fn scenario(n: u64) -> (GlobalFrame, Vec<RequestOutcome>) {
    let mut bundles = Vec::new();
    let mut outcomes = Vec::new();
    if n % 3 == 0 {
        bundles.push(shard(header(1, n / 3)));
        outcomes.push(outcome(Succeeded));
    }
    if n % 3 == 1 && n > 1 {
        bundles.push(shard(header(1, n / 3)));
        outcomes.push(outcome(Succeeded));
    }
    if n % 5 == 0 && n <= 760 {
        bundles.push(shard(header(2, n / 5)));
        outcomes.push(outcome(Succeeded));
    }
    if n == 700 {
        bundles.push(shard(header(3, 1)));
        outcomes.push(outcome(Succeeded));
    }
    if n == 1000 || n == 1400 {
        bundles.push(shard(header(3, 2)));
        outcomes.push(outcome(Rejected));
    }
    if n == 900 {
        bundles.push(handoff(&[4, 10, 11]));
        outcomes.push(outcome(Succeeded));
    }
    if n == 1300 {
        bundles.push(shard(header(4, 12)));
        outcomes.push(outcome(Succeeded));
    }
    (frame(n, bundles), outcomes)
}

#[test]
fn a_rebuilt_index_agrees_with_a_continuous_one() {
    let head = 1_500;
    let mut continuous = index(1);
    let mut rebuilt = index(head - REBUILD_FRAMES + 1);
    for n in 1..=head {
        let (f, o) = scenario(n);
        continuous.apply(&f, Some(o.as_slice()));
        if n > head - REBUILD_FRAMES {
            rebuilt.apply(&f, Some(o.as_slice()));
        }
    }
    let (a, b) = (continuous.view(), rebuilt.view());
    assert!(!a.shards.contains_key(&filter(2)), "idle for 720 frames: forgotten");
    assert_eq!(a.shards.get(&filter(3)).map(|s| s.last), Some(None), "applied 800 frames ago: forgotten");
    assert_eq!(a.shards, b.shards);
    assert_eq!((a.indexed_through, a.window_complete, a.median_frame_interval_ms), (b.indexed_through, b.window_complete, b.median_frame_interval_ms));
}

#[test]
fn a_wait_beyond_the_grace_starts_repeats_and_ends() {
    let t0 = Instant::now();
    let mut stall = StallTracker::default();
    assert_eq!(stall.observe(Some(100), 100 + OUTCOME_GRACE - 1, t0), None, "within the grace");
    assert_eq!(stall.observe(Some(100), 100 + OUTCOME_GRACE, t0), Some(StallEvent::Started { frame: 100 }));
    assert_eq!(stall.waiting_frame(), Some(100));
    assert_eq!(stall.observe(Some(100), 140, t0 + Duration::from_secs(60)), None);
    let later = t0 + STALL_REPEAT + Duration::from_secs(1);
    assert_eq!(
        stall.observe(Some(101), 150, later),
        Some(StallEvent::Persisting { frame: 101, waited: STALL_REPEAT + Duration::from_secs(1) })
    );
    let end = t0 + Duration::from_secs(700);
    assert_eq!(stall.observe(None, 150, end), Some(StallEvent::Ended { frame: 101, waited: Duration::from_secs(700) }));
    assert_eq!((stall.waiting_frame(), stall.observe(None, 150, end)), (None, None));
}

#[test]
fn selection_parameters_are_checked() {
    let params = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };
    assert_eq!(parse_selection(&params(&[])), Ok((None, None)));
    assert_eq!(parse_selection(&params(&[("class", " Producing ")])), Ok((Some(Class::Producing), None)));
    assert_eq!(parse_selection(&params(&[("filter", "ABcd"), ("class", "")])), Ok((None, Some("abcd".to_string()))));
    assert_eq!(parse_selection(&params(&[("class", "stalled")])), Err("invalid class"));
    assert_eq!(parse_selection(&params(&[("filter", "zz")])), Err("invalid filter"));
}

#[test]
fn the_grid_lists_the_quil_rows_frozen_ones_included() {
    let row = |key: Vec<u8>, prefix: Vec<u32>| quil_types::store::ShardInfo {
        shard_key: key,
        prefix,
        size: Vec::new(),
        data_shards: 0,
        commitment: Vec::new(),
    };
    let quil = [vec![1, 2, 3], quil_execution::domains::QUIL_TOKEN.to_vec()].concat();
    let other = [vec![4, 5, 6], vec![0xaa; 32]].concat();
    let rows = vec![
        row(quil.clone(), vec![0]),
        row(quil.clone(), vec![1]),
        // A pending split's frozen parent stays listed, as #816 lists it.
        row(quil.clone(), vec![63, 2]),
        row(quil, vec![1]),
        row(other, Vec::new()),
        row(vec![9; 10], vec![0]),
    ];
    let grid = grid_filters(&rows);
    assert_eq!(grid.len(), 3, "the QUIL key's rows, duplicates once; other apps and short keys out");
    // Computed apart from this code (Python hashlib), as in
    // `the_grid_digest_is_the_archive_shard_list_digest`.
    assert_eq!(grid_digest(&grid), "6686d6df");
}

fn quil_filter(suffix: &[u8]) -> Vec<u8> {
    [quil_execution::domains::QUIL_TOKEN.as_slice(), suffix].concat()
}

#[test]
fn a_regular_node_takes_its_grid_from_the_archive_cache() {
    // The archive lists depth-7 QUIL shards; the node's registry still
    // names a genesis depth-6 one, and the list carries another app's shard.
    let (current, empty, stale, other) =
        (quil_filter(&[0, 7, 8]), quil_filter(&[0, 7, 9]), quil_filter(&[0, 6, 4]), [vec![0xaa; 32], vec![5]].concat());
    let cache = HashMap::from([(current.clone(), (100, 1)), (empty.clone(), (0, 0)), (other.clone(), (5, 1))]);
    let grid = grid_from_cache(&[current.clone(), stale.clone()], Some(cache));
    assert_eq!(grid.source, GridSource::ArchiveCache);
    assert_eq!(grid.grid, Some(BTreeSet::from([current.clone(), empty])), "the QUIL grid only");
    assert_eq!(grid.live, BTreeSet::from([current.clone(), other]));

    let mut idx = index(1);
    empty_through(&mut idx, 239);
    let header_on = |f: &[u8]| FrameHeader { address: f.to_vec(), ..header(1, 3) };
    idx.apply(&frame(240, vec![shard(header_on(&current)), shard(header_on(&stale))]), Some(ok(2).as_slice()));
    let w = World { grid, active: HashMap::from([(current.clone(), 4)]), halted: BTreeSet::new(), committed: HashMap::new() };
    let r = report(&idx, &w);
    let on = r.shards.iter().find(|s| s.filter == hex::encode(&current)).unwrap();
    assert_eq!(on.class, Class::Producing);
    let s = &r.summary;
    assert_eq!((s.off_grid_inclusions_in_window, s.grid_shards, s.grid_digest.as_deref()), (Some(1), Some(2), Some("5936e534")));
    let json = serde_json::to_string(s).unwrap();
    assert!(json.ends_with(r#""grid_source":"archive_cache","grid_shards":2,"grid_digest":"5936e534","grid_unavailable":null}"#), "{json}");
}

/// GLOBAL's address in the registry (a prover's allocation) and in the
/// shard sizes (a root row an archive's shards store holds) makes no live
/// app shard, from either grid source; the grid and its digest stay the
/// QUIL rows'.
#[test]
fn global_is_never_a_live_app_shard() {
    let global = quil_execution::domains::GLOBAL.to_vec();
    let (staffed, empty) = (quil_filter(&[0, 7, 8]), quil_filter(&[0, 7, 9]));
    let registry = vec![staffed.clone(), global.clone()];
    let sizes = HashMap::from([
        (hex::encode(&staffed), (num_bigint::BigInt::from(5), 1)),
        (hex::encode(&empty), (num_bigint::BigInt::from(0), 0)),
        (hex::encode(&global), (num_bigint::BigInt::from(0), 0)),
    ]);
    let row = |key: Vec<u8>, prefix: Vec<u32>| quil_types::store::ShardInfo {
        shard_key: key,
        prefix,
        size: Vec::new(),
        data_shards: 0,
        commitment: Vec::new(),
    };
    let quil_rows = vec![
        row([vec![1, 2, 3], quil_execution::domains::QUIL_TOKEN.to_vec()].concat(), vec![0]),
        row([vec![1, 2, 3], quil_execution::domains::QUIL_TOKEN.to_vec()].concat(), vec![1]),
    ];
    let rows = [quil_rows.clone(), vec![row([vec![4, 5, 6], global.clone()].concat(), Vec::new())]].concat();
    let store = grid_from_store(&registry, &sizes, &rows);
    assert_eq!(store.live, BTreeSet::from([staffed.clone()]), "the staffed shard; GLOBAL out");
    let cache = HashMap::from([(staffed.clone(), (5, 1)), (empty.clone(), (0, 0)), (global.clone(), (7, 1))]);
    assert_eq!(grid_from_cache(&registry, Some(cache)).live, BTreeSet::from([staffed.clone()]), "a sized GLOBAL entry too");

    let mut idx = index(1);
    empty_through(&mut idx, 240);
    assert!(idx.window_complete());
    let w = World { grid: store, active: HashMap::from([(staffed.clone(), 4)]), halted: BTreeSet::new(), committed: HashMap::new() };
    let r = report(&idx, &w);
    let s = &r.summary;
    assert_eq!((s.live_shards, s.classes.below_quorum, s.classes.staffed_not_producing), (1, 0, 1));
    assert!(r.shards.iter().all(|shard| shard.filter != hex::encode(&global)), "no GLOBAL row");
    let grid = grid_filters(&quil_rows);
    assert_eq!((s.grid_shards, s.grid_digest.clone()), (Some(grid.len() as u64), Some(grid_digest(&grid))), "the QUIL grid's");
}

#[test]
fn an_unavailable_grid_is_reported_never_off_grid() {
    let registry = vec![quil_filter(&[0, 6, 4])];
    for cache in [None, Some(HashMap::new()), Some(HashMap::from([(vec![0xaa; 33], (5, 1))]))] {
        let grid = grid_from_cache(&registry, cache);
        assert!(grid.unavailable.is_some() && grid.grid.is_none() && grid.live.is_empty(), "{grid:?}");
    }
    let empty_store = grid_from_store(&registry, &HashMap::new(), &[]);
    assert_eq!((empty_store.source, empty_store.unavailable.is_some()), (GridSource::LocalStore, true));

    let mut idx = index(1);
    empty_through(&mut idx, 239);
    let header_on = FrameHeader { address: registry[0].clone(), ..header(1, 3) };
    idx.apply(&frame(240, vec![shard(header_on)]), Some(ok(1).as_slice()));
    let w = World { grid: grid_from_cache(&registry, None), active: HashMap::new(), halted: BTreeSet::new(), committed: HashMap::new() };
    let r = report(&idx, &w);
    let s = &r.summary;
    assert!(r.shards.is_empty());
    assert_eq!((s.off_grid_inclusions_in_window, s.grid_shards, s.grid_digest.clone()), (None, None, None));
    let json = serde_json::to_string(s).unwrap();
    assert!(
        json.ends_with(r#""grid_source":"archive_cache","grid_shards":null,"grid_digest":null,"grid_unavailable":"no archive shard-info refresh has answered yet"}"#),
        "{json}"
    );
}

// ---------------------------------------------------------------------------
// Measurement (run by hand)
// ---------------------------------------------------------------------------

fn percentiles(values: &[u64]) -> String {
    if values.is_empty() {
        return "n/a".into();
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let at = |p: usize| values[(values.len() - 1) * p / 100];
    format!("{}/{}/{}", at(50), at(95), values[values.len() - 1])
}

fn micros(d: Duration) -> u64 {
    d.as_micros() as u64
}

fn peak_rss() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l[6..].trim().to_string()))
        .unwrap_or_else(|| "n/a".into())
}

/// One pass over the last `frames` frames: per-frame read+clone, outcomes,
/// decode, signer and apply costs, the steady-state tick over the last
/// window (one frame's read+outcomes+apply plus `view()`), and the frame
/// interval median. Frames below request retention are counted apart and
/// kept out of every figure.
fn measure_pass(pass: &str, store: &quil_store::RocksClockStore, frames: u64) -> Option<i64> {
    use quil_types::store::ClockStore as _;
    let Some(head) = store.get_latest_frame_number() else {
        eprintln!("[{pass}] the store holds no GLOBAL frame");
        return None;
    };
    let first = head.saturating_sub(frames - 1);
    let retained_from = store.global_requests_retained_from();
    let mut idx = ProductionIndex::new(first, Decoders::default());
    let (mut read, mut outcome_reads, mut decode, mut signers, mut apply, mut tick, mut view_us) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut sizes = Vec::new();
    let mut per_frame = Vec::new();
    let mut filters = HashSet::new();
    let (mut not_found, mut read_errors, mut below_retention, mut without_outcomes, mut drains) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut headers_total = 0u64;
    let mut first_error = None;
    let started = Instant::now();
    for n in first..=head {
        let below = retained_from.is_some_and(|r| n < r);
        let t = Instant::now();
        let frame = match store.get_global_clock_frame(n) {
            Ok(frame) => frame,
            Err(QuilError::NotFound(_)) => {
                not_found += 1;
                idx.apply_missing(n);
                continue;
            }
            Err(e) => {
                read_errors += 1;
                if first_error.is_none() {
                    first_error = Some(format!("frame {n}: {e}"));
                }
                idx.apply_missing(n);
                continue;
            }
        };
        let read_t = t.elapsed();
        let t = Instant::now();
        let outcomes = store.get_global_clock_frame_outcomes(n).unwrap_or_default();
        let outcomes_t = t.elapsed();
        let t = Instant::now();
        let mut headers: Vec<&FrameHeader> = Vec::new();
        for bundle in &frame.requests {
            for request in &bundle.requests {
                match &request.request {
                    Some(Request::Shard(h)) => headers.push(h),
                    Some(Request::CommitteeHandoff(p)) => drains += seal_drain_headers(p).len() as u64,
                    _ => {}
                }
            }
        }
        let decode_t = t.elapsed();
        let t = Instant::now();
        for h in &headers {
            std::hint::black_box(Signers::read(h, cw_signers));
        }
        let signers_t = t.elapsed();
        let t = Instant::now();
        idx.apply(&frame, (!outcomes.is_empty()).then_some(outcomes.as_slice()));
        let apply_t = t.elapsed();
        if below {
            below_retention += 1;
            continue;
        }
        if !frame.requests.is_empty() && outcomes.is_empty() {
            without_outcomes += 1;
        }
        for h in &headers {
            filters.insert(h.address.clone());
        }
        headers_total += headers.len() as u64;
        per_frame.push(headers.len() as u64);
        sizes.push(prost::Message::encoded_len(&frame) as u64);
        read.push(micros(read_t));
        outcome_reads.push(micros(outcomes_t));
        decode.push(micros(decode_t));
        signers.push(micros(signers_t));
        apply.push(micros(apply_t));
        if n + WINDOW_FRAMES > head {
            let t = Instant::now();
            std::hint::black_box(idx.view());
            let view_t = t.elapsed();
            view_us.push(micros(view_t));
            tick.push(micros(read_t + outcomes_t + apply_t + view_t));
        }
    }
    let total = started.elapsed();
    let median = idx.median_frame_interval_ms();
    let view = idx.view();
    eprintln!(
        "[{pass}] frames {first}..={head}: measured {}, not found {not_found}, read errors {read_errors}{}, \
         below request retention {below_retention} (retained from {retained_from:?}, excluded), \
         with requests but no outcomes {without_outcomes}; pass {total:?}",
        sizes.len(),
        first_error.map(|e| format!(" (first: {e})")).unwrap_or_default()
    );
    eprintln!("[{pass}] frame encoded_len bytes p50/p95/max: {}", percentiles(&sizes));
    eprintln!(
        "[{pass}] shard headers per frame (P) p50/p95/max: {}; total {headers_total}; distinct filters (S) {}; drain headers {drains}",
        percentiles(&per_frame),
        filters.len()
    );
    eprintln!(
        "[{pass}] us/frame p50/p95/max: read+clone {}, outcomes {}, decode {}, unverified_signers {}, apply {}",
        percentiles(&read),
        percentiles(&outcome_reads),
        percentiles(&decode),
        percentiles(&signers),
        percentiles(&apply)
    );
    eprintln!(
        "[{pass}] steady-state tick over the last {} frames (read+outcomes+apply+view) us p50/p95/max: {}; view() alone {}; \
         median GLOBAL frame interval {median:?} ms",
        tick.len(),
        percentiles(&tick),
        percentiles(&view_us)
    );
    eprintln!(
        "[{pass}] index: window_complete {}, missing {}, outcome-less {} frames in the window, {} shards, heap ~{} bytes; peak RSS {}",
        view.window_complete,
        view.missing_frames,
        view.outcome_less_frames,
        view.shards.len(),
        idx.heap_bytes(),
        peak_rss()
    );
    median
}

/// The explorer's state over the opened store, as an archive wires it
/// (without the coverage monitor's halt provider).
fn explorer_state(db: &quil_store::RocksDb, head: u64) -> crate::ExplorerState {
    let raw = db.inner();
    let hg = Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        Arc::new(quil_tries::ShaInclusionProver),
    ));
    quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg.as_ref(), false, true);
    let t = Instant::now();
    let registry = quil_execution::prover_registry::SharedProverRegistry::new();
    registry.refresh_from_store(hg.as_ref()).expect("read the prover registry");
    eprintln!("[state] prover registry refresh {:?} (node start-up work, not the explorer's)", t.elapsed());
    let provider: crate::AppShardsProvider = {
        let crdt = crdt.clone();
        Arc::new(move |shard_key: &[u8], prefix: &[u32]| {
            let info = quil_types::store::ShardInfo {
                shard_key: shard_key.to_vec(),
                prefix: prefix.to_vec(),
                size: Vec::new(),
                data_shards: 0,
                commitment: Vec::new(),
            };
            let meta = quil_engine::app_shard_metadata::get_app_shard_metadata(crdt.as_ref(), &info)?;
            Some((meta.size, meta.data_shards, meta.commitments))
        })
    };
    crate::ExplorerState::new(
        Arc::new(quil_store::RocksClockStore::new(raw.clone())),
        crdt,
        Arc::new(registry),
        Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
        Arc::new(quil_store::RocksShardsStore::new(raw)),
        Some(provider),
        None,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
        Arc::new(crate::RecentMessageRing::new(16)),
        Arc::new(std::sync::atomic::AtomicU64::new(head)),
    )
}

/// The background rebuild of the last `REBUILD_FRAMES` frames through
/// `advance`, then the snapshot build: once with the shard sets read, twice
/// with them cached.
fn measure_rebuild_and_snapshot(db: &quil_store::RocksDb) {
    let clock = quil_store::RocksClockStore::new(db.inner());
    let Some(head) = clock.get_latest_frame_number() else { return };
    let state = explorer_state(db, head);
    let mut idx = ProductionIndex::new(head.saturating_sub(REBUILD_FRAMES - 1), Decoders::default());
    let t = Instant::now();
    // A regular node records no outcomes: step over them as an archive
    // steps over lost ones, so the whole range is read.
    let advance = idx.advance(&StoreSource(&clock), head, u64::MAX, &mut || Some(u64::MAX));
    eprintln!(
        "[rebuild] {} frames through {head} in {:?} (missing {}, outcome-less {}, waiting {:?}, error {:?})",
        advance.indexed,
        t.elapsed(),
        advance.missing.len(),
        advance.outcome_less.len(),
        advance.waiting,
        advance.error
    );
    let view = idx.view();
    let mut sets = crate::handlers::ShardSets::default();
    for run in ["shard sets read", "shard sets cached", "shard sets cached"] {
        let (report, t) = crate::handlers::build_production_report(&state, head, &view, &mut sets);
        let body = Snapshot::new(report);
        eprintln!(
            "[snapshot] {run}: total {:?} = shard sets {:?} + census {:?} + halts {:?} + committed {:?} + assemble {:?}; \
             live {} grid {:?} (digest {:?}), body {} bytes, classes {:?}",
            t.total,
            t.shard_sets,
            t.census,
            t.halts,
            t.committed,
            t.assemble,
            body.report.summary.live_shards,
            body.report.summary.grid_shards,
            body.report.summary.grid_digest,
            body.body.len(),
            body.report.summary.classes
        );
    }
    report_against_grid("local store", &state, head, &view);
    match archive_grid_list() {
        Ok((endpoint, list)) => {
            eprintln!("[archive grid] {} filters from {endpoint}", list.len());
            let state = state.clone().with_archive_grid(Arc::new(move || Some(list.clone())));
            report_against_grid("archive list", &state, head, &view);
        }
        Err(e) => eprintln!("[archive grid] not measured: {e}"),
    }
}

/// The snapshot over `state`'s grid source, and where the indexed headers
/// fall against it.
fn report_against_grid(label: &str, state: &crate::ExplorerState, head: u64, view: &IndexView) {
    let mut sets = crate::handlers::ShardSets::default();
    let (report, t) = crate::handlers::build_production_report(state, head, view, &mut sets);
    let live: BTreeSet<Vec<u8>> = report.shards.iter().filter_map(|s| hex::decode(&s.filter).ok()).collect();
    let grid = sets_grid(&sets);
    let indexed: BTreeSet<Vec<u8>> = view.shards.keys().cloned().collect();
    let s = &report.summary;
    eprintln!(
        "[grid {label}] source {:?}, build {:?}; grid {:?} (digest {:?}, unavailable {:?}); live {} (on grid {}); \
         indexed shards {} (on grid {}, live {}); off-grid inclusions in window {:?}; window applied {}, unknown-outcome {}; \
         classes {:?}",
        s.grid_source,
        t.total,
        s.grid_shards,
        s.grid_digest,
        s.grid_unavailable,
        live.len(),
        live.intersection(&grid).count(),
        indexed.len(),
        indexed.intersection(&grid).count(),
        indexed.intersection(&live).count(),
        s.off_grid_inclusions_in_window,
        s.applied_in_window,
        s.unknown_outcome_in_window,
        s.classes
    );
}

fn sets_grid(sets: &crate::handlers::ShardSets) -> BTreeSet<Vec<u8>> {
    sets.grid_view().grid.clone().unwrap_or_default()
}

/// The QUIL grid as an archive answers `GetAppShards` now, read once from
/// `QUIL_KPI_ARCHIVE` or the genesis archives under a throwaway network key:
/// the call needs an authenticated channel, not a known identity. Read-only.
fn archive_grid_list() -> Result<(String, HashMap<Vec<u8>, (u64, u64)>), String> {
    let falcon = quil_p2p::generate_falcon_signing_key();
    let endpoints: Vec<String> = match std::env::var("QUIL_KPI_ARCHIVE") {
        Ok(endpoint) if !endpoint.is_empty() => vec![endpoint],
        _ => quil_engine::genesis::genesis_archive_static_ips().into_iter().map(|(_, ip)| format!("{ip}:8340")).collect(),
    };
    let quil = quil_execution::domains::QUIL_TOKEN;
    let mut key = Vec::new();
    key.extend_from_slice(&quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3));
    key.extend_from_slice(&quil);
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    for endpoint in endpoints {
        let rows = runtime.block_on(async {
            let mut client = quil_rpc::ArchiveClient::connect_mtls(&endpoint, &falcon).await.map_err(|e| e.to_string())?;
            client.get_app_shards(key.clone(), Vec::new()).await.map_err(|e| e.to_string())
        });
        match rows {
            Ok(rows) if !rows.is_empty() => {
                let list = rows
                    .iter()
                    .map(|row| {
                        let size = row.size.iter().fold(0u64, |acc, b| acc.saturating_mul(256).saturating_add(*b as u64));
                        (quil_forest::shard_prefix_to_filter(&quil, &row.prefix), (size, row.data_shards))
                    })
                    .filter(|(filter, _)| !filter.is_empty())
                    .collect();
                return Ok((endpoint, list));
            }
            Ok(_) => eprintln!("[archive grid] {endpoint}: empty answer"),
            Err(e) => eprintln!("[archive grid] {endpoint}: {e}"),
        }
    }
    Err("no archive answered".into())
}

/// Cost of the index over a node store, opened read-only beside its
/// running node (`open_for_read_only_live`: no lock, no writes; mount it
/// read-only): `QUIL_KPI_STORE=<store dir>`, `QUIL_KPI_FRAMES` (default
/// 2880). Passes with the frame cache off (cold reads) and warmed (the
/// archive path over its 720 frames, every hit a deep clone), then the
/// rebuild and the snapshot build. Debug builds overstate the costs.
#[test]
#[ignore = "measurement over a node store"]
fn measure_production_index_over_store() {
    let Ok(path) = std::env::var("QUIL_KPI_STORE") else {
        eprintln!("QUIL_KPI_STORE is unset: nothing measured");
        return;
    };
    let frames: u64 = std::env::var("QUIL_KPI_FRAMES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_880)
        .max(1);
    let db = quil_store::RocksDb::open_for_read_only_live(std::path::Path::new(&path)).expect("open the store read-only");
    let cold = quil_store::RocksClockStore::new(db.inner());
    measure_pass("cold", &cold, frames);
    let cached = quil_store::RocksClockStore::new(db.inner());
    let started = Instant::now();
    let warmed = cached.warm_global_frame_cache().expect("warm the frame cache");
    eprintln!("[cached] cache warm-up: {warmed} frames in {:?}; peak RSS {}", started.elapsed(), peak_rss());
    // The cache holds the latest 720 frames: a longer pass would mostly miss.
    measure_pass("cached", &cached, frames.min(REBUILD_FRAMES));
    measure_rebuild_and_snapshot(&db);
    eprintln!("peak RSS (VmHWM): {}", peak_rss());
}
