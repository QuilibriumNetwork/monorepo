use super::*;

use std::collections::HashMap;

use quil_types::proto::global::{
    message_request::Request, FrameHeader, GlobalFrame, GlobalFrameHeader, MessageBundle, MessageRequest,
};
use quil_types::proto::keys::Bls48581AggregateSignature;
use quil_types::store::RequestOutcome;
use quil_types::store::RequestStatus::{self, Rejected, Succeeded};

fn filter(tag: u8) -> Vec<u8> {
    let mut f = vec![0x11; 32];
    f.push(tag);
    f
}

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

const DECODERS: Decoders = Decoders { signers: fake_signers, drains: fake_drains };

/// GLOBAL frame `n` of the test chain, with its outcomes:
/// - shard 1 applies app frame `n` in every frame;
/// - shard 2's header is rejected in every seventh frame;
/// - shard 3 applies app frame `n` through frame 1500, then stops;
/// - shards 4 and 7 apply one app frame, carried again 600 and 700 frames
///   later (a re-inclusion an index started too late counts as new);
/// - shard 5 has a header without an outcome at 2000, shard 6 a drain at 2010;
/// - frame 2500 is never stored, frame 2600 has no outcomes.
fn chain_frame(n: u64) -> Option<(GlobalFrame, Vec<RequestOutcome>)> {
    if n == 2500 {
        return None;
    }
    let mut requests: Vec<(MessageBundle, Option<RequestStatus>)> =
        vec![(bundle(Request::Shard(header(1, n))), Some(Succeeded))];
    if n % 7 == 0 {
        requests.push((bundle(Request::Shard(header(2, n))), Some(Rejected)));
    }
    if n <= 1500 {
        requests.push((bundle(Request::Shard(header(3, n))), Some(Succeeded)));
    }
    if n == 1600 || n == 2200 {
        requests.push((bundle(Request::Shard(header(4, 50))), Some(Succeeded)));
    }
    if n == 4100 || n == 4800 {
        requests.push((bundle(Request::Shard(header(7, 70))), Some(Succeeded)));
    }
    if n == 2010 {
        requests.push((bundle(Request::CommitteeHandoff(vec![6, 3])), Some(Succeeded)));
    }
    if n == 2000 {
        requests.push((bundle(Request::Shard(header(5, 1))), None));
    }
    let outcomes = if n == 2600 {
        Vec::new()
    } else {
        requests
            .iter()
            .map_while(|(_, status)| status.clone())
            .map(|status| RequestOutcome { status, error: String::new() })
            .collect()
    };
    let frame = GlobalFrame {
        header: Some(GlobalFrameHeader { frame_number: n, timestamp: n as i64 * 15_500, ..Default::default() }),
        requests: requests.into_iter().map(|(b, _)| b).collect(),
    };
    Some((frame, outcomes))
}

/// The test chain through `head`, every frame read counted.
struct Chain {
    head: u64,
    reads: std::cell::Cell<u64>,
}

impl Chain {
    fn new(head: u64) -> Self {
        Self { head, reads: std::cell::Cell::new(0) }
    }
}

impl FrameSource for Chain {
    fn frame(&self, n: u64) -> quil_types::error::Result<Option<GlobalFrame>> {
        self.reads.set(self.reads.get() + 1);
        Ok((n <= self.head).then(|| chain_frame(n)).flatten().map(|(f, _)| f))
    }

    fn outcomes(&self, n: u64) -> Vec<RequestOutcome> {
        (n <= self.head).then(|| chain_frame(n)).flatten().map(|(_, o)| o).unwrap_or_default()
    }
}

fn past_grace() -> Option<u64> {
    Some(u64::MAX)
}

/// Rows of an index run from frame 1 through `head` without a restart,
/// stopping at every row frame as the live index does.
fn continuous_rows(head: u64) -> BTreeMap<u64, Row> {
    let chain = Chain::new(head);
    let mut idx = ProductionIndex::new(1, DECODERS);
    let mut rows = BTreeMap::new();
    while idx.indexed_through() != Some(head) {
        let target = advance_target(&idx, head);
        let a = idx.advance(&chain, target, u64::MAX, &mut past_grace);
        assert_eq!(idx.indexed_through(), Some(target), "{a:?}");
        if let Some(row) = row_of(&idx, &idx.view()) {
            rows.insert(row.frame, row);
        }
    }
    rows
}

#[test]
fn row_frames_and_where_an_index_stops() {
    assert_eq!((row_frame_at_or_after(0), row_frame_at_or_after(1), row_frame_at_or_after(60)), (0, 60, 60));
    assert_eq!(ROW_LEAD, 960);
    assert_eq!(live_start(5_030), 4_020, "a lead below the newest row frame at or below the head");
    assert_eq!(live_start(500), 0);

    let mut idx = ProductionIndex::new(live_start(5_030), DECODERS);
    assert_eq!(first_exact_row(&idx), 4_980);
    assert_eq!(advance_target(&idx, 5_030), 4_980, "the rebuild ends at that row");
    let chain = Chain::new(5_030);
    idx.advance(&chain, 4_980, u64::MAX, &mut past_grace);
    assert_eq!(advance_target(&idx, 5_030), 5_030);
    assert_eq!(advance_target(&idx, 6_000), 5_040, "never past the next row frame");
    assert_eq!(first_exact_row(&ProductionIndex::new(0, DECODERS)), 960);
}

#[test]
fn a_row_is_the_window_at_its_frame_plus_its_own_frames() {
    let rows = continuous_rows(2_760);
    assert_eq!(rows.keys().next(), Some(&1_020), "the first row an index from frame 1 records exactly");

    assert_eq!((rows[&1_380].epoch, rows[&1_440].epoch), (1, 2), "a row's epoch is its frame's");
    let r = &rows[&1_500];
    assert_eq!((r.epoch, r.timestamp_ms, r.median_frame_interval_ms), (2, Some(1_500 * 15_500), Some(15_500)));
    assert!(r.window_complete);
    assert_eq!((r.producing_shards, r.shards_with_headers_in_window), (2, 3));
    assert_eq!((r.applied, r.inclusions, r.not_applied, r.unknown_outcome, r.drained), (120, 120, 9, 0, 0));

    let r = &rows[&2_040];
    assert_eq!((r.producing_shards, r.shards_with_headers_in_window), (1, 3), "an unknown header is no data");
    assert_eq!((r.applied, r.inclusions, r.not_applied, r.unknown_outcome, r.drained), (60, 60, 9, 1, 1));

    let r = &rows[&2_340];
    assert_eq!(
        (r.producing_shards, r.shards_with_headers_in_window, r.applied, r.inclusions),
        (1, 3, 60, 60),
        "an app frame carried again is not new: shard 4 does not produce"
    );

    let r = &rows[&2_520];
    assert!(!r.window_complete);
    assert_eq!(
        (r.producing_shards, r.missing_frames_in_window, r.missing_frames),
        (1, 1, 1),
        "an applied app frame is positive evidence in an incomplete window"
    );
    assert_eq!((r.applied, r.timestamp_ms), (59, Some(2_520 * 15_500)));

    let r = &rows[&2_760];
    assert!(r.window_complete, "the missing frame left the window");
    assert_eq!((r.producing_shards, r.outcome_less_frames_in_window, r.outcome_less_frames), (1, 1, 0));
    assert!(rows.values().all(|r| r.census.is_none()));
}

#[test]
fn live_rows_after_a_restart_match_a_continuous_index() {
    let reference = continuous_rows(5_400);
    let mut head = 5_030;
    let mut idx = ProductionIndex::new(live_start(head), DECODERS);
    let mut chain = Chain::new(head);
    let a = idx.advance(&chain, advance_target(&idx, head), u64::MAX, &mut past_grace);
    assert_eq!((a.indexed, idx.indexed_through()), (961, Some(4_980)));
    assert_eq!(row_of(&idx, &idx.view()).as_ref(), Some(&reference[&4_980]), "re-inclusion at 4800 not new");
    let mut rows = 1;
    while idx.indexed_through() != Some(5_400) {
        // Seven frames a tick: the head is sometimes one short of a row frame.
        head = (head + 7).min(5_400);
        chain = Chain::new(head);
        let target = advance_target(&idx, head);
        assert!(target - idx.indexed_through().unwrap() <= ROW_FRAMES);
        idx.advance(&chain, target, MAX_FRAMES_PER_TICK, &mut past_grace);
        if let Some(row) = row_of(&idx, &idx.view()) {
            assert_eq!(&row, &reference[&row.frame]);
            rows += 1;
        }
    }
    assert_eq!(rows, 8, "4980 through 5400");
}

#[test]
fn the_census_is_kept_only_near_the_head() {
    let mut row = continuous_rows(1_020).remove(&1_020).unwrap();
    let summary = Summary {
        live_shards: 9,
        classes: ClassCounts { no_data: 1, producing: 5, below_quorum: 1, staffed_not_producing: 2 },
        applied_in_window: 0,
        inclusions_in_window: 0,
        not_applied_in_window: 0,
        unknown_outcome_in_window: 0,
        drained_in_window: 0,
        off_grid_inclusions_in_window: None,
        missing_frames_in_window: 0,
        outcome_less_frames_in_window: 0,
        fees_relayed_in_window_quil: "0".into(),
        grid_source: Default::default(),
        grid_shards: Some(12),
        grid_digest: None,
        grid_unavailable: None,
    };
    attach_census(&mut row, &summary, 1_080);
    assert_eq!(row.census, None, "a row frame behind the head: not the census at the row");
    attach_census(&mut row, &summary, 1_079);
    let census = row.census.clone().unwrap();
    assert_eq!((census.head_frame, census.live_shards, census.grid_shards, census.classes.producing), (1_079, 9, Some(12), 5));
}

#[test]
fn the_backfill_matches_a_continuous_index_newest_segment_first() {
    let head = 10_980;
    let reference = continuous_rows(head);
    let chain = Chain::new(head);
    let rows = RwLock::new(Rows::default());
    let mut plan = Backfill::new(head, Some(1), None, DECODERS);
    assert_eq!((plan.floor(), plan.top()), ((1_020, Floor::EarliestStoredFrame), Some(10_920)));
    let mut segments = Vec::new();
    let mut steps = 0;
    while !plan.is_done() {
        let step = plan.step(&chain, MAX_FRAMES_PER_TICK, &mut past_grace, &rows);
        assert!(step.indexed <= MAX_FRAMES_PER_TICK, "a step reads at most its budget");
        assert_eq!((step.error.as_deref(), step.waiting), (None, None));
        if let Some(s) = step.segment {
            if segments.is_empty() {
                assert_eq!(rows.read().rows.keys().next(), Some(&2_340), "the newest day is published first");
            }
            segments.push((s.lo, s.hi, s.rows, s.frames));
        }
        steps += 1;
    }
    assert_eq!(segments, vec![(2_340, 10_920, 144, 9_541), (1_020, 2_280, 22, 2_221)]);
    assert_eq!((plan.rows, plan.frames, chain.reads.get()), (166, 11_762, 11_762));
    assert_eq!(steps, 11_762u64.div_ceil(MAX_FRAMES_PER_TICK) + 1, "full steps, plus the segment end");
    let held = rows.read();
    assert_eq!(held.len(), 166);
    for (frame, row) in &held.rows {
        assert_eq!(row, &reference[frame], "row {frame}");
    }
    assert!(plan.state().complete);
}

#[test]
fn held_segments_are_not_read_again() {
    let head = 3_000;
    let chain = Chain::new(head);
    let rows = RwLock::new(Rows::default());
    for row in continuous_rows(head).into_values() {
        rows.write().insert(row);
    }
    let mut plan = Backfill::new(head, Some(1), None, DECODERS);
    let step = plan.step(&chain, MAX_FRAMES_PER_TICK, &mut past_grace, &rows);
    assert!(step.completed && plan.is_done());
    assert_eq!((step.indexed, chain.reads.get()), (0, 0));
}

#[test]
fn the_floor_is_the_depth_the_earliest_frame_or_request_retention() {
    let floor = |live, earliest, retained| {
        let plan = Backfill::new(live, earliest, retained, DECODERS);
        (plan.floor(), plan.top(), plan.is_done())
    };
    let live = 300_000;
    let depth = live - (HISTORY_ROWS - 1) * ROW_FRAMES;
    assert_eq!(floor(live, Some(0), None), ((depth, Floor::HistoryDepth), Some(live - 60), false));
    assert_eq!(floor(live, Some(100_000), None), ((100_980, Floor::EarliestStoredFrame), Some(live - 60), false));
    assert_eq!(floor(live, Some(100_000), Some(200_000)), ((201_000, Floor::RequestRetention), Some(live - 60), false));
    assert_eq!(floor(live, Some(100_000), Some(50_000)), ((100_980, Floor::EarliestStoredFrame), Some(live - 60), false));
    assert_eq!(floor(live, None, None), ((live, Floor::EarliestStoredFrame), None, true), "an empty store");
    assert_eq!(floor(600, Some(0), None), ((960, Floor::EarliestStoredFrame), None, true), "too young for a row");
    assert_eq!(floor(live, Some(live - 1_000), None).1, None, "a store shallower than a lead");
}

fn row(frame: u64, producing: u64, complete: bool, census: Option<(u64, u64)>) -> Row {
    Row {
        frame,
        epoch: quil_types::consensus::epoch_for_frame(frame),
        timestamp_ms: Some(frame as i64 * 10_000),
        window_complete: complete,
        missing_frames_in_window: 0,
        outcome_less_frames_in_window: 0,
        median_frame_interval_ms: Some(10_000),
        producing_shards: producing,
        shards_with_headers_in_window: producing + 1,
        applied: 2 * producing,
        inclusions: 2 * producing + 1,
        not_applied: 0,
        unknown_outcome: 0,
        drained: 1,
        missing_frames: complete as u64 ^ 1,
        outcome_less_frames: 0,
        census: census.map(|(live, producing)| Census {
            head_frame: frame + 3,
            live_shards: live,
            classes: ClassCounts { no_data: 0, producing, below_quorum: 1, staffed_not_producing: live - producing - 1 },
            grid_shards: Some(150),
        }),
    }
}

fn query(params: &[(&str, &str)]) -> Result<Query, &'static str> {
    parse_query(&params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>())
}

#[test]
fn query_parameters_are_checked() {
    assert_eq!(query(&[]), Ok(Query::default()));
    assert_eq!(
        query(&[("from_frame", "60"), ("to_frame", " 120 "), ("bucket", "Epoch")]),
        Ok(Query { from_frame: Some(60), to_frame: Some(120), bucket: Bucket::Epoch })
    );
    assert_eq!(query(&[("bucket", "row"), ("to_frame", "")]), Ok(Query::default()));
    assert_eq!(query(&[("bucket", "day")]), Err("invalid bucket"));
    assert_eq!(query(&[("from_frame", "-1")]), Err("invalid from_frame"));
    assert_eq!(query(&[("to_frame", "x")]), Err("invalid to_frame"));
}

#[test]
fn the_response_selects_a_week_of_rows_at_most() {
    let mut rows = Rows::default();
    let empty = rows.response(&Query::default()).unwrap();
    assert_eq!((empty.rows.as_ref().map(Vec::len), empty.from_frame, empty.first_row_frame), (Some(0), None, None));
    for n in 1..=2_000u64 {
        rows.insert(row(n * 60, n % 5, true, None));
    }
    let r = rows.response(&Query::default()).unwrap();
    let selected = r.rows.as_ref().unwrap();
    assert_eq!((r.from_frame, r.to_frame, selected.len()), (Some(120_000 - 1_007 * 60), Some(120_000), 1_008));
    assert!(selected.windows(2).all(|w| w[0].frame < w[1].frame), "ascending");
    assert_eq!((r.first_row_frame, r.last_row_frame, r.rows_held), (Some(60), Some(120_000), 2_000));

    let week = |from, to| rows.response(&Query { from_frame: Some(from), to_frame: Some(to), bucket: Bucket::Row });
    assert_eq!(week(60, 60 + 1_007 * 60).unwrap().rows.unwrap().len(), 1_008);
    assert!(week(60, 60 + 1_008 * 60).is_err(), "1009 rows");
    assert_eq!(week(61, 119).unwrap().rows.unwrap().len(), 0);
    assert_eq!(week(120, 60).err(), Some("from_frame is above to_frame"));
    let r = rows.response(&Query { from_frame: Some(200_000), ..Default::default() });
    assert_eq!(r.err(), Some("from_frame is above to_frame"), "the default end is the last row");

    let all = rows.response(&Query { bucket: Bucket::Epoch, ..Default::default() }).unwrap();
    assert_eq!((all.from_frame, all.epochs.as_ref().map(Vec::len)), (Some(60), Some(167)), "every row held");
    assert!(all.rows.is_none());
    let body = serde_json::to_string(&all).unwrap();
    assert!(body.starts_with(r#"{"row_frames":60,"window_frames":240,"epoch_frames":720,"bucket":"epoch","first_row_frame":60,"last_row_frame":120000,"rows_held":2000,"backfill":{"complete":false,"floor_frame":null,"floor":null},"from_frame":60,"to_frame":120000,"epochs":["#), "{body}");
}

#[test]
fn epochs_roll_up_the_rows_recorded_at_their_frames() {
    let mut rows = Rows::default();
    rows.insert(row(660, 9, true, None));
    for (i, frame) in (720..=1_380).step_by(60).enumerate() {
        let i = i as u64;
        let census = (i < 3).then_some((100 + i, 50 + i));
        rows.insert(row(frame, 40 + i, i != 11, census));
    }
    rows.insert(row(1_440, 7, true, None));
    let r = rows.response(&Query { bucket: Bucket::Epoch, ..Default::default() }).unwrap();
    let epochs = r.epochs.unwrap();
    assert_eq!(epochs.iter().map(|e| (e.epoch, e.rows)).collect::<Vec<_>>(), vec![(0, 1), (1, 12), (2, 1)]);
    let e = &epochs[1];
    assert_eq!((e.first_row_frame, e.last_row_frame, e.complete_rows, e.census_rows), (720, 1_380, 11, 3));
    assert_eq!(e.producing_shards, Some(Spread { min: 40, mean: 45.0, max: 50 }), "the incomplete row is left out");
    assert_eq!(e.live_shards, Some(Spread { min: 100, mean: 101.0, max: 102 }));
    assert_eq!(e.live_producing, Some(Spread { min: 50, mean: 51.0, max: 52 }));
    assert_eq!((e.applied, e.inclusions, e.drained, e.missing_frames), ((40..52).sum::<u64>() * 2, (40..52).sum::<u64>() * 2 + 12, 12, 1));
    assert_eq!((epochs[0].live_shards.clone(), epochs[0].producing_shards.clone()), (None, Some(Spread { min: 9, mean: 9.0, max: 9 })));

    let one = rows.response(&Query { from_frame: Some(700), to_frame: Some(800), bucket: Bucket::Epoch }).unwrap();
    assert_eq!(one.epochs.unwrap().iter().map(|e| (e.epoch, e.rows)).collect::<Vec<_>>(), vec![(1, 2)]);
    assert_eq!(Spread::of(&[1, 2]).unwrap().mean, 1.5);
    assert_eq!(Spread::of(&[1, 1, 2]).unwrap().mean, 1.3);
}

#[test]
fn rows_are_bounded_and_small() {
    let mut rows = Rows::default();
    for n in 1..=HISTORY_ROWS + 5 {
        rows.insert(row(n * 60, 1, true, None));
    }
    assert_eq!((rows.len(), rows.stats().first_row_frame), (HISTORY_ROWS, Some(6 * 60)), "the oldest are dropped");
    assert!(std::mem::size_of::<Row>() <= 256, "{} bytes", std::mem::size_of::<Row>());
    assert_eq!(
        (rows.missing_run(6 * 60, 100 * 60), rows.missing_run(60, 100 * 60), rows.missing_run(120, 60)),
        (None, Some((60, 300)), None)
    );
}

#[test]
fn the_backfill_plans_only_runs_of_rows_not_held() {
    let mut rows = Rows::default();
    for frame in [120, 180, 360, 420] {
        rows.insert(row(frame, 1, true, None));
    }
    assert_eq!(rows.missing_run(60, 480), Some((480, 480)));
    assert_eq!(rows.missing_run(60, 420), Some((240, 300)), "the newest run below the held rows");
    assert_eq!(rows.missing_run(60, 180), Some((60, 60)));
    assert_eq!(rows.missing_run(120, 180), None);
    assert_eq!(rows.missing_run(240, 300), Some((240, 300)));
    assert_eq!((rows.count(60, 480), rows.count(480, 60)), (4, 0));
    rows.forget_below(360);
    assert_eq!((rows.len(), rows.stats().first_row_frame), (2, Some(360)));
}

/// Rows a complete backfill below `head` records over the test chain.
fn backfilled(head: u64) -> RwLock<Rows> {
    let chain = Chain::new(head);
    let rows = RwLock::new(Rows::default());
    let mut plan = Backfill::new(head, Some(1), None, DECODERS);
    while !plan.is_done() {
        plan.step(&chain, u64::MAX, &mut past_grace, &rows);
    }
    rows
}

/// Rows over the test chain's frames 2500 (never stored) and 2600 (without
/// outcomes), stepped over past the grace, are not final.
const NOT_FINAL: std::ops::RangeInclusive<u64> = 2_520..=3_540;

#[test]
fn a_row_is_final_once_no_stepped_over_frame_is_within_its_lead() {
    let head = 4_200;
    let chain = Chain::new(head);
    let mut idx = ProductionIndex::new(1, DECODERS);
    let mut provisional = Vec::new();
    while idx.indexed_through() != Some(head) {
        let target = advance_target(&idx, head);
        idx.advance(&chain, target, u64::MAX, &mut past_grace);
        if let Some(row) = row_of(&idx, &idx.view()) {
            if !is_final(&idx, &row) {
                provisional.push(row.frame);
            }
        }
    }
    assert_eq!(provisional, NOT_FINAL.step_by(60).collect::<Vec<_>>(), "up to ROW_LEAD above 2600");
    let rows = backfilled(head);
    let held = rows.read();
    assert_eq!((held.len(), held.final_rows().count()), (53, 53 - 18), "the backfill records the same");
    assert!(held.final_rows().all(|r| !NOT_FINAL.contains(&r.frame)));
}

#[test]
fn final_rows_round_trip_through_the_history_file() {
    let head = 4_200;
    let rows = backfilled(head);
    // A live row, with its census, at the stored frame's timestamp.
    let mut live = row(head, 3, true, Some((9, 3)));
    live.timestamp_ms = Some(head as i64 * 15_500);
    rows.write().record(live.clone(), true);
    let tmp = persist::TempPath::new("round-trip");
    let mut saver = persist::Saver::default();
    let first_save = Instant::now();
    saver.save_due(&tmp.file(), &rows, first_save);
    assert!(!rows.read().unsaved && tmp.0.exists());

    // At most one save a minute while rows arrive.
    rows.write().record(live.clone(), true);
    saver.save_due(&tmp.file(), &rows, first_save);
    assert!(rows.read().unsaved, "saved less than a minute ago");
    saver.save_due(&tmp.file(), &rows, first_save + persist::SAVE_INTERVAL);
    assert!(!rows.read().unsaved);

    let chain = Chain::new(head);
    let persist::Loaded::Rows(loaded) = tmp.file().load(&chain) else { panic!("rows expected") };
    let held = rows.read();
    assert_eq!(loaded.iter().collect::<Vec<_>>(), held.final_rows().collect::<Vec<_>>());
    assert_eq!((loaded.len(), loaded.last()), (53 - 18 + 1, Some(&live)), "the census is kept");

    let restored = RwLock::new(Rows::default());
    persist::restore(&tmp.file(), &chain, &restored);
    assert_eq!(restored.read().final_rows().collect::<Vec<_>>(), held.final_rows().collect::<Vec<_>>());
    assert!(!restored.read().unsaved, "restored rows are not saved again");
}

#[test]
fn a_history_file_of_another_format_or_parameters_is_ignored() {
    let head = 1_200;
    let chain = Chain::new(head);
    let mut saved = row(head, 2, true, None);
    saved.timestamp_ms = Some(head as i64 * 15_500);
    let tmp = persist::TempPath::new("outdated");
    let write = |format: u32, params: persist::Params| {
        let body = serde_json::json!({ "format": format, "params": params, "rows": [&saved] });
        tmp.file().write(&serde_json::to_vec(&body).unwrap()).unwrap();
    };
    let current = persist::Params::current(0);
    write(persist::FORMAT, current);
    assert_eq!(tmp.file().load(&chain), persist::Loaded::Rows(vec![saved.clone()]));
    let other_network = persist::HistoryFile::new(tmp.0.clone(), 1).load(&chain);
    assert!(matches!(other_network, persist::Loaded::Outdated(_)), "{other_network:?}");
    for params in [persist::Params { row_frames: 120, ..current }, persist::Params { epoch_frames: 60, ..current }] {
        write(persist::FORMAT, params);
        assert!(matches!(tmp.file().load(&chain), persist::Loaded::Outdated(_)), "{params:?}");
    }
    write(persist::FORMAT + 1, current);
    assert!(matches!(tmp.file().load(&chain), persist::Loaded::Outdated(_)));
    let rows = RwLock::new(Rows::default());
    persist::restore(&tmp.file(), &chain, &rows);
    assert!(rows.read().is_empty(), "nothing restored: the backfill rebuilds every row");
}

#[test]
fn a_corrupt_history_file_is_ignored() {
    let head = 1_200;
    let chain = Chain::new(head);
    let tmp = persist::TempPath::new("corrupt");
    let current = persist::Params::current(0);
    let stored = |frame: u64| {
        let mut r = row(frame, 2, true, None);
        r.timestamp_ms = Some(frame as i64 * 15_500);
        r
    };
    let file_of = |rows: &[Row]| {
        serde_json::to_vec(&serde_json::json!({ "format": persist::FORMAT, "params": current, "rows": rows })).unwrap()
    };
    let bodies = [
        b"\x00\xffnot json".to_vec(),
        br#"{"format":1,"params":"#.to_vec(),
        serde_json::to_vec(&serde_json::json!({ "format": persist::FORMAT, "params": current, "rows": [{ "frame": 60 }] }))
            .unwrap(),
        file_of(&[row(head, 2, true, None)]),
        file_of(&[stored(head + 60)]),
        file_of(&[stored(head), stored(head - 60)]),
        file_of(&[stored(head - 1)]),
    ];
    for body in bodies {
        tmp.file().write(&body).unwrap();
        let loaded = tmp.file().load(&chain);
        assert!(matches!(loaded, persist::Loaded::Invalid(_)), "{loaded:?}: {}", String::from_utf8_lossy(&body));
        let rows = RwLock::new(Rows::default());
        persist::restore(&tmp.file(), &chain, &rows);
        assert!(rows.read().is_empty());
    }
    std::fs::remove_file(&tmp.0).unwrap();
    assert_eq!(tmp.file().load(&chain), persist::Loaded::Absent);
}

#[test]
fn a_restart_with_a_restored_file_backfills_only_the_rows_it_lacks() {
    let head = 10_980;
    let reference = continuous_rows(head);
    // Saved before the restart: the rows through 6_000 but the ones not
    // final.
    let before = RwLock::new(Rows::default());
    for (frame, row) in reference.range(..=6_000) {
        before.write().record(row.clone(), !NOT_FINAL.contains(frame));
    }
    let tmp = persist::TempPath::new("restart");
    persist::Saver::default().save_due(&tmp.file(), &before, Instant::now());

    let chain = Chain::new(head);
    let rows = RwLock::new(Rows::default());
    persist::restore(&tmp.file(), &chain, &rows);
    assert_eq!((rows.read().len(), chain.reads.get()), (84 - 18, 1), "one frame read checks the file's chain");
    let mut plan = Backfill::new(head, Some(1), None, DECODERS);
    let mut segments = Vec::new();
    while !plan.is_done() {
        let step = plan.step(&chain, MAX_FRAMES_PER_TICK, &mut past_grace, &rows);
        assert_eq!((step.error.as_deref(), step.waiting), (None, None));
        if let Some(s) = step.segment {
            segments.push((s.lo, s.hi, s.rows, s.frames));
        }
    }
    assert_eq!(
        segments,
        vec![(6_060, 10_920, 82, 5_821), (2_520, 3_540, 18, 1_981)],
        "the rows after the file's last and the ones not saved, each with its lead"
    );
    assert_eq!(chain.reads.get(), 1 + 5_821 + 1_981, "from scratch: 11_762");
    let held = rows.read();
    assert_eq!(held.len(), 166);
    for (frame, row) in &held.rows {
        assert_eq!(row, &reference[frame], "row {frame}");
    }
    assert!(plan.state().complete);
}

#[test]
fn a_row_keeps_its_shape() {
    let r = row(1_440, 51, true, Some((104, 51)));
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"frame":1440,"epoch":2,"timestamp_ms":14400000,"window_complete":true,"missing_frames_in_window":0,"outcome_less_frames_in_window":0,"median_frame_interval_ms":10000,"producing_shards":51,"shards_with_headers_in_window":52,"applied":102,"inclusions":103,"not_applied":0,"unknown_outcome":0,"drained":1,"missing_frames":0,"outcome_less_frames":0,"census":{"head_frame":1443,"live_shards":104,"classes":{"no_data":0,"producing":51,"below_quorum":1,"staffed_not_producing":52},"grid_shards":150}}"#
    );
    let stats = serde_json::to_string(&Rows::default().stats()).unwrap();
    assert_eq!(stats, r#"{"rows":0,"first_row_frame":null,"last_row_frame":null,"backfill_complete":false}"#);
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

fn peak_rss() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l[6..].trim().to_string()))
        .unwrap_or_else(|| "n/a".into())
}

/// Cost of the history backfill over a node store, opened read-only beside
/// its running node (`open_for_read_only_live`: no lock, no writes; mount it
/// read-only): `QUIL_KPI_STORE=<store dir>`, `QUIL_KPI_HISTORY_DAYS`
/// (segments, default 1). Steps with the live index's per-tick budget, as
/// the task does once the live index has caught up. A store without
/// outcomes (a regular node's) is read as an archive whose outcomes were
/// lost. Debug builds overstate the costs.
#[test]
#[ignore = "measurement over a node store"]
fn measure_history_backfill_over_store() {
    use quil_types::store::ClockStore as _;
    let Ok(path) = std::env::var("QUIL_KPI_STORE") else {
        eprintln!("QUIL_KPI_STORE is unset: nothing measured");
        return;
    };
    let days: u64 = std::env::var("QUIL_KPI_HISTORY_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let db = quil_store::RocksDb::open_for_read_only_live(std::path::Path::new(&path)).expect("open the store read-only");
    let store = quil_store::RocksClockStore::new(db.inner());
    let Some(head) = store.get_latest_frame_number() else {
        eprintln!("the store holds no GLOBAL frame");
        return;
    };
    let earliest = store.get_earliest_global_clock_frame().ok().and_then(|f| f.header).map(|h| h.frame_number);
    let retained = store.global_requests_retained_from();
    let first_live = head / ROW_FRAMES * ROW_FRAMES;
    let mut plan = Backfill::new(first_live, earliest, retained, Decoders::default());
    eprintln!(
        "[plan] head {head}, earliest {earliest:?}, requests retained from {retained:?}: floor {:?}, top {:?}",
        plan.floor(),
        plan.top()
    );
    let rows = RwLock::new(Rows::default());
    let source = crate::production::StoreSource(&store);
    let (mut step_us, mut per_frame_us) = (Vec::new(), Vec::new());
    let mut segments = 0;
    let started = Instant::now();
    while !plan.is_done() && segments < days {
        let t = Instant::now();
        let step = plan.step(&source, MAX_FRAMES_PER_TICK, &mut past_grace, &rows);
        let us = t.elapsed().as_micros() as u64;
        if let Some(e) = step.error.or(step.waiting.map(|w| format!("waits at {w}"))) {
            eprintln!("[step] stopped at {:?}: {e}", step.frame);
            break;
        }
        step_us.push(us);
        if step.indexed > 0 {
            per_frame_us.push(us / step.indexed);
        }
        if let Some(s) = step.segment {
            segments += 1;
            eprintln!(
                "[segment] rows {}..={}: {} rows, {} frames ({} missing, {} outcome-less), busy {:?}",
                s.lo, s.hi, s.rows, s.frames, s.missing, s.outcome_less, s.busy
            );
        }
    }
    let held = rows.read();
    let json: usize = held.rows.values().map(|r| serde_json::to_vec(r).map_or(0, |b| b.len())).sum();
    eprintln!(
        "[backfill] {} rows, {} frames in {:?} ({} steps); step us p50/p95/max {}; us/frame p50/p95/max {}",
        held.len(),
        plan.frames,
        started.elapsed(),
        step_us.len(),
        percentiles(&step_us),
        percentiles(&per_frame_us)
    );
    eprintln!(
        "[rows] size_of::<Row>() {} bytes; JSON {} bytes/row; complete windows {}, producing p50/p95/max {}; peak RSS {}",
        std::mem::size_of::<Row>(),
        json / held.rows.len().max(1),
        held.rows.values().filter(|r| r.window_complete).count(),
        percentiles(&held.rows.values().map(|r| r.producing_shards).collect::<Vec<_>>()),
        peak_rss()
    );
}
