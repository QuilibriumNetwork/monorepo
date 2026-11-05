//! Base reproducers at the GLOBAL materializer and its voters: a GLOBAL frame
//! carrying a shard frame header whose GLOBAL anchor no store holds is voted
//! for (voters execute only the parent, `cw_global_seams.rs`), and then fails
//! as a whole wherever it executes: the header's validation reads the anchor
//! before any window check and returns `ExecutionUnavailable`, which the
//! materializer returns for the frame (`frame_materializer.rs`, the
//! sequential validate step and the parallel header pre-pass), so the cursor
//! never passes it. The header needs no key. The control shows a header
//! refused deterministically is skipped instead.
use super::*;

/// An anchor no GLOBAL frame in these rigs reaches.
const UNHELD_ANCHOR: u64 = 1_000_000;

/// The frame-header dependencies an archive installs on its GLOBAL engine
/// (`install_global_frame_header_deps`); without them validation refuses
/// every header before reading its anchor.
fn install_header_deps(source: &FrameMaterializer) {
    source
        .execution_manager
        .install_global_frame_header_deps(
            source.prover_registry.clone(),
            Arc::new(crate::rewards::OptRewardIssuance),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_tries::ShaInclusionProver),
            Arc::new(TestFrameProver),
        )
        .unwrap();
}

/// A shard frame header anyone can write, anchored to GLOBAL frame `anchor`:
/// no certificate or signature, an output that matches nothing.
fn junk_header_bundle(anchor: u64) -> quil_types::proto::global::MessageBundle {
    let header = quil_execution::global_intrinsic::frame_header::FrameHeader {
        address: vec![0x77; 32],
        frame_number: 9,
        rank: 9,
        global_frame_number: anchor,
        output: vec![0x5a; 32],
        parent_selector: vec![0x11; 32],
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    };
    quil_types::proto::global::MessageBundle {
        requests: vec![quil_types::proto::global::MessageRequest {
            request: Some(quil_types::proto::global::message_request::Request::Shard(
                quil_execution::global_intrinsic::conversions::frame_header_to_proto(&header),
            )),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The steps before validation must let the header through, and validation
/// must run with an archive's dependencies (a header anchored to 0 reaches
/// its output check), or a reproducer would pass for another reason.
fn check_setup(source: &FrameMaterializer, frame_number: u64) {
    let manager = &source.execution_manager;
    let global = quil_execution::domains::GLOBAL;
    for anchor in [UNHELD_ANCHOR, 0] {
        let bundle = junk_header_bundle(anchor);
        let bytes = crate::consensus_wire::proto_message_bundle_to_canonical_bytes(&bundle)
            .unwrap_or_else(|error| panic!("FH SETUP: the header does not encode: {error}"));
        assert_eq!(
            bundle_global_route(&bundle, false, |_| false),
            global.to_vec(),
            "FH SETUP: the header must take the GLOBAL route"
        );
        if let Err(error) = manager.get_cost(&bytes) {
            panic!("FH SETUP: pricing refused the header before validation: {error}");
        }
        if anchor == 0 {
            match manager.validate_message(frame_number, &global, &bytes) {
                Err(error) if error.to_string().contains("does not match") => {}
                other => panic!(
                    "FH SETUP: an unanchored junk header must reach its output check: {other:?}"
                ),
            }
        }
    }
}

fn materializer_with_header_deps() -> (Fixture, [u8; 32]) {
    let signer = quil_crypto::FalconSigner::generate();
    let fixture = Fixture::new(Some(signer.public_key()));
    install_header_deps(&fixture.source);
    let root = fixture
        .source
        .hypergraph
        .current_forest_phase_root(&[0xff; 32], 0)
        .unwrap();
    (fixture, root)
}

fn halt_or_finish(
    source: &FrameMaterializer,
    input: &quil_types::proto::global::GlobalFrame,
    what: &str,
) {
    let number = input.header.as_ref().unwrap().frame_number;
    let first = source.materialize(input);
    let retry = source.materialize(input);
    match first {
        Ok(result) => assert_eq!(
            (result.processed, source.last_materialized_frame()),
            (0, number),
            "the refused header is skipped and the frame completes"
        ),
        Err(error) => panic!(
            "FH HALT: the GLOBAL materializer failed frame {number} as a whole on {what} \
             (unavailable class: {}); cursor stays at {}, retry: {:?}; error: {error}",
            error.is_execution_unavailable(),
            source.last_materialized_frame(),
            retry.err().map(|e| e.to_string()),
        ),
    }
}

#[test]
fn fh_halt_global_materializer_must_finish_a_frame_whose_header_anchor_no_store_holds() {
    let (fixture, root) = materializer_with_header_deps();
    check_setup(&fixture.source, 1);
    let mut input = frame(1, root);
    input.requests = vec![junk_header_bundle(UNHELD_ANCHOR)];
    halt_or_finish(
        &fixture.source,
        &input,
        "a shard header no key signed, anchored to a frame no store holds",
    );
}

#[test]
fn fh_halt_global_header_pre_pass_must_finish_a_frame_whose_header_anchor_no_store_holds() {
    // Two headers take the parallel pre-pass instead of the sequential step.
    let (fixture, root) = materializer_with_header_deps();
    check_setup(&fixture.source, 1);
    let mut input = frame(1, root);
    input.requests = vec![junk_header_bundle(UNHELD_ANCHOR), junk_header_bundle(0)];
    halt_or_finish(
        &fixture.source,
        &input,
        "two shard headers no key signed, one anchored to a frame no store holds (pre-pass)",
    );
}

#[test]
fn fh_control_global_materializer_skips_a_refused_header_and_finishes_the_frame() {
    let (fixture, root) = materializer_with_header_deps();
    check_setup(&fixture.source, 1);
    let mut input = frame(1, root);
    // Without an anchor the junk header fails its output check: InvalidArgument-class.
    input.requests = vec![junk_header_bundle(0)];
    let result = fixture.source.materialize(&input).unwrap_or_else(|error| {
        panic!("control: a deterministically refused header must not fail the frame: {error}")
    });
    assert_eq!(
        (
            result.processed,
            result.skipped,
            fixture.source.last_materialized_frame()
        ),
        (0, 1, 1),
        "control: the refused header is skipped and the cursor passes frame 1"
    );
    eprintln!("FH CONTROL: a refused header is skipped and the GLOBAL frame completes");
}

#[test]
fn fh_halt_voters_certify_a_frame_carrying_the_header_and_it_never_executes() {
    // A leader proposes GLOBAL frame 2 carrying the header. Voters check the
    // header, VDF, requests root and parent state, executing only the parent:
    // they vote for it. Every node executing it then fails the frame.
    let rig = Rig::new();
    let parent = rig.deploy();
    rig.put(&parent);
    let expected = Fixture::new(Some(rig.signer.public_key()));
    expected.source.materialize(&parent).unwrap();
    let context = rig.context(&parent);
    let mut child = state_frame(&expected.source, 2, context.view, context.parent);
    child.requests.push(junk_header_bundle(UNHELD_ANCHOR));
    body_root(&mut child);
    let seam = rig.seam(&parent);
    let encoded = crate::consensus_wire::encode_global_frame(&child).unwrap();
    assert!(
        seam.verify_with_context(context, id(&child), Some(encoded)),
        "FH SETUP: GLOBAL voters refused the proposal carrying the header (they would not \
         certify it)"
    );
    install_header_deps(&expected.source);
    check_setup(&expected.source, 2);
    halt_or_finish(
        &expected.source,
        &child,
        "a voted GLOBAL frame carrying a shard header no key signed, anchored to a frame no \
         store holds",
    );
}

/// The warning of a header anchored outside its window is due once per
/// interval and counts the refusals it quieted meanwhile.
#[test]
fn fh_fix_anchor_refusal_warning_is_bounded_and_counts_the_quieted() {
    use crate::frame_materializer::{anchor_refusal_warning_due, ANCHOR_REFUSAL_WARN_INTERVAL};
    let start = std::time::Instant::now();
    let mut last = None;
    assert_eq!(anchor_refusal_warning_due(&mut last, start), Some(0));
    for _ in 0..3 {
        assert_eq!(anchor_refusal_warning_due(&mut last, start), None);
    }
    assert_eq!(
        anchor_refusal_warning_due(&mut last, start + ANCHOR_REFUSAL_WARN_INTERVAL),
        Some(3),
        "FH FIX: the next warning counts the three quieted refusals"
    );
}
