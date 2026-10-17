use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn frame() -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: 1,
            rank: 4,
            output: vec![7; 516],
            prover: vec![8; 32],
            requests_root: crate::leader_provider::compute_global_requests_root(
                &[],
                &quil_tries::ShaInclusionProver,
            ),
            ..Default::default()
        }),
        requests: vec![],
    }
}

fn finalizer(
    clock: Arc<dyn ClockStore>,
) -> (
    GlobalSeamFinalizer,
    tokio::sync::mpsc::UnboundedReceiver<(GlobalFrame, u64)>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let heads = Arc::new(AtomicUsize::new(0));
    let gossip = Arc::new(AtomicUsize::new(0));
    let sink = GlobalSeamFinalizer::new(
        clock,
        tx,
        {
            let heads = heads.clone();
            Arc::new(move |_, _| {
                heads.fetch_add(1, Ordering::SeqCst);
            })
        },
        Some({
            let gossip = gossip.clone();
            Arc::new(move |_| {
                gossip.fetch_add(1, Ordering::SeqCst);
            })
        }),
        vec![8; 32],
    );
    (sink, rx, heads, gossip)
}

#[test]
fn failed_clock_write_publishes_no_head_gossip_or_materialization_job() {
    let writable = quil_store::RocksDb::open_in_memory().unwrap();
    let path = writable.inner().path().to_path_buf();
    drop(writable);
    let db = quil_store::RocksDb::open_for_read_only(&path).unwrap();
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let (sink, mut jobs, heads, gossip) = finalizer(clock.clone());
    let frame = frame();
    let digest = frame_digest(frame.header.as_ref().unwrap()).unwrap();
    sink.on_finalized(
        4,
        digest,
        Some(encode_global_frame(&frame).unwrap()),
        None,
        true,
    );
    assert!(clock.get_global_clock_frame(1).is_err());
    assert!(jobs.try_recv().is_err());
    assert_eq!(heads.load(Ordering::SeqCst), 0);
    assert_eq!(gossip.load(Ordering::SeqCst), 0);
}

#[test]
fn finalizer_rebinds_reported_view_digest_and_body_before_persistence() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let (sink, mut jobs, heads, gossip) = finalizer(clock.clone());
    let frame = frame();
    let digest = frame_digest(frame.header.as_ref().unwrap()).unwrap();
    let bytes = encode_global_frame(&frame).unwrap();
    let wrong_digest = digest_from_identity([99; 32]);
    let mut wrong_body = frame.clone();
    wrong_body
        .requests
        .push(quil_types::proto::global::MessageBundle::default());
    let sequence = db.inner().latest_sequence_number();
    for (view, hash, body) in [
        (5, digest, bytes.clone()),
        (4, wrong_digest, bytes.clone()),
        (4, digest, encode_global_frame(&wrong_body).unwrap()),
    ] {
        sink.on_notarized(view, hash, Some(body.clone()));
        for locally_verified in [false, true] {
            sink.on_finalized(view, hash, Some(body.clone()), None, locally_verified);
        }
        assert_eq!(db.inner().latest_sequence_number(), sequence);
        assert!(jobs.try_recv().is_err());
        assert_eq!(heads.load(Ordering::SeqCst), 0);
        assert_eq!(gossip.load(Ordering::SeqCst), 0);
    }
    // These are callback-context/storage tests, not certificate authentication.
    sink.on_notarized(4, digest, Some(bytes.clone()));
    assert!(clock.get_global_clock_frame(1).is_err());
    sink.on_finalized(4, digest, Some(bytes), None, true);
    assert_eq!(clock.get_global_clock_frame(1).unwrap(), frame);
    assert_eq!(jobs.try_recv().unwrap(), (frame, 1));
    assert_eq!(heads.load(Ordering::SeqCst), 1);
    assert_eq!(gossip.load(Ordering::SeqCst), 1);
}

/// A journal replay after a restart finalizes the canonical head again. It is
/// neither rewritten nor announced again (every restart re-gossiped its head);
/// the worker still gets its job, which is idempotent.
#[test]
fn a_replayed_finalization_of_a_canonical_frame_is_not_rewritten_or_reannounced() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let (sink, mut jobs, heads, gossip) = finalizer(clock.clone());
    let frame = frame();
    let digest = frame_digest(frame.header.as_ref().unwrap()).unwrap();
    let bytes = encode_global_frame(&frame).unwrap();
    sink.on_finalized(4, digest, Some(bytes.clone()), None, true);
    assert_eq!(jobs.try_recv().unwrap(), (frame.clone(), 1));
    assert_eq!((heads.load(Ordering::SeqCst), gossip.load(Ordering::SeqCst)), (1, 1));

    let sequence = db.inner().latest_sequence_number();
    sink.on_finalized(4, digest, Some(bytes), None, true);
    assert_eq!(db.inner().latest_sequence_number(), sequence, "not rewritten");
    assert_eq!((heads.load(Ordering::SeqCst), gossip.load(Ordering::SeqCst)), (1, 1), "not announced again");
    assert_eq!(jobs.try_recv().unwrap(), (frame, 1));
}
