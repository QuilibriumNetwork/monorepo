//! The node's yamux configuration against frames that open a stream with more
//! data than its initial credit. They must be refused with a GoAway, never panic
//! the connection task.

use std::future::poll_fn;
use std::task::Poll;
use std::time::Duration;

use futures::AsyncReadExt;
use libp2p::core::muxing::StreamMuxerExt;
use libp2p::core::upgrade::InboundConnectionUpgrade;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt;

const DEFAULT_CREDIT: u32 = 256 * 1024;
const SYN: u16 = 1;
const FIN: u16 = 4;
const RST: u16 = 8;

/// The same calls as the TCP transport's yamux upgrade in `quil-p2p/src/node.rs`.
fn node_yamux_config() -> libp2p::yamux::Config {
    let mut cfg = libp2p::yamux::Config::default();
    cfg.set_max_num_streams(65536);
    cfg
}

fn data_frame(flags: u16, stream: u32, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8, 0u8];
    f.extend_from_slice(&flags.to_be_bytes());
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    f
}

/// GoAway, code 1: what yamux sends to refuse a frame. It leaves the session
/// for the peer to close, so a refused frame does not end the local session.
const GOAWAY_PROTOCOL_ERROR: [u8; 12] = [0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

struct Outcome {
    accepted: usize,
    session_error: bool,
    replies: Vec<u8>,
}

impl Outcome {
    fn refused(&self) -> bool {
        self.replies
            .windows(GOAWAY_PROTOCOL_ERROR.len())
            .any(|w| w == GOAWAY_PROTOCOL_ERROR)
    }
}

/// Feeds `input` to a server-side session built from the node's configuration,
/// optionally dropping each stream it accepts at once, and returns what the
/// session did and answered. A panic in the session surfaces here as a failed
/// join.
async fn feed_session(input: Vec<u8>, drop_streams: bool) -> Outcome {
    let (ours, theirs) = tokio::io::duplex(4 << 20);
    let (theirs_read, mut theirs_write) = tokio::io::split(theirs);
    let session = tokio::spawn(async move {
        let mut muxer = node_yamux_config()
            .upgrade_inbound(ours.compat(), "/yamux/1.0.0")
            .await
            .unwrap();
        let mut accepted = 0usize;
        let mut kept = Vec::new();
        let session_error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let got = poll_fn(|cx| {
                    if let Poll::Ready(Err(e)) = muxer.poll_unpin(cx) {
                        return Poll::Ready(Err(e));
                    }
                    muxer.poll_inbound_unpin(cx)
                })
                .await;
                match got {
                    Ok(stream) => {
                        accepted += 1;
                        if !drop_streams {
                            kept.push(stream);
                        }
                    }
                    Err(_) => return true,
                }
            }
        })
        .await
        .unwrap_or(false);
        // One more turn so a dropped stream's cleanup runs on the connection.
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            poll_fn(|cx| muxer.poll_unpin(cx)),
        )
        .await;
        (accepted, session_error)
    });
    let drain = tokio::spawn(async move {
        let mut r = theirs_read.compat();
        let mut replies = Vec::new();
        let _ = r.read_to_end(&mut replies).await;
        replies
    });
    let _ = theirs_write.write_all(&input).await;
    let (accepted, session_error) = session.await.expect("the session task must not panic");
    drop(theirs_write);
    Outcome {
        accepted,
        session_error,
        replies: drain.await.unwrap(),
    }
}

/// The published frame: SYN on a new stream, one byte over the initial credit.
#[tokio::test]
async fn syn_data_frame_over_the_initial_credit_ends_the_session_without_panic() {
    let body = vec![0u8; DEFAULT_CREDIT as usize + 1];
    let outcome = feed_session(data_frame(SYN, 1, &body), true).await;
    assert_eq!(outcome.accepted, 0, "the oversized stream must not surface");
    assert!(
        outcome.refused(),
        "the oversized frame was not refused with a GoAway: {:?}",
        outcome.replies
    );
}

#[tokio::test]
async fn variants_of_the_frame_do_not_panic_the_session() {
    let credit = DEFAULT_CREDIT as usize;
    let over = vec![0u8; credit + 1];
    let exact = vec![0u8; credit];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("SYN|FIN over credit", data_frame(SYN | FIN, 1, &over)),
        ("SYN|RST over credit", data_frame(SYN | RST, 1, &over)),
        ("SYN over credit, even id", data_frame(SYN, 2, &over)),
        ("SYN at exact credit", data_frame(SYN, 1, &exact)),
        ("SYN at exact credit, FIN", data_frame(SYN | FIN, 1, &exact)),
        (
            "SYN at exact credit, then one byte more",
            [data_frame(SYN, 1, &exact), data_frame(0, 1, &[0])].concat(),
        ),
        (
            "SYN at exact credit, then SYN over credit",
            [data_frame(SYN, 1, &exact), data_frame(SYN, 3, &over)].concat(),
        ),
        (
            "SYN repeated on one id",
            [data_frame(SYN, 1, &[1]), data_frame(SYN, 1, &[2])].concat(),
        ),
        (
            "small SYN, then SYN over credit",
            [data_frame(SYN, 1, &[1]), data_frame(SYN, 3, &over)].concat(),
        ),
        (
            "SYN, RST, then data",
            [
                data_frame(SYN, 1, &[1]),
                data_frame(RST, 1, &[]),
                data_frame(0, 1, &over),
            ]
            .concat(),
        ),
    ];
    for drop_streams in [true, false] {
        for (name, input) in &cases {
            let o = feed_session(input.clone(), drop_streams).await;
            println!(
                "{name}, drop_streams={drop_streams}: {} accepted, refused {}, session error {}",
                o.accepted,
                o.refused(),
                o.session_error
            );
        }
    }
}

/// Without this the frames above reach no yamux code: an honest stream carries data.
#[tokio::test]
async fn an_honest_stream_opens_under_the_same_configuration() {
    let outcome = feed_session(data_frame(SYN, 1, b"hello"), false).await;
    assert_eq!(outcome.accepted, 1);
    assert!(!outcome.refused());
    assert!(!outcome.session_error);
}
