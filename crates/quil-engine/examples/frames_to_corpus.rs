//! Convert explorer protojson frames into canonical wire bytes for the
//! `decode_global_frame` fuzz corpus.
//!
//! Each input is a protojson `GlobalFrame` (e.g. the body of
//! `GET https://explorer-api.quilibrium.com/frames/<n>`). We reconstruct the
//! prost `GlobalFrame` via `protojson::from_protojson` (explorer-only extras
//! like `requestOutcomes` are ignored), re-encode to the CANONICAL wire format
//! the fuzz target parses, and — as a self-check — require `decode_global_frame`
//! to accept our own encoding before writing the seed.
//!
//! Usage:
//!   cargo run -p quil-engine --example frames_to_corpus -- <out_dir> <frame.json>...
use std::io::Write as _;

fn main() {
    let mut args = std::env::args().skip(1);
    let out_dir = args
        .next()
        .expect("usage: frames_to_corpus <out_dir> <frame.json>...");
    std::fs::create_dir_all(&out_dir).expect("create out_dir");

    let (mut ok, mut fail) = (0usize, 0usize);
    for path in args {
        let json = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip {path}: read: {e}");
                fail += 1;
                continue;
            }
        };
        let frame: quil_types::proto::global::GlobalFrame =
            match quil_types::protojson::from_protojson(quil_types::protojson::GLOBAL_FRAME, &json)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("skip {path}: from_protojson: {e}");
                    fail += 1;
                    continue;
                }
            };
        let canonical = match quil_engine::consensus_wire::encode_global_frame(&frame) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip {path}: encode_global_frame: {e}");
                fail += 1;
                continue;
            }
        };
        // Self-check: the fuzz target's decoder must accept our seed.
        if let Err(e) = quil_engine::consensus_wire::decode_global_frame(&canonical) {
            eprintln!("skip {path}: decode round-trip failed: {e}");
            fail += 1;
            continue;
        }
        let n = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
        let out = format!("{out_dir}/frame_{n}.bin");
        match std::fs::File::create(&out).and_then(|mut f| f.write_all(&canonical)) {
            Ok(()) => {
                eprintln!("wrote {out} ({} bytes, {} bundles)", canonical.len(), frame.requests.len());
                ok += 1;
            }
            Err(e) => {
                eprintln!("skip {path}: write {out}: {e}");
                fail += 1;
            }
        }

        // Optionally also emit each request bundle's canonical bytes — real
        // seeds for the `decode_message_bundle` / `canonical_message_bundle`
        // fuzz targets. Set BUNDLE_CORPUS to a directory to enable.
        if let Ok(bdir) = std::env::var("BUNDLE_CORPUS") {
            let _ = std::fs::create_dir_all(&bdir);
            for (bi, bundle) in frame.requests.iter().enumerate() {
                if let Ok(bb) =
                    quil_engine::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle)
                {
                    let bout = format!("{bdir}/bundle_{n}_{bi}.bin");
                    let _ = std::fs::File::create(&bout).and_then(|mut f| f.write_all(&bb));
                }
            }
        }
    }
    eprintln!("done: {ok} seeds written, {fail} failed");
}
