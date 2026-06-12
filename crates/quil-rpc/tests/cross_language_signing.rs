//! Cross-language signing parity. Builds each of the prover-management
//! messages (Join, Leave, Confirm, Reject, Pause, Resume) using
//! deterministic seeds, then dumps the canonical bytes and Ed448
//! outer-auth signature as JSON. A parallel Go fixture generator
//! (see `client/cmd/node/prover/gen_fixtures/main.go`) does the same
//! against Go's TUI builders. The two outputs must diff to zero.
//!
//! Run with `cargo test -p quil-rpc --test cross_language_signing -- --nocapture`
//! to see the dumped JSON path. Pass `RUST_FIXTURE_OUT=/tmp/rust.json`
//! to override the default location.
//!
//! When the matching Go fixture file is present at the path in
//! `GO_FIXTURE_IN`, the test additionally asserts byte-for-byte
//! equality on every field. Otherwise it just emits the Rust output
//! and skips the cross-check.

use quil_types::crypto::Signer;
use quil_types::proto::global as pb;
use quil_types::proto::keys as keys_pb;

use std::fs;
use std::path::PathBuf;

/// Deterministic Ed448 peer-key seed (57 bytes). Used for the outer
/// Send authentication signature.
const PEER_SEED: [u8; 57] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
];

/// Fake 74-byte BLS sig + 32-byte address embedded in each prover
/// message. Real BLS sign/verify is expensive and not the focus of
/// this test — the fixture only checks that Go and Rust agree on the
/// canonical-bytes layout once the BLS sig field is populated.
const FAKE_BLS_SIG: [u8; 74] = [0xBB; 74];
const FAKE_PROVER_ADDR: [u8; 32] = [0xCC; 32];

const FRAME_NUMBER: u64 = 123_456;
const TIMESTAMP_MS: i64 = 1_700_000_000_000;

fn fixture_filter_a() -> Vec<u8> {
    vec![0xA1; 8]
}
fn fixture_filter_b() -> Vec<u8> {
    vec![0xB2; 8]
}

fn addr_sig() -> keys_pb::Bls48581AddressedSignature {
    keys_pb::Bls48581AddressedSignature {
        signature: FAKE_BLS_SIG.to_vec(),
        address: FAKE_PROVER_ADDR.to_vec(),
    }
}

fn build_leave() -> pb::MessageBundle {
    let leave = pb::ProverLeave {
        filters: vec![fixture_filter_a(), fixture_filter_b()],
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(addr_sig()),
    };
    bundle_with(pb::message_request::Request::Leave(leave))
}

fn build_confirm() -> pb::MessageBundle {
    let confirm = pb::ProverConfirm {
        filter: vec![],
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(addr_sig()),
        filters: vec![fixture_filter_a()],
    };
    bundle_with(pb::message_request::Request::Confirm(confirm))
}

fn build_reject() -> pb::MessageBundle {
    let reject = pb::ProverReject {
        filter: vec![],
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(addr_sig()),
        filters: vec![fixture_filter_a()],
    };
    bundle_with(pb::message_request::Request::Reject(reject))
}

fn build_pause() -> pb::MessageBundle {
    let pause = pb::ProverPause {
        filter: fixture_filter_a(),
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(addr_sig()),
    };
    bundle_with(pb::message_request::Request::Pause(pause))
}

fn build_resume() -> pb::MessageBundle {
    let resume = pb::ProverResume {
        filter: fixture_filter_a(),
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(addr_sig()),
    };
    bundle_with(pb::message_request::Request::Resume(resume))
}

fn build_join() -> pb::MessageBundle {
    // ProverJoin embeds a SignatureWithProofOfPossession (sig + pop +
    // pubkey). Use deterministic dummy values so canonical bytes are
    // reproducible.
    let join = pb::ProverJoin {
        filters: vec![fixture_filter_a()],
        frame_number: FRAME_NUMBER,
        public_key_signature_bls48581: Some(keys_pb::Bls48581SignatureWithProofOfPossession {
            signature: vec![0xAA; 74],
            public_key: Some(keys_pb::Bls48581g2PublicKey {
                key_value: vec![0xDD; 585],
            }),
            pop_signature: vec![0xEE; 74],
        }),
        delegate_address: vec![0x11; 32],
        merge_targets: vec![],
        proof: vec![0xFF; 64],
    };
    bundle_with(pb::message_request::Request::Join(join))
}

fn bundle_with(req: pb::message_request::Request) -> pb::MessageBundle {
    pb::MessageBundle {
        requests: vec![pb::MessageRequest {
            request: Some(req),
            timestamp: 0,
        }],
        timestamp: TIMESTAMP_MS,
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
struct OperationFixture {
    operation: String,
    domain_hex: String,
    peer_pubkey_hex: String,
    canonical_bytes_hex: String,
    outer_sig_hex: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FixtureFile {
    /// Hex of the 57-byte Ed448 seed used to sign every entry.
    peer_seed_hex: String,
    /// Hex of the corresponding 57-byte Ed448 public key.
    peer_pubkey_hex: String,
    /// Bundle-level Unix-millis timestamp included in every entry.
    timestamp_ms: i64,
    /// Frame number written into every prover op.
    frame_number: u64,
    operations: Vec<OperationFixture>,
}

fn build_fixtures() -> FixtureFile {
    let peer_pubkey =
        quil_crypto::Ed448Signer::derive_public(&PEER_SEED).expect("derive peer pubkey");
    let signer = quil_crypto::Ed448Signer::from_bytes(&PEER_SEED, &peer_pubkey)
        .expect("build Ed448 signer");

    let global_domain: Vec<u8> = vec![0xFF; 32];
    // Auth prefix that Go's `SignWithDomain` prepends to the body
    // before signing (`crypto.Hash(0)` opts → pure Ed448, ctx="").
    let mut auth_prefix = Vec::with_capacity(19 + 32);
    auth_prefix.extend_from_slice(b"NODE_AUTHENTICATION");
    auth_prefix.extend_from_slice(&global_domain);

    let entries: Vec<(&str, pb::MessageBundle)> = vec![
        ("Join", build_join()),
        ("Leave", build_leave()),
        ("Confirm", build_confirm()),
        ("Reject", build_reject()),
        ("Pause", build_pause()),
        ("Resume", build_resume()),
    ];

    let mut operations = Vec::new();
    for (name, bundle) in entries {
        let canonical = quil_execution::message_envelope::proto_message_bundle_to_canonical_bytes(
            &bundle,
        )
        .expect("canonicalize");
        let outer_sig = signer
            .sign_with_domain(&canonical, &auth_prefix)
            .expect("Ed448 sign");

        // Self-verify using the Go-compatible scheme: pure Ed448
        // over `prefix || body` with empty ctx.
        let mut digest = Vec::with_capacity(auth_prefix.len() + canonical.len());
        digest.extend_from_slice(&auth_prefix);
        digest.extend_from_slice(&canonical);
        let pk = ed448_rust::PublicKey::try_from(peer_pubkey.as_slice()).unwrap();
        pk.verify(&digest, &outer_sig, None)
            .expect("Rust must verify its own outer sig");

        operations.push(OperationFixture {
            operation: name.into(),
            domain_hex: hex::encode(&global_domain),
            peer_pubkey_hex: hex::encode(&peer_pubkey),
            canonical_bytes_hex: hex::encode(&canonical),
            outer_sig_hex: hex::encode(&outer_sig),
        });
    }

    FixtureFile {
        peer_seed_hex: hex::encode(PEER_SEED),
        peer_pubkey_hex: hex::encode(&peer_pubkey),
        timestamp_ms: TIMESTAMP_MS,
        frame_number: FRAME_NUMBER,
        operations,
    }
}

#[test]
fn dump_rust_fixtures() {
    let out = build_fixtures();
    let json = serde_json::to_string_pretty(&out).expect("serialize");
    let path = std::env::var("RUST_FIXTURE_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join("quil_cross_language_fixtures_rust.json")
        });
    fs::write(&path, &json).expect("write fixture file");
    eprintln!("wrote Rust fixtures to {}", path.display());
}

/// Cross-check: when `GO_FIXTURE_IN` points at a Go-produced fixture
/// file, every entry must match Rust's byte-for-byte. If the env var
/// isn't set, the test is a no-op (so CI without Go installed still
/// passes).
#[test]
fn rust_matches_go_fixtures_when_present() {
    let path = match std::env::var("GO_FIXTURE_IN") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!(
                "GO_FIXTURE_IN not set — skipping cross-check. Run \
                 `go run client/cmd/node/prover/gen_fixtures/main.go > /tmp/go.json` \
                 then re-run with GO_FIXTURE_IN=/tmp/go.json"
            );
            return;
        }
    };
    let go_raw = fs::read_to_string(&path).expect("read Go fixture file");
    let go: FixtureFile = serde_json::from_str(&go_raw).expect("parse Go fixture");

    let rust = build_fixtures();

    assert_eq!(
        rust.peer_seed_hex, go.peer_seed_hex,
        "test seeds must match between Go and Rust generators"
    );
    assert_eq!(
        rust.peer_pubkey_hex, go.peer_pubkey_hex,
        "Ed448 derive_public must produce the same pubkey for the same seed"
    );
    assert_eq!(rust.timestamp_ms, go.timestamp_ms);
    assert_eq!(rust.frame_number, go.frame_number);
    assert_eq!(
        rust.operations.len(),
        go.operations.len(),
        "operation count differs"
    );

    let mut diffs: Vec<String> = Vec::new();
    for (r, g) in rust.operations.iter().zip(go.operations.iter()) {
        if r.operation != g.operation {
            diffs.push(format!(
                "operation order: rust={}, go={}",
                r.operation, g.operation
            ));
            continue;
        }
        if r.canonical_bytes_hex != g.canonical_bytes_hex {
            diffs.push(format!(
                "{}: canonical bytes diverge\n  rust: {}\n  go:   {}",
                r.operation, r.canonical_bytes_hex, g.canonical_bytes_hex
            ));
        }
        if r.outer_sig_hex != g.outer_sig_hex {
            diffs.push(format!(
                "{}: outer Ed448 sig diverges\n  rust: {}\n  go:   {}",
                r.operation, r.outer_sig_hex, g.outer_sig_hex
            ));
        }
    }
    assert!(diffs.is_empty(), "{} divergence(s):\n{}", diffs.len(), diffs.join("\n\n"));
}
