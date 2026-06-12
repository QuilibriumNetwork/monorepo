//! End-to-end Send authentication: build a proto MessageBundle the
//! way qclient does, canonicalize it, sign with Ed448 under the
//! `NODE_AUTHENTICATION || domain` context, and verify with the
//! matching public key. Mirrors the production Send handler's verify
//! step exactly.

use quil_types::proto::global as pb;
use quil_types::proto::keys as keys_pb;

#[test]
fn ed448_sign_verify_over_canonical_bundle_matches_send_handler() {
    let leave_pb = pb::ProverLeave {
        filters: vec![vec![0xFFu8; 32]],
        frame_number: 12345,
        public_key_signature_bls48581: Some(keys_pb::Bls48581AddressedSignature {
            signature: vec![0xBBu8; 74],
            address: vec![0xCCu8; 32],
        }),
    };
    let bundle_pb = pb::MessageBundle {
        requests: vec![pb::MessageRequest {
            request: Some(pb::message_request::Request::Leave(leave_pb)),
            timestamp: 0,
        }],
        timestamp: 1_700_000_000_000,
    };

    let payload = quil_execution::message_envelope::proto_message_bundle_to_canonical_bytes(
        &bundle_pb,
    )
    .expect("canonicalize");

    // Reproducible seed — we don't care about secrecy, just that
    // sign and verify use the same key.
    let mut seed = [0u8; 57];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let pk_bytes =
        quil_crypto::Ed448Signer::derive_public(&seed).expect("derive pubkey");
    let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &pk_bytes)
        .expect("Ed448 signer");

    let domain = vec![0xFFu8; 32];
    let mut context = Vec::with_capacity(19 + 32);
    context.extend_from_slice(b"NODE_AUTHENTICATION");
    context.extend_from_slice(&domain);

    let signature = {
        use quil_types::crypto::Signer;
        signer
            .sign_with_domain(&payload, &context)
            .expect("Ed448 sign")
    };

    let pk = ed448_rust::PublicKey::try_from(pk_bytes.as_slice())
        .expect("decode pubkey");
    // Go's Ed448Key.SignWithDomain signs `concat(domain, message)` with
    // empty context (pure Ed448, not Ed448ctx). Our Ed448Signer mirrors
    // that. Verify the same way — concatenate, then verify with None.
    let mut signed_payload = Vec::with_capacity(context.len() + payload.len());
    signed_payload.extend_from_slice(&context);
    signed_payload.extend_from_slice(&payload);
    pk.verify(&signed_payload, &signature, None)
        .expect("verify must pass over canonical bytes Rust produces");
}

/// Sign with the native `PrivateKey`, but verify with a `PublicKey`
/// rebuilt from `derive_public` → `try_from`. If this fails, the
/// pubkey-bytes round-trip is broken (`as_byte` and `try_from`
/// disagree on encoding).
#[test]
fn ed448_pubkey_bytes_round_trip() {
    let mut seed = [0u8; 57];
    seed[0] = 0xAA;
    let sk = ed448_rust::PrivateKey::from(seed);
    let pk_native: ed448_rust::PublicKey = (&sk).into();
    let pk_bytes = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();

    // Bytes from `derive_public` should match `pk_native.as_byte()`.
    assert_eq!(
        pk_bytes,
        pk_native.as_byte().to_vec(),
        "derive_public must produce the same bytes as native pk.as_byte()"
    );

    let payload = b"hello world";
    let ctx = b"ctx";
    let sig = sk.sign(payload, Some(ctx)).unwrap();

    // 1) Native PK verifies its own sig.
    pk_native
        .verify(payload, &sig, Some(ctx))
        .expect("native PublicKey must verify a native signature");

    // 2) Rebuild PK from `as_byte()` then verify. This is what
    // production does (load from keystore).
    let pk_rebuilt = ed448_rust::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
    let rebuilt_bytes = pk_rebuilt.as_byte();
    eprintln!("native bytes: {}", hex::encode(&pk_native.as_byte()));
    eprintln!("rebuilt bytes: {}", hex::encode(&rebuilt_bytes));
    assert_eq!(
        &pk_native.as_byte()[..],
        &rebuilt_bytes[..],
        "rebuilt as_byte must equal native as_byte"
    );
    pk_rebuilt
        .verify(payload, &sig, Some(ctx))
        .expect("rebuilt PublicKey must verify a native signature");
}

/// Bare ed448-rust native sign/verify. Confirms the underlying
/// crate round-trips correctly when we call it directly (no
/// `Ed448Signer` wrapper).
#[test]
fn ed448_native_round_trip() {
    let mut seed = [0u8; 57];
    seed[0] = 0xAA;
    let sk = ed448_rust::PrivateKey::from(seed);
    let pk: ed448_rust::PublicKey = (&sk).into();
    let payload = b"hello world";
    let context = b"some-context";
    let sig = sk.sign(payload, Some(context)).expect("sign");
    pk.verify(payload, &sig, Some(context))
        .expect("native Ed448 sign/verify must round-trip");
}

/// Same payload + context as above, but going through
/// `quil_crypto::Ed448Signer::sign_with_domain`. If the native test
/// passes and this one fails, the wrapper is broken.
#[test]
fn ed448_simple_round_trip() {
    let payload = b"hello world";
    let context = b"some-context";
    let mut seed = [0u8; 57];
    seed[0] = 0xAA;
    let pk_bytes = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
    let signer =
        quil_crypto::Ed448Signer::from_bytes(&seed, &pk_bytes).unwrap();
    let sig = {
        use quil_types::crypto::Signer;
        signer.sign_with_domain(payload, context).unwrap()
    };
    let pk = ed448_rust::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
    let mut signed = Vec::with_capacity(context.len() + payload.len());
    signed.extend_from_slice(context);
    signed.extend_from_slice(payload);
    pk.verify(&signed, &sig, None)
        .expect("simple Ed448 sign/verify must round-trip");
}

#[test]
fn ed448_verify_rejects_when_payload_byte_is_flipped() {
    // Sanity check that the verify path actually rejects bad input —
    // not just always returning Ok regardless.
    let leave_pb = pb::ProverLeave {
        filters: vec![vec![0x01u8; 8]],
        frame_number: 99,
        public_key_signature_bls48581: None,
    };
    let bundle_pb = pb::MessageBundle {
        requests: vec![pb::MessageRequest {
            request: Some(pb::message_request::Request::Leave(leave_pb)),
            timestamp: 0,
        }],
        timestamp: 0,
    };
    let mut payload = quil_execution::message_envelope::proto_message_bundle_to_canonical_bytes(
        &bundle_pb,
    )
    .expect("canonicalize");

    let mut seed = [0u8; 57];
    seed[0] = 0xAA;
    let pk_bytes =
        quil_crypto::Ed448Signer::derive_public(&seed).expect("derive pubkey");
    let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &pk_bytes)
        .expect("Ed448 signer");
    let context = b"NODE_AUTHENTICATION".to_vec();
    let signature = {
        use quil_types::crypto::Signer;
        signer.sign_with_domain(&payload, &context).unwrap()
    };

    // Flip a byte AFTER signing — verify must reject.
    let last = payload.len() - 1;
    payload[last] ^= 0x01;

    // sign_with_domain signs concat(context, payload) with None ctx.
    // Verify the same way — concat then verify with None.
    let pk = ed448_rust::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
    let mut signed = Vec::with_capacity(context.len() + payload.len());
    signed.extend_from_slice(&context);
    signed.extend_from_slice(&payload);
    assert!(
        pk.verify(&signed, &signature, None).is_err(),
        "verify must reject tampered payload"
    );
}

#[test]
fn ed448_verify_rejects_when_context_differs() {
    let payload = b"some payload";
    let mut seed = [0u8; 57];
    seed[0] = 0xAA;
    let pk_bytes =
        quil_crypto::Ed448Signer::derive_public(&seed).expect("derive pubkey");
    let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &pk_bytes)
        .expect("Ed448 signer");
    let signature = {
        use quil_types::crypto::Signer;
        signer.sign_with_domain(payload, b"context-A").unwrap()
    };

    // sign_with_domain signed concat("context-A", payload) with None.
    // Verify with concat("context-B", payload) — must reject.
    let pk = ed448_rust::PublicKey::try_from(pk_bytes.as_slice()).unwrap();
    let mut wrong_signed = Vec::new();
    wrong_signed.extend_from_slice(b"context-B");
    wrong_signed.extend_from_slice(payload);
    assert!(
        pk.verify(&wrong_signed, &signature, None).is_err(),
        "verify must reject when context differs from sign-time"
    );
}

#[test]
fn ed448_verify_rejects_with_wrong_pubkey() {
    let payload = b"some payload";
    let mut seed_a = [0u8; 57];
    seed_a[0] = 0xAA;
    let signer_a = quil_crypto::Ed448Signer::from_bytes(
        &seed_a,
        &quil_crypto::Ed448Signer::derive_public(&seed_a).unwrap(),
    )
    .unwrap();
    let mut seed_b = [0u8; 57];
    seed_b[0] = 0xBB;
    let pk_b = quil_crypto::Ed448Signer::derive_public(&seed_b).unwrap();

    let context = b"ctx".to_vec();
    let signature = {
        use quil_types::crypto::Signer;
        signer_a.sign_with_domain(payload, &context).unwrap()
    };

    let pk = ed448_rust::PublicKey::try_from(pk_b.as_slice()).unwrap();
    assert!(
        pk.verify(payload, &signature, Some(&context)).is_err(),
        "verify must reject when pubkey doesn't match the signer"
    );
}
