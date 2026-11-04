//! Verify the running binary against the published release digest and
//! signatures: the startup self-check of the node and of qclient. Mirrors the
//! Go path at `node/main.go:309-378`.
//!
//! On startup the binary:
//! 1. Computes SHA3-256 of its own executable.
//! 2. Reads `<exe>.dgst` (an `sha3sum`-style line of the form
//! `SHA3-256(<filename>)= <hex>`) and checks that the parsed
//! hex digest equals the computed checksum.
//! 3. For each present `<exe>.dgst.sig.N` (N=1..len(SIGNATORIES)),
//! verifies the Ed448 signature over the **full bytes of the
//! `.dgst` file** (not the parsed digest) against the (N-1)th
//! hardcoded signatory public key.
//! 4. Refuses to start if fewer than `quorum_required(N_TOTAL)`
//! signatures verified.
//! 5. Refuses to start unless the signed `SHA3-256(<filename>)=` label
//! names the executable's own file name, so a release signed for
//! another version, type or platform does not pass under this name.
//!
//! Quorum follows the Go formula `((N-4)/2) + ((N-4) % 2)`. With
//! N=17, that's `(13/2)+(13%2) = 6 + 1 = 7`.

use ed448_rust::PublicKey;
use quil_config::SIGNATORIES;
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

/// What to do about a failed [`self_check`], for its error message.
pub const SELF_CHECK_HINT: &str = "are you running this from source? (use \
     --signature-check=false or QUILIBRIUM_SIGNATURE_CHECK=false)";

/// What [`self_check`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum SelfCheck {
    /// The binary verified, with this many valid signatures.
    Verified(usize),
    /// `--signature-check=false` or `QUILIBRIUM_SIGNATURE_CHECK=false`.
    Disabled,
    /// No signature check on this platform (Windows).
    Unavailable,
}

/// The release self-check of a starting binary: verify the running executable
/// unless `enabled` is false or the platform has no check. An error means the
/// binary must not run.
pub fn self_check(enabled: bool) -> Result<SelfCheck, ReleaseCheckError> {
    if !enabled {
        return Ok(SelfCheck::Disabled);
    }
    if cfg!(target_os = "windows") {
        return Ok(SelfCheck::Unavailable);
    }
    let exe = std::env::current_exe().map_err(|source| ReleaseCheckError::ExePath { source })?;
    verify_release_signatures(&exe).map(SelfCheck::Verified)
}

/// Minimum number of valid signatures required to accept the release.
/// Matches Go's `((N-4)/2) + ((N-4) % 2)` formula.
pub fn quorum_required(total_signatories: usize) -> usize {
    let n = total_signatories.saturating_sub(4);
    n / 2 + n % 2
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseCheckError {
    #[error("could not determine the executable path: {source}")]
    ExePath {
        #[source]
        source: std::io::Error,
    },
    #[error("io reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("digest file {path} is not valid utf-8: {source}")]
    DgstNotUtf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("digest file {path} format invalid: {detail}")]
    DgstFormat { path: PathBuf, detail: String },
    #[error("digest mismatch: binary SHA3-256={computed}, dgst file={claimed}")]
    DigestMismatch { claimed: String, computed: String },
    #[error("signatory {idx} pubkey decode failed: {detail}")]
    SignatoryDecode { idx: usize, detail: String },
    #[error("signature {idx} ({path}) failed Ed448 verification")]
    BadSignature { idx: usize, path: PathBuf },
    #[error(
        "quorum not met: {valid} valid signatures, need at least {required} (out of {total} signatories)"
    )]
    QuorumNotMet {
        valid: usize,
        required: usize,
        total: usize,
    },
    #[error(
        "digest file {path} is signed for another file ({label:?}), not {file}; run a release \
         under its published file name"
    )]
    NameMismatch {
        path: PathBuf,
        label: String,
        file: String,
    },
}

/// Verify `<exe_path>`, `<exe_path>.dgst`, and `<exe_path>.dgst.sig.*`.
/// Returns the number of valid signatures observed on success.
pub fn verify_release_signatures(exe_path: &Path) -> Result<usize, ReleaseCheckError> {
    verify_release_signatures_with(exe_path, &SIGNATORIES)
}

/// Same as [`verify_release_signatures`] but with a caller-supplied
/// signatory list. Exposed so the unit test can swap in a fixture set.
pub fn verify_release_signatures_with(
    exe_path: &Path,
    signatories_hex: &[&str],
) -> Result<usize, ReleaseCheckError> {
    // A release runs through its symlink (/usr/local/bin/qclient); on macOS
    // `current_exe` returns the link. The release files sit beside, and the
    // signed label names, the file it links.
    let exe_path = &std::fs::canonicalize(exe_path).map_err(|e| ReleaseCheckError::Io {
        path: exe_path.to_path_buf(),
        source: e,
    })?;

    let dgst_path = append_suffix(exe_path, ".dgst");
    let dgst_contents = std::fs::read(&dgst_path).map_err(|e| ReleaseCheckError::Io {
        path: dgst_path.clone(),
        source: e,
    })?;
    let dgst_str =
        std::str::from_utf8(&dgst_contents).map_err(|e| ReleaseCheckError::DgstNotUtf8 {
            path: dgst_path.clone(),
            source: e,
        })?;

    // Format produced by Go releases: `SHA3-256(<file>)= <hex>\n`.
    // Match Go's parser: split on ' ', second token is the hex digest,
    // take the first 64 chars (32 bytes).
    let mut parts = dgst_str.split(' ');
    let label = parts.next().unwrap_or_default();
    let hex_part = parts.next().ok_or_else(|| ReleaseCheckError::DgstFormat {
        path: dgst_path.clone(),
        detail: "missing space-separated hex".into(),
    })?;
    if hex_part.len() < 64 {
        return Err(ReleaseCheckError::DgstFormat {
            path: dgst_path.clone(),
            detail: format!("hex token too short ({} bytes)", hex_part.len()),
        });
    }
    let claimed = hex::decode(&hex_part[..64]).map_err(|e| ReleaseCheckError::DgstFormat {
        path: dgst_path.clone(),
        detail: format!("invalid hex: {}", e),
    })?;
    // Hashed last and in pieces: a build without a digest file fails at once,
    // and a check does not hold the whole binary in memory.
    let computed = file_sha3(exe_path)?;
    if claimed != computed {
        return Err(ReleaseCheckError::DigestMismatch {
            claimed: hex::encode(claimed),
            computed: hex::encode(computed),
        });
    }

    let mut valid = 0usize;
    let total = signatories_hex.len();
    for (zero_idx, pk_hex) in signatories_hex.iter().enumerate() {
        let one_idx = zero_idx + 1;
        let sig_path = append_suffix(exe_path, &format!(".dgst.sig.{}", one_idx));
        let sig = match std::fs::read(&sig_path) {
            Ok(b) => b,
            Err(_) => continue, // missing is fine; only present-but-bad fails
        };
        let pk_bytes = hex::decode(pk_hex).map_err(|e| ReleaseCheckError::SignatoryDecode {
            idx: one_idx,
            detail: format!("hex decode: {}", e),
        })?;
        let pubkey = PublicKey::try_from(pk_bytes.as_slice()).map_err(|e| {
            ReleaseCheckError::SignatoryDecode {
                idx: one_idx,
                detail: format!("ed448 key parse: {:?}", e),
            }
        })?;
        // Go does `ed448.Verify(pubkey, digest, sig, "")` — the message
        // is the *full digest file contents* (incl. label + trailing
        // newline), context is empty.
        if pubkey.verify(&dgst_contents, &sig, None).is_err() {
            return Err(ReleaseCheckError::BadSignature {
                idx: one_idx,
                path: sig_path,
            });
        }
        valid += 1;
    }

    let required = quorum_required(total);
    if valid < required {
        return Err(ReleaseCheckError::QuorumNotMet {
            valid,
            required,
            total,
        });
    }

    let file = exe_path.file_name().unwrap_or_default().to_string_lossy();
    if !label_names(label, &file) {
        return Err(ReleaseCheckError::NameMismatch {
            path: dgst_path,
            label: label.chars().take(120).collect(),
            file: file.into_owned(),
        });
    }
    Ok(valid)
}

/// Whether a `.dgst` label, `SHA3-256(<filename>)=` as `openssl sha3-256`
/// writes it, names `file`.
fn label_names(label: &str, file: &str) -> bool {
    label == format!("SHA3-256({file})=")
}

/// The SHA3-256 of a file.
fn file_sha3(path: &Path) -> Result<[u8; 32], ReleaseCheckError> {
    let io = |source| ReleaseCheckError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut hasher = Sha3_256::new();
    std::io::copy(&mut file, &mut hasher).map_err(io)?;
    Ok(hasher.finalize().into())
}

fn append_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    p.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Round-trip with a synthetic binary + deterministic test
    /// signatories. Exercises the full code path (digest computation,
    /// .dgst parsing, signature verify, quorum check) without
    /// touching production keys or the network. Uses fixed seeds so
    /// the test is fully reproducible.
    #[test]
    fn synthetic_round_trip() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("fake-node");
        let exe_bytes = b"pretend this is a binary";
        std::fs::write(&exe, exe_bytes).unwrap();
        let digest: [u8; 32] = Sha3_256::digest(exe_bytes).into();

        // Build the .dgst file in the same shape Go releases use.
        let dgst_path = append_suffix(&exe, ".dgst");
        let dgst_line = format!("SHA3-256(fake-node)= {}\n", hex::encode(digest));
        std::fs::write(&dgst_path, dgst_line.as_bytes()).unwrap();

        // Five test signatories with fixed 57-byte seeds. With N=5,
        // `quorum_required` = (1/2)+(1%2) = 1, so any single valid
        // signature satisfies quorum.
        let sks: Vec<PrivateKey> = (0u8..5)
            .map(|i| {
                let mut seed = [0u8; KEY_LENGTH];
                seed[0] = 0xA0 + i; // distinct seeds per signatory
                PrivateKey::from(seed)
            })
            .collect();
        let pks_hex: Vec<String> = sks
            .iter()
            .map(|sk| hex::encode(PublicKey::from(sk).as_byte()))
            .collect();

        // Sign for indices 1, 3, 5 — three valid out of five, well
        // above the quorum of 1.
        let dgst_bytes = std::fs::read(&dgst_path).unwrap();
        for &one_idx in &[1usize, 3, 5] {
            let sig = sks[one_idx - 1].sign(&dgst_bytes, None).unwrap();
            let sig_path = append_suffix(&exe, &format!(".dgst.sig.{}", one_idx));
            std::fs::File::create(&sig_path)
                .unwrap()
                .write_all(&sig)
                .unwrap();
        }

        let pks_refs: Vec<&str> = pks_hex.iter().map(|s| s.as_str()).collect();
        let count = verify_release_signatures_with(&exe, &pks_refs).expect("verify ok");
        assert_eq!(count, 3);
    }

    /// A signature present in the file system but invalid (signed by
    /// the wrong key) must fail the whole check, not silently skip.
    #[test]
    fn present_but_invalid_signature_rejected() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("fake-node");
        let exe_bytes = b"binary";
        std::fs::write(&exe, exe_bytes).unwrap();
        let digest: [u8; 32] = Sha3_256::digest(exe_bytes).into();
        let dgst_path = append_suffix(&exe, ".dgst");
        std::fs::write(
            &dgst_path,
            format!("SHA3-256(fake-node)= {}\n", hex::encode(digest)).as_bytes(),
        )
        .unwrap();

        let real_seed = [0xAAu8; KEY_LENGTH];
        let real_sk = PrivateKey::from(real_seed);
        let real_pk_hex = hex::encode(PublicKey::from(&real_sk).as_byte());

        // Sign the .dgst with an ATTACKER key, then place under sig.1.
        let attacker_seed = [0xFFu8; KEY_LENGTH];
        let attacker_sk = PrivateKey::from(attacker_seed);
        let dgst_bytes = std::fs::read(&dgst_path).unwrap();
        let bad_sig = attacker_sk.sign(&dgst_bytes, None).unwrap();
        std::fs::write(append_suffix(&exe, ".dgst.sig.1"), &bad_sig).unwrap();

        let err = verify_release_signatures_with(&exe, &[real_pk_hex.as_str()]).unwrap_err();
        match err {
            ReleaseCheckError::BadSignature { idx, .. } => assert_eq!(idx, 1),
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    /// A release run through a symlink verifies as the file it links, and
    /// that name is the one the label must carry: a copy under another name
    /// beside the same release files stays refused.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_release_verifies_under_the_release_name() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let name = "qclient-2.1.0.25-linux-amd64";
        let exe = tmp.path().join(name);
        std::fs::write(&exe, b"release").unwrap();
        let digest: [u8; 32] = Sha3_256::digest(b"release").into();
        let dgst = format!("SHA3-256({name})= {}\n", hex::encode(digest));
        std::fs::write(append_suffix(&exe, ".dgst"), &dgst).unwrap();
        let sk = PrivateKey::from([0xC3u8; KEY_LENGTH]);
        let sig = sk.sign(dgst.as_bytes(), None).unwrap();
        std::fs::write(append_suffix(&exe, ".dgst.sig.1"), &sig).unwrap();
        let pk_hex = hex::encode(PublicKey::from(&sk).as_byte());

        let link = tmp.path().join("qclient");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let count = verify_release_signatures_with(&link, &[pk_hex.as_str()]).unwrap();
        assert_eq!(count, 1);

        let copy = tmp.path().join("renamed");
        std::fs::copy(&exe, &copy).unwrap();
        std::fs::write(append_suffix(&copy, ".dgst"), &dgst).unwrap();
        std::fs::write(append_suffix(&copy, ".dgst.sig.1"), &sig).unwrap();
        let err = verify_release_signatures_with(&copy, &[pk_hex.as_str()]).unwrap_err();
        assert!(
            matches!(err, ReleaseCheckError::NameMismatch { .. }),
            "{err:?}"
        );
    }

    /// Enabled, the check fails closed on a binary without release files (a
    /// test binary is one); disabled, it reads nothing.
    #[cfg(unix)]
    #[test]
    fn self_check_fails_closed_without_release_files_unless_disabled() {
        assert_eq!(self_check(false).unwrap(), SelfCheck::Disabled);
        match self_check(true).unwrap_err() {
            ReleaseCheckError::Io { path, .. } => {
                assert!(path.to_string_lossy().ends_with(".dgst"), "{path:?}")
            }
            other => panic!("expected the missing digest file, got {other:?}"),
        }
    }

    /// Tampered binary — digest in .dgst no longer matches.
    #[test]
    fn tampered_binary_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("fake-node");
        std::fs::write(&exe, b"original").unwrap();
        let bad_digest = [0u8; 32];
        let dgst_path = append_suffix(&exe, ".dgst");
        std::fs::write(
            &dgst_path,
            format!("SHA3-256(fake-node)= {}\n", hex::encode(bad_digest)),
        )
        .unwrap();
        let err = verify_release_signatures_with(&exe, &[]).unwrap_err();
        match err {
            ReleaseCheckError::DigestMismatch { .. } => {}
            other => panic!("expected DigestMismatch, got {:?}", other),
        }
    }

    /// A quorum-signed release whose label names another release (an older
    /// version here) is refused when run under this release's file name.
    #[test]
    fn release_signed_for_another_file_rejected() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("node-2.1.0.25-linux-amd64");
        std::fs::write(&exe, b"old release").unwrap();
        let digest: [u8; 32] = Sha3_256::digest(b"old release").into();
        let sk = PrivateKey::from([0xA1u8; KEY_LENGTH]);
        let pk_hex = hex::encode(PublicKey::from(&sk).as_byte());
        for signed_as in [
            "node-2.1.0.24-linux-amd64",
            "node-2.1.0.25-linux-arm64",
            "qclient-2.1.0.25-linux-amd64",
        ] {
            let dgst = format!("SHA3-256({signed_as})= {}\n", hex::encode(digest));
            std::fs::write(append_suffix(&exe, ".dgst"), &dgst).unwrap();
            let sig = sk.sign(dgst.as_bytes(), None).unwrap();
            std::fs::write(append_suffix(&exe, ".dgst.sig.1"), &sig).unwrap();
            let err = verify_release_signatures_with(&exe, &[pk_hex.as_str()]).unwrap_err();
            match err {
                ReleaseCheckError::NameMismatch { label, file, .. } => {
                    assert_eq!(label, format!("SHA3-256({signed_as})="));
                    assert_eq!(file, "node-2.1.0.25-linux-amd64");
                }
                other => panic!("expected NameMismatch, got {:?}", other),
            }
        }
    }

    /// The signed label names the release file: a quorum-signed release
    /// renamed to a short command name, with its release files renamed beside
    /// it, is refused, and the same files pass under the release name. A
    /// release image must keep that name and link it.
    #[test]
    fn a_release_renamed_to_a_command_name_is_refused() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let name = "node-2.1.0.25-linux-amd64";
        let digest: [u8; 32] = Sha3_256::digest(b"release").into();
        let dgst = format!("SHA3-256({name})= {}\n", hex::encode(digest));
        let sk = PrivateKey::from([0xD4u8; KEY_LENGTH]);
        let sig = sk.sign(dgst.as_bytes(), None).unwrap();
        let pk_hex = hex::encode(PublicKey::from(&sk).as_byte());
        let place = |file: &str| {
            let exe = tmp.path().join(file);
            std::fs::write(&exe, b"release").unwrap();
            std::fs::write(append_suffix(&exe, ".dgst"), &dgst).unwrap();
            std::fs::write(append_suffix(&exe, ".dgst.sig.1"), sig).unwrap();
            exe
        };

        let released = place(name);
        assert_eq!(
            verify_release_signatures_with(&released, &[pk_hex.as_str()]).unwrap(),
            1
        );
        let renamed = place("node");
        match verify_release_signatures_with(&renamed, &[pk_hex.as_str()]).unwrap_err() {
            ReleaseCheckError::NameMismatch { label, file, .. } => {
                assert_eq!(label, format!("SHA3-256({name})="));
                assert_eq!(file, "node");
            }
            other => panic!("expected NameMismatch, got {other:?}"),
        }
    }

    /// The committed published `.dgst` names its own file, and only it.
    #[test]
    fn published_label_names_its_file() {
        const DGST: &[u8] =
            include_bytes!("../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst");
        let label = std::str::from_utf8(DGST)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        assert!(label_names(label, "node-2.1.0.22-linux-amd64"));
        assert!(!label_names(label, "node-2.1.0.23-linux-amd64"));
        assert!(!label_names(label, "node-2.1.0.22-linux-arm64"));
        assert!(!label_names(label, "qclient-2.1.0.22-linux-amd64"));
        assert!(!label_names(label, "node"));
    }

    /// Quorum math test mirroring Go's formula.
    #[test]
    fn quorum_math() {
        // N=17 (production): (13/2)+(13%2) = 6+1 = 7
        assert_eq!(quorum_required(17), 7);
        // N=16: (12/2)+(12%2) = 6+0 = 6
        assert_eq!(quorum_required(16), 6);
        // N=5: (1/2)+(1%2) = 0+1 = 1
        assert_eq!(quorum_required(5), 1);
        // N=4: 0
        assert_eq!(quorum_required(4), 0);
        // N=0: 0 (saturating)
        assert_eq!(quorum_required(0), 0);
        assert_eq!(
            quorum_required(SIGNATORIES.len()),
            quil_config::signatory_quorum()
        );
    }

    /// Offline check against fixtures pulled from
    /// `https://releases.quilibrium.com/` and committed under
    /// `quil-node/tests/fixtures/release/`. Asserts every published signature
    /// for `node-2.1.0.22-linux-amd64` validates against the
    /// production [`SIGNATORIES`] using the same Ed448 verify call
    /// the live path uses, and that quorum is met.
    ///
    /// Refreshing fixtures: re-download the `.dgst` and `.dgst.sig.*`
    /// files for a new release into the same directory and bump
    /// `REL_PREFIX` below.
    #[test]
    fn production_signatories_offline() {
        const DGST: &[u8] =
            include_bytes!("../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst");
        // (one-based signatory index, signature bytes) pairs for
        // every `.dgst.sig.N` present in the release. Quorum on N=17
        // is 7; the published set has exactly 7 here.
        let sigs: &[(usize, &[u8])] = &[
            (
                1,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.1"
                ),
            ),
            (
                2,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.2"
                ),
            ),
            (
                10,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.10"
                ),
            ),
            (
                13,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.13"
                ),
            ),
            (
                14,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.14"
                ),
            ),
            (
                16,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.16"
                ),
            ),
            (
                17,
                include_bytes!(
                    "../../quil-node/tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.17"
                ),
            ),
        ];

        let mut valid = 0;
        for (one_idx, sig) in sigs {
            let pk_hex = SIGNATORIES[one_idx - 1];
            let pk_bytes = hex::decode(pk_hex).expect("signatory hex");
            let pubkey = PublicKey::try_from(pk_bytes.as_slice()).expect("ed448 key parse");
            assert!(
                pubkey.verify(DGST, sig, None).is_ok(),
                "signatory #{} ({}…) failed to verify against committed .dgst fixture",
                one_idx,
                &pk_hex[..16]
            );
            valid += 1;
        }
        let required = quorum_required(SIGNATORIES.len());
        assert!(
            valid >= required,
            "fixture set under quorum: {} valid, need {}",
            valid,
            required
        );
    }

    /// Network-gated test against an actual published release.
    /// Downloads only `.dgst` and `.dgst.sig.N` (small files), then:
    /// - Asserts every present signature validates against the
    /// production [`SIGNATORIES`] using the same Ed448 verify call
    /// the live `verify_release_signatures` path uses.
    /// - Asserts quorum is met by the present signatures.
    ///
    /// We deliberately do **not** download the binary itself (hundreds
    /// of megabytes); the `synthetic_round_trip` and
    /// `tampered_binary_rejected` tests cover the digest-vs-binary
    /// path. This test specifically guards the signatory list and
    /// Ed448 verify implementation against published wire data.
    ///
    /// **Run manually**: `cargo test -p quil-crypto \
    /// release_check::tests::production_release_signatures \
    /// -- --ignored --nocapture`
    #[test]
    #[ignore = "fetches files from releases.quilibrium.com — run on demand"]
    fn production_release_signatures() {
        // Pinned to a published version. Bump as releases ship.
        const REL: &str = "2.1.0.21";
        const PLATFORM: &str = "linux-amd64";
        let base = format!("https://releases.quilibrium.com/node-{}-{}", REL, PLATFORM);

        let dgst = http_get(&format!("{}.dgst", base)).expect("download .dgst");
        let dgst_str = std::str::from_utf8(&dgst).expect(".dgst utf-8");
        eprintln!("dgst: {}", dgst_str.trim());

        let mut valid = 0usize;
        let mut present = 0usize;
        for (zero_idx, pk_hex) in SIGNATORIES.iter().enumerate() {
            let one_idx = zero_idx + 1;
            let sig = match http_get(&format!("{}.dgst.sig.{}", base, one_idx)) {
                Ok(b) => b,
                Err(_) => continue,
            };
            present += 1;
            let pk_bytes = hex::decode(pk_hex).expect("signatory hex");
            let pubkey = PublicKey::try_from(pk_bytes.as_slice()).expect("signatory ed448 key");
            assert!(
                pubkey.verify(&dgst, &sig, None).is_ok(),
                "signatory #{} ({}…) failed to verify against published .dgst",
                one_idx,
                &pk_hex[..16]
            );
            valid += 1;
        }
        let required = quorum_required(SIGNATORIES.len());
        eprintln!(
            "release {} {}: present={} valid={} required={} total={}",
            REL,
            PLATFORM,
            present,
            valid,
            required,
            SIGNATORIES.len()
        );
        assert!(
            valid >= required,
            "quorum not met for release {}: {} valid, need {}",
            REL,
            valid,
            required
        );
    }

    fn http_get(url: &str) -> Result<Vec<u8>, String> {
        // Minimal blocking HTTP — uses `ureq` if available, otherwise
        // falls back to `curl`. Avoids pulling reqwest into the crate
        // dep graph just for one ignored test.
        match std::process::Command::new("curl")
            .args(["-fsSL", url])
            .output()
        {
            Ok(out) if out.status.success() => Ok(out.stdout),
            Ok(out) => Err(format!("curl {}: exit {}", url, out.status)),
            Err(e) => Err(format!("spawn curl: {}", e)),
        }
    }

    /// A release-origin attacker serves an older quorum-signed release under
    /// the newer release's file name.
    #[test]
    fn reproduces_relabelled_release_passes_self_check() {
        use ed448_rust::{PrivateKey, KEY_LENGTH};
        let tmp = tempfile::TempDir::new().unwrap();
        let exe = tmp.path().join("node-2.1.0.25-linux-amd64");
        std::fs::write(&exe, b"older release").unwrap();
        let digest: [u8; 32] = Sha3_256::digest(b"older release").into();
        let dgst = format!(
            "SHA3-256(node-2.1.0.24-linux-amd64)= {}\n",
            hex::encode(digest)
        );
        std::fs::write(append_suffix(&exe, ".dgst"), &dgst).unwrap();
        let sk = PrivateKey::from([0xB2u8; KEY_LENGTH]);
        let sig = sk.sign(dgst.as_bytes(), None).unwrap();
        std::fs::write(append_suffix(&exe, ".dgst.sig.1"), sig).unwrap();
        let pk_hex = hex::encode(PublicKey::from(&sk).as_byte());
        let result = verify_release_signatures_with(&exe, &[pk_hex.as_str()]);
        assert!(
            result.is_err(),
            "release signed for node-2.1.0.24 passed the self-check as \
             node-2.1.0.25-linux-amd64: {result:?}"
        );
    }
}
