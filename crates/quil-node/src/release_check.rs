//! Verify the running binary against the published release digest and
//! signatures. Mirrors the Go path at `node/main.go:309-378`.
//!
//! On startup the node:
//!   1. Computes SHA3-256 of its own executable.
//!   2. Reads `<exe>.dgst` (an `sha3sum`-style line of the form
//!      `SHA3-256(<filename>)= <hex>`) and checks that the parsed
//!      hex digest equals the computed checksum.
//!   3. For each present `<exe>.dgst.sig.N` (N=1..len(SIGNATORIES)),
//!      verifies the Ed448 signature over the **full bytes of the
//!      `.dgst` file** (not the parsed digest) against the (N-1)th
//!      hardcoded signatory public key.
//!   4. Refuses to start if fewer than `quorum_required(N_TOTAL)`
//!      signatures verified.
//!
//! Quorum follows the Go formula `((N-4)/2) + ((N-4) % 2)`. With
//! N=17, that's `(13/2)+(13%2) = 6 + 1 = 7`.

use ed448_rust::PublicKey;
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

/// Ed448 public keys of the release signatories, hex-encoded.
/// Mirrors `config.Signatories` in `/config/config.go:151-169`.
/// **Order matters**: `.dgst.sig.N` is signed by `SIGNATORIES[N-1]`.
pub const SIGNATORIES: &[&str] = &[
    "b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100",
    "de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00",
    "540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680",
    "fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900",
    "4160572e493e1bf15c44e055b11bf75230c76c7d2c67b48066770ab03dfd5ed34c97b9a431ec18578c83a0df9250b8362c38068650e8b01400",
    "45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00",
    "92cd8ee5362f3ae274a75ab9471024dbc144bff441ed8af7d19750ac512ff51e40e7f7b01e4f96b6345dd58878565948c3eb52c53f250b5080",
    "001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700",
    "65b835071731c6e785bb2d107c7d85d8a537d79c435c3f42bb2f87027f93f858d7b37c598cef267a5db46e345f7a6f81969b465686657d1e00",
    "b6df0ebab6ea20cc2eb718db5873c07bb50cf239a16bb6306bbe0f24280664f99f732c4049b8eda1226067e70ffb81958834d486942a122100",
    "3e087771c36098cb2d371711fd882d309b4caebbd06ded3077a975231344f027ad31c7069e76ba5070451d8eb5abf29bfeb34fcdf9ba906480",
    "57be2861faf0fffcbfd122c85c77010dce8f213030905781b85b6f345d912c7b5ace17797d9810899dfb8d13e7c8369595740725ab3dd5bd00",
    "61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980",
    "9ab76d775487c85c8e5aa0c5b3f961772967899a14644651031ae5f98ac197bee3f8880492c4fdba268716fc4b7c38ffcac370b663ac10b600",
    "c0d2d47d6309572a055abf593de26a8c980be04df9672ed40939f93b51806be53f6e58f330ff348592350783d24109fa7db8bf7e61c9a8b780",
    "6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100",
    "0ca6f5a9d7f86c1111be5edf31e26979918aa4fa3daae6de1120e05c2a09bdb8d2feeb084286a3347e06ced25530358cbc74c204d2a1753a00",
];

/// Minimum number of valid signatures required to accept the release.
/// Matches Go's `((N-4)/2) + ((N-4) % 2)` formula.
pub fn quorum_required(total_signatories: usize) -> usize {
    let n = total_signatories.saturating_sub(4);
    n / 2 + n % 2
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseCheckError {
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
}

/// Verify `<exe_path>`, `<exe_path>.dgst`, and `<exe_path>.dgst.sig.*`.
/// Returns the number of valid signatures observed on success.
pub fn verify_release_signatures(exe_path: &Path) -> Result<usize, ReleaseCheckError> {
    verify_release_signatures_with(exe_path, SIGNATORIES)
}

/// Same as [`verify_release_signatures`] but with a caller-supplied
/// signatory list. Exposed so the unit test can swap in a fixture set.
pub fn verify_release_signatures_with(
    exe_path: &Path,
    signatories_hex: &[&str],
) -> Result<usize, ReleaseCheckError> {
    let exe_bytes = std::fs::read(exe_path).map_err(|e| ReleaseCheckError::Io {
        path: exe_path.to_path_buf(),
        source: e,
    })?;
    let computed: [u8; 32] = Sha3_256::digest(&exe_bytes).into();

    let dgst_path = append_suffix(exe_path, ".dgst");
    let dgst_contents = std::fs::read(&dgst_path).map_err(|e| ReleaseCheckError::Io {
        path: dgst_path.clone(),
        source: e,
    })?;
    let dgst_str = std::str::from_utf8(&dgst_contents).map_err(|e| {
        ReleaseCheckError::DgstNotUtf8 {
            path: dgst_path.clone(),
            source: e,
        }
    })?;

    // Format produced by Go releases: `SHA3-256(<file>)= <hex>\n`.
    // Match Go's parser: split on ' ', second token is the hex digest,
    // take the first 64 chars (32 bytes).
    let mut parts = dgst_str.split(' ');
    let _label = parts.next();
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
        let pubkey =
            PublicKey::try_from(pk_bytes.as_slice()).map_err(|e| ReleaseCheckError::SignatoryDecode {
                idx: one_idx,
                detail: format!("ed448 key parse: {:?}", e),
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
    Ok(valid)
}

fn append_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    p.with_file_name(name)
}

/// Default value for the signature-check flag, matching Go's
/// `signatureCheckDefault()` at `node/main.go:195`. Honors
/// `QUILIBRIUM_SIGNATURE_CHECK=true|false`; otherwise true.
pub fn signature_check_default() -> bool {
    match std::env::var("QUILIBRIUM_SIGNATURE_CHECK") {
        Ok(v) => match v.parse::<bool>() {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false': {}",
                    v
                );
                true
            }
        },
        Err(_) => true,
    }
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

        let err =
            verify_release_signatures_with(&exe, &[real_pk_hex.as_str()]).unwrap_err();
        match err {
            ReleaseCheckError::BadSignature { idx, .. } => assert_eq!(idx, 1),
            other => panic!("expected BadSignature, got {:?}", other),
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
    }

    /// Offline check against fixtures pulled from
    /// `https://releases.quilibrium.com/` and committed under
    /// `tests/fixtures/release/`. Asserts every published signature
    /// for `node-2.1.0.22-linux-amd64` validates against the
    /// production [`SIGNATORIES`] using the same Ed448 verify call
    /// the live path uses, and that quorum is met.
    ///
    /// Refreshing fixtures: re-download the `.dgst` and `.dgst.sig.*`
    /// files for a new release into the same directory and bump
    /// `REL_PREFIX` below.
    #[test]
    fn production_signatories_offline() {
        const DGST: &[u8] = include_bytes!(
            "../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst"
        );
        // (one-based signatory index, signature bytes) pairs for
        // every `.dgst.sig.N` present in the release. Quorum on N=17
        // is 7; the published set has exactly 7 here.
        let sigs: &[(usize, &[u8])] = &[
            (1,  include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.1")),
            (2,  include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.2")),
            (10, include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.10")),
            (13, include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.13")),
            (14, include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.14")),
            (16, include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.16")),
            (17, include_bytes!("../tests/fixtures/release/node-2.1.0.22-linux-amd64.dgst.sig.17")),
        ];

        let mut valid = 0;
        for (one_idx, sig) in sigs {
            let pk_hex = SIGNATORIES[one_idx - 1];
            let pk_bytes = hex::decode(pk_hex).expect("signatory hex");
            let pubkey =
                PublicKey::try_from(pk_bytes.as_slice()).expect("ed448 key parse");
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
    ///   production [`SIGNATORIES`] using the same Ed448 verify call
    ///   the live `verify_release_signatures` path uses.
    /// - Asserts quorum is met by the present signatures.
    ///
    /// We deliberately do **not** download the binary itself (hundreds
    /// of megabytes); the `synthetic_round_trip` and
    /// `tampered_binary_rejected` tests cover the digest-vs-binary
    /// path. This test specifically guards the signatory list and
    /// Ed448 verify implementation against published wire data.
    ///
    /// **Run manually**: `cargo test -p quil-node \
    ///   release_check::tests::production_release_signatures \
    ///   -- --ignored --nocapture`
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
            Ok(out) => Err(format!(
                "curl {}: exit {}",
                url,
                out.status
            )),
            Err(e) => Err(format!("spawn curl: {}", e)),
        }
    }
}
