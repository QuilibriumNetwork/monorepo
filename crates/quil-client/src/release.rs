//! Release download + signatory-quorum verification.
//!
//! Port of `client/utils/download.go` + the signature gate in
//! `client/cmd/root.go`. Binaries and their `.dgst` / `.dgst.sig.N` files
//! come from `https://releases.quilibrium.com`; a release is trusted when a
//! quorum of the [`SIGNATORIES`](quil_config::SIGNATORIES) Ed448 keys sign
//! its digest file.
//!
//! A release is held in memory until it verifies: nothing is written under
//! the install tree before that, and the verified files reach their final
//! names by atomic rename from private temporary files beside them.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use quil_config::{signatory_quorum, SIGNATORIES};

use crate::system;

/// Fetch a URL's body as bytes.
pub async fn http_get_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {url}: HTTP {}", resp.status());
    }
    Ok(resp
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("read {url}: {e}"))?
        .to_vec())
}

/// Whether a remote file exists (HEAD-ish via GET status).
pub async fn remote_exists(url: &str) -> bool {
    reqwest::get(url)
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Fetch the latest version string for a release type (`node` or `qclient`).
/// The `/release` (or `/qclient-release`) endpoint's first line is a
/// filename `type-VERSION-os-arch`; the version is the 2nd `-`-segment.
pub async fn get_latest_version(release_type: &str) -> anyhow::Result<String> {
    let url = if release_type == system::RELEASE_TYPE_QCLIENT {
        format!("{}/qclient-release", system::BASE_RELEASE_URL)
    } else {
        format!("{}/release", system::BASE_RELEASE_URL)
    };
    let body = http_get_bytes(&url).await?;
    parse_latest_version(&String::from_utf8_lossy(&body))
}

/// The version named by the first line of a release list, which must be a
/// release version ([`is_release_version`]).
fn parse_latest_version(text: &str) -> anyhow::Result<String> {
    let first = text.lines().next().unwrap_or("").trim();
    let parts: Vec<&str> = first.split('-').collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid release filename format: {first:?}");
    }
    validate_version(parts[1])?;
    Ok(parts[1].to_string())
}

/// Whether `version` is a release version: two to five dot-separated
/// decimal parts, such as `2.1.0.25`. Only such a version may name a file
/// or directory under the install tree.
pub fn is_release_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    (2..=5).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 18 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Fail unless `version` is a release version ([`is_release_version`]).
pub fn validate_version(version: &str) -> anyhow::Result<()> {
    if !is_release_version(version) {
        anyhow::bail!(
            "invalid release version {version:?}: expected digits and dots, such as 2.1.0.25"
        );
    }
    Ok(())
}

/// Order two release versions part by part, numerically (`2.1.0.9` is
/// older than `2.1.0.25`); a missing part counts as 0.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let parse = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    let (a, b) = (parse(a), parse(b));
    (0..a.len().max(b.len()))
        .map(|i| {
            let x = a.get(i).copied().unwrap_or(0);
            x.cmp(&b.get(i).copied().unwrap_or(0))
        })
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// The version of the release binary `symlink` points to, when it points to
/// a `<release_type>-<version>-<os>-<arch>` file.
pub fn linked_version(symlink: &Path, release_type: &str) -> Option<String> {
    let target = std::fs::read_link(symlink).ok()?;
    let rest = target
        .file_name()?
        .to_str()?
        .strip_prefix(release_type)?
        .strip_prefix('-')?;
    let version = rest.split('-').next()?;
    is_release_version(version).then(|| version.to_string())
}

/// Refuse to replace `installed` with the older `target` unless
/// `allow_downgrade`: a served release list must not roll a host back to an
/// older signed release.
pub fn check_downgrade(
    installed: Option<&str>,
    target: &str,
    allow_downgrade: bool,
) -> anyhow::Result<()> {
    if let Some(installed) = installed {
        if !allow_downgrade && compare_versions(target, installed).is_lt() {
            anyhow::bail!(
                "refusing to downgrade from {installed} to {target}; pass --allow-downgrade \
                 to install an older release on purpose"
            );
        }
    }
    Ok(())
}

/// The standardized binary filename `type-version-os-arch`. Fails unless
/// `version` is a release version ([`is_release_version`]).
pub fn release_filename(release_type: &str, version: &str) -> anyhow::Result<String> {
    validate_version(version)?;
    let (os, arch) = system::system_info()?;
    Ok(format!("{release_type}-{version}-{os}-{arch}"))
}

/// Fetch the `.dgst` file + each present `.dgst.sig.N` signature for a
/// release binary, writing nothing. Returns the digest bytes + the collected
/// `(index, signature)` pairs.
pub async fn fetch_signatures(
    release_type: &str,
    version: &str,
) -> anyhow::Result<(Vec<u8>, Vec<(usize, Vec<u8>)>)> {
    let base = release_filename(release_type, version)?;

    // Digest file.
    let dgst_url = format!("{}/{base}.dgst", system::BASE_RELEASE_URL);
    let digest = http_get_bytes(&dgst_url).await?;
    println!("Downloaded {base}.dgst");

    // Signature files (1..=len(SIGNATORIES)); some may be absent.
    let mut sigs = Vec::new();
    for i in 1..=SIGNATORIES.len() {
        let url = format!("{}/{base}.dgst.sig.{i}", system::BASE_RELEASE_URL);
        if !remote_exists(&url).await {
            continue;
        }
        if let Ok(sig) = http_get_bytes(&url).await {
            sigs.push((i, sig));
        }
    }
    println!("Downloaded {} signature file(s)", sigs.len());
    Ok((digest, sigs))
}

/// Verify a quorum of signatories signed the digest file. Returns the count
/// of valid signatures; a release is trusted when it is
/// `>= signatory_quorum()`. `sigs` are `(1-based signatory index, signature)`.
pub fn verify_quorum(digest: &[u8], sigs: &[(usize, Vec<u8>)]) -> anyhow::Result<usize> {
    verify_quorum_with(digest, sigs, &SIGNATORIES)
}

/// [`verify_quorum`] against the given signatory keys (hex). A present but
/// invalid signature fails the check; each signatory counts once.
pub fn verify_quorum_with(
    digest: &[u8],
    sigs: &[(usize, Vec<u8>)],
    signatories: &[&str],
) -> anyhow::Result<usize> {
    let mut valid = BTreeSet::new();
    for (i, sig) in sigs {
        let key = i
            .checked_sub(1)
            .and_then(|j| signatories.get(j))
            .ok_or_else(|| anyhow::anyhow!("no signatory #{i}"))?;
        let pubkey = hex::decode(key).map_err(|e| anyhow::anyhow!("bad signatory {i} hex: {e}"))?;
        if quil_crypto::ed448_verify(&pubkey, digest, sig) {
            valid.insert(*i);
        } else {
            anyhow::bail!("Failed signature check for signatory #{i}");
        }
    }
    Ok(valid.len())
}

/// Parse the sha256 hex digest out of a `.dgst` file (`"SHA3-256 <hex>"` /
/// `"<algo> <hex>"` — the checksum is the first 64 hex chars of field 2).
pub fn digest_checksum(digest_file: &[u8]) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(digest_file);
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 2 || parts[1].len() < 64 {
        anyhow::bail!("invalid digest file format");
    }
    hex::decode(&parts[1][..64]).map_err(|e| anyhow::anyhow!("invalid digest hex: {e}"))
}

/// A downloaded release, held in memory until it verifies.
pub struct Release {
    /// The binary's file name, `type-version-os-arch`.
    pub base: String,
    /// The binary.
    pub bin: Vec<u8>,
    /// The `.dgst` file.
    pub digest: Vec<u8>,
    /// `(1-based signatory index, signature)` of each present `.dgst.sig.N`.
    pub sigs: Vec<(usize, Vec<u8>)>,
}

impl Release {
    /// Check that the binary matches the digest file and that at least
    /// `quorum` of `signatories` signed it. Returns the count of valid
    /// signatures.
    pub fn verify_with(&self, signatories: &[&str], quorum: usize) -> anyhow::Result<usize> {
        let checksum = {
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest(&self.bin).to_vec()
        };
        if checksum != digest_checksum(&self.digest)? {
            anyhow::bail!("downloaded binary does not match its digest");
        }
        let count = verify_quorum_with(&self.digest, &self.sigs, signatories)?;
        if count < quorum {
            anyhow::bail!("signature quorum not met ({count}/{quorum})");
        }
        Ok(count)
    }

    /// Verify the release ([`Release::verify_with`]), then install it into
    /// `dest_dir`: the signatures and digest file first, then the binary
    /// (0755), each by atomic rename. Nothing is written when verification
    /// fails. Returns the installed binary path and the count of valid
    /// signatures.
    pub fn install_with(
        &self,
        dest_dir: &Path,
        signatories: &[&str],
        quorum: usize,
    ) -> anyhow::Result<(PathBuf, usize)> {
        let count = self.verify_with(signatories, quorum)?;
        write_signature_files(dest_dir, &self.base, &self.digest, &self.sigs)?;
        let bin_path = write_atomic(dest_dir, &self.base, &self.bin, 0o755)?;
        Ok((bin_path, count))
    }
}

/// Write a verified release's `.dgst` and `.dgst.sig.N` files into
/// `dest_dir` (created if absent; it must not be a symlink), and remove any
/// other `.dgst.sig.N` file of `base` there, so the set beside the binary is
/// the one that verified.
pub fn write_signature_files(
    dest_dir: &Path,
    base: &str,
    digest: &[u8],
    sigs: &[(usize, Vec<u8>)],
) -> anyhow::Result<()> {
    if base.is_empty() || base.starts_with('.') || base.contains('/') {
        anyhow::bail!("invalid release file name {base:?}");
    }
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e} (root required)", dest_dir.display()))?;
    let meta = std::fs::symlink_metadata(dest_dir)
        .map_err(|e| anyhow::anyhow!("stat {}: {e}", dest_dir.display()))?;
    if !meta.is_dir() {
        anyhow::bail!("{} is not a directory", dest_dir.display());
    }
    for (i, sig) in sigs {
        write_atomic(dest_dir, &format!("{base}.dgst.sig.{i}"), sig, 0o644)?;
    }
    write_atomic(dest_dir, &format!("{base}.dgst"), digest, 0o644)?;
    let kept: BTreeSet<usize> = sigs.iter().map(|(i, _)| *i).collect();
    let prefix = format!("{base}.dgst.sig.");
    for entry in std::fs::read_dir(dest_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let stale = name
            .to_str()
            .and_then(|n| n.strip_prefix(prefix.as_str()))
            .is_some_and(|i| !i.parse::<usize>().is_ok_and(|i| kept.contains(&i)));
        if stale {
            std::fs::remove_file(entry.path())
                .map_err(|e| anyhow::anyhow!("remove {}: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Write `bytes` to `dir/name` with `mode`: into a new private temporary
/// file beside it (created exclusively, 0600), synced, then renamed over
/// `dir/name`, so the name never holds partial content.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> anyhow::Result<PathBuf> {
    use std::io::Write;
    let path = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp-{:016x}", rand::random::<u64>()));
    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, &path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("write {}: {e} (root required)", path.display());
    }
    Ok(path)
}

/// Point `link` at `target`, replacing what `link` held by atomic rename.
#[cfg(unix)]
pub fn switch_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    let name = link.file_name().and_then(|n| n.to_str()).unwrap_or("link");
    let tmp = link.with_file_name(format!(".{name}.tmp-{:016x}", rand::random::<u64>()));
    std::os::unix::fs::symlink(target, &tmp)
        .and_then(|()| std::fs::rename(&tmp, link))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!("symlink {}: {e} (root required)", link.display())
        })
}

/// Point `link` at `target`: unsupported off unix.
#[cfg(not(unix))]
pub fn switch_symlink(_target: &Path, link: &Path) -> anyhow::Result<()> {
    anyhow::bail!("symlink {}: unsupported on this platform", link.display())
}

/// Verify an installed release binary against the `.dgst` and `.dgst.sig.N`
/// files beside it, as [`download_and_install`] leaves them. Returns the
/// count of valid signatures.
pub fn verify_installed(bin_path: &Path) -> anyhow::Result<usize> {
    verify_installed_with(bin_path, &SIGNATORIES, signatory_quorum())
}

/// [`verify_installed`] against the given signatory keys (hex) and quorum.
pub fn verify_installed_with(
    bin_path: &Path,
    signatories: &[&str],
    quorum: usize,
) -> anyhow::Result<usize> {
    let base = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid binary path {}", bin_path.display()))?
        .to_string();
    let bin = read_file(bin_path)?;
    let digest = read_file(&bin_path.with_file_name(format!("{base}.dgst")))?;
    let mut sigs = Vec::new();
    for i in 1..=signatories.len() {
        let path = bin_path.with_file_name(format!("{base}.dgst.sig.{i}"));
        match std::fs::read(&path) {
            Ok(sig) => sigs.push((i, sig)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("read {}: {e}", path.display()),
        }
    }
    Release {
        base,
        bin,
        digest,
        sigs,
    }
    .verify_with(signatories, quorum)
}

/// Whether `symlink` links `bin_path` and that binary verifies against the
/// release files beside it ([`verify_installed_with`]).
pub fn is_linked_and_verified_with(
    bin_path: &Path,
    symlink: &Path,
    signatories: &[&str],
    quorum: usize,
) -> bool {
    std::fs::read_link(symlink).is_ok_and(|t| t.as_path() == bin_path)
        && verify_installed_with(bin_path, signatories, quorum).is_ok()
}

fn read_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))
}

/// Where [`download_and_install`] left a release.
pub struct Installed {
    /// The installed binary.
    pub path: PathBuf,
    /// Whether this call installed it; false when the symlink already
    /// linked this verified release, which was then not downloaded again.
    pub fresh: bool,
}

/// Download a release binary, verify its digest + signatory quorum, install
/// it to `<binary_path>/<type>/<version>/<file>` (0755), and symlink
/// `symlink` to it. Shared by `qclient update` and `node install`/`update`.
/// Install paths require root.
///
/// Refuses a `version` older than the one `symlink` points to unless
/// `allow_downgrade`, and leaves an already linked, verified release as it
/// is.
pub async fn download_and_install(
    release_type: &str,
    version: &str,
    symlink: &Path,
    allow_downgrade: bool,
) -> anyhow::Result<Installed> {
    let base = release_filename(release_type, version)?;
    let installed = linked_version(symlink, release_type);
    check_downgrade(installed.as_deref(), version, allow_downgrade)?;
    let dest_dir = Path::new(system::BINARY_PATH)
        .join(release_type)
        .join(version);
    let current = dest_dir.join(&base);
    if is_linked_and_verified_with(&current, symlink, &SIGNATORIES, signatory_quorum()) {
        println!("{base} is already installed and linked");
        return Ok(Installed {
            path: current,
            fresh: false,
        });
    }

    let bin_url = format!("{}/{base}", system::BASE_RELEASE_URL);
    println!("Downloading {base}...");
    let bin = http_get_bytes(&bin_url).await?;
    let (digest, sigs) = fetch_signatures(release_type, version).await?;
    let release = Release {
        base,
        bin,
        digest,
        sigs,
    };
    let (bin_path, count) = release.install_with(&dest_dir, &SIGNATORIES, signatory_quorum())?;
    println!("Signature quorum met ({count} valid)");

    switch_symlink(&bin_path, symlink)?;
    Ok(Installed {
        path: bin_path,
        fresh: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer;

    #[test]
    fn quorum_threshold_is_seven() {
        assert_eq!(quil_config::signatory_quorum(), 7);
    }

    #[test]
    fn digest_checksum_parses() {
        let f =
            b"SHA3-256 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 filename";
        let sum = digest_checksum(f).unwrap();
        assert_eq!(sum.len(), 32);
        assert_eq!(sum[0], 0xaa);
    }

    const BASE: &str = "node-2.1.0.25-linux-amd64";

    /// Three test signatories with fixed seeds, and their public keys (hex).
    fn signatories() -> (Vec<quil_crypto::Ed448Signer>, Vec<String>) {
        (1u8..=3)
            .map(|seed| {
                let public = quil_crypto::Ed448Signer::derive_public(&[seed; 57]).unwrap();
                let signer = quil_crypto::Ed448Signer::from_bytes(&[seed; 57], &public).unwrap();
                (signer, hex::encode(public))
            })
            .unzip()
    }

    /// A release of `signed` bytes, its digest signed by the signatories at
    /// `indices` (1-based), carrying `bin` as its binary.
    fn release(bin: &[u8], signed: &[u8], indices: &[usize]) -> Release {
        use sha3::{Digest, Sha3_256};
        let (signers, _) = signatories();
        let digest = format!(
            "SHA3-256({BASE})= {}\n",
            hex::encode(Sha3_256::digest(signed))
        );
        let sigs = indices
            .iter()
            .map(|&i| (i, signers[i - 1].sign(digest.as_bytes()).unwrap()))
            .collect();
        Release {
            base: BASE.to_string(),
            bin: bin.to_vec(),
            digest: digest.into_bytes(),
            sigs,
        }
    }

    fn keys(hex_keys: &[String]) -> Vec<&str> {
        hex_keys.iter().map(String::as_str).collect()
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn tampered_release_never_reaches_the_install_dir() {
        let (_, hex_keys) = signatories();
        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("node").join("2.1.0.25");
        let tampered = release(b"tampered", b"signed binary", &[1, 2]);
        let err = tampered
            .install_with(&dest, &keys(&hex_keys), 2)
            .unwrap_err();
        assert!(
            err.to_string().contains("does not match its digest"),
            "{err}"
        );
        assert!(
            !dest.exists(),
            "a failed release must not create its directory"
        );
    }

    #[test]
    fn tampered_release_leaves_the_installed_binary_untouched() {
        let (_, hex_keys) = signatories();
        let keys = keys(&hex_keys);
        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("2.1.0.25");
        let (bin_path, _) = release(b"good", b"good", &[1, 2])
            .install_with(&dest, &keys, 2)
            .unwrap();
        let before = entries(&dest);

        // The same version again, with other bytes under the good digest.
        let tampered = release(b"tampered", b"good", &[1, 2]);
        assert!(tampered.install_with(&dest, &keys, 2).is_err());
        assert_eq!(std::fs::read(&bin_path).unwrap(), b"good");
        assert_eq!(entries(&dest), before, "no temporary or stray file is left");
    }

    #[test]
    fn release_below_quorum_or_with_a_bad_signature_is_not_installed() {
        let (_, hex_keys) = signatories();
        let keys = keys(&hex_keys);
        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("2.1.0.25");

        let under = release(b"bin", b"bin", &[1]);
        let err = under.install_with(&dest, &keys, 2).unwrap_err();
        assert!(err.to_string().contains("quorum not met"), "{err}");

        // Signature 3 is signatory 1's, filed under index 3.
        let mut forged = release(b"bin", b"bin", &[1, 2]);
        forged.sigs.push((3, forged.sigs[0].1.clone()));
        let err = forged.install_with(&dest, &keys, 2).unwrap_err();
        assert!(err.to_string().contains("signatory #3"), "{err}");

        // A signatory counts once, however often its signature is listed.
        let mut repeated = release(b"bin", b"bin", &[1]);
        repeated.sigs.push(repeated.sigs[0].clone());
        assert!(repeated.install_with(&dest, &keys, 2).is_err());
        assert!(!dest.exists());
    }

    #[test]
    fn verified_release_is_installed_with_its_signatures() {
        let (_, hex_keys) = signatories();
        let keys = keys(&hex_keys);
        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("2.1.0.25");
        std::fs::create_dir_all(&dest).unwrap();
        // A signature left by an earlier attempt, outside the verified set.
        std::fs::write(dest.join(format!("{BASE}.dgst.sig.3")), b"junk").unwrap();

        let (bin_path, count) = release(b"bin", b"bin", &[1, 2])
            .install_with(&dest, &keys, 2)
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(bin_path, dest.join(BASE));
        assert_eq!(std::fs::read(&bin_path).unwrap(), b"bin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bin_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        assert_eq!(
            entries(&dest),
            vec![
                BASE.to_string(),
                format!("{BASE}.dgst"),
                format!("{BASE}.dgst.sig.1"),
                format!("{BASE}.dgst.sig.2"),
            ]
        );
        assert_eq!(verify_installed_with(&bin_path, &keys, 2).unwrap(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn linked_verified_release_is_current() {
        let (_, hex_keys) = signatories();
        let keys = keys(&hex_keys);
        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("quilibrium-node");
        let (bin_path, _) = release(b"bin", b"bin", &[1, 2])
            .install_with(&tmp.path().join("2.1.0.25"), &keys, 2)
            .unwrap();
        assert!(!is_linked_and_verified_with(&bin_path, &link, &keys, 2));
        switch_symlink(&bin_path, &link).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), bin_path);
        assert!(is_linked_and_verified_with(&bin_path, &link, &keys, 2));
        std::fs::write(&bin_path, b"changed").unwrap();
        assert!(!is_linked_and_verified_with(&bin_path, &link, &keys, 2));
    }

    #[test]
    fn installed_binary_without_signatures_does_not_verify() {
        let (_, hex_keys) = signatories();
        let tmp = tempfile::TempDir::new().unwrap();
        let bin_path = tmp.path().join(BASE);
        std::fs::write(&bin_path, b"bin").unwrap();
        assert!(verify_installed_with(&bin_path, &keys(&hex_keys), 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn install_dir_symlink_is_refused() {
        let (_, hex_keys) = signatories();
        let tmp = tempfile::TempDir::new().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let dest = tmp.path().join("2.1.0.25");
        std::os::unix::fs::symlink(&elsewhere, &dest).unwrap();
        let ok = release(b"bin", b"bin", &[1, 2]);
        assert!(ok.install_with(&dest, &keys(&hex_keys), 2).is_err());
        assert!(entries(&elsewhere).is_empty());
    }

    #[test]
    fn release_versions_are_digits_and_dots() {
        for ok in ["2.1", "2.1.0.25", "2.1.0.25.87"] {
            assert!(is_release_version(ok), "{ok}");
            assert!(release_filename("node", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "2",
            "latest",
            "..",
            "../../../../etc/cron.d/x",
            "2.1.0.25/../../x",
            "/etc",
            "2..1",
            ".2.1",
            "2.1.",
            "1.2.3.4.5.6",
            "2.1.0.25-rc1",
            "2.1.0.25\n",
        ] {
            assert!(!is_release_version(bad), "{bad:?}");
            assert!(release_filename("node", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn latest_version_must_be_a_release_version() {
        let list = "node-2.1.0.25-linux-amd64\nnode-2.1.0.25-linux-amd64.dgst\n";
        assert_eq!(parse_latest_version(list).unwrap(), "2.1.0.25");
        assert!(parse_latest_version("node-../../../../tmp/x-linux-amd64\n").is_err());
        assert!(parse_latest_version("node-latest-linux-amd64\n").is_err());
        assert!(parse_latest_version("").is_err());
    }

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("2.1.0.9", "2.1.0.25"), Ordering::Less);
        assert_eq!(compare_versions("2.1.0.25", "2.1.0.25"), Ordering::Equal);
        assert_eq!(compare_versions("2.1.0.25", "2.1.0.25.0"), Ordering::Equal);
        assert_eq!(
            compare_versions("2.1.0.25.1", "2.1.0.25"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("2.2", "2.1.9.9"), Ordering::Greater);
    }

    #[test]
    fn downgrade_needs_the_flag() {
        let err = check_downgrade(Some("2.1.0.25"), "2.1.0.24", false).unwrap_err();
        assert!(err.to_string().contains("--allow-downgrade"), "{err}");
        assert!(check_downgrade(Some("2.1.0.25"), "2.1.0.24", true).is_ok());
        // The same version, a newer one, or a fresh install proceed.
        assert!(check_downgrade(Some("2.1.0.25"), "2.1.0.25", false).is_ok());
        assert!(check_downgrade(Some("2.1.0.9"), "2.1.0.25", false).is_ok());
        assert!(check_downgrade(None, "2.1.0.1", false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn linked_version_reads_the_symlink_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("quilibrium-node");
        assert_eq!(linked_version(&link, "node"), None);
        std::os::unix::fs::symlink(
            "/var/quilibrium/bin/node/2.1.0.25/node-2.1.0.25-linux-amd64",
            &link,
        )
        .unwrap();
        assert_eq!(linked_version(&link, "node").as_deref(), Some("2.1.0.25"));
        assert_eq!(linked_version(&link, "qclient"), None);
    }
}
