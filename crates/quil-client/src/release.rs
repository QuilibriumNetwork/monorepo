//! Release download + signatory-quorum verification.
//!
//! Port of `client/utils/download.go` + the signature gate in
//! `client/cmd/root.go`. Binaries and their `.dgst` / `.dgst.sig.N` files
//! come from `https://releases.quilibrium.com`; a release is trusted when a
//! quorum of the [`SIGNATORIES`](quil_config::SIGNATORIES) Ed448 keys sign
//! its digest file.

use std::path::Path;

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
    Ok(resp.bytes().await.map_err(|e| anyhow::anyhow!("read {url}: {e}"))?.to_vec())
}

/// Whether a remote file exists (HEAD-ish via GET status).
pub async fn remote_exists(url: &str) -> bool {
    reqwest::get(url).await.map(|r| r.status().is_success()).unwrap_or(false)
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
    let text = String::from_utf8_lossy(&body);
    let first = text.lines().next().unwrap_or("").trim();
    let parts: Vec<&str> = first.split('-').collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid release filename format: {first:?}");
    }
    Ok(parts[1].to_string())
}

/// The standardized binary filename `type-version-os-arch`.
pub fn release_filename(release_type: &str, version: &str) -> anyhow::Result<String> {
    let (os, arch) = system::system_info()?;
    Ok(format!("{release_type}-{version}-{os}-{arch}"))
}

/// Download the `.dgst` file + each present `.dgst.sig.N` signature for a
/// release binary into `dest_dir`. Returns the digest bytes + the collected
/// `(index, signature)` pairs.
pub async fn download_signatures(
    release_type: &str,
    version: &str,
    dest_dir: &Path,
) -> anyhow::Result<(Vec<u8>, Vec<(usize, Vec<u8>)>)> {
    std::fs::create_dir_all(dest_dir)?;
    let base = release_filename(release_type, version)?;

    // Digest file.
    let dgst_url = format!("{}/{base}.dgst", system::BASE_RELEASE_URL);
    let digest = http_get_bytes(&dgst_url).await?;
    std::fs::write(dest_dir.join(format!("{base}.dgst")), &digest)?;
    println!("Downloaded {base}.dgst");

    // Signature files (1..=len(SIGNATORIES)); some may be absent.
    let mut sigs = Vec::new();
    for i in 1..=SIGNATORIES.len() {
        let url = format!("{}/{base}.dgst.sig.{i}", system::BASE_RELEASE_URL);
        if !remote_exists(&url).await {
            continue;
        }
        if let Ok(sig) = http_get_bytes(&url).await {
            std::fs::write(dest_dir.join(format!("{base}.dgst.sig.{i}")), &sig)?;
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
    let mut count = 0;
    for (i, sig) in sigs {
        let pubkey = hex::decode(SIGNATORIES[i - 1])
            .map_err(|e| anyhow::anyhow!("bad signatory {i} hex: {e}"))?;
        if quil_crypto::ed448_verify(&pubkey, digest, sig) {
            count += 1;
        } else {
            anyhow::bail!("Failed signature check for signatory #{i}");
        }
    }
    Ok(count)
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

/// Download a release binary, verify its digest + signatory quorum, install
/// it to `<binary_path>/<type>/<version>/<file>` (0755), and symlink
/// `symlink` to it. Returns the installed binary path. Shared by `qclient
/// update` and `node install`/`update`. Install paths require root.
pub async fn download_and_install(
    release_type: &str,
    version: &str,
    symlink: &Path,
) -> anyhow::Result<std::path::PathBuf> {
    let base = release_filename(release_type, version)?;
    let dest_dir = Path::new(system::BINARY_PATH).join(release_type).join(version);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e} (root required)", dest_dir.display()))?;

    let bin_url = format!("{}/{base}", system::BASE_RELEASE_URL);
    println!("Downloading {base}...");
    let bin = http_get_bytes(&bin_url).await?;
    let bin_path = dest_dir.join(&base);
    std::fs::write(&bin_path, &bin)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))?;
    }

    let (digest, sigs) = download_signatures(release_type, version, &dest_dir).await?;
    let checksum = {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(&bin).to_vec()
    };
    if checksum != digest_checksum(&digest)? {
        anyhow::bail!("downloaded binary does not match its digest");
    }
    let count = verify_quorum(&digest, &sigs)?;
    if count < signatory_quorum() {
        anyhow::bail!("signature quorum not met ({count}/{})", signatory_quorum());
    }
    println!("Signature quorum met ({count} valid)");

    let _ = std::fs::remove_file(symlink);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&bin_path, symlink)
        .map_err(|e| anyhow::anyhow!("symlink {}: {e} (root required)", symlink.display()))?;
    Ok(bin_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_threshold_is_seven() {
        assert_eq!(quil_config::signatory_quorum(), 7);
    }

    #[test]
    fn digest_checksum_parses() {
        let f = b"SHA3-256 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 filename";
        let sum = digest_checksum(f).unwrap();
        assert_eq!(sum.len(), 32);
        assert_eq!(sum[0], 0xaa);
    }
}
