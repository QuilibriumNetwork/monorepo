//! Where releases come from, and whose signatures make one trusted.
//!
//! The official source ([`ReleaseSource::official`]) is
//! `https://releases.quilibrium.com`, trusted when a quorum of the
//! [`SIGNATORIES`] sign a release. An operator may opt into another
//! source: an `https://` base URL serving the official server's layout
//! (`<base>/release`, `<base>/qclient-release`, `<base>/<file>`,
//! `<base>/<file>.dgst` and `<base>/<file>.dgst.sig.<i>`) and the Ed448
//! public keys whose signatures make its releases trusted. A release from
//! it is verified by those keys alone, never together with the official
//! signatories: the i-th key given (1-based) verifies `<file>.dgst.sig.<i>`,
//! and its quorum (default 1) is how many of them must sign.
//!
//! `--release-source` on `node auto-update enable` is stored in
//! `<install root>/release-source.yaml`, which the auto-update job and
//! every later install naming no source then use. The file decides what
//! root installs, so it is used only while root owns it, and the
//! directories above it, and no one else can write them
//! ([`quil_config::release_source`], whose rules the node's and qclient's
//! startup checks apply too). Those checks start a release the official
//! signatories do not sign only under the stored source, so an install
//! from a custom source links a release only once that check, run on it,
//! starts it, and the stored source is not changed or removed while a
//! linked release starts only under it. On `qclient
//! update`, `node install` and `node update` the flag picks where that
//! run downloads from.

use std::path::{Path, PathBuf};

use quil_config::release_source::{
    check_release_keys, load_release_source_at, owner_and_mode, ReleaseSourceFile,
};
use quil_config::{signatory_quorum, SIGNATORIES};
use quil_crypto::release_check::{verify_release, verify_release_signatures_quorum, SelfCheck};

use crate::system;

pub use quil_config::release_source::Stat;

/// The `--release-source` value naming the official source.
pub const OFFICIAL: &str = "official";

/// A release source: its base URL, its signers' keys (hex) and the count
/// of them that must sign a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseSource {
    base: String,
    keys: Vec<String>,
    quorum: usize,
    custom: bool,
    https_only: bool,
}

impl ReleaseSource {
    /// `https://releases.quilibrium.com`, trusted by a quorum of the
    /// [`SIGNATORIES`].
    pub fn official() -> Self {
        Self {
            base: system::BASE_RELEASE_URL.to_string(),
            keys: SIGNATORIES.iter().map(|k| k.to_string()).collect(),
            quorum: signatory_quorum(),
            custom: false,
            https_only: false,
        }
    }

    /// A source at the `https://` base `url`, trusted when `quorum`
    /// (default 1) of the Ed448 public `keys` (hex) sign a release. Every
    /// fetch from it, redirects included, is over HTTPS.
    pub fn custom(url: &str, keys: &[String], quorum: Option<usize>) -> anyhow::Result<Self> {
        let base = check_base_url(url)?;
        if keys.is_empty() {
            anyhow::bail!(
                "release source {base} names no signer: give its Ed448 public key (hex) with \
                 --release-key"
            );
        }
        let (checked, quorum) = check_release_keys(keys, quorum).map_err(anyhow::Error::msg)?;
        Ok(Self {
            base,
            keys: checked,
            quorum,
            custom: true,
            https_only: true,
        })
    }

    /// The URL of `file` at this source.
    pub fn url(&self, file: &str) -> String {
        format!("{}/{file}", self.base)
    }

    /// The signers' public keys (hex); the i-th signs `.dgst.sig.<i+1>`.
    pub fn keys(&self) -> Vec<&str> {
        self.keys.iter().map(String::as_str).collect()
    }

    /// How many of [`Self::keys`] must sign a release.
    pub fn quorum(&self) -> usize {
        self.quorum
    }

    /// Whether this is a source other than the official one.
    pub fn is_custom(&self) -> bool {
        self.custom
    }

    /// Whether fetches from this source, redirects included, must use
    /// HTTPS.
    pub(crate) fn https_only(&self) -> bool {
        self.https_only
    }

    /// The source in one line, for output.
    pub fn describe(&self) -> String {
        if self.custom {
            format!(
                "{} ({} key(s), quorum {})",
                self.base,
                self.keys.len(),
                self.quorum
            )
        } else {
            format!("{} (official signatories)", self.base)
        }
    }
}

/// `url` as a release source base, without a trailing `/`: an `https://`
/// URL with a host and no credentials, query or fragment.
fn check_base_url(url: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|e| anyhow::anyhow!("release source {url:?} is not a URL: {e}"))?;
    if parsed.scheme() != "https" {
        anyhow::bail!(
            "refusing release source {url:?}: only an https:// URL is accepted, so no one on \
             the path can change what it serves"
        );
    }
    let plain = parsed.host_str().is_some_and(|h| !h.is_empty())
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    if !plain {
        anyhow::bail!(
            "release source {url:?} must be a plain https://host/path base URL, without \
             credentials, query or fragment"
        );
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// The release source flags of the commands that install releases.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ReleaseSourceArgs {
    /// Install from this https:// base URL instead of
    /// https://releases.quilibrium.com, trusting only the --release-key
    /// signers (`official` names the official source).
    ///
    /// The source serves the official server's layout: `release` and
    /// `qclient-release` (the latest file name first), each
    /// `<type>-<version>-<os>-<arch>` file, its `.dgst` (`SHA3-256(<file
    /// name>)= <hex>`) and `.dgst.sig.<i>`, the Ed448 signature of the
    /// `.dgst` file by the i-th --release-key. Redirects are followed over
    /// HTTPS only. `node auto-update enable` stores the source for the
    /// auto-update job and later installs; `official` removes it. Other
    /// commands download from it for that run only, and link a release the
    /// official signatories do not sign only when the stored source
    /// verifies it, as the node and qclient start only such a release.
    #[arg(long, value_name = "URL|official")]
    pub release_source: Option<String>,
    /// An Ed448 public key (hex) of the release source's signers; repeat
    /// for each. The i-th key, counting from 1, verifies
    /// `<file>.dgst.sig.<i>`.
    #[arg(long = "release-key", value_name = "HEX", requires = "release_source")]
    pub release_keys: Vec<String>,
    /// How many of the --release-key signers must sign a release (default
    /// 1).
    #[arg(long, value_name = "N", requires = "release_source")]
    pub release_quorum: Option<usize>,
}

impl ReleaseSourceArgs {
    /// The source these flags name, if they name one.
    pub fn named(&self) -> anyhow::Result<Option<ReleaseSource>> {
        match self.release_source.as_deref() {
            None if self.release_keys.is_empty() && self.release_quorum.is_none() => Ok(None),
            None => anyhow::bail!("--release-key and --release-quorum need --release-source"),
            Some(OFFICIAL) if self.release_keys.is_empty() && self.release_quorum.is_none() => {
                Ok(Some(ReleaseSource::official()))
            }
            Some(OFFICIAL) => anyhow::bail!(
                "the official source takes its own signatories: drop --release-key and \
                 --release-quorum"
            ),
            Some(url) => Ok(Some(ReleaseSource::custom(
                url,
                &self.release_keys,
                self.release_quorum,
            )?)),
        }
    }
}

/// The source an install uses: the one its flags name, else the stored one
/// (read only then), else the official one.
pub fn resolve(
    named: Option<ReleaseSource>,
    stored: impl FnOnce() -> anyhow::Result<Option<ReleaseSource>>,
) -> anyhow::Result<ReleaseSource> {
    match named {
        Some(source) => Ok(source),
        None => Ok(stored()?.unwrap_or_else(ReleaseSource::official)),
    }
}

/// [`resolve`] for this host: the flags' source, else the stored one.
pub fn active(args: &ReleaseSourceArgs) -> anyhow::Result<ReleaseSource> {
    resolve(args.named()?, load_stored)
}

/// The source stored on this host ([`system::release_source_path`]).
pub fn load_stored() -> anyhow::Result<Option<ReleaseSource>> {
    load_stored_at(&system::release_source_path(), &owner_and_mode)
}

/// The source stored at `path`, or `None` when there is no file. Fails
/// unless root owns the file and each directory above it and no one else
/// can write them (`stat` reads each `(owner uid, mode)`): whoever can
/// write the file chooses what root installs.
pub fn load_stored_at(path: &Path, stat: Stat) -> anyhow::Result<Option<ReleaseSource>> {
    let Some(stored) = load_release_source_at(path, stat).map_err(anyhow::Error::msg)? else {
        return Ok(None);
    };
    let source = ReleaseSource::custom(&stored.url, &stored.keys, Some(stored.quorum))
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(Some(source))
}

/// What `node auto-update enable` does with the source its flags name:
/// store a custom source at `path` (0644), remove the stored one for the
/// official source, keep it when they name none. Returns the source the
/// auto-update job then uses. Refuses a change that would stop a release
/// linked at one of `links` from starting ([`check_linked_still_start`]),
/// and a file its readers would refuse is never written.
pub fn store_at(
    path: &Path,
    named: Option<ReleaseSource>,
    stat: Stat,
    links: &[PathBuf],
) -> anyhow::Result<ReleaseSource> {
    if let Some(named) = named {
        let next = named.is_custom().then_some(named);
        check_linked_still_start(path, next.as_ref(), stat, links)?;
        match next {
            Some(source) => write_checked(path, &source, stat)?,
            None => match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    anyhow::bail!("remove {}: {e} (root required)", path.display())
                }
                _ => {}
            },
        }
    }
    resolve(None, || load_stored_at(path, stat))
}

/// [`store_at`] on this host, keeping the releases at [`guarded_links`]
/// starting.
pub fn store(named: Option<ReleaseSource>) -> anyhow::Result<ReleaseSource> {
    store_at(
        &system::release_source_path(),
        named,
        &owner_and_mode,
        &guarded_links(),
    )
}

/// The links whose releases must keep starting across a source change:
/// the node's, qclient's and the qclient the auto-update job runs
/// (`<install root>/current`).
pub fn guarded_links() -> Vec<PathBuf> {
    vec![
        system::default_node_symlink_path(),
        system::default_qclient_symlink_path(),
        system::client_data_path().join(system::QCLIENT_ROOT_LINK),
    ]
}

/// Refuse to change the source stored at `path` to `next` (`None`: the
/// official source alone) while a release linked at one of `links` starts
/// only under the stored one, by the startup check itself
/// ([`verify_release`]): after the change that check would refuse it,
/// stopping the node at its next start and qclient at its next command.
/// Official releases start under any source.
fn check_linked_still_start(
    path: &Path,
    next: Option<&ReleaseSource>,
    stat: Stat,
    links: &[PathBuf],
) -> anyhow::Result<()> {
    let Ok(file) = std::fs::canonicalize(path) else {
        return Ok(()); // nothing stored: nothing starts under it
    };
    for link in links {
        let Ok(bin) = std::fs::canonicalize(link) else {
            continue;
        };
        let under = match verify_release(&bin, &SIGNATORIES, stat) {
            Ok(SelfCheck::VerifiedBySource { file: under, .. }) => under,
            _ => continue, // official, or not started now either
        };
        if std::fs::canonicalize(&under).ok().as_ref() != Some(&file) {
            continue;
        }
        let starts_next = next.is_some_and(|next| {
            verify_release_signatures_quorum(&bin, &next.keys(), next.quorum()).is_ok()
        });
        if starts_next {
            continue;
        }
        anyhow::bail!(
            "refusing to {} the release source in {}: {} links {}, which starts only under it, \
             so the node and qclient check would refuse it after the change; first install \
             official releases, which start under any source ('qclient node update \
             --release-source official --allow-downgrade' and 'qclient update \
             --release-source official --allow-downgrade'), then run this again",
            if next.is_some() { "replace" } else { "remove" },
            path.display(),
            link.display(),
            bin.display()
        );
    }
    Ok(())
}

/// Write `source` to `path` (0644), by atomic rename of a file beside it
/// that first passes the checks its readers apply ([`load_stored_at`]): a
/// stored file they refuse would stop every later install and refuse
/// every release it was meant to start.
fn write_checked(path: &Path, source: &ReleaseSource, stat: Stat) -> anyhow::Result<()> {
    use std::io::Write;
    let text = serde_yaml::to_string(&ReleaseSourceFile {
        url: source.base.clone(),
        keys: source.keys.clone(),
        quorum: Some(source.quorum),
    })?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.new-{:016x}", rand::random::<u64>()));
    let written = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("write {}: {e} (root required)", path.display()))?;
        file.write_all(text.as_bytes())?;
        // Whatever the umask: a group- or world-writable file is refused.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        file.sync_all()?;
        let read = load_stored_at(&tmp, stat)?;
        if read.as_ref() != Some(source) {
            anyhow::bail!("{} reads back as {read:?}", path.display());
        }
        std::fs::rename(&tmp, path)
            .map_err(|e| anyhow::anyhow!("write {}: {e} (root required)", path.display()))
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("not storing the release source in {}: {e}", path.display());
    }
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release;
    use quil_types::crypto::Signer;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Test signers with fixed seeds, and their public keys (hex).
    fn signers(seeds: &[u8]) -> (Vec<quil_crypto::Ed448Signer>, Vec<String>) {
        seeds
            .iter()
            .map(|&seed| {
                let public = quil_crypto::Ed448Signer::derive_public(&[seed; 57]).unwrap();
                let signer = quil_crypto::Ed448Signer::from_bytes(&[seed; 57], &public).unwrap();
                (signer, hex::encode(public))
            })
            .unzip()
    }

    /// A served release: the files a source holds for one node binary.
    struct Served {
        base: String,
        files: HashMap<String, Vec<u8>>,
    }

    /// The node release 2.1.0.25 for this platform, its `.dgst` labelled
    /// `label` (the file's own name when `None`) and signed by `signers`
    /// as `.dgst.sig.<index>`.
    fn served(label: Option<&str>, signed: &[(usize, &quil_crypto::Ed448Signer)]) -> Served {
        served_with(label, " ", signed)
    }

    /// [`served`] with `sep` between the `.dgst` label and checksum.
    fn served_with(
        label: Option<&str>,
        sep: &str,
        signed: &[(usize, &quil_crypto::Ed448Signer)],
    ) -> Served {
        use sha3::{Digest, Sha3_256};
        let base = release::release_filename(system::RELEASE_TYPE_NODE, "2.1.0.25").unwrap();
        let bin = b"node release".to_vec();
        let digest = format!(
            "SHA3-256({})={sep}{}\n",
            label.unwrap_or(&base),
            hex::encode(Sha3_256::digest(&bin))
        );
        let mut files = HashMap::new();
        files.insert("release".to_string(), format!("{base}\n").into_bytes());
        for (i, signer) in signed {
            files.insert(
                format!("{base}.dgst.sig.{i}"),
                signer.sign(digest.as_bytes()).unwrap(),
            );
        }
        files.insert(format!("{base}.dgst"), digest.into_bytes());
        files.insert(base.clone(), bin);
        Served { base, files }
    }

    /// Serve `files` over plain HTTP on loopback; returns the base URL.
    async fn serve(files: HashMap<String, Vec<u8>>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    return;
                };
                let files = files.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req);
                    let path = line.split_whitespace().nth(1).unwrap_or("/");
                    let (status, body) = match files.get(path.trim_start_matches('/')) {
                        Some(body) => ("200 OK", body.clone()),
                        None => ("404 Not Found", Vec::new()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = conn.write_all(head.as_bytes()).await;
                    let _ = conn.write_all(&body).await;
                });
            }
        });
        base
    }

    /// A custom source at the loopback `base`, over plain HTTP, which only
    /// a test builds: [`ReleaseSource::custom`] takes `https://` alone.
    fn loopback_source(base: String, keys: &[String], quorum: usize) -> ReleaseSource {
        ReleaseSource {
            base,
            keys: keys.to_vec(),
            quorum,
            custom: true,
            https_only: false,
        }
    }

    /// Install `served` from a loopback source trusting `keys` and
    /// `quorum`, into a fresh install tree whose stored release source
    /// trusts `stored` (none stored for `None`) with quorum 1, so the
    /// signature checks are the install's own, under `keys` and `quorum`;
    /// returns the result and the tree's root, which holds nothing unless
    /// the install verified.
    async fn install(
        served: &Served,
        keys: &[String],
        quorum: usize,
        stored: Option<&[String]>,
    ) -> (anyhow::Result<release::Installed>, tempfile::TempDir) {
        let source = loopback_source(serve(served.files.clone()).await, keys, quorum);
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        if let Some(stored) = stored {
            let stored = ReleaseSource::custom("https://releases.example.org", stored, None);
            let path = root.join(quil_config::release_source::RELEASE_SOURCE_FILE);
            store_at(&path, Some(stored.unwrap()), &root_only, &[]).unwrap();
        }
        let link = root.join("quilibrium-node");
        let version = release::get_latest_version(&source, system::RELEASE_TYPE_NODE)
            .await
            .unwrap();
        assert_eq!(version, "2.1.0.25");
        let result = release::download_and_install_in(
            &source,
            &root.join("bin"),
            system::RELEASE_TYPE_NODE,
            &version,
            &link,
            false,
            &root_only,
        )
        .await;
        (result, tmp)
    }

    /// A release a custom source serves, signed by its key, installs and
    /// links when that source is stored, and stays verifiable under that
    /// key.
    #[tokio::test]
    async fn custom_source_release_installs_with_its_key() {
        let (signer, keys) = signers(&[7]);
        let served = served(None, &[(1, &signer[0])]);
        let (result, tmp) = install(&served, &keys, 1, Some(&keys)).await;
        let installed = result.expect("custom_installed: a release signed by the source's key");
        assert!(installed.fresh);
        let bin = tmp.path().join("bin/node/2.1.0.25").join(&served.base);
        assert_eq!(installed.path, bin);
        assert_eq!(
            std::fs::read_link(tmp.path().join("quilibrium-node")).unwrap(),
            bin
        );
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        assert_eq!(release::verify_installed_with(&bin, &keys, 1).unwrap(), 1);
    }

    /// Signed by a key the source does not name: refused, nothing written.
    #[tokio::test]
    async fn custom_source_release_signed_by_another_key_is_refused() {
        let (signer, _) = signers(&[8]);
        let (_, keys) = signers(&[7]);
        let served = served(None, &[(1, &signer[0])]);
        let (result, tmp) = install(&served, &keys, 1, Some(&keys)).await;
        let err = match result {
            Ok(_) => panic!("wrong_key_installed: a release signed by another key"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("Failed signature check"),
            "wrong_key_installed: {err}"
        );
        assert!(!tmp.path().join("bin").exists(), "nothing is written");
    }

    /// One valid signature of a source needing two: refused.
    #[tokio::test]
    async fn custom_source_release_below_its_quorum_is_refused() {
        let (signer, keys) = signers(&[7, 9]);
        let served = served(None, &[(1, &signer[0])]);
        let (result, tmp) = install(&served, &keys, 2, Some(&keys)).await;
        let err = match result {
            Ok(_) => panic!("below_quorum_installed: 1 of the 2 signatures needed"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("quorum not met (1/2)"),
            "below_quorum_installed: {err}"
        );
        assert!(!tmp.path().join("bin").exists(), "nothing is written");
    }

    /// A digest signed for another file (an older release under the new
    /// name): refused by qclient's own label check, before staging.
    #[tokio::test]
    async fn custom_source_release_with_a_mislabeled_digest_is_refused() {
        let (signer, keys) = signers(&[7]);
        let other = release::release_filename(system::RELEASE_TYPE_NODE, "2.1.0.24").unwrap();
        let served = served(Some(&other), &[(1, &signer[0])]);
        let (result, tmp) = install(&served, &keys, 1, Some(&keys)).await;
        let err = match result {
            Ok(_) => panic!("mislabeled_installed: a digest signed for {other}"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("refusing a release served under another name"),
            "mislabeled_installed: {err}"
        );
        assert!(!tmp.path().join("bin").exists(), "nothing is written");
    }

    /// A release signed only by a custom source's key, which the source
    /// stored in the install root does not verify (none stored, or another
    /// key), is not installed: the node and qclient check would refuse it
    /// at their next start. Nothing is written or linked.
    #[tokio::test]
    async fn custom_release_the_stored_source_does_not_verify_is_not_linked() {
        let (signer, keys) = signers(&[7]);
        let (_, other) = signers(&[8]);
        let served = served(None, &[(1, &signer[0])]);
        for stored in [None, Some(other.as_slice())] {
            let (result, tmp) = install(&served, &keys, 1, stored).await;
            let err = match result {
                Ok(i) => panic!(
                    "unstartable_linked: {} under stored {stored:?}",
                    i.path.display()
                ),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("auto-update enable --release-source"), "{err}");
            assert_nothing_installed(tmp.path());
        }
    }

    /// Every path under `dir`, for a failure message.
    fn paths_under(dir: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path.clone());
                }
                paths.push(path);
            }
        }
        paths
    }

    /// Nothing of a refused install is left in the tree at `root`: no
    /// release or staging directory, nor the directories made for them, and
    /// no link.
    fn assert_nothing_installed(root: &Path) {
        assert!(
            !root.join("bin").exists(),
            "refused_install_left: {:?}",
            paths_under(&root.join("bin"))
        );
        let link = root.join("quilibrium-node");
        assert!(
            std::fs::symlink_metadata(link).is_err(),
            "nothing is linked"
        );
    }

    /// A `.dgst` the client reads but the startup check does not (a tab
    /// between label and checksum), signed by the stored source's key, is
    /// not installed: the check that refuses it at start, run on the
    /// staged release, refuses it first.
    #[tokio::test]
    async fn custom_release_the_startup_check_refuses_is_not_linked() {
        let (signer, keys) = signers(&[7]);
        let served = served_with(None, "\t", &[(1, &signer[0])]);
        let (result, tmp) = install(&served, &keys, 1, Some(&keys)).await;
        let err = match result {
            Ok(i) => panic!("unstartable_linked: {} with a tab", i.path.display()),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("would not start it"), "{err}");
        assert_nothing_installed(tmp.path());
    }

    /// The links a source change keeps starting include the qclient the
    /// auto-update job runs, beside the node and qclient links.
    #[test]
    fn source_changes_guard_the_job_qclient() {
        let links = guarded_links();
        let job = system::client_data_path().join(system::QCLIENT_ROOT_LINK);
        assert!(links.contains(&job), "root_link_unguarded: {links:?}");
        assert!(links.contains(&system::default_node_symlink_path()));
        assert!(links.contains(&system::default_qclient_symlink_path()));
    }

    /// An http:// base is refused, and a parsed source fetches nothing over
    /// plain HTTP (reqwest applies this to every redirect too).
    #[tokio::test]
    async fn http_release_source_is_refused() {
        let (_, keys) = signers(&[7]);
        for url in [
            "http://releases.example.org",
            "HTTP://releases.example.org/x",
        ] {
            if let Ok(source) = ReleaseSource::custom(url, &keys, None) {
                panic!("http_base_accepted: {url} as {source:?}");
            }
        }
        let source = ReleaseSource::custom("https://releases.example.org/", &keys, None).unwrap();
        assert_eq!(
            source.url("release"),
            "https://releases.example.org/release"
        );
        let plain = serve(served(None, &[]).files).await;
        let err = match release::get_latest_version(
            &ReleaseSource {
                base: plain.clone(),
                ..source
            },
            system::RELEASE_TYPE_NODE,
        )
        .await
        {
            Ok(v) => panic!("plain_http_fetched: {v} from {plain}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("GET"), "{err}");
    }

    /// Flags that would weaken the source's trust are refused.
    #[test]
    fn release_source_flags_are_checked() {
        let (_, keys) = signers(&[7, 9]);
        let url = "https://releases.example.org";
        let custom = |keys: &[String], quorum| ReleaseSource::custom(url, keys, quorum);
        let repeated = [keys[0].clone(), keys[0].to_uppercase()];
        if custom(&repeated, Some(2)).is_ok() {
            panic!("repeated_key_accepted: one signer listed twice meets quorum 2");
        }
        assert!(custom(&[], None).is_err(), "no key");
        assert!(custom(&keys, Some(0)).is_err(), "quorum 0");
        assert!(custom(&keys, Some(3)).is_err(), "quorum over the keys");
        assert!(
            custom(&[keys[0][..112].to_string()], None).is_err(),
            "short key"
        );
        assert!(custom(&["zz".repeat(57)], None).is_err(), "not hex");
        for bad in [
            "https://user:pw@releases.example.org",
            "https://releases.example.org/?a=b",
            "https://releases.example.org/#x",
            "releases.example.org",
        ] {
            assert!(ReleaseSource::custom(bad, &keys, None).is_err(), "{bad}");
        }
        let ok = custom(&keys, None).unwrap();
        assert_eq!((ok.quorum(), ok.keys().len()), (1, 2));

        let args = |source: Option<&str>, keys: Vec<String>, quorum| ReleaseSourceArgs {
            release_source: source.map(str::to_string),
            release_keys: keys,
            release_quorum: quorum,
        };
        assert_eq!(args(None, vec![], None).named().unwrap(), None);
        assert!(args(None, keys.clone(), None).named().is_err());
        assert!(args(Some(OFFICIAL), keys.clone(), None).named().is_err());
        assert_eq!(
            args(Some(OFFICIAL), vec![], None).named().unwrap(),
            Some(ReleaseSource::official())
        );
        assert_eq!(
            args(Some(url), keys.clone(), Some(2)).named().unwrap(),
            Some(custom(&keys, Some(2)).unwrap())
        );
    }

    /// No flags and no stored file: the official source, as before.
    #[test]
    fn official_source_is_the_default() {
        let source = resolve(None, || Ok(None)).unwrap();
        assert_eq!(source, ReleaseSource::official());
        assert_eq!(
            source.url("release"),
            format!("{}/release", system::BASE_RELEASE_URL)
        );
        assert_eq!(source.keys(), SIGNATORIES.to_vec());
        assert_eq!(
            source.quorum(),
            signatory_quorum(),
            "official_quorum changed"
        );
        assert!(!source.is_custom() && !source.https_only());
    }

    /// Every path root-owned and writable only by root.
    fn root_only(_: &Path) -> std::io::Result<(u32, u32)> {
        Ok((0, 0o40755))
    }

    /// `auto-update enable --release-source` stores the source; the job,
    /// naming none, then uses it; `official` removes it.
    #[test]
    fn auto_update_source_round_trips_for_the_job() {
        let (_, keys) = signers(&[7, 9]);
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("quilibrium").join("release-source.yaml");
        let source = ReleaseSource::custom(
            "https://github.com/o/r/releases/latest/download",
            &keys,
            Some(2),
        )
        .unwrap();

        let stored = store_at(&path, Some(source.clone()), &root_only, &[]).unwrap();
        assert_eq!(
            stored, source,
            "stored_source_lost: enable stored {stored:?}"
        );
        let job = resolve(None, || load_stored_at(&path, &root_only)).unwrap();
        assert_eq!(job, source, "stored_source_lost: the job uses {job:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644);
        }
        // Enable again naming no source: kept. A one-off flag wins.
        assert_eq!(store_at(&path, None, &root_only, &[]).unwrap(), source);
        let once = ReleaseSource::official();
        assert_eq!(
            resolve(Some(once.clone()), || panic!("not read")).unwrap(),
            once
        );

        let back = store_at(&path, Some(ReleaseSource::official()), &root_only, &[]).unwrap();
        assert_eq!(back, ReleaseSource::official());
        assert!(!path.exists());
        assert_eq!(load_stored_at(&path, &root_only).unwrap(), None);
    }

    /// A stored source that another user owns or can write, or that sits
    /// in such a directory, is refused, not used.
    #[test]
    fn stored_source_others_can_write_is_refused() {
        let (_, keys) = signers(&[7]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("quilibrium");
        let path = dir.join("release-source.yaml");
        let source = ReleaseSource::custom("https://releases.example.org", &keys, None).unwrap();
        store_at(&path, Some(source.clone()), &root_only, &[]).unwrap();

        let with = |set: &[(PathBuf, (u32, u32))]| {
            let facts: HashMap<PathBuf, (u32, u32)> = set.iter().cloned().collect();
            load_stored_at(&path, &move |p: &Path| {
                Ok(facts.get(p).copied().unwrap_or((0, 0o40755)))
            })
        };
        assert_eq!(with(&[]).unwrap(), Some(source));
        for (what, set) in [
            (
                "file owned by uid 1000",
                vec![(path.clone(), (1000, 0o100644))],
            ),
            ("group-writable file", vec![(path.clone(), (0, 0o100664))]),
            (
                "world-writable directory",
                vec![(dir.clone(), (0, 0o40777))],
            ),
        ] {
            match with(&set) {
                Ok(s) => panic!("writable_source_used: {what}: {s:?}"),
                Err(e) => assert!(e.to_string().contains("writable only by root"), "{e}"),
            }
        }
    }

    /// A node release signed by `signer` (public key `pk`) as
    /// `.dgst.sig.1`, installed in the install root `root`; returns its
    /// path.
    fn installed_node(root: &Path, signer: &quil_crypto::Ed448Signer, pk: &str) -> PathBuf {
        use sha3::{Digest, Sha3_256};
        let base = "node-2.1.0.25-linux-amd64";
        let digest = format!(
            "SHA3-256({base})= {}\n",
            hex::encode(Sha3_256::digest(b"bin"))
        );
        let served = release::Release {
            base: base.to_string(),
            bin: b"bin".to_vec(),
            sigs: vec![(1, signer.sign(digest.as_bytes()).unwrap())],
            digest: digest.into_bytes(),
        };
        let dest = root.join("bin").join("node").join("2.1.0.25");
        served.install_with(&dest, &[pk], 1).unwrap().0
    }

    /// The stored source is not replaced or removed while a linked release
    /// starts only under it, which the node and qclient check would then
    /// refuse; a source that still verifies it is stored, and a release
    /// installed in another root does not hold the source.
    #[cfg(unix)]
    #[test]
    fn a_source_change_that_strands_a_linked_release_is_refused() {
        let (signer, keys) = signers(&[7]);
        let (_, other) = signers(&[8]);
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap().join("q");
        let path = root.join(quil_config::release_source::RELEASE_SOURCE_FILE);
        let url = "https://releases.example.org";
        let source = ReleaseSource::custom(url, &keys, None).unwrap();
        store_at(&path, Some(source.clone()), &root_only, &[]).unwrap();
        let bin = installed_node(&root, &signer[0], &keys[0]);
        let link = root.join("quilibrium-node");
        std::os::unix::fs::symlink(&bin, &link).unwrap();
        let links = [link.clone()];

        let rotated = ReleaseSource::custom(url, &other, None).unwrap();
        for next in [ReleaseSource::official(), rotated] {
            match store_at(&path, Some(next.clone()), &root_only, &links) {
                Ok(s) => panic!(
                    "linked_stranded: {s:?} stored while {} starts only under {source:?}",
                    bin.display()
                ),
                Err(e) => assert!(e.to_string().contains("starts only under it"), "{e}"),
            }
            assert_eq!(
                load_stored_at(&path, &root_only).unwrap(),
                Some(source.clone()),
                "the stored source is kept"
            );
        }

        let both = [keys[0].clone(), other[0].clone()];
        let mirror = ReleaseSource::custom("https://mirror.example.org", &both, None).unwrap();
        let stored = store_at(&path, Some(mirror.clone()), &root_only, &links).unwrap();
        assert_eq!(stored, mirror, "a source that verifies the linked release");

        let other_root = std::fs::canonicalize(tmp.path()).unwrap().join("other");
        let elsewhere = installed_node(&other_root, &signer[0], &keys[0]);
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let back = store_at(&path, Some(ReleaseSource::official()), &root_only, &links).unwrap();
        assert_eq!(back, ReleaseSource::official());
        assert!(!path.exists());
    }

    /// A stored file the startup check uses though qclient refuses its URL
    /// (hand-edited to http://) still holds the source while a linked
    /// release starts only under it.
    #[cfg(unix)]
    #[test]
    fn a_hand_edited_source_still_holds_its_linked_release() {
        let (signer, keys) = signers(&[7]);
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap().join("q");
        let path = root.join(quil_config::release_source::RELEASE_SOURCE_FILE);
        let bin = installed_node(&root, &signer[0], &keys[0]);
        std::fs::write(
            &path,
            format!("url: http://releases.example.org\nkeys:\n- {}\n", keys[0]),
        )
        .unwrap();
        assert!(
            load_stored_at(&path, &root_only).is_err(),
            "qclient refuses it"
        );
        let link = root.join("quilibrium-node");
        std::os::unix::fs::symlink(&bin, &link).unwrap();
        match store_at(&path, Some(ReleaseSource::official()), &root_only, &[link]) {
            Ok(s) => panic!(
                "url_stranded: {s:?} while {} starts under it",
                bin.display()
            ),
            Err(e) => assert!(e.to_string().contains("starts only under it"), "{e}"),
        }
        assert!(path.exists(), "the stored source is kept");
    }

    /// A source its readers would refuse (here, in a group-writable
    /// directory) is not written, nor does it replace the stored one, and
    /// no temporary file is left.
    #[test]
    fn a_source_its_readers_would_refuse_is_not_stored() {
        let (_, keys) = signers(&[7]);
        let (_, other) = signers(&[8]);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap().join("q");
        let path = dir.join(quil_config::release_source::RELEASE_SOURCE_FILE);
        let open = dir.clone();
        let group_writable = move |p: &Path| -> std::io::Result<(u32, u32)> {
            Ok(if p == open {
                (0, 0o40775)
            } else {
                (0, 0o40755)
            })
        };
        let url = "https://releases.example.org";
        let first = ReleaseSource::custom(url, &keys, None).unwrap();
        if let Ok(s) = store_at(&path, Some(first.clone()), &group_writable, &[]) {
            panic!("refused_store_written: {s:?}");
        }
        assert!(!path.exists(), "refused_store_written: {}", path.display());
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(left.is_empty(), "refused_store_written: {left:?}");

        store_at(&path, Some(first.clone()), &root_only, &[]).unwrap();
        let second = ReleaseSource::custom(url, &other, None).unwrap();
        assert!(store_at(&path, Some(second), &group_writable, &[]).is_err());
        assert_eq!(
            load_stored_at(&path, &root_only).unwrap(),
            Some(first),
            "refused_store_written: the stored source was replaced"
        );
    }

    /// A stored source reached through a linked directory is checked in the
    /// directory the link names, not the link's own.
    #[cfg(unix)]
    #[test]
    fn a_stored_source_behind_a_link_checks_its_real_directory() {
        let (_, keys) = signers(&[7]);
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let linked = root.join("q");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let path = linked.join(quil_config::release_source::RELEASE_SOURCE_FILE);
        let source = ReleaseSource::custom("https://releases.example.org", &keys, None).unwrap();
        store_at(&path, Some(source.clone()), &root_only, &[]).unwrap();

        let open = real.clone();
        let world_writable_target = move |p: &Path| -> std::io::Result<(u32, u32)> {
            Ok(if p == open {
                (0, 0o40777)
            } else {
                (0, 0o40755)
            })
        };
        match load_stored_at(&path, &world_writable_target) {
            Ok(s) => panic!("link_parent_unchecked: {s:?} through {}", linked.display()),
            Err(e) => {
                let e = e.to_string();
                assert!(e.contains("writable only by root"), "{e}");
                assert!(e.contains(&real.display().to_string()), "{e}");
            }
        }
        assert_eq!(load_stored_at(&path, &root_only).unwrap(), Some(source));
    }
}
