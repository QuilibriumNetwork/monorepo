//! Coins a wallet scan already found not to be ours.
//!
//! A scan lists every unspent coin of an application and trial-opens each
//! memo with the wallet's key; nearly all belong to someone else. This cache
//! remembers those, so a later scan opens only coins it has not seen. It is
//! an optimisation only: a missing, corrupt or oversized file is ignored and
//! rebuilt, and a failure to write it never fails the command.
//!
//! Each entry is a SHAKE256 hash of a key derived from the wallet's secret
//! memo key and the application's parameter context, the coin address and the
//! coin's full output bytes. A different key, application or output never
//! matches, and a coin that opens is never stored, so owned coins are always
//! opened. Without the wallet key the file reveals only how many coins were
//! checked; with it, only which listed coins are not ours.
//!
//! One file per wallet key and application in the config directory, named by
//! a hash of the derived key, so swapping keys keeps each key's cache.
//!
//! File: magic `QCSCAN\0\0`, version (u32 LE), entry count (u64 LE), then the
//! entries as strictly ascending 32-byte hashes. Written 0600 to a temporary
//! file and renamed over the old one. After a complete scan it holds exactly
//! the coins that scan found not ours, so it tracks the unspent set.
use quil_lattice_ct::confidential::transfer::Output;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QCSCAN\0\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 8 + 4 + 8;
const ENTRY_BYTES: usize = 32;

/// Most entries kept: twice the coins a scan reaches at the default page
/// budget (2,048 pages of 64), so at defaults nothing is dropped. The file
/// stays at 8 MiB or less; coins past the cap are simply opened every time.
pub(super) const MAX_ENTRIES: usize = 1 << 18;

pub(super) type Entry = [u8; ENTRY_BYTES];

pub(super) struct ScanCache {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    /// Sorted and unique.
    known: Vec<Entry>,
}

impl ScanCache {
    /// The cache of the wallet with this memo key in `dir`, one file per
    /// application context. Any unreadable or invalid file loads as empty.
    pub(super) fn load(dir: &Path, context: &[u8; 32], kem_secret: &[u8]) -> Self {
        let mut hash = Shake256::default();
        hash.update(b"quil/qclient/scan-cache/key/v1\0");
        hash.update(context);
        hash.update(&(kem_secret.len() as u64).to_le_bytes());
        hash.update(kem_secret);
        let mut key = Zeroizing::new([0u8; 32]);
        hash.finalize_xof().read(key.as_mut());
        // One file per key and application, so operators who swap keys or
        // configs in one directory keep each key's cache warm.
        let mut id = [0u8; 8];
        let mut hash = Shake256::default();
        hash.update(b"quil/qclient/scan-cache/file/v1\0");
        hash.update(key.as_ref());
        hash.finalize_xof().read(&mut id);
        let path = dir.join(format!(
            "wallet-scan-cache-{}-{}.bin",
            hex::encode(&context[..8]),
            hex::encode(id)
        ));
        let known = read_entries(&path, MAX_ENTRIES).unwrap_or_default();
        Self { path, key, known }
    }

    /// This wallet's entry for one listed coin.
    pub(super) fn entry(&self, address: &[u8; 32], output: &Output) -> Entry {
        let mut hash = Shake256::default();
        hash.update(b"quil/qclient/scan-cache/entry/v1\0");
        hash.update(self.key.as_ref());
        hash.update(address);
        hash.update(&output.commitment.to_bytes());
        hash.update(&output.owner);
        hash.update(&output.memo);
        let mut entry = [0u8; ENTRY_BYTES];
        hash.finalize_xof().read(&mut entry);
        entry
    }

    /// Whether an earlier scan found this coin not ours.
    pub(super) fn known_not_ours(&self, entry: &Entry) -> bool {
        self.known.binary_search(entry).is_ok()
    }

    /// Record a scan's not-ours entries. A complete scan replaces the file
    /// with them; an incomplete one adds them to what was known. Errors are
    /// ignored: the cache only saves work.
    pub(super) fn store(&self, seen: Vec<Entry>, complete: bool) {
        self.store_capped(seen, complete, MAX_ENTRIES)
    }

    pub(super) fn store_capped(&self, mut seen: Vec<Entry>, complete: bool, cap: usize) {
        if !complete {
            seen.extend_from_slice(&self.known);
        }
        seen.sort_unstable();
        seen.dedup();
        seen.truncate(cap);
        if seen == self.known {
            return;
        }
        let _ = write_entries(&self.path, &seen);
    }

    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// The entries of a valid cache file of at most `cap` entries, else `None`.
pub(super) fn read_entries(path: &Path, cap: usize) -> Option<Vec<Entry>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let length = usize::try_from(file.metadata().ok()?.len()).ok()?;
    if length < HEADER_BYTES || length > HEADER_BYTES + cap * ENTRY_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes).ok()?;
    let (header, body) = bytes.split_at_checked(HEADER_BYTES)?;
    let count = u64::from_le_bytes(header[12..20].try_into().ok()?);
    if &header[..8] != MAGIC
        || u32::from_le_bytes(header[8..12].try_into().ok()?) != VERSION
        || usize::try_from(count).ok()? > cap
        || body.len() != count as usize * ENTRY_BYTES
    {
        return None;
    }
    let entries: Vec<Entry> = body
        .chunks_exact(ENTRY_BYTES)
        .map(|chunk| chunk.try_into().expect("exact chunk"))
        .collect();
    entries
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        .then_some(entries)
}

fn write_entries(path: &Path, entries: &[Entry]) -> std::io::Result<()> {
    use std::io::Write;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + entries.len() * ENTRY_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&temporary).and_then(|mut file| {
        file.write_all(&bytes)?;
        file.sync_all()
    });
    match written.and_then(|()| std::fs::rename(&temporary, path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}
