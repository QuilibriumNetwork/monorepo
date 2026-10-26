//! The verified PeerInfo records of the master's `peer_info_cache`, kept
//! across restarts. Gossip is the cache's only other source, and regular
//! nodes republish their PeerInfo every 30 minutes on mainnet, so a restarted
//! node knew no peer's stream endpoints for up to that long. An archive's
//! app-shard gap fetch then asked only other archives for a frame the shard's
//! members held: after all four archives restarted together, GLOBAL waited
//! 35 minutes on one such frame (2026-10-25).
//!
//! Every saved record is verified on load exactly as a gossiped one, and is
//! dropped once older than [`MAX_AGE_MS`]. Gossip still replaces a restored
//! record: it inserts unconditionally, and only a record no older than a
//! minute passes its mesh validator.
use std::{
    collections::HashMap,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) type PeerInfoCache =
    Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>;

/// The file, in the node's configuration directory.
pub(super) const FILE_NAME: &str = "peer-info-cache.bin";
/// How often the records are saved; they are saved at shutdown too.
pub(super) const SAVE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Records older than this (by their signed timestamp) are neither saved nor
/// loaded: four mainnet republish intervals.
pub(super) const MAX_AGE_MS: i64 = 2 * 60 * 60 * 1000;
/// At most this many records, the newest, are saved and loaded.
pub(super) const MAX_RECORDS: usize = 4096;
/// A record's GLOBAL head older than this is not reported as current: a
/// live peer republishes every 30 minutes.
pub(super) const HEAD_REPORT_MAX_AGE_MS: i64 = 60 * 60 * 1000;
/// A signed timestamp further ahead than this is not loaded, as the
/// gossip validator ignores one.
const MAX_FUTURE_MS: i64 = 5 * 60 * 1000;
const MAX_RECORD_BYTES: u64 = 256 * 1024;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"QPEERS01";

pub(super) fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

/// The checks a PeerInfo passes before it is cached: Falcon key and
/// signature lengths (897 / 666), the peer ID bound to the signing key
/// (without it an attacker signs with their own key but names a genesis
/// archive's peer ID), and the Falcon signature over the record with an
/// empty signature field and an empty domain (as `Signer::sign` signs).
pub(crate) fn verified(info: &quil_p2p::CanonicalPeerInfo) -> bool {
    if info.peer_id.is_empty() || info.public_key.len() != 897 || info.signature.len() != 666 {
        return false;
    }
    if info.peer_id != quil_p2p::peer_id_from_falcon_pubkey(&info.public_key) {
        return false;
    }
    let signing_payload = quil_p2p::encode_canonical_peer_info(info, &info.public_key, &[]);
    quil_crypto::falcon_verify(&info.public_key, &info.signature, &signing_payload, &[])
}

fn within_age(info: &quil_p2p::CanonicalPeerInfo, now_ms: i64) -> bool {
    info.timestamp <= now_ms.saturating_add(MAX_FUTURE_MS)
        && now_ms.saturating_sub(info.timestamp) <= MAX_AGE_MS
}

/// Whether `info`'s GLOBAL head is recent enough to report as current.
pub(super) fn head_is_current(info: &quil_p2p::CanonicalPeerInfo, now_ms: i64) -> bool {
    now_ms.saturating_sub(info.timestamp) <= HEAD_REPORT_MAX_AGE_MS
}

/// The stream endpoints the members of the shard `filter` publish for it,
/// sorted and deduplicated: whom the archive gap fetch asks first.
pub(super) fn shard_member_endpoints(
    cache: &HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    filter: &[u8],
    network: u8,
) -> Vec<String> {
    let mut endpoints: Vec<String> = cache
        .values()
        .flat_map(|info| info.reachability.iter())
        .filter(|reach| reach.filter == filter)
        .flat_map(|reach| reach.stream_multiaddrs.iter())
        .filter_map(|ma| crate::util::multiaddr::archive_multiaddr_to_host_port(ma, network))
        .collect();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

/// Saves the newest [`MAX_RECORDS`] records no older than [`MAX_AGE_MS`],
/// atomically (written beside the file, then renamed). Returns how many
/// were saved.
pub(super) fn save(
    cache: &PeerInfoCache,
    path: &Path,
    network: u8,
    now_ms: i64,
) -> std::io::Result<usize> {
    let mut records: Vec<quil_p2p::CanonicalPeerInfo> = cache
        .read()
        .values()
        .filter(|info| within_age(info, now_ms))
        .cloned()
        .collect();
    records.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.peer_id.cmp(&b.peer_id))
    });
    records.truncate(MAX_RECORDS);
    let mut encoded = Vec::with_capacity(records.len());
    let mut total = (MAGIC.len() + 1 + 8) as u64;
    for info in &records {
        let bytes = quil_p2p::encode_canonical_peer_info(info, &info.public_key, &info.signature);
        let size = 8 + bytes.len() as u64;
        if bytes.len() as u64 > MAX_RECORD_BYTES || total + size > MAX_FILE {
            continue;
        }
        total += size;
        encoded.push(bytes);
    }
    let temporary = path.with_extension("pending");
    let mut file = BufWriter::with_capacity(65536, std::fs::File::create(&temporary)?);
    file.write_all(MAGIC)?;
    file.write_all(&[network])?;
    file.write_all(&(encoded.len() as u64).to_be_bytes())?;
    for bytes in &encoded {
        file.write_all(&(bytes.len() as u64).to_be_bytes())?;
        file.write_all(bytes)?;
    }
    file.flush()?;
    file.get_ref().sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(encoded.len())
}

/// What [`restore`] loaded, and why it dropped the rest.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Restored {
    pub loaded: usize,
    /// Older than [`MAX_AGE_MS`], or dated ahead of this node's clock.
    pub stale: usize,
    /// Undecodable, or failing the checks of [`verified`].
    pub invalid: usize,
    /// The cache already held the peer's record, no older.
    pub superseded: usize,
    /// Beyond [`MAX_RECORDS`].
    pub over_cap: usize,
}

/// Loads the saved records into `cache`, verifying each. A record replaces
/// the cache's record of its peer only when its timestamp is newer. An
/// unreadable or malformed file loads nothing (`Err`).
pub(super) fn restore(
    cache: &PeerInfoCache,
    path: &Path,
    network: u8,
    now_ms: i64,
) -> std::io::Result<Restored> {
    let records = read(path, network)?;
    let mut restored = Restored::default();
    let mut accepted = Vec::new();
    for (index, bytes) in records.into_iter().enumerate() {
        if index >= MAX_RECORDS {
            restored.over_cap += 1;
            continue;
        }
        let Ok(info) = quil_p2p::decode_canonical_peer_info(&bytes) else {
            restored.invalid += 1;
            continue;
        };
        if !within_age(&info, now_ms) {
            restored.stale += 1;
        } else if !verified(&info) {
            restored.invalid += 1;
        } else {
            accepted.push(info);
        }
    }
    let mut cache = cache.write();
    for info in accepted {
        if cache
            .get(&info.peer_id)
            .is_none_or(|held| held.timestamp < info.timestamp)
        {
            cache.insert(info.peer_id.clone(), info);
            restored.loaded += 1;
        } else {
            restored.superseded += 1;
        }
    }
    Ok(restored)
}

fn read(path: &Path, network: u8) -> std::io::Result<Vec<Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE {
        return Err(invalid("file too large"));
    }
    let mut file = BufReader::with_capacity(65536, file);
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid("unknown format"));
    }
    let mut saved_network = [0];
    file.read_exact(&mut saved_network)?;
    if saved_network[0] != network {
        return Err(invalid("saved for another network"));
    }
    let count = read_u64(&mut file)?;
    let mut records = Vec::new();
    for _ in 0..count {
        let size = read_u64(&mut file)?;
        if size > MAX_RECORD_BYTES {
            return Err(invalid("oversized record"));
        }
        let mut bytes = vec![0; size as usize];
        file.read_exact(&mut bytes)?;
        records.push(bytes);
    }
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(invalid("trailing bytes"));
    }
    Ok(records)
}

fn invalid(reason: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid peer info cache file: {reason}"),
    )
}

fn read_u64(r: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

/// Restores the saved records at startup and logs the outcome in one line;
/// a missing or unreadable file leaves the cache as it is.
pub(super) fn restore_at_startup(cache: &PeerInfoCache, path: &Path, network: u8) {
    let started = Instant::now();
    match restore(cache, path, network, unix_millis()) {
        Ok(restored) => tracing::info!(
            loaded = restored.loaded,
            dropped_stale = restored.stale,
            dropped_invalid = restored.invalid,
            dropped_superseded = restored.superseded,
            dropped_over_cap = restored.over_cap,
            max_age_secs = MAX_AGE_MS / 1000,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "peer info cache restored from the last run; gossip replaces each record when its peer republishes"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => tracing::info!(
            loaded = 0,
            "peer info cache: no records saved by a previous run; peers' stream endpoints are known once they republish their PeerInfo"
        ),
        Err(error) => tracing::warn!(
            %error,
            "peer info cache file unreadable; starting with an empty cache: peers' stream endpoints are known once they republish their PeerInfo, and the file is rewritten at the next save"
        ),
    }
}

/// Saves the records every [`SAVE_INTERVAL`] and at shutdown. Never ends
/// the node: a failed save is logged and retried at the next interval.
pub(super) async fn save_until_cancelled(
    cache: PeerInfoCache,
    path: std::path::PathBuf,
    network: u8,
    token: tokio_util::sync::CancellationToken,
) {
    let mut interval = tokio::time::interval(SAVE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        let shutdown = tokio::select! {
            _ = token.cancelled() => true,
            _ = interval.tick() => false,
        };
        let (records, file) = (cache.clone(), path.clone());
        let saved =
            tokio::task::spawn_blocking(move || save(&records, &file, network, unix_millis()))
                .await;
        match saved {
            Ok(Ok(count)) if shutdown => {
                tracing::info!(records = count, "peer info cache saved at shutdown")
            }
            Ok(Ok(count)) => tracing::debug!(records = count, "peer info cache saved"),
            Ok(Err(error)) => tracing::warn!(%error, shutdown,
                "peer info cache save failed; a restart before the next save restores older records or none"),
            Err(error) => tracing::warn!(%error, shutdown, "peer info cache save task failed"),
        }
        if shutdown {
            return;
        }
    }
}

/// Once per filter per hour: whether to log that the gap fetch knows no
/// member endpoint for it.
#[derive(Default)]
pub(super) struct HourlyNotice(parking_lot::Mutex<HashMap<Vec<u8>, Instant>>);

impl HourlyNotice {
    pub(super) fn due(&self, filter: &[u8]) -> bool {
        const HOUR: Duration = Duration::from_secs(3600);
        let now = Instant::now();
        let mut last = self.0.lock();
        if last
            .get(filter)
            .is_some_and(|at| now.duration_since(*at) < HOUR)
        {
            return false;
        }
        if last.len() >= 4096 {
            last.retain(|_, at| now.duration_since(*at) < HOUR);
        }
        last.insert(filter.to_vec(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;

    const FILTER: [u8; 35] = [7; 35];
    // TEST-NET-3 documentation address.
    const STREAM: &str = "/ip4/203.0.113.7/tcp/8340";

    fn signed(timestamp: i64, filter: &[u8]) -> quil_p2p::CanonicalPeerInfo {
        let signer = quil_crypto::FalconSigner::generate();
        let public_key = signer.public_key().to_vec();
        let mut info = quil_p2p::CanonicalPeerInfo {
            peer_id: quil_p2p::peer_id_from_falcon_pubkey(&public_key),
            reachability: vec![quil_p2p::CanonicalReachability {
                filter: filter.to_vec(),
                pubsub_multiaddrs: vec!["/ip4/203.0.113.7/udp/8336/quic-v1".into()],
                stream_multiaddrs: vec![STREAM.into()],
            }],
            timestamp,
            version: vec![2, 1, 0],
            patch_number: vec![25],
            last_received_frame: 20_095,
            last_global_head_frame: 932_137,
            ..Default::default()
        };
        let payload = quil_p2p::encode_canonical_peer_info(&info, &public_key, &[]);
        info.signature = signer.sign(&payload).unwrap();
        info.public_key = public_key;
        // As gossip delivers it: decoded from the wire.
        let wire = quil_p2p::encode_canonical_peer_info(&info, &info.public_key, &info.signature);
        let info = quil_p2p::decode_canonical_peer_info(&wire).unwrap();
        assert!(verified(&info));
        info
    }

    fn cache_of(records: impl IntoIterator<Item = quil_p2p::CanonicalPeerInfo>) -> PeerInfoCache {
        Arc::new(parking_lot::RwLock::new(
            records
                .into_iter()
                .map(|info| (info.peer_id.clone(), info))
                .collect(),
        ))
    }

    #[test]
    fn peer_info_restored_after_restart_names_the_shard_members_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let now = 1_800_000_000_000;
        let member = signed(now - 25 * 60 * 1000, &FILTER);
        let running = cache_of([member.clone()]);
        assert_eq!(
            shard_member_endpoints(&running.read(), &FILTER, 0),
            vec!["203.0.113.7:8340".to_string()]
        );
        assert_eq!(save(&running, &path, 0, now).unwrap(), 1);

        // The restarted node: an empty cache, then the saved file.
        let restarted = cache_of([]);
        assert!(shard_member_endpoints(&restarted.read(), &FILTER, 0).is_empty());
        let restored = restore(&restarted, &path, 0, now + 5 * 60 * 1000).unwrap();
        assert_eq!(
            restored,
            Restored {
                loaded: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            shard_member_endpoints(&restarted.read(), &FILTER, 0),
            vec!["203.0.113.7:8340".to_string()]
        );
        let held = restarted.read().get(&member.peer_id).cloned().unwrap();
        assert_eq!(
            (held.signature, held.last_global_head_frame),
            (member.signature, 932_137)
        );
    }

    #[test]
    fn peer_info_restore_rejects_forged_and_tampered_records_and_drops_stale_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let now = 1_800_000_000_000;
        let good = signed(now - 60_000, &FILTER);
        // Another endpoint written into a signed record.
        let mut tampered = signed(now - 60_000, &FILTER);
        tampered.reachability[0].stream_multiaddrs = vec!["/ip4/198.51.100.9/tcp/8340".into()];
        // Signed by its own key, naming another peer's ID.
        let mut forged = signed(now - 60_000, &FILTER);
        forged.peer_id = good.peer_id.clone();
        forged.timestamp = now - 30_000;
        let mut unsigned = signed(now - 60_000, &FILTER);
        unsigned.signature.clear();
        let stale = signed(now - MAX_AGE_MS - 60_000, &FILTER);
        let ahead = signed(now + MAX_FUTURE_MS + 60_000, &FILTER);
        // save() writes what a cache holds; build the file from records
        // the running cache would never hold, as an attacker could.
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.push(0);
        let records = [&good, &tampered, &forged, &unsigned, &stale, &ahead];
        file.extend_from_slice(&(records.len() as u64).to_be_bytes());
        for info in records {
            let bytes =
                quil_p2p::encode_canonical_peer_info(info, &info.public_key, &info.signature);
            file.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            file.extend_from_slice(&bytes);
        }
        std::fs::write(&path, &file).unwrap();
        let cache = cache_of([]);
        let restored = restore(&cache, &path, 0, now).unwrap();
        assert_eq!(
            restored,
            Restored {
                loaded: 1,
                stale: 2,
                invalid: 3,
                ..Default::default()
            }
        );
        let cache = cache.read();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&good.peer_id).unwrap().signature, good.signature);

        // Saved for another network, or damaged: nothing loads.
        assert!(restore(&cache_of([]), &path, 1, now).is_err());
        std::fs::write(&path, &file[..file.len() - 3]).unwrap();
        let damaged = cache_of([]);
        assert!(restore(&damaged, &path, 0, now).is_err());
        assert!(damaged.read().is_empty());
    }

    #[test]
    fn peer_info_save_keeps_fresh_records_and_gossip_wins_over_restored_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let now = 1_800_000_000_000;
        let fresh = signed(now - 10 * 60 * 1000, &FILTER);
        let stale = signed(now - MAX_AGE_MS - 1, &FILTER);
        assert_eq!(
            save(&cache_of([fresh.clone(), stale]), &path, 0, now).unwrap(),
            1
        );
        // The cache already holds a newer record of the peer (from gossip).
        let mut newer = fresh.clone();
        newer.timestamp = now;
        newer.reachability.clear();
        let cache = cache_of([newer]);
        let restored = restore(&cache, &path, 0, now).unwrap();
        assert_eq!(
            restored,
            Restored {
                superseded: 1,
                ..Default::default()
            }
        );
        assert!(cache
            .read()
            .get(&fresh.peer_id)
            .unwrap()
            .reachability
            .is_empty());
        // Restored records are older than the head report bound only once
        // they are an hour old.
        assert!(head_is_current(&fresh, now));
        assert!(!head_is_current(&fresh, now + HEAD_REPORT_MAX_AGE_MS));
    }

    #[test]
    fn hourly_notice_is_due_once_per_filter() {
        let notice = HourlyNotice::default();
        assert!(notice.due(b"a"));
        assert!(!notice.due(b"a"));
        assert!(notice.due(b"b"));
    }
}
