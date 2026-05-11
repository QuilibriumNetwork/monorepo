//! Archive-direct shard size fetcher.
//!
//! The lifecycle's `ProposeJoin` / `ProposeLeave` gate requires
//! shard size data sourced from an archive — local registry summaries
//! and the local shards-store are not authoritative for this purpose
//! because a node that hasn't yet synced the prover tree won't have
//! sizes for shards it isn't a member of. Archives have the full
//! picture.
//!
//! This module dials archives directly via the mTLS
//! `GlobalServiceClient::GetAppShards` RPC, parses the response into
//! `(filter, size)` pairs, and returns the map. It deliberately does
//! NOT consult `LocalShardInfoProvider` (which has a "try local first,
//! dial out on miss" fallback) — the contract here is "always go to
//! the archive."
//!
//! Picks endpoints round-robin from `ArchiveEndpointPool`. Blacklists
//! endpoints that fail at the transport layer; rotates without
//! blacklist on application-layer errors ("not currently syncable").
//! Returns the first successful fetch; gives up after exhausting all
//! endpoints in a single attempt cycle.

use std::collections::HashMap;
use std::sync::Arc;

use num_bigint::BigUint;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::archive_client::{ArchiveClient, ArchiveClientError};
use crate::frame_sync::ArchiveEndpointPool;

#[derive(Debug, Error)]
pub enum ShardInfoRefreshError {
    #[error("archive endpoint pool empty")]
    PoolEmpty,
    #[error("all archive endpoints failed; last error: {0}")]
    AllEndpointsFailed(String),
}

/// Dial one archive at a time until one succeeds. On success, decode
/// the `AppShardInfo` list into a `filter → size` map and return.
///
/// The wire filter is constructed from `shard_key[3..]` (L2, 32 bytes)
/// concatenated with one byte per `prefix` element — matching the
/// existing filter encoding used by the lifecycle's local
/// `shards_store` consumer at `provers/lifecycle.rs:515-524`. The
/// `AppShardInfo.size` field is a BigInt-encoded byte string; we
/// parse via `num_bigint::BigUint::from_bytes_be` and saturate to
/// `u64::MAX` if the value overflows.
///
/// `cap_per_attempt` bounds the number of endpoints we try before
/// giving up in this call. `None` means "every endpoint in the pool."
pub async fn fetch_shard_sizes_from_archive(
    pool: &Arc<ArchiveEndpointPool>,
    ed448_seed: &[u8; 57],
    cap_per_attempt: Option<usize>,
) -> Result<HashMap<Vec<u8>, u64>, ShardInfoRefreshError> {
    let pool_size = pool.len().await;
    if pool_size == 0 {
        return Err(ShardInfoRefreshError::PoolEmpty);
    }
    let max_attempts = cap_per_attempt.unwrap_or(pool_size).max(1);

    let mut last_err: Option<String> = None;
    for attempt in 0..max_attempts {
        let Some(endpoint) = pool.next().await else {
            break;
        };

        match try_one_endpoint(&endpoint, ed448_seed).await {
            Ok(map) => {
                info!(
                    %endpoint,
                    shards = map.len(),
                    attempt,
                    "shard_info refresh: success"
                );
                return Ok(map);
            }
            Err(e) => {
                let msg = format!("{e}");
                // Application-layer "not currently syncable" — rotate,
                // do NOT blacklist (the operator may flip the archive
                // on later). Network-layer failures are not handled
                // specially here since we just rotate to the next
                // endpoint either way; the frame_sync poller is the
                // authoritative blacklist owner.
                if msg.contains("not currently syncable") {
                    debug!(%endpoint, "shard_info refresh: not currently syncable, rotating");
                } else {
                    warn!(
                        %endpoint,
                        attempt,
                        error = %msg,
                        "shard_info refresh: endpoint failed, rotating"
                    );
                }
                last_err = Some(msg);
            }
        }
    }

    Err(ShardInfoRefreshError::AllEndpointsFailed(
        last_err.unwrap_or_else(|| "no error captured".into()),
    ))
}

async fn try_one_endpoint(
    endpoint: &str,
    ed448_seed: &[u8; 57],
) -> Result<HashMap<Vec<u8>, u64>, ArchiveClientError> {
    let mut client = ArchiveClient::connect_mtls(endpoint, ed448_seed).await?;
    // Empty shard_key + empty prefix → server returns the full app
    // shard list (`global_service.rs:185-193`).
    let infos = client.get_app_shards(Vec::new(), Vec::new()).await?;

    let mut out: HashMap<Vec<u8>, u64> = HashMap::with_capacity(infos.len());
    for info in infos {
        let Some(filter) = build_filter(&info.shard_key, &info.prefix) else {
            // Malformed shard_key (must be 35 bytes for L1||L2); skip.
            continue;
        };
        // Empty filter would collide with the global plane; skip.
        if filter.is_empty() {
            continue;
        }
        let size = bigint_to_u64_saturating(&info.size);
        out.insert(filter, size);
    }
    Ok(out)
}

/// Build the wire filter from `(shard_key, prefix)` using the
/// L2 || prefix.byte() encoding. Matches the lifecycle's local
/// shards-store consumer.
fn build_filter(shard_key: &[u8], prefix: &[u32]) -> Option<Vec<u8>> {
    if shard_key.len() < 35 {
        return None;
    }
    // L1 = bytes 0..3, L2 = bytes 3..35.
    let l2 = &shard_key[3..35];
    let mut filter = l2.to_vec();
    for p in prefix {
        filter.push((*p & 0xFF) as u8);
    }
    Some(filter)
}

/// Parse an `AppShardInfo.size` BigInt byte string into a `u64`.
/// Saturates at `u64::MAX` for overflow. Empty input → 0.
fn bigint_to_u64_saturating(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let bi = BigUint::from_bytes_be(bytes);
    let digits = bi.to_u64_digits();
    if digits.len() <= 1 {
        digits.first().copied().unwrap_or(0)
    } else {
        u64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_strips_l1_and_appends_prefix() {
        let shard_key: Vec<u8> = (0u8..35).collect(); // 0..2 = L1, 3..34 = L2
        let prefix = vec![0x12u32, 0x34u32, 0x56u32];
        let filter = build_filter(&shard_key, &prefix).unwrap();
        // L2 is bytes 3..35 (32 bytes) → starts with 0x03..
        assert_eq!(filter.len(), 32 + 3);
        assert_eq!(&filter[..32], &shard_key[3..35]);
        assert_eq!(&filter[32..], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn build_filter_rejects_short_shard_key() {
        let shard_key = vec![0u8; 10]; // < 35
        assert!(build_filter(&shard_key, &[]).is_none());
    }

    #[test]
    fn build_filter_prefix_only_low_byte() {
        let shard_key: Vec<u8> = (0u8..35).collect();
        // High bytes of u32 are dropped — wire format uses one byte
        // per prefix element.
        let prefix = vec![0xABCDu32, 0xFF00FFFFu32];
        let filter = build_filter(&shard_key, &prefix).unwrap();
        assert_eq!(&filter[32..], &[0xCD, 0xFF]);
    }

    #[test]
    fn bigint_to_u64_handles_empty_zero_and_normal() {
        assert_eq!(bigint_to_u64_saturating(&[]), 0);
        assert_eq!(bigint_to_u64_saturating(&[0]), 0);
        assert_eq!(bigint_to_u64_saturating(&[0x12, 0x34]), 0x1234);
        assert_eq!(
            bigint_to_u64_saturating(&[0xFF; 8]),
            u64::MAX,
        );
    }

    #[test]
    fn bigint_to_u64_saturates_on_overflow() {
        // 9 bytes of 0xFF → > u64::MAX
        let big = vec![0xFFu8; 9];
        assert_eq!(bigint_to_u64_saturating(&big), u64::MAX);
    }
}
