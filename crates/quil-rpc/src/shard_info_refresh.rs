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
//! **Per-shard enumeration is required.** Go's `GetAppShards` server
//! (`node/consensus/global/services.go:230-247`) rejects requests
//! with empty `ShardKey` from any remote caller with "invalid shard
//! key" — the only way to enumerate every shard is to call the RPC
//! once per known 35-byte `L1‖L2` shard_key, mirroring Go's
//! `getRemoteAppShards` loop in `shard_info.go:117-138`. The caller
//! must therefore know the set of shard_keys up front. We pull that
//! list from the local `ShardsStore` (which is seeded from genesis,
//! so even a fresh node has the canonical set).
//!
//! Picks endpoints round-robin from `ArchiveEndpointPool`. Rotates
//! without blacklist on application-layer errors ("not currently
//! syncable"). Within a single endpoint, per-shard failures are
//! logged and skipped rather than aborting the whole batch — partial
//! data is acceptable per the lifecycle's "propose over what we have"
//! contract.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use num_bigint::BigUint;
use thiserror::Error;
use tracing::{debug, info, warn};

use quil_types::store::ShardsStore;

use crate::archive_client::{ArchiveClient, ArchiveClientError};
use crate::frame_sync::ArchiveEndpointPool;

#[derive(Debug, Error)]
pub enum ShardInfoRefreshError {
    #[error("archive endpoint pool empty")]
    PoolEmpty,
    #[error("local shards store empty — no shard keys to query")]
    NoLocalShards,
    #[error("local shards store error: {0}")]
    LocalStoreFailed(String),
    #[error("all archive endpoints failed; last error: {0}")]
    AllEndpointsFailed(String),
}

/// Enumerate shard_keys from the local `ShardsStore`, then dial one
/// archive at a time and request `GetAppShards` for each shard_key
/// in turn. Aggregates all returned `(filter, size)` pairs into a
/// single map.
///
/// Behaviors:
/// - Local shard_keys are deduplicated. Each `RangeAppShards` row
///   carries one (shard_key, prefix) pair, but multiple rows can
///   share the same 35-byte shard_key (with different prefixes); we
///   only need one RPC per unique shard_key since the response
///   includes every sub-shard under that L2.
/// - Per-shard RPC failures within a connected endpoint are logged
///   and skipped — partial data is preferable to aborting the entire
///   refresh (the lifecycle's "propose over what we have" contract).
/// - Endpoint-level transport failures rotate to the next endpoint.
///   The first endpoint to return at least one successful per-shard
///   result wins; the partial map is returned.
///
/// The wire filter is constructed from `shard_key[3..]` (L2, 32 bytes)
/// concatenated with one byte per `prefix` element — matching the
/// existing filter encoding used by the lifecycle's local
/// `shards_store` consumer at `provers/lifecycle.rs:515-524` and Go's
/// `buildShardEntries` at `shard_info.go:191-194`.
///
/// `AppShardInfo.size` is a BigInt-encoded byte string; we parse via
/// `num_bigint::BigUint::from_bytes_be` and saturate to `u64::MAX` if
/// the value overflows.
///
/// `cap_per_attempt` bounds the number of endpoints we try before
/// giving up in this call. `None` means "every endpoint in the pool."
pub async fn fetch_shard_sizes_from_archive(
    pool: &Arc<ArchiveEndpointPool>,
    ed448_seed: &[u8; 57],
    shards_store: &dyn ShardsStore,
    cap_per_attempt: Option<usize>,
) -> Result<HashMap<Vec<u8>, u64>, ShardInfoRefreshError> {
    let pool_size = pool.len().await;
    if pool_size == 0 {
        return Err(ShardInfoRefreshError::PoolEmpty);
    }

    // Local shard_key enumeration. Mainnet genesis seeds many
    // shards; even a brand-new node should have non-empty local
    // shards-store state.
    let local = shards_store
        .range_app_shards()
        .map_err(|e| ShardInfoRefreshError::LocalStoreFailed(e.to_string()))?;
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut shard_keys: Vec<Vec<u8>> = Vec::new();
    for s in local {
        if s.shard_key.len() == 35 && seen.insert(s.shard_key.clone()) {
            shard_keys.push(s.shard_key);
        }
    }
    if shard_keys.is_empty() {
        return Err(ShardInfoRefreshError::NoLocalShards);
    }

    let max_attempts = cap_per_attempt.unwrap_or(pool_size).max(1);
    let mut last_err: Option<String> = None;
    for attempt in 0..max_attempts {
        let Some(endpoint) = pool.next().await else {
            break;
        };

        match try_one_endpoint(&endpoint, ed448_seed, &shard_keys).await {
            Ok(map) if !map.is_empty() => {
                info!(
                    %endpoint,
                    shard_keys = shard_keys.len(),
                    shards_filtered = map.len(),
                    attempt,
                    "shard_info refresh: success"
                );
                return Ok(map);
            }
            Ok(_) => {
                // Connected but got zero filters back — likely all
                // per-shard calls failed individually. Rotate.
                let msg = "endpoint returned no shard sizes".to_string();
                warn!(%endpoint, attempt, %msg, "shard_info refresh: empty result, rotating");
                last_err = Some(msg);
            }
            Err(e) => {
                let msg = format!("{e}");
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

/// Enumerate `shard_keys` against a single endpoint. Returns
/// whatever sizes were successfully fetched; per-shard errors are
/// logged and skipped (partial OK).
async fn try_one_endpoint(
    endpoint: &str,
    ed448_seed: &[u8; 57],
    shard_keys: &[Vec<u8>],
) -> Result<HashMap<Vec<u8>, u64>, ArchiveClientError> {
    let mut client = ArchiveClient::connect_mtls(endpoint, ed448_seed).await?;
    let mut out: HashMap<Vec<u8>, u64> = HashMap::new();
    for shard_key in shard_keys {
        let infos = match client.get_app_shards(shard_key.clone(), Vec::new()).await {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    %endpoint,
                    shard_key = hex::encode(shard_key),
                    error = %e,
                    "shard_info refresh: per-shard call failed, skipping"
                );
                continue;
            }
        };
        // Server omits `shard_key` in the response when the request
        // had a non-empty key (see services.go:261:
        // `includeShardKey := len(req.ShardKey) != 35`). Use our
        // copy from the request to build the wire filter.
        for info in infos {
            let Some(filter) = build_filter(shard_key, &info.prefix) else {
                continue;
            };
            if filter.is_empty() {
                continue;
            }
            let size = bigint_to_u64_saturating(&info.size);
            out.insert(filter, size);
        }
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
