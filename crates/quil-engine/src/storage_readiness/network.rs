//! A traffic-share scenario, not a measurement of GLOBAL inclusion.
//! Precommit buckets serialize only their own sectors; different buckets
//! pipeline. A proof waits until committed_at + 2, as check_capacity requires.
use super::*;
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize)]
pub struct NetworkModel {
    pub frames: u64,
    pub storage_bytes_per_frame: u64,
    pub traffic_share_percent: u8,
    pub pending_sector_limit: usize,
    pub model: &'static str,
}

pub fn inclusion_model(
    capacity: &[CapacityInclusion],
    registrations: &[u64],
    share: u8,
    pending_sector_limit: usize,
) -> Result<NetworkModel, &'static str> {
    let frame_bytes = quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME as u64;
    if !(1..=100).contains(&share) || pending_sector_limit == 0 {
        return Err("invalid network traffic share");
    }
    if capacity.is_empty()
        || capacity.iter().any(|c| {
            c.bucket >= 16
                || c.precommit_bytes == 0
                || c.certificate_bytes == 0
                || c.precommit_bytes > frame_bytes
                || c.certificate_bytes > frame_bytes
        })
        || registrations.iter().any(|&n| n > frame_bytes)
    {
        return Err("capacity inclusion measurements are missing or exceed a frame");
    }
    let pending_sector_limit = pending_sector_limit.min(16);
    let budget = frame_bytes * u64::from(share) / 100;
    let mut queued: [VecDeque<&CapacityInclusion>; 16] = std::array::from_fn(|_| VecDeque::new());
    for certificate in capacity {
        queued[certificate.bucket as usize].push_back(certificate);
    }
    let mut active: [Option<(u64, u64)>; 16] = [None; 16];
    let mut remaining = capacity.len();
    let mut registrations: VecDeque<_> = registrations.iter().copied().filter(|&n| n > 0).collect();
    let mut capacity_finished = None;
    let mut credit = 0u64;
    for frame in 1..=100_000u64 {
        // Accumulated share permits a single large, indivisible proof to fit
        // within the actual 4 MiB cap, without assuming the whole channel.
        credit = credit.saturating_add(budget).min(frame_bytes);
        // Locally initialized sectors remain pending until the worker sees
        // their committed acknowledgment in the following frame.
        let mut free_slots =
            pending_sector_limit.saturating_sub(active.iter().filter(|p| p.is_some()).count());
        let mut released = [false; 16];
        for (bucket, pending) in active.iter_mut().enumerate() {
            if let Some((ready, bytes)) = *pending {
                if frame >= ready && bytes <= credit {
                    credit -= bytes;
                    *pending = None;
                    remaining -= 1;
                    released[bucket] = true;
                }
            }
        }
        for bucket in 0..16 {
            // The worker sees the preceding frame's committed acknowledgment.
            if free_slots == 0 || active[bucket].is_some() || released[bucket] {
                continue;
            }
            if let Some(next) = queued[bucket].front() {
                if next.precommit_bytes <= credit {
                    credit -= next.precommit_bytes;
                    free_slots -= 1;
                    active[bucket] = Some((frame + 2, next.certificate_bytes));
                    queued[bucket].pop_front();
                }
            }
        }
        if remaining == 0 {
            let finished = *capacity_finished.get_or_insert(frame);
            if frame > finished {
                while let Some(&bytes) = registrations.front() {
                    if bytes > credit {
                        break;
                    }
                    credit -= bytes;
                    registrations.pop_front();
                }
            }
            if registrations.is_empty() {
                return Ok(NetworkModel { frames: frame, storage_bytes_per_frame: budget,
                    traffic_share_percent: share,
                    pending_sector_limit,
                    model: "modeled parallel precommit/beacon/certificate pipeline; 16 member buckets; bounded traffic share with a one-frame burst; no inclusion guarantee or other-node execution measurement" });
            }
        }
    }
    Err("network inclusion scenario exceeds its simulation bound")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cert(bucket: u8) -> CapacityInclusion {
        CapacityInclusion {
            bucket,
            precommit_bytes: 2304,
            certificate_bytes: 300_000,
        }
    }
    #[test]
    fn measured_wire_sizes_include_the_actual_collector_bundle() {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let message = CanonicalMessageBundle {
            timestamp: i64::MAX,
            requests: vec![Some(CanonicalMessageRequest {
                inner_type_prefix:
                    quil_execution::global_intrinsic::storage_epoch_proof::TYPE_STORAGE_EPOCH_PROOF,
                inner_bytes: vec![0; 512],
            })],
        }
        .to_canonical_bytes()
        .unwrap();
        assert_eq!(storage_wire_bytes(512), message.len() as u64);
    }

    #[test]
    fn independent_buckets_pipeline_and_collisions_wait_for_acknowledgment() {
        assert_eq!(
            inclusion_model(&[cert(0), cert(1)], &[], 100, 16)
                .unwrap()
                .frames,
            3
        );
        assert_eq!(
            inclusion_model(&[cert(0), cert(0)], &[], 100, 16)
                .unwrap()
                .frames,
            6
        );
    }
    #[test]
    fn worker_pool_limits_pending_sectors_until_the_next_frame_acknowledgment() {
        let capacity = [cert(0), cert(1)];
        assert_eq!(inclusion_model(&capacity, &[], 100, 1).unwrap().frames, 6);
        assert_eq!(inclusion_model(&capacity, &[], 100, 2).unwrap().frames, 3);
        assert!(inclusion_model(&capacity, &[], 100, 0).is_err());
    }

    #[test]
    fn eighty_sectors_use_frame_bytes_and_bucket_waves_not_serial_per_sector_latency() {
        let capacity: Vec<_> = (0..80).map(|i| cert(i % 16)).collect();
        let model = inclusion_model(&capacity, &[500_000; 9], 25, 9).unwrap();
        assert!(model.frames < 60, "not 320 serialized frames");
        assert!(
            model.frames >= 28,
            "all proof and registration bytes consume the share"
        );
    }
    #[test]
    fn indivisible_large_messages_wait_for_credit_and_invalid_inputs_fail_closed() {
        let mut c = cert(0);
        c.certificate_bytes = 4 << 20;
        assert!(
            inclusion_model(&[c.clone()], &[], 25, 16).unwrap().frames
                > inclusion_model(&[c.clone()], &[], 100, 16).unwrap().frames
        );
        c.certificate_bytes += 1;
        assert!(inclusion_model(&[c], &[], 25, 16).is_err());
        assert!(inclusion_model(&[], &[], 25, 16).is_err());
        assert!(inclusion_model(&[cert(16)], &[], 25, 16).is_err());
        assert!(inclusion_model(&[cert(0)], &[], 0, 16).is_err());
    }
}
