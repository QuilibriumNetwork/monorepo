//! Legacy byte-suffix split layout (Go's `proposeShardSplit`): the
//! split factor by population and the children it proposes. The coverage
//! monitor (`coverage.rs`) and the reassignment ordering use them; the
//! signed proposal itself is built by `prover_pipeline::submit_shard_split`.

/// Threshold breakpoints (hardcoded in Go's coverage_monitor.go).
pub const SPLIT_FACTOR_2: u64 = 32;
pub const SPLIT_FACTOR_4: u64 = 48;
pub const SPLIT_FACTOR_8: u64 = 64;

/// Go's `proposeShardSplit` splits into 2 / 4 / 8 shards based on
/// population, appending a discriminator byte to the existing
/// filter. We preserve that exact prefix/suffix layout so receivers
/// can route against either child shard correctly.
pub fn split_factor(active_count: u64) -> u8 {
    if active_count > SPLIT_FACTOR_8 {
        8
    } else if active_count > SPLIT_FACTOR_4 {
        4
    } else {
        2
    }
}

pub fn compute_proposed_shards(filter: &[u8], factor: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(factor as usize);
    match factor {
        2 => {
            for suffix in [0x00u8, 0x80u8] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
        4 => {
            for suffix in [0x00u8, 0x40, 0x80, 0xC0] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
        8 => {
            // 2-byte suffix encoding octal bucket (Go uses
            // big-endian 2-byte markers 0x0000, 0x2000, ..., 0xE000).
            for hi in [0x00u8, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0] {
                let mut s = filter.to_vec();
                s.push(hi);
                s.push(0x00);
                out.push(s);
            }
        }
        _ => {
            // Fallback to binary split.
            for suffix in [0x00u8, 0x80u8] {
                let mut s = filter.to_vec();
                s.push(suffix);
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_factor_thresholds() {
        assert_eq!(split_factor(33), 2);
        assert_eq!(split_factor(48), 2);
        assert_eq!(split_factor(49), 4);
        assert_eq!(split_factor(64), 4);
        assert_eq!(split_factor(65), 8);
    }

    #[test]
    fn proposed_shards_shape() {
        let two = compute_proposed_shards(&[0x11; 32], 2);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].len(), 33);
        assert_eq!(two[0][32], 0x00);
        assert_eq!(two[1][32], 0x80);

        let four = compute_proposed_shards(&[0x11; 32], 4);
        assert_eq!(four.len(), 4);

        let eight = compute_proposed_shards(&[0x11; 32], 8);
        assert_eq!(eight.len(), 8);
        assert_eq!(eight[0].len(), 34);
    }
}
