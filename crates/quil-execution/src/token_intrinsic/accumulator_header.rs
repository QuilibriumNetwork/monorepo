//! When an app-shard header carries its shard's accumulator report. Pure and
//! feature-independent, so the frame producer and validators decide it
//! identically in every build.

/// Frames between heartbeats: a header carries its shard's report when the
/// report changed in the previous frame, and also on every frame number that
/// is a multiple of this, so a dropped header delays the canonical root by at
/// most this many frames instead of until the shard's next change.
pub const HEARTBEAT_FRAMES: u64 = 32;

/// The per-frame digest of a report: SHA3-256 of its bytes, empty for none.
pub fn report_digest(report: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    if report.is_empty() {
        return Vec::new();
    }
    sha3::Sha3_256::digest(report).to_vec()
}

/// Frames a changed report is re-carried for. The global commit rejects a
/// spend whose root is not yet canonical, and shard headers reach the global
/// frame as ordinary messages that can be dropped, so one dropped header must
/// not keep a new root out of the canonical history until the heartbeat.
/// Matches the spend relay window.
pub const CARRY_WINDOW_FRAMES: u64 = 8;

/// Whether header `frame_number` carries the report of frame `frame_number - 1`,
/// given the report digest `last` of that frame and `earlier`, the digests of
/// the [`CARRY_WINDOW_FRAMES`] frames before it (newest first; frames before
/// genesis are empty).
pub fn header_carries(frame_number: u64, earlier: &[Vec<u8>], last: &[u8]) -> bool {
    !last.is_empty() && (earlier.iter().any(|digest| digest.as_slice() != last) || frame_number % HEARTBEAT_FRAMES == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_carries_a_report_when_it_changed_or_on_the_heartbeat() {
        let (a, b) = (report_digest(b"report a"), report_digest(b"report b"));
        assert!(report_digest(&[]).is_empty());
        let window = |digests: &[&Vec<u8>]| digests.iter().map(|d| d.to_vec()).collect::<Vec<_>>();
        // Changed within the window: carried, for every frame of the window.
        assert!(header_carries(7, &window(&[&a, &a, &a]), &b));
        assert!(header_carries(7, &window(&[&b, &b, &a]), &b));
        assert!(header_carries(7, &window(&[&vec![]]), &a));
        // Unchanged across the window: not carried, except on the heartbeat.
        assert!(!header_carries(7, &window(&[&a, &a]), &a));
        assert!(header_carries(HEARTBEAT_FRAMES * 3, &window(&[&a, &a]), &a));
        // A shard with no coins never carries one.
        assert!(!header_carries(HEARTBEAT_FRAMES, &window(&[&a]), &[]));
        assert!(!header_carries(7, &window(&[&vec![]]), &[]));
    }


}
