//! The renewal grace frame leaves a renewal signed at it time to be included
//! in the epoch it was signed in. Its own binary: the epoch-length override is
//! process-global.

use quil_engine::app_shard_metadata::storage_snapshot_grace;
use quil_execution::global_intrinsic::verify::validate_confirm_epoch;
use quil_types::consensus::{epoch_start_frame, set_epoch_length_frames, storage_snapshot_frame};

/// Frames after the grace frame within which GLOBAL must accept a renewal
/// signed at it.
const INCLUSION_FRAMES: u64 = 8;

/// A seat without its snapshot renews at the grace frame and signs that
/// frame; GLOBAL refuses a confirm signed in one epoch and included in the
/// next. So for every epoch length a renewal signed at the grace frame stays
/// valid for [`INCLUSION_FRAMES`] frames, and mainnet keeps 320 frames.
#[test]
fn a_renewal_signed_at_its_grace_frame_can_land_in_its_epoch() {
    const EPOCH: u64 = 25;
    for length in [30u64, 31, 36, 45, 60, 720] {
        set_epoch_length_frames(length);
        let grace = storage_snapshot_frame(EPOCH) + storage_snapshot_grace();
        let boundary = epoch_start_frame(EPOCH);
        assert!(
            grace < boundary,
            "epoch length {length}: grace frame {grace} is not before the boundary {boundary}"
        );
        for inclusion in grace + 1..=grace + INCLUSION_FRAMES {
            if let Err(e) = validate_confirm_epoch(grace, inclusion) {
                set_epoch_length_frames(0);
                panic!(
                    "epoch length {length}: a renewal signed at grace frame {grace} and \
                     included at frame {inclusion} (boundary {boundary}) is refused: {e}"
                );
            }
        }
    }
    set_epoch_length_frames(720);
    assert_eq!(
        storage_snapshot_grace(),
        320,
        "mainnet grace stays 320 frames"
    );
    set_epoch_length_frames(0);
}
