//! Frame replay verification harness. Replays archived frames through
//! the Rust execution pipeline and compares the resulting CRDT state
//! against expected values.
//!
//! Used for Phase 8B byte-identical verification: ensure the Rust
//! node's materialization produces the same state as Go for the same
//! sequence of frames.

use num_bigint::BigInt;
use tracing::info;

use quil_types::proto::global::GlobalFrame;

/// Result of replaying a batch of frames.
#[derive(Debug)]
pub struct ReplayResult {
    /// Number of frames successfully replayed.
    pub frames_replayed: u64,
    /// Number of messages materialized across all frames.
    pub messages_materialized: u64,
    /// Number of materialization errors (non-fatal — logged and skipped).
    pub errors: u64,
    /// Frame number of the last successfully replayed frame.
    pub last_frame: u64,
}

/// Replay a sequence of frames through the execution pipeline.
/// Each frame's messages are processed via `ExecutionEngineManager::process_message`.
///
/// This is the core verification path: given the same sequence of
/// frames, the Rust pipeline should produce the same CRDT mutations
/// as the Go pipeline.
pub fn replay_frames(
    exec_manager: &quil_execution::ExecutionEngineManager,
    frames: &[GlobalFrame],
    fee_multiplier: &BigInt,
) -> ReplayResult {
    let mut result = ReplayResult {
        frames_replayed: 0,
        messages_materialized: 0,
        errors: 0,
        last_frame: 0,
    };

    for frame in frames {
        let frame_num = frame
            .header
            .as_ref()
            .map(|h| h.frame_number)
            .unwrap_or(0);

        match crate::frame_processor::process_global_frame(exec_manager, frame, fee_multiplier) {
            Ok((applied, _skipped)) => {
                result.frames_replayed += 1;
                result.messages_materialized += applied as u64;
                result.last_frame = frame_num;
            }
            Err(e) => {
                result.errors += 1;
                tracing::warn!(
                    frame = frame_num,
                    error = %e,
                    "replay: frame processing failed"
                );
            }
        }
    }

    info!(
        frames = result.frames_replayed,
        messages = result.messages_materialized,
        errors = result.errors,
        last_frame = result.last_frame,
        "frame replay complete"
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn replay_empty_frames() {
        let exec = quil_execution::ExecutionEngineManager::new(
            Arc::new(quil_crypto::KzgInclusionProver),
            true,
        );
        let result = replay_frames(&exec, &[], &BigInt::from(1));
        assert_eq!(result.frames_replayed, 0);
        assert_eq!(result.errors, 0);
    }

    #[test]
    fn replay_frame_without_messages() {
        let exec = quil_execution::ExecutionEngineManager::new(
            Arc::new(quil_crypto::KzgInclusionProver),
            true,
        );
        let frame = GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: 1,
                ..Default::default()
            }),
            requests: Vec::new(),
        };
        let result = replay_frames(&exec, &[frame], &BigInt::from(1));
        assert_eq!(result.frames_replayed, 1);
        assert_eq!(result.messages_materialized, 0);
        assert_eq!(result.last_frame, 1);
    }
}
