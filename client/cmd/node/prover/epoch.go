package prover

import (
	"fmt"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// This file mirrors the Rust node's epoch-aligned prover lifecycle so the
// client can display and gate join/leave/confirm/reject exactly the way the
// node validates them. The authoritative definitions live in the node:
//   - crates/quil-types/src/consensus.rs        (epoch_for_frame, effective_status)
//   - crates/quil-execution/.../verify.rs       (validate_confirm_timing)
//
// The lifecycle pipeline is "propose in epoch E → settle in E+1 → effect in
// E+2". A join/leave proposed in epoch E must be confirmed (or rejected) in
// EXACTLY epoch E+1; the chain rejects confirms outside that one-epoch slot.
// An Active data-shard prover re-confirms every epoch X for X+1, so its
// recorded `Epoch` (highest epoch it has registered leaf roots for) must stay
// >= the current epoch or it reads as ExpiredEpoch.

// defaultEpochLengthFrames is the mainnet epoch length. The node reports the
// real value (720 mainnet / 60 testnet) in NodeInfoResponse.epoch_length_frames;
// this is only the fallback when a node predates that field (reports 0).
const defaultEpochLengthFrames = 720

// effectiveStatus is the client-side mirror of the node's EffectiveStatus enum.
type effectiveStatus int

const (
	effUnknown effectiveStatus = iota
	effJoining
	effActive
	effPaused
	effLeaving
	effExpiredJoining
	effExpiredLeaving
	effExpiredEpoch
	effRejected
	effKicked
)

// Raw ProverStatus byte values as sent over the RPC (the ProverStatus enum
// discriminants, NOT the trie byte scheme). Mirrors quil-types ProverStatus.
const (
	rawStatusUnknown  = 0
	rawStatusJoining  = 1
	rawStatusActive   = 2
	rawStatusPaused   = 3
	rawStatusLeaving  = 4
	rawStatusRejected = 5
	rawStatusKicked   = 6
)

// epochLen returns a safe epoch length, falling back to the mainnet default
// when the node reports 0 (older node without the epoch_length_frames field).
func epochLen(epochLength uint64) uint64 {
	if epochLength == 0 {
		return defaultEpochLengthFrames
	}
	return epochLength
}

// epochForFrame mirrors quil_types::consensus::epoch_for_frame.
func epochForFrame(frame, epochLength uint64) uint64 {
	return frame / epochLen(epochLength)
}

// epochStartFrame returns the first frame of the given epoch.
func epochStartFrame(epoch, epochLength uint64) uint64 {
	return epoch * epochLen(epochLength)
}

// computeEffectiveStatus mirrors ProverAllocationInfo::effective_status. It maps
// the raw RPC status byte + timing fields + current frame to the effective
// lifecycle state the node would compute. `filter` is the allocation's
// ConfirmationFilter (empty => global prover, exempt from epoch obligations).
func computeEffectiveStatus(
	rawStatus uint32,
	filter []byte,
	joinFrame, joinConfirmFrame, leaveFrame, leaveConfirmFrame, epoch uint64,
	currentFrame, epochLength uint64,
) effectiveStatus {
	el := epochLen(epochLength)
	currentEpoch := currentFrame / el

	switch rawStatus {
	case rawStatusJoining:
		// A join proposed in epoch E must confirm in EXACTLY E+1. A Joining
		// byte that slipped past its confirm epoch is implicitly rejected.
		// joinFrame==0 is the genesis/test sentinel (no expiry).
		if joinFrame > 0 && currentEpoch > joinFrame/el+1 {
			return effExpiredJoining
		}
		return effJoining

	case rawStatusActive:
		// The global/empty filter stores no shard data — exempt from epochs.
		if len(filter) == 0 {
			return effActive
		}
		// Deferred activation: a fresh join confirmed in E+1 flips its byte to
		// Active but doesn't join the committee until the E+2 boundary, so it
		// reads as Joining until then. The join_confirm>0 guard keeps genesis /
		// legacy fixtures (which leave it 0) on the always-active path.
		if joinConfirmFrame > 0 {
			activationEpoch := joinConfirmFrame/el + 1
			if currentEpoch < activationEpoch {
				return effJoining
			}
		}
		// Epoch re-confirm obligation: `epoch` is the highest epoch this
		// allocation registered leaf roots for. A current member always
		// satisfies epoch >= currentEpoch; a stale one missed its re-confirm.
		if epoch >= currentEpoch {
			return effActive
		}
		return effExpiredEpoch

	case rawStatusPaused:
		return effPaused

	case rawStatusLeaving:
		// A leave proposed in E confirms in E+1 and departs at the E+2
		// boundary (DeactivationEpoch = epoch_for_frame(leaveConfirm)+1); the
		// prover serves notice (still Leaving) until then. A leave that never
		// confirmed in its E+1 slot is implicitly departed.
		if leaveConfirmFrame > 0 {
			deactivationEpoch := leaveConfirmFrame/el + 1
			if currentEpoch < deactivationEpoch {
				return effLeaving
			}
			return effExpiredLeaving
		}
		if leaveFrame > 0 && currentEpoch > leaveFrame/el+1 {
			return effExpiredLeaving
		}
		return effLeaving

	case rawStatusRejected:
		return effRejected
	case rawStatusKicked:
		return effKicked
	default:
		return effUnknown
	}
}

// String renders the effective status as a display label. These labels feed
// statusStyle() for color coding, so keep them lowercase-matchable there.
func (e effectiveStatus) String() string {
	switch e {
	case effJoining:
		return "Joining"
	case effActive:
		return "Active"
	case effPaused:
		return "Paused"
	case effLeaving:
		return "Leaving"
	case effExpiredJoining:
		return "ExpiredJoin"
	case effExpiredLeaving:
		return "ExpiredLeave"
	case effExpiredEpoch:
		return "Re-confirm!"
	case effRejected:
		return "Rejected"
	case effKicked:
		return "Kicked"
	default:
		return "Unknown"
	}
}

// isLive mirrors EffectiveStatus::is_live (Joining|Active|Paused|Leaving).
func (e effectiveStatus) isLive() bool {
	switch e {
	case effJoining, effActive, effPaused, effLeaving:
		return true
	default:
		return false
	}
}

// confirmWindow describes the single epoch slot in which a pending join or
// leave may be confirmed or rejected. Confirm is valid iff the current epoch
// equals confirmEpoch; the absolute frame range is [startFrame, endFrame).
type confirmWindow struct {
	confirmEpoch uint64
	startFrame   uint64 // first frame confirm/reject is valid (inclusive)
	endFrame     uint64 // first frame after the window (exclusive)
}

// joinConfirmWindow mirrors validate_confirm_timing for a Joining allocation:
// confirm must land in exactly epoch_for_frame(joinFrame)+1.
func joinConfirmWindow(joinFrame, epochLength uint64) confirmWindow {
	el := epochLen(epochLength)
	ce := joinFrame/el + 1
	return confirmWindow{confirmEpoch: ce, startFrame: ce * el, endFrame: (ce + 1) * el}
}

// leaveConfirmWindow mirrors validate_confirm_timing for a Leaving allocation:
// confirm must land in exactly epoch_for_frame(leaveFrame)+1.
func leaveConfirmWindow(leaveFrame, epochLength uint64) confirmWindow {
	el := epochLen(epochLength)
	ce := leaveFrame/el + 1
	return confirmWindow{confirmEpoch: ce, startFrame: ce * el, endFrame: (ce + 1) * el}
}

// state describes where the current frame sits relative to a confirm window.
type windowState int

const (
	windowPending windowState = iota // current epoch is before confirmEpoch (wait)
	windowOpen                       // current epoch == confirmEpoch (act now)
	windowMissed                     // current epoch is past confirmEpoch (expired)
)

func (w confirmWindow) state(currentFrame, epochLength uint64) windowState {
	ce := currentFrame / epochLen(epochLength)
	switch {
	case ce < w.confirmEpoch:
		return windowPending
	case ce == w.confirmEpoch:
		return windowOpen
	default:
		return windowMissed
	}
}

// label renders a compact human hint about when confirm/reject can happen,
// e.g. "Confirm@epoch 5 (frame 3600)" or "Confirm window open now".
func (w confirmWindow) label(verb string, currentFrame, epochLength uint64) string {
	switch w.state(currentFrame, epochLength) {
	case windowOpen:
		return fmt.Sprintf("%s now (epoch %d, until frame %d)", verb, w.confirmEpoch, w.endFrame)
	case windowPending:
		return fmt.Sprintf("%s @epoch %d (frame %d)", verb, w.confirmEpoch, w.startFrame)
	default:
		return fmt.Sprintf("%s window missed (was epoch %d)", verb, w.confirmEpoch)
	}
}

// allocConfirmWindow returns the applicable confirm window for a pending
// allocation (Joining or Leaving) plus true, or a zero window + false when the
// allocation is not in a confirmable state.
func allocConfirmWindow(a *protobufs.ShardAllocationInfo, epochLength uint64) (confirmWindow, bool) {
	switch a.GetStatus() {
	case rawStatusJoining:
		if a.GetJoinFrameNumber() > 0 {
			return joinConfirmWindow(a.GetJoinFrameNumber(), epochLength), true
		}
	case rawStatusLeaving:
		if a.GetLeaveFrameNumber() > 0 {
			return leaveConfirmWindow(a.GetLeaveFrameNumber(), epochLength), true
		}
	}
	return confirmWindow{}, false
}
