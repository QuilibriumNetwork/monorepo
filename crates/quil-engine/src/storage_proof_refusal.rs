//! Names the member whose storage epoch proof this GLOBAL leader's message
//! validation refused. GLOBAL refuses a proof whole when one of its seats
//! fails, so the member loses the epoch it settles and the registration it
//! seals; the mempool drop summary groups reasons with their digits masked
//! and cut short, and so cannot say whose proof it was, which epoch, or
//! whether it came late or was a copy of one already applied
//! (`storage_epoch_proof::REFUSED_LATE`, `REFUSED_DUPLICATE`). One info line
//! per proof, at most [`LINES_PER_FRAME`] a frame. Logging only: which
//! proofs are accepted does not change.

use std::collections::HashSet;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use quil_execution::global_intrinsic::storage_epoch_proof::{
    StorageEpochProof, REFUSED_DUPLICATE, REFUSED_LATE, TYPE_STORAGE_EPOCH_PROOF,
};

/// Refused proofs named in one GLOBAL frame; the rest are named in a later
/// frame that refuses them again, and the drop summary counts them all.
const LINES_PER_FRAME: usize = 8;
/// Proofs remembered as named; past it the memory starts over, so a proof
/// still refused may be named once more.
const NAMED_KEPT: usize = 4096;
/// Seats listed in one line.
const SEATS_LISTED: usize = 8;
/// Longest reason logged, in characters.
const REASON_CHARS: usize = 400;

/// One refused storage epoch proof, as logged.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused {
    /// The member's prover address, first 8 bytes in hex.
    pub(crate) prover: String,
    /// Each seat: shard filter, the epoch it settles and the one it seals.
    pub(crate) seats: String,
    pub(crate) more_seats: usize,
    /// `duplicate`, `deadline_miss` or `other`.
    pub(crate) kind: &'static str,
    pub(crate) reason: String,
}

#[derive(Default)]
pub(crate) struct RefusalLog {
    named: HashSet<[u8; 32]>,
    frame: u64,
    lines: usize,
    unlisted: usize,
}

impl RefusalLog {
    /// The storage epoch proofs `raw` (a collected bundle, or a bare proof)
    /// carries that GLOBAL frame `frame` refused with `reason` and that were
    /// not named before, each once, within the frame's line budget; and
    /// whether this refusal left one unnamed for lack of budget.
    pub(crate) fn refused(&mut self, frame: u64, raw: &[u8], reason: &str) -> (Vec<Refused>, bool) {
        if frame != self.frame {
            self.frame = frame;
            self.lines = 0;
            self.unlisted = 0;
        }
        let mut out = Vec::new();
        let mut unlisted = false;
        for inner in storage_proofs(raw) {
            let Ok(proof) = StorageEpochProof::from_canonical_bytes(&inner) else {
                continue;
            };
            let hash: [u8; 32] = Sha256::digest(&inner).into();
            if self.named.contains(&hash) {
                continue;
            }
            if self.lines >= LINES_PER_FRAME {
                self.unlisted += 1;
                unlisted = self.unlisted == 1;
                continue;
            }
            if self.named.len() >= NAMED_KEPT {
                self.named.clear();
            }
            self.named.insert(hash);
            self.lines += 1;
            out.push(describe(&proof, reason));
        }
        (out, unlisted)
    }
}

/// The inner bytes of each storage epoch proof `raw` carries.
fn storage_proofs(raw: &[u8]) -> Vec<Vec<u8>> {
    if raw.get(..4) == Some(&TYPE_STORAGE_EPOCH_PROOF.to_be_bytes()[..]) {
        return vec![raw.to_vec()];
    }
    let Ok(bundle) =
        quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(raw)
    else {
        return Vec::new();
    };
    bundle
        .requests
        .into_iter()
        .flatten()
        .filter(|request| request.inner_type_prefix == TYPE_STORAGE_EPOCH_PROOF)
        .map(|request| request.inner_bytes)
        .collect()
}

fn describe(proof: &StorageEpochProof, reason: &str) -> Refused {
    let seats = proof
        .seats
        .iter()
        .take(SEATS_LISTED)
        .map(|seat| {
            let mut parts = Vec::new();
            if seat.settles {
                parts.push(format!("settles {}", seat.epoch));
            }
            if seat.seals {
                parts.push(format!("seals {}", seat.seal_epoch()));
            }
            format!("{}: {}", hex::encode(&seat.shard_filter), parts.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");
    let kind = if reason.contains(REFUSED_DUPLICATE) {
        "duplicate"
    } else if reason.contains(REFUSED_LATE) {
        "deadline_miss"
    } else {
        "other"
    };
    Refused {
        prover: hex::encode(&proof.member[..8]),
        seats,
        more_seats: proof.seats.len().saturating_sub(SEATS_LISTED),
        kind,
        reason: reason.chars().take(REASON_CHARS).collect(),
    }
}

static LOG: Mutex<Option<RefusalLog>> = Mutex::new(None);

/// Logs the storage epoch proofs in `raw` that validation for GLOBAL frame
/// `frame` refused with `reason` ([`RefusalLog::refused`]).
pub(crate) fn note(frame: u64, raw: &[u8], reason: &str) {
    let (refused, unlisted) = {
        let mut guard = LOG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .get_or_insert_with(RefusalLog::default)
            .refused(frame, raw, reason)
    };
    for refused in refused {
        tracing::info!(
            frame,
            prover = %refused.prover,
            seats = %refused.seats,
            more_seats = refused.more_seats,
            kind = refused.kind,
            reason = %refused.reason,
            scope = "peer",
            "storage epoch proof refused: GLOBAL drops the whole proof, so this prover loses each \
             settlement and seal in it that GLOBAL has not applied, unless it sends another in time; \
             duplicate: a part GLOBAL already applied; deadline_miss: a part sent after the frame it \
             had to land by, the prover's node is late (its operator's logs say why); other: see \
             reason (reported once a proof)"
        );
    }
    if unlisted {
        tracing::info!(
            frame,
            listed = LINES_PER_FRAME,
            scope = "peer",
            "more storage epoch proofs refused in this frame than are named here; a later frame \
             refusing them again names them, and the mempool drop summary counts them all"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::global_intrinsic::storage_epoch_proof::SeatProof;
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

    fn proof(member: u8, epoch: u64) -> Vec<u8> {
        StorageEpochProof {
            member: [member; 32],
            seats: vec![SeatProof {
                shard_filter: vec![0xAB; 3],
                epoch,
                seals: true,
                settles: true,
                ..Default::default()
            }],
            proof: vec![1, 2, 3],
        }
        .to_canonical_bytes()
    }

    fn bundle(inner: Vec<u8>) -> Vec<u8> {
        CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest {
                inner_type_prefix: TYPE_STORAGE_EPOCH_PROOF,
                inner_bytes: inner,
            })],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn a_refused_storage_proof_names_its_prover_once() {
        let mut log = RefusalLog::default();
        let late = format!("storage epoch proof: epoch 12 began at frame 8640: {REFUSED_LATE}");
        let (named, unlisted) = log.refused(988_593, &bundle(proof(0x5C, 10)), &late);
        assert_eq!(
            named,
            vec![Refused {
                prover: "5c5c5c5c5c5c5c5c".into(),
                seats: "ababab: settles 10, seals 12".into(),
                more_seats: 0,
                kind: "deadline_miss",
                reason: late.clone(),
            }]
        );
        assert!(!unlisted);
        assert!(
            log.refused(988_594, &bundle(proof(0x5C, 10)), &late)
                .0
                .is_empty(),
            "named once, though refused every frame"
        );
        let copy = format!("x: {REFUSED_DUPLICATE}, sealed at frame 8000; {REFUSED_LATE}");
        let (named, _) = log.refused(988_594, &proof(0x5D, 10), &copy);
        assert_eq!(named[0].kind, "duplicate", "a bare proof, a late copy");
        assert!(log.refused(988_594, b"not a proof", "x").0.is_empty());

        // At most a frame's budget of lines; the rest wait for a later one.
        let mut log = RefusalLog::default();
        for member in 0..LINES_PER_FRAME as u8 {
            assert_eq!(log.refused(7, &bundle(proof(member, 1)), "x").0.len(), 1);
        }
        let (named, unlisted) = log.refused(7, &bundle(proof(0xEE, 1)), "x");
        assert!(named.is_empty() && unlisted, "over budget: one notice");
        let (_, unlisted) = log.refused(7, &bundle(proof(0xEF, 1)), "x");
        assert!(!unlisted, "the notice once a frame");
        assert_eq!(
            log.refused(8, &bundle(proof(0xEE, 1)), "x").0.len(),
            1,
            "named in a later frame"
        );
    }
}
