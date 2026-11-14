//! Which committee session each of this prover's seats was last seen hosted
//! in, by which worker and at which GLOBAL frame, kept in the node's store.
//!
//! A restart otherwise cannot tell a worker that is starting from one that
//! has not hosted for long, so a seat whose worker is seen unable to host
//! after the start waits a settle period before it renews
//! ([`super::session_hosting::settle_frames`], 60 frames on mainnet). Near
//! the epoch's end that wait outlasted the renewal window. A seat restored
//! here is held to the epoch rule from its last hosted frame instead
//! ([`super::session_hosting::SessionHosting::resume`]).
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::warn;

/// A seat's latest hosting observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hosted {
    pub core_id: u32,
    /// The id of the committee session that counted the seat.
    pub session: [u8; 32],
    /// The GLOBAL frame the worker was last seen hosting it, at most
    /// [`save_step`] frames before the latest such observation.
    pub frame: u64,
}

#[derive(Serialize, Deserialize)]
struct Record {
    filter: Vec<u8>,
    core_id: u32,
    session: Vec<u8>,
    frame: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    version: u8,
    seats: Vec<Record>,
}

const KEY_PREFIX: &[u8] = b"local:lifecycle:session-hosting:v1:";
const MAX_SEATS: usize = 4096;
const MAX_JOURNAL_BYTES: usize = 1_048_576;

/// Frames a seat still hosted in the same session goes between saves: a
/// sixth of the settle period, 10 frames on mainnet.
pub(crate) fn save_step(epoch_frames: u64) -> u64 {
    (super::session_hosting::settle_frames(epoch_frames) / 6).max(1)
}

#[derive(Default)]
struct State {
    seats: HashMap<Vec<u8>, Hosted>,
    saved: HashMap<Vec<u8>, Hosted>,
    store: Option<(Arc<quil_store::RocksDb>, Vec<u8>)>,
    /// The frame a failed save was last warned of at.
    save_warned: Option<u64>,
}

#[derive(Default)]
pub(crate) struct HostedSessions(Mutex<State>);

fn load(db: &quil_store::RocksDb, key: &[u8]) -> Result<HashMap<Vec<u8>, Hosted>, String> {
    use quil_types::store::KvDb;
    let Some(bytes) = db.get(key).map_err(|e| e.to_string())? else {
        return Ok(HashMap::new());
    };
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(format!("{} bytes, over the size limit", bytes.len()));
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if journal.version != 1 || journal.seats.len() > MAX_SEATS {
        return Err("invalid records".into());
    }
    journal
        .seats
        .into_iter()
        .map(|record| {
            let session: [u8; 32] = record
                .session
                .as_slice()
                .try_into()
                .map_err(|_| "invalid session id".to_string())?;
            if record.filter.is_empty() || record.filter.len() > 256 {
                return Err("invalid filter".to_string());
            }
            Ok((
                record.filter,
                Hosted {
                    core_id: record.core_id,
                    session,
                    frame: record.frame,
                },
            ))
        })
        .collect()
}

impl HostedSessions {
    /// Restore the observations this prover saved before a restart, for
    /// [`super::session_hosting::SessionHosting::restore`], and save every
    /// later change. Called once at startup, before the lifecycle evaluates.
    /// An unreadable journal is warned of and replaced: each seat whose
    /// worker is seen unable to host then waits out the settle period.
    pub(crate) fn attach(
        &self,
        db: Arc<quil_store::RocksDb>,
        address: &[u8],
    ) -> HashMap<Vec<u8>, Hosted> {
        let mut key = KEY_PREFIX.to_vec();
        key.extend_from_slice(address);
        let seats = load(&db, &key).unwrap_or_else(|error| {
            warn!(%error, scope = "this node",
                action = "none: the records are rebuilt as workers are seen hosting",
                "saved session-hosting records unreadable and discarded: after this start, a seat whose \
                 worker is not hosting yet waits the settle period before it renews");
            HashMap::new()
        });
        let Ok(mut state) = self.0.lock() else {
            return seats;
        };
        state.seats = seats.clone();
        state.saved = seats.clone();
        state.store = Some((db, key));
        seats
    }

    /// Record at GLOBAL `frame` the seats in `hosted`, each with the worker
    /// hosting it and the id of the session that counts it, and forget a
    /// seat not in `bound` once its record is over a settle period old: it
    /// can spare no seat then ([`super::session_hosting::SessionHosting::resume`]),
    /// and until then a worker bound to the seat a few frames after a start
    /// still resumes. A seat not hosted now keeps its last hosted frame.
    /// Saved when a seat is added, rebound, moves to another session or is
    /// forgotten, or when a seat's frame is [`save_step`] past its saved one.
    pub(crate) fn note(
        &self,
        frame: u64,
        epoch_frames: u64,
        hosted: &[(Vec<u8>, u32, [u8; 32])],
        bound: &HashSet<Vec<u8>>,
    ) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        for (filter, core_id, session) in hosted {
            state.seats.insert(
                filter.clone(),
                Hosted {
                    core_id: *core_id,
                    session: *session,
                    frame,
                },
            );
        }
        let settle = super::session_hosting::settle_frames(epoch_frames);
        state.seats.retain(|filter, hosted| {
            bound.contains(filter) || frame <= hosted.frame.saturating_add(settle)
        });
        let step = save_step(epoch_frames);
        let due = state.seats.len() != state.saved.len()
            || state
                .seats
                .iter()
                .any(|(filter, now)| match state.saved.get(filter) {
                    None => true,
                    Some(saved) => {
                        saved.core_id != now.core_id
                            || saved.session != now.session
                            || now.frame.saturating_sub(saved.frame) >= step
                    }
                });
        if !due {
            return;
        }
        match Self::save(&state) {
            Ok(()) => state.saved = state.seats.clone(),
            Err(error) => {
                if state
                    .save_warned
                    .is_none_or(|warned| frame.saturating_sub(warned) >= epoch_frames)
                {
                    state.save_warned = Some(frame);
                    warn!(frame, %error, seats = state.seats.len(), scope = "this node",
                        action = "check this node's store (disk space, permissions)",
                        "session-hosting record not saved: after a restart, a seat whose worker is not \
                         hosting yet waits the settle period before it renews (warned once per epoch)");
                }
            }
        }
    }

    /// Write the records under the lock that changed them. Unsynced: a save
    /// outlives the process, and a record lost with the host costs one
    /// settle period.
    fn save(state: &State) -> Result<(), String> {
        let Some((db, key)) = &state.store else {
            return Ok(());
        };
        let mut seats: Vec<Record> = state
            .seats
            .iter()
            .map(|(filter, hosted)| Record {
                filter: filter.clone(),
                core_id: hosted.core_id,
                session: hosted.session.to_vec(),
                frame: hosted.frame,
            })
            .collect();
        seats.sort_by(|a, b| a.filter.cmp(&b.filter));
        seats.truncate(MAX_SEATS);
        let bytes =
            serde_json::to_vec(&Journal { version: 1, seats }).map_err(|e| e.to_string())?;
        db.inner().put(key, bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 720;

    /// Records survive a restart, are saved only every save step while a
    /// seat stays in its session, at once when it moves, are kept for a
    /// seat not bound for a settle period, and belong to their prover; an
    /// unreadable journal starts empty.
    #[test]
    fn hosting_records_survive_a_restart_saved_by_step_and_change() {
        use quil_types::store::KvDb;
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let (a, b) = (vec![0xA1; 32], vec![0xA2; 32]);
        let bound: HashSet<Vec<u8>> = [a.clone(), b.clone()].into();
        let step = save_step(EPOCH);
        let restored = |address: u8| HostedSessions::default().attach(db.clone(), &[address; 32]);

        let both = [(a.clone(), 1, [1; 32]), (b.clone(), 2, [2; 32])];
        let first = HostedSessions::default();
        assert!(first.attach(db.clone(), &[7; 32]).is_empty());
        first.note(100, EPOCH, &both, &bound);
        first.note(100 + step - 1, EPOCH, &both, &bound);
        assert_eq!(
            restored(7).get(&a),
            Some(&Hosted {
                core_id: 1,
                session: [1; 32],
                frame: 100
            }),
            "hosting_record_not_restored: a seat in the same session saves every step"
        );
        first.note(100 + step, EPOCH, &both, &bound);
        assert_eq!(restored(7).get(&b).map(|h| h.frame), Some(100 + step));
        first.note(100 + 2 * step, EPOCH, &both[..1], &bound);
        assert_eq!(restored(7).get(&a).map(|h| h.frame), Some(100 + 2 * step));
        assert_eq!(
            restored(7).get(&b).map(|h| h.frame),
            Some(100 + step),
            "a seat not hosted now keeps its last hosted frame"
        );
        first.note(
            100 + 2 * step + 1,
            EPOCH,
            &[(a.clone(), 1, [3; 32])],
            &bound,
        );
        assert_eq!(
            restored(7).get(&a).map(|h| h.session),
            Some([3; 32]),
            "a new session saves at once"
        );
        let only_a: HashSet<Vec<u8>> = [a.clone()].into();
        let settle = crate::provers::session_hosting::settle_frames(EPOCH);
        first.note(100 + 2 * step + 2, EPOCH, &[], &only_a);
        assert_eq!(
            restored(7).get(&b).map(|h| h.frame),
            Some(100 + step),
            "unbound_seat_record_dropped: a seat not bound yet keeps its record a settle period"
        );
        first.note(100 + step + settle, EPOCH, &[], &only_a);
        assert!(restored(7).contains_key(&b));
        first.note(100 + step + settle + 1, EPOCH, &[], &only_a);
        assert!(
            !restored(7).contains_key(&b),
            "an unbound seat is forgotten once its record is a settle period old"
        );
        assert!(
            restored(8).is_empty(),
            "another prover's records are its own"
        );

        let mut key = KEY_PREFIX.to_vec();
        key.extend_from_slice(&[7; 32]);
        db.inner().put(&key, b"not json").unwrap();
        assert!(db.get(&key).unwrap().is_some());
        assert!(restored(7).is_empty());
    }
}
