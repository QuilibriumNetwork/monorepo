//! Which seats' storage for the epoch their renewal registers the confirm
//! pipeline last found encoding or encoded (`ProverLifecycle::note_renewal_storage`),
//! kept in the node's store. The capacity shed spares those seats; its first
//! run after a restart comes before the pipeline prepares any seat again, so
//! a note held only in memory left that run free to shed a seat whose
//! snapshot was encoding (devnet, 2026-10-29).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// A seat's storage work for the epoch its renewal registers, as the confirm
/// pipeline last prepared it (`ProverLifecycle::note_renewal_storage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenewalStorage {
    /// Its snapshot is requested and not encoded yet: queued or encoding
    /// (`QuilError::StorageSnapshotPending`).
    Encoding,
    /// Its snapshot is encoded: the confirm registers its leaves.
    Encoded,
}

impl RenewalStorage {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::Encoded => "encoded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Note {
    filter: Vec<u8>,
    epoch: u64,
    storage: RenewalStorage,
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    version: u8,
    notes: Vec<Note>,
}

const MAX_NOTES: usize = 4096;
const MAX_JOURNAL_BYTES: usize = 1_048_576;

#[derive(Default)]
struct State {
    /// Each seat's storage work, with the epoch it registers.
    seats: HashMap<Vec<u8>, (u64, RenewalStorage)>,
    store: Option<(Arc<quil_store::RocksDb>, Vec<u8>)>,
    /// The epoch a failed save was last warned of in.
    save_warned: Option<u64>,
}

#[derive(Default)]
pub(crate) struct RenewalStorageNotes(Mutex<State>);

fn load(db: &quil_store::RocksDb, key: &[u8]) -> Result<Vec<Note>, String> {
    use quil_types::store::KvDb;
    let Some(bytes) = db.get(key).map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(format!("{} bytes, over the size limit", bytes.len()));
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if journal.version != 1
        || journal.notes.len() > MAX_NOTES
        || journal
            .notes
            .iter()
            .any(|n| n.filter.is_empty() || n.filter.len() > 256)
    {
        return Err("invalid records".into());
    }
    Ok(journal.notes)
}

impl RenewalStorageNotes {
    /// Restore the notes this prover saved before a restart and save every
    /// later change. Called once at startup, before the lifecycle evaluates.
    /// An unreadable journal is warned of and replaced: the shed then spares
    /// a seat once the confirm pipeline prepares it again.
    pub(crate) fn attach(&self, db: Arc<quil_store::RocksDb>, address: &[u8]) {
        let mut key = b"local:lifecycle:renewal-storage:v1:".to_vec();
        key.extend_from_slice(address);
        let notes = load(&db, &key).unwrap_or_else(|error| {
            warn!(%error, scope = "this node",
                action = "none: the notes are rebuilt as the confirm pipeline prepares each seat",
                "saved capacity-shed storage notes unreadable and discarded: until the confirm \
                 pipeline prepares a renewing seat again, the capacity shed does not know its \
                 storage is encoding and may take it");
            Vec::new()
        });
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        state.seats = notes
            .into_iter()
            .map(|n| (n.filter, (n.epoch, n.storage)))
            .collect();
        state.store = Some((db, key));
        if !state.seats.is_empty() {
            let mut seats: Vec<String> = state
                .seats
                .iter()
                .map(|(f, (epoch, s))| format!("{}:{}@{epoch}", hex::encode(f), s.name()))
                .collect();
            seats.sort();
            info!(
                restored = seats.len(),
                ?seats,
                scope = "local",
                "capacity-shed storage notes restored from before the restart: the shed spares \
                 these seats (seat:storage@epoch it registers) until each renews or its grace \
                 frame passes"
            );
        }
    }

    /// Record the seats whose storage for `epoch` is `encoded` or `encoding`,
    /// forget notes for earlier epochs, and save the notes if they changed.
    pub(crate) fn note(&self, epoch: u64, encoded: &[Vec<u8>], encoding: &[Vec<u8>]) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let before = state.seats.clone();
        state.seats.retain(|_, (registers, _)| *registers >= epoch);
        for (filters, storage) in [
            (encoding, RenewalStorage::Encoding),
            (encoded, RenewalStorage::Encoded),
        ] {
            for filter in filters.iter().filter(|f| !f.is_empty()) {
                state.seats.insert(filter.clone(), (epoch, storage));
            }
        }
        if state.seats == before {
            return;
        }
        if let Err(error) = Self::save(&state) {
            if state.save_warned.is_none_or(|warned| warned < epoch) {
                state.save_warned = Some(epoch);
                warn!(epoch, %error, seats = state.seats.len(), scope = "this node",
                    action = "check this node's store (disk space, permissions)",
                    "capacity-shed storage note not saved: after a restart the shed may take a \
                     seat whose storage is encoding before the confirm pipeline prepares it again \
                     (warned once per epoch)");
            }
        }
    }

    /// Write the notes under the lock that changed them, so saves land in
    /// the order of the changes. Unsynced: a save outlives the process, and
    /// a note lost with the host costs one shed's spare.
    fn save(state: &State) -> Result<(), String> {
        let Some((db, key)) = &state.store else {
            return Ok(());
        };
        let mut notes: Vec<Note> = state
            .seats
            .iter()
            .map(|(filter, (epoch, storage))| Note {
                filter: filter.clone(),
                epoch: *epoch,
                storage: *storage,
            })
            .collect();
        notes.sort_by(|a, b| a.filter.cmp(&b.filter));
        notes.truncate(MAX_NOTES);
        let bytes =
            serde_json::to_vec(&Journal { version: 1, notes }).map_err(|e| e.to_string())?;
        db.inner().put(key, bytes).map_err(|e| e.to_string())
    }

    /// `filter`'s storage work and the epoch it registers, if noted.
    pub(crate) fn get(&self, filter: &[u8]) -> Option<(u64, RenewalStorage)> {
        self.0.lock().ok()?.seats.get(filter).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_survive_a_restart_and_drop_past_epochs() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let (a, b) = (vec![0xA1; 8], vec![0xA2; 8]);
        let first = RenewalStorageNotes::default();
        first.attach(db.clone(), &[7; 32]);
        first.note(2, &[a.clone()], &[b.clone()]);
        let restarted = RenewalStorageNotes::default();
        restarted.attach(db.clone(), &[7; 32]);
        assert_eq!(restarted.get(&a), Some((2, RenewalStorage::Encoded)));
        assert_eq!(restarted.get(&b), Some((2, RenewalStorage::Encoding)));
        // Another prover's notes are its own.
        let other = RenewalStorageNotes::default();
        other.attach(db.clone(), &[8; 32]);
        assert_eq!(other.get(&a), None);
        // A later epoch's note replaces the earlier ones, saved too.
        restarted.note(3, &[], &[a.clone()]);
        let again = RenewalStorageNotes::default();
        again.attach(db, &[7; 32]);
        assert_eq!(again.get(&a), Some((3, RenewalStorage::Encoding)));
        assert_eq!(again.get(&b), None);
    }

    #[test]
    fn an_unreadable_journal_starts_empty() {
        use quil_types::store::KvDb;
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let mut key = b"local:lifecycle:renewal-storage:v1:".to_vec();
        key.extend_from_slice(&[7; 32]);
        db.inner().put(&key, b"not json".to_vec()).unwrap();
        assert!(db.get(&key).unwrap().is_some());
        let notes = RenewalStorageNotes::default();
        notes.attach(db.clone(), &[7; 32]);
        assert_eq!(notes.get(&[0xA1; 8]), None);
        notes.note(2, &[vec![0xA1; 8]], &[]);
        let restarted = RenewalStorageNotes::default();
        restarted.attach(db, &[7; 32]);
        assert_eq!(
            restarted.get(&[0xA1; 8]),
            Some((2, RenewalStorage::Encoded))
        );
    }
}
