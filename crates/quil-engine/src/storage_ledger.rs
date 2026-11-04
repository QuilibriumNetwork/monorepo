//! The storage job reservations ([`crate::storage_jobs`]) of every node
//! process on one host. A master and its standalone workers each admit
//! their own jobs, so each could hold the jobs' share of the host's memory,
//! label leaves ahead up to its own cap and run work due now beyond the
//! share alone, all at once: a second process sees the first one's jobs
//! only once they have allocated.
//!
//! Each process keeps a record in a directory they share, beside the
//! storage labels ([`crate::storage_labels::install`]): `<id>.lock`, locked
//! for as long as the process runs, and `<id>.res`, replaced whenever its
//! jobs' reservations change, with the bytes they hold, the leaves it
//! labels ahead and whether work due now waits for memory. A record whose
//! lock is free belongs to a process that ended and is removed. The one
//! process running work due now beyond the share alone holds `alone.lock`.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// What one process's storage jobs hold, as its record says, or summed over
/// the other processes ([`HostLedger::others`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Held {
    /// Bytes their reservations hold.
    pub bytes: u64,
    /// Leaves labelled ahead.
    pub ahead: u64,
    /// Whether work due now waits for memory.
    pub due_waiting: bool,
}

const RECORD_LEN: usize = 17;

fn encode(held: Held) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[..8].copy_from_slice(&held.bytes.to_le_bytes());
    out[8..16].copy_from_slice(&held.ahead.to_le_bytes());
    out[16] = u8::from(held.due_waiting);
    out
}

fn decode(bytes: &[u8]) -> Option<Held> {
    if bytes.len() != RECORD_LEN || bytes[16] > 1 {
        return None;
    }
    Some(Held {
        bytes: u64::from_le_bytes(bytes[..8].try_into().ok()?),
        ahead: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        due_waiting: bytes[16] == 1,
    })
}

/// This process's record among the host's ([`crate::storage_jobs`]).
pub struct HostLedger {
    dir: PathBuf,
    id: String,
    /// Locked while this process runs.
    _lock: File,
    /// What the record says now.
    last: Mutex<Option<Held>>,
}

impl HostLedger {
    /// Keep this process's record in `dir`, under its process id.
    pub fn open(dir: &Path) -> io::Result<Self> {
        Self::open_as(dir, &std::process::id().to_string())
    }

    /// [`Self::open`] under `id`: a test's two processes in one.
    pub(crate) fn open_as(dir: &Path, id: &str) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{id}.lock"));
        // A process removing the record of an ended one with this id may
        // hold its lock a moment; the file it removes is not ours.
        let mut attempts = 0;
        let lock = loop {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            match file.try_lock() {
                Ok(()) if same_file(&file, &path) => break file,
                Ok(()) | Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(error)) => return Err(error),
            }
            attempts += 1;
            if attempts == 8 {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} is held by another process", path.display()),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let ledger = Self {
            dir: dir.to_path_buf(),
            id: id.to_string(),
            _lock: lock,
            last: Mutex::new(None),
        };
        ledger.publish(Held::default())?;
        Ok(ledger)
    }

    /// The directory holding the host's records.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Replace this process's record with `held`, unless it says so already.
    pub fn publish(&self, held: Held) -> io::Result<()> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if *last == Some(held) {
            return Ok(());
        }
        // Renamed into place, so a reader sees the old record or the new.
        let tmp = self.dir.join(format!(".{}.res.tmp", self.id));
        let mut file = File::create(&tmp)?;
        file.write_all(&encode(held))?;
        drop(file);
        std::fs::rename(&tmp, self.dir.join(format!("{}.res", self.id)))?;
        *last = Some(held);
        Ok(())
    }

    /// What the other processes' jobs hold, summed. The records of
    /// processes that ended are removed; one that cannot be read counts as
    /// holding nothing.
    pub fn others(&self) -> Held {
        let mut sum = Held::default();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return sum;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".res")) else {
                continue;
            };
            if id == self.id || id.starts_with('.') {
                continue;
            }
            if !self.alive(id) {
                continue;
            }
            if let Some(held) = std::fs::read(entry.path()).ok().and_then(|b| decode(&b)) {
                sum.bytes = sum.bytes.saturating_add(held.bytes);
                sum.ahead = sum.ahead.saturating_add(held.ahead);
                sum.due_waiting |= held.due_waiting;
            }
        }
        sum
    }

    /// Whether the process of record `id` runs: its lock is held. If not,
    /// its record is removed, under its lock.
    fn alive(&self, id: &str) -> bool {
        let lock = self.dir.join(format!("{id}.lock"));
        let Ok(file) = OpenOptions::new().write(true).open(&lock) else {
            let _ = std::fs::remove_file(self.dir.join(format!("{id}.res")));
            return false;
        };
        match file.try_lock() {
            Ok(()) => {
                let _ = std::fs::remove_file(self.dir.join(format!("{id}.res")));
                let _ = std::fs::remove_file(&lock);
                false
            }
            Err(TryLockError::WouldBlock) => true,
            // Cannot tell: count what it holds.
            Err(TryLockError::Error(_)) => true,
        }
    }

    /// The host's lock for work due now running alone beyond the jobs'
    /// share, held until the returned file drops; `None` while another
    /// holds it.
    pub fn try_alone(&self) -> Option<File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join("alone.lock"))
            .ok()?;
        file.try_lock().ok()?;
        Some(file)
    }

    /// Whether another process holds [`Self::try_alone`]'s lock: call it
    /// only while this process does not hold it.
    pub fn alone_elsewhere(&self) -> bool {
        self.try_alone().is_none()
    }
}

/// Whether `file` is still the file at `path` (no other process removed
/// and recreated it since it was opened).
fn same_file(file: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (file.metadata(), std::fs::metadata(path)) {
            (Ok(open), Ok(named)) => open.ino() == named.ino() && open.dev() == named.dev(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("quil-storage-ledger-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Each process reads what the others hold, not its own; the record of
    /// a process that ended is removed and counts nothing.
    #[test]
    fn a_ledger_sums_the_other_live_processes() {
        let dir = ledger_dir("sum");
        let a = HostLedger::open_as(&dir, "a").unwrap();
        let b = HostLedger::open_as(&dir, "b").unwrap();
        let c = HostLedger::open_as(&dir, "c").unwrap();
        a.publish(Held {
            bytes: 5,
            ahead: 1,
            due_waiting: false,
        })
        .unwrap();
        b.publish(Held {
            bytes: 7,
            ahead: 0,
            due_waiting: true,
        })
        .unwrap();
        c.publish(Held {
            bytes: 11,
            ahead: 1,
            due_waiting: false,
        })
        .unwrap();
        assert_eq!(
            a.others(),
            Held {
                bytes: 18,
                ahead: 1,
                due_waiting: true
            }
        );
        drop(c);
        assert_eq!(
            a.others(),
            Held {
                bytes: 7,
                ahead: 0,
                due_waiting: true
            }
        );
        assert!(!dir.join("c.res").exists() && !dir.join("c.lock").exists());
        assert!(
            HostLedger::open_as(&dir, "a").is_err(),
            "one process per record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One process at a time holds the alone lock.
    #[test]
    fn one_process_at_a_time_runs_alone() {
        let dir = ledger_dir("alone");
        let a = HostLedger::open_as(&dir, "a").unwrap();
        let b = HostLedger::open_as(&dir, "b").unwrap();
        let held = a.try_alone().unwrap();
        assert!(b.try_alone().is_none());
        assert!(b.alone_elsewhere());
        drop(held);
        assert!(!b.alone_elsewhere());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
