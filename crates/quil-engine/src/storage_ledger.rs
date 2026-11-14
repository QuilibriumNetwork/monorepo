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
//! labels ahead and whether work due now waits for memory, and the bytes
//! its storage labels have still to write
//! ([`HostLedger::publish_labels_pending`]). A record whose lock is free
//! belongs to a process that ended and is removed. The one process running
//! work due now beyond the share alone holds `alone.lock`. The one process
//! deciding what to grant holds `grant.lock`, from reading the records
//! until its own is written; the one admitting a leaf's labels to the disk
//! holds `labels.lock` likewise. They are OS file locks: the kernel frees
//! them when their process ends, however it ends.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

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

/// One process's record: what its storage jobs hold, and the bytes the
/// leaves its storage labels are being written for have still to write
/// (`crate::storage_labels::LabelStore`), or both summed over the other
/// processes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Record {
    held: Held,
    labels_pending: u64,
}

const RECORD_LEN: usize = 25;

fn encode(record: Record) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[..8].copy_from_slice(&record.held.bytes.to_le_bytes());
    out[8..16].copy_from_slice(&record.held.ahead.to_le_bytes());
    out[16] = u8::from(record.held.due_waiting);
    out[17..].copy_from_slice(&record.labels_pending.to_le_bytes());
    out
}

fn decode(bytes: &[u8]) -> Option<Record> {
    if bytes.len() != RECORD_LEN || bytes[16] > 1 {
        return None;
    }
    Some(Record {
        held: Held {
            bytes: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            ahead: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            due_waiting: bytes[16] == 1,
        },
        labels_pending: u64::from_le_bytes(bytes[17..].try_into().ok()?),
    })
}

/// This process's record among the host's ([`crate::storage_jobs`]).
pub struct HostLedger {
    dir: PathBuf,
    id: String,
    /// Locked while this process runs.
    _lock: File,
    /// What the record is to say, and what it says now (`None` until
    /// written).
    record: Mutex<(Record, Option<Record>)>,
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
            record: Mutex::new((Record::default(), None)),
        };
        ledger.update(|_| {})?;
        Ok(ledger)
    }

    /// The directory holding the host's records.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Say in this process's record that its jobs hold `held`.
    pub fn publish(&self, held: Held) -> io::Result<()> {
        self.update(|record| record.held = held)
    }

    /// Say in this process's record that its storage labels have `bytes`
    /// still to write, for the other processes' labels on the host's disk
    /// ([`Self::others_labels_pending`]).
    pub fn publish_labels_pending(&self, bytes: u64) -> io::Result<()> {
        self.update(|record| record.labels_pending = bytes)
    }

    /// Change this process's record by `change` and write it, unless it
    /// says so already. One that could not be written is written whole at
    /// the next change.
    fn update(&self, change: impl FnOnce(&mut Record)) -> io::Result<()> {
        let mut guard = self.record.lock().unwrap_or_else(PoisonError::into_inner);
        let (wanted, written) = &mut *guard;
        change(wanted);
        if *written == Some(*wanted) {
            return Ok(());
        }
        // Renamed into place, so a reader sees the old record or the new.
        let tmp = self.dir.join(format!(".{}.res.tmp", self.id));
        let mut file = File::create(&tmp)?;
        file.write_all(&encode(*wanted))?;
        drop(file);
        std::fs::rename(&tmp, self.dir.join(format!("{}.res", self.id)))?;
        *written = Some(*wanted);
        Ok(())
    }

    /// What the other processes' jobs hold, summed. The records of
    /// processes that ended are removed; one that cannot be read counts as
    /// holding nothing.
    pub fn others(&self) -> Held {
        self.others_summed().held
    }

    /// The bytes the other processes' storage labels have still to write,
    /// summed, as [`Self::others`] reads them.
    pub fn others_labels_pending(&self) -> u64 {
        self.others_summed().labels_pending
    }

    fn others_summed(&self) -> Record {
        let mut sum = Record::default();
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
            if let Some(record) = std::fs::read(entry.path()).ok().and_then(|b| decode(&b)) {
                let held = record.held;
                sum.held.bytes = sum.held.bytes.saturating_add(held.bytes);
                sum.held.ahead = sum.held.ahead.saturating_add(held.ahead);
                sum.held.due_waiting |= held.due_waiting;
                sum.labels_pending = sum.labels_pending.saturating_add(record.labels_pending);
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

    /// The host's lock over one process's decision on what to grant: held
    /// from reading the records until this process's own is written, and
    /// freed when the returned file drops or the process ends. Waits up to
    /// `wait`; `None` when another still holds it, an error when the
    /// directory cannot be used.
    pub fn grant_turn(&self, wait: Duration) -> io::Result<Option<File>> {
        self.turn("grant.lock", wait)
    }

    /// [`Self::grant_turn`] for admitting a leaf's labels to the disk
    /// (`crate::storage_labels::LabelStore::admit`): held from reading the
    /// others' labels still to write until this process's own record counts
    /// the leaf.
    pub fn labels_turn(&self, wait: Duration) -> io::Result<Option<File>> {
        self.turn("labels.lock", wait)
    }

    fn turn(&self, name: &str, wait: Duration) -> io::Result<Option<File>> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join(name))?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Some(file)),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(error)) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The host's lock for work due now running alone beyond the jobs'
    /// share, held until the returned file drops; `None` while another
    /// holds it, an error when the directory cannot be used.
    pub fn try_alone(&self) -> io::Result<Option<File>> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join("alone.lock"))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    /// Whether another process holds [`Self::try_alone`]'s lock: call it
    /// only while this process does not hold it.
    pub fn alone_elsewhere(&self) -> bool {
        matches!(self.try_alone(), Ok(None))
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
        let held = a.try_alone().unwrap().unwrap();
        assert!(b.try_alone().unwrap().is_none());
        assert!(b.alone_elsewhere());
        drop(held);
        assert!(!b.alone_elsewhere());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One process at a time has the turn to decide; another's wait for it
    /// is bounded, and it has it once the first gives it up.
    #[test]
    fn one_process_at_a_time_has_the_turn_to_decide() {
        let dir = ledger_dir("turn");
        let a = HostLedger::open_as(&dir, "a").unwrap();
        let b = HostLedger::open_as(&dir, "b").unwrap();
        let turn = a.grant_turn(Duration::ZERO).unwrap().unwrap();
        let asked = Instant::now();
        assert!(b.grant_turn(Duration::from_millis(50)).unwrap().is_none());
        assert!(asked.elapsed() >= Duration::from_millis(50));
        drop(turn);
        assert!(b.grant_turn(Duration::ZERO).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Not a test of its own: the process [`a_killed_process_frees_its_turn_and_its_record`]
    /// starts and kills, keeping a record and the turn.
    #[test]
    fn child_process_keeping_the_turn() {
        let Ok(dir) = std::env::var("QUIL_TEST_LEDGER_CHILD") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let ledger = HostLedger::open(&dir).unwrap();
        ledger
            .publish(Held {
                bytes: 5,
                ahead: 0,
                due_waiting: false,
            })
            .unwrap();
        let _turn = ledger.grant_turn(Duration::from_secs(60)).unwrap().unwrap();
        std::fs::write(dir.join(format!("child-{}.ready", std::process::id())), b"").unwrap();
        std::thread::sleep(Duration::from_secs(600));
    }

    /// A process that dies keeping the turn wedges nothing: the kernel frees
    /// it. Its record goes with it, and the same directory serves the process
    /// started after it, read and written.
    #[test]
    fn a_killed_process_frees_its_turn_and_its_record() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = ledger_dir("killed");
        let here = HostLedger::open_as(&dir, "here").unwrap();
        for round in 0..2 {
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "storage_ledger::tests::child_process_keeping_the_turn",
                    ])
                    .env("QUIL_TEST_LEDGER_CHILD", &dir)
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let ready = dir.join(format!("child-{}.ready", child.0.id()));
            let deadline = Instant::now() + Duration::from_secs(120);
            while !ready.exists() {
                assert!(Instant::now() < deadline, "round {round}: no child ready");
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "round {round}: the child ended"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(here.others().bytes, 5, "round {round}: its record is read");
            assert!(here.grant_turn(Duration::ZERO).unwrap().is_none());
            drop(child);
            assert!(
                here.grant_turn(Duration::ZERO).unwrap().is_some(),
                "round {round}: the turn is freed with its process"
            );
            assert_eq!(
                here.others().bytes,
                0,
                "round {round}: its record went with it"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
