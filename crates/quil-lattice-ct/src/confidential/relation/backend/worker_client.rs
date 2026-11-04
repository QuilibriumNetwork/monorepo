//! Caller-owned configuration for an isolated amount-proof verifier.
//! Clones share a single worker slot; busy/error outcomes are local unavailability.
use super::{
    worker_process::{run_worker, run_worker_capped, WorkerError, READINESS_REQUEST},
    worker_request::{RequestError, WorkerRequest},
};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum ClientError {
    Configuration,
    Busy,
    Poisoned,
    Request(RequestError),
    Process(WorkerError),
}

/// Slot time this process's verifications held, summed over slots, in
/// microseconds, and the longest one since it was last taken
/// ([`slot_busy_total`], [`take_longest_slot_hold`]).
static SLOT_BUSY_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SLOT_LONGEST_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A verification holding its slots, counted when it ends.
struct SlotHeld(Instant);

impl Drop for SlotHeld {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        let micros = self.0.elapsed().as_micros();
        let micros = u64::try_from(micros).unwrap_or(u64::MAX);
        SLOT_BUSY_MICROS.fetch_add(micros, Relaxed);
        SLOT_LONGEST_MICROS.fetch_max(micros, Relaxed);
    }
}

/// How long this process's verifications have held verifier slots since it
/// started, summed over slots: from admission to the worker's exit, whatever
/// the verdict. An interval's difference over its length and the slot count
/// is the slots' utilization.
pub fn slot_busy_total() -> Duration {
    use std::sync::atomic::Ordering::Relaxed;
    Duration::from_micros(SLOT_BUSY_MICROS.load(Relaxed))
}

/// The longest single verification since the last call, which starts the
/// next interval.
pub fn take_longest_slot_hold() -> Duration {
    use std::sync::atomic::Ordering::Relaxed;
    Duration::from_micros(SLOT_LONGEST_MICROS.swap(0, Relaxed))
}

/// Waiters admitted per slot before further callers are refused outright, so
/// a stalled verifier cannot accumulate blocked threads without bound.
const MAX_WAITERS_PER_SLOT: usize = 4;

/// In-process admission slots shared by every clone of one client.
///
/// Callers that may wait are served fairly across LANES (one per execution
/// manager): a free slot goes to the waiting lane that was admitted least
/// recently, oldest first within a lane. One busy shard therefore cannot keep
/// the global engine or another shard out indefinitely, which plain
/// first-come admission allowed. (Counting verifications in flight would not
/// do: with a single slot every lane has none at the moment one is released.)
struct Slots {
    max: usize,
    state: Mutex<SlotState>,
    freed: Condvar,
}

#[derive(Default)]
struct SlotState {
    used: usize,
    next_ticket: u64,
    /// `(ticket, lane)` of every caller currently waiting.
    waiting: Vec<(u64, u32)>,
    /// Admission sequence number of each lane's latest admission.
    last_admitted: HashMap<u32, u64>,
    admissions: u64,
}

impl SlotState {
    fn next_admitted(&self) -> Option<u64> {
        self.waiting
            .iter()
            .min_by_key(|(ticket, lane)| {
                (self.last_admitted.get(lane).copied().unwrap_or(0), *ticket)
            })
            .map(|(ticket, _)| *ticket)
    }

    fn admit(&mut self, lane: u32) {
        self.used += 1;
        self.admissions += 1;
        self.last_admitted.insert(lane, self.admissions);
    }
}

impl Slots {
    fn new(max: usize) -> Self {
        Self {
            max,
            state: Mutex::new(SlotState::default()),
            freed: Condvar::new(),
        }
    }
}

struct LocalPermit<'a>(&'a Slots);
impl Drop for LocalPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.used = state.used.saturating_sub(1);
        }
        self.0.freed.notify_all();
    }
}

#[derive(Clone)]
pub struct WorkerVerifier {
    executable: PathBuf,
    cpu_seconds: u64,
    wall_timeout: Duration,
    address_space_bytes: Option<u64>,
    /// Native aggregation threads per child (`QUIL_NATIVE_AGGREGATION_THREADS`).
    native_threads: Option<u8>,
    slots: Arc<Slots>,
    shared_admission: Option<Arc<SharedAdmission>>,
    /// Fairness lane of this clone; see [`Slots`].
    lane: u32,
    /// How long `verify` may wait for a slot. Zero refuses at once (`Busy`).
    admission_wait: Duration,
    /// Resident-memory cap enforced on each child by this process.
    max_resident_bytes: Option<u64>,
    /// Argument placed before the worker arguments, for an executable that is
    /// the worker only in a mode (a node running itself as its worker).
    worker_mode_arg: Option<&'static str>,
    /// A background verification (see [`Self::background`]).
    background: bool,
}

/// Node-wide admission: one lock file per slot (`<path>` for slot 0, then
/// `<path>.1`, `<path>.2`, …), each held with `flock`, which conflicts across
/// open file descriptions, so independent clients in one process and other
/// node processes all count against the same slots.
struct SharedAdmission {
    path: PathBuf,
    files: Vec<std::fs::File>,
}

impl SharedAdmission {
    fn slot_path(path: &std::path::Path, slot: usize) -> PathBuf {
        if slot == 0 {
            path.to_path_buf()
        } else {
            let mut name = path.as_os_str().to_os_string();
            name.push(format!(".{slot}"));
            PathBuf::from(name)
        }
    }

    fn open(path: PathBuf, slots: usize) -> Result<Self, ClientError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut files = Vec::with_capacity(slots);
            for slot in 0..slots {
                files.push(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .mode(0o600)
                        .open(Self::slot_path(&path, slot))
                        .map_err(|e| ClientError::Process(WorkerError::Io(e)))?,
                );
            }
            Ok(Self { path, files })
        }
        #[cfg(not(unix))]
        {
            let _ = (path, slots);
            Err(ClientError::Configuration)
        }
    }
}

impl WorkerVerifier {
    /// The executable must be chosen by trusted local configuration. This
    /// requires an absolute path but does not attest or pin the binary's bytes.
    /// CPU and wall limits do not cap native workspace memory.
    pub fn new(
        executable: PathBuf,
        cpu_seconds: u64,
        wall_timeout: Duration,
    ) -> Result<Self, ClientError> {
        if !executable.is_absolute()
            || !(1..=3600).contains(&cpu_seconds)
            || wall_timeout.is_zero()
            || wall_timeout > Duration::from_secs(3600)
        {
            return Err(ClientError::Configuration);
        }
        // Normally recorded at startup already; see the function.
        super::worker_process::remember_process_cpus();
        Ok(Self {
            executable,
            cpu_seconds,
            wall_timeout,
            address_space_bytes: None,
            native_threads: None,
            slots: Arc::new(Slots::new(1)),
            shared_admission: None,
            lane: 0,
            admission_wait: Duration::ZERO,
            max_resident_bytes: None,
            worker_mode_arg: None,
            background: false,
        })
    }

    /// A clone for background verifications (work no finalized frame waits
    /// on yet). With more than one node-wide slot it never takes the first
    /// one, which stays for frames and inline verifications in every node
    /// process: `flock` has no fair queue, so without the reservation the
    /// background work of other processes could hold every slot while a
    /// frame waited. With a single slot nothing can be reserved.
    pub fn background(&self) -> Self {
        let mut clone = self.clone();
        clone.background = true;
        clone
    }

    /// Start the executable with `arg` first, selecting its worker mode.
    pub fn with_worker_mode_arg(mut self, arg: &'static str) -> Self {
        self.worker_mode_arg = Some(arg);
        self
    }

    /// Allow up to `max` verifications in flight per node (1..=64). Every
    /// clone made after this call shares the slots; the node-wide admission
    /// file gets the same number of byte-range slots. Memory scales with the
    /// number of concurrent children (≈1 GB each at depth 32).
    pub fn with_concurrency(mut self, max: usize) -> Result<Self, ClientError> {
        if !(1..=64).contains(&max) {
            return Err(ClientError::Configuration);
        }
        self.slots = Arc::new(Slots::new(max));
        if let Some(shared) = self.shared_admission.take() {
            self.shared_admission =
                Some(Arc::new(SharedAdmission::open(shared.path.clone(), max)?));
        }
        Ok(self)
    }

    /// Cap the native aggregation threads of each child (1..=8). With N
    /// concurrent children, N × threads should not exceed the machine's cores.
    pub fn with_native_threads(mut self, threads: u8) -> Result<Self, ClientError> {
        if !(1..=8).contains(&threads) {
            return Err(ClientError::Configuration);
        }
        self.native_threads = Some(threads);
        Ok(self)
    }

    /// Number of verifications this client admits concurrently.
    pub fn concurrency(&self) -> usize {
        self.slots.max
    }

    /// A clone that waits and is accounted in its own fairness lane. Give each
    /// execution manager its own lane; clones of one lane share its standing.
    pub fn for_lane(&self, lane: u32) -> Self {
        let mut clone = self.clone();
        clone.lane = lane;
        clone
    }

    /// Let `verify` wait up to `wait` (at most 60 s) for a slot instead of
    /// refusing at once. Waiting callers are served fairly across lanes and
    /// their number is bounded; past that bound, and at the deadline, the
    /// outcome is still `Busy` (local unavailability).
    pub fn with_admission_wait(mut self, wait: Duration) -> Result<Self, ClientError> {
        if wait > Duration::from_secs(60) {
            return Err(ClientError::Configuration);
        }
        self.admission_wait = wait;
        Ok(self)
    }

    /// Kill a child whose resident memory exceeds `bytes` (sampled by this
    /// process; portable across Linux and macOS, unlike the address-space cap).
    pub fn with_resident_limit(mut self, bytes: u64) -> Result<Self, ClientError> {
        if bytes == 0 || !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(ClientError::Configuration);
        }
        self.max_resident_bytes = Some(bytes);
        Ok(self)
    }

    fn acquire_local(&self, deadline: Instant) -> Result<LocalPermit<'_>, ClientError> {
        let slots = &*self.slots;
        let mut state = slots.state.lock().map_err(|_| ClientError::Poisoned)?;
        if state.used < slots.max && state.waiting.is_empty() {
            state.admit(self.lane);
            return Ok(LocalPermit(slots));
        }
        if Instant::now() >= deadline || state.waiting.len() >= slots.max * MAX_WAITERS_PER_SLOT {
            return Err(ClientError::Busy);
        }
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        state.waiting.push((ticket, self.lane));
        loop {
            if state.used < slots.max && state.next_admitted() == Some(ticket) {
                state.waiting.retain(|(waiting, _)| *waiting != ticket);
                state.admit(self.lane);
                // Another slot may be free for the next waiter.
                slots.freed.notify_all();
                return Ok(LocalPermit(slots));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.waiting.retain(|(waiting, _)| *waiting != ticket);
                slots.freed.notify_all();
                return Err(ClientError::Busy);
            }
            state = match slots.freed.wait_timeout(state, remaining) {
                Ok((state, _)) => state,
                Err(_) => return Err(ClientError::Poisoned),
            };
        }
    }

    /// Join the node-wide verifier slots shared by independently started
    /// processes: `path` for slot 0 and `path.<n>` for further slots. The path
    /// is trusted local configuration on the node's local filesystem. Keep the
    /// files in place while any node process runs; replacing/unlinking one
    /// creates a different lock. OS process exit releases held locks.
    pub fn with_shared_admission(mut self, path: PathBuf) -> Result<Self, ClientError> {
        if !path.is_absolute() {
            return Err(ClientError::Configuration);
        }
        self.shared_admission = Some(Arc::new(SharedAdmission::open(path, self.slots.max)?));
        Ok(self)
    }

    /// Test-fixture constructor. CPU and wall limits come from
    /// `QUIL_TEST_WORKER_CPU_SECS` and `QUIL_TEST_WORKER_WALL_SECS` (seconds;
    /// both default to 600, CPU defaults to the wall value when only wall is
    /// set) and are clamped into the 1..=3600 policy range so slower
    /// platforms can raise the deadline without editing fixtures. This is a
    /// test convenience, not a node configuration path.
    pub fn from_test_env(executable: PathBuf) -> Result<Self, ClientError> {
        let wall = test_limit_secs(
            std::env::var("QUIL_TEST_WORKER_WALL_SECS").ok().as_deref(),
            600,
        );
        let cpu = test_limit_secs(
            std::env::var("QUIL_TEST_WORKER_CPU_SECS").ok().as_deref(),
            wall,
        );
        Self::new(executable, cpu, Duration::from_secs(wall))
    }

    /// Optional Linux mapping limit. Clone the configured client to share
    /// admission; this setting is never derived from transaction input.
    pub fn with_address_space_limit(mut self, bytes: u64) -> Result<Self, ClientError> {
        if !cfg!(target_os = "linux") || bytes == 0 || bytes >= i64::MAX as u64 {
            return Err(ClientError::Configuration);
        }
        self.address_space_bytes = Some(bytes);
        Ok(self)
    }

    /// Check executable startup, request ABI and configured OS limits within
    /// five seconds. This does not attest the binary or prove native correctness.
    pub fn check_ready(&self) -> Result<(), ClientError> {
        let _permit = self.acquire_local(Instant::now())?;
        match run_worker(
            self.command(),
            READINESS_REQUEST,
            self.wall_timeout.min(Duration::from_secs(5)),
        )
        .map_err(ClientError::Process)?
        {
            true => Ok(()),
            false => Err(ClientError::Configuration),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.args(self.worker_mode_arg);
        // The worker otherwise reads a node running as PID 1 as init.
        command.env(
            super::worker_limits::PARENT_PID_ENV,
            std::process::id().to_string(),
        );
        command
            .arg("--cpu-seconds")
            .arg(self.cpu_seconds.to_string());
        if let Some(bytes) = self.address_space_bytes {
            command.arg("--address-space-bytes").arg(bytes.to_string());
        }
        if let Some(threads) = self.native_threads {
            command.env("QUIL_NATIVE_AGGREGATION_THREADS", threads.to_string());
        }
        command
    }

    /// Verify only the amount relation. The enclosing execution engine must
    /// check authorization, canonical state/root eligibility, fees and replay.
    /// The permit remains held through worker exit and input-thread cleanup.
    pub fn verify(&self, request: &WorkerRequest<'_>) -> Result<bool, ClientError> {
        let deadline = Instant::now() + self.admission_wait;
        let _permit = self.acquire_local(deadline)?;
        let _shared = self
            .shared_admission
            .as_deref()
            .map(|shared| acquire_shared_until(shared, deadline, self.background))
            .transpose()?;
        let _held = SlotHeld(Instant::now());
        let bytes = request.encode().map_err(ClientError::Request)?;
        run_worker_capped(
            self.command(),
            &bytes,
            self.wall_timeout,
            self.max_resident_bytes,
        )
        .map_err(ClientError::Process)
    }
}

/// One held slot descriptor of the node-wide admission file.
struct SharedPermit<'a>(&'a std::fs::File);

/// Other node processes hold these locks too, and `flock` has no fair queue;
/// poll until the caller's admission deadline rather than refusing at once.
/// A `background` caller leaves the first slot free ([`WorkerVerifier::background`]).
fn acquire_shared_until(
    shared: &SharedAdmission,
    deadline: Instant,
    background: bool,
) -> Result<SharedPermit<'_>, ClientError> {
    loop {
        match acquire_shared_for(shared, background) {
            Err(ClientError::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
fn acquire_shared(shared: &SharedAdmission) -> Result<SharedPermit<'_>, ClientError> {
    acquire_shared_for(shared, false)
}

/// Take a free node-wide slot; a `background` caller skips the first one
/// when there are others.
fn acquire_shared_for(
    shared: &SharedAdmission,
    background: bool,
) -> Result<SharedPermit<'_>, ClientError> {
    let reserved = usize::from(background && shared.files.len() > 1);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // Nonblocking: busy is local unavailability, never proof rejection.
        for file in shared.files.iter().skip(reserved) {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(SharedPermit(file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(ClientError::Process(WorkerError::Io(error)));
            }
        }
        Err(ClientError::Busy)
    }
    #[cfg(not(unix))]
    {
        let _ = (shared, reserved);
        Err(ClientError::Configuration)
    }
}
impl Drop for SharedPermit<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Parse a test limit in seconds; unset, empty or unparsable values fall back
/// to `default`, and every result is clamped into the 1..=3600 policy range.
fn test_limit_secs(value: Option<&str>, default: u64) -> u64 {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(1, 3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::transfer::CompileLimits;

    /// Each verification's slot time adds to the busy total when it ends,
    /// and the longest is kept until taken, which resets it.
    #[test]
    fn verifications_holding_a_slot_add_to_busy_time_and_the_longest() {
        fn ago(millis: u64) -> Instant {
            Instant::now() - Duration::from_millis(millis)
        }
        let before = slot_busy_total();
        take_longest_slot_hold();
        drop(SlotHeld(ago(1500)));
        drop(SlotHeld(ago(400)));
        let busy = slot_busy_total() - before;
        assert!(
            busy >= Duration::from_millis(1900),
            "slot busy time lost a verification: {busy:?}"
        );
        let longest = take_longest_slot_hold();
        assert!(
            longest >= Duration::from_millis(1500) && longest < busy,
            "the longest verification was not recorded: {longest:?} of {busy:?}"
        );
        assert_eq!(
            take_longest_slot_hold(),
            Duration::ZERO,
            "taking the longest verification did not start a new interval"
        );
    }

    #[test]
    fn the_worker_command_names_this_process_as_its_parent() {
        use super::super::worker_limits::PARENT_PID_ENV;
        use std::ffi::OsStr;
        let verifier =
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap();
        let pid = std::process::id().to_string();
        assert!(verifier.command().get_envs().any(|(key, value)| key
            == OsStr::new(PARENT_PID_ENV)
            && value == Some(OsStr::new(&pid))));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess fixture invoked by shared_admission_coordinates_processes"]
    fn shared_admission_child() {
        let path = PathBuf::from(std::env::var_os("QUIL_TEST_ADMISSION_FILE").unwrap());
        let verifier =
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap()
                .with_shared_admission(path)
                .unwrap();
        let result = acquire_shared(verifier.shared_admission.as_deref().unwrap());
        if std::env::var("QUIL_TEST_ADMISSION_BUSY").unwrap() == "1" {
            assert!(matches!(result, Err(ClientError::Busy)));
        } else {
            let _held = result.unwrap();
            // Exit without Rust destructors: kernel cleanup must release it.
            std::process::exit(0);
        }
    }

    #[test]
    fn waiting_admission_is_fair_across_lanes_bounded_and_times_out() {
        let base = WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
            .unwrap();
        assert!(base
            .clone()
            .with_admission_wait(Duration::from_secs(61))
            .is_err());
        let base = base.with_admission_wait(Duration::from_secs(20)).unwrap();
        let (busy, quiet) = (base.for_lane(1), base.for_lane(2));
        let held = busy.acquire_local(Instant::now()).unwrap();
        // A zero deadline still refuses at once, as before.
        assert!(matches!(
            quiet.acquire_local(Instant::now()),
            Err(ClientError::Busy)
        ));

        // Lane 1 queues three more requests BEFORE lane 2 asks once.
        let order = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new((Mutex::new(0usize), Condvar::new()));
        let spawn = |verifier: WorkerVerifier, lane: u32| {
            let (order, release) = (order.clone(), release.clone());
            std::thread::spawn(move || {
                let permit = verifier
                    .acquire_local(Instant::now() + Duration::from_secs(20))
                    .unwrap();
                order.lock().unwrap().push(lane);
                // Hold the slot until the test releases this admission.
                let (count, signal) = &*release;
                let mut released = count.lock().unwrap();
                let position = order.lock().unwrap().len();
                while *released < position {
                    released = signal.wait(released).unwrap();
                }
                drop(permit);
            })
        };
        let waiting = |n: usize| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while base.slots.state.lock().unwrap().waiting.len() != n {
                assert!(Instant::now() < deadline, "waiters never queued");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        let mut threads = Vec::new();
        for n in 1..=3 {
            threads.push(spawn(busy.clone(), 1));
            waiting(n);
        }
        threads.push(spawn(quiet.clone(), 2));
        waiting(4);
        // The queue is bounded (4 per slot): a fifth waiter is refused outright.
        let start = Instant::now();
        assert!(matches!(
            quiet.acquire_local(Instant::now() + Duration::from_secs(20)),
            Err(ClientError::Busy)
        ));
        assert!(start.elapsed() < Duration::from_secs(5));

        drop(held);
        for admitted in 1..=4 {
            let deadline = Instant::now() + Duration::from_secs(10);
            while order.lock().unwrap().len() < admitted {
                assert!(
                    Instant::now() < deadline,
                    "admission {admitted} never happened"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let (count, signal) = &*release;
            *count.lock().unwrap() = admitted;
            signal.notify_all();
        }
        for thread in threads {
            thread.join().unwrap();
        }
        // Lane 1 was admitted last, so lane 2's single request overtakes all
        // three of lane 1's earlier ones; within lane 1 the order is arrival.
        assert_eq!(*order.lock().unwrap(), vec![2, 1, 1, 1]);

        // A waiter that reaches its deadline leaves the queue and reports Busy.
        let held = busy.acquire_local(Instant::now()).unwrap();
        let start = Instant::now();
        assert!(matches!(
            quiet.acquire_local(Instant::now() + Duration::from_millis(150)),
            Err(ClientError::Busy)
        ));
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(base.slots.state.lock().unwrap().waiting.is_empty());
        drop(held);
        assert!(quiet.acquire_local(Instant::now()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn shared_admission_coordinates_processes() {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let directory = std::env::temp_dir().join(format!(
            "quil-admission-{}-{:x?}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("slot");
        let make = || {
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap()
                .with_shared_admission(path.clone())
                .unwrap()
        };
        let first = make();
        let second = make();
        let child = |busy| {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "confidential::relation::backend::worker_client::tests::shared_admission_child",
                    "--ignored",
                    "--nocapture"
                ])
                .env("QUIL_TEST_ADMISSION_FILE", &path)
                .env("QUIL_TEST_ADMISSION_BUSY", if busy { "1" } else { "0" })
                .status()
                .unwrap()
                .success());
        };
        let held = acquire_shared(first.shared_admission.as_deref().unwrap()).unwrap();
        let request = WorkerRequest {
            network: [1; 32],
            application: [2; 32],
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 32,
            },
            submission_bytes: 0,
            transaction: &[],
        };
        assert!(matches!(second.verify(&request), Err(ClientError::Busy)));
        child(true);
        drop(held);
        child(false);
        // Encode failure also releases the shared slot before returning.
        assert!(matches!(
            second.verify(&request),
            Err(ClientError::Request(_))
        ));
        let held = acquire_shared(first.shared_admission.as_deref().unwrap()).unwrap();
        drop(held);
        drop(first);
        drop(second);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrency_slots_admit_n_in_flight_locally_and_across_descriptors() {
        let directory =
            std::env::temp_dir().join(format!("quil-admission-slots-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let verifier =
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap();
        assert!(verifier.clone().with_concurrency(0).is_err());
        assert!(verifier.clone().with_concurrency(65).is_err());
        assert!(verifier.clone().with_native_threads(0).is_err());
        assert!(verifier.clone().with_native_threads(9).is_err());
        let verifier = verifier
            .with_shared_admission(directory.join("slots"))
            .unwrap()
            .with_concurrency(2)
            .unwrap()
            .with_native_threads(2)
            .unwrap();
        assert_eq!(verifier.concurrency(), 2);
        assert_eq!(verifier.shared_admission.as_ref().unwrap().files.len(), 2);
        let clone = verifier.clone();
        let first = verifier.acquire_local(Instant::now()).unwrap();
        let second = clone.acquire_local(Instant::now()).unwrap();
        assert!(matches!(
            verifier.acquire_local(Instant::now()),
            Err(ClientError::Busy)
        ));
        drop(first);
        assert!(verifier.acquire_local(Instant::now()).is_ok());
        drop(second);
        // An independent client on the same file competes for the same two slots.
        let other =
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap()
                .with_shared_admission(directory.join("slots"))
                .unwrap()
                .with_concurrency(2)
                .unwrap();
        let third =
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap()
                .with_shared_admission(directory.join("slots"))
                .unwrap()
                .with_concurrency(2)
                .unwrap();
        let a = acquire_shared(verifier.shared_admission.as_deref().unwrap()).unwrap();
        let b = acquire_shared(other.shared_admission.as_deref().unwrap()).unwrap();
        // Both slot files are held by other descriptors: a third client is busy.
        assert!(matches!(
            acquire_shared(third.shared_admission.as_deref().unwrap()),
            Err(ClientError::Busy)
        ));
        drop(a);
        let c = acquire_shared(third.shared_admission.as_deref().unwrap()).unwrap();
        drop(b);
        drop(c);
        let command = verifier.command();
        let envs: Vec<_> = command
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string())))
            .collect();
        assert!(
            envs.iter()
                .any(|(k, v)| k == "QUIL_NATIVE_AGGREGATION_THREADS"
                    && v.as_deref() == Some(std::ffi::OsStr::new("2"))),
            "{envs:?}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Background verifications of every node process leave the first
    /// node-wide slot to frames and inline verifications: holding the other
    /// slots, they find the worker busy while a frame's verification is
    /// admitted; a released slot admits background work again. With one
    /// slot nothing is reserved.
    #[cfg(unix)]
    #[test]
    fn background_verifications_leave_the_first_node_wide_slot_free() {
        let directory =
            std::env::temp_dir().join(format!("quil-admission-background-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let client = |slots: usize, name: &str| {
            WorkerVerifier::new(std::env::current_exe().unwrap(), 1, Duration::from_secs(1))
                .unwrap()
                .with_concurrency(slots)
                .unwrap()
                .with_shared_admission(directory.join(name))
                .unwrap()
        };
        // Three node processes' clients of one node-wide pair of slots.
        let (one, two, frames) = (client(2, "slots"), client(2, "slots"), client(2, "slots"));
        let (one, two) = (one.background(), two.background());
        fn shared(verifier: &WorkerVerifier) -> Result<SharedPermit<'_>, ClientError> {
            acquire_shared_for(
                verifier.shared_admission.as_deref().unwrap(),
                verifier.background,
            )
        }
        let held = shared(&one).unwrap();
        assert!(std::ptr::eq(
            held.0,
            &one.shared_admission.as_ref().unwrap().files[1]
        ));
        assert!(
            matches!(shared(&two), Err(ClientError::Busy)),
            "background work took the slot left for frames"
        );
        let request = WorkerRequest {
            network: [1; 32],
            application: [2; 32],
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 32,
            },
            submission_bytes: 0,
            transaction: &[],
        };
        assert!(matches!(two.verify(&request), Err(ClientError::Busy)));
        // A frame's verification is admitted (and then fails to encode the
        // empty transaction, after its admission).
        assert!(matches!(
            frames.verify(&request),
            Err(ClientError::Request(_))
        ));
        drop(held);
        assert!(matches!(two.verify(&request), Err(ClientError::Request(_))));
        // One slot: background work takes it.
        let single = client(1, "single").background();
        assert!(shared(&single).is_ok());
        drop((one, two, frames, single));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_limit_parsing_defaults_and_clamps() {
        assert_eq!(test_limit_secs(None, 600), 600);
        assert_eq!(test_limit_secs(Some(""), 600), 600);
        assert_eq!(test_limit_secs(Some("abc"), 600), 600);
        assert_eq!(test_limit_secs(Some(" 3000 "), 600), 3000);
        assert_eq!(test_limit_secs(Some("0"), 600), 1);
        assert_eq!(test_limit_secs(Some("99999"), 600), 3600);
        assert_eq!(test_limit_secs(None, 0), 1);
    }

    #[test]
    fn worker_client_clones_share_admission_and_validate_policy() {
        assert!(WorkerVerifier::new("relative-worker".into(), 1, Duration::from_secs(2)).is_err());
        let path = std::env::current_exe().unwrap();
        assert!(WorkerVerifier::new(path.clone(), 0, Duration::from_secs(2)).is_err());
        assert!(WorkerVerifier::new(path.clone(), 1, Duration::ZERO).is_err());
        let verifier = WorkerVerifier::new(path, 1, Duration::from_secs(2)).unwrap();
        assert!(verifier.clone().with_address_space_limit(0).is_err());
        assert!(verifier.clone().with_address_space_limit(u64::MAX).is_err());
        #[cfg(not(target_os = "linux"))]
        assert!(verifier.clone().with_address_space_limit(1 << 30).is_err());
        let clone = verifier.clone();
        let request = WorkerRequest {
            network: [1; 32],
            application: [2; 32],
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 32,
            },
            submission_bytes: 0,
            transaction: &[0; 4],
        };
        let permit = verifier.acquire_local(Instant::now()).unwrap();
        assert!(matches!(clone.verify(&request), Err(ClientError::Busy)));
        drop(permit);
        let bad = WorkerRequest {
            transaction: &[],
            ..request
        };
        assert!(matches!(clone.verify(&bad), Err(ClientError::Request(_))));
        assert!(verifier.acquire_local(Instant::now()).is_ok());
    }

    #[test]
    #[ignore = "requires built native worker and saved public mint fixture"]
    fn worker_client_verifies_saved_native_mint() {
        use std::io::Read;
        let path = PathBuf::from(std::env::var("QUIL_AMOUNT_WORKER_PATH").expect("worker path"));
        let fixture = std::env::var("QUIL_AMOUNT_WORKER_FIXTURE").expect("public fixture path");
        let mut transaction = Vec::new();
        std::fs::File::open(fixture)
            .unwrap()
            .take(1 << 20)
            .read_to_end(&mut transaction)
            .unwrap();
        // Independently specified context for the saved mint fixture.
        let hex = "11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9";
        let mut app = [0; 32];
        for (i, value) in app.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let verifier = WorkerVerifier::from_test_env(path).unwrap();
        // Explicit test allowance, not a node default or a measured RSS bound.
        #[cfg(target_os = "linux")]
        let verifier = verifier.with_address_space_limit(8 << 30).unwrap();
        let request = WorkerRequest {
            network: [1; 32],
            application: app,
            limits: CompileLimits {
                max_inputs: 2,
                max_outputs: 2,
                max_depth: 32,
            },
            submission_bytes: 1 << 30,
            transaction: &transaction,
        };
        assert!(verifier.verify(&request).unwrap());
        let wrong = WorkerRequest {
            network: [2; 32],
            ..request
        };
        assert!(!verifier.verify(&wrong).unwrap());
        let unavailable = WorkerRequest {
            submission_bytes: 0,
            ..request
        };
        assert!(matches!(
            verifier.verify(&unavailable),
            Err(ClientError::Process(WorkerError::UnexpectedExit(Some(82))))
        ));
        assert!(verifier.acquire_local(Instant::now()).is_ok());
        println!(
            "worker_client_native_mint=true context_rejected=true budget_unavailable=true bytes={}",
            transaction.len()
        );
    }
}
