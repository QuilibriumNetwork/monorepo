//! Local, durable sector pool. Fixed capacities and IDs survive changes to
//! logical shard ownership. Leases prevent two concurrent leaves selecting the
//! same physical sector; GLOBAL independently enforces that invariant.
use super::*;
use crate::storage_labels::{LabelStore, Labelling, Stage};
use quil_crypto::{
    persistent_storage as sector, storage_hash as hash,
    storage_proof::{self as proof, LabelSource, MerkleCap, Node, Tree},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

fn io(error: std::io::Error) -> QuilError {
    unavailable(format!("persistent sector: {error}"))
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Sha3_256::digest(bytes).into()
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)?;
    File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(io)
}
fn home(store: &LabelStore, member: &[u8]) -> PathBuf {
    store
        .directory()
        .join("sectors-v1")
        .join(hex::encode(member))
}

fn sector_directory(path: &Path) -> bool {
    path.is_dir()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Clone)]
struct Sector {
    dir: PathBuf,
    cert: sector::Certificate,
    certified: bool,
}
impl Sector {
    fn load(dir: PathBuf) -> Result<Option<Self>> {
        let bytes = match fs::read(dir.join("certificate")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        if bytes.len() != sector::Certificate::BYTES + 1
            && bytes.len() != sector::Certificate::PROFILED_BYTES + 1
        {
            return Err(unavailable("sector metadata length".into()));
        }
        let cert = sector::Certificate::parse(&bytes[..bytes.len() - 1])
            .ok_or_else(|| unavailable("sector metadata is invalid".into()))?;
        if bytes[bytes.len() - 1] > 1 {
            return Err(unavailable("sector certification flag".into()));
        }
        Ok(Some(Self {
            dir,
            cert,
            certified: bytes[bytes.len() - 1] == 1,
        }))
    }
    fn save(&self) -> Result<()> {
        let mut bytes = self.cert.to_bytes();
        bytes.push(u8::from(self.certified));
        atomic(&self.dir.join("certificate"), &bytes)
    }
    fn cap(&self) -> Result<MerkleCap> {
        let cap = MerkleCap::from_bytes(&fs::read(self.dir.join("cap")).map_err(io)?)
            .ok_or_else(|| unavailable("sector cap is invalid".into()))?;
        if cap.n != self.cert.n || cap.commitment(Tree::Replica) != self.cert.labels {
            return Err(unavailable("sector cap differs from certificate".into()));
        }
        Ok(cap)
    }
    fn last(&self) -> Result<Vec<hash::Digest>> {
        #[cfg(test)]
        tests::count_last_read(&self.dir);
        let mut file = File::open(self.dir.join("last")).map_err(io)?;
        if file.metadata().map_err(io)?.len() != self.cert.n * 32 {
            return Err(unavailable("sector last layer is short".into()));
        }
        let mut out = Vec::with_capacity(self.cert.n as usize);
        let mut bytes = vec![0; 1024 * 32];
        for at in (0..self.cert.n).step_by(1024) {
            let bytes = &mut bytes[..(self.cert.n - at).min(1024) as usize * 32];
            file.read_exact(bytes).map_err(io)?;
            out.extend(
                hash::digests_from_bytes(bytes)
                    .ok_or_else(|| unavailable("noncanonical sector label".into()))?,
            );
        }
        Ok(out)
    }
    /// Whether the last layer on disk commits to the certificate.
    fn last_matches(&self) -> bool {
        #[cfg(test)]
        tests::count_last_check(&self.dir);
        self.last().is_ok_and(|last| {
            let cap = MerkleCap::from_digests(&last, proof::seal_cap_height(self.cert.n));
            cap.commitment(Tree::Replica) == self.cert.labels
        })
    }
    /// Whether a repair found the sector's labels, made again, to differ
    /// from its certificate: it is not labelled again, and no leaf is
    /// reserved in it, until its certificate is set up anew.
    fn given_up(&self) -> bool {
        fs::read(self.dir.join("repair-failed")).is_ok_and(|bytes| bytes == self.cert.to_bytes())
    }
}

fn reserve(
    store: &LabelStore,
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    exact: u64,
) -> Result<(PathBuf, [u8; 32], u64)> {
    try_reserve(store, member, leaf, epoch, exact)?
        .ok_or_else(|| unavailable("sector initialization slots are occupied".into()))
}

fn sector_lane(member: &[u8], id: &[u8; 32]) -> Vec<u8> {
    [b"persistent sector/".as_slice(), member, id].concat()
}

/// The capacity to label for `exact` nodes: 25% growth headroom, rounded to a
/// power of two, no less than GLOBAL certifies.
fn sector_nodes(exact: u64) -> Option<u64> {
    let floor = sector_floor();
    sector::capacity(exact.saturating_add(exact.div_ceil(4)).max(floor))
}

#[cfg(not(test))]
fn sector_floor() -> u64 {
    quil_types::consensus::min_sector_nodes()
}

/// Unit tests label small sectors on every thread, spawned ones included,
/// unless the labelling thread sets its own floor.
#[cfg(test)]
fn sector_floor() -> u64 {
    use quil_types::consensus::min_sector_nodes_thread_override;
    min_sector_nodes_thread_override().unwrap_or(2)
}

fn try_reserve(
    store: &LabelStore,
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    exact: u64,
) -> Result<Option<(PathBuf, [u8; 32], u64)>> {
    let profile = quil_types::consensus::storage_seal_profile(epoch);
    let root = home(store, member);
    fs::create_dir_all(&root).map_err(io)?;
    let lock = File::open(&root).map_err(io)?;
    lock.lock().map_err(io)?;
    // A creator holds this lock through publication. Hidden staging directories
    // found here are interrupted reservations, never initialized sector data.
    for entry in fs::read_dir(&root).map_err(io)?.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".new-sector-"))
            && entry.path().is_dir()
        {
            fs::remove_dir_all(entry.path()).map_err(io)?;
        }
    }
    let leaf_hash = digest(leaf);
    let mapping = root.join(format!("leaf-{}", hex::encode(leaf_hash)));
    let mapped = fs::read(&mapping)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    if let Some(id) = mapped {
        let dir = root.join(hex::encode(id));
        if matches!(Sector::load(dir.clone()), Ok(None)) {
            if let Ok(bytes) = fs::read(dir.join("reservation")) {
                if (bytes.len() == 48 || bytes.len() == 52) && bytes[16..48] == leaf_hash {
                    let n = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                    if sector::padded_nodes_allowed(exact, n) {
                        atomic(&dir.join(format!("lease-{epoch}")), &leaf_hash)?;
                        return Ok(Some((dir, id, n)));
                    }
                }
            }
        }
    }
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&root).map_err(io)?.flatten() {
        if !sector_directory(&entry.path()) {
            continue;
        }
        // A sector that cannot be read is skipped here: the certificate
        // poll reports it, and it holds back no other leaf. A sector given
        // up is skipped too: its leaves go to another.
        if let Ok(Some(sector)) = Sector::load(entry.path()) {
            if sector.cert.n >= exact && !sector.given_up() {
                candidates.push(sector);
            }
        }
    }
    candidates.sort_by_key(|s| (Some(s.cert.sector) != mapped, s.cert.n, s.cert.sector));
    for candidate in candidates {
        for entry in fs::read_dir(&candidate.dir).map_err(io)?.flatten() {
            let old = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("lease-")?.parse::<u64>().ok());
            if old.is_some_and(|old| old.saturating_add(4) < epoch) {
                let _ = fs::remove_file(entry.path());
            }
        }
        let lease = candidate.dir.join(format!("lease-{epoch}"));
        match fs::read(&lease) {
            Ok(owner) if owner != leaf_hash => continue,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(e)),
            _ => {}
        }
        atomic(&lease, &leaf_hash)?;
        atomic(&mapping, &candidate.cert.sector)?;
        return Ok(Some((
            candidate.dir,
            candidate.cert.sector,
            candidate.cert.n,
        )));
    }
    // A crash during initialization reuses its reservation and kept layers.
    let pending = root.join(format!("pending-{epoch}-{}", hex::encode(leaf_hash)));
    if let Ok(bytes) = fs::read(&pending) {
        if bytes.len() == 40 {
            let id: [u8; 32] = bytes[..32].try_into().unwrap();
            let n = u64::from_be_bytes(bytes[32..].try_into().unwrap());
            if sector::padded_nodes_allowed(exact, n) {
                return Ok(Some((root.join(hex::encode(id)), id, n)));
            }
        }
    }
    // Bound retained uncertified caches by CPU slots, not one global sector.
    // LabelStore admission separately reserves their disk bytes and RAM.
    let mut pending_count = 0usize;
    for entry in fs::read_dir(&root).map_err(io)?.flatten() {
        if !sector_directory(&entry.path()) {
            continue;
        }
        if Sector::load(entry.path()).is_ok_and(|s| !s.is_some_and(|s| s.certified)) {
            pending_count += 1;
        }
    }
    if pending_count >= crate::storage_jobs::job_slots() {
        return Ok(None);
    }
    let n = sector_nodes(exact)
        .ok_or_else(|| unavailable("snapshot exceeds maximum sector size".into()))?;
    let mut seed = b"quil/local-sector-id/v1".to_vec();
    seed.extend_from_slice(member);
    seed.extend_from_slice(leaf);
    seed.extend_from_slice(&epoch.to_be_bytes());
    seed.extend_from_slice(&n.to_be_bytes());
    if profile != sector::Profile::Eleven {
        seed.extend_from_slice(profile.tag());
    }
    let id = digest(&seed);
    let dir = root.join(hex::encode(id));
    // Publish the directory only after its recovery metadata is durable.
    // A crash between mkdir and reservation must not block the entire pool.
    let staged = root.join(format!(
        ".new-sector-{}-{}",
        hex::encode(id),
        std::process::id()
    ));
    fs::create_dir_all(&staged).map_err(io)?;
    atomic(
        &staged.join("reservation"),
        &[
            n.to_be_bytes().as_slice(),
            &epoch.to_be_bytes(),
            &leaf_hash,
            if profile == sector::Profile::Eleven {
                &[]
            } else {
                profile.tag().as_slice()
            },
        ]
        .concat(),
    )?;
    fs::rename(&staged, &dir).map_err(io)?;
    File::open(&root).and_then(|f| f.sync_all()).map_err(io)?;
    atomic(&dir.join(format!("lease-{epoch}")), &leaf_hash)?;
    atomic(&mapping, &id)?;
    atomic(&pending, &[id.as_slice(), &n.to_be_bytes()].concat())?;
    Ok(Some((dir, id, n)))
}

fn initialize(
    store: &LabelStore,
    member: &[u8],
    epoch: u64,
    dir: PathBuf,
    id: [u8; 32],
    n: u64,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<Sector> {
    initialize_with_progress(store, member, epoch, dir, id, n, stop, &|_| {})
}

fn initialize_with_progress(
    store: &LabelStore,
    member: &[u8],
    epoch: u64,
    dir: PathBuf,
    id: [u8; 32],
    n: u64,
    stop: &(dyn Fn() -> bool + Sync),
    layers: &dyn Fn(usize),
) -> Result<Sector> {
    let reservation = fs::read(dir.join("reservation")).map_err(io)?;
    let profile = match reservation.len() {
        48 => sector::Profile::Eleven,
        52 => sector::Profile::from_tag(&reservation[48..])
            .ok_or_else(|| unavailable("sector reservation profile".into()))?,
        _ => return Err(unavailable("sector reservation length".into())),
    };
    let view = store.for_profile(profile);
    let store = &view;
    let params = store.params();
    let guard = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("initializing"))
        .map_err(io)?;
    if guard.try_lock().is_err() {
        return Err(unavailable("sector initialization already runs".into()));
    }
    let previous = Sector::load(dir.clone())?;
    if let Some(sector) = &previous {
        if sector.certified || store.find(epoch, member, &id, |count| count == n).is_some() {
            return Ok(sector.clone());
        }
    }
    // Kept labels that are not whole are labelled again rather than set up
    // from: a certificate committing to them could never be proven.
    let kept = store
        .find(epoch, member, &id, |count| count == n)
        .and_then(|kept| match kept.wholly_verified_last_layer() {
            Some(last) => Some((last, kept.comm_c)),
            None => {
                warn!(epoch, sector = %hex::encode(id), nodes = n, scope = "local",
                    action = "check this node's disk and its kernel log for I/O errors if \
                              this recurs",
                    "storage labels kept for a sector do not match their column commitment, \
                     as a torn or damaged file on this node's disk leaves them; they are \
                     removed and the sector is labelled again before its certificate");
                drop(kept);
                store.discard_damaged(epoch, member, &id, n);
                None
            }
        });
    let (last, columns) = match kept {
        Some(pair) => pair,
        None => {
            let admitted = store
                .admit(epoch, member, &id, n, Stage::Snapshot)
                .ok_or_else(|| unavailable("no disk space to certify a new sector".into()))?;
            match admitted.label_kept(params, stop, layers)? {
                Labelling::Labelled(labelled) if labelled.kept => (labelled.last, labelled.comm_c),
                _ => {
                    return Err(unavailable(
                        "initial sector labelling stopped or could not be retained".into(),
                    ))
                }
            }
        }
    };
    let cap = MerkleCap::from_digests(&last, proof::seal_cap_height(n));
    let cert = sector::Certificate {
        profile,
        sector: id,
        n,
        columns,
        labels: cap.commitment(Tree::Replica),
    };
    if let Some(old) = previous.as_ref().filter(|old| old.cert != cert) {
        if old.certified {
            return Err(unavailable(
                "regenerated sector differs from committed labels".into(),
            ));
        }
        // Uncertified, its certificate is GLOBAL's only as a pending
        // precommit: the one its own labels give replaces it, rather than
        // the sector being labelled again at every poll.
        warn!(epoch, sector = %hex::encode(id), nodes = n, scope = "local",
            action = "check this node's disk and its kernel log for I/O errors if this recurs",
            "an uncertified sector's certificate on disk differs from the one its labels, \
             made again, give, as labels damaged before it was written leave it; it takes \
             theirs, and its precommit target and cached proofs are dropped");
        let _ = fs::remove_file(dir.join("capacity-target"));
        for entry in fs::read_dir(&dir).map_err(io)?.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("proof-"))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    write_last(&dir, &last)?;
    atomic(&dir.join("cap"), &cap.to_bytes())?;
    let sector = Sector {
        dir,
        cert: sector::Certificate {
            profile,
            sector: id,
            n,
            columns,
            labels: cap.commitment(Tree::Replica),
        },
        certified: false,
    };
    sector.save()?;
    Ok(sector)
}

/// Write a sector's last layer whole, or leave the one there. Up to 2 GiB:
/// paced as the labels are, so the stores' synced commits never wait behind
/// all of it, on a repair as at setup.
fn write_last(dir: &Path, last: &[hash::Digest]) -> Result<()> {
    let path = dir.join("last.tmp");
    crate::storage_labels::write_digests_paced(&path, last).map_err(io)?;
    fs::rename(&path, dir.join("last")).map_err(io)
}

/// The sectors whose repair is queued or running, by directory: one repair
/// a sector at most, so a repair running longer than an epoch queues none
/// behind it.
static REPAIRING: Mutex<std::collections::BTreeSet<PathBuf>> =
    Mutex::new(std::collections::BTreeSet::new());

/// A sector's place in [`REPAIRING`], left as its repair ends or is dropped.
struct Repairing(PathBuf);
impl Drop for Repairing {
    fn drop(&mut self) {
        REPAIRING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Whether a repair of the sector in `dir` is queued now: false when one
/// is queued or running already.
fn queue_repair(dir: &Path) -> bool {
    REPAIRING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(dir.to_owned())
}

/// Label a certified sector again on its lane, and rewrite its last layer
/// and cap from the labels when they match its certificate: the labels are
/// the sector's own, so a last layer damaged on disk is repaired. A sector
/// queues one repair at most; one whose labels, made again, differ from its
/// certificate is given up ([`Sector::given_up`]) and never labelled again.
fn repair_last(store: &LabelStore, member: &[u8], epoch: u64, sector: &Sector) {
    if sector.given_up() || !queue_repair(&sector.dir) {
        return;
    }
    let repairing = Repairing(sector.dir.clone());
    let store = store.for_profile(sector.cert.profile);
    let (member, sector) = (member.to_vec(), sector.clone());
    crate::storage_jobs::spawn(
        &sector_lane(&member, &sector.cert.sector),
        "sector repair",
        move || {
            let _repairing = repairing;
            let (id, n) = (sector.cert.sector, sector.cert.n);
            let order = crate::storage_jobs::AheadOrder {
                deferrable: false,
                seat_leaves: 1,
                seat: crate::storage_jobs::ahead_place(),
                leaf: 0,
            };
            let memory = crate::storage_jobs::reserve_ahead(
                crate::storage_labels::label_ahead_bytes(n),
                order,
                epoch,
                &crate::storage_jobs::stopping,
            )
            .ok_or_else(|| unavailable("sector repair stopped".into()))?;
            // A last layer made whole since the repair was queued, or a
            // sector given up, is labelled no more.
            if sector.given_up() || sector.last_matches() {
                return Ok(());
            }
            let stop = || {
                memory.wait_while_paused(&crate::storage_jobs::stopping);
                crate::storage_jobs::stopping() || memory.yield_requested()
            };
            let admitted = store
                .admit(epoch, &member, &id, n, Stage::Snapshot)
                .ok_or_else(|| unavailable("no disk space to repair a sector".into()))?;
            let labelled = match admitted.label_kept(store.params(), &stop, &|_| {})? {
                Labelling::Labelled(labelled) => labelled,
                _ => return Err(unavailable("sector repair stopped".into())),
            };
            store.release_certified_sector(epoch, &member, &id);
            let cap = MerkleCap::from_digests(&labelled.last, proof::seal_cap_height(n));
            if cap.commitment(Tree::Replica) != sector.cert.labels
                || labelled.comm_c != sector.cert.columns
            {
                atomic(&sector.dir.join("repair-failed"), &sector.cert.to_bytes())?;
                warn!(epoch, sector = %hex::encode(id), nodes = n, scope = "local",
                    action = "check this node's disk and its kernel log for I/O errors",
                    "a certified sector labelled again does not match its certificate, as a \
                     damaged certificate file, or labels damaged before it was certified, \
                     leave it; it is given up: it is not labelled again, its last layer on \
                     disk is left as it is, and its leaves go to another sector");
                return Err(unavailable(
                    "relabelled sector differs from its certificate".into(),
                ));
            }
            write_last(&sector.dir, &labelled.last)?;
            atomic(&sector.dir.join("cap"), &cap.to_bytes())?;
            info!(epoch, sector = %hex::encode(id), nodes = n,
                "a certified sector was labelled again and its last layer rewritten");
            Ok(())
        },
    );
}

/// After a failed seal: when the sector's last layer on disk is missing or
/// differs from its certificate, label the sector again, warning once an
/// epoch. A leaf whose snapshot is unchanged is never encoded again, so a
/// registered replica's damaged last layer shows only in its seal. The mark
/// is checked before the layer, which each failing leaf would read again.
fn repair_if_torn(store: &LabelStore, member: &[u8], epoch: u64, sector: &Sector) {
    if repair_due(sector, epoch) && !sector.last_matches() {
        start_repair(store, member, epoch, sector);
    }
}

/// Whether a failing seal may start a repair of the sector this epoch: it
/// is not given up, and no repair is marked this epoch.
fn repair_due(sector: &Sector, epoch: u64) -> bool {
    !sector.given_up() && !sector.dir.join(format!("repair-{epoch}")).exists()
}

/// Mark the sector's repair this epoch and start it, warning once: a
/// failing seal found its last layer missing or differing from its
/// certificate.
fn start_repair(store: &LabelStore, member: &[u8], epoch: u64, sector: &Sector) {
    if atomic(&sector.dir.join(format!("repair-{epoch}")), &[]).is_err() {
        return;
    }
    warn!(epoch, sector = %hex::encode(sector.cert.sector), nodes = sector.cert.n,
        scope = "local", action = "check this node's disk and its kernel log for I/O errors",
        "a registered sector's last layer on disk is missing or does not match its \
         certificate, as a damaged or lost file leaves it; its seals fail until it is \
         labelled again, which starts now");
    repair_last(store, member, epoch, sector);
}

/// A registered sector's cap, rewritten from its last layer when the file is
/// damaged or missing and the layer matches the certificate, as the cap is
/// made from it; otherwise the layer is repaired as after a failed seal. A
/// cap that cannot be read fails every seal before one is made. The layer,
/// up to 2 GiB, is read once an epoch at most, under a reservation of its
/// size, and never for a sector given up: each failing leaf would read it
/// again.
fn cap_or_repair(
    store: &LabelStore,
    member: &[u8],
    epoch: u64,
    sector: &Sector,
) -> Result<MerkleCap> {
    let error = match sector.cap() {
        Ok(cap) => return Ok(cap),
        Err(error) => error,
    };
    if !repair_due(sector, epoch) {
        return Err(error);
    }
    let whole = {
        let _memory = crate::storage_jobs::reserve(sector.cert.n.saturating_mul(32));
        sector
            .last()
            .ok()
            .map(|last| MerkleCap::from_digests(&last, proof::seal_cap_height(sector.cert.n)))
    };
    if let Some(cap) = whole {
        if cap.commitment(Tree::Replica) == sector.cert.labels {
            atomic(&sector.dir.join("cap"), &cap.to_bytes())?;
            warn!(epoch, sector = %hex::encode(sector.cert.sector), nodes = sector.cert.n,
                scope = "local",
                action = "check this node's disk and its kernel log for I/O errors",
                "a registered sector's cap on disk is damaged or missing; it was rewritten \
                 from the sector's last layer, which matches its certificate");
            return Ok(cap);
        }
    }
    start_repair(store, member, epoch, sector);
    Err(error)
}

/// Whether the files a sector's certificate proof would be made from are
/// its own: its last layer on disk commits to its certificate, and the
/// labels kept for it, checked as a snapshot checks them, hold that layer
/// under its column commitment.
fn proof_inputs_whole(
    kept: &crate::storage_labels::Kept,
    last: &[u8],
    cert: &sector::Certificate,
) -> bool {
    let Some(last) = hash::digests_from_bytes(last) else {
        return false;
    };
    if last.len() as u64 != cert.n {
        return false;
    }
    let cap = MerkleCap::from_digests(&last, proof::seal_cap_height(cert.n));
    cap.commitment(Tree::Replica) == cert.labels
        && kept.comm_c == cert.columns
        && kept.verified_last_layer() == Some(last)
}

/// Whether a sector's cached certificate proof verifies as GLOBAL verifies
/// it, before it is sent again.
fn proof_verifies(
    member: &[u8; 32],
    cert: &sector::Certificate,
    epoch: u64,
    beacon: &[u8],
    bytes: &[u8],
) -> bool {
    use quil_execution::global_intrinsic::persistent_storage as protocol;
    let message = protocol::CapacityMessage {
        member: *member,
        epoch,
        certificate: *cert,
        signed_at: 0,
        signature: Vec::new(),
        proof: Vec::new(),
    };
    let root = message.root();
    protocol::verify_certificate(member, &cert.sector, epoch, cert.n, &root, beacon, bytes).is_ok()
}

pub(super) fn encode_leaf(
    captured: &Captured,
    member: &[u8],
    prefix: &[u32],
    replicas: &ReplicaStore,
    store: Option<&LabelStore>,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<(u64, bool, usize)> {
    let store = store
        .ok_or_else(|| unavailable("persistent storage requires a sector directory".into()))?;
    if stop() {
        return Err(unavailable("persistent snapshot stopped".into()));
    }
    let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&captured.filter, prefix);
    let exact = captured.node_count(prefix)?;
    let (dir, id, n) = reserve(store, member, &leaf, captured.epoch, exact)?;
    let sector = Sector::load(dir)?
        .filter(|sector| sector.certified)
        .ok_or_else(|| {
            unavailable("sector certification must finish before data registration".into())
        })?;
    let fingerprint = captured.fingerprint(member, prefix);
    if let Some(from) = replicas.snapshot_match(&leaf, &fingerprint)? {
        if let Some(old) = replicas.get_hash_leaf(from, &leaf)? {
            if sector::Registration::parse(&old.registration_root)
                .is_some_and(|r| r.certificate(old.n) == sector.cert)
                && replicas.alias_hash(captured.epoch, &leaf, from)?
            {
                replicas.note_snapshot(captured.epoch, &leaf, &fingerprint)?;
                return Ok((n, true, 0));
            }
        }
    }
    if stop() {
        return Err(unavailable("persistent snapshot stopped".into()));
    }
    let _memory = crate::storage_jobs::reserve_until(proof::encoding_with_labels_bytes(n), stop)
        .ok_or_else(|| unavailable("persistent encoding stopped waiting for memory".into()))?;
    let data = captured.leaf_data(prefix)?;
    if proof::data_node_count(data.len() as u64) != exact {
        return Err(unavailable(
            "snapshot layout metadata differs from data".into(),
        ));
    }
    let found = sector.last();
    // A last layer damaged or lost on disk since its sector was certified
    // would encode a replica whose proofs can never open it: check it against
    // the certificate first, as its encoding reads every node anyway.
    let whole = found.as_ref().is_ok_and(|last| {
        let cap = MerkleCap::from_digests(last, proof::seal_cap_height(n));
        cap.commitment(Tree::Replica) == sector.cert.labels
    });
    if !whole {
        // Once an epoch: the sector is labelled again, its labels being its
        // own, and its last layer rewritten when they match its certificate.
        let marker = sector.dir.join(format!("repair-{}", captured.epoch));
        if !marker.exists() && atomic(&marker, &[]).is_ok() {
            warn!(epoch = captured.epoch, sector = %hex::encode(id), nodes = n, scope = "local",
                action = "check this node's disk and its kernel log for I/O errors",
                "a certified sector's last layer on disk is missing or does not match its \
                 certificate, as a torn, damaged or lost file on this node's disk leaves it; \
                 the sector is labelled again, and its leaves are encoded once that ends");
            repair_last(store, member, captured.epoch, &sector);
        }
        return Err(unavailable(
            "sector last layer differs from its certificate; it is labelled again".into(),
        ));
    }
    let last = found?;
    let encoded = proof::encode_with_labels(&data, n, &last, sector.cert.labels)
        .map_err(QuilError::InvalidArgument)?;
    let root = sector::Registration {
        profile: sector.cert.profile,
        data: encoded.comm_d,
        labels: sector.cert.labels,
        replica: encoded.comm_r,
        sector: id,
        columns: sector.cert.columns,
    };
    replicas.put_hash(
        captured.epoch,
        &leaf,
        &encoded.replica,
        &encoded.replica_cap.to_bytes(),
        &root.to_bytes(),
    )?;
    replicas.put_data_cap(captured.epoch, &leaf, &encoded.data_cap)?;
    replicas.note_snapshot(captured.epoch, &leaf, &fingerprint)?;
    Ok((n, true, 0))
}

struct Source {
    sector: Sector,
    last: Mutex<File>,
    cap: MerkleCap,
    data: MerkleCap,
    replicas: ReplicaStore,
    epoch: u64,
    leaf: Vec<u8>,
    stored: Arc<quil_store::replica_store::HashLeaf>,
}
impl Source {
    fn new(
        store: &LabelStore,
        replicas: &ReplicaStore,
        member: &[u8],
        epoch: u64,
        leaf: Vec<u8>,
    ) -> Result<Self> {
        let stored = replicas
            .get_hash_leaf(epoch, &leaf)?
            .ok_or_else(|| unavailable("persistent replica is absent".into()))?;
        let root = sector::Registration::parse(&stored.registration_root)
            .ok_or_else(|| unavailable("not a persistent registration".into()))?;
        let sector = Sector::load(home(store, member).join(hex::encode(root.sector)))?
            .ok_or_else(|| unavailable("sector final labels are absent".into()))?;
        if sector.cert != root.certificate(stored.n) {
            return Err(unavailable(
                "sector differs from registered certificate".into(),
            ));
        }
        let cap = cap_or_repair(store, member, epoch, &sector)?;
        let data = replicas
            .get_data_cap(epoch, &leaf)?
            .ok_or_else(|| unavailable("persistent data cap is absent".into()))?;
        if data.n != stored.n || data.commitment(Tree::Data) != root.data {
            return Err(unavailable(
                "persistent data cap differs from registration".into(),
            ));
        }
        // A last layer gone from disk fails every seal: it is labelled again.
        let last = match File::open(sector.dir.join("last")) {
            Ok(file) => Mutex::new(file),
            Err(error) => {
                repair_if_torn(store, member, epoch, &sector);
                return Err(io(error));
            }
        };
        Ok(Self {
            sector,
            last,
            cap,
            data,
            replicas: replicas.clone(),
            epoch,
            leaf,
            stored,
        })
    }
    fn labels(&self, range: std::ops::Range<u64>) -> Option<Vec<u8>> {
        if range.start > range.end || range.end > self.stored.n {
            return None;
        }
        let mut file = self.last.lock().ok()?;
        file.seek(SeekFrom::Start(range.start * 32)).ok()?;
        let mut bytes = vec![0; (range.end - range.start) as usize * 32];
        file.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
    fn open(&self, tree: Tree, index: u64) -> Option<(Node, Vec<Node>)> {
        let cap = match tree {
            Tree::Data => &self.data,
            Tree::Column => &self.cap,
            Tree::Replica => &self.stored.cap,
        };
        let range = cap.subtree(index)?;
        let bytes = self.nodes(tree, range.clone())?;
        let path = cap.subtree_path(&bytes, index)?;
        let at = (index - range.start) as usize * 32;
        Some((bytes[at..at + 32].try_into().ok()?, path))
    }
}
impl LabelSource for Source {
    fn cap(&self, tree: Tree) -> Option<MerkleCap> {
        Some(match tree {
            Tree::Data => self.data.clone(),
            Tree::Column => self.cap.clone(),
            Tree::Replica => self.stored.cap.clone(),
        })
    }
    fn nodes(&self, tree: Tree, range: std::ops::Range<u64>) -> Option<Vec<u8>> {
        if tree == Tree::Column {
            return self.labels(range);
        }
        let mut bytes = self
            .replicas
            .read_nodes(self.epoch, &self.leaf, &self.stored, range.clone())
            .ok()?;
        if tree == Tree::Data {
            let last = hash::digests_from_bytes(&self.labels(range)?)?;
            let mut data = hash::digests_from_bytes(&bytes)?;
            for (value, label) in data.iter_mut().zip(last) {
                *value = hash::sub(value, &label);
            }
            bytes = hash::digests_to_bytes(&data);
        }
        Some(bytes)
    }
    fn label(&self, _layer: usize, _v: u64) -> Option<Node> {
        None
    }
    fn columns(&self) -> Option<Vec<hash::Digest>> {
        None
    }
    fn last_layer(&self) -> Option<Vec<hash::Digest>> {
        self.sector.last().ok()
    }
}

pub(super) fn observe_sealed(
    replicas: &ReplicaStore,
    member: &[u8],
    filter: &[u8],
    slot: &quil_types::consensus::StorageSeatSlot,
) -> Result<()> {
    let Some(store) = crate::storage_labels::installed() else {
        return Ok(());
    };
    for prefix in &slot.leaves {
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        let Some(stored) = replicas.get_hash_leaf(slot.epoch, &leaf)? else {
            continue;
        };
        let Some(root) = sector::Registration::parse(&stored.registration_root) else {
            continue;
        };
        if let Some(mut sector) = Sector::load(home(store, member).join(hex::encode(root.sector)))?
        {
            if sector.cert != root.certificate(stored.n) {
                return Err(unavailable(
                    "observed sector differs from certificate".into(),
                ));
            }
            sector.certified = true;
            sector.save()?;
        }
    }
    Ok(())
}

pub(super) fn prepare(
    replicas: &ReplicaStore,
    member: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    slot: &quil_types::consensus::StorageSeatSlot,
    output: &[u8],
    captured: &Captured,
) -> Result<crate::storage_epoch_batch::PreparedSeat> {
    use quil_execution::global_intrinsic::storage_epoch_proof::{
        SealedLeaf, SeatClaim, SeatProof, SeatWitness,
    };
    let store = crate::storage_labels::installed()
        .ok_or_else(|| unavailable("persistent sector store is absent".into()))?;
    let target = epoch + 2;
    if captured.epoch != target || captured.filter != filter || slot.epoch != target {
        return Err(unavailable(
            "persistent snapshot epoch or shard mismatch".into(),
        ));
    }
    let beacon = quil_crypto::porep::derive_storage_beacon(slot.registered_at + 1, output);
    let mut claim = SeatClaim {
        seal_epoch: target,
        settle_epoch: epoch,
        ..Default::default()
    };
    let mut witness = SeatWitness {
        certificates: Vec::new(),
        seals: Vec::new(),
        opened: Vec::new(),
    };
    let mut bindings = Vec::new();
    let prepared = crate::storage_jobs::for_each_parallel(&slot.leaves, |prefix| {
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(filter, prefix);
        let source = Source::new(store, replicas, member, target, leaf.clone())?;
        let n = source.stored.n;
        if !source.sector.certified {
            return Err(unavailable(
                "sector certificate acknowledgment is pending".into(),
            ));
        }
        let _memory = crate::storage_jobs::reserve(64 << 20);
        let root = sector::Registration::parse(&source.stored.registration_root).unwrap();
        let leaf_claim = captured.claim(prefix, &leaf, member, &beacon, root.data, n)?;
        let binding = captured
            .prove_binding_sparse(&leaf_claim, &source)
            .inspect_err(|_| repair_if_torn(store, member, target, &source.sector))?;
        let seal = sector::prove(member, &leaf, target, n, &root, &beacon, &|tree, index| {
            source.open(tree, index)
        })
        .map_err(|error| {
            repair_if_torn(store, member, target, &source.sector);
            QuilError::InvalidArgument(error)
        })?;
        let leaf = SealedLeaf {
            persistent: Some(root),
            n,
            registered: root.registered(),
            beacon: beacon.clone(),
            leaf_id: leaf,
        };
        Ok((binding, seal, leaf))
    })?;
    for (binding, seal, leaf) in prepared {
        let n = leaf.n;
        bindings.push(binding);
        witness.seals.push(seal);
        witness.certificates.push(Vec::new());
        let proof_bytes = witness
            .seals
            .iter()
            .enumerate()
            .try_fold(0usize, |total, (i, proof)| {
                sector::encode_proof(proof, claim.seals.get(i).map_or(n, |leaf| leaf.n))
                    .map(|bytes| total + bytes.len() + 8)
            })
            .map_err(QuilError::InvalidArgument)?;
        let bytes = proof_bytes
            + bindings
                .iter()
                .map(|binding| binding.to_bytes().len() + 4)
                .sum::<usize>();
        if bytes > quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME.saturating_sub(4096) {
            return Err(unavailable(
                "persistent snapshot proof exceeds GLOBAL message budget".into(),
            ));
        }
        claim.seals.push(leaf);
    }
    Ok(crate::storage_epoch_batch::PreparedSeat {
        member: *member,
        part: SeatProof {
            shard_filter: filter.to_vec(),
            epoch,
            seals: true,
            settles: false,
            frames: Vec::new(),
            bindings,
        },
        claim,
        witness,
        solo: false,
    })
}

/// Warm sectors side by side, bounded globally by CPU, memory and disk admission.
pub(crate) fn prewarm_sectors(
    captured: &Captured,
    store: &LabelStore,
    member: &[u8],
) -> Result<()> {
    let sizes = captured
        .prefixes
        .iter()
        .map(|p| captured.leaf_size(p))
        .collect::<Result<Vec<_>>>()?;
    let orders = crate::storage_labels::ahead_orders(
        captured.epoch,
        crate::storage_jobs::ahead_place(),
        &sizes,
    );
    let mut tasks = Vec::new();
    for (prefix, order) in captured.prefixes.iter().zip(orders) {
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&captured.filter, prefix);
        let Some((dir, id, n)) = try_reserve(
            store,
            member,
            &leaf,
            captured.epoch,
            captured.node_count(prefix)?,
        )?
        else {
            break;
        };
        if Sector::load(dir.clone())?.is_some() {
            continue;
        }
        tasks.push((dir, id, n, order));
    }
    crate::storage_jobs::for_each_parallel(&tasks, |(dir, id, n, order)| {
        let gone = || crate::storage_jobs::stopping();
        let memory = crate::storage_jobs::reserve_ahead(
            crate::storage_labels::label_ahead_bytes(*n),
            *order,
            captured.epoch,
            &gone,
        )
        .ok_or_else(|| unavailable("sector warmup stopped".into()))?;
        initialize(store, member, captured.epoch, dir.clone(), *id, *n, &|| {
            memory.wait_while_paused(&gone);
            gone() || memory.yield_requested()
        })?;
        Ok(())
    })?;
    Ok(())
}

/// GLOBAL refuses a precommit signed more than 10 frames before the frame
/// that takes it: a signed precommit is resent unchanged for this many
/// frames from its signing, which leaves its last copy time to land.
const PRECOMMIT_REUSE_FRAMES: u64 = 6;
/// Frames between two sends of the same precommit.
const PRECOMMIT_RESEND_FRAMES: u64 = 3;
/// Frames before a certificate GLOBAL has not taken is sent again: archives
/// keep a message for 10 finalized frames, so an earlier copy is only a
/// duplicate. The wait doubles at each resend, up to
/// [`CERTIFICATE_RESEND_MAX_FRAMES`].
const CERTIFICATE_RESEND_FRAMES: u64 = 15;
const CERTIFICATE_RESEND_MAX_FRAMES: u64 = 120;
/// How far the frame the sector pool was last polled at may lie ahead of a
/// poll's frame, or of the newest GLOBAL frame this node holds: an hour at
/// 10 s frames, far more than application engines' GLOBAL frames differ
/// by. One further ahead is a damaged file, not a poll of this node's.
const POLL_AHEAD_FRAMES: u64 = 360;
/// Frames between two capacity traffic summary lines.
const POLL_SUMMARY_FRAMES: u64 = 60;

/// Capacity traffic since the last summary line.
struct Pacing {
    polls: std::sync::atomic::AtomicU64,
    precommits_signed: std::sync::atomic::AtomicU64,
    precommits_resent: std::sync::atomic::AtomicU64,
    precommits_held: std::sync::atomic::AtomicU64,
    certificates_sent: std::sync::atomic::AtomicU64,
    certificates_held: std::sync::atomic::AtomicU64,
    summary_at: Mutex<Option<u64>>,
}
static PACING: Pacing = Pacing {
    polls: std::sync::atomic::AtomicU64::new(0),
    precommits_signed: std::sync::atomic::AtomicU64::new(0),
    precommits_resent: std::sync::atomic::AtomicU64::new(0),
    precommits_held: std::sync::atomic::AtomicU64::new(0),
    certificates_sent: std::sync::atomic::AtomicU64::new(0),
    certificates_held: std::sync::atomic::AtomicU64::new(0),
    summary_at: Mutex::new(None),
};
fn tally(counter: &std::sync::atomic::AtomicU64) {
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Count a poll at `frame`, and log one summary line of capacity traffic
/// every [`POLL_SUMMARY_FRAMES`] frames that sent any.
fn poll_summary(frame: u64) {
    tally(&PACING.polls);
    let mut at = PACING
        .summary_at
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let since = *at.get_or_insert(frame);
    if since <= frame && frame < since.saturating_add(POLL_SUMMARY_FRAMES) {
        return;
    }
    *at = Some(frame);
    let take = |c: &std::sync::atomic::AtomicU64| c.swap(0, std::sync::atomic::Ordering::Relaxed);
    let polls = take(&PACING.polls);
    let (signed, resent, held) = (
        take(&PACING.precommits_signed),
        take(&PACING.precommits_resent),
        take(&PACING.precommits_held),
    );
    let (sent, backed_off) = (
        take(&PACING.certificates_sent),
        take(&PACING.certificates_held),
    );
    if signed + resent + sent > 0 {
        info!(
            frame,
            frames = frame.saturating_sub(since),
            polls,
            precommits_signed = signed,
            precommits_resent = resent,
            precommits_held = held,
            certificates_sent = sent,
            certificates_backed_off = backed_off,
            "sector capacity traffic: the pool is polled once per new GLOBAL frame, a \
             precommit is resent unchanged while GLOBAL takes it, and a certificate \
             GLOBAL has not taken is resent at a widening interval"
        );
    }
}

/// Whether the sector pool polls at `frame`, recorded in `path`: once per
/// new GLOBAL frame. Each application engine polls with the GLOBAL frame it
/// has seen, and those differ: a poll from a frame at or below the last one
/// polled would sign and send its sectors' messages again. `head` is the
/// newest GLOBAL frame this node holds: a poll from a frame behind it is
/// skipped too, as it would retarget sectors to an epoch already past.
fn poll_due(path: &Path, frame: u64, head: u64) -> Result<bool> {
    let last = fs::read(path)
        .ok()
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes);
    let ahead = frame.max(head).saturating_add(POLL_AHEAD_FRAMES);
    if last.is_some_and(|last| frame <= last && last <= ahead) {
        return Ok(false);
    }
    atomic(path, &frame.to_be_bytes())?;
    Ok(true)
}

/// The precommit `sector` sends for `target` at `frame`, if one is due. It
/// is signed once and resent unchanged every [`PRECOMMIT_RESEND_FRAMES`],
/// so archives and the GLOBAL leader hold and check one copy; it is signed
/// again for a new target, or [`PRECOMMIT_REUSE_FRAMES`] after its signing,
/// before GLOBAL would find it stale.
fn precommit_due(
    sector: &Sector,
    member: &[u8; 32],
    target: u64,
    frame: u64,
    signer: &dyn quil_types::crypto::Signer,
) -> Result<Option<Vec<u8>>> {
    use quil_execution::global_intrinsic::persistent_storage as protocol;
    let path = sector.dir.join("precommit");
    let key = digest(&[target.to_be_bytes().as_slice(), &sector.cert.to_bytes()].concat());
    let held = fs::read(&path)
        .ok()
        .filter(|b| b.len() > 48 && b[..32] == key);
    if let Some(mut held) = held {
        let signed_at = u64::from_be_bytes(held[32..40].try_into().unwrap());
        let sent_at = u64::from_be_bytes(held[40..48].try_into().unwrap());
        if signed_at <= sent_at && sent_at <= frame && frame - signed_at < PRECOMMIT_REUSE_FRAMES {
            if frame - sent_at < PRECOMMIT_RESEND_FRAMES {
                tally(&PACING.precommits_held);
                return Ok(None);
            }
            held[40..48].copy_from_slice(&frame.to_be_bytes());
            atomic(&path, &held)?;
            tally(&PACING.precommits_resent);
            return Ok(Some(held.split_off(48)));
        }
    }
    let mut message = protocol::CapacityMessage {
        member: *member,
        epoch: target,
        certificate: sector.cert,
        signed_at: frame,
        signature: Vec::new(),
        proof: Vec::new(),
    };
    message.signature =
        signer.sign_with_domain(&message.signing_message(), &protocol::capacity_domain()?)?;
    let bytes = message.envelope().to_canonical_bytes();
    let at = frame.to_be_bytes();
    atomic(&path, &[key.as_slice(), &at, &at, &bytes].concat())?;
    tally(&PACING.precommits_signed);
    Ok(Some(bytes))
}

/// When a sector's certificate for `target` and `beacon_frame` was last
/// sent, and how many times.
fn certificate_sends(dir: &Path, target: u64, beacon_frame: u64) -> Option<(u64, u64)> {
    let bytes = <[u8; 32]>::try_from(fs::read(dir.join("certificate-sent")).ok()?).ok()?;
    let at = |i: usize| u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    (at(0) == target && at(1) == beacon_frame).then_some((at(2), at(3)))
}

/// Whether a sector's certificate is sent at `frame`: at once the first
/// time, then, while GLOBAL has not taken it, again after
/// [`CERTIFICATE_RESEND_FRAMES`], doubled at each resend.
fn certificate_due(dir: &Path, target: u64, beacon_frame: u64, frame: u64) -> bool {
    let Some((sent_at, sends)) = certificate_sends(dir, target, beacon_frame) else {
        return true;
    };
    let wait = CERTIFICATE_RESEND_FRAMES
        .saturating_mul(1 << sends.saturating_sub(1).min(8))
        .min(CERTIFICATE_RESEND_MAX_FRAMES);
    frame < sent_at || frame >= sent_at.saturating_add(wait)
}

/// Record that a sector's certificate was sent at `frame`.
fn certificate_sent(dir: &Path, target: u64, beacon_frame: u64, frame: u64) -> Result<()> {
    let sends = certificate_sends(dir, target, beacon_frame).map_or(0, |(_, sends)| sends);
    tally(&PACING.certificates_sent);
    atomic(
        &dir.join("certificate-sent"),
        &[target, beacon_frame, frame, sends.saturating_add(1)]
            .map(u64::to_be_bytes)
            .concat(),
    )
}

// A lost shard or a restart must not strand the pool behind an unfinished
// reservation. Capacity is independent of that shard's data; finish it here.
fn resume_reserved_sector(
    store: &'static LabelStore,
    member: &[u8; 32],
    dir: PathBuf,
) -> Result<()> {
    let bytes = fs::read(dir.join("reservation")).map_err(io)?;
    if bytes.len() != 48 && bytes.len() != 52 {
        return Err(unavailable("sector reservation length".into()));
    }
    let n = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let epoch = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    if !sector::padded_nodes_allowed(n, n) || !quil_types::consensus::persistent_storage_at(epoch) {
        return Err(unavailable("sector reservation capacity or epoch".into()));
    }
    let id: [u8; 32] = hex::decode(dir.file_name().and_then(|s| s.to_str()).unwrap_or(""))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| unavailable("sector directory identity".into()))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("resuming"))
        .map_err(io)?;
    if lock.try_lock().is_err() {
        return Ok(());
    }
    let member = *member;
    crate::storage_jobs::spawn(
        &sector_lane(&member, &id),
        "sector initialization",
        move || {
            let _lock = lock;
            let order = crate::storage_jobs::AheadOrder {
                deferrable: false,
                seat_leaves: 1,
                seat: crate::storage_jobs::ahead_place(),
                leaf: 0,
            };
            let memory = crate::storage_jobs::reserve_ahead(
                crate::storage_labels::label_ahead_bytes(n),
                order,
                epoch,
                &crate::storage_jobs::stopping,
            )
            .ok_or_else(|| unavailable("sector initialization stopped".into()))?;
            initialize(store, &member, epoch, dir, id, n, &|| {
                memory.wait_while_paused(&crate::storage_jobs::stopping);
                crate::storage_jobs::stopping() || memory.yield_requested()
            })?;
            Ok(())
        },
    );
    Ok(())
}

/// Whether a sector's damaged precommit target is reported now: once an
/// epoch a sector, as polls from engines whose frames lie far apart may each
/// find the other's target past their next epoch.
fn target_warn_due(dir: &Path, epoch: u64) -> bool {
    static WARNED: Mutex<std::collections::BTreeMap<PathBuf, u64>> =
        Mutex::new(std::collections::BTreeMap::new());
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    warned.insert(dir.to_owned(), epoch) != Some(epoch)
}

/// The precommit holding a sector's GLOBAL slot: its sector id and epoch.
type SlotHolder = ([u8; 32], u64);

/// A sector's wait for its GLOBAL precommit slot: its sector, the epoch the
/// wait began, the last epoch of the term of the precommit it waits behind,
/// the precommit last found holding the slot, the one past the term last
/// reported, and the poll frame that last found the slot held.
struct SlotWait {
    sector: [u8; 32],
    since: u64,
    term: u64,
    holder: SlotHolder,
    warned: Option<SlotHolder>,
    seen: u64,
}

/// The sectors whose precommit waits for its slot, by directory.
static SLOT_WAITS: Mutex<std::collections::BTreeMap<PathBuf, SlotWait>> =
    Mutex::new(std::collections::BTreeMap::new());

/// Note that a sector's precommit waits for its slot, held by `holder`.
/// A precommit holds its slot through the two epochs after its own, which
/// in the capacity warmup is the first persistent epoch, so a wait lasts
/// that term: it is noted as it begins, with the epoch it ends by, and
/// again as a precommit that took the slot within the term extends it. A
/// precommit found holding the slot past the term took it again: warned
/// once for each.
fn slot_wait(
    sector: &Sector,
    frame: u64,
    current: u64,
    target: u64,
    holder: &quil_execution::global_intrinsic::persistent_storage::PendingCertificate,
) {
    let mut waits = SLOT_WAITS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let held = (holder.certificate.sector, holder.epoch);
    let mut begun = false;
    let wait = waits.entry(sector.dir.clone()).or_insert_with(|| {
        begun = true;
        SlotWait {
            sector: sector.cert.sector,
            since: current,
            term: holder.epoch.saturating_add(2),
            holder: held,
            warned: None,
            seen: frame,
        }
    });
    wait.seen = frame;
    let (id, held_by) = (
        hex::encode(sector.cert.sector),
        hex::encode(holder.certificate.sector),
    );
    if current > wait.term {
        wait.holder = held;
        if wait.warned != Some(held) {
            wait.warned = Some(held);
            warn!(frame, sector = %id, target, waited = current.saturating_sub(wait.since),
                held_by = %held_by, held_for = holder.epoch, term_ended = wait.term,
                scope = "local",
                action = "check the certification of this member's sector holding the slot: \
                          one never certified precommits into it again as each precommit \
                          expires",
                "a sector's precommit has waited for its GLOBAL slot past the term of the \
                 precommit it waited behind: another precommit took the slot again");
        }
        return;
    }
    if begun || wait.holder != held {
        wait.holder = held;
        wait.term = wait.term.max(holder.epoch.saturating_add(2));
        info!(frame, sector = %id, target, held_by = %held_by, held_for = holder.epoch,
            ends_by = wait.term.saturating_add(1),
            "a sector's precommit waits: another precommit of this member holds its GLOBAL \
             slot, which refuses this one until that one's epoch has passed by two or its \
             sector is certified; nothing is sent before then, and the wait ends by epoch \
             ends_by");
    }
}

/// End the wait of each sector in `root` that the poll at `frame` did not
/// find waiting for its slot, however its poll ended: the slot freed, the
/// sector was certified, its member's sector cap held it back, it could
/// not be polled, or it is gone.
fn slot_waits_ended(root: &Path, frame: u64, current: u64) {
    SLOT_WAITS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|dir, wait| {
            if dir.parent() != Some(root) || wait.seen == frame {
                return true;
            }
            info!(frame, sector = %hex::encode(wait.sector),
                waited = current.saturating_sub(wait.since),
                "a sector's precommit no longer waits for its GLOBAL slot: the slot is free, \
                 or the sector was certified, held back by its member's sector cap, not \
                 polled or removed");
            false
        });
}

/// Poll committed GLOBAL records, never execution's speculative overlay.
/// Proof generation has a separate lane and durable retry files; a restart
/// neither relabels certified capacity nor changes an accepted precommit.
pub(crate) fn poll_sector_certificates(
    frame: u64,
    member: &[u8; 32],
    global: &Arc<HypergraphCrdt>,
    anchors: Arc<dyn ClockStore>,
    signer: &dyn quil_types::crypto::Signer,
    publish: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
) -> Result<()> {
    use quil_execution::global_intrinsic::persistent_storage as protocol;
    let first = quil_types::consensus::persistent_storage_epoch();
    let current = quil_types::consensus::epoch_for_frame(frame);
    if !quil_types::consensus::persistent_storage_warmup_at(current) {
        return Ok(());
    }
    let Some(store) = crate::storage_labels::installed() else {
        return Ok(());
    };
    let root = home(store, member);
    if !root.is_dir() {
        return Ok(());
    }
    let lock = File::open(&root).map_err(io)?;
    if lock.try_lock().is_err() {
        return Ok(());
    }
    // All application engines share this pool. Poll it once per GLOBAL
    // frame, and never from a frame older than one polled: a materialized
    // frame behind the head would retarget its sectors and sign precommits
    // GLOBAL refuses as stale.
    let poll = root.join("last-poll");
    let head = anchors
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|latest| latest.header)
        .map_or(0, |header| header.frame_number);
    if !poll_due(&poll, frame, head)? {
        return Ok(());
    }
    poll_summary(frame);
    let snapshot = global.capture_committed_snapshot()?;
    // One sector at a time: a sector that cannot be read, or that differs
    // from GLOBAL, is skipped and never holds back the others.
    let poll_one = |entry: fs::DirEntry| -> Result<()> {
        let Some(mut sector) = Sector::load(entry.path())? else {
            resume_reserved_sector(store, member, entry.path())?;
            return Ok(());
        };
        let initialized = fs::read(sector.dir.join("reservation")).map_err(io)?;
        let cache_epoch = u64::from_be_bytes(
            initialized
                .get(8..16)
                .ok_or_else(|| unavailable("bad sector reservation".into()))?
                .try_into()
                .unwrap(),
        );
        if let Some(known) =
            protocol::committed_certificate(snapshot.as_ref(), member, &sector.cert.sector)?
        {
            if known != sector.cert {
                return Err(unavailable(
                    "GLOBAL sector certificate differs from disk".into(),
                ));
            }
            if !sector.certified {
                sector.certified = true;
                sector.save()?;
            }
            store
                .for_profile(sector.cert.profile)
                .release_certified_sector(cache_epoch, member, &sector.cert.sector);
            return Ok(());
        }
        // A disk flag is only a hint. Authority always comes from GLOBAL.
        if sector.certified {
            return Err(unavailable(
                "certified sector absent from committed GLOBAL state".into(),
            ));
        }
        // GLOBAL would refuse it: wait, labelled, until a seat opens room.
        // Certified sectors go on serving every leaf they fit.
        let room = protocol::committed_sector_room(snapshot.as_ref(), member)?;
        if room.full() {
            // Bounded to one line an hour at 10 s frames.
            if frame.is_multiple_of(360) {
                warn!(frame, sector = %hex::encode(sector.cert.sector), held = room.held,
                    cap = room.cap(), seats = room.seats, scope = "local",
                    "sector certification waits: this member holds its sector cap; a new \
                     seat opens room, and certified sectors keep serving leaves they fit");
            }
            return Ok(());
        }
        let target_path = sector.dir.join("capacity-target");
        let previous = fs::read(&target_path)
            .ok()
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes);
        // A target is written as the next epoch, or the first, and kept
        // two epochs past it at most: one past both is damage.
        let next = first.max(current.saturating_add(1));
        if previous.is_some_and(|e| e > next) && target_warn_due(&sector.dir, current) {
            warn!(frame, sector = %hex::encode(sector.cert.sector), stored = ?previous, next,
                scope = "local", action = "check this node's disk if this recurs",
                "a sector's precommit target on disk is past the next epoch, as a damaged \
                 file leaves it; it precommits for the next epoch instead");
        }
        let target = previous
            .filter(|e| current <= e.saturating_add(2) && *e <= next)
            .unwrap_or(next);
        atomic(&target_path, &target.to_be_bytes())?;
        let pending = protocol::committed_pending(snapshot.as_ref(), member, &sector.cert, target)?;
        let (pending, holder) = match pending {
            Some(p) if p.epoch == target && p.certificate == sector.cert => (Some(p), None),
            other => (None, other),
        };
        // GLOBAL refuses a precommit while its slot (this member, the
        // sector id's first byte mod 16 and the target mod 4) holds another
        // whose epoch has not passed by two and whose sector is not
        // certified (`persistent_storage::check_capacity`): a sector given
        // a new certificate, or another sharing its slot, waits rather than
        // sending one GLOBAL refuses at every frame.
        if let Some(holder) = holder.filter(|h| h.epoch >= current.saturating_sub(2)) {
            let certified = protocol::committed_certificate(
                snapshot.as_ref(),
                member,
                &holder.certificate.sector,
            )?;
            if certified.is_none() {
                slot_wait(&sector, frame, current, target, &holder);
                return Ok(());
            }
        }
        let Some(pending) = pending else {
            if let Some(precommit) = precommit_due(&sector, member, target, frame, signer)? {
                publish(precommit);
            }
            return Ok(());
        };
        let beacon_frame = pending.committed_at.saturating_add(1);
        if frame <= beacon_frame {
            return Ok(());
        }
        let Some(header) = anchors.get_global_clock_frame(beacon_frame)?.header else {
            return Ok(());
        };
        let beacon = quil_crypto::porep::derive_storage_beacon(beacon_frame, &header.output);
        let proving = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(sector.dir.join("proving"))
            .map_err(io)?;
        if proving.try_lock().is_err() {
            return Ok(());
        }
        let cache = sector.dir.join(format!("proof-{target}-{beacon_frame}"));
        // Refresh temporary layers while needed, but a durable proof can be
        // retransmitted after pressure eviction without regenerating them.
        let kept_epoch = cache_epoch.max(current.saturating_add(1));
        let kept = store.for_profile(sector.cert.profile).find(
            kept_epoch,
            member,
            &sector.cert.sector,
            |n| n == sector.cert.n,
        );
        if kept.is_none() && !cache.is_file() {
            resume_reserved_sector(store, member, sector.dir.clone())?;
            return Ok(());
        }
        if !certificate_due(&sector.dir, target, beacon_frame, frame) {
            tally(&PACING.certificates_held);
            return Ok(());
        }
        let member = *member;
        let publish = publish.clone();
        crate::storage_jobs::spawn(
            &sector_lane(&member, &sector.cert.sector),
            "sector certificate",
            move || {
                let _guard = proving;
                let verifies =
                    |bytes: &[u8]| proof_verifies(&member, &sector.cert, target, &beacon, bytes);
                let bytes = match fs::read(&cache) {
                    Ok(bytes) if verifies(&bytes) => bytes,
                    Ok(_) => {
                        warn!(epoch = target, sector = %hex::encode(sector.cert.sector),
                            scope = "local", action = "check this node's disk if this recurs",
                            "a sector's cached certificate proof does not verify, as a damaged \
                             file leaves it; it is removed and made again");
                        let _ = fs::remove_file(&cache);
                        return Err(unavailable(
                            "cached sector certificate proof does not verify".into(),
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let kept = kept.ok_or_else(|| {
                            unavailable("sector proof cache and temporary layers are absent".into())
                        })?;
                        let _memory = crate::storage_jobs::reserve(
                            proof::labelling_peak_bytes(sector.cert.n, &sector.cert.params())
                                .saturating_add(400 << 20),
                        );
                        let message = protocol::CapacityMessage {
                            member,
                            epoch: target,
                            certificate: sector.cert,
                            signed_at: 0,
                            signature: Vec::new(),
                            proof: Vec::new(),
                        };
                        let root = message.root();
                        let last = fs::read(sector.dir.join("last")).map_err(io)?;
                        // Damaged labels or a damaged last layer fail the
                        // proof at every poll: they are removed instead, and
                        // the sector is labelled again from the next poll.
                        if !proof_inputs_whole(&kept, &last, &sector.cert) {
                            warn!(epoch = target, sector = %hex::encode(sector.cert.sector),
                                scope = "local",
                                action = "check this node's disk and kernel log for I/O errors",
                                "a sector's kept labels or last layer on disk do not match its \
                                 certificate, as a damaged file leaves them; they are removed \
                                 and the sector is labelled again before its proof");
                            drop(kept);
                            let labels = store.for_profile(sector.cert.profile);
                            labels.discard_damaged(
                                kept_epoch,
                                &member,
                                &sector.cert.sector,
                                sector.cert.n,
                            );
                            return Err(unavailable(
                                "sector proof files differ from its certificate".into(),
                            ));
                        }
                        let challenge = sector::certificate_beacon(
                            &member,
                            &sector.cert.sector,
                            target,
                            sector.cert.n,
                            &root,
                            &beacon,
                        );
                        let statement = proof::SealStatement {
                            member: &member,
                            leaf_id: &sector.cert.sector,
                            epoch: target,
                            n: sector.cert.n,
                            registered: sector.cert.registered().unwrap(),
                            beacon: &challenge,
                        };
                        let plain = proof::prove_seal_with_labels(
                            &last,
                            &statement,
                            &sector.cert.params(),
                            sector::CHALLENGES,
                            &kept,
                        )
                        .map_err(QuilError::InvalidArgument)?;
                        let bytes =
                        quil_execution::global_intrinsic::persistent_storage::prove_certificate(
                            &member,
                            &sector.cert.sector,
                            target,
                            sector.cert.n,
                            &root,
                            &beacon,
                            &plain,
                        )
                        .map_err(QuilError::InvalidArgument)?;
                        atomic(&cache, &bytes)?;
                        bytes
                    }
                    Err(e) => return Err(io(e)),
                };
                certificate_sent(&sector.dir, target, beacon_frame, frame)?;
                publish(
                    protocol::CapacityMessage {
                        member,
                        epoch: target,
                        certificate: sector.cert,
                        signed_at: 0,
                        signature: Vec::new(),
                        proof: bytes,
                    }
                    .envelope()
                    .to_canonical_bytes(),
                );
                Ok(())
            },
        );
        Ok(())
    };
    for entry in fs::read_dir(&root).map_err(io)?.flatten() {
        if !sector_directory(&entry.path()) {
            continue;
        }
        let (name, path) = (entry.file_name(), entry.path());
        if let Err(error) = poll_one(entry) {
            // Bounded to one line an hour at 10 s frames.
            if frame.is_multiple_of(360) {
                let action = if Sector::load(path).is_err() {
                    "check this node's disk and its kernel log for I/O errors"
                } else {
                    "none if it clears as this node follows GLOBAL; it is retried each frame"
                };
                warn!(frame, sector = %name.to_string_lossy(), %error, scope = "local", action,
                    "a sector could not be polled for certification and is skipped; \
                     the other sectors are polled as usual");
            }
        }
    }
    slot_waits_ended(&root, frame, current);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gates(on: bool) {
        quil_types::consensus::set_persistent_storage_epoch_for_thread(on.then_some(1500));
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(on.then_some(1393));
        // These fixtures intentionally cover existing eleven-layer sectors.
        quil_types::consensus::set_storage_seal_profile_for_thread(
            on.then_some(quil_types::consensus::StorageSealProfile::Eleven),
        );
    }
    #[test]
    fn scheduled_mainnet_warmup_builds_three_layer_sectors_for_the_first_epoch() {
        gates(false);
        let first = quil_types::consensus::MAINNET_PERSISTENT_STORAGE_EPOCH.unwrap();
        quil_types::consensus::set_min_sector_nodes_for_thread(Some(64));
        crate::storage_jobs::set_available_for_test(Some(64 << 30));
        let graph = super::super::tests::test_crdt();
        let filter = [0xB4; 32];
        graph
            .add_vertex(
                &quil_hypergraph::Location {
                    app_address: filter,
                    data_address: [1; 32],
                },
                &[7; 100],
            )
            .unwrap();
        graph.commit(1).unwrap();
        let captured = capture_at(
            &graph,
            &filter,
            first,
            &[current_source(&graph, &filter, first)],
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [0xC4; 32];
        prewarm_sectors(&captured, &store, &member).unwrap();
        let sector = fs::read_dir(home(&store, &member))
            .unwrap()
            .flatten()
            .filter(|entry| sector_directory(&entry.path()))
            .find_map(|entry| Sector::load(entry.path()).unwrap())
            .unwrap();
        assert_eq!(sector.cert.profile, sector::Profile::Three);
        assert!(
            !sector.certified,
            "only committed GLOBAL acknowledgment certifies capacity"
        );
        assert_eq!(fs::read(sector.dir.join("reservation")).unwrap().len(), 52);
        assert!(store
            .for_profile(sector::Profile::Three)
            .find(first, &member, &sector.cert.sector, |n| n == sector.cert.n)
            .is_some());
        assert!(store
            .find(first, &member, &sector.cert.sector, |_| true)
            .is_none());
        quil_types::consensus::set_min_sector_nodes_for_thread(None);
        crate::storage_jobs::set_available_for_test(None);
    }

    #[test]
    fn sectors_are_labelled_at_no_less_than_the_certified_floor() {
        use quil_types::consensus::{set_min_sector_nodes_for_thread, MIN_SECTOR_NODES};
        gates(true);
        set_min_sector_nodes_for_thread(Some(MIN_SECTOR_NODES));
        assert_eq!(sector_nodes(100), Some(MIN_SECTOR_NODES));
        assert_eq!(sector_nodes(MIN_SECTOR_NODES), Some(MIN_SECTOR_NODES * 2));
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let (_, _, n) = reserve(&store, &[18; 32], b"small", 1500, 100).unwrap();
        assert_eq!(n, MIN_SECTOR_NODES);
        set_min_sector_nodes_for_thread(None);
        gates(false);
    }
    #[test]
    fn sectors_are_small_in_tests_unless_the_thread_sets_the_floor() {
        use quil_types::consensus::{set_min_sector_nodes_for_thread, MIN_SECTOR_NODES};
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        // A thread a test spawns carries no scoped epoch and no floor.
        let spawned = || reserve(&store, &[19; 32], b"spawned", 1500, 100).unwrap();
        let (_, _, n) = std::thread::scope(|scope| scope.spawn(spawned).join().unwrap());
        assert_eq!(n, 128, "a test labels a small sector by default");
        set_min_sector_nodes_for_thread(Some(MIN_SECTOR_NODES));
        assert_eq!(sector_nodes(100), Some(MIN_SECTOR_NODES), "a test opts in");
        set_min_sector_nodes_for_thread(None);
        assert_eq!(sector_nodes(100), Some(128));
    }
    #[test]
    fn a_member_at_its_sector_cap_publishes_nothing_until_a_seat_opens_room() {
        use quil_execution::global_intrinsic::{materialize, persistent_storage as protocol};
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{
                hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState,
            },
        };
        use quil_types::crypto::Signer;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let key = TestIdentity.public_key();
        let member = materialize::prover_address_from_pubkey(key).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let adds = vertex_adds_discriminator().unwrap();
        let prover = materialize::create_prover_vertex_tree(key, 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &adds,
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&prover),
            )
            .unwrap();
        let held = quil_types::consensus::max_certified_sectors(0);
        protocol::apply(
            &state,
            frame,
            &[protocol::sector_count_record(&member, held)],
        )
        .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"new leaf", 1500, 100).unwrap();
        initialize(store, &member, 1500, path, id, n, &|| false).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        poll_sector_certificates(
            frame,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        assert!(
            recv.try_recv().is_err(),
            "GLOBAL would refuse this precommit"
        );
        let state = HypergraphState::new(global.clone());
        let filter = [4u8; 32];
        let address = materialize::allocation_address(key, &filter).unwrap();
        let seat = materialize::create_allocation_vertex_tree(&member, &filter, frame).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &address,
                &adds,
                frame + 1,
                quil_execution::prover_registry::vertex_tree_to_blob(&seat),
            )
            .unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &hyperedge_adds_discriminator().unwrap(),
                frame + 1,
                materialize::build_prover_allocation_hyperedge_blob(&member, &[(address, &seat)])
                    .unwrap(),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame + 1).unwrap();
        poll_sector_certificates(frame + 1, &member, &global, clock, &TestIdentity, publish)
            .unwrap();
        let precommit =
            quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof::from_canonical_bytes(
                &recv.try_recv().expect("a seat opened room"),
            )
            .unwrap();
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame + 1, &precommit, &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        assert_eq!(records.len(), 1, "GLOBAL takes it now");
        gates(false);
    }
    #[test]
    fn pool_bounds_cold_work_and_reuses_certified_capacity_after_restart() {
        crate::storage_jobs::set_job_slots_for_test(1);
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [17; 32];
        let abandoned = home(&store, &member).join(".new-sector-interrupted");
        fs::create_dir_all(&abandoned).unwrap();
        fs::write(abandoned.join("reservation.tmp"), b"partial").unwrap();
        let (path, id, n) = reserve(&store, &member, b"first", 1500, 100).unwrap();
        assert!(!abandoned.exists());
        assert_eq!(fs::read(path.join("reservation")).unwrap().len(), 48);
        assert!(n >= 125, "reserve growth headroom");
        let first = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        assert!(!first.certified);
        assert!(store.find(1500, &member, &id, |count| count == n).is_some());
        assert_eq!(reserve(&store, &member, b"first", 1500, 100).unwrap().1, id);
        assert!(
            reserve(&store, &member, b"second", 1500, 100).is_err(),
            "one uncertified sector per available CPU slot"
        );
        let mut first = Sector::load(path).unwrap().unwrap();
        first.certified = true;
        first.save().unwrap();
        store.release_certified_sector(1500, &member, &id);
        assert!(store.find(1500, &member, &id, |count| count == n).is_none());
        assert!(first.cap().is_ok());
        assert_eq!(first.last().unwrap().len(), n as usize);
        // Another shard/leaf in a later epoch uses the same identity-bound L.
        let reopened =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        assert_eq!(
            reserve(&reopened, &member, b"different shard", 1501, 110)
                .unwrap()
                .1,
            id
        );
        let (other, other_id, _) = reserve(&reopened, &member, b"second", 1501, 100).unwrap();
        assert_ne!(
            other_id, id,
            "same-epoch leases cannot count one sector twice"
        );
        assert!(Sector::load(other).unwrap().is_none());
        gates(false);
    }
    /// A sector's last layer, up to 2 GiB, goes to disk as its labels do: a
    /// chunk at a time through the flush gate, paced, then synced. Written
    /// whole, then synced, it held the stores' synced commits behind all of
    /// it (2026-11-07). Its bytes are as before.
    #[test]
    fn a_sectors_last_layer_goes_to_disk_a_gated_chunk_at_a_time() {
        use crate::storage_labels::{set_chunk_bytes_for_test, take_gated_pushes};
        const CHUNK: u64 = 1024;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [0xD4; 32];
        let (path, id, n) = reserve(&store, &member, b"paced", 1500, 100).unwrap();
        set_chunk_bytes_for_test(Some(CHUNK as usize));
        let first = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let written = fs::read(path.join("last")).unwrap();
        // Labelled already, as warmup labels ahead: only the last layer is
        // written now.
        fs::remove_file(path.join("certificate")).unwrap();
        fs::remove_file(path.join("last")).unwrap();
        take_gated_pushes();
        let again = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let (chunks, bytes) = take_gated_pushes();
        set_chunk_bytes_for_test(None);
        let last = n * 32;
        assert!(
            bytes == last && chunks == last.div_ceil(CHUNK),
            "PACE-LABELS-LAST: a sector's last layer of {last} bytes went to disk as {chunks} \
             gated chunks of {bytes} bytes in all, not a {CHUNK}-byte chunk at a time \
             through the flush gate"
        );
        assert_eq!(fs::read(path.join("last")).unwrap(), written);
        assert_eq!(again.cert, first.cert);
        assert_eq!(again.last().unwrap().len(), n as usize);
        gates(false);
    }
    /// The one kept layers file of `n` nodes under the label store at `dir`.
    fn kept_layers(dir: &Path, n: u64) -> PathBuf {
        let name = format!("{n}.layers");
        let (mut found, mut stack) = (Vec::new(), vec![dir.to_owned()]);
        while let Some(at) = stack.pop() {
            for entry in fs::read_dir(&at).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().and_then(|f| f.to_str()) == Some(name.as_str()) {
                    found.push(path);
                }
            }
        }
        assert_eq!(found.len(), 1, "one kept layers file: {found:?}");
        found.pop().unwrap()
    }
    /// A sector is set up from its kept labels only when they are whole
    /// (`Kept::verified_last_layer`), as a snapshot encodes from them: labels
    /// torn over their last layer, as a damaged disk leaves them, are
    /// labelled again, and the sector commits to the labels it makes, never
    /// to the torn layer, which its certificate proof could not open.
    #[test]
    fn a_sector_is_not_set_up_from_kept_labels_torn_over_their_last_layer() {
        use std::os::unix::fs::FileExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [29; 32];
        let (path, id, n) = reserve(&store, &member, b"torn", 1500, 100).unwrap();
        let whole = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let whole_last = whole.last().unwrap();
        // Set up again from the kept labels, as after a crash before the
        // sector's certificate was written, the second half of their last
        // layer zeroed and the file's length unchanged.
        fs::remove_file(path.join("certificate")).unwrap();
        let layers = kept_layers(dir.path(), n);
        let torn = (n - n / 2) * 32;
        let at = fs::metadata(&layers).unwrap().len() - torn;
        let file = OpenOptions::new().write(true).open(&layers).unwrap();
        file.write_all_at(&vec![0u8; torn as usize], at).unwrap();
        drop(file);
        let again = initialize(&store, &member, 1500, path.clone(), id, n, &|| false)
            .expect("LAST-LAYER-RELABEL: a sector whose kept labels are torn is labelled again");
        assert!(
            again.cert == whole.cert && again.last().unwrap() == whole_last,
            "LAST-LAYER-CERT: a sector was set up from kept labels torn over their last layer"
        );
        gates(false);
    }
    /// A certified sector encodes data only from a last layer that matches
    /// its certificate: one torn on disk since, its length unchanged, would
    /// give a replica its proofs could never open. The leaf is refused and
    /// nothing is stored for it, and it is encoded once the layer is whole.
    #[test]
    fn a_leaf_is_not_encoded_into_a_sector_whose_last_layer_is_torn() {
        use std::os::unix::fs::FileExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [31; 32];
        let app = [33; 32];
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"torn payload").unwrap();
        crdt.commit(1).unwrap();
        let capture =
            |epoch| capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let snap = capture(1500);
        let prefix = &snap.prefixes[0];
        prewarm_sectors(&snap, &store, &member).unwrap();
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
        let exact = snap.node_count(prefix).unwrap();
        let (path, id, n) = reserve(&store, &member, &leaf, 1500, exact).unwrap();
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1500, &member, &id);
        // The second half of the certified last layer zeroed, its length
        // unchanged, as a damaged disk leaves it.
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        let file = OpenOptions::new().write(true).open(&last).unwrap();
        let torn = (n - n / 2) as usize * 32;
        file.write_all_at(&vec![0u8; torn], n / 2 * 32).unwrap();
        drop(file);
        assert_ne!(fs::read(&last).unwrap(), whole);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let encoded = encode_leaf(&snap, &member, prefix, &replicas, Some(&store), &|| false);
        assert!(
            encoded.is_err() && replicas.get_hash_leaf(1500, &leaf).unwrap().is_none(),
            "LAST-LAYER-ENCODE: a leaf was encoded into a sector whose last layer is torn"
        );
        fs::write(&last, &whole).unwrap();
        encode_leaf(&snap, &member, prefix, &replicas, Some(&store), &|| false).unwrap();
        assert!(replicas.get_hash_leaf(1500, &leaf).unwrap().is_some());
        gates(false);
    }
    /// A sector precommits for the next epoch whatever target its disk
    /// holds: a target past the next epoch, as a damaged file leaves it,
    /// would pin each precommit to an epoch it is never taken for.
    #[test]
    fn a_sector_precommits_for_the_next_epoch_past_a_damaged_target() {
        use quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof;
        use quil_execution::global_intrinsic::{materialize, persistent_storage as protocol};
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"damaged target", 1500, 100).unwrap();
        initialize(store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        // A target far past the next epoch, as a damaged disk leaves it.
        let target = path.join("capacity-target");
        fs::write(&target, 1_000_000u64.to_be_bytes()).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        let polled =
            poll_sector_certificates(frame + 1, &member, &global, clock, &TestIdentity, publish);
        let next = 1500u64.max(quil_types::consensus::epoch_for_frame(frame + 1) + 1);
        assert_eq!(
            fs::read(&target).unwrap(),
            next.to_be_bytes(),
            "LAST-LAYER-TARGET: a sector kept a precommit target past the next epoch"
        );
        polled.unwrap();
        let sent = recv.try_recv().unwrap();
        let precommit = StorageEpochProof::from_canonical_bytes(&sent).unwrap();
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame + 1, &precommit, &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        assert_eq!(records.len(), 1, "GLOBAL takes it");
        gates(false);
    }
    /// A sector that cannot be read is skipped by a poll, never ending it:
    /// the other sectors still precommit.
    #[test]
    fn a_damaged_sector_does_not_hold_back_the_others_certification() {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        crate::storage_jobs::set_job_slots_for_test(2);
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (whole, id, n) = reserve(store, &member, b"whole", 1500, 100).unwrap();
        initialize(store, &member, 1500, whole, id, n, &|| false).unwrap();
        let (torn, id, n) = reserve(store, &member, b"torn", 1500, 100).unwrap();
        initialize(store, &member, 1500, torn.clone(), id, n, &|| false).unwrap();
        // Its certificate torn, as a damaged disk leaves it.
        fs::write(torn.join("certificate"), b"torn").unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        let polled =
            poll_sector_certificates(frame + 1, &member, &global, clock, &TestIdentity, publish);
        assert!(
            polled.is_ok(),
            "LAST-LAYER-POLL: a damaged sector ended the poll of every other sector"
        );
        assert!(recv.try_recv().is_ok(), "the whole sector precommits");
        assert!(recv.try_recv().is_err(), "the damaged sector does not");
        gates(false);
    }
    /// A sector is set up from kept labels only when every node of their
    /// last layer chains to its column digest: one damaged node, which a
    /// sample of the leaf's nodes would most likely miss, is labelled again.
    #[test]
    fn a_sector_is_not_set_up_from_kept_labels_with_one_damaged_node() {
        use std::os::unix::fs::FileExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [39; 32];
        let (path, id, n) = reserve(&store, &member, b"one node", 1500, 400).unwrap();
        assert!(n > 256, "more nodes than a sample checks");
        let whole = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let whole_last = whole.last().unwrap();
        // Set up again, as after a crash before the certificate was written,
        // one node in the middle of the kept last layer zeroed.
        fs::remove_file(path.join("certificate")).unwrap();
        let layers = kept_layers(dir.path(), n);
        let at = fs::metadata(&layers).unwrap().len() - (n - n / 2 - 1) * 32;
        let file = OpenOptions::new().write(true).open(&layers).unwrap();
        file.write_all_at(&[0u8; 32], at).unwrap();
        drop(file);
        let again = initialize(&store, &member, 1500, path.clone(), id, n, &|| false)
            .expect("LAST-LAYER-NODE: kept labels with a damaged node are labelled again");
        assert!(
            again.cert == whole.cert && again.last().unwrap() == whole_last,
            "LAST-LAYER-NODE: a sector was set up from kept labels with a damaged node"
        );
        gates(false);
    }
    /// A certified sector whose last layer is torn on disk is labelled
    /// again, and its last layer rewritten from labels that match its
    /// certificate: the leaf it refused is then encoded.
    #[test]
    fn a_certified_sector_with_a_torn_last_layer_is_labelled_again() {
        use std::os::unix::fs::FileExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [41; 32];
        let app = [43; 32];
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"torn payload").unwrap();
        crdt.commit(1).unwrap();
        let capture =
            |epoch| capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let snap = capture(1500);
        let prefix = &snap.prefixes[0];
        prewarm_sectors(&snap, &store, &member).unwrap();
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
        let exact = snap.node_count(prefix).unwrap();
        let (path, id, n) = reserve(&store, &member, &leaf, 1500, exact).unwrap();
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1500, &member, &id);
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        let file = OpenOptions::new().write(true).open(&last).unwrap();
        let torn = (n - n / 2) as usize * 32;
        file.write_all_at(&vec![0u8; torn], n / 2 * 32).unwrap();
        drop(file);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let encoded = loop {
            let encoded = encode_leaf(&snap, &member, prefix, &replicas, Some(&store), &|| false);
            if encoded.is_ok() || std::time::Instant::now() > deadline {
                break encoded;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert!(
            encoded.is_ok() && fs::read(&last).unwrap() == whole,
            "LAST-LAYER-REPAIR: a certified sector's torn last layer was not labelled again"
        );
        gates(false);
    }
    /// The certificate poll never goes back in frames: a poll from a frame
    /// older than one polled, as a materialized frame behind the head brings,
    /// neither retargets a sector nor sends a stale precommit.
    #[test]
    fn a_poll_from_an_older_frame_changes_nothing() {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"older frame", 1500, 100).unwrap();
        initialize(store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        let head = 1500 * quil_types::consensus::epoch_length_frames() + 5;
        poll_sector_certificates(
            head,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        assert!(recv.try_recv().is_ok(), "the head's poll precommits");
        let target = fs::read(path.join("capacity-target")).unwrap();
        poll_sector_certificates(head - 10, &member, &global, clock, &TestIdentity, publish)
            .unwrap();
        assert!(
            recv.try_recv().is_err() && fs::read(path.join("capacity-target")).unwrap() == target,
            "LAST-LAYER-BACKWARDS: a poll from an older frame retargeted or precommitted again"
        );
        gates(false);
    }
    /// One sector whose certificate cannot be read holds back no other
    /// leaf's reservation.
    #[test]
    fn a_damaged_sector_does_not_hold_back_reservations() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [45; 32];
        let (torn, id, n) = reserve(&store, &member, b"torn", 1500, 100).unwrap();
        initialize(&store, &member, 1500, torn.clone(), id, n, &|| false).unwrap();
        fs::write(torn.join("certificate"), b"torn").unwrap();
        let other = reserve(&store, &member, b"other", 1500, 100);
        assert!(
            other.is_ok(),
            "LAST-LAYER-RESERVE: a damaged sector held back another leaf's reservation"
        );
        gates(false);
    }
    /// A sector's certificate proof is made only from files that match its
    /// certificate, and a cached proof is sent again only when it verifies:
    /// a last layer torn before the proof is labelled again, and a torn
    /// cached proof is removed rather than sent.
    #[test]
    fn a_sector_proof_is_made_and_sent_only_from_whole_files() {
        use quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof;
        use quil_execution::global_intrinsic::{materialize, persistent_storage as protocol};
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        use std::time::Duration;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"proof files", 1500, 100).unwrap();
        initialize(store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        poll_sector_certificates(
            frame + 1,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        let precommit = StorageEpochProof::from_canonical_bytes(
            &recv.recv_timeout(Duration::from_secs(5)).unwrap(),
        )
        .unwrap();
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame + 1, &precommit, &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        protocol::apply(&state, frame + 1, &records).unwrap();
        state.commit().unwrap();
        global.commit(frame + 1).unwrap();
        let output = vec![9; 516];
        let txn = clock.new_transaction(false).unwrap();
        clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: frame + 2,
                        output: output.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
        // The last layer torn before the sector's proof is made.
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        let mut torn = whole.clone();
        torn[whole.len() / 2..].fill(0);
        fs::write(&last, &torn).unwrap();
        let mut at = frame + 3;
        let mut sent = None;
        while sent.is_none() && at < frame + 600 {
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            sent = recv.recv_timeout(Duration::from_millis(200)).ok();
            at += 1;
        }
        let sent = sent.map(|bytes| StorageEpochProof::from_canonical_bytes(&bytes).unwrap());
        let state = HypergraphState::new(global.clone());
        let proven = sent.is_some_and(|certificate| {
            protocol::check_capacity(frame + 4, &certificate, &state, &TestIdentity, &|at| {
                assert_eq!(at, frame + 2);
                Ok(output.clone())
            })
            .is_ok()
        });
        assert!(
            proven && fs::read(&last).unwrap() == whole,
            "LAST-LAYER-PROVE: no certificate proof was made from the sector's whole files"
        );
        // A cached proof torn, then sent again while GLOBAL has not taken it.
        let proving = File::open(path.join("proving")).unwrap();
        for _ in 0..1000 {
            if proving.try_lock().is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(proving);
        // A later poll of the loop above may have sent the cached proof
        // again before the first send was received.
        while recv.try_recv().is_ok() {}
        let mut cache = None;
        for entry in fs::read_dir(&path).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with("proof-") {
                cache = Some(entry.path());
            }
        }
        let cache = cache.expect("a cached certificate proof");
        let proof = fs::read(&cache).unwrap();
        fs::write(&cache, &proof[..proof.len() / 2]).unwrap();
        // GLOBAL has not taken the proof: it is sent again once its resend
        // wait has passed. A poll of the loop above may have sent it again,
        // doubling the wait, so this poll lies past the longest wait.
        let at = at + CERTIFICATE_RESEND_MAX_FRAMES;
        poll_sector_certificates(at, &member, &global, clock, &TestIdentity, publish).unwrap();
        let proving = File::open(path.join("proving")).unwrap();
        for _ in 0..1000 {
            if proving.try_lock().is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            recv.try_recv().is_err(),
            "LAST-LAYER-CACHE: a cached certificate proof that does not verify was sent"
        );
        assert!(
            !cache.exists(),
            "LAST-LAYER-CACHE-KEPT: a cached certificate proof that does not verify was kept"
        );
        gates(false);
    }
    /// A registered replica's sector whose last layer is torn on disk is
    /// labelled again when its seal fails: with its snapshot unchanged, the
    /// leaf is never encoded again, so the seal is where the damage shows.
    #[test]
    fn a_registered_sector_with_a_torn_last_layer_is_labelled_again() {
        use std::os::unix::fs::FileExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = [47; 32];
        let app = [49; 32];
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"served payload").unwrap();
        crdt.commit(1).unwrap();
        let capture =
            |epoch| capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let snap = capture(1502);
        let prefix = &snap.prefixes[0];
        prewarm_sectors(&snap, store, &member).unwrap();
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
        let exact = snap.node_count(prefix).unwrap();
        let (path, id, n) = reserve(store, &member, &leaf, 1502, exact).unwrap();
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1502, &member, &id);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        encode_leaf(&snap, &member, prefix, &replicas, Some(store), &|| false).unwrap();
        // The registered sector's last layer torn, its length unchanged.
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        let file = OpenOptions::new().write(true).open(&last).unwrap();
        let torn = (n - n / 2) as usize * 32;
        file.write_all_at(&vec![0u8; torn], n / 2 * 32).unwrap();
        drop(file);
        let slot = quil_types::consensus::StorageSeatSlot {
            epoch: 1502,
            leaves: vec![prefix.clone()],
            registered_at: 1502 * quil_types::consensus::epoch_length_frames(),
            sealed_at: None,
            frames: 0,
            accumulator: [0; 32],
            chained: Vec::new(),
            open: true,
        };
        let output = vec![9; 516];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let prepared = loop {
            let prepared = prepare(&replicas, &member, &app, 1500, &slot, &output, &snap);
            if prepared.is_ok() || std::time::Instant::now() > deadline {
                break prepared;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert!(
            prepared.is_ok() && fs::read(&last).unwrap() == whole,
            "LAST-LAYER-SERVE: a registered sector's torn last layer was not labelled again"
        );
        gates(false);
    }
    /// A certified sector holding the one leaf of `app`'s data, set up at
    /// epoch 1500: the data, the leaf's prefix, and the sector's directory,
    /// id and nodes.
    fn certified_leaf(
        store: &LabelStore,
        member: &[u8; 32],
        app: [u8; 32],
    ) -> (
        Arc<quil_hypergraph::HypergraphCrdt>,
        Vec<u32>,
        PathBuf,
        [u8; 32],
        u64,
    ) {
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"repaired payload").unwrap();
        crdt.commit(1).unwrap();
        let snap = capture_at(&crdt, &app, 1500, &[current_source(&crdt, &app, 1500)]).unwrap();
        let prefix = snap.prefixes[0].clone();
        prewarm_sectors(&snap, store, member).unwrap();
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, &prefix);
        let exact = snap.node_count(&prefix).unwrap();
        let (path, id, n) = reserve(store, member, &leaf, 1500, exact).unwrap();
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1500, member, &id);
        (crdt, prefix, path, id, n)
    }
    /// The second half of a sector's last layer zeroed, its length
    /// unchanged, as a damaged disk leaves it: the whole layer's bytes.
    fn tear_last(path: &Path, n: u64) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        let file = OpenOptions::new().write(true).open(&last).unwrap();
        let torn = (n - n / 2) as usize * 32;
        file.write_all_at(&vec![0u8; torn], n / 2 * 32).unwrap();
        whole
    }
    /// A sector whose labels, made again, do not match its certificate, as
    /// a damaged certificate file leaves it, is labelled again once and
    /// then given up: no later epoch labels it again, and its leaf goes to
    /// another sector.
    #[test]
    fn a_sector_whose_repair_cannot_match_its_certificate_is_given_up() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let (member, app) = ([51; 32], [57; 32]);
        let (crdt, prefix, path, id, _) = certified_leaf(&store, &member, app);
        // The certificate's labels damaged, the file still read whole.
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.cert.labels = sector.cert.columns;
        sector.save().unwrap();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let lane = sector_lane(&member, &id);
        let idle = std::time::Duration::from_secs(120);
        let encode = |epoch| {
            let snap =
                capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
            let encoded = encode_leaf(&snap, &member, &prefix, &replicas, Some(&store), &|| false);
            assert!(
                crate::storage_jobs::wait_lane_idle(&lane, idle),
                "the repair ends"
            );
            encoded
        };
        let _ = encode(1500);
        let _ = encode(1501);
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, &prefix);
        let snap = capture_at(&crdt, &app, 1501, &[current_source(&crdt, &app, 1501)]).unwrap();
        let exact = snap.node_count(&prefix).unwrap();
        let (_, again, _) = reserve(&store, &member, &leaf, 1501, exact).unwrap();
        assert!(
            again != id && !path.join("repair-1501").exists(),
            "LAST-LAYER-GIVE-UP: a sector whose repair cannot match its certificate was \
             labelled again or kept its leaf"
        );
        gates(false);
    }
    /// A sector queues at most one repair: a repair running longer than an
    /// epoch queues none behind it each epoch.
    #[test]
    fn a_sector_queues_at_most_one_repair() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let (member, app) = ([53; 32], [59; 32]);
        let (crdt, prefix, path, id, n) = certified_leaf(&store, &member, app);
        let whole = tear_last(&path, n);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        // A job running on the sector's lane through three epochs, as a long
        // repair runs.
        let lane = sector_lane(&member, &id);
        let (release, running) = std::sync::mpsc::channel::<()>();
        crate::storage_jobs::spawn(&lane, "long repair", move || {
            let _ = running.recv();
            Ok(())
        });
        for epoch in 1500..1503 {
            let snap =
                capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
            let _ = encode_leaf(&snap, &member, &prefix, &replicas, Some(&store), &|| false);
        }
        let queued = crate::storage_jobs::queued_in_lane(&lane);
        release.send(()).unwrap();
        let idle = std::time::Duration::from_secs(120);
        assert!(
            crate::storage_jobs::wait_lane_idle(&lane, idle),
            "the repairs end"
        );
        assert_eq!(
            queued, 1,
            "LAST-LAYER-QUEUE: a sector queued other than one repair over three epochs"
        );
        assert_eq!(fs::read(path.join("last")).unwrap(), whole);
        gates(false);
    }
    /// A repair that finds its sector's last layer whole when it starts, as
    /// a repair before it leaves it, labels nothing again.
    #[test]
    fn a_repair_of_a_whole_last_layer_labels_nothing() {
        use std::os::unix::fs::MetadataExt;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let (member, app) = ([55; 32], [61; 32]);
        let (crdt, prefix, path, id, n) = certified_leaf(&store, &member, app);
        let whole = tear_last(&path, n);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let lane = sector_lane(&member, &id);
        let (release, running) = std::sync::mpsc::channel::<()>();
        crate::storage_jobs::spawn(&lane, "earlier repair", move || {
            let _ = running.recv();
            Ok(())
        });
        let snap = capture_at(&crdt, &app, 1500, &[current_source(&crdt, &app, 1500)]).unwrap();
        let _ = encode_leaf(&snap, &member, &prefix, &replicas, Some(&store), &|| false);
        let queued = crate::storage_jobs::queued_in_lane(&lane);
        // The layer made whole while the repair waits, as the repair before
        // it leaves it.
        let last = path.join("last");
        fs::write(&last, whole).unwrap();
        let inode = fs::metadata(&last).unwrap().ino();
        release.send(()).unwrap();
        let idle = std::time::Duration::from_secs(120);
        assert!(
            crate::storage_jobs::wait_lane_idle(&lane, idle),
            "the repair ends"
        );
        assert_eq!(
            queued, 1,
            "LAST-LAYER-REPAIR: a torn last layer queued no repair"
        );
        assert_eq!(
            fs::metadata(&last).unwrap().ino(),
            inode,
            "LAST-LAYER-AGAIN: a repair labelled a sector whose last layer was whole again"
        );
        gates(false);
    }
    /// A poll is not skipped for a last-polled frame past every frame known,
    /// as a damaged file leaves it: the sector still precommits.
    #[test]
    fn a_sector_precommits_past_a_damaged_last_poll() {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"damaged last poll", 1500, 100).unwrap();
        initialize(store, &member, 1500, path, id, n, &|| false).unwrap();
        // A last-polled frame far past every frame, as a damaged file
        // leaves it.
        fs::write(
            home(store, &member).join("last-poll"),
            u64::MAX.to_be_bytes(),
        )
        .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        poll_sector_certificates(frame + 1, &member, &global, clock, &TestIdentity, publish)
            .unwrap();
        assert!(
            recv.try_recv().is_ok(),
            "LAST-LAYER-FUTURE: a damaged last-polled frame stopped the sector's precommit"
        );
        gates(false);
    }
    /// Each sector's checks of its last layer against its certificate
    /// (`Sector::last_matches`), by directory.
    static LAST_CHECKS: Mutex<std::collections::BTreeMap<PathBuf, usize>> =
        Mutex::new(std::collections::BTreeMap::new());
    pub(super) fn count_last_check(dir: &Path) {
        *LAST_CHECKS
            .lock()
            .unwrap()
            .entry(dir.to_owned())
            .or_default() += 1;
    }
    fn last_checks(dir: &Path) -> usize {
        LAST_CHECKS.lock().unwrap().get(dir).copied().unwrap_or(0)
    }
    /// Each read of a sector's last layer (`Sector::last`), by directory:
    /// the bytes this process held reserved as it began.
    static LAST_READS: Mutex<std::collections::BTreeMap<PathBuf, Vec<u64>>> =
        Mutex::new(std::collections::BTreeMap::new());
    pub(super) fn count_last_read(dir: &Path) {
        LAST_READS
            .lock()
            .unwrap()
            .entry(dir.to_owned())
            .or_default()
            .push(crate::storage_jobs::held_bytes());
    }
    fn last_reads(dir: &Path) -> Vec<u64> {
        LAST_READS
            .lock()
            .unwrap()
            .get(dir)
            .cloned()
            .unwrap_or_default()
    }
    /// A certified sector set up at epoch 1502, the one leaf of `app`'s data
    /// encoded into it, and the seat slot that seals the leaf: the
    /// snapshot, the slot, the replicas, and the sector's directory and
    /// nodes.
    fn registered_leaf(
        store: &LabelStore,
        member: &[u8; 32],
        app: [u8; 32],
    ) -> (
        Captured,
        quil_types::consensus::StorageSeatSlot,
        ReplicaStore,
        PathBuf,
        u64,
    ) {
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"served payload").unwrap();
        crdt.commit(1).unwrap();
        let snap = capture_at(&crdt, &app, 1502, &[current_source(&crdt, &app, 1502)]).unwrap();
        let prefix = snap.prefixes[0].clone();
        prewarm_sectors(&snap, store, member).unwrap();
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, &prefix);
        let exact = snap.node_count(&prefix).unwrap();
        let (path, id, n) = reserve(store, member, &leaf, 1502, exact).unwrap();
        let mut sector = Sector::load(path.clone()).unwrap().unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1502, member, &id);
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        encode_leaf(&snap, member, &prefix, &replicas, Some(store), &|| false).unwrap();
        let slot = quil_types::consensus::StorageSeatSlot {
            epoch: 1502,
            leaves: vec![prefix],
            registered_at: 1502 * quil_types::consensus::epoch_length_frames(),
            sealed_at: None,
            frames: 0,
            accumulator: [0; 32],
            chained: Vec::new(),
            open: true,
        };
        (snap, slot, replicas, path, n)
    }
    /// A registered replica whose sector's repair was given up
    /// (`Sector::given_up`) marks no repair when its seal fails, nor warns
    /// that one starts: the sector is never labelled again, and its leaves
    /// go to another.
    #[test]
    fn a_failing_seal_of_a_given_up_sector_marks_no_repair() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([65; 32], [67; 32]);
        let (snap, slot, replicas, path, n) = registered_leaf(store, &member, app);
        tear_last(&path, n);
        // Given up, as a repair whose labels differ from the certificate
        // leaves it.
        let sector = Sector::load(path.clone()).unwrap().unwrap();
        fs::write(path.join("repair-failed"), sector.cert.to_bytes()).unwrap();
        let prepared = prepare(&replicas, &member, &app, 1500, &slot, &[9u8; 516], &snap);
        assert!(prepared.is_err(), "a torn last layer fails the seal");
        assert!(
            !path.join("repair-1502").exists(),
            "LAST-LAYER-SEAL-GIVE-UP: a failing seal of a given-up sector marked a repair"
        );
        gates(false);
    }
    /// A failing seal checks its sector's last layer against the
    /// certificate only while no repair is marked this epoch: each failing
    /// leaf of the sector would read the layer again, 32 bytes a node,
    /// outside any reservation.
    #[test]
    fn a_failing_seal_reads_no_last_layer_once_a_repair_is_marked() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([69; 32], [71; 32]);
        let (snap, slot, replicas, path, n) = registered_leaf(store, &member, app);
        tear_last(&path, n);
        // A repair marked this epoch, as an earlier failing seal leaves it.
        fs::write(path.join("repair-1502"), b"").unwrap();
        let prepared = prepare(&replicas, &member, &app, 1500, &slot, &[9u8; 516], &snap);
        assert!(prepared.is_err(), "a torn last layer fails the seal");
        assert_eq!(
            last_checks(&path),
            0,
            "LAST-LAYER-MARKED-READ: a failing seal read its sector's last layer though its \
             repair was marked this epoch"
        );
        gates(false);
    }
    /// A failing seal reads no last layer to rewrite its sector's damaged
    /// cap from once a repair is marked this epoch, nor for a sector given
    /// up: each failing leaf would read the layer again, up to 2 GiB.
    #[test]
    fn a_damaged_cap_reads_no_last_layer_once_a_repair_is_marked_or_given_up() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([83; 32], [85; 32]);
        let (snap, slot, replicas, path, n) = registered_leaf(store, &member, app);
        tear_last(&path, n);
        fs::write(path.join("cap"), b"torn").unwrap();
        let before = last_reads(&path).len();
        // A repair marked this epoch, as an earlier failing seal leaves it.
        fs::write(path.join("repair-1502"), b"").unwrap();
        let marked = prepare(&replicas, &member, &app, 1500, &slot, &[9u8; 516], &snap);
        let read_marked = last_reads(&path).len() - before;
        // Given up, as a repair whose labels differ from the certificate
        // leaves it.
        fs::remove_file(path.join("repair-1502")).unwrap();
        let sector = Sector::load(path.clone()).unwrap().unwrap();
        fs::write(path.join("repair-failed"), sector.cert.to_bytes()).unwrap();
        let given_up = prepare(&replicas, &member, &app, 1500, &slot, &[9u8; 516], &snap);
        let read_given_up = last_reads(&path).len() - before - read_marked;
        assert_eq!(
            (read_marked, read_given_up),
            (0, 0),
            "LAST-LAYER-CAP-READ: a failing seal read its sector's last layer for a damaged cap \
             though its repair was marked, or the sector given up"
        );
        assert!(
            marked.is_err() && given_up.is_err(),
            "a damaged cap over a torn last layer fails the seal"
        );
        gates(false);
    }
    /// A damaged cap is rewritten from a last layer read under a
    /// reservation of its size: up to 2 GiB, read outside any, it would
    /// take memory every other storage job waits for.
    #[test]
    fn a_damaged_cap_reads_its_last_layer_under_a_reservation() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([87; 32], [89; 32]);
        let (_, _, _, path, n) = registered_leaf(store, &member, app);
        let cap = fs::read(path.join("cap")).unwrap();
        fs::write(path.join("cap"), b"torn").unwrap();
        let sector = Sector::load(path.clone()).unwrap().unwrap();
        let (before, held) = (last_reads(&path).len(), crate::storage_jobs::held_bytes());
        let rewritten = cap_or_repair(store, &member, 1502, &sector);
        let reads = last_reads(&path)[before..].to_vec();
        assert!(
            reads.len() == 1 && reads[0] >= held + n * 32,
            "LAST-LAYER-CAP-RESERVED: a damaged cap's last layer was read holding {reads:?} \
             bytes reserved, not {held} and its {} bytes",
            n * 32
        );
        assert!(
            rewritten.is_ok() && fs::read(path.join("cap")).unwrap() == cap,
            "a whole last layer rewrites a damaged cap"
        );
        gates(false);
    }
    /// An uncertified sector whose certificate on disk differs from the one
    /// its labels, made again, give, as a sector set up from torn kept
    /// labels leaves it, takes the certificate they give: GLOBAL holds the
    /// old one only as a pending precommit, so its target and cached proof
    /// are dropped and it precommits anew. Refused, it was labelled again at
    /// every poll, with no end.
    #[test]
    fn an_uncertified_sector_takes_the_certificate_its_labels_give() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [73; 32];
        let (path, id, n) = reserve(&store, &member, b"certified anew", 1500, 100).unwrap();
        let whole = initialize(&store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        // Its certificate committed to other labels, its target and a proof
        // made for them on disk.
        let mut torn = Sector::load(path.clone()).unwrap().unwrap();
        torn.cert.labels = torn.cert.columns;
        torn.save().unwrap();
        fs::write(path.join("capacity-target"), 1501u64.to_be_bytes()).unwrap();
        fs::write(path.join("proof-1501-7"), b"proof").unwrap();
        // Its kept labels removed, as a proof's check of them removes them.
        store.discard_damaged(1500, &member, &id, n);
        let again = initialize(&store, &member, 1500, path.clone(), id, n, &|| false);
        let saved = Sector::load(path.clone()).unwrap().unwrap();
        assert!(
            again.is_ok_and(|sector| sector.cert == whole.cert)
                && saved.cert == whole.cert
                && !saved.certified
                && !path.join("capacity-target").exists()
                && !path.join("proof-1501-7").exists(),
            "LAST-LAYER-RECERTIFY: an uncertified sector kept a certificate its labels do not \
             give"
        );
        gates(false);
    }
    /// A damaged precommit target is reported once an epoch a sector,
    /// however many polls find it: engines whose frames lie far apart may
    /// each find the other's target past their next epoch.
    #[test]
    fn a_damaged_precommit_target_is_reported_once_an_epoch() {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        let logs = super::super::tests::capture_logs();
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, b"reported target", 1500, 100).unwrap();
        initialize(store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(|_| {});
        // A target far past the next epoch at each of two polls in one
        // epoch.
        for at in [frame + 1, frame + 2] {
            fs::write(path.join("capacity-target"), 1_000_000u64.to_be_bytes()).unwrap();
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
        }
        let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
        let reports = logged
            .matches("precommit target on disk is past the next epoch")
            .count();
        assert_eq!(
            reports, 1,
            "LAST-LAYER-TARGET-WARN: a damaged precommit target was reported {reports} times \
             in an epoch, not once"
        );
        gates(false);
    }
    /// A GLOBAL where this member is registered at `frame`, in epoch 1499,
    /// and a sector of the installed store set up for epoch 1500 that has
    /// not precommitted: the GLOBAL, the member, the sector and `frame`.
    fn unprecommitted_sector(label: &[u8]) -> (Arc<HypergraphCrdt>, [u8; 32], Sector, u64) {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let (path, id, n) = reserve(store, &member, label, 1500, 100).unwrap();
        let sector = initialize(store, &member, 1500, path, id, n, &|| false).unwrap();
        (global, member, sector, frame)
    }
    /// Commit at `frame` this member's precommit of `certificate` for
    /// `epoch`, as GLOBAL takes it.
    fn commit_precommit(
        global: &Arc<HypergraphCrdt>,
        member: &[u8; 32],
        certificate: sector::Certificate,
        epoch: u64,
        frame: u64,
    ) {
        use quil_execution::global_intrinsic::persistent_storage as protocol;
        use quil_execution::hypergraph_state::HypergraphState;
        use quil_types::crypto::Signer;
        let mut message = protocol::CapacityMessage {
            member: *member,
            epoch,
            certificate,
            signed_at: frame,
            signature: Vec::new(),
            proof: Vec::new(),
        };
        message.signature = TestIdentity
            .sign_with_domain(
                &message.signing_message(),
                &protocol::capacity_domain().unwrap(),
            )
            .unwrap();
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame, &message.envelope(), &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        assert_eq!(records.len(), 1, "GLOBAL takes the precommit");
        protocol::apply(&state, frame, &records).unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
    }
    /// How many of the precommits `sent` GLOBAL takes at `frame`.
    fn precommits_taken(global: &Arc<HypergraphCrdt>, frame: u64, sent: &[Vec<u8>]) -> usize {
        use quil_execution::global_intrinsic::persistent_storage as protocol;
        use quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof;
        use quil_execution::hypergraph_state::HypergraphState;
        let state = HypergraphState::new(global.clone());
        sent.iter()
            .filter(|bytes| {
                let precommit = StorageEpochProof::from_canonical_bytes(bytes).unwrap();
                protocol::check_capacity(frame, &precommit, &state, &TestIdentity, &|_| {
                    Err(unavailable("not known".into()))
                })
                .is_ok_and(|records| records.len() == 1)
            })
            .count()
    }
    /// The node's publish callback, as the poll takes it.
    type Publish = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
    /// A publish that sends each message to the receiver.
    fn published() -> (Publish, std::sync::mpsc::Receiver<Vec<u8>>) {
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Publish = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        (publish, recv)
    }
    /// An uncertified sector given the certificate its labels give, while
    /// its old certificate's precommit holds its GLOBAL slot, waits and
    /// sends nothing: GLOBAL refuses another precommit in the slot until
    /// that one's epoch has passed by two. Then it precommits, and GLOBAL
    /// takes it. It signed and sent a precommit GLOBAL refused at every
    /// frame, for two or three epochs.
    #[test]
    fn a_sector_given_a_new_certificate_waits_for_its_precommit_slot() {
        let logs = super::super::tests::capture_logs();
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let (global, member, sector, frame) = unprecommitted_sector(b"certified anew");
        // Its old certificate's precommit, for the next epoch, holds the
        // slot, as a sector set up from torn kept labels leaves it.
        let mut old = sector.cert;
        old.labels = old.columns;
        commit_precommit(&global, &member, old, 1500, frame + 1);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (publish, recv) = published();
        for at in [frame + 2, frame + 3] {
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
        }
        let sent: Vec<_> = recv.try_iter().collect();
        assert!(
            sent.is_empty(),
            "LAST-LAYER-SLOT-SENT: a sector sent {} precommits while another held its GLOBAL \
             slot; GLOBAL takes {} of them",
            sent.len(),
            precommits_taken(&global, frame + 3, &sent)
        );
        let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
        let notes = logged.matches("a sector's precommit waits").count();
        assert_eq!(
            notes, 1,
            "LAST-LAYER-SLOT-NOTE: a sector's wait for its precommit slot was noted {notes} \
             times, not once"
        );
        let after = 1503 * quil_types::consensus::epoch_length_frames() + 2;
        poll_sector_certificates(after, &member, &global, clock, &TestIdentity, publish).unwrap();
        let sent: Vec<_> = recv.try_iter().collect();
        assert!(
            sent.len() == 1 && precommits_taken(&global, after, &sent) == 1,
            "a sector whose precommit slot freed did not precommit, or GLOBAL refused it"
        );
        gates(false);
    }
    /// A sector whose GLOBAL precommit slot another of this member's
    /// sectors holds, their ids sharing their first byte mod 16, waits and
    /// sends nothing until that precommit's epoch has passed by two. A wait
    /// past that term, as the other precommits into the slot again, is
    /// reported once for that precommit.
    #[test]
    fn a_sector_waits_for_a_precommit_slot_another_sector_holds() {
        let logs = super::super::tests::capture_logs();
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let (global, member, sector, frame) = unprecommitted_sector(b"shared slot");
        let mut other = sector.cert;
        other.sector[31] ^= 1;
        commit_precommit(&global, &member, other, 1500, frame + 1);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (publish, recv) = published();
        let poll = |at: u64| {
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            recv.try_iter().collect::<Vec<_>>()
        };
        let sent = poll(frame + 2);
        assert!(
            sent.is_empty(),
            "LAST-LAYER-SLOT-SHARED: a sector sent {} precommits while another sector held its \
             GLOBAL slot; GLOBAL takes {} of them",
            sent.len(),
            precommits_taken(&global, frame + 2, &sent)
        );
        // The other, never certified, precommits into the slot again as
        // its precommit expires.
        let length = quil_types::consensus::epoch_length_frames();
        commit_precommit(&global, &member, other, 1504, 1503 * length + 1);
        let sent: Vec<_> = [1503 * length + 2, 1504 * length + 2, 1504 * length + 3]
            .into_iter()
            .flat_map(&poll)
            .collect();
        assert!(
            sent.is_empty(),
            "LAST-LAYER-SLOT-SHARED: a sector sent {} precommits while another sector held its \
             GLOBAL slot again",
            sent.len()
        );
        let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
        let overruns = logged.matches("has waited for its GLOBAL slot").count();
        assert_eq!(
            overruns, 1,
            "LAST-LAYER-SLOT-OVERRUN: a wait for a precommit slot past its holder's term was \
             reported {overruns} times, not once"
        );
        let after = 1507 * length + 2;
        let sent = poll(after);
        assert!(
            sent.len() == 1 && precommits_taken(&global, after, &sent) == 1,
            "a sector whose precommit slot freed did not precommit, or GLOBAL refused it"
        );
        gates(false);
    }
    /// Commit at `frame` this member's certificate of a sector, as GLOBAL
    /// records it once it takes the sector's proof.
    fn commit_certificate(
        global: &Arc<HypergraphCrdt>,
        member: &[u8; 32],
        certificate: sector::Certificate,
        frame: u64,
    ) {
        use quil_execution::global_intrinsic::persistent_storage as protocol;
        use quil_execution::global_schema::{write_field, write_type, GLOBAL_INTRINSIC_ADDRESS};
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use sha3::{Digest as _, Sha3_256};
        const CLASS: &str = "storage:PersistentSector";
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, CLASS).unwrap();
        let bytes = certificate.to_bytes();
        for (name, value) in [
            ("Member", member.as_slice()),
            ("Sector", certificate.sector.as_slice()),
            ("Certificate", bytes.as_slice()),
            ("Usage", b"".as_slice()),
        ] {
            write_field(&mut tree, CLASS, name, value).unwrap();
        }
        let address: [u8; 32] = Sha3_256::new()
            .chain_update(b"quil/sector-certificate/v1")
            .chain_update(member)
            .chain_update(certificate.sector)
            .finalize()
            .into();
        let state = HypergraphState::new(global.clone());
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &address,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        let snapshot = global.capture_committed_snapshot().unwrap();
        let held = protocol::committed_certificate(snapshot.as_ref(), member, &certificate.sector);
        assert!(
            held.unwrap() == Some(certificate),
            "GLOBAL holds the certificate"
        );
    }
    /// In the capacity warmup every precommit targets the first persistent
    /// epoch, so one holding a sector's GLOBAL slot holds it until two
    /// epochs past that. A sector waiting behind it, as one given a new
    /// certificate does, notes the epoch its wait ends by and reports no
    /// overrun within that term; then it precommits, and GLOBAL takes it.
    /// It warned at every epoch from the fifth, naming a cause that did not
    /// apply.
    #[test]
    fn a_sector_waits_out_its_precommit_slots_warmup_term_unreported() {
        let logs = super::super::tests::capture_logs();
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let (global, member, sector, frame) = unprecommitted_sector(b"warmup slot");
        // Epoch 1499 lies in the warmup of a first persistent epoch 1510.
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1510));
        let mut old = sector.cert;
        old.labels = old.columns;
        commit_precommit(&global, &member, old, 1510, frame + 1);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (publish, recv) = published();
        let length = quil_types::consensus::epoch_length_frames();
        let mut sent = Vec::new();
        for at in std::iter::once(frame + 2).chain((1500..=1512).map(|epoch| epoch * length + 2)) {
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            sent.extend(recv.try_iter());
        }
        assert!(
            sent.is_empty(),
            "LAST-LAYER-SLOT-WARMUP: a sector sent {} precommits while another held its GLOBAL \
             slot",
            sent.len()
        );
        let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
        let overruns = logged.matches("has waited for its GLOBAL slot").count();
        assert_eq!(
            overruns, 0,
            "LAST-LAYER-SLOT-TERM: a wait for a precommit slot within its holder's warmup term \
             was reported as overrun {overruns} times"
        );
        assert!(
            logged.contains("ends_by=1513"),
            "LAST-LAYER-SLOT-EXPECTED: a sector's wait for its precommit slot was not noted \
             with the epoch it ends by"
        );
        let after = 1513 * length + 2;
        poll_sector_certificates(after, &member, &global, clock, &TestIdentity, publish).unwrap();
        let sent: Vec<_> = recv.try_iter().collect();
        assert!(
            sent.len() == 1 && precommits_taken(&global, after, &sent) == 1,
            "a sector whose precommit slot freed did not precommit, or GLOBAL refused it"
        );
        gates(false);
    }
    /// A sector whose GLOBAL precommit slot holds the precommit of another
    /// of this member's sectors, one GLOBAL has certified, precommits at
    /// once, and GLOBAL takes it: a certified sector's precommit holds no
    /// slot.
    #[test]
    fn a_sector_precommits_into_a_slot_a_certified_sector_holds() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let (global, member, sector, frame) = unprecommitted_sector(b"certified holder");
        let mut other = sector.cert;
        other.sector[31] ^= 1;
        commit_precommit(&global, &member, other, 1500, frame + 1);
        commit_certificate(&global, &member, other, frame + 2);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (publish, recv) = published();
        poll_sector_certificates(frame + 3, &member, &global, clock, &TestIdentity, publish)
            .unwrap();
        let sent: Vec<_> = recv.try_iter().collect();
        assert!(
            sent.len() == 1 && precommits_taken(&global, frame + 3, &sent) == 1,
            "LAST-LAYER-SLOT-CERTIFIED: a sector sent {} precommits into a slot a certified \
             sector holds; GLOBAL takes {} of them",
            sent.len(),
            precommits_taken(&global, frame + 3, &sent)
        );
        gates(false);
    }
    /// A sector's wait for its GLOBAL precommit slot that ends other than
    /// by the slot freeing, here as the sector is certified, logs its end
    /// once and is dropped. It was kept with no end line, and a later wait
    /// took its start.
    #[test]
    fn a_slot_wait_ended_by_certification_logs_its_end_once() {
        let logs = super::super::tests::capture_logs();
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let (global, member, sector, frame) = unprecommitted_sector(b"certified waiter");
        let mut other = sector.cert;
        other.sector[31] ^= 1;
        commit_precommit(&global, &member, other, 1500, frame + 1);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (publish, recv) = published();
        let poll = |at: u64| {
            poll_sector_certificates(
                at,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            recv.try_iter().collect::<Vec<_>>()
        };
        let sent = poll(frame + 2);
        assert!(
            sent.is_empty(),
            "LAST-LAYER-SLOT-WAITED: a sector sent {} precommits while another sector held its \
             GLOBAL slot",
            sent.len()
        );
        commit_certificate(&global, &member, sector.cert, frame + 3);
        let sent: Vec<_> = [frame + 4, frame + 5].into_iter().flat_map(&poll).collect();
        assert!(sent.is_empty(), "a certified sector sent a precommit");
        let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
        let ends = logged
            .matches("no longer waits for its GLOBAL slot")
            .count();
        assert_eq!(
            ends, 1,
            "LAST-LAYER-SLOT-ENDED: a sector's wait for its precommit slot, ended as it was \
             certified, logged its end {ends} times, not once"
        );
        gates(false);
    }
    /// A registered replica seals again once its sector's cap file, damaged
    /// on disk, is rewritten from a last layer that matches the
    /// certificate, and once a last layer gone from disk is labelled again:
    /// either failed its seals for good, before any repair could start.
    #[test]
    fn a_registered_sector_seals_again_past_a_damaged_cap_or_a_lost_last_layer() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([75; 32], [77; 32]);
        let (snap, slot, replicas, path, _) = registered_leaf(store, &member, app);
        let output = vec![9; 516];
        let cap = fs::read(path.join("cap")).unwrap();
        fs::write(path.join("cap"), b"torn").unwrap();
        let prepared = prepare(&replicas, &member, &app, 1500, &slot, &output, &snap);
        assert!(
            prepared.is_ok() && fs::read(path.join("cap")).unwrap() == cap,
            "LAST-LAYER-CAP: a registered sector's damaged cap was not rewritten from its \
             whole last layer"
        );
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        fs::remove_file(&last).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let prepared = loop {
            let prepared = prepare(&replicas, &member, &app, 1500, &slot, &output, &snap);
            if prepared.is_ok() || std::time::Instant::now() > deadline {
                break prepared;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert!(
            prepared.is_ok() && fs::read(&last).is_ok_and(|bytes| bytes == whole),
            "LAST-LAYER-SERVE-MISSING: a registered sector whose last layer is gone was not \
             labelled again"
        );
        gates(false);
    }
    /// A registered replica seals again once its sector's cap and last
    /// layer, both damaged on disk, are made again: the cap cannot be
    /// rewritten from the layer, so the sector is labelled again, else its
    /// seals fail for good.
    #[test]
    fn a_registered_sector_seals_again_past_a_damaged_cap_and_last_layer() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let (member, app) = ([93; 32], [95; 32]);
        let (snap, slot, replicas, path, n) = registered_leaf(store, &member, app);
        let output = vec![9; 516];
        let cap = fs::read(path.join("cap")).unwrap();
        let whole = tear_last(&path, n);
        fs::write(path.join("cap"), b"torn").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let prepared = loop {
            let prepared = prepare(&replicas, &member, &app, 1500, &slot, &output, &snap);
            if prepared.is_ok() || std::time::Instant::now() > deadline {
                break prepared;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert!(
            prepared.is_ok()
                && fs::read(path.join("cap")).unwrap() == cap
                && fs::read(path.join("last")).unwrap() == whole,
            "LAST-LAYER-CAP-FALLBACK: a registered sector whose cap and last layer are both \
             damaged was not labelled again"
        );
        gates(false);
    }
    /// A certified sector whose last layer is gone from disk is labelled
    /// again, as one torn is, and the leaf it refused is then encoded.
    #[test]
    fn a_certified_sector_whose_last_layer_is_lost_is_labelled_again() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let (member, app) = ([79; 32], [81; 32]);
        let (crdt, prefix, path, _, _) = certified_leaf(&store, &member, app);
        let last = path.join("last");
        let whole = fs::read(&last).unwrap();
        fs::remove_file(&last).unwrap();
        let snap = capture_at(&crdt, &app, 1500, &[current_source(&crdt, &app, 1500)]).unwrap();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let encoded = loop {
            let encoded = encode_leaf(&snap, &member, &prefix, &replicas, Some(&store), &|| false);
            if encoded.is_ok() || std::time::Instant::now() > deadline {
                break encoded;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert!(
            encoded.is_ok() && fs::read(&last).is_ok_and(|bytes| bytes == whole),
            "LAST-LAYER-MISSING: a certified sector whose last layer is gone was not labelled \
             again"
        );
        gates(false);
    }
    #[test]
    fn concurrent_pool_reservations_are_unique_and_bounded_by_cpu_slots() {
        crate::storage_jobs::set_job_slots_for_test(3);
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [91; 32];
        let results = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0u8..9)
                .map(|i| {
                    let store = &store;
                    scope.spawn(move || try_reserve(store, &member, &[i], 1500, 100).unwrap())
                })
                .collect();
            jobs.into_iter()
                .filter_map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.len(), 3);
        assert_eq!(
            results
                .iter()
                .map(|(_, id, _)| *id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        assert!(try_reserve(&store, &member, b"extra", 1500, 100)
            .unwrap()
            .is_none());
        let (path, id, n) = results[0].clone();
        let mut sector = initialize(&store, &member, 1500, path, id, n, &|| false).unwrap();
        sector.certified = true;
        sector.save().unwrap();
        store.release_certified_sector(1500, &member, &id);
        assert!(try_reserve(&store, &member, b"extra", 1500, 100)
            .unwrap()
            .is_some());
        gates(false);
    }

    #[test]
    fn independent_sector_jobs_overlap_while_one_sectors_retries_stay_ordered() {
        use std::sync::mpsc;
        let member = [92; 32];
        let first = sector_lane(&member, &[1; 32]);
        let second = sector_lane(&member, &[2; 32]);
        let (started, recv) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let tx = started.clone();
        crate::storage_jobs::spawn(&first, "first sector", move || {
            tx.send(1).unwrap();
            wait.recv().unwrap();
            Ok(())
        });
        assert_eq!(
            recv.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            1
        );
        let tx = started.clone();
        crate::storage_jobs::spawn(&first, "same sector retry", move || {
            tx.send(3).unwrap();
            Ok(())
        });
        crate::storage_jobs::spawn(&second, "second sector", move || {
            started.send(2).unwrap();
            Ok(())
        });
        assert_eq!(
            recv.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            2
        );
        release.send(()).unwrap();
        assert_eq!(
            recv.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            3
        );
    }

    #[test]
    fn warm_data_updates_keep_labels_and_refuse_uncertified_admission() {
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        let store =
            LabelStore::with_space(dir.path().to_owned(), crate::storage_labels::ample_space());
        let member = [18; 32];
        let app = [21; 32];
        let crdt = super::super::tests::test_crdt();
        let location = quil_hypergraph::Location {
            app_address: app,
            data_address: [1; 32],
        };
        crdt.add_vertex(&location, b"first payload").unwrap();
        crdt.commit(1).unwrap();
        let capture =
            |epoch| capture_at(&crdt, &app, epoch, &[current_source(&crdt, &app, epoch)]).unwrap();
        let captured = capture(1500);
        let prefix = &captured.prefixes[0];
        prewarm_sectors(&captured, &store, &member).unwrap();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        assert!(
            encode_leaf(&captured, &member, prefix, &replicas, Some(&store), &|| {
                false
            })
            .is_err()
        );
        let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&app, prefix);
        let (path, id, n) = reserve(
            &store,
            &member,
            &leaf,
            1500,
            captured.node_count(prefix).unwrap(),
        )
        .unwrap();
        let mut capacity = Sector::load(path).unwrap().unwrap();
        capacity.certified = true;
        capacity.save().unwrap();
        store.release_certified_sector(1500, &member, &id);
        encode_leaf(&captured, &member, prefix, &replicas, Some(&store), &|| {
            false
        })
        .unwrap();
        let before = replicas.get_hash_leaf(1500, &leaf).unwrap().unwrap();
        let next = capture(1501);
        encode_leaf(&next, &member, prefix, &replicas, Some(&store), &|| false).unwrap();
        assert_eq!(
            replicas
                .get_hash_leaf(1501, &leaf)
                .unwrap()
                .unwrap()
                .registration_root,
            before.registration_root
        );
        // A changed snapshot uses a new R but never regenerates eleven layers.
        crdt.add_vertex(
            &quil_hypergraph::Location {
                app_address: app,
                data_address: [2; 32],
            },
            b"new value",
        )
        .unwrap();
        crdt.commit(2).unwrap();
        let changed = capture(1502);
        encode_leaf(
            &changed,
            &member,
            &changed.prefixes[0],
            &replicas,
            Some(&store),
            &|| false,
        )
        .unwrap();
        let after = replicas.get_hash_leaf(1502, &leaf).unwrap().unwrap();
        let old = sector::Registration::parse(&before.registration_root).unwrap();
        let new = sector::Registration::parse(&after.registration_root).unwrap();
        assert_eq!(old.certificate(n), new.certificate(n));
        assert_ne!(old.data, new.data);
        assert_ne!(old.replica, new.replica);
        assert!(store.find(1502, &member, &id, |count| count == n).is_none());
        let source = Source::new(&store, &replicas, &member, 1502, leaf.clone()).unwrap();
        let claim = changed
            .claim(
                &changed.prefixes[0],
                &leaf,
                &member,
                b"new beacon",
                new.data,
                n,
            )
            .unwrap();
        let binding = changed.prove_binding_sparse(&claim, &source).unwrap();
        binding::verify(&claim, &binding).unwrap();
        let fresh = sector::prove(&member, &leaf, 1502, n, &new, b"new beacon", &|t, i| {
            source.open(t, i)
        })
        .unwrap();
        sector::verify(&member, &leaf, 1502, n, &new, b"new beacon", &fresh).unwrap();

        use crate::storage_epoch_batch::PreparedSeat;
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            HeldLeaf, SealedLeaf, SeatClaim, SeatProof, SeatWitness,
        };
        let prepared = PreparedSeat {
            member,
            part: SeatProof {
                shard_filter: app.to_vec(),
                epoch: 1500,
                seals: true,
                bindings: vec![binding],
                ..Default::default()
            },
            claim: SeatClaim {
                seal_epoch: 1502,
                settle_epoch: 1500,
                seals: vec![SealedLeaf {
                    leaf_id: leaf.clone(),
                    n,
                    registered: new.registered(),
                    beacon: b"new beacon".to_vec(),
                    persistent: Some(new),
                }],
                ..Default::default()
            },
            witness: SeatWitness {
                certificates: vec![Vec::new()],
                seals: vec![fresh],
                opened: Vec::new(),
            },
            solo: false,
        };
        let bytes = prepared.to_bytes();
        assert_eq!(PreparedSeat::from_bytes(&bytes).unwrap().to_bytes(), bytes);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PreparedSeat::from_bytes(&trailing).is_err());
        let mut combined = prepared.clone();
        combined.part.settles = true;
        combined.claim.held.push(HeldLeaf {
            leaf_id: leaf,
            n,
            comm_r: new.replica,
        });
        let expected = combined.to_bytes();
        let (seal, settle) = combined.halves();
        assert_eq!(
            PreparedSeat::join(seal, settle).unwrap().to_bytes(),
            expected
        );
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1503));
        assert!(PreparedSeat::from_bytes(&bytes).is_err());
        gates(false);
    }
    struct TestIdentity;
    impl quil_types::crypto::Signer for TestIdentity {
        fn key_type(&self) -> quil_types::crypto::KeyType {
            quil_types::crypto::KeyType::Falcon512
        }
        fn public_key(&self) -> &[u8] {
            &[7; 897]
        }
        fn private_key(&self) -> &[u8] {
            &[]
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![3; 666])
        }
        fn sign_with_domain(&self, message: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            self.sign(message)
        }
    }
    impl quil_types::crypto::KeyManager for TestIdentity {
        fn validate_signature(
            &self,
            key: quil_types::crypto::KeyType,
            pk: &[u8],
            _: &[u8],
            sig: &[u8],
            _: &[u8],
        ) -> Result<bool> {
            Ok(key == quil_types::crypto::KeyType::Falcon512 && pk == [7; 897] && sig == [3; 666])
        }
    }
    #[test]
    fn controller_resumes_orphaned_capacity_and_releases_layers_only_after_global_ack() {
        capacity_lifecycle(100, std::time::Duration::from_secs(120), false);
    }
    #[test]
    fn a_cached_capacity_certificate_retries_without_its_evicted_layers() {
        capacity_lifecycle(100, std::time::Duration::from_secs(120), true);
    }
    #[test]
    #[ignore = "512 MiB sector lifecycle; run explicitly on representative hardware"]
    fn full_size_sector_lifecycle() {
        let n = std::env::var("QUIL_STORAGE_SCALE_NODES")
            .ok()
            .map(|s| s.parse::<u64>().expect("node count"))
            .unwrap_or(WORKER_SECTOR_NODES);
        assert!(n >= 128 && n <= WORKER_SECTOR_NODES && n.is_power_of_two());
        capacity_lifecycle(n * 3 / 4, std::time::Duration::from_secs(6 * 3600), false);
    }
    fn capacity_lifecycle(exact: u64, deadline: std::time::Duration, evict_pending: bool) {
        use quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof;
        use quil_execution::global_intrinsic::{materialize, persistent_storage as protocol};
        use quil_execution::{
            global_schema::GLOBAL_INTRINSIC_ADDRESS,
            hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        };
        use quil_types::crypto::Signer;
        use std::time::Duration;
        gates(true);
        let dir = tempfile::tempdir().unwrap();
        crate::storage_labels::install_with_space(
            dir.path().to_owned(),
            crate::storage_labels::ample_space(),
        );
        let store = crate::storage_labels::installed().unwrap();
        let member = materialize::prover_address_from_pubkey(TestIdentity.public_key()).unwrap();
        let global = super::super::tests::test_crdt();
        let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
        let state = HypergraphState::new(global.clone());
        let tree = materialize::create_prover_vertex_tree(TestIdentity.public_key(), 1).unwrap();
        state
            .set(
                &GLOBAL_INTRINSIC_ADDRESS,
                &member,
                &vertex_adds_discriminator().unwrap(),
                frame,
                quil_execution::prover_registry::vertex_tree_to_blob(&tree),
            )
            .unwrap();
        state.commit().unwrap();
        global.commit(frame).unwrap();
        // No shard engine remains for this unfinished reservation.
        let (path, id, n) = reserve(store, &member, b"lost shard", 1500, exact).unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (send, recv) = std::sync::mpsc::channel();
        let publish: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
            send.send(bytes).unwrap();
        });
        let started = std::time::Instant::now();
        poll_sector_certificates(
            frame,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        while started.elapsed() < deadline {
            if Sector::load(path.clone()).unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let labelled = started.elapsed();
        let local = Sector::load(path.clone())
            .unwrap()
            .expect("orphan reservation resumes without shard data");
        assert!(!local.certified);
        assert!(store.find(1500, &member, &id, |count| count == n).is_some());
        poll_sector_certificates(
            frame + 1,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        let precommit = StorageEpochProof::from_canonical_bytes(
            &recv.recv_timeout(Duration::from_secs(5)).unwrap(),
        )
        .unwrap();
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame + 1, &precommit, &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        protocol::apply(&state, frame + 1, &records).unwrap();
        state.commit().unwrap();
        global.commit(frame + 1).unwrap();
        let output = vec![9; 516];
        let txn = clock.new_transaction(false).unwrap();
        clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: frame + 2,
                        output: output.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
        poll_sector_certificates(
            frame + 3,
            &member,
            &global,
            clock.clone(),
            &TestIdentity,
            publish.clone(),
        )
        .unwrap();
        let certificate =
            StorageEpochProof::from_canonical_bytes(&recv.recv_timeout(deadline).unwrap()).unwrap();
        assert!(
            !Sector::load(path.clone()).unwrap().unwrap().certified,
            "publishing is not acknowledgment"
        );
        assert!(store.find(1500, &member, &id, |count| count == n).is_some());
        if evict_pending {
            for _ in 0..500 {
                store.release_certified_sector(1500, &member, &id);
                if store.find(1500, &member, &id, |count| count == n).is_none() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(store.find(1500, &member, &id, |count| count == n).is_none());
            let proving = File::open(path.join("proving")).unwrap();
            let mut idle = false;
            for _ in 0..500 {
                if proving.try_lock().is_ok() {
                    idle = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(idle);
            drop(proving);
            // A certificate GLOBAL has not taken is sent again once the
            // archives have let the last copy go.
            poll_sector_certificates(
                frame + 3 + 15,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            let retry = StorageEpochProof::from_canonical_bytes(
                &recv.recv_timeout(Duration::from_secs(5)).unwrap(),
            )
            .unwrap();
            assert_eq!(retry, certificate, "retry neither relabels nor reproves");
        }
        let state = HypergraphState::new(global.clone());
        let records =
            protocol::check_capacity(frame + 4, &certificate, &state, &TestIdentity, &|at| {
                assert_eq!(at, frame + 2);
                Ok(output.clone())
            })
            .unwrap();
        protocol::apply(&state, frame + 4, &records).unwrap();
        state.commit().unwrap();
        global.commit(frame + 4).unwrap();
        for i in 0..20 {
            poll_sector_certificates(
                frame + 19 + i,
                &member,
                &global,
                clock.clone(),
                &TestIdentity,
                publish.clone(),
            )
            .unwrap();
            if store.find(1500, &member, &id, |count| count == n).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let acknowledged = Sector::load(path).unwrap().unwrap();
        assert!(acknowledged.certified);
        assert!(store.find(1500, &member, &id, |count| count == n).is_none());
        assert!(acknowledged.cap().is_ok());
        assert_eq!(acknowledged.last().unwrap().len(), n as usize);
        let certified = started.elapsed();
        let replicas = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        for round in 0..2 {
            let begin = std::time::Instant::now();
            let epoch = 1501 + round;
            let data = vec![round as u8 + 3; (n * 30 * 3 / 4) as usize];
            let last = acknowledged.last().unwrap();
            let encoded =
                proof::encode_with_labels(&data, n, &last, acknowledged.cert.labels).unwrap();
            drop(last);
            drop(data);
            let root = sector::Registration {
                profile: quil_types::consensus::StorageSealProfile::Eleven,
                data: encoded.comm_d,
                labels: acknowledged.cert.labels,
                replica: encoded.comm_r,
                columns: acknowledged.cert.columns,
                sector: id,
            };
            replicas
                .put_hash(
                    epoch,
                    b"scale data",
                    &encoded.replica,
                    &encoded.replica_cap.to_bytes(),
                    &root.to_bytes(),
                )
                .unwrap();
            replicas
                .put_data_cap(epoch, b"scale data", &encoded.data_cap)
                .unwrap();
            drop(encoded);
            let encoded_time = begin.elapsed();
            let source =
                Source::new(store, &replicas, &member, epoch, b"scale data".to_vec()).unwrap();
            let fresh = sector::prove(
                &member,
                b"scale data",
                epoch,
                n,
                &root,
                b"new GLOBAL beacon",
                &|tree, i| source.open(tree, i),
            )
            .unwrap();
            sector::verify(
                &member,
                b"scale data",
                epoch,
                n,
                &root,
                b"new GLOBAL beacon",
                &fresh,
            )
            .unwrap();
            assert!(store
                .find(epoch, &member, &id, |count| count == n)
                .is_none());
            eprintln!("sector_nodes={n} replica_mib={} cold_labels_seconds={:.3} certified_seconds={:.3} round={round} changed_encode_seconds={:.3} fresh_proof_seconds={:.3} fresh_proof_bytes={}",
                n*32>>20,labelled.as_secs_f64(),certified.as_secs_f64(),encoded_time.as_secs_f64(),begin.elapsed().saturating_sub(encoded_time).as_secs_f64(),fresh.to_bytes().len());
        }
        gates(false);
    }
    /// A registered member with one labelled, uncertified sector, and the
    /// messages its polls send.
    struct Pool {
        _dir: tempfile::TempDir,
        member: [u8; 32],
        global: Arc<HypergraphCrdt>,
        clock: Arc<quil_store::testing::InMemoryClockStore>,
        frame: u64,
        path: PathBuf,
        recv: std::sync::mpsc::Receiver<Vec<u8>>,
        publish: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    }
    impl Pool {
        fn new() -> Self {
            use quil_execution::global_intrinsic::materialize;
            use quil_execution::{
                global_schema::GLOBAL_INTRINSIC_ADDRESS,
                hypergraph_state::{vertex_adds_discriminator, HypergraphState},
            };
            use quil_types::crypto::Signer;
            gates(true);
            let dir = tempfile::tempdir().unwrap();
            crate::storage_labels::install_with_space(
                dir.path().to_owned(),
                crate::storage_labels::ample_space(),
            );
            let store = crate::storage_labels::installed().unwrap();
            let key = TestIdentity.public_key();
            let member = materialize::prover_address_from_pubkey(key).unwrap();
            let global = super::super::tests::test_crdt();
            let frame = 1499 * quil_types::consensus::epoch_length_frames() + 20;
            let state = HypergraphState::new(global.clone());
            let prover = materialize::create_prover_vertex_tree(key, 1).unwrap();
            state
                .set(
                    &GLOBAL_INTRINSIC_ADDRESS,
                    &member,
                    &vertex_adds_discriminator().unwrap(),
                    frame,
                    quil_execution::prover_registry::vertex_tree_to_blob(&prover),
                )
                .unwrap();
            state.commit().unwrap();
            global.commit(frame).unwrap();
            let (path, id, n) = reserve(store, &member, b"paced leaf", 1500, 100).unwrap();
            initialize(store, &member, 1500, path.clone(), id, n, &|| false).unwrap();
            let (send, recv) = std::sync::mpsc::channel::<Vec<u8>>();
            Self {
                _dir: dir,
                member,
                global,
                clock: Arc::new(quil_store::testing::InMemoryClockStore::new()),
                frame,
                path,
                recv,
                publish: Arc::new(move |bytes: Vec<u8>| send.send(bytes).unwrap()),
            }
        }
        /// Poll at `frame`, wait for the sector's proof job to end, and
        /// return what was sent.
        fn poll(&self, frame: u64) -> Vec<Vec<u8>> {
            poll_sector_certificates(
                frame,
                &self.member,
                &self.global,
                self.clock.clone(),
                &TestIdentity,
                self.publish.clone(),
            )
            .unwrap();
            let started = std::time::Instant::now();
            while File::open(self.path.join("proving")).is_ok_and(|f| f.try_lock().is_err()) {
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(600),
                    "the sector's proof job never ended"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            self.recv.try_iter().collect()
        }
    }
    fn decoded(
        bytes: &[u8],
    ) -> quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof {
        quil_execution::global_intrinsic::storage_epoch_proof::StorageEpochProof::from_canonical_bytes(
            bytes,
        )
        .unwrap()
    }
    #[test]
    fn engines_at_different_frames_poll_the_sector_pool_once_per_new_frame() {
        let pool = Pool::new();
        let f = pool.frame;
        // Application engines poll with the GLOBAL frame each has seen,
        // which lie a frame or more apart and arrive in any order. Only the
        // first poll of a new frame sends; a precommit sent at f + 1 is not
        // due again at f + 2.
        let sent: usize = [f + 1, f, f + 1, f, f + 2, f + 1, f + 2]
            .into_iter()
            .map(|frame| pool.poll(frame).len())
            .sum();
        assert_eq!(
            sent, 1,
            "flood: {sent} precommits from polls of two new frames, one wanted (polled-again)"
        );
        gates(false);
    }
    #[test]
    fn a_sectors_precommit_is_signed_once_and_resent_unchanged_while_global_takes_it() {
        use quil_execution::global_intrinsic::persistent_storage as protocol;
        use quil_execution::hypergraph_state::HypergraphState;
        let pool = Pool::new();
        let mut sends = Vec::new();
        for frame in pool.frame + 1..=pool.frame + 13 {
            sends.extend(pool.poll(frame).into_iter().map(|bytes| (frame, bytes)));
        }
        let state = HypergraphState::new(pool.global.clone());
        for (frame, bytes) in &sends {
            // Each copy still lands if GLOBAL takes it four frames later.
            protocol::check_capacity(frame + 4, &decoded(bytes), &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap_or_else(|e| {
                panic!("stale: GLOBAL refuses the precommit sent at frame {frame}: {e}")
            });
        }
        for pair in sends.windows(2) {
            assert!(
                pair[1].0 >= pair[0].0 + 3,
                "flood: precommits went out at frames {} and {} (resent-sooner)",
                pair[0].0,
                pair[1].0
            );
        }
        let distinct: std::collections::BTreeSet<&Vec<u8>> =
            sends.iter().map(|(_, bytes)| bytes).collect();
        assert!(
            distinct.len() <= 3,
            "flood: {} distinct precommits signed in 13 frames (re-signed)",
            distinct.len()
        );
        assert!(
            sends.len() >= 4,
            "a precommit GLOBAL has not taken is still resent: {} sends",
            sends.len()
        );
        gates(false);
    }
    #[test]
    fn a_certificate_global_has_not_taken_is_resent_at_a_widening_interval() {
        use quil_execution::global_intrinsic::persistent_storage as protocol;
        use quil_execution::hypergraph_state::HypergraphState;
        let pool = Pool::new();
        let f = pool.frame;
        let precommit = pool.poll(f + 1).pop().expect("a precommit");
        let state = HypergraphState::new(pool.global.clone());
        let records =
            protocol::check_capacity(f + 1, &decoded(&precommit), &state, &TestIdentity, &|_| {
                Err(unavailable("not known".into()))
            })
            .unwrap();
        protocol::apply(&state, f + 1, &records).unwrap();
        state.commit().unwrap();
        pool.global.commit(f + 1).unwrap();
        let txn = pool.clock.new_transaction(false).unwrap();
        pool.clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: f + 2,
                        output: vec![9; 516],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
        let mut sends = Vec::new();
        for frame in f + 3..f + 64 {
            for bytes in pool.poll(frame) {
                let magic = decoded(&bytes).proof[..4].to_vec();
                assert!(magic == b"PSC2" || magic == b"PSC4", "only certificates");
                sends.push(frame);
            }
        }
        assert_eq!(
            sends.first(),
            Some(&(f + 3)),
            "the first certificate goes at once"
        );
        for pair in sends.windows(2) {
            assert!(
                pair[1] >= pair[0] + 15,
                "flood: certificates went out at frames {} and {} (resent-sooner)",
                pair[0],
                pair[1]
            );
        }
        assert!(
            sends.len() >= 3,
            "a certificate GLOBAL has not taken is still resent: {sends:?}"
        );
        gates(false);
    }
}

pub(super) mod readiness;
