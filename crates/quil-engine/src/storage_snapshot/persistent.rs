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
        if bytes.len() != sector::Certificate::BYTES + 1 {
            return Err(unavailable("sector metadata length".into()));
        }
        let cert = sector::Certificate::parse(&bytes[..sector::Certificate::BYTES])
            .ok_or_else(|| unavailable("sector metadata is invalid".into()))?;
        if bytes[sector::Certificate::BYTES] > 1 {
            return Err(unavailable("sector certification flag".into()));
        }
        Ok(Some(Self {
            dir,
            cert,
            certified: bytes[sector::Certificate::BYTES] == 1,
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
        if Sector::load(dir.clone())?.is_none() {
            if let Ok(bytes) = fs::read(dir.join("reservation")) {
                if bytes.len() == 48 && bytes[16..] == leaf_hash {
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
        if let Some(sector) = Sector::load(entry.path())? {
            if sector.cert.n >= exact {
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
        if !Sector::load(entry.path())?.is_some_and(|s| s.certified) {
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
        &[n.to_be_bytes().as_slice(), &epoch.to_be_bytes(), &leaf_hash].concat(),
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
    let (last, columns) = match store.find(epoch, member, &id, |count| count == n) {
        Some(kept) => (
            kept.last_layer()
                .ok_or_else(|| unavailable("sector labels unreadable".into()))?,
            kept.comm_c,
        ),
        None => {
            let admitted = store
                .admit(epoch, member, &id, n, Stage::Snapshot)
                .ok_or_else(|| unavailable("no disk space to certify a new sector".into()))?;
            match admitted.label_kept(&quil_crypto::sdr::SdrParams::default(), stop, &|_| {})? {
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
        sector: id,
        n,
        columns,
        labels: cap.commitment(Tree::Replica),
    };
    if previous.as_ref().is_some_and(|old| old.cert != cert) {
        return Err(unavailable(
            "regenerated sector differs from committed labels".into(),
        ));
    }
    let path = dir.join("last.tmp");
    let mut file = File::create(&path).map_err(io)?;
    for chunk in last.chunks(1024) {
        file.write_all(&hash::digests_to_bytes(chunk)).map_err(io)?;
    }
    file.sync_all().map_err(io)?;
    fs::rename(&path, dir.join("last")).map_err(io)?;
    atomic(&dir.join("cap"), &cap.to_bytes())?;
    let sector = Sector {
        dir,
        cert: sector::Certificate {
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
    let last = sector.last()?;
    let encoded = proof::encode_with_labels(&data, n, &last, sector.cert.labels)
        .map_err(QuilError::InvalidArgument)?;
    let root = sector::Registration {
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
        let cap = sector.cap()?;
        let data = replicas
            .get_data_cap(epoch, &leaf)?
            .ok_or_else(|| unavailable("persistent data cap is absent".into()))?;
        if data.n != stored.n || data.commitment(Tree::Data) != root.data {
            return Err(unavailable(
                "persistent data cap differs from registration".into(),
            ));
        }
        let last = Mutex::new(File::open(sector.dir.join("last")).map_err(io)?);
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
        let binding = captured.prove_binding_sparse(&leaf_claim, &source)?;
        let seal = sector::prove(member, &leaf, target, n, &root, &beacon, &|tree, index| {
            source.open(tree, index)
        })
        .map_err(QuilError::InvalidArgument)?;
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

// A lost shard or a restart must not strand the pool behind an unfinished
// reservation. Capacity is independent of that shard's data; finish it here.
fn resume_reserved_sector(
    store: &'static LabelStore,
    member: &[u8; 32],
    dir: PathBuf,
) -> Result<()> {
    let bytes = fs::read(dir.join("reservation")).map_err(io)?;
    if bytes.len() != 48 {
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
    if first == u64::MAX
        || current.saturating_add(quil_types::consensus::PERSISTENT_STORAGE_WARMUP_EPOCHS) < first
    {
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
    // All application engines share this pool. Poll it once per GLOBAL frame.
    let poll = root.join("last-poll");
    if fs::read(&poll).ok().as_deref() == Some(frame.to_be_bytes().as_slice()) {
        return Ok(());
    }
    atomic(&poll, &frame.to_be_bytes())?;
    let snapshot = global.capture_committed_snapshot()?;
    for entry in fs::read_dir(root).map_err(io)?.flatten() {
        if !sector_directory(&entry.path()) {
            continue;
        }
        let Some(mut sector) = Sector::load(entry.path())? else {
            resume_reserved_sector(store, member, entry.path())?;
            continue;
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
            store.release_certified_sector(cache_epoch, member, &sector.cert.sector);
            continue;
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
            continue;
        }
        let target_path = sector.dir.join("capacity-target");
        let previous = fs::read(&target_path)
            .ok()
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes);
        let target = previous
            .filter(|e| current <= e.saturating_add(2))
            .unwrap_or(first.max(current.saturating_add(1)));
        atomic(&target_path, &target.to_be_bytes())?;
        let pending = protocol::committed_pending(snapshot.as_ref(), member, &sector.cert, target)?;
        let pending = pending.filter(|p| p.epoch == target && p.certificate == sector.cert);
        let Some(pending) = pending else {
            let mut message = protocol::CapacityMessage {
                member: *member,
                epoch: target,
                certificate: sector.cert,
                signed_at: frame,
                signature: Vec::new(),
                proof: Vec::new(),
            };
            message.signature = signer
                .sign_with_domain(&message.signing_message(), &protocol::capacity_domain()?)?;
            publish(message.envelope().to_canonical_bytes());
            continue;
        };
        let beacon_frame = pending.committed_at.saturating_add(1);
        if frame <= beacon_frame {
            continue;
        }
        let Some(header) = anchors.get_global_clock_frame(beacon_frame)?.header else {
            continue;
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
            continue;
        }
        let cache = sector.dir.join(format!("proof-{target}-{beacon_frame}"));
        // Refresh temporary layers while needed, but a durable proof can be
        // retransmitted after pressure eviction without regenerating them.
        let kept = store.find(
            cache_epoch.max(current.saturating_add(1)),
            member,
            &sector.cert.sector,
            |n| n == sector.cert.n,
        );
        if kept.is_none() && !cache.is_file() {
            resume_reserved_sector(store, member, sector.dir.clone())?;
            continue;
        }
        let member = *member;
        let publish = publish.clone();
        crate::storage_jobs::spawn(
            &sector_lane(&member, &sector.cert.sector),
            "sector certificate",
            move || {
                let _guard = proving;
                let bytes = match fs::read(&cache) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let kept = kept.ok_or_else(|| {
                            unavailable("sector proof cache and temporary layers are absent".into())
                        })?;
                        let _memory = crate::storage_jobs::reserve(
                            proof::labelling_peak_bytes(
                                sector.cert.n,
                                &quil_crypto::sdr::SdrParams::default(),
                            )
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
                            &quil_crypto::sdr::SdrParams::default(),
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gates(on: bool) {
        quil_types::consensus::set_persistent_storage_epoch_for_thread(on.then_some(1500));
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(on.then_some(1393));
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
            poll_sector_certificates(
                frame + 4,
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
                frame + 5 + i,
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
}

pub(super) mod readiness;
