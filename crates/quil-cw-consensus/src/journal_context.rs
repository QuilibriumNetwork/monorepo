//! Bounded file handles over the existing Commonware journal format.
//!
//! Segmented journals retain one Blob per view. A Blob here is a logical
//! handle: ordinary I/O reopens the same runtime blob, while removed blobs
//! retain an underlying handle to preserve Commonware's read-after-remove
//! contract. Only completed I/O releases its slot, even if its waiter cancels.

use std::collections::HashMap;
use std::future::Future;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use commonware_runtime::{
    signal, tokio::Context, Blob, BufferPool, BufferPooler, Clock, Error, Handle, IoBufs,
    IoBufsMut, Metrics, Name, Spawner, Storage, Supervisor,
};
use commonware_utils::channel::oneshot;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};

type RuntimeBlob = <Context as Storage>::Blob;
type Key = (String, Vec<u8>);

const ACTIVE_FILES: usize = 32;
const REMOVED_FILES: usize = 32;

struct Removed {
    blob: RuntimeBlob,
    _slot: OwnedSemaphorePermit,
}

struct Entry {
    key: Key,
    version: u16,
    // Coordinates reopen, I/O and unlink. The gate is never held by a caller
    // future: an owned task retains it through underlying completion.
    gate: Arc<Mutex<Option<Removed>>>,
}

struct Files {
    context: Context,
    entries: Mutex<HashMap<Key, Weak<Entry>>>,
    active: Arc<Semaphore>,
    removed: Arc<Semaphore>,
    tasks: AtomicUsize,
    idle: Notify,
}

struct Task(Arc<Files>);
impl Task {
    fn new(files: Arc<Files>) -> Self {
        files.tasks.fetch_add(1, Ordering::AcqRel);
        Self(files)
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        if self.0.tasks.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_one();
        }
    }
}

#[derive(Clone)]
pub(crate) struct JournalBlob {
    files: Arc<Files>,
    entry: Arc<Entry>,
}

fn limit_error() -> Error {
    Error::Io(std::io::Error::other("journal removed-handle budget exhausted").into())
}

// Drop/abort of an observer must not release a descriptor slot while the
// runtime's blocking filesystem operation still owns that descriptor.
async fn complete<T: Send + 'static>(
    files: Arc<Files>,
    operation: impl Future<Output = Result<T, Error>> + Send + 'static,
) -> Result<T, Error> {
    let task = Task::new(files);
    tokio::spawn(async move {
        let _task = task;
        operation.await
    })
    .await
    .map_err(|_| Error::Closed)?
}

impl JournalBlob {
    async fn use_blob<T: Send + 'static>(
        self,
        op: impl FnOnce(RuntimeBlob) -> std::pin::Pin<Box<dyn Future<Output = Result<T, Error>> + Send>>
            + Send
            + 'static,
    ) -> Result<T, Error> {
        let guard = self.entry.gate.lock().await;
        if let Some(removed) = guard.as_ref() {
            return op(removed.blob.clone()).await;
        }
        let _slot = self
            .files
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)?;
        let (blob, _, _) = self
            .files
            .context
            .open_versioned(
                &self.entry.key.0,
                &self.entry.key.1,
                self.entry.version..=self.entry.version,
            )
            .await?;
        op(blob).await
    }
}

impl Blob for JournalBlob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        complete(
            self.files.clone(),
            self.clone()
                .use_blob(move |blob| Box::pin(async move { blob.read_at(offset, len).await })),
        )
        .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let bufs = bufs.into();
        complete(
            self.files.clone(),
            self.clone().use_blob(move |blob| {
                Box::pin(async move { blob.read_at_buf(offset, len, bufs).await })
            }),
        )
        .await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        complete(
            self.files.clone(),
            self.clone()
                .use_blob(move |blob| Box::pin(async move { blob.write_at(offset, bufs).await })),
        )
        .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        complete(
            self.files.clone(),
            self.clone().use_blob(move |blob| {
                Box::pin(async move { blob.write_at_sync(offset, bufs).await })
            }),
        )
        .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        complete(
            self.files.clone(),
            self.clone()
                .use_blob(move |blob| Box::pin(async move { blob.resize(len).await })),
        )
        .await
    }

    async fn sync(&self) -> Result<(), Error> {
        complete(
            self.files.clone(),
            self.clone()
                .use_blob(move |blob| Box::pin(async move { blob.sync().await })),
        )
        .await
    }

    async fn start_sync(&self) -> Handle<()> {
        let (tx, rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let blob = self.clone();
        let task = Task::new(self.files.clone());
        tokio::spawn(async move {
            let _task = task;
            let result = blob
                .use_blob(move |blob| {
                    Box::pin(async move {
                        let handle = blob.start_sync().await;
                        let _ = started_tx.send(());
                        handle.await
                    })
                })
                .await;
            let _ = tx.send(result);
        });
        let _ = started_rx.await;
        Handle::from_receiver(rx)
    }
}

/// Runtime capabilities are forwarded unchanged; only journal Storage differs.
pub(crate) struct JournalContext {
    inner: Context,
    files: Arc<Files>,
}

impl JournalContext {
    pub(crate) fn new(inner: Context) -> Self {
        let files = Arc::new(Files {
            context: inner.child("journal_files"),
            entries: Mutex::new(HashMap::new()),
            active: Arc::new(Semaphore::new(ACTIVE_FILES)),
            removed: Arc::new(Semaphore::new(REMOVED_FILES)),
            tasks: AtomicUsize::new(0),
            idle: Notify::new(),
        });
        Self { inner, files }
    }

    /// Hold the owning runtime on its host thread until canceled actors and
    /// detached filesystem operations have released their runtime references.
    pub(crate) async fn wait_idle(&self) {
        loop {
            let wake = self.files.idle.notified();
            if self.files.tasks.load(Ordering::Acquire) == 0 {
                return;
            }
            wake.await;
        }
    }
}

impl Storage for JournalContext {
    type Blob = JournalBlob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(JournalBlob, u64, u16), Error> {
        let key = (partition.to_owned(), name.to_vec());
        let files = self.files.clone();
        complete(files.clone(), async move {
            let mut entries = files.entries.lock().await;
            let _slot = files
                .active
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::Closed)?;
            let (blob, len, version) = files
                .context
                .open_versioned(&key.0, &key.1, versions)
                .await?;
            drop(blob);
            let entry = match entries.get(&key).and_then(Weak::upgrade) {
                Some(entry) => entry,
                None => {
                    if entries.len() % 1024 == 0 {
                        entries.retain(|_, entry| entry.strong_count() != 0);
                    }
                    let entry = Arc::new(Entry {
                        key: key.clone(),
                        version,
                        gate: Arc::new(Mutex::new(None)),
                    });
                    entries.insert(key, Arc::downgrade(&entry));
                    entry
                }
            };
            drop(entries);
            Ok((JournalBlob { files, entry }, len, version))
        })
        .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        let partition = partition.to_owned();
        let name = name.map(<[u8]>::to_vec);
        let files = self.files.clone();
        complete(files.clone(), async move {
            // Block reopen of this name until unlink and generation replacement
            // finish. All existing handles keep the old Entry and removed inode.
            let mut entries = files.entries.lock().await;
            let live: Vec<_> = match name.as_ref() {
                Some(name) => entries
                    .get(&(partition.clone(), name.clone()))
                    .and_then(Weak::upgrade)
                    .into_iter()
                    .collect(),
                None => entries
                    .iter()
                    .filter(|(key, _)| key.0 == partition)
                    .filter_map(|(_, weak)| weak.upgrade())
                    .collect(),
            };
            let mut pinned = Vec::new();
            for entry in &live {
                let guard = entry.gate.clone().lock_owned().await;
                let slot = files
                    .removed
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| limit_error())?;
                let _active = files
                    .active
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| Error::Closed)?;
                let (blob, _, _) = files
                    .context
                    .open_versioned(&entry.key.0, &entry.key.1, entry.version..=entry.version)
                    .await?;
                pinned.push((guard, Removed { blob, _slot: slot }));
            }
            // Pin before unlink: even a partially failed partition removal
            // must leave old handles readable. New opens get a new generation.
            let mut guards = Vec::new();
            for (mut guard, removed) in pinned {
                *guard = Some(removed);
                guards.push(guard);
            }
            let _active = files
                .active
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::Closed)?;
            let result = files.context.remove(&partition, name.as_deref()).await;
            match name {
                Some(name) => {
                    entries.remove(&(partition, name));
                }
                None => entries.retain(|key, _| key.0 != partition),
            }
            result
        })
        .await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        let files = self.files.clone();
        let partition = partition.to_owned();
        complete(files.clone(), async move {
            let _slot = files
                .active
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::Closed)?;
            files.context.scan(&partition).await
        })
        .await
    }
}

impl Supervisor for JournalContext {
    fn name(&self) -> Name {
        self.inner.name()
    }
    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            files: self.files.clone(),
        }
    }
    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            files: self.files,
        }
    }
}

impl Spawner for JournalContext {
    fn shared(self, blocking: bool) -> Self {
        Self {
            inner: self.inner.shared(blocking),
            files: self.files,
        }
    }
    fn dedicated(self) -> Self {
        Self {
            inner: self.inner.dedicated(),
            files: self.files,
        }
    }
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let files = self.files;
        let task = Task::new(files.clone());
        self.inner.spawn(move |inner| async move {
            let _task = task;
            f(Self { inner, files }).await
        })
    }
    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }
    fn stopped(&self) -> signal::Signal {
        self.inner.stopped()
    }
}

impl Metrics for JournalContext {
    fn register<
        N: Into<String>,
        H: Into<String>,
        M: commonware_runtime::telemetry::metrics::Metric,
    >(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> commonware_runtime::telemetry::metrics::Registered<M> {
        self.inner.register(name, help, metric)
    }
    fn encode(&self) -> String {
        self.inner.encode()
    }
}

impl governor::clock::Clock for JournalContext {
    type Instant = SystemTime;
    fn now(&self) -> Self::Instant {
        governor::clock::Clock::now(&self.inner)
    }
}
impl governor::clock::ReasonablyRealtime for JournalContext {}
impl Clock for JournalContext {
    fn current(&self) -> SystemTime {
        self.inner.current()
    }
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep(duration)
    }
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep_until(deadline)
    }
}
impl BufferPooler for JournalContext {
    fn network_buffer_pool(&self) -> &BufferPool {
        self.inner.network_buffer_pool()
    }
    fn storage_buffer_pool(&self) -> &BufferPool {
        self.inner.storage_buffer_pool()
    }
}
impl rand_core::TryRng for JournalContext {
    type Error = <Context as rand_core::TryRng>::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64()
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(bytes)
    }
}
impl rand_core::TryCryptoRng for JournalContext {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::buffer::paged::CacheRef;
    use commonware_runtime::{Buf, IoBuf, Runner as _};
    use commonware_storage::journal::segmented::variable::{Config, Journal};
    use commonware_utils::{NZUsize, NZU16};
    use futures::StreamExt;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "quil-journal-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn runner(&self) -> commonware_runtime::tokio::Runner {
            commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::new()
                    .with_storage_directory(self.0.clone())
                    .with_worker_threads(2),
            )
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    async fn read(blob: &JournalBlob, len: usize) -> Vec<u8> {
        blob.read_at(0, len)
            .await
            .unwrap()
            .copy_to_bytes(len)
            .to_vec()
    }
    fn config(context: &impl BufferPooler) -> Config<()> {
        Config {
            partition: "test".into(),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
            write_buffer: NZUsize!(16 * 1024),
        }
    }
    fn open_files() -> usize {
        let path = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        std::fs::read_dir(path).unwrap().count()
    }

    #[test]
    fn journal_replays_thousands_of_views_with_bounded_handles() {
        let dir = Directory::new();
        // Existing runtime/journal bytes remain the on-disk format.
        dir.runner().start(|context| async move {
            let mut journal = Journal::<_, u64>::init(context.child("journal"), config(&context))
                .await
                .unwrap();
            for view in 0..64u64 {
                journal.append(view, &view).await.unwrap();
            }
            journal.sync_all().await.unwrap();
        });
        dir.runner().start(|context| async move {
            let context = JournalContext::new(context);
            let baseline = open_files();
            let mut journal = Journal::<_, u64>::init(context.child("journal"), config(&context))
                .await
                .unwrap();
            for view in 64..4096u64 {
                journal.append(view, &view).await.unwrap();
                journal.sync(view).await.unwrap();
            }
            assert!(
                open_files() < baseline + 128,
                "retained views must not retain one file handle each"
            );
            let mut stream = Box::pin(journal.replay(0, 0, NZUsize!(4096)).await.unwrap());
            for expected in 0..4096u64 {
                let (section, _, _, value) = stream.next().await.unwrap().unwrap();
                assert_eq!((section, value), (expected, expected));
            }
            assert!(stream.next().await.is_none());
            drop(stream);
            journal.prune(4080).await.unwrap();
            assert_eq!(context.scan("test").await.unwrap().len(), 16);
            drop(journal);
            context.wait_idle().await;
            assert_eq!(context.files.active.available_permits(), ACTIVE_FILES);
            assert_eq!(context.files.removed.available_permits(), REMOVED_FILES);
        });
        // Standard runtime can still read files written through the adapter.
        dir.runner().start(|context| async move {
            let mut journal = Journal::<_, u64>::init(context.child("journal"), config(&context))
                .await
                .unwrap();
            let mut stream = Box::pin(journal.replay(4080, 0, NZUsize!(4096)).await.unwrap());
            for expected in 4080..4096u64 {
                assert_eq!(stream.next().await.unwrap().unwrap().3, expected);
            }
            assert!(stream.next().await.is_none());
        });
    }

    #[test]
    fn unlink_preserves_unsynced_bytes_and_reopen_is_independent() {
        Directory::new().runner().start(|context| async move {
            let context = JournalContext::new(context);
            let (old, _, version) = context.open_versioned("test", b"one", 3..=3).await.unwrap();
            assert_eq!(version, 3);
            old.write_at(0, IoBuf::from(b"old!".to_vec()))
                .await
                .unwrap();
            assert!(matches!(
                context.open_versioned("test", b"one", 1..=1).await,
                Err(Error::BlobVersionMismatch { .. })
            ));
            context.remove("test", Some(b"one")).await.unwrap();
            assert_eq!(read(&old, 4).await, b"old!");
            let (new, len, _) = context.open_versioned("test", b"one", 7..=7).await.unwrap();
            assert_eq!(len, 0);
            new.write_at_sync(0, IoBuf::from(b"new!".to_vec()))
                .await
                .unwrap();
            context.remove("test", None).await.unwrap();
            assert_eq!(read(&old, 4).await, b"old!");
            assert_eq!(read(&new, 4).await, b"new!");
            drop((old, new));
            context.wait_idle().await;
            assert_eq!(context.files.removed.available_permits(), REMOVED_FILES);
        });
    }

    #[test]
    fn removed_handle_limit_refuses_before_unlink_and_recovers_after_drop() {
        Directory::new().runner().start(|context| async move {
            let context = JournalContext::new(context);
            let mut held = Vec::new();
            for n in 0..=REMOVED_FILES {
                let (blob, _) = context.open("test", &n.to_be_bytes()).await.unwrap();
                blob.write_at(0, IoBuf::from(vec![n as u8])).await.unwrap();
                held.push(blob);
            }
            assert!(context.remove("test", None).await.is_err());
            assert_eq!(context.scan("test").await.unwrap().len(), REMOVED_FILES + 1);
            assert_eq!(context.files.removed.available_permits(), REMOVED_FILES);
            drop(held.pop());
            context.remove("test", None).await.unwrap();
            assert_eq!(context.files.removed.available_permits(), 0);
            for (n, blob) in held.iter().enumerate() {
                assert_eq!(read(blob, 1).await, vec![n as u8]);
            }
            // Removed handles cannot consume the separate active-I/O budget.
            let (new, len) = context.open("test", b"new").await.unwrap();
            assert_eq!(len, 0);
            new.resize(8).await.unwrap();
            new.sync().await.unwrap();
            assert_eq!(read(&new, 8).await, vec![0; 8]);
            drop((held, new));
            context.wait_idle().await;
            assert_eq!(context.files.removed.available_permits(), REMOVED_FILES);
        });
    }

    #[test]
    fn canceled_io_observers_keep_slots_until_completion_and_sync_is_durable() {
        Directory::new().runner().start(|context| async move {
            let context = JournalContext::new(context);
            let (blob, _) = context.open("test", b"one").await.unwrap();
            let gate = blob.entry.gate.clone().lock_owned().await;
            let write = tokio::spawn({
                let blob = blob.clone();
                async move { blob.write_at(0, IoBuf::from(b"kept".to_vec())).await }
            });
            while context.files.tasks.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
            write.abort();
            let _ = write.await;
            assert_eq!(context.files.tasks.load(Ordering::Acquire), 1);
            drop(gate);
            context.wait_idle().await;
            assert_eq!(read(&blob, 4).await, b"kept");
            let observer = blob.start_sync().await;
            observer.abort();
            drop(observer);
            context.wait_idle().await;
            let task = context.child("canceled").spawn(|ctx| async move {
                ctx.sleep(Duration::from_secs(3600)).await;
            });
            task.abort();
            context.wait_idle().await;
            drop(blob);
            let (reopened, len) = context.open("test", b"one").await.unwrap();
            assert_eq!(len, 4);
            assert_eq!(read(&reopened, 4).await, b"kept");
        });
    }
}
