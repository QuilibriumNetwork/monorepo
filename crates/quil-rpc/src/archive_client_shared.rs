//! One connection per key (an archive endpoint, the identity dialing it and
//! what it carries), shared by every caller in the process.
//!
//! A submission used to dial its own connection to every archive, so a host
//! running many nodes behind one public address opened hundreds of
//! connections to each archive within seconds when finalizations bunched,
//! and every archive's peer listener refused that address at its per-source
//! cap. A [`SharedConnections`] set keeps one connection per key while it is
//! used: callers that find none wait on a single dial, and share its failure
//! when it fails, so a burst opens at most one connection. A connection
//! nobody holds closes once unused for the set's idle limit (a sweep runs
//! while any is kept, so within one and a half times that limit), and is
//! dropped at once when its caller saw the transport fail.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// A shared connection a caller holds: idle time counts from its release.
pub struct Shared<C> {
    client: C,
    id: u64,
    kept: bool,
    slot: Arc<parking_lot::Mutex<Option<Kept<C>>>>,
}

impl<C> Shared<C> {
    /// Whether an earlier caller opened this connection.
    pub fn kept(&self) -> bool {
        self.kept
    }

    /// The connection's id within its set.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Drop this connection from its set (its transport failed): the next
    /// caller dials a new one. A newer connection that replaced it stays.
    pub fn discard(&self) {
        let mut kept = self.slot.lock();
        if kept.as_ref().is_some_and(|kept| kept.id == self.id) {
            *kept = None;
        }
    }
}

impl<C> std::ops::Deref for Shared<C> {
    type Target = C;
    fn deref(&self) -> &C {
        &self.client
    }
}

impl<C> std::ops::DerefMut for Shared<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.client
    }
}

impl<C> Drop for Shared<C> {
    fn drop(&mut self) {
        let mut kept = self.slot.lock();
        if let Some(kept) = kept.as_mut().filter(|kept| kept.id == self.id) {
            kept.busy = kept.busy.saturating_sub(1);
            kept.used = Instant::now();
        }
    }
}

struct Kept<C> {
    client: C,
    id: u64,
    /// Callers holding it.
    busy: usize,
    /// When it was last taken or released.
    used: Instant,
}

impl<C> Kept<C> {
    fn expired(&self, idle: Duration) -> bool {
        self.busy == 0 && self.used.elapsed() >= idle
    }
}

/// One key's connection, its dial and its request slots.
struct Slot<C, E> {
    kept: Arc<parking_lot::Mutex<Option<Kept<C>>>>,
    /// Held across a dial, so callers that find no connection wait on it;
    /// holds the last failed dial's time and error.
    dial: tokio::sync::Mutex<Option<(Instant, Arc<E>)>>,
    permits: Option<Arc<tokio::sync::Semaphore>>,
}

struct Slots<K, C, E> {
    by_key: HashMap<K, Arc<Slot<C, E>>>,
    sweeping: bool,
}

struct Inner<K, C, E> {
    idle: Duration,
    in_flight: Option<usize>,
    sweeper: Option<tokio::runtime::Handle>,
    next_id: AtomicU64,
    slots: parking_lot::Mutex<Slots<K, C, E>>,
}

/// Connections shared per key; see the module docs. Clones share the set.
pub struct SharedConnections<K, C, E> {
    inner: Arc<Inner<K, C, E>>,
}

impl<K, C, E> Clone for SharedConnections<K, C, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, C, E> SharedConnections<K, C, E>
where
    K: Clone + Eq + Hash + Send + 'static,
    C: Clone + Send + 'static,
    E: Send + Sync + 'static,
{
    /// A set closing connections unused for `idle`, with at most
    /// `in_flight` requests per connection through [`Self::permit`] (`None`:
    /// no bound), sweeping on `sweeper` (`None`: the runtime of the first
    /// dial).
    pub fn new(
        idle: Duration,
        in_flight: Option<usize>,
        sweeper: Option<tokio::runtime::Handle>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                idle,
                in_flight,
                sweeper,
                next_id: AtomicU64::new(0),
                slots: parking_lot::Mutex::new(Slots {
                    by_key: HashMap::new(),
                    sweeping: false,
                }),
            }),
        }
    }

    fn slot(&self, key: &K) -> Arc<Slot<C, E>> {
        let in_flight = self.inner.in_flight;
        self.inner
            .slots
            .lock()
            .by_key
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(Slot {
                    kept: Default::default(),
                    dial: tokio::sync::Mutex::new(None),
                    permits: in_flight.map(|n| Arc::new(tokio::sync::Semaphore::new(n))),
                })
            })
            .clone()
    }

    /// The kept connection of `slot`, unless it expired.
    fn reuse(&self, slot: &Slot<C, E>) -> Option<Shared<C>> {
        let mut kept = slot.kept.lock();
        if kept
            .as_ref()
            .is_some_and(|kept| kept.expired(self.inner.idle))
        {
            *kept = None;
        }
        let held = kept.as_mut()?;
        held.busy += 1;
        held.used = Instant::now();
        Some(Shared {
            client: held.client.clone(),
            id: held.id,
            kept: true,
            slot: slot.kept.clone(),
        })
    }

    /// The connection for `key`, else one `dial` opens. Callers that find
    /// none while a dial runs wait for it and take its connection, or its
    /// error when it failed after they asked: a burst dials once.
    pub async fn connect<F, Fut>(&self, key: &K, dial: F) -> Result<Shared<C>, Arc<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<C, E>>,
    {
        let asked = Instant::now();
        let slot = self.slot(key);
        if let Some(shared) = self.reuse(&slot) {
            return Ok(shared);
        }
        let mut last_failure = slot.dial.lock().await;
        if let Some(shared) = self.reuse(&slot) {
            return Ok(shared);
        }
        if let Some((failed, error)) = last_failure.as_ref() {
            if *failed >= asked {
                return Err(error.clone());
            }
        }
        match dial().await {
            Ok(client) => {
                let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
                *slot.kept.lock() = Some(Kept {
                    client: client.clone(),
                    id,
                    busy: 1,
                    used: Instant::now(),
                });
                *last_failure = None;
                drop(last_failure);
                self.sweep_while_kept();
                Ok(Shared {
                    client,
                    id,
                    kept: false,
                    slot: slot.kept.clone(),
                })
            }
            Err(error) => {
                let error = Arc::new(error);
                *last_failure = Some((Instant::now(), error.clone()));
                Err(error)
            }
        }
    }

    /// A request slot on `key`'s connection, waited for while all are taken
    /// (never another connection); `None` when the set has no bound.
    pub async fn permit(&self, key: &K) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permits = self.slot(key).permits.clone()?;
        permits.acquire_owned().await.ok()
    }

    /// Drop expired connections and the slots nobody uses; whether any
    /// connection is still kept. The sweep ends when none is.
    fn expire(inner: &Inner<K, C, E>) -> bool {
        let mut slots = inner.slots.lock();
        slots.by_key.retain(|_, slot| {
            let mut kept = slot.kept.lock();
            if kept.as_ref().is_some_and(|kept| kept.expired(inner.idle)) {
                *kept = None;
            }
            kept.is_some() || Arc::strong_count(slot) > 1
        });
        let any = slots.by_key.values().any(|slot| slot.kept.lock().is_some());
        if !any {
            slots.sweeping = false;
        }
        any
    }

    /// Expire unused connections every half idle limit while any is kept.
    fn sweep_while_kept(&self) {
        let mut slots = self.inner.slots.lock();
        if slots.sweeping {
            return;
        }
        let runtime = match &self.inner.sweeper {
            Some(runtime) => runtime.clone(),
            None => match tokio::runtime::Handle::try_current() {
                Ok(runtime) => runtime,
                Err(_) => return,
            },
        };
        slots.sweeping = true;
        let weak = Arc::downgrade(&self.inner);
        let every = self.inner.idle / 2;
        runtime.spawn(async move {
            // A sweep its runtime drops lets the next dial start another.
            let mut ended = SweepEnded(Some(weak.clone()));
            loop {
                tokio::time::sleep(every).await;
                let Some(inner) = weak.upgrade() else {
                    ended.0 = None;
                    return;
                };
                if !Self::expire(&inner) {
                    ended.0 = None;
                    return;
                }
            }
        });
    }

    /// Keys with a kept connection (tests and diagnostics).
    pub fn kept(&self) -> usize {
        self.inner
            .slots
            .lock()
            .by_key
            .values()
            .filter(|slot| slot.kept.lock().is_some())
            .count()
    }
}

/// Clears the sweeping flag when a sweep is dropped before it ended itself.
struct SweepEnded<K, C, E>(Option<Weak<Inner<K, C, E>>>);

impl<K, C, E> Drop for SweepEnded<K, C, E> {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take().and_then(|weak| weak.upgrade()) {
            inner.slots.lock().sweeping = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    type Set = SharedConnections<&'static str, Arc<u64>, String>;

    fn counted_dial(
        dials: &Arc<AtomicUsize>,
        took: Duration,
        fail: bool,
    ) -> impl Future<Output = Result<Arc<u64>, String>> {
        let dials = dials.clone();
        async move {
            let n = dials.fetch_add(1, Ordering::SeqCst) as u64;
            tokio::time::sleep(took).await;
            if fail {
                Err(format!("dial {n} failed"))
            } else {
                Ok(Arc::new(n))
            }
        }
    }

    /// Two hundred callers asking at once for a key with no connection wait
    /// on one dial and share its connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn callers_asking_at_once_share_one_dial() {
        let set = Set::new(Duration::from_secs(60), None, None);
        let dials = Arc::new(AtomicUsize::new(0));
        let callers = (0..200).map(|_| {
            let (set, dials) = (set.clone(), dials.clone());
            tokio::spawn(async move {
                let shared = set
                    .connect(&"archive", || {
                        counted_dial(&dials, Duration::from_millis(50), false)
                    })
                    .await
                    .unwrap();
                shared.id()
            })
        });
        let ids: Vec<u64> = futures::future::join_all(callers)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "a burst dialed once per caller: no single flight"
        );
        assert!(ids.iter().all(|id| *id == ids[0]), "{ids:?}");
        let again = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        assert!(again.kept());
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "the connection was not kept"
        );
    }

    /// Callers waiting on a dial that fails share its failure rather than
    /// each dialing in turn; a caller asking after it dials again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn callers_waiting_on_a_failed_dial_share_its_failure() {
        let set = Set::new(Duration::from_secs(60), None, None);
        let dials = Arc::new(AtomicUsize::new(0));
        let callers = (0..16).map(|_| {
            let (set, dials) = (set.clone(), dials.clone());
            tokio::spawn(async move {
                set.connect(&"archive", || {
                    counted_dial(&dials, Duration::from_millis(100), true)
                })
                .await
                .err()
            })
        });
        for failed in futures::future::join_all(callers).await {
            assert_eq!(
                failed.unwrap().as_deref().map(String::as_str),
                Some("dial 0 failed")
            );
        }
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "a failed dial was repeated by its waiters"
        );
        let later = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await;
        assert!(later.is_ok());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    /// A connection a caller holds stays however long the call runs; one
    /// nobody holds is closed once unused for the idle limit, by the sweep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unused_connection_closes_after_its_idle_limit_and_a_held_one_stays() {
        let idle = Duration::from_millis(100);
        let set = Set::new(idle, None, None);
        let dials = Arc::new(AtomicUsize::new(0));
        let held = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        tokio::time::sleep(idle * 3).await;
        let during = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        assert!(during.kept(), "a held connection expired under its call");
        let client = Arc::clone(&held);
        drop((held, during));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&client) > 1 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            Arc::strong_count(&client),
            1,
            "the sweep did not close an unused connection"
        );
        assert_eq!(set.kept(), 0);
        let after = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        assert!(!after.kept());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    /// A discarded connection is dialed again by the next caller; discarding
    /// an older connection leaves the newer one.
    #[tokio::test]
    async fn a_discarded_connection_is_replaced_and_a_stale_discard_keeps_its_successor() {
        let set = Set::new(Duration::from_secs(60), None, None);
        let dials = Arc::new(AtomicUsize::new(0));
        let first = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        first.discard();
        let second = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        assert!(!second.kept());
        assert_ne!(first.id(), second.id());
        first.discard();
        drop(first);
        let third = set
            .connect(&"archive", || counted_dial(&dials, Duration::ZERO, false))
            .await
            .unwrap();
        assert_eq!(third.id(), second.id());
        assert_eq!(dials.load(Ordering::SeqCst), 2);
    }

    /// Requests on one connection take a slot each; with every slot taken a
    /// caller waits.
    #[tokio::test]
    async fn requests_beyond_the_in_flight_bound_wait_for_a_slot() {
        let set = Set::new(Duration::from_secs(60), Some(2), None);
        let first = set.permit(&"archive").await.unwrap();
        let _second = set.permit(&"archive").await.unwrap();
        let third = tokio::time::timeout(Duration::from_millis(100), set.permit(&"archive")).await;
        assert!(third.is_err(), "a third request ran beside two in flight");
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(5), set.permit(&"archive")).await;
        assert!(matches!(third, Ok(Some(_))));
        assert!(Set::new(Duration::from_secs(60), None, None)
            .permit(&"archive")
            .await
            .is_none());
    }
}
