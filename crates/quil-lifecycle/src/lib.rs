//! Process-lifecycle primitives shared across the workspace.
//!
//! Currently only [`Supervisor`], the central join-and-propagate task
//! manager. Lives in its own crate so any subsystem that needs to
//! register a long-running task can take `&mut Supervisor<E>` directly,
//! regardless of whether it's reached from `quil-node` (where the
//! supervisor is created) or one of the lower-level crates like
//! `quil-p2p` or `quil-rpc`.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::{Id, JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

/// A task submitted to the supervisor via [`DetachedSpawner`].
type BoxedTask<E> = Pin<Box<dyn Future<Output = Result<(), E>> + Send + 'static>>;

struct DetachRegistration<E> {
    name: String,
    fut: BoxedTask<E>,
}

/// Cloneable handle for spawning fire-and-forget tasks onto the
/// supervisor's `JoinSet`. Use this from sync trait impls or per-event
/// handlers that can't be made `async`, where you'd otherwise reach for
/// bare `tokio::spawn`.
///
/// Tasks registered this way still surface panics as [`ShutdownReason::JoinError`]
/// and `Err` returns as [`ShutdownReason::TaskError`] — they're tracked
/// the same as anything spawned via [`Supervisor::spawn`].
pub struct DetachedSpawner<E> {
    tx: mpsc::UnboundedSender<DetachRegistration<E>>,
    token: CancellationToken,
}

impl<E> Clone for DetachedSpawner<E> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            token: self.token.clone(),
        }
    }
}

impl<E: Send + 'static> DetachedSpawner<E> {
    /// Submit a task to the supervisor. If the supervisor has already
    /// shut down, the task is dropped silently — the caller is expected
    /// to be on a path that's about to be cancelled anyway.
    pub fn detach<F>(&self, name: impl Into<String>, f: F)
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
    {
        let _ = self.tx.send(DetachRegistration {
            name: name.into(),
            fut: Box::pin(f),
        });
    }

    /// The supervisor's cancellation token. Detached tasks that contain
    /// long-running loops should honor this.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

pub struct Supervisor<E> {
    set: JoinSet<Result<(), E>>,
    names: HashMap<Id, String>,
    /// Tasks registered via `spawn_startup_task` — their normal `Ok(())`
    /// completion is expected and does NOT trigger a `TaskExited`
    /// shutdown. Panics and `Err` returns still do.
    startup: HashSet<Id>,
    /// Tasks registered via [`DetachedSpawner`] — same shutdown semantics
    /// as `startup`: normal `Ok(())` is not a `TaskExited` shutdown.
    detached: HashSet<Id>,
    token: CancellationToken,
    shutdown_timeout: Duration,
    detach_tx: mpsc::UnboundedSender<DetachRegistration<E>>,
    detach_rx: mpsc::UnboundedReceiver<DetachRegistration<E>>,
}

pub enum ShutdownReason<E> {
    CtrlC,
    TaskExited(String),
    TaskError(String, E),
    JoinError(String, JoinError),
}

impl<E: Send + 'static> Supervisor<E> {
    pub fn new() -> Self {
        let (detach_tx, detach_rx) = mpsc::unbounded_channel();
        Self {
            set: JoinSet::new(),
            names: HashMap::new(),
            startup: HashSet::new(),
            detached: HashSet::new(),
            token: CancellationToken::new(),
            shutdown_timeout: Duration::from_secs(10),
            detach_tx,
            detach_rx,
        }
    }

    /// Return a cloneable handle for spawning fire-and-forget tasks.
    pub fn detached_spawner(&self) -> DetachedSpawner<E> {
        DetachedSpawner {
            tx: self.detach_tx.clone(),
            token: self.token.clone(),
        }
    }

    pub fn with_shutdown_timeout(mut self, d: Duration) -> Self {
        self.shutdown_timeout = d;
        self
    }

    /// Exposed so callers can wire the same token into things outside the set
    /// (e.g. an axum server's `with_graceful_shutdown`).
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Register a task. The closure receives a `CancellationToken` the task
    /// should honor; `name` is surfaced in `ShutdownReason` for diagnostics.
    pub fn spawn<F, Fut>(&mut self, name: impl Into<String>, f: F)
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
    {
        let token = self.token.clone();
        let id = self.set.spawn(f(token)).id();
        self.names.insert(id, name.into());
    }

    /// Register a task that should run until the supervisor's token is
    /// cancelled. The user's future is dropped on cancellation and the task
    /// returns `Ok(())`. Use plain `spawn` if the task needs to perform work
    /// *on* cancellation that can't be expressed as drop (e.g. calling a
    /// `stop()` method on a handle).
    pub fn run_until_cancelled<F, Fut>(&mut self, name: impl Into<String>, f: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
    {
        self.spawn(name, |token| async move {
            tokio::select! {
                _ = token.cancelled() => Ok(()),
                r = f(token.clone()) => r,
            }
        });
    }

    /// Register a short-lived background task that is expected to terminate
    /// normally before the node shuts down (e.g. a one-shot init job that
    /// shouldn't block startup). Unlike `spawn`, a normal `Ok(())` completion
    /// does NOT trigger `ShutdownReason::TaskExited` — the supervisor just
    /// drops it from tracking and keeps running. Panics and `Err` returns
    /// still surface as `JoinError` / `TaskError` and shut the supervisor
    /// down.
    pub fn spawn_startup_task<F, Fut>(&mut self, name: impl Into<String>, f: F)
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
    {
        let token = self.token.clone();
        let id = self.set.spawn(f(token)).id();
        self.names.insert(id, name.into());
        self.startup.insert(id);
    }

    pub async fn run(mut self) -> ShutdownReason<E> {
        // Drop our own copy of the detach sender so the channel closes
        // once the last `DetachedSpawner` clone goes away. Without this,
        // `detach_rx.recv()` would block forever even after all real
        // senders are dropped.
        drop(self.detach_tx);
        let reason = loop {
            tokio::select! {
                Some(reg) = self.detach_rx.recv() => {
                    let id = self.set.spawn(reg.fut).id();
                    self.names.insert(id, reg.name);
                    self.detached.insert(id);
                }
                Some(res) = self.set.join_next_with_id() => match res {
                    Err(e) => {
                        let name = self.names.remove(&e.id()).unwrap_or_default();
                        self.startup.remove(&e.id());
                        self.detached.remove(&e.id());
                        break ShutdownReason::JoinError(name, e);
                    }
                    Ok((id, Ok(()))) => {
                        let name = self.names.remove(&id).unwrap_or_default();
                        if self.startup.remove(&id) {
                            // Startup task finished as expected — keep
                            // running the rest of the supervised set.
                            debug!(task = %name, "startup task completed");
                            continue;
                        }
                        if self.detached.remove(&id) {
                            // Detached fire-and-forget completed normally —
                            // not a shutdown trigger.
                            debug!(task = %name, "detached task completed");
                            continue;
                        }
                        break ShutdownReason::TaskExited(name);
                    }
                    Ok((id, Err(e))) => {
                        let name = self.names.remove(&id).unwrap_or_default();
                        self.startup.remove(&id);
                        self.detached.remove(&id);
                        break ShutdownReason::TaskError(name, e);
                    }
                },
                _ = tokio::signal::ctrl_c() => break ShutdownReason::CtrlC,
            }
        };

        self.token.cancel();
        Self::drain(&mut self.set, self.shutdown_timeout, &mut self.names).await;
        reason
    }

    async fn drain(
        set: &mut JoinSet<Result<(), E>>,
        timeout: Duration,
        names: &mut HashMap<Id, String>,
    ) {
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                res = set.join_next_with_id() => match res {
                    None => return,
                    Some(Err(e)) => {
                        let name = names.remove(&e.id()).unwrap_or_default();
                        error!(task = %name, error = %e, "task error during shutdown");
                    }
                    Some(Ok((id, _))) => { names.remove(&id); }
                },
                _ = &mut deadline => {
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn detached_task_runs_then_does_not_trigger_shutdown() {
        let mut sup: Supervisor<String> = Supervisor::new();
        let counter = Arc::new(AtomicUsize::new(0));

        let counter_for_main = counter.clone();
        sup.spawn("main", move |token| async move {
            token.cancelled().await;
            counter_for_main.fetch_add(100, Ordering::SeqCst);
            Ok(())
        });

        let spawner = sup.detached_spawner();
        let counter_for_detached = counter.clone();
        spawner.detach("oneshot", async move {
            counter_for_detached.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        drop(spawner);

        let sup_token = sup.token();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            sup_token.cancel();
        });

        let reason = sup.run().await;
        assert!(matches!(reason, ShutdownReason::TaskExited(_)));
        assert_eq!(counter.load(Ordering::SeqCst), 101);
    }

    #[tokio::test]
    async fn detached_task_error_shuts_down_supervisor() {
        let mut sup: Supervisor<String> = Supervisor::new();
        sup.spawn("main", |token| async move {
            token.cancelled().await;
            Ok(())
        });
        let spawner = sup.detached_spawner();
        spawner.detach("failing", async move { Err("boom".into()) });
        let reason = sup.run().await;
        match reason {
            ShutdownReason::TaskError(name, e) => {
                assert_eq!(name, "failing");
                assert_eq!(e, "boom");
            }
            _ => panic!("expected TaskError, got something else"),
        }
    }
}
