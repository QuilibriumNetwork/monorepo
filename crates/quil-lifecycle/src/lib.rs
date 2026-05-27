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
use std::time::Duration;
use tokio::task::{Id, JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

pub struct Supervisor<E> {
    set: JoinSet<Result<(), E>>,
    names: HashMap<Id, String>,
    /// Tasks registered via `spawn_startup_task` — their normal `Ok(())`
    /// completion is expected and does NOT trigger a `TaskExited`
    /// shutdown. Panics and `Err` returns still do.
    startup: HashSet<Id>,
    token: CancellationToken,
    shutdown_timeout: Duration,
}

pub enum ShutdownReason<E> {
    CtrlC,
    TaskExited(String),
    TaskError(String, E),
    JoinError(String, JoinError),
}

impl<E: Send + 'static> Supervisor<E> {
    pub fn new() -> Self {
        Self {
            set: JoinSet::new(),
            names: HashMap::new(),
            startup: HashSet::new(),
            token: CancellationToken::new(),
            shutdown_timeout: Duration::from_secs(10),
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
        let reason = loop {
            tokio::select! {
                Some(res) = self.set.join_next_with_id() => match res {
                    Err(e) => {
                        let name = self.names.remove(&e.id()).unwrap_or_default();
                        self.startup.remove(&e.id());
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
                        break ShutdownReason::TaskExited(name);
                    }
                    Ok((id, Err(e))) => {
                        let name = self.names.remove(&id).unwrap_or_default();
                        self.startup.remove(&id);
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
