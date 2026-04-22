use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use quil_types::lifecycle::{Component, ErrorHandlingBehavior};

/// A supervised component with error handling policy and dependencies.
pub struct SupervisedComponent {
    pub name: String,
    pub component: Arc<dyn Component>,
    pub on_error: Box<dyn Fn(anyhow::Error) -> ErrorHandlingBehavior + Send + Sync>,
    pub deps: Vec<String>,
}

/// Manages the lifecycle of a set of components with DAG-ordered startup,
/// configurable error handling, and coordinated shutdown.
pub struct Supervisor {
    components: Vec<SupervisedComponent>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Add a component with its error policy and dependencies.
    pub fn add(
        &mut self,
        name: impl Into<String>,
        component: Arc<dyn Component>,
        deps: Vec<String>,
        on_error: impl Fn(anyhow::Error) -> ErrorHandlingBehavior + Send + Sync + 'static,
    ) {
        self.components.push(SupervisedComponent {
            name: name.into(),
            component,
            on_error: Box::new(on_error),
            deps,
        });
    }

    /// Start all components in dependency order and run until shutdown.
    pub async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        // Topological sort for startup order
        let order = self.topo_sort()?;

        // Start components in order, waiting for each to become ready
        let mut handles: HashMap<String, tokio::task::JoinHandle<Result<(), anyhow::Error>>> =
            HashMap::new();

        for idx in order {
            let sc = &self.components[idx];
            let component = sc.component.clone();
            let child_token = token.child_token();
            let name = sc.name.clone();

            info!(component = %name, "starting component");

            let handle = tokio::spawn(async move {
                component
                    .start(child_token)
                    .await
                    .map_err(|e| anyhow::anyhow!("component '{}' failed: {}", name, e))
            });

            // Wait for ready signal (with timeout)
            let mut ready_rx = sc.component.ready();
            let ready_timeout = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                async {
                    while !*ready_rx.borrow_and_update() {
                        if ready_rx.changed().await.is_err() {
                            break;
                        }
                    }
                },
            );

            if ready_timeout.await.is_err() {
                error!(component = %sc.name, "timed out waiting for ready signal");
            } else {
                info!(component = %sc.name, "component ready");
            }

            handles.insert(sc.name.clone(), handle);
        }

        // Wait for any component to finish or for cancellation.
        // The `result = async` block consumes the hashmap by value via
        // `drain()`, so once a handle is awaited here it's removed from
        // `handles` — the final cleanup loop below only sees handles that
        // were still pending when the select branch was cancelled.
        tokio::select! {
            _ = token.cancelled() => {
                info!("supervisor received shutdown signal");
            }
            result = async {
                let drained: Vec<_> = handles.drain().collect();
                for (name, handle) in drained {
                    match handle.await {
                        Ok(Ok(())) => {
                            info!(component = %name, "component exited cleanly");
                        }
                        Ok(Err(e)) => {
                            error!(component = %name, error = %e, "component failed");
                            return Err(anyhow::anyhow!(
                                "component '{}' failed: {}",
                                name,
                                e
                            ));
                        }
                        Err(join_err) => {
                            error!(component = %name, error = %join_err, "component panicked");
                            return Err(anyhow::anyhow!(
                                "component '{}' panicked: {}",
                                name,
                                join_err
                            ));
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            } => {
                if let Err(e) = result {
                    error!(error = %e, "supervisor shutting down due to component failure");
                    token.cancel();
                    return Err(e);
                }
            }
        }

        // Cancel all remaining components
        token.cancel();

        // Wait for all still-pending handles to finish. If the
        // select's result branch fully drained the hashmap above,
        // this loop is a no-op.
        for (name, handle) in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!(component = %name, error = %e, "component error during shutdown");
                }
                Err(_) => {
                    error!(component = %name, "component panicked during shutdown");
                }
            }
        }

        info!("supervisor shutdown complete");
        Ok(())
    }

    /// Topological sort of components by dependency order.
    fn topo_sort(&self) -> Result<Vec<usize>, anyhow::Error> {
        let name_to_idx: HashMap<&str, usize> = self
            .components
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.as_str(), i))
            .collect();

        let n = self.components.len();
        let mut in_degree = vec![0usize; n];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (i, sc) in self.components.iter().enumerate() {
            for dep in &sc.deps {
                if let Some(&dep_idx) = name_to_idx.get(dep.as_str()) {
                    adj[dep_idx].push(i);
                    in_degree[i] += 1;
                } else {
                    return Err(anyhow::anyhow!(
                        "component '{}' depends on unknown component '{}'",
                        sc.name,
                        dep
                    ));
                }
            }
        }

        let mut queue: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut order = Vec::with_capacity(n);

        while let Some(idx) = queue.pop() {
            order.push(idx);
            for &next in &adj[idx] {
                in_degree[next] -= 1;
                if in_degree[next] == 0 {
                    queue.push(next);
                }
            }
        }

        if order.len() != n {
            return Err(anyhow::anyhow!("circular dependency detected in component graph"));
        }

        Ok(order)
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export anyhow for error handling in component factories
pub use anyhow;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use quil_types::error::Result;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;
    use tokio::sync::watch;

    // =================================================================
    // Test components
    // =================================================================

    /// A component that:
    /// - Records its start order via an atomic counter.
    /// - Signals ready immediately.
    /// - Blocks on cancellation, then exits cleanly (or fails).
    struct RecordingComponent {
        name: String,
        ready_tx: Mutex<watch::Sender<bool>>,
        start_order: Arc<AtomicU64>,
        order_counter: Arc<AtomicU64>,
        fail_on_start: bool,
    }

    impl RecordingComponent {
        fn new(
            name: &str,
            order_counter: Arc<AtomicU64>,
            start_order: Arc<AtomicU64>,
        ) -> Self {
            let (tx, _rx) = watch::channel(false);
            Self {
                name: name.to_string(),
                ready_tx: Mutex::new(tx),
                start_order,
                order_counter,
                fail_on_start: false,
            }
        }

        fn new_failing(
            name: &str,
            order_counter: Arc<AtomicU64>,
            start_order: Arc<AtomicU64>,
        ) -> Self {
            let mut c = Self::new(name, order_counter, start_order);
            c.fail_on_start = true;
            c
        }
    }

    #[async_trait]
    impl Component for RecordingComponent {
        async fn start(&self, token: CancellationToken) -> Result<()> {
            let order = self.order_counter.fetch_add(1, Ordering::SeqCst);
            self.start_order.store(order, Ordering::SeqCst);
            let _ = self.ready_tx.lock().unwrap().send(true);
            if self.fail_on_start {
                return Err(quil_types::error::QuilError::Internal(format!(
                    "component {} failed on start",
                    self.name
                )));
            }
            token.cancelled().await;
            Ok(())
        }

        fn ready(&self) -> watch::Receiver<bool> {
            self.ready_tx.lock().unwrap().subscribe()
        }
    }

    // =================================================================
    // Topological sort tests (sync)
    // =================================================================

    fn build_sup_with_deps(
        deps: Vec<(&'static str, Vec<&'static str>)>,
    ) -> Supervisor {
        let order_counter = Arc::new(AtomicU64::new(0));
        let mut sup = Supervisor::new();
        for (name, dep_list) in deps {
            let start_order = Arc::new(AtomicU64::new(u64::MAX));
            let component = Arc::new(RecordingComponent::new(
                name,
                Arc::clone(&order_counter),
                start_order,
            )) as Arc<dyn Component>;
            sup.add(
                name,
                component,
                dep_list.iter().map(|s| s.to_string()).collect(),
                |_| ErrorHandlingBehavior::ShouldShutdown,
            );
        }
        sup
    }

    fn name_of(sup: &Supervisor, i: usize) -> &str {
        sup.components[i].name.as_str()
    }

    fn position_of(sup: &Supervisor, order: &[usize], name: &str) -> usize {
        order
            .iter()
            .position(|&i| name_of(sup, i) == name)
            .unwrap_or_else(|| panic!("{} not in sort order", name))
    }

    #[test]
    fn topo_sort_linear_chain() {
        let sup = build_sup_with_deps(vec![
            ("a", vec![]),
            ("b", vec!["a"]),
            ("c", vec!["b"]),
        ]);
        let order = sup.topo_sort().unwrap();
        assert_eq!(order.len(), 3);
        let pa = position_of(&sup, &order, "a");
        let pb = position_of(&sup, &order, "b");
        let pc = position_of(&sup, &order, "c");
        assert!(pa < pb);
        assert!(pb < pc);
    }

    #[test]
    fn topo_sort_parallel_branches() {
        let sup = build_sup_with_deps(vec![
            ("a", vec![]),
            ("b", vec!["a"]),
            ("c", vec!["a"]),
        ]);
        let order = sup.topo_sort().unwrap();
        let pa = position_of(&sup, &order, "a");
        let pb = position_of(&sup, &order, "b");
        let pc = position_of(&sup, &order, "c");
        assert!(pa < pb);
        assert!(pa < pc);
    }

    #[test]
    fn topo_sort_diamond() {
        let sup = build_sup_with_deps(vec![
            ("a", vec![]),
            ("b", vec!["a"]),
            ("c", vec!["a"]),
            ("d", vec!["b", "c"]),
        ]);
        let order = sup.topo_sort().unwrap();
        let pa = position_of(&sup, &order, "a");
        let pb = position_of(&sup, &order, "b");
        let pc = position_of(&sup, &order, "c");
        let pd = position_of(&sup, &order, "d");
        assert!(pa < pb);
        assert!(pa < pc);
        assert!(pb < pd);
        assert!(pc < pd);
    }

    #[test]
    fn topo_sort_circular_is_error() {
        let sup = build_sup_with_deps(vec![
            ("a", vec!["c"]),
            ("b", vec!["a"]),
            ("c", vec!["b"]),
        ]);
        let err = sup.topo_sort().unwrap_err();
        assert!(format!("{}", err).contains("circular"));
    }

    #[test]
    fn topo_sort_unknown_dep_is_error() {
        let sup = build_sup_with_deps(vec![("a", vec!["ghost"])]);
        let err = sup.topo_sort().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unknown") || msg.contains("ghost"));
    }

    #[test]
    fn topo_sort_empty_returns_empty() {
        let sup = Supervisor::new();
        assert_eq!(sup.topo_sort().unwrap().len(), 0);
    }

    #[test]
    fn topo_sort_single_component_no_deps() {
        let sup = build_sup_with_deps(vec![("only", vec![])]);
        assert_eq!(sup.topo_sort().unwrap(), vec![0]);
    }

    #[test]
    fn topo_sort_independent_roots() {
        let sup = build_sup_with_deps(vec![
            ("a", vec![]),
            ("b", vec![]),
        ]);
        let order = sup.topo_sort().unwrap();
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn topo_sort_self_reference_is_circular() {
        let sup = build_sup_with_deps(vec![("a", vec!["a"])]);
        let err = sup.topo_sort().unwrap_err();
        assert!(format!("{}", err).contains("circular"));
    }

    // =================================================================
    // Async supervisor run tests
    // =================================================================

    #[tokio::test]
    async fn supervisor_runs_and_shuts_down_cleanly() {
        let sup = build_sup_with_deps(vec![
            ("a", vec![]),
            ("b", vec!["a"]),
        ]);
        let token = CancellationToken::new();
        let token_clone = token.clone();
        let h = tokio::spawn(async move { sup.run(token_clone).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        token.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), h)
            .await
            .expect("supervisor should stop within 1s")
            .unwrap();
        assert!(result.is_ok(), "supervisor returned error: {:?}", result);
    }

    #[tokio::test]
    async fn supervisor_starts_in_dependency_order() {
        let order_counter = Arc::new(AtomicU64::new(0));
        let order_a = Arc::new(AtomicU64::new(u64::MAX));
        let order_b = Arc::new(AtomicU64::new(u64::MAX));
        let order_c = Arc::new(AtomicU64::new(u64::MAX));

        let mut sup = Supervisor::new();
        sup.add(
            "a",
            Arc::new(RecordingComponent::new(
                "a",
                Arc::clone(&order_counter),
                Arc::clone(&order_a),
            )),
            vec![],
            |_| ErrorHandlingBehavior::ShouldShutdown,
        );
        sup.add(
            "b",
            Arc::new(RecordingComponent::new(
                "b",
                Arc::clone(&order_counter),
                Arc::clone(&order_b),
            )),
            vec!["a".into()],
            |_| ErrorHandlingBehavior::ShouldShutdown,
        );
        sup.add(
            "c",
            Arc::new(RecordingComponent::new(
                "c",
                Arc::clone(&order_counter),
                Arc::clone(&order_c),
            )),
            vec!["b".into()],
            |_| ErrorHandlingBehavior::ShouldShutdown,
        );

        let token = CancellationToken::new();
        let token_clone = token.clone();
        let h = tokio::spawn(async move { sup.run(token_clone).await });
        // Give all three components time to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h).await;

        let a = order_a.load(Ordering::SeqCst);
        let b = order_b.load(Ordering::SeqCst);
        let c = order_c.load(Ordering::SeqCst);
        assert!(
            a < b && b < c,
            "expected a < b < c, got a={} b={} c={}",
            a,
            b,
            c
        );
    }

    #[tokio::test]
    async fn supervisor_reports_failing_component() {
        let order_counter = Arc::new(AtomicU64::new(0));
        let start_order = Arc::new(AtomicU64::new(u64::MAX));
        let mut sup = Supervisor::new();
        sup.add(
            "failing",
            Arc::new(RecordingComponent::new_failing(
                "failing",
                order_counter,
                start_order,
            )),
            vec![],
            |_| ErrorHandlingBehavior::ShouldShutdown,
        );
        let token = CancellationToken::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sup.run(token),
        )
        .await
        .expect("supervisor should return promptly");
        assert!(result.is_err(), "expected supervisor to report failure");
    }

    #[tokio::test]
    async fn supervisor_cancellation_terminates_blocking_components() {
        struct BlockingComponent {
            ready_tx: Mutex<watch::Sender<bool>>,
            seen_cancel: Arc<AtomicBool>,
        }
        #[async_trait]
        impl Component for BlockingComponent {
            async fn start(&self, token: CancellationToken) -> Result<()> {
                let _ = self.ready_tx.lock().unwrap().send(true);
                token.cancelled().await;
                self.seen_cancel.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn ready(&self) -> watch::Receiver<bool> {
                self.ready_tx.lock().unwrap().subscribe()
            }
        }

        let seen_cancel = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = watch::channel(false);
        let blocker = Arc::new(BlockingComponent {
            ready_tx: Mutex::new(tx),
            seen_cancel: Arc::clone(&seen_cancel),
        }) as Arc<dyn Component>;

        let mut sup = Supervisor::new();
        sup.add("blocker", blocker, vec![], |_| {
            ErrorHandlingBehavior::ShouldShutdown
        });

        let token = CancellationToken::new();
        let token_clone = token.clone();
        let h = tokio::spawn(async move { sup.run(token_clone).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), h)
            .await
            .expect("supervisor should stop within 1s");

        assert!(
            seen_cancel.load(Ordering::SeqCst),
            "blocking component did not see cancellation token fire"
        );
    }

    #[tokio::test]
    async fn supervisor_passes_error_from_underlying_component() {
        // The failing component returns an error; supervisor::run
        // should surface it via its Result return value.
        let order_counter = Arc::new(AtomicU64::new(0));
        let start_order = Arc::new(AtomicU64::new(u64::MAX));
        let mut sup = Supervisor::new();
        sup.add(
            "bad",
            Arc::new(RecordingComponent::new_failing(
                "bad",
                order_counter,
                start_order,
            )),
            vec![],
            |_| ErrorHandlingBehavior::ShouldShutdown,
        );
        let token = CancellationToken::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sup.run(token),
        )
        .await
        .unwrap();
        let err = result.unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("bad"));
    }
}
