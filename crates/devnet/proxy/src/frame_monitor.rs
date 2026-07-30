//! Polls archive nodes until enough of them reach the target frame, then
//! fetches the committed frame chain for the safety check.
//!
//! Mirrors the Go `FrameMonitor`. Dials each archive's `:8340` `GlobalService`
//! directly (the proxy shares every archive's network) via
//! `quil_rpc::ArchiveClient`, reusing the production PQNoise connector. The
//! dial identity is a Falcon `q-prover-key` signing key borrowed from an
//! archive, since that port authenticates peers by Falcon identity.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use quil_rpc::ArchiveClient;

use crate::frame::GlobalFrameWrapper;

/// A node to poll: a `host:port` GlobalService address.
#[derive(Debug, Clone)]
pub struct FrameTarget {
    pub address: String,
}

struct NodeStatus {
    /// Lazily (re)connected client; `None` until first connect / after error.
    client: Option<ArchiveClient>,
    last_head_frame: u64,
    first_polled_at: Option<Instant>,
    last_successful_poll: Option<Instant>,
    errored: bool,
}

impl NodeStatus {
    fn new() -> Self {
        Self {
            client: None,
            last_head_frame: 0,
            first_polled_at: None,
            last_successful_poll: None,
            errored: false,
        }
    }
}

/// Polls archives for frame convergence.
pub struct FrameMonitor {
    /// Falcon signing key the proxy dials archives with (borrowed from an archive).
    dial_key: Vec<u8>,
    stop_frame: u64,
    targets: Vec<FrameTarget>,
    poll_interval: Duration,
    timeout: Duration,
    min_nodes: usize,
    statuses: HashMap<String, NodeStatus>,
}

impl FrameMonitor {
    pub fn new(
        dial_key: Vec<u8>,
        stop_frame: u64,
        targets: Vec<FrameTarget>,
        poll_interval: Duration,
        min_nodes: usize,
        timeout: Duration,
    ) -> Self {
        let statuses = targets
            .iter()
            .map(|t| (t.address.clone(), NodeStatus::new()))
            .collect();
        Self {
            dial_key,
            stop_frame,
            targets,
            poll_interval,
            timeout,
            min_nodes,
            statuses,
        }
    }

    /// Poll one node: connect if needed, query the stop frame, update status.
    async fn poll_node(&mut self, address: &str) {
        let dial_key = self.dial_key.clone();
        let stop_frame = self.stop_frame;
        let status = self.statuses.get_mut(address).expect("status exists");
        let now = Instant::now();
        if status.first_polled_at.is_none() {
            status.first_polled_at = Some(now);
        }

        // (Re)connect if we don't have a live client.
        if status.client.is_none() {
            match ArchiveClient::connect_mtls(address, &dial_key).await {
                Ok(c) => status.client = Some(c),
                Err(e) => {
                    status.errored = true;
                    tracing::debug!(address, error = %e, "frame monitor: connect failed");
                    return;
                }
            }
        }

        let client = status.client.as_mut().unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(5), client.get_global_frame(stop_frame)).await;
        match result {
            Ok(Ok(frame)) => {
                let head = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                status.last_head_frame = head;
                status.last_successful_poll = Some(now);
                status.errored = false;
            }
            Ok(Err(e)) => {
                status.errored = true;
                status.client = None; // force reconnect next poll
                tracing::debug!(address, stop_frame, error = %e, "frame monitor: poll failed");
            }
            Err(_) => {
                status.errored = true;
                status.client = None;
                tracing::debug!(address, stop_frame, "frame monitor: poll timed out");
            }
        }
    }

    async fn poll_all(&mut self) {
        let addresses: Vec<String> = self.targets.iter().map(|t| t.address.clone()).collect();
        for address in addresses {
            self.poll_node(&address).await;
        }
    }

    fn count_reached(&self) -> usize {
        self.statuses
            .values()
            .filter(|s| s.last_head_frame >= self.stop_frame && !s.errored)
            .count()
    }

    /// Returns true when monitoring should stop: either enough nodes reached the
    /// stop frame, or too many have failed to ever reach the minimum.
    fn should_stop(&self) -> bool {
        let ready = self.count_reached();
        if ready >= self.min_nodes {
            return true;
        }

        let now = Instant::now();
        let mut failed = 0;
        for status in self.statuses.values() {
            if status.errored {
                let since_success = match status.last_successful_poll {
                    Some(t) => now.duration_since(t),
                    None => status
                        .first_polled_at
                        .map(|t| now.duration_since(t))
                        .unwrap_or_default(),
                };
                if since_success > self.timeout {
                    failed += 1;
                }
            }
        }

        tracing::info!(
            ready,
            failed,
            min_nodes = self.min_nodes,
            "frame convergence check"
        );

        // Impossible to reach the minimum even if all non-failed nodes succeed.
        if self.targets.len().saturating_sub(failed) < self.min_nodes {
            tracing::error!(
                min_nodes = self.min_nodes,
                failed,
                total = self.targets.len(),
                "insufficient nodes available to reach minimum, aborting"
            );
            return true;
        }
        false
    }

    /// Poll until enough nodes reach the stop frame (or it becomes impossible).
    /// Returns `(nodes_reached, total_nodes)`.
    pub async fn start_monitoring(
        &mut self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> (usize, usize) {
        let total = self.targets.len();
        tracing::info!(
            node_count = total,
            stop_frame = self.stop_frame,
            "starting frame monitoring"
        );

        self.poll_all().await;
        if self.should_stop() {
            return (self.count_reached(), total);
        }

        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::debug!("frame monitoring cancelled");
                    return (self.count_reached(), total);
                }
                _ = ticker.tick() => {
                    self.poll_all().await;
                    if self.should_stop() {
                        return (self.count_reached(), total);
                    }
                }
            }
        }
    }

    /// Fetch frames `1..=stop_frame` from every node that reached the stop frame.
    /// Call after [`Self::start_monitoring`]. Duplicates across nodes are kept
    /// (the safety check tolerates the same frame reported by multiple nodes).
    pub async fn fetch_committed_frames(&mut self) -> Vec<GlobalFrameWrapper> {
        let ready_addrs: Vec<String> = self
            .statuses
            .iter()
            .filter(|(_, s)| s.last_head_frame >= self.stop_frame && !s.errored)
            .map(|(a, _)| a.clone())
            .collect();

        let mut frames = Vec::new();
        for address in &ready_addrs {
            let mut client = match ArchiveClient::connect_mtls(address, &self.dial_key).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(address, error = %e, "fetch frames: connect failed");
                    continue;
                }
            };
            for frame_num in 1..=self.stop_frame {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    client.get_global_frame(frame_num),
                )
                .await
                {
                    Ok(Ok(frame)) => frames.push(GlobalFrameWrapper::new(frame)),
                    Ok(Err(e)) => {
                        tracing::warn!(address, frame_num, error = %e, "fetch frame failed")
                    }
                    Err(_) => tracing::warn!(address, frame_num, "fetch frame timed out"),
                }
            }
        }

        tracing::info!(
            node_count = ready_addrs.len(),
            frame_count = frames.len(),
            "fetched committed frames"
        );
        frames
    }
}
