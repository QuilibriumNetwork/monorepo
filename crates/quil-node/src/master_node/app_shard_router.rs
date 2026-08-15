use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use quil_rpc::stub_services::AppShardFrameProvider;
use quil_types::error::QuilError;
use quil_types::proto::global::AppShardFrame;
use quil_types::store::ClockStore;
use tonic::Status;

struct LocalRoute {
    core_id: u32,
    generation: u64,
    clock_store: Arc<dyn ClockStore>,
}

/// Resolves public app-shard reads to the worker that currently owns a filter.
/// The master store is deliberately absent on prover nodes; archives may retain
/// a store fallback because their local store is authoritative, not a mirror.
pub(crate) struct AppShardFrameRouter {
    local: parking_lot::RwLock<HashMap<Vec<u8>, LocalRoute>>,
    remote: OnceLock<Arc<quil_engine::remote_worker::RemoteWorkerManager>>,
    archive_store: Option<Arc<dyn ClockStore>>,
}

impl AppShardFrameRouter {
    pub(crate) fn new(archive_store: Option<Arc<dyn ClockStore>>) -> Self {
        Self {
            local: parking_lot::RwLock::new(HashMap::new()),
            remote: OnceLock::new(),
            archive_store,
        }
    }

    pub(crate) fn set_remote(&self, manager: Arc<quil_engine::remote_worker::RemoteWorkerManager>) {
        let _ = self.remote.set(manager);
    }

    pub(crate) fn register_local(
        &self,
        core_id: u32,
        generation: u64,
        filter: Vec<u8>,
        clock_store: Arc<dyn ClockStore>,
    ) {
        self.local.write().insert(
            filter,
            LocalRoute {
                core_id,
                generation,
                clock_store,
            },
        );
    }

    /// Remove a route only if the deactivation belongs to the same engine
    /// generation. A cancelled engine can report deactivation after its
    /// replacement has already activated.
    pub(crate) fn unregister_local(&self, core_id: u32, generation: u64, filter: &[u8]) -> bool {
        let mut routes = self.local.write();
        if routes
            .get(filter)
            .is_some_and(|route| route.core_id == core_id && route.generation == generation)
        {
            routes.remove(filter);
            true
        } else {
            false
        }
    }

    async fn read_store(
        clock_store: Arc<dyn ClockStore>,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<AppShardFrame>, Status> {
        tokio::task::spawn_blocking(move || {
            let result = if frame_number == 0 {
                clock_store.get_latest_shard_clock_frame(&filter)
            } else {
                clock_store.get_shard_clock_frame(&filter, frame_number, false)
            };
            match result {
                Ok(frame) => Ok(Some(frame)),
                Err(QuilError::NotFound(_)) => Ok(None),
                Err(e) => Err(Status::internal(format!(
                    "worker app-shard frame read failed: {e}"
                ))),
            }
        })
        .await
        .map_err(|e| Status::internal(format!("worker frame read task failed: {e}")))?
    }
}

#[tonic::async_trait]
impl AppShardFrameProvider for AppShardFrameRouter {
    async fn get_app_shard_frame(
        &self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<AppShardFrame>, Status> {
        let local_store = self
            .local
            .read()
            .get(&filter)
            .map(|route| route.clock_store.clone());
        if let Some(clock_store) = local_store {
            match Self::read_store(clock_store, filter.clone(), frame_number).await {
                Ok(Some(frame)) => return Ok(Some(frame)),
                Ok(None) => {}
                Err(status) => return Err(status),
            }
        }

        if let Some(remote) = self.remote.get() {
            match remote.get_app_shard_frame(&filter, frame_number).await {
                Ok(Some(frame)) => return Ok(Some(frame)),
                Ok(None) => {}
                Err(status) => return Err(status),
            }
        }

        if let Some(clock_store) = self.archive_store.clone() {
            return Self::read_store(clock_store, filter, frame_number).await;
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_store::testing::InMemoryClockStore;

    fn store_with_frame(filter: &[u8], frame_number: u64) -> Arc<InMemoryClockStore> {
        let store = Arc::new(InMemoryClockStore::new());
        let mut header = quil_types::proto::global::FrameHeader::default();
        header.address = filter.to_vec();
        header.frame_number = frame_number;
        let frame = AppShardFrame {
            header: Some(header),
            requests: Vec::new(),
            ..Default::default()
        };
        let selector = vec![frame_number as u8; 32];
        let txn = store.new_transaction(false).unwrap();
        store
            .stage_shard_clock_frame(&selector, &frame, txn.as_ref())
            .unwrap();
        store
            .commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), false)
            .unwrap();
        txn.commit().unwrap();
        store
    }

    #[tokio::test]
    async fn serves_latest_and_numbered_directly_from_worker_store() {
        let filter = b"worker-shard";
        let worker_store = store_with_frame(filter, 17);
        let master_store = Arc::new(InMemoryClockStore::new());
        let router = AppShardFrameRouter::new(None);
        router.register_local(1, 1, filter.to_vec(), worker_store);

        let latest = router
            .get_app_shard_frame(filter.to_vec(), 0)
            .await
            .unwrap()
            .unwrap();
        let numbered = router
            .get_app_shard_frame(filter.to_vec(), 17)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(latest.header.unwrap().frame_number, 17);
        assert_eq!(numbered.header.unwrap().frame_number, 17);
        assert!(matches!(
            master_store.get_latest_shard_clock_frame(filter),
            Err(QuilError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn stale_deactivation_cannot_remove_replacement_route() {
        let filter = b"worker-shard";
        let router = AppShardFrameRouter::new(None);
        router.register_local(1, 1, filter.to_vec(), store_with_frame(filter, 3));
        router.register_local(1, 2, filter.to_vec(), store_with_frame(filter, 4));

        assert!(!router.unregister_local(1, 1, filter));
        let frame = router
            .get_app_shard_frame(filter.to_vec(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.header.unwrap().frame_number, 4);

        assert!(router.unregister_local(1, 2, filter));
        assert!(router
            .get_app_shard_frame(filter.to_vec(), 0)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn archive_store_is_an_explicit_fallback() {
        let filter = b"archived-shard";
        let archive_store = store_with_frame(filter, 8);
        let router = AppShardFrameRouter::new(Some(archive_store));

        let frame = router
            .get_app_shard_frame(filter.to_vec(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.header.unwrap().frame_number, 8);
    }

    #[tokio::test]
    async fn archive_store_fills_an_active_worker_history_miss() {
        let filter = b"archived-shard";
        let archive_store = store_with_frame(filter, 8);
        let router = AppShardFrameRouter::new(Some(archive_store));
        router.register_local(1, 1, filter.to_vec(), Arc::new(InMemoryClockStore::new()));

        let frame = router
            .get_app_shard_frame(filter.to_vec(), 8)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.header.unwrap().frame_number, 8);
    }

    #[tokio::test]
    async fn archive_store_fills_an_unassigned_remote_miss() {
        let filter = b"archived-shard";
        let archive_store = store_with_frame(filter, 8);
        let router = AppShardFrameRouter::new(Some(archive_store));
        router.set_remote(Arc::new(
            quil_engine::remote_worker::RemoteWorkerManager::new(
                Vec::new(),
                "http://master:8340".into(),
                None,
            ),
        ));

        let frame = router
            .get_app_shard_frame(filter.to_vec(), 8)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.header.unwrap().frame_number, 8);
    }
}
