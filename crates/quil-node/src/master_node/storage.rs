use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

pub(crate) struct StorageHandles {
    #[allow(dead_code)]
    pub db_path: PathBuf,
    pub db_arc: Arc<quil_store::RocksDb>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub token_store: Arc<quil_store::RocksTokenStore>,
    pub key_store: Arc<quil_store::RocksKeyStore>,
    pub shards_store: Arc<dyn quil_types::store::ShardsStore>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
}

pub(crate) fn init(
    config: &quil_config::Config,
    archive_mode: bool,
) -> anyhow::Result<StorageHandles> {
    // ---------------------------------------------------------------
    // 1. Open database
    // ---------------------------------------------------------------
    let db_path = if config.db.path.is_empty() {
        PathBuf::from(".config/store")
    } else {
        PathBuf::from(&config.db.path)
    };

    // Detect the on-disk store format BEFORE we let RocksDB touch the
    // path. The Go node wrote Pebble; the Rust node writes RocksDB.
    // Opening a Pebble dir with RocksDB produces a confusing
    // "Corruption" error far from the real cause.
    //
    // Policy:
    //   - non-archive nodes: wipe & let RocksDB recreate. State is
    //     recoverable from peers via hypersync.
    //   - archive nodes: refuse to wipe — that store is the canonical
    //     copy and must be migrated, not deleted. Tell the user to
    //     run the conversion tool.
    match quil_store::detect_store_format(&db_path) {
        quil_store::StoreFormat::Pebble => {
            if archive_mode {
                return Err(anyhow::anyhow!(
                    "detected Go-Pebble store at {} but this node is in archive mode — \
                     refusing to wipe. Run the Pebble→RocksDB conversion tool first, \
                     or move the directory aside and re-hypersync from another archive.",
                    db_path.display()
                ));
            }
            warn!(
                path = %db_path.display(),
                "detected legacy Go-Pebble store; wiping for fresh RocksDB init \
                 (non-archive node — state will be re-synced from peers)"
            );
            std::fs::remove_dir_all(&db_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to wipe legacy Pebble store at {}: {}",
                    db_path.display(),
                    e
                )
            })?;
        }
        quil_store::StoreFormat::Unknown => {
            return Err(anyhow::anyhow!(
                "store path {} exists but is neither RocksDB nor Pebble — \
                 refusing to touch it. Move it aside if you want a clean start.",
                db_path.display()
            ));
        }
        quil_store::StoreFormat::RocksDb | quil_store::StoreFormat::Empty => { /* OK */ }
    }

    std::fs::create_dir_all(&db_path)?;
    let db = quil_store::RocksDb::open(&db_path)?;
    let db_arc = Arc::new(db);
    info!(path = %db_path.display(), "opened database");

    // ---------------------------------------------------------------
    // 2. Create stores
    // ---------------------------------------------------------------
    let clock_store = Arc::new(quil_store::RocksClockStore::new(db_arc.inner()));
    let token_store = Arc::new(quil_store::RocksTokenStore::new(db_arc.inner()));
    let key_store: Arc<quil_store::RocksKeyStore> =
        Arc::new(quil_store::RocksKeyStore::new(db_arc.inner()));
    // Trait-object handle so the shard_info refresh task (lower in
    // this fn) can hold a `&dyn ShardsStore` for enumerating
    // shard_keys against archives. A second `Arc<dyn ShardsStore>`
    // is built later for the gRPC server's `GetAppShards` handler;
    // both share the same underlying RocksDB column family.
    let shards_store: Arc<dyn quil_types::store::ShardsStore> =
        Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()));
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db_arc.inner()));

    // Check latest stored frame
    match clock_store.get_latest_global_frame() {
        Ok(frame) => {
            let frame_num = frame.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
            info!(frame = frame_num, "resuming from stored state");
        }
        Err(_) => {
            info!("no stored frames — will sync from network");
        }
    }

    Ok(StorageHandles {
        db_path,
        db_arc,
        clock_store,
        token_store,
        key_store,
        shards_store,
        hg_store,
    })
}
