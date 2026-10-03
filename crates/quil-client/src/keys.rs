//! Key-manager construction for the client.
//!
//! Mirrors the node's `master_node/keys.rs` setup: a `FileKeyManager`
//! backed by `keys.yml`, with `q-peer-key` sourced from
//! `config.p2p.peer_priv_key`. Uses `FalconKeyConstructor` as the
//! post-quantum drop-in for the former BLS constructor, so any signing
//! key the client creates or loads matches the node's verify path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use quil_config::Config;
use quil_keys::FileKeyManager;

/// Build a `FileKeyManager` for the given node config + directory.
///
/// Does NOT auto-create the standard keys — the client reads existing
/// keys and creates specific ones on demand (e.g. `q-view-key` /
/// `q-spend-key` for token balances, or via `qclient key create`).
pub fn build_key_manager(config: &Config, config_dir: &Path) -> anyhow::Result<Arc<FileKeyManager>> {
    let keys_path: PathBuf = if config.key.key_store_file.path.is_empty() {
        config_dir.join("keys.yml")
    } else {
        PathBuf::from(&config.key.key_store_file.path)
    };

    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };

    let fkm = FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;

    // `q-peer-key` lives in config, not keys.yml — wire it through so
    // outer-auth signing (Send RPC) and peer-id derivation work.
    fkm.set_peer_priv_key_hex(&config.p2p.peer_priv_key);

    Ok(Arc::new(fkm))
}
