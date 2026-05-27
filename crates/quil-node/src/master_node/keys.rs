use std::path::PathBuf;
use std::sync::Arc;

use tracing::info;

// Import KeyManager trait for get_public_key
use quil_keys::KeyManager as _;

pub(crate) struct KeyHandles {
    pub file_key_manager: Arc<quil_keys::FileKeyManager>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
}

pub(crate) fn init(
    config: &quil_config::Config,
    config_dir: &std::path::Path,
) -> anyhow::Result<KeyHandles> {
    // ---------------------------------------------------------------
    // 2b. Key management — load or create BLS prover key from keys.yml
    // ---------------------------------------------------------------
    let keys_path = if config.key.key_store_file.path.is_empty() {
        config_dir.join("keys.yml")
    } else {
        PathBuf::from(&config.key.key_store_file.path)
    };

    let bls_ctor = quil_crypto::Bls48581KeyConstructor;
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };

    let file_key_manager = Arc::new(quil_keys::FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(bls_ctor),
    )?);

    // `q-peer-key` lives in `config.p2p.peer_priv_key`, not `keys.yml` —
    // wire it through so keystore lookups (Send RPC outer auth, peer ID
    // derivation) work on Go-style configs.
    file_key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);

    // Auto-create all standard keys if missing
    file_key_manager.ensure_standard_keys()?;
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Bls48581G1)?;

    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)?;
    // Publish the local prover address to the execution layer's static
    // so `apply_reward` can surface incoming credits to the operator.
    let _ = quil_execution::global_intrinsic::prover_shard_update::LOCAL_PROVER_ADDRESS
        .set(prover_address.to_vec());
    info!(
        prover_address = hex::encode(&prover_address),
        bls_pubkey_len = bls_pubkey.len(),
        "BLS prover identity ready"
    );

    Ok(KeyHandles {
        file_key_manager,
        bls_pubkey,
        prover_address,
    })
}
