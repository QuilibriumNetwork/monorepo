use std::sync::Arc;

use tracing::{info, warn};

// Import KeyManager trait for get_public_key
use quil_keys::KeyManager as _;

pub(crate) struct KeyHandles {
    pub file_key_manager: Arc<quil_keys::FileKeyManager>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
}

/// Restrict the files holding this node's private keys to their owner
/// when group or others can access them: the config (the keystore's
/// encryption key and the Ed448 peer key), its `config.yml.bak*` backups,
/// the keystore, and the configs of `engine.multisigProverEnrollmentPaths`.
/// Earlier releases wrote them with the umask's mode, usually 0644.
pub(crate) fn restrict_key_files(config: &quil_config::Config, config_dir: &std::path::Path) {
    let mut files = vec![config_dir.join("config.yml")];
    if let Ok(entries) = std::fs::read_dir(config_dir) {
        let mut backups: Vec<_> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("config.yml.bak"))
            })
            .collect();
        backups.sort();
        files.extend(backups);
    }
    let keystore = quil_keys::resolve_keystore_path(&config.key.key_store_file, config_dir);
    files.extend(keystore.ok());
    files.extend(
        config
            .engine
            .multisig_prover_enrollment_paths
            .iter()
            .map(|dir| std::path::Path::new(dir).join("config.yml")),
    );
    for path in files {
        match quil_config::restrict_private_file(&path) {
            Ok(None) => {}
            Ok(Some(mode)) => warn!(
                path = %path.display(),
                old_mode = %format!("{mode:04o}"),
                "a file holding this node's private keys was readable by other accounts; \
                 restricted it to its owner (mode 0600). If other accounts or backups could \
                 read it, consider its keys exposed"
            ),
            Err(e) => warn!(
                path = %path.display(),
                error = %e,
                "could not check or restrict the access of a file holding this node's \
                 private keys; make sure only its owner can read it (chmod 600)"
            ),
        }
    }
}

pub(crate) fn init(
    config: &quil_config::Config,
    config_dir: &std::path::Path,
) -> anyhow::Result<KeyHandles> {
    // ---------------------------------------------------------------
    // 2b. Key management — load or create BLS prover key from keys.yml
    // ---------------------------------------------------------------
    // Refuses a missing keystore that must not be recreated, so a wrong
    // path cannot silently give the node a new prover identity.
    let keys_path = quil_keys::resolve_keystore_path(&config.key.key_store_file, config_dir)?;

    let bls_ctor = quil_crypto::FalconKeyConstructor;
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
    let bls_pubkey = file_key_manager.get_public_key(quil_types::crypto::KeyType::Falcon512)?;

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
