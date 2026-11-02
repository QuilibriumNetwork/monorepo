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

/// What the opened store shows about earlier runs of this node.
pub(crate) fn store_evidence(
    hg_store: &quil_store::RocksHypergraphStore,
    clock_store: &dyn quil_types::store::ClockStore,
) -> quil_keys::StoreEvidence {
    quil_keys::StoreEvidence {
        had_data: clock_store.get_latest_global_clock_frame().is_ok(),
        ran_post_quantum: crate::unified_consolidation::boot_reset_applied(hg_store),
    }
}

pub(crate) fn init(
    config: &quil_config::Config,
    config_dir: &std::path::Path,
    store: quil_keys::StoreEvidence,
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

    // Auto-create all standard keys if missing, unless that would change the
    // identity of a node that already had one.
    quil_keys::refuse_prover_key_change(&file_key_manager, config_dir, store)?;
    file_key_manager.ensure_standard_keys()?;
    quil_keys::record_identity(&file_key_manager, config_dir);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The node's startup, as nothing in its store shows an earlier run.
    fn start(config: &quil_config::Config, dir: &Path) -> anyhow::Result<KeyHandles> {
        init(config, dir, quil_keys::StoreEvidence::default())
    }

    /// A config as a node's first start leaves it.
    fn node_config(dir: &Path) -> quil_config::Config {
        let mut config = quil_config::load_config(dir).unwrap();
        config.p2p.peer_priv_key = quil_p2p::ed448_identity::Ed448Identity::generate()
            .unwrap()
            .to_config_hex();
        quil_config::save_config(dir, &config).unwrap();
        config
    }

    /// Put back a keystore an old build wrote: its prover key is BLS, type 2.
    fn put_back_old_keystore(config: &quil_config::Config, dir: &Path) {
        let path = dir.join("keys.yml");
        let _ = std::fs::remove_file(&path);
        quil_keys::FileKeyManager::new(
            path,
            &config.key.key_store_file.encryption_key,
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap()
        .create_bls_key("q-prover-key")
        .unwrap();
    }

    #[test]
    fn an_old_keystore_put_back_keeps_the_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config = node_config(dir.path());
        let ran = start(&config, dir.path()).unwrap();
        put_back_old_keystore(&config, dir.path());
        let before = std::fs::read(dir.path().join("keys.yml")).unwrap();

        match start(&config, dir.path()) {
            Ok(next) => panic!(
                "the outdated key was replaced at startup: prover {} became the new prover {}",
                hex::encode(ran.prover_address),
                hex::encode(next.prover_address)
            ),
            Err(e) => assert!(e.to_string().contains("refusing to replace"), "{e}"),
        }
        assert_eq!(std::fs::read(dir.path().join("keys.yml")).unwrap(), before);
    }

    #[test]
    fn a_lost_keystore_keeps_the_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config = node_config(dir.path());
        let ran = start(&config, dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("keys.yml")).unwrap();

        match start(&config, dir.path()) {
            Ok(next) => panic!(
                "a new prover key was created at startup: prover {} became the new prover {}",
                hex::encode(ran.prover_address),
                hex::encode(next.prover_address)
            ),
            Err(e) => assert!(e.to_string().contains("refusing to create"), "{e}"),
        }
        assert!(!dir.path().join("keys.yml").exists());
    }

    #[test]
    fn a_refused_node_recovers_by_pointing_at_its_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = node_config(dir.path());
        let ran = start(&config, dir.path()).unwrap();
        let saved = dir.path().join("saved-keys.yml");
        std::fs::copy(dir.path().join("keys.yml"), &saved).unwrap();
        put_back_old_keystore(&config, dir.path());
        assert!(start(&config, dir.path()).is_err());

        config.key.key_store_file.path = saved.display().to_string();

        let recovered = start(&config, dir.path()).unwrap();
        assert_eq!(recovered.prover_address, ran.prover_address);
    }

    #[test]
    fn a_keystore_migrates_when_nothing_shows_an_earlier_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config = node_config(dir.path());
        put_back_old_keystore(&config, dir.path());
        let store = quil_keys::StoreEvidence {
            had_data: true,
            ran_post_quantum: false,
        };

        let migrated = init(&config, dir.path(), store).unwrap();

        // The node starts as a Falcon prover and comes back as the same one.
        let again = init(&config, dir.path(), store).unwrap();
        assert_eq!(again.prover_address, migrated.prover_address);
    }

    #[test]
    fn the_store_shows_earlier_runs() {
        use quil_types::store::ClockStore as _;
        let rocks = quil_store::RocksDb::open_in_memory().unwrap();
        let hg = quil_store::RocksHypergraphStore::new(rocks.inner());
        let clock = quil_store::RocksClockStore::new(rocks.inner());
        assert_eq!(
            store_evidence(&hg, &clock),
            quil_keys::StoreEvidence::default(),
            "a fresh store shows no earlier run"
        );

        let txn = clock.new_transaction(false).unwrap();
        clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: 1,
                        ..Default::default()
                    }),
                    requests: Vec::new(),
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            store_evidence(&hg, &clock),
            quil_keys::StoreEvidence {
                had_data: true,
                ran_post_quantum: false,
            },
            "a synced store of an older build"
        );

        hg.raw_db()
            .put(quil_engine::frame_maintenance::BOOT_RESET_MARKER_KEY, [1u8])
            .unwrap();
        assert!(store_evidence(&hg, &clock).ran_post_quantum);
    }
}
