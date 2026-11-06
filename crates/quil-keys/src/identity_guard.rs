//! Whether a start may give the node a new identity.
//!
//! A node's prover key sets its prover address and network peer id; its
//! Ed448 peer key is the root of its seniority. Creating either one by
//! accident, for example after an old `keys.yml` was put back, leaves the
//! node's seats and seniority on the old identity while it keeps running.
//!
//! Each start of the master therefore records the identity it ran as in
//! `<config_dir>/node-identity.yml`. Creating or replacing a key is refused
//! when the record, the keystore or the store shows that the node already
//! had an identity. A first start and the migration of a genuinely old
//! keystore show none of these and go ahead. A usable key that differs from
//! the record is only warned about: no key is created or lost, and pointing
//! `key.keyManagerFile.path` at the right keystore is how an operator
//! recovers. The way past a refusal is one explicit run of
//! `--generate-keys --allow-new-identity`, so no lasting setting can hide
//! the next accident.

use std::path::{Path, PathBuf};

use quil_types::error::{QuilError, Result};
use serde::{Deserialize, Serialize};

use crate::file_key_manager::ProverKeyChange;
use crate::keystore_path::holds_prover_key;
use crate::{FileKeyManager, KeyManager};

/// The file in the config directory naming the identity the node last ran as.
const IDENTITY_RECORD_FILE: &str = "node-identity.yml";

/// What the node's store shows about earlier runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreEvidence {
    /// The store holds data of an earlier run, so a keystore without a
    /// prover key was lost rather than never made.
    pub had_data: bool,
    /// A build with post-quantum prover keys ran on this store, so an
    /// outdated prover key was put back rather than left to migrate. A
    /// store of an older build has data but not this.
    pub ran_post_quantum: bool,
}

impl StoreEvidence {
    /// For a command that does not open the store: any store on disk counts
    /// as both kinds of evidence, since it cannot tell them apart.
    pub fn unopened(db_path: &Path) -> Self {
        let seen = db_path.join("CURRENT").exists();
        Self {
            had_data: seen,
            ran_post_quantum: seen,
        }
    }
}

/// The identity a node ran as. Public values only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityRecord {
    prover_address: String,
    peer_id: Option<String>,
}

enum RecordRead {
    Missing,
    Unreadable,
    Found(IdentityRecord),
}

fn record_path(config_dir: &Path) -> PathBuf {
    config_dir.join(IDENTITY_RECORD_FILE)
}

fn read_record(path: &Path) -> RecordRead {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RecordRead::Missing,
        Err(_) => return RecordRead::Unreadable,
    };
    match serde_yaml::from_str(&contents) {
        Ok(record) => RecordRead::Found(record),
        Err(_) => RecordRead::Unreadable,
    }
}

/// `…` and the last six characters of `id`, as logs name peers and provers.
fn tail(id: &str) -> String {
    format!("…{}", &id[id.len().saturating_sub(6)..])
}

/// The record's reason to believe this node already had an identity.
fn recorded_identity(config_dir: &Path) -> Option<String> {
    let path = record_path(config_dir);
    match read_record(&path) {
        RecordRead::Missing => None,
        RecordRead::Unreadable => Some(format!("{} names an earlier identity", path.display())),
        RecordRead::Found(record) => Some(format!(
            "this node last ran as prover {} ({})",
            tail(&record.prover_address),
            path.display()
        )),
    }
}

/// What to do about a refused key: the same for every refusal of a start.
fn recovery(config_dir: &Path) -> String {
    format!(
        "A new key would give this node a new identity, leaving its seats and seniority on the \
         old one. Put back the keystore holding the old prover key, or set \
         key.keyManagerFile.path in {} to it. If that key is gone or a new identity is intended, \
         run the node once with --config {} --generate-keys --allow-new-identity, start it, and \
         check `qclient node prover merge --dry-run`",
        config_dir.join("config.yml").display(),
        config_dir.display()
    )
}

/// Refuse what `ensure_standard_keys` would do to the prover key if the
/// node already had an identity. Migrating a genuinely old keystore and a
/// first start show no evidence and pass.
pub fn refuse_prover_key_change(
    km: &FileKeyManager,
    config_dir: &Path,
    store: StoreEvidence,
) -> Result<()> {
    let Some(change) = km.prover_key_change() else {
        return Ok(());
    };
    let store_reason = match change {
        ProverKeyChange::Create if store.had_data => {
            Some("the store already holds this node's data")
        }
        ProverKeyChange::Replace { .. } if store.ran_post_quantum => {
            Some("a post-quantum build already ran on the store")
        }
        _ => None,
    };
    let evidence = recorded_identity(config_dir)
        .or_else(|| {
            km.replaced_prover_key_entry()
                .map(|id| format!("this keystore was migrated before (it holds {id})"))
        })
        .or_else(|| store_reason.map(str::to_string));
    let Some(evidence) = evidence else {
        return Ok(());
    };
    let action = match change {
        ProverKeyChange::Create => {
            format!(
                "create a q-prover-key: {} holds none",
                km.keys_path().display()
            )
        }
        ProverKeyChange::Replace { old_type } => format!(
            "replace q-prover-key: {} holds one of type {old_type}, which this build cannot use",
            km.keys_path().display()
        ),
    };
    Err(QuilError::InvalidArgument(format!(
        "refusing to {action}, and {evidence}. {}",
        recovery(config_dir)
    )))
}

/// Refuse to create the Ed448 peer key, the root of seniority, if the node
/// already had an identity. A keystore holding a prover key is no evidence:
/// `--generate-keys` prepares one before a first start.
pub fn refuse_new_peer_key(config_dir: &Path, store: StoreEvidence) -> Result<()> {
    let evidence = recorded_identity(config_dir).or_else(|| {
        store
            .had_data
            .then(|| "the store already holds this node's data".to_string())
    });
    let Some(evidence) = evidence else {
        return Ok(());
    };
    Err(QuilError::InvalidArgument(format!(
        "refusing to create a peer key: p2p.peerPrivKey in {} is empty, and {evidence}. Restore \
         that setting from a backup of config.yml. If the key is gone or a new identity is \
         intended, run the node once with --config {} --generate-keys --allow-new-identity, \
         start it, and check `qclient node prover merge --dry-run`",
        config_dir.join("config.yml").display(),
        config_dir.display()
    )))
}

/// Refuse to generate a fresh `config.yml` in a directory that shows the
/// node already had one: the new config would carry a new peer key and a
/// key that cannot decrypt the keystore.
pub fn refuse_recreated_config(config_dir: &Path) -> Result<()> {
    if config_dir.join("config.yml").exists() {
        return Ok(());
    }
    let keystore = config_dir.join("keys.yml");
    let store = config_dir.join("store");
    let evidence = if holds_prover_key(&keystore)? {
        keystore
    } else if record_path(config_dir).exists() {
        record_path(config_dir)
    } else if store.join("CURRENT").exists() {
        store
    } else {
        return Ok(());
    };
    Err(QuilError::InvalidArgument(format!(
        "refusing to create a new config.yml in {}: {} shows this node already ran there, and a \
         new config would carry a new peer key and could not decrypt its keystore. Restore \
         config.yml from a backup, or pass --config with the node's config directory. To start \
         over with a new identity, move this directory away",
        config_dir.display(),
        evidence.display()
    )))
}

/// Note the identity this start runs as: warn if it differs from the last
/// one, so a swapped keystore or config does not go unnoticed, and save it
/// for the refusals above. A failed save only costs that protection, so it
/// warns and the node runs.
pub fn record_identity(km: &FileKeyManager, config_dir: &Path) {
    let Some(prover_address) = km.prover_address_hex() else {
        return;
    };
    let current = IdentityRecord {
        prover_address,
        peer_id: km.get_peer_id().ok().map(hex::encode),
    };
    let path = record_path(config_dir);
    match read_record(&path) {
        RecordRead::Found(last) if last == current => return,
        RecordRead::Found(last) => tracing::warn!(
            previous_prover = %last.prover_address,
            prover = %current.prover_address,
            previous_peer = last.peer_id.as_deref().unwrap_or("none"),
            peer = current.peer_id.as_deref().unwrap_or("none"),
            path = %km.keys_path().display(),
            "this node's identity changed since its last start; its seats and seniority stay on \
             the previous identity. If this is not intended, stop the node and set \
             key.keyManagerFile.path to the keystore of the previous prover. Check with \
             `qclient node prover merge --dry-run`"
        ),
        RecordRead::Unreadable => tracing::warn!(
            path = %path.display(),
            "could not read the record of this node's identity; replacing it with the current \
             identity"
        ),
        RecordRead::Missing => tracing::info!(
            prover = %current.prover_address,
            path = %path.display(),
            "recorded this node's identity"
        ),
    }
    if let Err(e) = write_record(&path, &current) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not save the record of this node's identity: the node runs, but will not \
             notice a keystore put back later. Check that this directory is writable"
        );
    }
}

fn write_record(path: &Path, record: &IdentityRecord) -> std::io::Result<()> {
    let contents = serde_yaml::to_string(record).map_err(std::io::Error::other)?;
    quil_config::write_private_file(path, contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_key_manager::tests::warns_of;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn config_dir(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "quil-identity-guard-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(dir: &Path) -> FileKeyManager {
        FileKeyManager::new(
            dir.join("keys.yml"),
            "",
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap()
    }

    /// A keystore as an old build left it: a BLS prover key, type 2.
    fn old_keystore(dir: &Path) -> FileKeyManager {
        let km = open(dir);
        km.create_bls_key("q-prover-key").unwrap();
        km
    }

    /// A node that ran once on the current keystore.
    fn node_that_ran(dir: &Path) -> FileKeyManager {
        let km = open(dir);
        km.ensure_standard_keys().unwrap();
        record_identity(&km, dir);
        km
    }

    fn keystore(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("keys.yml")).unwrap()
    }

    const NO_STORE: StoreEvidence = StoreEvidence {
        had_data: false,
        ran_post_quantum: false,
    };
    const OLD_STORE: StoreEvidence = StoreEvidence {
        had_data: true,
        ran_post_quantum: false,
    };
    const POST_QUANTUM_STORE: StoreEvidence = StoreEvidence {
        had_data: true,
        ran_post_quantum: true,
    };

    #[test]
    fn a_first_start_may_create_every_key() {
        let dir = config_dir("first_start");
        let km = open(&dir);
        refuse_new_peer_key(&dir, NO_STORE).unwrap();
        refuse_prover_key_change(&km, &dir, NO_STORE).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_genuinely_old_keystore_migrates_beside_a_store_of_its_own_era() {
        let dir = config_dir("honest_migration");
        let km = old_keystore(&dir);
        refuse_prover_key_change(&km, &dir, OLD_STORE)
            .expect("an old keystore on an old store is the migration itself");
        km.ensure_standard_keys().unwrap();
        assert_eq!(km.prover_key_change(), None, "the migration is done");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_keystore_put_back_after_a_recorded_start_is_refused_and_kept() {
        let dir = config_dir("put_back");
        let ran = node_that_ran(&dir);
        let address = ran.prover_address_hex().unwrap();
        let _ = std::fs::remove_file(dir.join("keys.yml"));
        let km = old_keystore(&dir);
        let before = keystore(&dir);

        let err = refuse_prover_key_change(&km, &dir, NO_STORE)
            .expect_err("the record shows this node already had a prover")
            .to_string();

        assert!(err.contains("refusing to replace q-prover-key"), "{err}");
        assert!(err.contains(&tail(&address)), "names the prover: {err}");
        assert!(
            err.contains("--allow-new-identity"),
            "states recovery: {err}"
        );
        assert!(err.contains("key.keyManagerFile.path"), "{err}");
        assert_eq!(keystore(&dir), before, "the refused keystore is untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_key_on_a_store_that_ran_post_quantum_is_refused() {
        let dir = config_dir("post_quantum_store");
        let km = old_keystore(&dir);
        let err = refuse_prover_key_change(&km, &dir, POST_QUANTUM_STORE)
            .expect_err("that store ran on a Falcon identity")
            .to_string();
        assert!(err.contains("post-quantum build already ran"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_key_in_a_keystore_migrated_before_is_refused() {
        // The keys.yml held both an outdated q-prover-key and an entry an
        // earlier replacement preserved.
        let dir = config_dir("migrated_before");
        let km = old_keystore(&dir);
        km.create_bls_key("q-prover-key-legacy-bls48581").unwrap();
        let err = refuse_prover_key_change(&km, &dir, NO_STORE)
            .expect_err("this keystore was migrated before")
            .to_string();
        assert!(err.contains("q-prover-key-legacy-bls48581"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_keystore_lost_beside_a_store_with_data_is_refused() {
        let dir = config_dir("lost_beside_store");
        let km = open(&dir);
        let err = refuse_prover_key_change(&km, &dir, OLD_STORE)
            .expect_err("a store with data shows the node had an identity")
            .to_string();
        assert!(err.contains("refusing to create a q-prover-key"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_keystore_lost_after_a_recorded_start_is_refused() {
        let dir = config_dir("lost_after_record");
        node_that_ran(&dir);
        std::fs::remove_file(dir.join("keys.yml")).unwrap();
        let err = refuse_prover_key_change(&open(&dir), &dir, NO_STORE)
            .expect_err("the record shows this node already had a prover")
            .to_string();
        assert!(err.contains("refusing to create a q-prover-key"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_still_refuses_a_new_key_but_not_a_kept_one() {
        let dir = config_dir("corrupt_record");
        let km = node_that_ran(&dir);
        std::fs::write(record_path(&dir), "{ not yaml").unwrap();

        refuse_prover_key_change(&km, &dir, NO_STORE)
            .expect("a healthy keystore must start whatever the record holds");
        record_identity(&km, &dir);
        assert!(matches!(
            read_record(&record_path(&dir)),
            RecordRead::Found(_)
        ));

        std::fs::write(record_path(&dir), "{ not yaml").unwrap();
        std::fs::remove_file(dir.join("keys.yml")).unwrap();
        refuse_prover_key_change(&open(&dir), &dir, NO_STORE)
            .expect_err("an unreadable record still shows an earlier identity");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_peer_key_is_refused_where_the_node_already_ran() {
        let dir = config_dir("peer_key");
        // `--generate-keys` before a first start leaves a prover key alone.
        open(&dir).ensure_standard_keys().unwrap();
        refuse_new_peer_key(&dir, NO_STORE).expect("a prepared keystore is no earlier run");

        let err = refuse_new_peer_key(&dir, OLD_STORE)
            .expect_err("a store with data shows the node had a peer key")
            .to_string();
        assert!(err.contains("p2p.peerPrivKey"), "{err}");
        assert!(err.contains("--allow-new-identity"), "{err}");

        record_identity(&open(&dir), &dir);
        refuse_new_peer_key(&dir, NO_STORE).expect_err("the record shows the same");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_config_is_refused_beside_what_a_node_left() {
        let empty = config_dir("config_empty");
        refuse_recreated_config(&empty).expect("an empty directory is a fresh install");
        std::fs::write(empty.join("keys.yml"), "null:\n").unwrap();
        refuse_recreated_config(&empty).expect("a placeholder keystore holds no identity");
        let _ = std::fs::remove_dir_all(&empty);

        let keystore_left = config_dir("config_keystore");
        open(&keystore_left).ensure_standard_keys().unwrap();
        let err = refuse_recreated_config(&keystore_left)
            .expect_err("the keystore could no longer be decrypted")
            .to_string();
        assert!(err.contains("refusing to create a new config.yml"), "{err}");
        assert!(err.contains("Restore"), "states recovery: {err}");
        let _ = std::fs::remove_dir_all(&keystore_left);

        let store_left = config_dir("config_store");
        std::fs::create_dir_all(store_left.join("store")).unwrap();
        std::fs::write(store_left.join("store/CURRENT"), "MANIFEST-1\n").unwrap();
        refuse_recreated_config(&store_left).expect_err("a store shows an earlier run");
        let _ = std::fs::remove_dir_all(&store_left);

        let has_config = config_dir("config_present");
        open(&has_config).ensure_standard_keys().unwrap();
        std::fs::write(has_config.join("config.yml"), "{}\n").unwrap();
        refuse_recreated_config(&has_config).expect("nothing is created");
        let _ = std::fs::remove_dir_all(&has_config);
    }

    #[test]
    fn a_usable_keystore_that_differs_from_the_record_starts_and_warns() {
        // The recovery path: the record names the wrong prover, and the
        // operator points the node back at the keystore of the right one.
        let dir = config_dir("recovery_other_keystore");
        let wrong = node_that_ran(&dir);
        let wrong_address = wrong.prover_address_hex().unwrap();
        let right_dir = config_dir("recovery_right_keystore");
        let right = open(&right_dir);
        right.ensure_standard_keys().unwrap();
        let right_address = right.prover_address_hex().unwrap();

        refuse_prover_key_change(&right, &dir, POST_QUANTUM_STORE)
            .expect("a usable key is not created or replaced, so it is never refused");
        let warns = warns_of(|| record_identity(&right, &dir));

        assert!(
            warns.iter().any(|w| w.contains("identity changed")
                && w.contains(&wrong_address)
                && w.contains(&right_address)
                && w.contains("merge --dry-run")),
            "the change names both provers: {warns:?}"
        );
        match read_record(&record_path(&dir)) {
            RecordRead::Found(record) => assert_eq!(record.prover_address, right_address),
            _ => panic!("the record must name the running prover"),
        }
        let quiet = warns_of(|| record_identity(&right, &dir));
        assert!(
            quiet.is_empty(),
            "an unchanged identity is silent: {quiet:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&right_dir);
    }

    #[test]
    fn a_failed_record_save_warns_and_never_stops_the_node() {
        let dir = config_dir("record_save");
        let km = node_that_ran(&dir);
        std::fs::remove_file(record_path(&dir)).unwrap();
        // A directory in the record's place makes the save fail.
        std::fs::create_dir(record_path(&dir)).unwrap();
        let warns = warns_of(|| record_identity(&km, &dir));
        assert!(
            warns
                .iter()
                .any(|w| w.contains("could not save the record")),
            "{warns:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
