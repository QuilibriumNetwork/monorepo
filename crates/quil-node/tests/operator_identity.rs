//! An operator must not change a node's identity by accident: the commands
//! that make keys, run as an operator runs them.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A node directory; its config directory is `.config`, as in the Go layout.
struct NodeDir(tempfile::TempDir);

impl NodeDir {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }

    fn config_dir(&self) -> PathBuf {
        self.0.path().join(".config")
    }

    fn keystore(&self) -> PathBuf {
        self.config_dir().join("keys.yml")
    }

    fn node(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_quil-node"))
            .current_dir(self.0.path())
            .args(["--config", ".config"])
            .args(args)
            .output()
            .unwrap()
    }

    /// Start the node as a service does. A refusal ends it within moments; a
    /// node that goes on to run is stopped and fails the test. It runs on a
    /// test network, so that such a node never joins mainnet. A test build
    /// has no release signatures, whose check comes first in a start.
    fn start_expecting_refusal(&self) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_quil-node"))
            .current_dir(self.0.path())
            .args(["--config", ".config", "--network", "1"])
            .arg("--signature-check=false")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("the node started instead of refusing: {}", stderr(&output));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        child.wait_with_output().unwrap()
    }

    /// Run `args` and expect success.
    fn ok(&self, args: &[&str]) -> Output {
        let output = self.node(args);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        output
    }

    /// Leave what an earlier run of the node leaves in its store directory.
    fn add_store(&self) {
        let store = self.config_dir().join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("CURRENT"), "MANIFEST-000001\n").unwrap();
    }

    fn config(&self) -> quil_config::Config {
        quil_config::load_config(&self.config_dir()).unwrap()
    }

    /// Put back a keystore an old build wrote: its prover key is BLS, type 2.
    fn put_back_old_keystore(&self) -> Vec<u8> {
        let config = self.config();
        let _ = std::fs::remove_file(self.keystore());
        quil_keys::FileKeyManager::new(
            self.keystore(),
            &config.key.key_store_file.encryption_key,
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap()
        .create_bls_key("q-prover-key")
        .unwrap();
        std::fs::read(self.keystore()).unwrap()
    }

    fn prover_key_type(&self) -> u8 {
        let config = self.config();
        quil_keys::FileKeyManager::new(
            self.keystore(),
            &config.key.key_store_file.encryption_key,
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap()
        .list_keys()
        .into_iter()
        .find(|key| key.id == "q-prover-key")
        .unwrap()
        .key_type
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_fresh_install_creates_its_identity() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    assert_eq!(node.prover_key_type(), 8);

    let first = node.ok(&["--print-identity"]);
    let second = node.ok(&["--print-identity"]);
    assert_eq!(first.stdout, second.stdout, "the identity is stable");
}

#[test]
fn an_old_keystore_without_a_store_migrates() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    node.put_back_old_keystore();

    node.ok(&["--generate-keys"]);

    assert_eq!(node.prover_key_type(), 8);
    let saved = std::fs::read_to_string(node.keystore()).unwrap();
    assert!(saved.contains("q-prover-key-legacy-bls48581"), "{saved}");
}

#[test]
fn an_old_keystore_put_back_beside_a_store_is_not_replaced() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    node.add_store();
    let before = node.put_back_old_keystore();

    let output = node.node(&["--generate-keys"]);

    assert_eq!(
        std::fs::read(node.keystore()).unwrap(),
        before,
        "the outdated prover key was replaced: the node has a new prover and peer id"
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to replace q-prover-key"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_keystore_lost_beside_a_store_gets_no_new_prover() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    node.add_store();
    std::fs::remove_file(node.keystore()).unwrap();

    let output = node.node(&["--generate-keys"]);

    assert!(
        !node.keystore().exists(),
        "a new prover key was created beside the store of this node"
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to create a q-prover-key"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_peer_key_lost_beside_a_store_is_not_regenerated() {
    let node = NodeDir::new();
    node.ok(&["--print-identity"]);
    node.add_store();
    let mut config = node.config();
    assert!(!config.p2p.peer_priv_key.is_empty());
    config.p2p.peer_priv_key.clear();
    quil_config::save_config(&node.config_dir(), &config).unwrap();

    let output = node.node(&["--print-identity"]);

    assert!(
        node.config().p2p.peer_priv_key.is_empty(),
        "a new peer key, the root of seniority, was generated beside the store of this node"
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to create a peer key"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_config_lost_beside_its_keystore_is_not_regenerated() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    let config_file = node.config_dir().join("config.yml");
    std::fs::remove_file(&config_file).unwrap();

    let output = node.node(&["--generate-keys"]);

    assert!(
        !config_file.exists(),
        "a new config, with a new peer key and encryption key, was written beside the keystore"
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to create a new config.yml"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_explicit_run_recovers_a_refused_node() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys"]);
    node.add_store();
    node.put_back_old_keystore();
    assert!(!node.node(&["--generate-keys"]).status.success());

    node.ok(&["--generate-keys", "--allow-new-identity"]);

    assert_eq!(node.prover_key_type(), 8);
    let saved = std::fs::read_to_string(node.keystore()).unwrap();
    assert!(
        saved.contains("q-prover-key-legacy-bls48581"),
        "the replaced key stays in the keystore: {saved}"
    );
    assert!(!node.config().p2p.peer_priv_key.is_empty());
    assert!(node.config_dir().join("node-identity.yml").is_file());
    // Every later start finds a usable key, so the flag is needed only once.
    let settled = std::fs::read(node.keystore()).unwrap();
    node.ok(&["--generate-keys"]);
    assert_eq!(std::fs::read(node.keystore()).unwrap(), settled);
}

#[test]
fn a_start_refuses_an_old_keystore_put_back() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys", "--allow-new-identity"]);
    let before = node.put_back_old_keystore();

    let output = node.start_expecting_refusal();

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to replace q-prover-key"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(node.keystore()).unwrap(), before);
}

#[test]
fn a_start_refuses_a_lost_peer_key() {
    let node = NodeDir::new();
    node.ok(&["--generate-keys", "--allow-new-identity"]);
    let mut config = node.config();
    config.p2p.peer_priv_key.clear();
    quil_config::save_config(&node.config_dir(), &config).unwrap();

    let output = node.start_expecting_refusal();

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("refusing to create a peer key"),
        "{}",
        stderr(&output)
    );
    assert!(node.config().p2p.peer_priv_key.is_empty());
}

#[test]
fn the_explicit_flag_only_applies_to_the_one_time_run() {
    let node = NodeDir::new();
    let output = node.node(&["--allow-new-identity"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("--generate-keys"),
        "{}",
        stderr(&output)
    );
}
