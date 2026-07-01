//! Docker Compose interaction and node-identity resolution.
//!
//! Like the Go original, this shells out to the `docker compose` CLI rather than
//! using a Docker SDK. Peer IDs are derived from each node's `config.yml`
//! `p2p.peerPrivKey` using `quil-p2p`'s Ed448 identity (which produces the same
//! base58 `QmX…` form as Go's libp2p `peer.ID`).

use std::path::PathBuf;
use std::process::Stdio;
use std::{collections::HashMap, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use quil_p2p::ed448_identity::Ed448Identity;
use serde::Deserialize;
use tokio::process::Command;

use devnet::shared::NodeInfo;

/// Plaintext NodeService gRPC port (rust node default).
const NODE_PORT: i32 = 8337;

/// Minimal view of the fields we need from a node's `config.yml`.
#[derive(Debug, Deserialize)]
struct NodeConfigYaml {
    p2p: P2pSection,
}

#[derive(Debug, Deserialize)]
struct P2pSection {
    #[serde(rename = "peerPrivKey", default)]
    peer_priv_key: String,
    #[serde(rename = "streamListenMultiaddr", default)]
    stream_listen_multiaddr: String,
}

/// Minimal view of a node's `keys.yml` — just the prover key's public key.
#[derive(Debug, Deserialize)]
struct KeysYaml {
    #[serde(rename = "q-prover-key", default)]
    q_prover_key: Option<StoredKeyYaml>,
}

#[derive(Debug, Deserialize)]
struct StoredKeyYaml {
    #[serde(rename = "publicKey", default)]
    public_key: String,
}

/// Peer ID and raw (hex) private key for a node.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub peer_id: String,
    pub peer_priv_key: String,
}

fn config_path(exec_dir: &str, name: &str) -> PathBuf {
    PathBuf::from(exec_dir)
        .join("config")
        .join(format!("{name}-config"))
        .join("config.yml")
}

fn read_node_config(exec_dir: &str, name: &str) -> Result<NodeConfigYaml> {
    let path = config_path(exec_dir, name);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read config for node {name}"))?;
    serde_yaml::from_str(&data).with_context(|| format!("failed to parse config for node {name}"))
}

fn keys_path(exec_dir: &str, name: &str) -> PathBuf {
    PathBuf::from(exec_dir)
        .join("config")
        .join(format!("{name}-config"))
        .join("keys.yml")
}

/// Derives a node's prover address — `hex(Poseidon(q-prover-key publicKey))`,
/// the 32-byte BLS-derived identity that appears in `ProposalVote.address` and
/// frame headers. Reads the plaintext public key from the node's `keys.yml`
/// (no decryption needed) and hashes it the same way the engine does
/// (`prover_address_from_pubkey`). Returns the lowercase hex address.
fn derive_prover_address(exec_dir: &str, name: &str) -> Result<String> {
    let path = keys_path(exec_dir, name);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read keys.yml for node {name}"))?;
    let keys: KeysYaml = serde_yaml::from_str(&data)
        .with_context(|| format!("failed to parse keys.yml for node {name}"))?;
    let pubkey_hex = keys
        .q_prover_key
        .map(|k| k.public_key)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("q-prover-key publicKey not found in keys.yml for node {name}"))?;
    let pubkey = hex::decode(&pubkey_hex)
        .with_context(|| format!("failed to decode q-prover-key publicKey for node {name}"))?;
    let address = quil_crypto::hash_bytes_to_32(&pubkey)
        .map_err(|e| anyhow!("failed to hash prover pubkey for node {name}: {e}"))?;
    Ok(hex::encode(address))
}

/// Discovers archive and client node services from docker-compose.yml and
/// returns a sorted list of [`NodeInfo`] (archives first, then clients).
pub async fn get_node_services(exec_dir: &str) -> Result<Vec<NodeInfo>> {
    let output = Command::new("docker")
        .args(["compose", "config", "--services"])
        .current_dir(exec_dir)
        .output()
        .await
        .context("failed to list docker compose services")?;
    if !output.status.success() {
        bail!(
            "docker compose config --services failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut archive_names = Vec::new();
    let mut client_names = Vec::new();
    for service in stdout.split('\n').map(str::trim) {
        if service.starts_with("archive-") {
            archive_names.push(service.to_string());
        } else if service.starts_with("client-") {
            client_names.push(service.to_string());
        }
    }

    if archive_names.is_empty() {
        bail!("no archive node addresses found");
    }
    archive_names.sort();
    client_names.sort();

    let mut all_names = archive_names.clone();
    all_names.extend(client_names);

    let identities = resolve_node_identities(exec_dir, &all_names)
        .context("failed to resolve node identities")?;

    let mut nodes = Vec::with_capacity(all_names.len());
    for name in &all_names {
        let port = resolve_node_stream_port(exec_dir, name)?;
        let id = identities
            .get(name)
            .ok_or_else(|| anyhow!("missing identity for node {name}"))?;
        let prover_address = derive_prover_address(exec_dir, name)
            .with_context(|| format!("failed to derive prover address for node {name}"))?;
        nodes.push(NodeInfo {
            name: name.clone(),
            hostname: name.clone(),
            stream_port: port,
            node_port: NODE_PORT,
            peer_id: id.peer_id.clone(),
            peer_priv_key: id.peer_priv_key.clone(),
            is_archive: name.starts_with("archive-"),
            prover_address,
        });
    }

    Ok(nodes)
}

/// Derives the peer ID and preserves the hex-encoded private key for each named
/// node from its `config.yml`.
pub fn resolve_node_identities(
    exec_dir: &str,
    node_names: &[String],
) -> Result<HashMap<String, NodeIdentity>> {
    let mut result = HashMap::with_capacity(node_names.len());
    for raw_name in node_names {
        let name = raw_name.trim();
        let cfg = read_node_config(exec_dir, name)?;
        if cfg.p2p.peer_priv_key.is_empty() {
            bail!("p2p.peerPrivKey not found in config for node {name}");
        }
        let identity = Ed448Identity::from_config_hex(&cfg.p2p.peer_priv_key)
            .map_err(|e| anyhow!("failed to parse peerPrivKey for node {name}: {e}"))?;
        result.insert(
            name.to_string(),
            NodeIdentity {
                peer_id: identity.peer_id_base58(),
                peer_priv_key: cfg.p2p.peer_priv_key,
            },
        );
    }
    Ok(result)
}

/// Reads the TCP port from `p2p.streamListenMultiaddr` in a node's `config.yml`.
/// Expected format: `/ip4/0.0.0.0/tcp/8340/`.
pub fn resolve_node_stream_port(exec_dir: &str, name: &str) -> Result<i32> {
    let cfg = read_node_config(exec_dir, name)?;
    let ma = cfg.p2p.stream_listen_multiaddr;
    if ma.is_empty() {
        bail!("p2p.streamListenMultiaddr not found in config for node {name}");
    }
    let parts: Vec<&str> = ma.split('/').collect();
    for (i, p) in parts.iter().enumerate() {
        if *p == "tcp" && i + 1 < parts.len() {
            return parts[i + 1].parse::<i32>().with_context(|| {
                format!("invalid TCP port in streamListenMultiaddr for node {name}")
            });
        }
    }
    bail!("no TCP component in streamListenMultiaddr for node {name}: {ma:?}")
}

/// Parameters for [`execute_test`].
pub struct ExecuteTest<'a> {
    pub run_id: &'a str,
    pub exec_dir: &'a str,
    pub bearer_token: &'a str,
    pub listen_port: &'a str,
    pub project_name: &'a str,
    pub stop_frame: i32,
    pub verbose: bool,
    pub parallel: i32,
    pub nodes: &'a [NodeInfo],
    pub minimum_nodes: i32,
    pub resolved_rank_partitions: &'a str,
    pub global_timeout: Duration,
    pub node_catchup_timeout: Duration,
}

/// Starts the compose stack for a run via `docker compose up`.
pub async fn execute_test(args: ExecuteTest<'_>) -> Result<()> {
    let compose_path = PathBuf::from(args.exec_dir).join("docker-compose.yml");
    if !compose_path.exists() {
        bail!("docker-compose.yml not found in {}", args.exec_dir);
    }
    tracing::debug!(path = %compose_path.display(), project = args.project_name, "Found docker-compose.yml");

    let node_infos_json =
        serde_json::to_string(args.nodes).context("failed to serialize node infos")?;

    let runner_address = format!(
        "host.docker.internal:{}",
        args.listen_port.trim_start_matches(':')
    );

    // In verbose runs, turn on the proxy's own debug logging (e.g. per-frame
    // consensus progress) without the h2/hyper flood; otherwise keep it at info.
    let proxy_log = if args.verbose {
        "info,devnet_proxy=debug"
    } else {
        "info"
    };

    let env: Vec<(&str, String)> = vec![
        ("RUN_ID", args.run_id.to_string()),
        ("RUNNER_AUTH", args.bearer_token.to_string()),
        ("RUNNER_ADDRESS", runner_address),
        ("STOP_FRAME", args.stop_frame.to_string()),
        ("NODE_INFOS", node_infos_json),
        ("MIN_NODES", args.minimum_nodes.to_string()),
        ("RANK_PARTITIONS", args.resolved_rank_partitions.to_string()),
        ("GLOBAL_TIMEOUT", args.global_timeout.as_secs().to_string()),
        (
            "NODE_CATCHUP_TIMEOUT",
            args.node_catchup_timeout.as_secs().to_string(),
        ),
        ("RUST_LOG", proxy_log.to_string()),
    ];

    docker_compose_up(
        args.exec_dir,
        args.project_name,
        &env,
        args.verbose,
        args.parallel,
    )
    .await
    .context("failed to start compose stack")
}

/// `docker compose build` in the given working directory.
pub async fn docker_compose_build(exec_dir: &str, verbose: bool) -> Result<()> {
    let status = Command::new("docker")
        .args(["compose", "build"])
        .current_dir(exec_dir)
        .stdout(stdio(verbose))
        .stderr(stdio(verbose))
        .status()
        .await
        .context("docker compose build failed to spawn")?;
    if !status.success() {
        bail!("docker compose build failed");
    }
    Ok(())
}

/// `docker compose -p <project> up -d --wait --remove-orphans --no-build`,
/// inheriting the parent environment and adding the run-specific variables.
pub async fn docker_compose_up(
    exec_dir: &str,
    project_name: &str,
    env: &[(&str, String)],
    verbose: bool,
    parallel: i32,
) -> Result<()> {
    tracing::debug!(project = project_name, "Executing docker compose up");
    let show = verbose && parallel == 1;
    let status = Command::new("docker")
        .args([
            "compose",
            "-p",
            project_name,
            "up",
            "-d",
            "--wait",
            "--remove-orphans",
            "--no-build",
        ])
        .current_dir(exec_dir)
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdout(stdio(show))
        .stderr(stdio(show))
        .status()
        .await
        .context("docker compose up failed to spawn")?;
    if !status.success() {
        bail!("docker compose up failed");
    }
    Ok(())
}

/// Lists service names for a running compose project.
pub async fn docker_compose_project_services(
    exec_dir: &str,
    project_name: &str,
) -> Result<Vec<String>> {
    let output = Command::new("docker")
        .args(["compose", "-p", project_name, "ps", "--services"])
        .current_dir(exec_dir)
        .output()
        .await
        .context("docker compose ps --services failed to spawn")?;
    if !output.status.success() {
        bail!("docker compose ps --services failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\n')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Captures logs for a specific service in a compose project.
pub async fn docker_compose_service_logs(
    exec_dir: &str,
    project_name: &str,
    service: &str,
) -> Result<Vec<u8>> {
    let output = Command::new("docker")
        .args(["compose", "-p", project_name, "logs", "--no-color", service])
        .current_dir(exec_dir)
        .output()
        .await
        .with_context(|| format!("docker compose logs for {service} failed to spawn"))?;
    if !output.status.success() {
        bail!("docker compose logs for {service} failed");
    }
    Ok(output.stdout)
}

/// `docker compose -p <project> down --remove-orphans --volumes`.
pub async fn docker_compose_down(
    exec_dir: &str,
    project_name: &str,
    verbose: bool,
    parallel: i32,
) -> Result<()> {
    tracing::debug!(project = project_name, "Executing docker compose down");
    let show = verbose && parallel == 1;
    let status = Command::new("docker")
        .args([
            "compose",
            "-p",
            project_name,
            "down",
            "--remove-orphans",
            "--volumes",
        ])
        .current_dir(exec_dir)
        .stdout(stdio(show))
        .stderr(stdio(show))
        .status()
        .await
        .context("docker compose down failed to spawn")?;
    if !status.success() {
        bail!("docker compose down failed");
    }
    Ok(())
}

fn stdio(show: bool) -> Stdio {
    if show {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parity check: the peer IDs derived from each node's `peerPrivKey` must
    /// exactly match the IDs documented in `config/*/config.yml` (and pinned in
    /// the docker-compose healthchecks). This guards the Ed448 → base58 peer-id
    /// derivation reused from `quil-p2p` against the Go libp2p behaviour.
    #[test]
    fn peer_id_derivation_matches_pinned_ids() {
        let cases = [
            (
                "QmUTm2VphyTw3ZxFEP5Bsmf7oEbNm9odWfWVfq2uMWE71G",
                "6d5f7af9e6546ed193f2afea43afa807569770e995eb7fb813d1f6a89ef90f650dffa1161eddaf30b6794407c1253d73cdb317649a329d7cf71ed667a8ff39881cab52391e664c1b5b42e5ab841cafcf360ec0a72c4ec751e1ce88e3a367432ed7de2f9d9e6dd558aaf3c2efddb9cb5de600",
            ),
            (
                "QmabWWynnmuommyVP1cQDxrGESweGmzrG84p24uERR5sYh",
                "09446ac1e249611be68fe6fc7babf77e6b04f6272d91d0c5d565ed2870d939a4e0bb149fa510d65a5f94803e34e938d40b50e1a68b8d927fc8431afcc3b4bf3988279f08f7dbeb3da0627bc9c40e28bb97c4edcff75f4d7eef14fd845079bd0607e834edc807d0dd17274b46eae73be21100",
            ),
            (
                "QmdgHiGSSHD25cTjfZmYCXzajhdXzPKpPC9sXRFtZgUePX",
                "5b064e083bc058c86756ef4240bceabc356b9af058515a1bd35e20e0bc1ec08d1ec4ebae4717eb57975d1a5f64e68a1cdbbc8c2834f24dc2494abde22367a1db43cd2bde81e18959180a23ae10e33e83bdba0c4c3ea6db52dcdfde656e008d3ccc83b0badd891f34bf763e6d9ecc09349400",
            ),
            (
                "QmRTd8oGd75wjYhoVxkffpzmmCm9MF6oqYpoXNL7n3rjGk",
                "8f875c435dea3ca3a97256eec0d2b406bb09ff10cfaa6b3935b6032efe4e257497a0c23b0d0bc3febf6518ab444ee5a92519ecb2ec2062f242909e437aa25981deef5cc5633431d9e493286631854f77c4140b7534a8657a59c1c4d7e7a6b368e5e092b86e6c25f8eb6de1d4cb50e0c36080",
            ),
            (
                "QmeR2GE77KwyavM7RHn2C415wDxytvh3Q119v7JSSjK6KM",
                "78dc47fe6a5d8b176bb291b7720b315246a6f42521ea2948e1390c799e3416be505d73c3dbeb63e9981ff823a4b4834bd7bc4bfdf22b0665bccbd2cf64779025771a8e7496dd691c86d65b06f1f85929502aec0b94fa48fe0736dfdf0208535990cf3351e116152927a4ba74c4ea32cb5080",
            ),
            (
                "QmYWRH2ujTmiD1m4jCQaLgUqx72AD31P51pZdtynbHi8Sc",
                "4ee2b6a8ab83db96df43b1c5b0239ce3077fa14e77b23bb6b3ade66e50d4c7e1136478938e868439d2266d800c9cbd472ced584db4a651d8fdf18ebbc46deecb7007a316da06a22246cef854e241c33f295841d1e352b9c182d0b5057fac09e26c99b31dd19f80a6cc014e3b855bbabd8e80",
            ),
        ];
        for (expected_peer_id, priv_key_hex) in cases {
            let identity = Ed448Identity::from_config_hex(priv_key_hex).unwrap();
            assert_eq!(
                identity.peer_id_base58(),
                expected_peer_id,
                "derived peer ID mismatch for key {priv_key_hex}"
            );
        }
    }

    /// Parity check: `derive_prover_address` from client-1's real `keys.yml`
    /// must reproduce the prover address previously pinned for client-1
    /// (`04c6d96f…`, derived once via the node helper). This guards the prover-
    /// address derivation — used to attribute consensus messages to nodes —
    /// against the value the rest of the system computes. Tests run with the
    /// crate root as CWD, so the bundled `config/` is resolvable at ".".
    #[test]
    fn prover_address_derivation_matches_pinned_client_1() {
        let addr = derive_prover_address(".", "client-1").expect("derive client-1 prover address");
        assert_eq!(
            addr,
            "04c6d96f9b108107c62adf098b2994777da4b9f1d80e52ee303be72961df23bd"
        );
    }
}
