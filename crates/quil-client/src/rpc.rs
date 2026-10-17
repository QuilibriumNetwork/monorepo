//! gRPC connection layer.
//!
//! Port of `client/utils/rpc.go` (`GetGRPCClient`) and the light-node
//! selection in `client/cmd/token/token.go`. Two transports, exactly as
//! in Go:
//!
//! - **Local node** (default): parse `config.listen_grpc_multiaddr` to a
//!   `host:port` and dial plaintext h2 (`insecure.NewCredentials()`).
//! - **Public / custom RPC**: dial `rpc.quilibrium.com:8337` (or the
//!   configured `customRpc`) over ordinary system-CA TLS
//!   (`credentials.NewTLS(InsecureSkipVerify:false)`).
//!
//! There is deliberately **no** Ed448-mTLS / pqnoise here — that is only
//! how nodes talk to nodes. The client uses plaintext-local or public-TLS.

use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use quil_types::proto::global::dispatch_service_client::DispatchServiceClient;
use quil_types::proto::node::node_service_client::NodeServiceClient;

/// 100 MiB send/recv, matching Go's `GetGRPCClient` call options.
const MAX_MSG: usize = 100 * 1024 * 1024;
/// Default hosted RPC endpoint (`client/utils/rpc.go:24`).
pub const PUBLIC_RPC_ADDR: &str = "rpc.quilibrium.com:8337";

/// Inputs to the connection decision, gathered from the client config,
/// the node config, and the `--public-rpc` flag.
#[derive(Debug, Clone, Default)]
pub struct ConnectOpts {
    /// `--public-rpc` flag OR `ClientConfig.publicRpc`.
    pub public_rpc: bool,
    /// `ClientConfig.customRpc` (may be empty).
    pub custom_rpc: String,
    /// `config.listen_grpc_multiaddr` from the node config (may be empty).
    pub listen_grpc_multiaddr: String,
}

impl ConnectOpts {
    /// Light node ⇔ talk to a hosted/public RPC rather than the local
    /// node. Port of `token.go:69-83`: true if `--public-rpc`, or the
    /// client config's `publicRpc`, or the node has no gRPC listener.
    pub fn is_light_node(&self) -> bool {
        self.public_rpc || self.listen_grpc_multiaddr.is_empty()
    }

    /// The `host:port` to dial and whether TLS is required.
    fn target(&self) -> anyhow::Result<(String, bool)> {
        if self.is_light_node() {
            let addr = if self.custom_rpc.is_empty() {
                PUBLIC_RPC_ADDR.to_string()
            } else {
                self.custom_rpc.clone()
            };
            Ok((addr, true))
        } else {
            let addr = grpc_multiaddr_to_host_port(&self.listen_grpc_multiaddr)?;
            Ok((addr, false))
        }
    }
}

/// Build a tonic `Channel` per the connection options.
pub async fn connect_channel(opts: &ConnectOpts) -> anyhow::Result<Channel> {
    let (addr, tls) = opts.target()?;
    build_channel(&addr, tls).await
}

async fn build_channel(addr: &str, tls: bool) -> anyhow::Result<Channel> {
    let scheme = if tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{addr}"))
        .map_err(|e| anyhow::anyhow!("invalid endpoint {addr}: {e}"))?
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120));
    if tls {
        // System trust roots, verifying the server cert (Go's
        // InsecureSkipVerify:false). SNI is taken from the URI authority.
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connect {addr}: {e}"))?;
    Ok(channel)
}

/// Connect and return a `NodeServiceClient` with 100 MiB limits.
pub async fn connect_node_service(
    opts: &ConnectOpts,
) -> anyhow::Result<NodeServiceClient<Channel>> {
    let channel = connect_channel(opts).await?;
    Ok(NodeServiceClient::new(channel)
        .max_decoding_message_size(MAX_MSG)
        .max_encoding_message_size(MAX_MSG))
}

/// Connect a `DispatchServiceClient` to the node's stream endpoint
/// (`:8340`) over the Quilibrium PQNoise transport, authenticating with a
/// Falcon signing key. The node's `:8340` DispatchService no longer uses
/// TLS — it uses the same PQNoise handshake as node-to-node peers.
///
/// Used by `qclient message …`. `falcon_signing_key` is the node's
/// `q-prover-key` private bytes.
pub async fn connect_dispatch_mtls(
    addr: &str,
    falcon_signing_key: Vec<u8>,
) -> anyhow::Result<DispatchServiceClient<Channel>> {
    // Scheme is `http://`: tonic refuses `https://` without its own
    // tls_config, and we install our own PQNoise connector instead.
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .map_err(|e| anyhow::anyhow!("invalid endpoint {addr}: {e}"))?
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);
    let connector = quil_rpc::QuilPqNoiseConnector::new(falcon_signing_key);
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|e| anyhow::anyhow!("connect dispatch {addr}: {e}"))?;
    Ok(DispatchServiceClient::new(channel)
        .max_decoding_message_size(MAX_MSG)
        .max_encoding_message_size(MAX_MSG))
}

/// Convert a gRPC listen multiaddr to a `host:port` string.
///
/// Port of `go-multiaddr/net.DialArgs` for the multiaddr shapes the node
/// emits: `/ip4/H/tcp/P`, `/ip6/H/tcp/P`, `/dns4|dns6|dns/H/tcp/P`.
pub fn grpc_multiaddr_to_host_port(ma: &str) -> anyhow::Result<String> {
    // A multiaddr is `/proto/value/proto/value/...`.
    let parts: Vec<&str> = ma.trim_matches('/').split('/').collect();
    if parts.len() < 4 {
        anyhow::bail!("unsupported gRPC multiaddr: {ma}");
    }
    let mut host: Option<String> = None;
    let mut port: Option<String> = None;
    let mut i = 0;
    while i + 1 < parts.len() {
        let proto = parts[i];
        let value = parts[i + 1];
        match proto {
            "ip4" | "ip6" | "dns" | "dns4" | "dns6" => host = Some(value.to_string()),
            "tcp" | "udp" => port = Some(value.to_string()),
            _ => {}
        }
        i += 2;
    }
    match (host, port) {
        (Some(h), Some(p)) => {
            // Bracket IPv6 literals for a valid authority.
            if h.contains(':') {
                Ok(format!("[{h}]:{p}"))
            } else {
                Ok(format!("{h}:{p}"))
            }
        }
        _ => anyhow::bail!("could not extract host:port from multiaddr: {ma}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip4_tcp_multiaddr() {
        assert_eq!(
            grpc_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8337").unwrap(),
            "127.0.0.1:8337"
        );
    }

    #[test]
    fn parses_dns_multiaddr() {
        assert_eq!(
            grpc_multiaddr_to_host_port("/dns4/rpc.quilibrium.com/tcp/8337").unwrap(),
            "rpc.quilibrium.com:8337"
        );
    }

    #[test]
    fn brackets_ipv6() {
        assert_eq!(
            grpc_multiaddr_to_host_port("/ip6/::1/tcp/8337").unwrap(),
            "[::1]:8337"
        );
    }

    #[test]
    fn light_node_when_no_listener() {
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: String::new(),
        };
        assert!(opts.is_light_node());
        assert_eq!(opts.target().unwrap(), (PUBLIC_RPC_ADDR.to_string(), true));
    }

    #[test]
    fn custom_rpc_used_for_light_node() {
        let opts = ConnectOpts {
            public_rpc: true,
            custom_rpc: "example.com:9000".into(),
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/8337".into(),
        };
        assert!(opts.is_light_node());
        assert_eq!(opts.target().unwrap(), ("example.com:9000".to_string(), true));
    }

    #[test]
    fn local_node_uses_multiaddr_plaintext() {
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/8337".into(),
        };
        assert!(!opts.is_light_node());
        assert_eq!(opts.target().unwrap(), ("127.0.0.1:8337".to_string(), false));
    }
}
