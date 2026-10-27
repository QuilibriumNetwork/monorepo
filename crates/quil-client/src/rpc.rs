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
    /// `config.listen_grpc_multiaddr` from the node config (may be empty:
    /// the node then listens on `DEFAULT_LISTEN_GRPC_MULTIADDR`).
    pub listen_grpc_multiaddr: String,
}

impl ConnectOpts {
    /// Light node ⇔ talk to a hosted/public RPC rather than the local
    /// node: `--public-rpc`, the client config's `publicRpc`, or a
    /// `customRpc` with no node listener configured. An empty listener alone
    /// is not one: unlike Go's, the node then listens on its local default.
    pub fn is_light_node(&self) -> bool {
        self.public_rpc || (self.listen_grpc_multiaddr.is_empty() && !self.custom_rpc.is_empty())
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
            let listen = if self.listen_grpc_multiaddr.is_empty() {
                quil_config::DEFAULT_LISTEN_GRPC_MULTIADDR
            } else {
                &self.listen_grpc_multiaddr
            };
            Ok((grpc_multiaddr_to_host_port(listen)?, false))
        }
    }
}

/// Build a tonic `Channel` per the connection options.
pub async fn connect_channel(opts: &ConnectOpts) -> anyhow::Result<Channel> {
    let (addr, tls) = opts.target()?;
    build_channel(&addr, tls).await
}

fn endpoint(addr: &str, tls: bool) -> anyhow::Result<Endpoint> {
    let scheme = if tls { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{addr}"))
        .map_err(|e| anyhow::anyhow!("invalid endpoint {addr}: {e}"))?
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120));
    if tls {
        // rustls cannot pick a process-level provider from its features in
        // qclient's build and would panic here without one (#696).
        quil_rpc::quil_tls::install_crypto_provider();
        // System trust roots, verifying the server cert (Go's
        // InsecureSkipVerify:false). SNI is taken from the URI authority.
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
    }
    Ok(endpoint)
}

async fn build_channel(addr: &str, tls: bool) -> anyhow::Result<Channel> {
    let channel = endpoint(addr, tls)?
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connect {addr}: {}", with_causes(&e)))?;
    Ok(channel)
}

/// An error with its causes: tonic's own message is only "transport error",
/// and the cause says what failed (e.g. "Connection refused").
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let text = next.to_string();
        if !message.ends_with(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = next.source();
    }
    message
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

/// The node's stream endpoint (`:8340`) as a `host:port` to dial: its stream
/// listen address, on localhost for a `0.0.0.0` listener.
pub fn local_stream_addr(node_config: &quil_config::Config) -> anyhow::Result<String> {
    let stream = if node_config.p2p.stream_listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/tcp/8340"
    } else {
        node_config.p2p.stream_listen_multiaddr.as_str()
    };
    Ok(grpc_multiaddr_to_host_port(stream)?.replace("0.0.0.0", "127.0.0.1"))
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

/// Whether a gRPC multiaddr dials this host: a loopback or unspecified IP
/// address, or `localhost`. Plaintext h2 stays on the machine only then.
pub fn is_local_multiaddr(ma: &str) -> anyhow::Result<bool> {
    let host_port = grpc_multiaddr_to_host_port(ma)?;
    let (host, _) = host_port
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("could not extract host from multiaddr: {ma}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok(match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_multiaddrs_are_loopback_unspecified_or_localhost() {
        for (ma, local) in [
            ("/ip4/127.0.0.1/tcp/8337", true),
            ("/ip4/127.8.9.10/tcp/8337", true),
            ("/ip4/0.0.0.0/tcp/8337", true),
            ("/ip6/::1/tcp/8337", true),
            ("/ip6/::/tcp/8337", true),
            ("/dns/localhost/tcp/8337", true),
            ("/ip4/10.0.0.2/tcp/8337", false),
            ("/ip4/192.0.2.7/tcp/8337", false),
            ("/ip6/2001:db8::7/tcp/8337", false),
            ("/dns4/rpc.quilibrium.com/tcp/8337", false),
            ("/dns4/localhost.example.com/tcp/8337", false),
        ] {
            assert_eq!(is_local_multiaddr(ma).unwrap(), local, "{ma}");
        }
        assert!(is_local_multiaddr("127.0.0.1:8337").is_err());
    }

    /// A refused connection names its cause, not only "transport error".
    #[tokio::test]
    async fn a_failed_connection_names_its_cause() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: format!("/ip4/127.0.0.1/tcp/{port}"),
        };
        let error = connect_channel(&opts).await.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!("connect 127.0.0.1:{port}: transport error: ")),
            "{error}"
        );
        assert!(error.len() > format!("connect 127.0.0.1:{port}: transport error: ").len());
    }

    #[test]
    fn parses_ip4_tcp_multiaddr() {
        assert_eq!(
            grpc_multiaddr_to_host_port("/ip4/127.0.0.1/tcp/8337").unwrap(),
            "127.0.0.1:8337"
        );
    }

    #[test]
    fn a_tls_endpoint_builds_without_a_preinstalled_crypto_provider() {
        assert!(endpoint(PUBLIC_RPC_ADDR, true).is_ok());
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
    fn an_empty_listener_dials_the_local_default() {
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: String::new(),
        };
        assert!(!opts.is_light_node());
        assert_eq!(
            opts.target().unwrap(),
            ("127.0.0.1:8337".to_string(), false)
        );
    }

    #[test]
    fn public_rpc_flag_selects_the_hosted_endpoint() {
        let opts = ConnectOpts {
            public_rpc: true,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: String::new(),
        };
        assert!(opts.is_light_node());
        assert_eq!(opts.target().unwrap(), (PUBLIC_RPC_ADDR.to_string(), true));
    }

    #[test]
    fn custom_rpc_without_a_listener_stays_a_light_node() {
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: "example.com:9000".into(),
            listen_grpc_multiaddr: String::new(),
        };
        assert!(opts.is_light_node());
        assert_eq!(
            opts.target().unwrap(),
            ("example.com:9000".to_string(), true)
        );
    }

    #[test]
    fn custom_rpc_used_for_light_node() {
        let opts = ConnectOpts {
            public_rpc: true,
            custom_rpc: "example.com:9000".into(),
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/8337".into(),
        };
        assert!(opts.is_light_node());
        assert_eq!(
            opts.target().unwrap(),
            ("example.com:9000".to_string(), true)
        );
    }

    #[test]
    fn local_node_uses_multiaddr_plaintext() {
        let opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/8337".into(),
        };
        assert!(!opts.is_light_node());
        assert_eq!(
            opts.target().unwrap(),
            ("127.0.0.1:8337".to_string(), false)
        );
    }
}
