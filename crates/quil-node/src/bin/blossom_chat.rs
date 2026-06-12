//! Minimal BlossomSub chat test. Publishes a random message every 5s
//! on bitmask [0x00; 80] and logs anything received on that bitmask.
//!
//! Usage:
//!   cargo run --release --bin blossom-chat -- --port 9100
//!   cargo run --release --bin blossom-chat -- --port 9100 --peer /ip4/127.0.0.1/tcp/9000/p2p/<goNodePeerID>

use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(clap::Parser)]
struct Args {
    #[arg(long, default_value_t = 9100)]
    port: u16,
    /// Multiaddr of a Go peer to connect to
    #[arg(long)]
    peer: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Build a minimal P2P config
    let mut p2p_config = quil_config::P2PConfig::default();
    p2p_config.listen_multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port);
    p2p_config.network = 0;
    if let Some(ref peer) = args.peer {
        p2p_config.bootstrap_peers = vec![peer.clone()];
    } else {
        p2p_config.bootstrap_peers = vec![];
    }

    // Use Ed448 (Quilibrium's native identity type)
    let p2p_node = quil_p2p::node::P2PNode::new_with_options(&p2p_config, false)?;
    let peer_id = p2p_node.peer_id;
    info!(%peer_id, port = args.port, "Rust node started");

    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", args.port);
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let (p2p_handle, mut msg_rx) = p2p_node.start(&mut sup, &listen_addr).await?;
    // This dev binary doesn't drive `sup.run()`; the swarm task is
    // registered just to mirror production behavior. If a panic fires,
    // it propagates into the supervisor where this binary never joins it.
    let _sup = sup;
    info!("P2P swarm started");

    // Subscribe to test bitmask (80 zero bytes)
    let test_bitmask = vec![0u8; 80];
    p2p_handle.subscribe(test_bitmask.clone()).await;
    info!(bitmask_len = 80, "subscribed to test bitmask");

    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        t.cancel();
    });

    // Receive loop
    let recv_bitmask = test_bitmask.clone();
    let recv_token = token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = msg_rx.recv() => {
                    match msg {
                        Some(received) => {
                            if received.bitmask == recv_bitmask {
                                let data = String::from_utf8_lossy(&received.data);
                                info!(data = %data, bytes = received.data.len(), "[RECV]");
                            }
                        }
                        None => break,
                    }
                }
                _ = recv_token.cancelled() => break,
            }
        }
    });

    // Publish loop
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut count = 0u32;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                count += 1;
                let msg = format!("rust-ping-{}-{}", args.port, count);
                if let Err(e) = p2p_handle.publish(test_bitmask.clone(), msg.as_bytes().to_vec()).await {
                    warn!(error = %e, "publish failed");
                }
                info!(msg = %msg, "[SEND]");
            }
            _ = token.cancelled() => break,
        }
    }

    p2p_handle.shutdown().await;
    info!("shutdown");
    Ok(())
}
