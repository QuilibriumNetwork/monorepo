use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) async fn run(
    config: &quil_config::Config,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1"
    } else {
        &config.p2p.listen_multiaddr
    };

    let p2p_node = quil_p2p::node::P2PNode::new(&config.p2p)?;
    info!(peer_id = %p2p_node.peer_id, "starting DHT node");

    let (p2p_handle, _msg_rx) = p2p_node.start(listen_addr).await?;
    info!("DHT node running");

    token.cancelled().await;
    p2p_handle.shutdown().await;
    info!("DHT node shut down");

    Ok(())
}
