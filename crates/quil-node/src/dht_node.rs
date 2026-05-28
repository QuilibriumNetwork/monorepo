use tracing::info;

use quil_lifecycle::{ShutdownReason, Supervisor};

pub(crate) async fn start(
    mut sup: Supervisor<anyhow::Error>,
    config: &quil_config::Config,
) -> anyhow::Result<ShutdownReason<anyhow::Error>> {
    let listen_addr = if config.p2p.listen_multiaddr.is_empty() {
        "/ip4/0.0.0.0/udp/8336/quic-v1"
    } else {
        &config.p2p.listen_multiaddr
    };

    let p2p_node = quil_p2p::node::P2PNode::new(&config.p2p)?;
    info!(peer_id = %p2p_node.peer_id, "starting DHT node");

    let (p2p_handle, _msg_rx) = p2p_node.start(&mut sup, listen_addr).await?;
    info!("DHT node running");

    let reason = sup.run().await;
    info!("DHT node shut down");

    Ok(reason)
}
