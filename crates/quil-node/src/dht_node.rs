use tracing::info;

use quil_lifecycle::{ShutdownReason, Supervisor};

/// The DHT bootstrap peer's listen address and the config its node starts
/// from: as for the master, a config naming no listen address also listens
/// on IPv6, so peers of either family can bootstrap from it.
fn dht_p2p_config(p2p: &quil_config::P2PConfig) -> (String, quil_config::P2PConfig) {
    crate::master_node::networking::p2p_node_config(p2p, p2p.network)
}

/// The DHT bootstrap peer's node and listen address; like the master, it
/// logs what it made of the configured peer lists.
fn dht_p2p_node(p2p: &quil_config::P2PConfig) -> anyhow::Result<(String, quil_p2p::node::P2PNode)> {
    let (listen_addr, p2p_config) = dht_p2p_config(p2p);
    let p2p_node = quil_p2p::node::P2PNode::new(&p2p_config)?;
    info!(peer_id = %p2p_node.peer_id, "starting DHT node");
    p2p_node.peer_list_notes().log();
    Ok((listen_addr, p2p_node))
}

pub(crate) async fn start(
    mut sup: Supervisor<anyhow::Error>,
    config: &quil_config::Config,
) -> anyhow::Result<ShutdownReason<anyhow::Error>> {
    let (listen_addr, p2p_node) = dht_p2p_node(&config.p2p)?;
    let (_p2p_handle, _msg_rx) = p2p_node.start(&mut sup, &listen_addr).await?;
    info!("DHT node running");

    let reason = sup.run().await;
    info!("DHT node shut down");

    Ok(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DHT bootstrap peer naming no listen address listens on both
    /// families on its configured network; a named one stays as written.
    #[test]
    fn a_dht_bootstrap_peer_listens_on_both_families_by_default() {
        let mut p2p = quil_config::P2PConfig {
            network: 1,
            ..Default::default()
        };
        let (listen, node) = dht_p2p_config(&p2p);
        assert_eq!(listen, quil_config::DEFAULT_LISTEN_MULTIADDR);
        assert_eq!(
            node.additional_listen_multiaddrs,
            [quil_config::DEFAULT_IPV6_LISTEN_MULTIADDR],
            "the DHT node does not listen on IPv6"
        );
        assert_eq!(node.network, 1);

        p2p.listen_multiaddr = "/ip4/0.0.0.0/udp/8337/quic-v1".into();
        let (listen, node) = dht_p2p_config(&p2p);
        assert_eq!(listen, p2p.listen_multiaddr);
        assert!(node.additional_listen_multiaddrs.is_empty());
    }

    /// A DHT bootstrap peer warns of each configured peer it does not dial
    /// and says how many bootstrap peers `p2p.extraBootstrapPeers` added.
    #[test]
    fn a_dht_bootstrap_peer_logs_its_peer_list_notes() {
        let p2p = quil_config::P2PConfig {
            network: 1,
            bootstrap_peers: Vec::new(),
            extra_bootstrap_peers: vec![
                "/ip4/192.0.2.1/udp/8336/quic-v1/p2p/QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC"
                    .into(),
                "not an address".into(),
            ],
            ..Default::default()
        };
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || dht_p2p_node(&p2p).unwrap());
        let logged = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        let notes = [
            "entry=not an address",
            "p2p.extraBootstrapPeers adds 1 bootstrap peers",
        ];
        for note in notes {
            assert!(
                logged.contains(note),
                "the DHT node does not log its peer-list notes: no {note:?} in {logged}"
            );
        }
    }

    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}
