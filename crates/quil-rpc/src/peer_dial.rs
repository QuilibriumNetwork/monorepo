//! Open an mTLS gRPC connection to a peer discovered via the key
//! registry + peer info manager.

use std::sync::Arc;

use quil_engine::worker_node::multiaddr_to_socket_addr;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::GlobalFrame;
use quil_types::store::KeyStore;

use crate::archive_client::{ArchiveClient, ArchiveClientError};

/// `peer_info_lookup` returns candidate stream multiaddrs for the
/// given peer id (e.g. `/ip4/10.0.0.1/tcp/8340`). The first that
/// flattens to a parseable socket address is dialed, and must answer as
/// the prover's peer: a record cannot name another node's address and
/// have that node answer for the prover.
pub async fn dial_latest_frame_prover<F>(
    frame: &GlobalFrame,
    key_store: Arc<dyn KeyStore>,
    peer_info_lookup: F,
    self_falcon_signing_key: &[u8],
) -> Result<ArchiveClient>
where
    F: Fn(&[u8]) -> Vec<String> + Send + Sync,
{
    let header = frame.header.as_ref().ok_or_else(|| {
        QuilError::Internal("dial_latest_frame_prover: frame missing header".into())
    })?;
    let prover_addr = &header.prover;
    if prover_addr.is_empty() {
        return Err(QuilError::Internal(
            "dial_latest_frame_prover: header.prover is empty".into(),
        ));
    }

    let registry = key_store
        .get_key_registry_by_prover(prover_addr)
        .map_err(|e| QuilError::Internal(format!("get_key_registry_by_prover: {e}")))?;

    // The network peer-id is derived from the remote's FALCON prover key (the
    // network identity), not its Ed448 identity key.
    let prover_key = registry.prover_key.ok_or_else(|| {
        QuilError::Internal("dial_latest_frame_prover: prover_key missing".into())
    })?;
    if prover_key.key_value.is_empty() {
        return Err(QuilError::Internal(
            "dial_latest_frame_prover: prover_key.key_value empty".into(),
        ));
    }

    let peer_id = quil_p2p::peer_id_from_falcon_pubkey(&prover_key.key_value);
    let candidates = peer_info_lookup(&peer_id);
    if candidates.is_empty() {
        return Err(QuilError::Internal(format!(
            "dial_latest_frame_prover: no peer info for prover (peer_id_len={})",
            peer_id.len()
        )));
    }

    let socket_addr = candidates
        .iter()
        .find_map(|ma| multiaddr_to_socket_addr(ma))
        .ok_or_else(|| {
            QuilError::Internal(format!(
                "dial_latest_frame_prover: no parseable stream multiaddrs (had {})",
                candidates.len()
            ))
        })?;

    let peer = quil_p2p::PeerId::from_bytes(&peer_id).map_err(|e| {
        QuilError::Internal(format!("dial_latest_frame_prover: prover peer id: {e}"))
    })?;
    ArchiveClient::connect_peer(&socket_addr, self_falcon_signing_key, peer)
        .await
        .map_err(|e: ArchiveClientError| QuilError::P2p(format!("dial frame prover: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto;
    use quil_types::store::Transaction;
    use std::time::Duration;

    /// A key store holding one registry, whatever the prover address.
    struct OneRegistry(proto::keys::KeyRegistry);

    impl KeyStore for OneRegistry {
        fn new_transaction(&self) -> Result<Box<dyn Transaction>> {
            unimplemented!("not read by the dial")
        }
        fn put_identity_key(
            &self,
            _: &dyn Transaction,
            _: &[u8],
            _: &proto::keys::Ed448PublicKey,
        ) -> Result<()> {
            unimplemented!("not read by the dial")
        }
        fn get_identity_key(&self, _: &[u8]) -> Result<proto::keys::Ed448PublicKey> {
            unimplemented!("not read by the dial")
        }
        fn put_proving_key(
            &self,
            _: &dyn Transaction,
            _: &[u8],
            _: &proto::keys::Bls48581SignatureWithProofOfPossession,
        ) -> Result<()> {
            unimplemented!("not read by the dial")
        }
        fn get_proving_key(
            &self,
            _: &[u8],
        ) -> Result<proto::keys::Bls48581SignatureWithProofOfPossession> {
            unimplemented!("not read by the dial")
        }
        fn put_cross_signature(
            &self,
            _: &dyn Transaction,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<()> {
            unimplemented!("not read by the dial")
        }
        fn get_cross_signature_by_identity_key(&self, _: &[u8]) -> Result<Vec<u8>> {
            unimplemented!("not read by the dial")
        }
        fn get_cross_signature_by_proving_key(&self, _: &[u8]) -> Result<Vec<u8>> {
            unimplemented!("not read by the dial")
        }
        fn put_signed_x448_key(
            &self,
            _: &dyn Transaction,
            _: &[u8],
            _: &proto::keys::SignedX448Key,
        ) -> Result<()> {
            unimplemented!("not read by the dial")
        }
        fn get_signed_x448_key(&self, _: &[u8]) -> Result<proto::keys::SignedX448Key> {
            unimplemented!("not read by the dial")
        }
        fn get_signed_x448_keys_by_parent(
            &self,
            _: &[u8],
            _: &str,
        ) -> Result<Vec<proto::keys::SignedX448Key>> {
            unimplemented!("not read by the dial")
        }
        fn get_key_registry(&self, _: &[u8]) -> Result<proto::keys::KeyRegistry> {
            unimplemented!("not read by the dial")
        }
        fn get_key_registry_by_prover(&self, _: &[u8]) -> Result<proto::keys::KeyRegistry> {
            Ok(self.0.clone())
        }
    }

    /// The 897-byte Falcon public key of `signing_key`, as a key registry
    /// holds it.
    fn falcon_public_key(signing_key: &[u8]) -> Vec<u8> {
        let public = quil_p2p::Keypair::falcon_from_bytes(signing_key)
            .unwrap()
            .public();
        let encoded = public.encode_protobuf();
        let key = encoded[encoded.len() - 897..].to_vec();
        assert_eq!(
            quil_p2p::peer_id_from_falcon_pubkey(&key),
            public.to_peer_id().to_bytes(),
            "harness check: the registry key derives the listener's peer id"
        );
        key
    }

    /// A loopback listener completing the PQNoise handshake of every dial
    /// as the holder of `signing_key`, keeping each connection open until
    /// the test's runtime ends: its stream multiaddr.
    async fn listener_as(signing_key: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                open.push(crate::pqnoise_channel::pq_server_handshake(tcp, &signing_key).await);
            }
        });
        format!("/ip4/127.0.0.1/tcp/{port}")
    }

    /// Dials the latest frame's prover, registered with `prover_key`'s
    /// public key, at an endpoint where a node holding `listener_key`
    /// answers.
    async fn dial(prover_key: &[u8], listener_key: Vec<u8>) -> Result<ArchiveClient> {
        let endpoint = listener_as(listener_key).await;
        let registry = proto::keys::KeyRegistry {
            prover_key: Some(proto::keys::Bls48581g2PublicKey {
                key_value: falcon_public_key(prover_key),
            }),
            ..Default::default()
        };
        let frame = GlobalFrame {
            header: Some(proto::global::GlobalFrameHeader {
                prover: vec![7; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let lookup = move |_: &[u8]| vec![endpoint.clone()];
        tokio::time::timeout(
            Duration::from_secs(10),
            dial_latest_frame_prover(
                &frame,
                Arc::new(OneRegistry(registry)),
                lookup,
                &quil_p2p::generate_falcon_signing_key(),
            ),
        )
        .await
        .expect("the dial ends")
    }

    /// The prover's PeerInfo endpoint is dialed only as the prover: a node
    /// there answering with another peer's identity is refused, so a
    /// record cannot name another node's address and have it answer for
    /// the latest frame's prover.
    #[tokio::test]
    async fn the_latest_frame_prover_is_dialed_only_as_itself() {
        let prover = quil_p2p::generate_falcon_signing_key();
        let other = quil_p2p::generate_falcon_signing_key();
        if dial(&prover, other).await.is_ok() {
            panic!(
                "VULNERABLE: an unpinned dial accepted a node answering with a \
                 different peer's identity as the latest frame's prover"
            );
        }
        if let Err(error) = dial(&prover, prover.clone()).await {
            panic!("the prover was refused at its own endpoint: {error}");
        }
    }
}
