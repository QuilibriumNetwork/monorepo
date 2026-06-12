//! Direct Ed448-authenticated peer connection.
//!
//! Establishes a TCP connection to a Go node, performs the Ed448 noise
//! XX handshake, and returns an authenticated encrypted channel.
//! This bypasses libp2p's swarm for cases where Ed448 identity is
//! required (Go-node interop).

use tokio::net::TcpStream;
use tracing::debug;

use quil_types::error::{QuilError, Result};

use crate::ed448_identity;
use crate::ed448_noise_transport;

/// An authenticated connection to a remote peer.
pub struct Ed448PeerConnection {
    /// The remote peer's Ed448 public key.
    pub remote_public_key: Vec<u8>,
    /// The remote peer's derived peer ID (multihash).
    pub remote_peer_id: Vec<u8>,
    /// The underlying TCP stream (noise-encrypted after handshake).
    pub stream: TcpStream,
}

/// Connect to a Go node at `addr` (e.g. "192.168.1.1:8336") and
/// perform the Ed448 noise handshake.
pub async fn connect_ed448(
    addr: &str,
    ed448_seed: &[u8; 57],
) -> Result<Ed448PeerConnection> {
    let ed448_pubkey = ed448_identity::derive_public_key(ed448_seed);

    debug!(addr, "connecting to Go node");
    let mut stream = TcpStream::connect(addr).await
        .map_err(|e| QuilError::P2p(format!("connect to {}: {}", addr, e)))?;

    let result = ed448_noise_transport::handshake_initiator(
        &mut stream,
        ed448_seed,
        &ed448_pubkey,
    ).await?;

    let remote_peer_id = ed448_identity::peer_id_from_ed448_pubkey(
        &result.remote_public_key,
    );

    debug!(
        addr,
        remote_peer_id = hex::encode(&remote_peer_id),
        "Ed448 noise handshake complete"
    );

    Ok(Ed448PeerConnection {
        remote_public_key: result.remote_public_key,
        remote_peer_id,
        stream,
    })
}

/// Accept an incoming Ed448 noise connection on an already-accepted
/// TCP stream.
pub async fn accept_ed448(
    mut stream: TcpStream,
    ed448_seed: &[u8; 57],
) -> Result<Ed448PeerConnection> {
    let ed448_pubkey = ed448_identity::derive_public_key(ed448_seed);

    let result = ed448_noise_transport::handshake_responder(
        &mut stream,
        ed448_seed,
        &ed448_pubkey,
    ).await?;

    let remote_peer_id = ed448_identity::peer_id_from_ed448_pubkey(
        &result.remote_public_key,
    );

    debug!(
        remote_peer_id = hex::encode(&remote_peer_id),
        "accepted Ed448 noise connection"
    );

    Ok(Ed448PeerConnection {
        remote_public_key: result.remote_public_key,
        remote_peer_id,
        stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_send_receive_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let seed_a = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();
        let seed_b = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = accept_ed448(stream, &seed_b).await.unwrap();
            let mut len_buf = [0u8; 4];
            conn.stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            conn.stream.read_exact(&mut data).await.unwrap();
            data
        });

        let client = tokio::spawn(async move {
            let mut conn = connect_ed448(&addr, &seed_a).await.unwrap();
            let frame_data = b"test-global-frame-data-12345";
            let len = (frame_data.len() as u32).to_be_bytes();
            conn.stream.write_all(&len).await.unwrap();
            conn.stream.write_all(frame_data).await.unwrap();
            conn.stream.flush().await.unwrap();
        });

        client.await.unwrap();
        let received = server.await.unwrap();
        assert_eq!(received, b"test-global-frame-data-12345");
    }

    #[tokio::test]
    async fn connect_and_accept_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let seed_a = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();
        let seed_b = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();

        let pubkey_a = ed448_identity::derive_public_key(&seed_a);
        let pubkey_b = ed448_identity::derive_public_key(&seed_b);

        let addr_str = addr.to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_ed448(stream, &seed_b).await
        });

        let client = tokio::spawn(async move {
            connect_ed448(&addr_str, &seed_a).await
        });

        let server_conn = server.await.unwrap().unwrap();
        let client_conn = client.await.unwrap().unwrap();

        assert_eq!(client_conn.remote_public_key, pubkey_b);
        assert_eq!(server_conn.remote_public_key, pubkey_a);

        // Peer IDs should be derivable
        assert!(!client_conn.remote_peer_id.is_empty());
        assert!(!server_conn.remote_peer_id.is_empty());
    }
}
