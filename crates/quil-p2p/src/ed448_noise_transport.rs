//! Ed448 noise XX handshake transport.
//!
//! Performs a Noise_XX_25519_ChaChaPoly_SHA256 handshake with Ed448
//! identity authentication, compatible with Quilibrium Go nodes.
//!
//! The DH uses X25519 (same as stock libp2p). The identity
//! authentication uses Ed448 (KeyType=4) instead of Ed25519.
//!
//! Wire format matches Go's `go-libp2p/p2p/security/noise`:
//! - 2-byte big-endian length prefix per noise message
//! - XX pattern: 3 message exchange
//! - Payload in messages 2+3: NoiseHandshakePayload protobuf with Ed448 identity

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use quil_types::error::{QuilError, Result};

use crate::ed448_noise;

/// Length prefix size for noise messages (matching Go's LengthPrefixLength).
const LENGTH_PREFIX: usize = 2;

/// Maximum noise message size.
const MAX_NOISE_MSG_SIZE: usize = 65535;

/// Result of a successful noise handshake.
pub struct NoiseHandshakeResult {
    /// The remote peer's Ed448 public key (57 bytes).
    pub remote_public_key: Vec<u8>,
}

/// Perform an Ed448 noise XX handshake as the **initiator**.
///
/// `stream`: an already-connected TCP/QUIC stream
/// `ed448_seed`: our 57-byte Ed448 private key seed
/// `ed448_pubkey`: our 57-byte Ed448 public key
///
/// Returns the remote peer's Ed448 public key on success.
pub async fn handshake_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
) -> Result<NoiseHandshakeResult> {
    // Build snow handshake state (initiator)
    let builder = snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_SHA256".parse()
            .map_err(|_| QuilError::Crypto("invalid noise params".into()))?,
    );
    let keypair = builder.generate_keypair()
        .map_err(|e| QuilError::Crypto(format!("keygen failed: {}", e)))?;
    let mut hs = builder
        .local_private_key(&keypair.private)
        .build_initiator()
        .map_err(|e| QuilError::Crypto(format!("handshake init: {}", e)))?;

    let mut buf = vec![0u8; MAX_NOISE_MSG_SIZE];

    // Message 1: initiator → responder (e)
    let len = hs.write_message(&[], &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg1 write: {}", e)))?;
    send_noise_msg(stream, &buf[..len]).await?;

    // Message 2: responder → initiator (e, ee, s, es + payload)
    let msg2 = recv_noise_msg(stream).await?;
    let payload_len = hs.read_message(&msg2, &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg2 read: {}", e)))?;

    // Verify remote's Ed448 payload
    let remote_static = hs.get_remote_static()
        .ok_or_else(|| QuilError::Crypto("no remote static key after msg2".into()))?;
    let remote_pubkey = ed448_noise::verify_ed448_payload(
        &buf[..payload_len],
        remote_static,
    )?;

    // Message 3: initiator → responder (s, se + payload)
    let payload = ed448_noise::generate_ed448_payload(
        ed448_seed,
        ed448_pubkey,
        &keypair.public,
    )?;
    let len = hs.write_message(&payload, &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg3 write: {}", e)))?;
    send_noise_msg(stream, &buf[..len]).await?;

    Ok(NoiseHandshakeResult {
        remote_public_key: remote_pubkey,
    })
}

/// Perform an Ed448 noise XX handshake as the **responder**.
pub async fn handshake_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
) -> Result<NoiseHandshakeResult> {
    let builder = snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_SHA256".parse()
            .map_err(|_| QuilError::Crypto("invalid noise params".into()))?,
    );
    let keypair = builder.generate_keypair()
        .map_err(|e| QuilError::Crypto(format!("keygen failed: {}", e)))?;
    let mut hs = builder
        .local_private_key(&keypair.private)
        .build_responder()
        .map_err(|e| QuilError::Crypto(format!("handshake init: {}", e)))?;

    let mut buf = vec![0u8; MAX_NOISE_MSG_SIZE];

    // Message 1: initiator → responder (e)
    let msg1 = recv_noise_msg(stream).await?;
    hs.read_message(&msg1, &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg1 read: {}", e)))?;

    // Message 2: responder → initiator (e, ee, s, es + payload)
    let payload = ed448_noise::generate_ed448_payload(
        ed448_seed,
        ed448_pubkey,
        &keypair.public,
    )?;
    let len = hs.write_message(&payload, &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg2 write: {}", e)))?;
    send_noise_msg(stream, &buf[..len]).await?;

    // Message 3: initiator → responder (s, se + payload)
    let msg3 = recv_noise_msg(stream).await?;
    let payload_len = hs.read_message(&msg3, &mut buf)
        .map_err(|e| QuilError::Crypto(format!("msg3 read: {}", e)))?;

    let remote_static = hs.get_remote_static()
        .ok_or_else(|| QuilError::Crypto("no remote static key after msg3".into()))?;
    let remote_pubkey = ed448_noise::verify_ed448_payload(
        &buf[..payload_len],
        remote_static,
    )?;

    Ok(NoiseHandshakeResult {
        remote_public_key: remote_pubkey,
    })
}

async fn send_noise_msg<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<()> {
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await
        .map_err(|e| QuilError::P2p(format!("noise send: {}", e)))?;
    stream.write_all(data).await
        .map_err(|e| QuilError::P2p(format!("noise send: {}", e)))?;
    stream.flush().await
        .map_err(|e| QuilError::P2p(format!("noise flush: {}", e)))?;
    Ok(())
}

async fn recv_noise_msg<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; LENGTH_PREFIX];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| QuilError::P2p(format!("noise recv len: {}", e)))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_NOISE_MSG_SIZE {
        return Err(QuilError::P2p(format!("noise msg too large: {}", len)));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await
        .map_err(|e| QuilError::P2p(format!("noise recv data: {}", e)))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn ed448_noise_handshake_round_trip() {
        let seed_a = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();
        let pubkey_a = crate::ed448_identity::derive_public_key(&seed_a);

        let seed_b = *ed448_rust::PrivateKey::new(&mut rand::thread_rng()).as_bytes();
        let pubkey_b = crate::ed448_identity::derive_public_key(&seed_b);

        let (mut client, mut server) = duplex(65536);

        let pubkey_a_clone = pubkey_a.clone();
        let pubkey_b_clone = pubkey_b.clone();

        let client_handle = tokio::spawn(async move {
            handshake_initiator(&mut client, &seed_a, &pubkey_a).await
        });
        let server_handle = tokio::spawn(async move {
            handshake_responder(&mut server, &seed_b, &pubkey_b).await
        });

        let client_result = client_handle.await.unwrap().unwrap();
        let server_result = server_handle.await.unwrap().unwrap();

        assert_eq!(client_result.remote_public_key, pubkey_b_clone);
        assert_eq!(server_result.remote_public_key, pubkey_a_clone);
    }
}
