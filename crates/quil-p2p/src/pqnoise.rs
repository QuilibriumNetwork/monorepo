//! Post-quantum, forward-secret Noise transport over Streamlined NTRU Prime.
//!
//! This is the PQ analog of [`crate::ed448_noise_transport`]. Where that module
//! runs `Noise_XX_25519_...` (classical X25519 DH — breakable by a quantum
//! adversary, so harvest-now-decrypt-later defeats its forward secrecy), this
//! module runs a **PQNoise** handshake: the DH is replaced by a KEM, and
//! **forward secrecy comes from an ephemeral KEM encapsulation** that no
//! quantum adversary can recover after the ephemeral secret is dropped.
//!
//! Building blocks (both battle-hardened; we invent no protocol crypto):
//! * **[`clatter`]** — pure-Rust implementation of the PQNoise framework
//! (Angel/Dowling/Hülsing/Schwabe, CCS'22). It owns the handshake state
//! machine, transcript hashing, and the `pqxx` pattern (mutual auth via
//! static KEM keys + forward secrecy via ephemeral KEM).
//! * **Streamlined NTRU Prime (sntrup761)** via PQClean (`pqcrypto-ntruprime`)
//! — the NTRU-family KEM deployed in OpenSSH (`sntrup761x25519`) at internet
//! scale. Pure NTRU, **non-hybrid**, non-NIST-standardized. Supplied to
//! clatter through its `Kem` trait ([`Sntrup761`]).
//!
//! **Identity binding.** clatter's `pqxx` authenticates possession of the
//! static KEM keys but knows nothing of Quilibrium peer identities (Ed448 /
//! Falcon). We bind the channel to the identity exactly as the classical
//! transport does: after the handshake, each side signs the **handshake hash**
//! (the Noise channel-binding value, which commits to every exchanged key) with
//! its identity key and exchanges the signed `NoiseHandshakePayload` over the
//! now-encrypted, forward-secret channel. We reuse
//! [`crate::ed448_noise`]'s payload codec verbatim, so the identity wire format
//! is unchanged.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use clatter::bytearray::{ByteArray, HeapArray, SensitiveByteArray};
use clatter::constants::MAX_MESSAGE_LEN;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256;
use clatter::error::{KemError, KemResult};
use clatter::handshakepattern::noise_pqxx;
use clatter::traits::{CryptoComponent, Kem, Rng};
use clatter::transportstate::TransportState;
use clatter::{Handshaker, KeyPair, PqHandshake};

use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};

use quil_types::error::{QuilError, Result};

use crate::ed448_noise;

/// Max bytes of a single length-framed handshake / transport message.
const MAX_FRAME: usize = MAX_MESSAGE_LEN;

// ---------------------------------------------------------------------------
// Streamlined NTRU Prime (sntrup761) as a clatter KEM.
//
// Mirrors clatter's own `crypto_impl/pqclean_ml_kem.rs` wrapper exactly, but
// over PQClean's sntrup761 instead of ML-KEM. PQClean drives its own internal
// CSPRNG, so the `Rng` argument is unused (same as the ML-KEM wrapper).
// ---------------------------------------------------------------------------

/// Streamlined NTRU Prime (sntrup761) KEM: pk 1158 B / sk 1763 B / ct 1039 B /
/// shared secret 32 B.
#[derive(Clone)]
pub struct Sntrup761;

impl CryptoComponent for Sntrup761 {
    fn name() -> &'static str {
        "sntrup761"
    }
}

impl Kem for Sntrup761 {
    type SecretKey = SensitiveByteArray<HeapArray<{ sntrup761::secret_key_bytes() }>>;
    type PubKey = HeapArray<{ sntrup761::public_key_bytes() }>;
    type Ct = HeapArray<{ sntrup761::ciphertext_bytes() }>;
    type Ss = SensitiveByteArray<[u8; sntrup761::shared_secret_bytes()]>;

    fn genkey_rng<R: Rng>(_rng: &mut R) -> KemResult<KeyPair<Self::PubKey, Self::SecretKey>> {
        // PQClean uses its own RNG.
        let (pk, sk) = sntrup761::keypair();
        Ok(KeyPair {
            public: ByteArray::from_slice(pk.as_bytes()),
            secret: SensitiveByteArray::from_slice(sk.as_bytes()),
        })
    }

    fn encapsulate<R: Rng>(pk: &[u8], _rng: &mut R) -> KemResult<(Self::Ct, Self::Ss)> {
        let pk = sntrup761::PublicKey::from_bytes(pk).map_err(|_| KemError::Input)?;
        // PQClean uses its own RNG.
        let (ss, ct) = sntrup761::encapsulate(&pk);
        Ok((
            Self::Ct::from_slice(ct.as_bytes()),
            Self::Ss::from_slice(ss.as_bytes()),
        ))
    }

    fn decapsulate(ct: &[u8], sk: &[u8]) -> KemResult<Self::Ss> {
        let sk = sntrup761::SecretKey::from_bytes(sk).map_err(|_| KemError::Input)?;
        let ct = sntrup761::Ciphertext::from_bytes(ct).map_err(|_| KemError::Input)?;
        let ss = sntrup761::decapsulate(&ct, &sk);
        Ok(Self::Ss::from_slice(ss.as_bytes()))
    }
}

/// The concrete PQNoise handshake: sntrup761 for both ephemeral and static KEM,
/// ChaCha20-Poly1305 + SHA-256 (matching the classical transport's suite).
type Handshake = PqHandshake<Sntrup761, Sntrup761, ChaChaPoly, Sha256>;

/// A live post-quantum transport channel plus the authenticated remote identity.
pub struct PqNoiseResult {
    /// The forward-secret encrypted channel. Use `send_vec` / `receive_vec`.
    pub transport: TransportState<ChaChaPoly, Sha256>,
    /// The remote peer's Ed448 identity public key (57 bytes).
    pub remote_public_key: Vec<u8>,
}

/// Perform the PQNoise `pqxx` handshake as the **initiator**, then bind the
/// channel to our Ed448 identity by exchanging handshake-hash signatures.
pub async fn pq_handshake_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
) -> Result<PqNoiseResult> {
    let static_kem = Sntrup761::genkey()
        .map_err(|e| QuilError::Crypto(format!("sntrup761 keygen: {:?}", e)))?;
    let mut hs = Handshake::new(noise_pqxx(), &[], true, Some(static_kem), None, None, None)
        .map_err(|e| QuilError::Crypto(format!("pqnoise init: {:?}", e)))?;

    drive_handshake(stream, &mut hs, true).await?;

    let mut transport = hs
        .finalize()
        .map_err(|e| QuilError::Crypto(format!("pqnoise finalize: {:?}", e)))?;
    // Channel-binding value: commits to every key exchanged in the handshake.
    let hash_bytes = transport.get_handshake_hash().as_slice().to_vec();

    // Initiator authenticates first, then verifies the responder.
    send_identity(stream, &mut transport, ed448_seed, ed448_pubkey, &hash_bytes).await?;
    let remote_public_key = recv_identity(stream, &mut transport, &hash_bytes).await?;

    Ok(PqNoiseResult {
        transport,
        remote_public_key,
    })
}

/// Perform the PQNoise `pqxx` handshake as the **responder**.
pub async fn pq_handshake_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
) -> Result<PqNoiseResult> {
    let static_kem = Sntrup761::genkey()
        .map_err(|e| QuilError::Crypto(format!("sntrup761 keygen: {:?}", e)))?;
    let mut hs = Handshake::new(noise_pqxx(), &[], false, Some(static_kem), None, None, None)
        .map_err(|e| QuilError::Crypto(format!("pqnoise init: {:?}", e)))?;

    drive_handshake(stream, &mut hs, false).await?;

    let mut transport = hs
        .finalize()
        .map_err(|e| QuilError::Crypto(format!("pqnoise finalize: {:?}", e)))?;
    let hash_bytes = transport.get_handshake_hash().as_slice().to_vec();

    // Responder verifies the initiator first, then authenticates.
    let remote_public_key = recv_identity(stream, &mut transport, &hash_bytes).await?;
    send_identity(stream, &mut transport, ed448_seed, ed448_pubkey, &hash_bytes).await?;

    Ok(PqNoiseResult {
        transport,
        remote_public_key,
    })
}

/// Drive the KEM handshake to completion over `stream`. `writes_first` is true
/// for the initiator. Works for any strictly-alternating pattern (pqxx is 3
/// messages) — empty payloads; identity is bound afterward over the transport.
async fn drive_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hs: &mut Handshake,
    writes_first: bool,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_FRAME];
    let mut my_turn = writes_first;
    while !hs.is_finished() {
        if my_turn {
            let len = hs
                .write_message(&[], &mut buf)
                .map_err(|e| QuilError::Crypto(format!("pqnoise write: {:?}", e)))?;
            send_frame(stream, &buf[..len]).await?;
        } else {
            let msg = recv_frame(stream).await?;
            hs.read_message(&msg, &mut buf)
                .map_err(|e| QuilError::Crypto(format!("pqnoise read: {:?}", e)))?;
        }
        my_turn = !my_turn;
    }
    Ok(())
}

/// Sign the handshake hash with our Ed448 identity and send the encrypted
/// `NoiseHandshakePayload` over the transport. Reuses the classical transport's
/// payload codec (the "dh_public_key" slot carries the handshake hash here).
async fn send_identity<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut TransportState<ChaChaPoly, Sha256>,
    ed448_seed: &[u8; 57],
    ed448_pubkey: &[u8],
    hash: &[u8],
) -> Result<()> {
    let payload = ed448_noise::generate_ed448_payload(ed448_seed, ed448_pubkey, hash)?;
    let ct = transport
        .send_vec(&payload)
        .map_err(|e| QuilError::Crypto(format!("pqnoise transport send: {:?}", e)))?;
    send_frame(stream, &ct).await
}

/// Receive the peer's encrypted identity payload and verify its signature over
/// the shared handshake hash. Returns the peer's Ed448 identity public key.
async fn recv_identity<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut TransportState<ChaChaPoly, Sha256>,
    hash: &[u8],
) -> Result<Vec<u8>> {
    let ct = recv_frame(stream).await?;
    let payload = transport
        .receive_vec(&ct)
        .map_err(|e| QuilError::Crypto(format!("pqnoise transport recv: {:?}", e)))?;
    ed448_noise::verify_ed448_payload(&payload, hash)
}

// ---------------------------------------------------------------------------
// u32-length-prefixed framing (self-contained; the classical transport's
// helpers are private to that module).
// ---------------------------------------------------------------------------

async fn send_frame<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| QuilError::Crypto(format!("pqnoise frame len write: {}", e)))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| QuilError::Crypto(format!("pqnoise frame write: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| QuilError::Crypto(format!("pqnoise flush: {}", e)))?;
    Ok(())
}

async fn recv_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| QuilError::Crypto(format!("pqnoise frame len read: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(QuilError::Crypto(format!(
            "pqnoise frame too large: {} > {}",
            len, MAX_FRAME
        )));
    }
    let mut data = vec![0u8; len];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|e| QuilError::Crypto(format!("pqnoise frame read: {}", e)))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sntrup761_kem_roundtrip() {
        let kp = Sntrup761::genkey().unwrap();
        let mut rng = clatter::rand_core::OsRng;
        let (ct, ss1) = Sntrup761::encapsulate(kp.public.as_slice(), &mut rng).unwrap();
        let ss2 = Sntrup761::decapsulate(ct.as_slice(), kp.secret.as_slice()).unwrap();
        assert_eq!(ss1.as_slice(), ss2.as_slice());
        assert_eq!(ss1.as_slice().len(), 32);
    }

    /// Full initiator↔responder PQNoise handshake over an in-memory duplex,
    /// including Ed448 identity binding, and a round-tripped transport message.
    #[tokio::test]
    async fn pq_handshake_end_to_end() {
        // Two Ed448 identities.
        let init_seed = [7u8; 57];
        let resp_seed = [9u8; 57];
        let init_priv = ed448_rust::PrivateKey::from(init_seed);
        let resp_priv = ed448_rust::PrivateKey::from(resp_seed);
        let init_pub = ed448_rust::PublicKey::from(&init_priv).as_byte().to_vec();
        let resp_pub = ed448_rust::PublicKey::from(&resp_priv).as_byte().to_vec();

        let (mut a, mut b) = tokio::io::duplex(1 << 20);

        let init_pub_c = init_pub.clone();
        let resp_pub_c = resp_pub.clone();
        let initiator = tokio::spawn(async move {
            pq_handshake_initiator(&mut a, &init_seed, &init_pub_c)
                .await
                .map(|mut r| {
                    let ct = r.transport.send_vec(b"ping").unwrap();
                    (r.remote_public_key, ct)
                })
        });
        let responder = tokio::spawn(async move {
            let mut r = pq_handshake_responder(&mut b, &resp_seed, &resp_pub_c)
                .await
                .unwrap();
            // The initiator's first transport message follows the identity
            // exchange; read it to confirm the channel works.
            (r.remote_public_key, r.transport)
        });

        let (init_remote, ping_ct) = initiator.await.unwrap().unwrap();
        let (resp_remote, mut resp_transport) = responder.await.unwrap();

        // Each side learned the other's real Ed448 identity.
        assert_eq!(init_remote, resp_pub);
        assert_eq!(resp_remote, init_pub);

        // The forward-secret channel decrypts an application message.
        let msg = resp_transport.receive_vec(&ping_ct).unwrap();
        assert_eq!(msg, b"ping");
    }
}
