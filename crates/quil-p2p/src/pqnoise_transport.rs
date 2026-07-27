//! libp2p security transport over the post-quantum PQNoise handshake.
//!
//! This is the libp2p `SecurityUpgrade` that replaces `libp2p::noise::Config`
//! (classical `Noise_XX_25519`) on the TCP path with a **forward-secret,
//! pure-NTRU** channel. It mirrors libp2p-noise's structure — a
//! [`asynchronous_codec::Framed`] carrying length-delimited AEAD frames, wrapped
//! by an [`PqOutput`] that buffers plaintext across `poll_read`/`poll_write` —
//! but the session is clatter's [`TransportState`] (ChaCha20-Poly1305 + SHA-256)
//! established by the [`crate::pqnoise`] `pqxx` handshake over sntrup761.
//!
//! **Identity binding is key-type-agnostic.** After the KEM handshake, each side
//! signs the channel-binding handshake hash with its libp2p identity key
//! (`Keypair::sign`) and sends its `PublicKey::encode_protobuf()` — so this works
//! unchanged for Ed448 today and Falcon (KeyType=5) once identities migrate. The
//! remote `PeerId` is derived from the verified identity key.
//!
//! Wire is a new Rust-only protocol id (`/quilibrium/pqnoise/sntrup761/1.0.0`),
//! consistent with the re-substrate hard fork.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use asynchronous_codec::{Decoder, Encoder, Framed};
use bytes::{Buf, Bytes, BytesMut};
use futures::{ready, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, Sink, Stream};

use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256;
use clatter::handshakepattern::noise_pqxx;
use clatter::traits::{Handshaker, Kem};
use clatter::transportstate::TransportState;
use clatter::PqHandshake;

use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p::core::UpgradeInfo;
use libp2p::identity::{Keypair, PeerId, PublicKey};

use crate::pqnoise::Sntrup761;

/// Negotiated libp2p protocol id for the PQ transport.
pub const PROTOCOL_ID: &str = "/quilibrium/pqnoise/sntrup761/1.0.0";

/// Domain separation for the identity signature over the handshake hash.
const ID_SIG_PREFIX: &[u8] = b"quilibrium-pqnoise-static-key:";

/// AEAD tag length (ChaCha20-Poly1305).
const TAG_LEN: usize = 16;
/// Max plaintext per transport frame (leaves room for the tag under clatter's
/// 65535-byte message ceiling, with headroom).
const MAX_FRAME_LEN: usize = 64 * 1024 - 1024;

type Handshake = PqHandshake<Sntrup761, Sntrup761, ChaChaPoly, Sha256>;
type Session = TransportState<ChaChaPoly, Sha256>;

/// Errors from the PQNoise security upgrade.
#[derive(Debug, thiserror::Error)]
pub enum PqNoiseError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("pqnoise handshake: {0}")]
    Handshake(String),
    #[error("identity: {0}")]
    Identity(String),
}

/// libp2p security-transport configuration for PQNoise. Constructed from the
/// node's libp2p identity keypair; pass `PqNoiseConfig::new` to `with_tcp`.
#[derive(Clone)]
pub struct PqNoiseConfig {
    keypair: Keypair,
}

impl PqNoiseConfig {
    pub fn new(identity: &Keypair) -> Result<Self, PqNoiseError> {
        Ok(Self {
            keypair: identity.clone(),
        })
    }
}

impl UpgradeInfo for PqNoiseConfig {
    type Info = &'static str;
    type InfoIter = std::iter::Once<&'static str>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(PROTOCOL_ID)
    }
}

impl<T> InboundConnectionUpgrade<T> for PqNoiseConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, PqOutput<T>);
    type Error = PqNoiseError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move { upgrade(self.keypair, socket, false).await }.boxed()
    }
}

impl<T> OutboundConnectionUpgrade<T> for PqNoiseConfig
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (PeerId, PqOutput<T>);
    type Error = PqNoiseError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        async move { upgrade(self.keypair, socket, true).await }.boxed()
    }
}

/// Run the full upgrade: `pqxx` KEM handshake → identity binding → secured I/O.
///
/// Public so transports outside libp2p (the `:8340` tonic/gRPC path) can reuse
/// the exact same sntrup761 PQNoise handshake + identity binding. `initiator`
/// is the dialer (client); the responder passes `false`. `socket` is any
/// `futures`-I/O stream — a tokio stream adapts via `tokio_util::compat`.
pub async fn upgrade<T>(
    keypair: Keypair,
    mut socket: T,
    initiator: bool,
) -> Result<(PeerId, PqOutput<T>), PqNoiseError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. PQNoise pqxx handshake (forward secrecy via ephemeral sntrup761 KEM).
    let static_kem = Sntrup761::genkey()
        .map_err(|e| PqNoiseError::Handshake(format!("sntrup761 keygen: {:?}", e)))?;
    let mut hs = Handshake::new(noise_pqxx(), &[], initiator, Some(static_kem), None, None, None)
        .map_err(|e| PqNoiseError::Handshake(format!("{:?}", e)))?;

    let mut buf = vec![0u8; clatter::constants::MAX_MESSAGE_LEN];
    let mut my_turn = initiator;
    while !hs.is_finished() {
        if my_turn {
            let n = hs
                .write_message(&[], &mut buf)
                .map_err(|e| PqNoiseError::Handshake(format!("write: {:?}", e)))?;
            write_hs_frame(&mut socket, &buf[..n]).await?;
        } else {
            let msg = read_hs_frame(&mut socket).await?;
            hs.read_message(&msg, &mut buf)
                .map_err(|e| PqNoiseError::Handshake(format!("read: {:?}", e)))?;
        }
        my_turn = !my_turn;
    }

    let mut session = hs
        .finalize()
        .map_err(|e| PqNoiseError::Handshake(format!("finalize: {:?}", e)))?;
    let hash = session.get_handshake_hash().as_slice().to_vec();

    // 2. Identity binding over the now-encrypted session (before wrapping in the
    //    stream codec). Initiator authenticates first; responder verifies first.
    let our_payload = build_identity_payload(&keypair, &hash)?;
    let remote_peer_id = if initiator {
        send_encrypted(&mut socket, &mut session, &our_payload).await?;
        let peer_payload = recv_encrypted(&mut socket, &mut session).await?;
        verify_identity_payload(&peer_payload, &hash)?
    } else {
        let peer_payload = recv_encrypted(&mut socket, &mut session).await?;
        let id = verify_identity_payload(&peer_payload, &hash)?;
        send_encrypted(&mut socket, &mut session, &our_payload).await?;
        id
    };

    // 3. Hand the socket + session to the length-delimited AEAD stream.
    let framed = Framed::new(socket, PqCodec::new(session));
    Ok((remote_peer_id, PqOutput::new(framed)))
}

// ---------------------------------------------------------------------------
// Identity payload (key-type-agnostic: Ed448 today, Falcon later).
// Layout: [u32 pk_len][pk protobuf][u32 sig_len][sig].
// ---------------------------------------------------------------------------

fn build_identity_payload(keypair: &Keypair, hash: &[u8]) -> Result<Vec<u8>, PqNoiseError> {
    let pk = keypair.public().encode_protobuf();
    let mut to_sign = Vec::with_capacity(ID_SIG_PREFIX.len() + hash.len());
    to_sign.extend_from_slice(ID_SIG_PREFIX);
    to_sign.extend_from_slice(hash);
    let sig = keypair
        .sign(&to_sign)
        .map_err(|e| PqNoiseError::Identity(format!("sign: {}", e)))?;
    let mut out = Vec::with_capacity(8 + pk.len() + sig.len());
    out.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    out.extend_from_slice(&pk);
    out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

fn verify_identity_payload(payload: &[u8], hash: &[u8]) -> Result<PeerId, PqNoiseError> {
    let take_u32 = |p: &[u8], at: usize| -> Result<usize, PqNoiseError> {
        p.get(at..at + 4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
            .ok_or_else(|| PqNoiseError::Identity("truncated identity payload".into()))
    };
    let pk_len = take_u32(payload, 0)?;
    let pk_bytes = payload
        .get(4..4 + pk_len)
        .ok_or_else(|| PqNoiseError::Identity("truncated pubkey".into()))?;
    let sig_off = 4 + pk_len;
    let sig_len = take_u32(payload, sig_off)?;
    let sig = payload
        .get(sig_off + 4..sig_off + 4 + sig_len)
        .ok_or_else(|| PqNoiseError::Identity("truncated signature".into()))?;

    let pk = PublicKey::try_decode_protobuf(pk_bytes)
        .map_err(|e| PqNoiseError::Identity(format!("decode pubkey: {}", e)))?;
    let mut to_verify = Vec::with_capacity(ID_SIG_PREFIX.len() + hash.len());
    to_verify.extend_from_slice(ID_SIG_PREFIX);
    to_verify.extend_from_slice(hash);
    if !pk.verify(&to_verify, sig) {
        return Err(PqNoiseError::Identity("identity signature invalid".into()));
    }
    Ok(pk.to_peer_id())
}

// ---------------------------------------------------------------------------
// Framing helpers (u16 length prefix). Handshake frames are plaintext KEM
// messages; the two `_encrypted` helpers run one transport message through the
// session before the stream codec takes over.
// ---------------------------------------------------------------------------

async fn write_hs_frame<T: AsyncWrite + Unpin>(s: &mut T, data: &[u8]) -> io::Result<()> {
    s.write_all(&(data.len() as u16).to_be_bytes()).await?;
    s.write_all(data).await?;
    s.flush().await
}

async fn read_hs_frame<T: AsyncRead + Unpin>(s: &mut T) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut data).await?;
    Ok(data)
}

async fn send_encrypted<T: AsyncWrite + Unpin>(
    s: &mut T,
    session: &mut Session,
    plaintext: &[u8],
) -> Result<(), PqNoiseError> {
    let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
    let n = session
        .send(plaintext, &mut buf)
        .map_err(|e| PqNoiseError::Handshake(format!("encrypt: {:?}", e)))?;
    write_hs_frame(s, &buf[..n]).await?;
    Ok(())
}

async fn recv_encrypted<T: AsyncRead + Unpin>(
    s: &mut T,
    session: &mut Session,
) -> Result<Vec<u8>, PqNoiseError> {
    let ct = read_hs_frame(s).await?;
    let mut out = vec![0u8; ct.len()];
    let n = session
        .receive(&ct, &mut out)
        .map_err(|e| PqNoiseError::Handshake(format!("decrypt: {:?}", e)))?;
    out.truncate(n);
    Ok(out)
}

// ---------------------------------------------------------------------------
// PqCodec: per-frame AEAD over the clatter transport session. Mirrors
// libp2p-noise's `Codec<TransportState>`.
// ---------------------------------------------------------------------------

/// Length-delimited AEAD codec over a clatter transport session.
pub struct PqCodec {
    session: Session,
    encrypt_buffer: Vec<u8>,
}

impl PqCodec {
    fn new(session: Session) -> Self {
        Self {
            session,
            encrypt_buffer: Vec::new(),
        }
    }
}

impl Encoder for PqCodec {
    type Item<'a> = &'a [u8];
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let out_len = item.len() + TAG_LEN;
        self.encrypt_buffer.resize(out_len, 0);
        let n = self
            .session
            .send(item, &mut self.encrypt_buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
        dst.reserve(2 + n);
        dst.extend_from_slice(&(n as u16).to_be_bytes());
        dst.extend_from_slice(&self.encrypt_buffer[..n]);
        Ok(())
    }
}

impl Decoder for PqCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([src[0], src[1]]) as usize;
        if src.len() - 2 < len {
            return Ok(None);
        }
        src.advance(2);
        let ct = src.split_to(len);
        let mut out = BytesMut::zeroed(len);
        let n = self
            .session
            .receive(&ct, &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
        Ok(Some(out.split_to(n).freeze()))
    }
}

// ---------------------------------------------------------------------------
// PqOutput: the secured stream handed back to libp2p. Structure copied from
// libp2p-noise's `Output<T>` — buffers plaintext across poll_read/poll_write.
// ---------------------------------------------------------------------------

/// A live post-quantum secured stream. Implements `futures::AsyncRead`/`AsyncWrite`.
pub struct PqOutput<T> {
    io: Framed<T, PqCodec>,
    recv_buffer: Bytes,
    recv_offset: usize,
    send_buffer: Vec<u8>,
    send_offset: usize,
}

impl<T> PqOutput<T> {
    fn new(io: Framed<T, PqCodec>) -> Self {
        Self {
            io,
            recv_buffer: Bytes::new(),
            recv_offset: 0,
            send_buffer: Vec::new(),
            send_offset: 0,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PqOutput<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let len = self.recv_buffer.len();
            let off = self.recv_offset;
            if len > 0 {
                let n = std::cmp::min(len - off, buf.len());
                buf[..n].copy_from_slice(&self.recv_buffer[off..off + n]);
                self.recv_offset += n;
                if len == self.recv_offset {
                    self.recv_buffer = Bytes::new();
                }
                return Poll::Ready(Ok(n));
            }
            match Pin::new(&mut self.io).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(frame))) => {
                    self.recv_buffer = frame;
                    self.recv_offset = 0;
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PqOutput<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = Pin::into_inner(self);
        let mut io = Pin::new(&mut this.io);

        if this.send_offset == MAX_FRAME_LEN {
            ready!(io.as_mut().poll_ready(cx))?;
            io.as_mut().start_send(&this.send_buffer[..])?;
            this.send_offset = 0;
        }

        let off = this.send_offset;
        let n = std::cmp::min(MAX_FRAME_LEN, off.saturating_add(buf.len()));
        this.send_buffer.resize(n, 0u8);
        let n = std::cmp::min(MAX_FRAME_LEN - off, buf.len());
        this.send_buffer[off..off + n].copy_from_slice(&buf[..n]);
        this.send_offset += n;

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        let mut io = Pin::new(&mut this.io);

        if this.send_offset > 0 {
            ready!(io.as_mut().poll_ready(cx))?;
            io.as_mut().start_send(&this.send_buffer[..this.send_offset])?;
            this.send_offset = 0;
        }
        io.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full libp2p-style upgrade over an in-memory duplex: both sides derive
    /// the other's PeerId from its Ed448 identity, then exchange encrypted
    /// application data through the secured `PqOutput` stream.
    #[tokio::test]
    async fn pqnoise_upgrade_and_stream() {
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let init_kp = Keypair::generate_ed448(); // Quilibrium's identity type
        let resp_kp = Keypair::generate_ed448();
        let init_id = init_kp.public().to_peer_id();
        let resp_id = resp_kp.public().to_peer_id();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (a, b) = (a.compat(), b.compat());

        let init = tokio::spawn(async move { upgrade(init_kp, a, true).await });
        let resp = tokio::spawn(async move { upgrade(resp_kp, b, false).await });

        let (init_peer, mut init_io) = init.await.unwrap().unwrap();
        let (resp_peer, mut resp_io) = resp.await.unwrap().unwrap();

        // Mutual identity authentication.
        assert_eq!(init_peer, resp_id);
        assert_eq!(resp_peer, init_id);

        // Encrypted application stream round-trips.
        init_io.write_all(b"pq-hello").await.unwrap();
        init_io.flush().await.unwrap();
        let mut got = [0u8; 8];
        resp_io.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pq-hello");
    }
}
