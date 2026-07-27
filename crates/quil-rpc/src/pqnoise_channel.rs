//! PQNoise channel for the `:8340` tonic/gRPC transport.
//!
//! Reuses the exact sntrup761 PQNoise handshake + Ed448/Falcon identity
//! binding the libp2p transport uses ([`quil_p2p::pq_upgrade`]), adapted to
//! **tokio** I/O so tonic can run gRPC over the secured channel — replacing
//! the classical Ed448-mTLS (rustls) path on `:8340`.
//!
//! The handshake is symmetric: the dialer is the initiator, the accept side
//! the responder. Both authenticate by signing the channel-binding handshake
//! hash with their Ed448 identity key, so the verified [`PeerId`] each side
//! learns is the SAME identity the archive/genesis allowlist already keys on
//! (`quil_p2p::peer_id_from_ed448_pubkey`) — the mTLS SAN + proof-of-possession
//! collapse into one identity-over-hash signature.
//!
//! I/O adaptation: a tokio [`TcpStream`] becomes `futures` I/O via
//! `TokioAsyncReadCompatExt::compat`, the handshake runs, and the resulting
//! `futures`-I/O [`PqOutput`] becomes tokio I/O again via
//! `FuturesAsyncReadCompatExt::compat` for tonic.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use quil_p2p::{pq_upgrade, Keypair, PeerId, PqOutput};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tonic::transport::server::Connected;

/// A secured `:8340` stream: tokio I/O over the sntrup761 PQNoise AEAD session.
pub type PqTokioStream = Compat<PqOutput<Compat<TcpStream>>>;

/// Connection info tonic inserts into every request's extensions for a PQNoise
/// server connection — the handshake-verified peer identity. The peer-auth
/// interceptor reads this to build an `AuthenticatedPeer`, exactly as it reads
/// `TlsConnectInfo` on the mTLS path.
#[derive(Clone, Debug)]
pub struct PqConnectInfo {
    pub peer_id: PeerId,
}

/// Server-side secured stream: the PQNoise tokio stream plus the verified peer
/// identity, so tonic's [`Connected`] machinery can surface the peer to the
/// auth interceptor (the role the TLS client cert played).
pub struct PqServerStream {
    inner: PqTokioStream,
    peer_id: PeerId,
}

impl PqServerStream {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}

impl Connected for PqServerStream {
    type ConnectInfo = PqConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        PqConnectInfo { peer_id: self.peer_id }
    }
}

// `PqTokioStream` (a `Compat` over the buffered `PqOutput`) is `Unpin`, so the
// wrapper delegates I/O by re-pinning the inner stream — no pin projection.
impl AsyncRead for PqServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PqServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Build the node's libp2p FALCON keypair from its 1281-byte q-prover-key
/// signing key, so the PQNoise `:8340` identity is the same Falcon network
/// identity the p2p transport and the allowlist use.
fn keypair_from_falcon(falcon_signing_key: &[u8]) -> io::Result<Keypair> {
    Keypair::falcon_from_bytes(falcon_signing_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("falcon keypair: {e}")))
}

fn pq_to_io(e: quil_p2p::PqNoiseError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("pqnoise: {e}"))
}

/// Client (dialer) side: run the PQNoise handshake as the initiator over an
/// already-connected TCP stream. Returns the verified server [`PeerId`] and
/// the secured tokio stream for gRPC.
pub async fn pq_client_handshake(
    tcp: TcpStream,
    falcon_signing_key: &[u8],
) -> io::Result<(PeerId, PqTokioStream)> {
    let _ = tcp.set_nodelay(true);
    let kp = keypair_from_falcon(falcon_signing_key)?;
    let (peer, pq) = pq_upgrade(kp, tcp.compat(), /* initiator */ true)
        .await
        .map_err(pq_to_io)?;
    Ok((peer, pq.compat()))
}

/// Server (accept) side: run the PQNoise handshake as the responder over an
/// accepted TCP stream. Returns the verified client [`PeerId`] and the secured
/// tokio stream for gRPC. Callers gate the `PeerId` against the archive/genesis
/// allowlist (what the mTLS cert SAN + PoP enforced).
pub async fn pq_server_handshake(tcp: TcpStream, falcon_signing_key: &[u8]) -> io::Result<PqServerStream> {
    let _ = tcp.set_nodelay(true);
    let kp = keypair_from_falcon(falcon_signing_key)?;
    let (peer_id, pq) = pq_upgrade(kp, tcp.compat(), /* initiator */ false)
        .await
        .map_err(pq_to_io)?;
    Ok(PqServerStream { inner: pq.compat(), peer_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// End-to-end over a real loopback TCP socket: server binds, client dials,
    /// both complete the sntrup761 PQNoise handshake, learn each other's Ed448
    /// PeerId, and round-trip gRPC-shaped bytes through the encrypted channel.
    #[tokio::test]
    async fn pq_8340_loopback_round_trips_over_tcp() {
        let server_seed = [0x11u8; 57];
        let client_seed = [0x22u8; 57];

        // Expected identities (same derivation the allowlist uses).
        let server_id = keypair_from_ed448_seed(&server_seed)
            .unwrap()
            .public()
            .to_peer_id();
        let client_id = keypair_from_ed448_seed(&client_seed)
            .unwrap()
            .public()
            .to_peer_id();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut io = pq_server_handshake(tcp, &server_seed).await.unwrap();
            let peer = io.peer_id();
            // Echo one framed request back.
            let mut buf = [0u8; 8];
            io.read_exact(&mut buf).await.unwrap();
            io.write_all(&buf).await.unwrap();
            io.flush().await.unwrap();
            // The Connected impl surfaces the same verified identity.
            assert_eq!(io.connect_info().peer_id, peer);
            peer
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (got_server_id, mut io) = pq_client_handshake(tcp, &client_seed).await.unwrap();
        io.write_all(b"grpc-req").await.unwrap();
        io.flush().await.unwrap();
        let mut echo = [0u8; 8];
        io.read_exact(&mut echo).await.unwrap();

        assert_eq!(&echo, b"grpc-req", "encrypted round-trip over pqnoise");
        assert_eq!(got_server_id, server_id, "client authenticated the server's Ed448 id");
        let got_client_id = server.await.unwrap();
        assert_eq!(got_client_id, client_id, "server authenticated the client's Ed448 id");
    }
}
