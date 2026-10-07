//! Point-to-point delivery of one bitmask's message to one connected peer.
//!
//! App-shard consensus addresses its resolver traffic (requests for missing
//! certificates and their responses) to a single committee member, but the
//! only transport was the shard's gossip topic, so every subscriber received
//! every response. On one regular node that was 163–171 Mbit/s of resolver
//! responses, 98% repeating content it had already seen (2026-10-04 report).
//!
//! A direct message is delivered to the application exactly as a gossip
//! message on its bitmask would be ([`crate::ReceivedMessage`]), with `from`
//! the authenticated connection's peer. The receiver accepts it only for a
//! bitmask it has allowed ([`crate::P2PHandle::allow_direct`]); otherwise it
//! answers "refused" and the sender falls back to gossip. A peer without the
//! protocol (an older build) fails negotiation and is remembered for a while
//! so senders go straight to gossip. Only already-connected peers are used:
//! no dial, so delivery never waits on NAT traversal.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;

/// Largest bitmask a direct message may name.
pub const MAX_DIRECT_BITMASK: usize = 256;
/// Largest payload a direct message may carry.
pub const MAX_DIRECT_DATA: usize = 8 * 1024 * 1024;
/// How long a direct send may take before it is reported failed.
pub const DIRECT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a peer that lacks the protocol is not asked again.
pub const UNSUPPORTED_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(600);

/// The direct-delivery protocol on `network`.
pub fn direct_protocol(network: u8) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/quilibrium/direct/1.0.0/{network}"))
        .expect("valid protocol name")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRequest {
    pub bitmask: Vec<u8>,
    pub data: Vec<u8>,
}

/// What became of one direct send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOutcome {
    /// The peer accepted it for delivery.
    Delivered,
    /// The peer does not take direct messages on that bitmask.
    Refused,
    /// No connection to the peer; nothing was sent.
    NotConnected,
    /// The peer lacks the protocol (an older build).
    Unsupported,
    /// Timed out, the connection closed, or an I/O error.
    Failed,
}

/// Counters for direct delivery, sent and received.
#[derive(Default)]
pub struct DirectStats {
    pub delivered: AtomicU64,
    pub refused: AtomicU64,
    pub not_connected: AtomicU64,
    pub unsupported: AtomicU64,
    pub failed: AtomicU64,
    /// Sends the caller then made over gossip instead.
    pub fallbacks: AtomicU64,
    pub received: AtomicU64,
    pub received_refused: AtomicU64,
}

/// A point-in-time copy of [`DirectStats`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DirectStatsSnapshot {
    pub delivered: u64,
    pub refused: u64,
    pub not_connected: u64,
    pub unsupported: u64,
    pub failed: u64,
    pub fallbacks: u64,
    pub received: u64,
    pub received_refused: u64,
}

impl DirectStats {
    pub fn note(&self, outcome: DirectOutcome) {
        let counter = match outcome {
            DirectOutcome::Delivered => &self.delivered,
            DirectOutcome::Refused => &self.refused,
            DirectOutcome::NotConnected => &self.not_connected,
            DirectOutcome::Unsupported => &self.unsupported,
            DirectOutcome::Failed => &self.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DirectStatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        DirectStatsSnapshot {
            delivered: get(&self.delivered),
            refused: get(&self.refused),
            not_connected: get(&self.not_connected),
            unsupported: get(&self.unsupported),
            failed: get(&self.failed),
            fallbacks: get(&self.fallbacks),
            received: get(&self.received),
            received_refused: get(&self.received_refused),
        }
    }
}

/// Request: `u32 len ‖ bitmask ‖ u32 len ‖ data`. Response: one byte, 1 when
/// accepted.
#[derive(Debug, Clone, Default)]
pub struct DirectCodec;

async fn read_prefixed<T: AsyncRead + Unpin + Send>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "direct message field too large"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_prefixed<T: AsyncWrite + Unpin + Send>(io: &mut T, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "direct message field too large"))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(bytes).await
}

#[async_trait::async_trait]
impl libp2p::request_response::Codec for DirectCodec {
    type Protocol = StreamProtocol;
    type Request = DirectRequest;
    type Response = bool;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<DirectRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bitmask = read_prefixed(io, MAX_DIRECT_BITMASK).await?;
        let data = read_prefixed(io, MAX_DIRECT_DATA).await?;
        Ok(DirectRequest { bitmask, data })
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<bool>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut accepted = [0u8; 1];
        io.read_exact(&mut accepted).await?;
        Ok(accepted[0] == 1)
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: DirectRequest) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if req.bitmask.len() > MAX_DIRECT_BITMASK || req.data.len() > MAX_DIRECT_DATA {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "direct message too large"));
        }
        write_prefixed(io, &req.bitmask).await?;
        write_prefixed(io, &req.data).await?;
        io.flush().await
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, accepted: bool) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[u8::from(accepted)]).await?;
        io.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec as _;

    #[test]
    fn requests_and_responses_round_trip_and_oversized_fields_are_refused() {
        futures::executor::block_on(async {
            let protocol = direct_protocol(0);
            let request = DirectRequest { bitmask: vec![1, 2, 3], data: vec![9; 1000] };
            let mut wire = futures::io::Cursor::new(Vec::new());
            DirectCodec.write_request(&protocol, &mut wire, request.clone()).await.unwrap();
            let mut read = futures::io::Cursor::new(wire.into_inner());
            assert_eq!(DirectCodec.read_request(&protocol, &mut read).await.unwrap(), request);

            for accepted in [true, false] {
                let mut wire = futures::io::Cursor::new(Vec::new());
                DirectCodec.write_response(&protocol, &mut wire, accepted).await.unwrap();
                let mut read = futures::io::Cursor::new(wire.into_inner());
                assert_eq!(DirectCodec.read_response(&protocol, &mut read).await.unwrap(), accepted);
            }

            let mut forged = (u32::MAX).to_be_bytes().to_vec();
            forged.extend_from_slice(&[0; 8]);
            let mut read = futures::io::Cursor::new(forged);
            assert!(DirectCodec.read_request(&protocol, &mut read).await.is_err(), "a huge length is refused before allocating");
            let oversized = DirectRequest { bitmask: vec![0; MAX_DIRECT_BITMASK + 1], data: Vec::new() };
            let mut wire = futures::io::Cursor::new(Vec::new());
            assert!(DirectCodec.write_request(&protocol, &mut wire, oversized).await.is_err());
        });
    }

    #[test]
    fn outcomes_are_counted() {
        let stats = DirectStats::default();
        stats.note(DirectOutcome::Delivered);
        stats.note(DirectOutcome::Delivered);
        stats.note(DirectOutcome::Unsupported);
        let snapshot = stats.snapshot();
        assert_eq!((snapshot.delivered, snapshot.unsupported, snapshot.failed), (2, 1, 0));
    }
}
