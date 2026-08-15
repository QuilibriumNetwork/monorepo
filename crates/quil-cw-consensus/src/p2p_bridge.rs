//! Channel-backed commonware-p2p `Sender`/`Receiver` bridging simplex's three
//! consensus channels onto the node's existing `:8340` mTLS transport (P2c).
//!
//! simplex's `engine.start(vote, certificate, resolver)` wants a
//! `(Sender, Receiver)` pair per channel. Rather than adopt commonware's own
//! authenticated networking, we implement the two traits over plain channels:
//!
//! - **Outbound**: `Sender::send` pushes an [`Outbound`] `{channel, recipients,
//!   bytes}` onto a shared queue the node drains and fans out over `:8340`
//!   `SubmitGlobalConsensus` (tagging the channel id so the peer demuxes).
//! - **Inbound**: the node feeds each demuxed `:8340` message into the matching
//!   channel's `inbound_tx`; [`ChannelReceiver`] yields it to the engine.
//!
//! So the mTLS transport, committee endpoint map, and connection reuse stay in
//! the node (DirectGlobalConsensusPublisher); this is just the trait shim.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Buf as _;
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::PublicKey;
use commonware_p2p::{CheckedSender, LimitedSender, Receiver, Recipients};
pub use commonware_p2p::Message;
use commonware_runtime::{IoBuf, IoBufs};
use tokio::sync::mpsc;

/// An outbound consensus message the node must deliver over `:8340`.
pub struct Outbound<P> {
    /// simplex channel id: 0=vote, 1=certificate, 2=resolver.
    pub channel: u64,
    /// Committee members to deliver to (already expanded from `Recipients`).
    pub recipients: Vec<P>,
    /// The encoded simplex message.
    pub bytes: Vec<u8>,
    /// simplex priority hint.
    pub priority: bool,
}

/// Error yielded when the inbound channel closes.
#[derive(Debug)]
pub struct Closed;
impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "p2p bridge inbound channel closed")
    }
}
impl std::error::Error for Closed {}

/// commonware-p2p `Sender` that enqueues outbound messages for the node.
pub struct ChannelSender<P> {
    channel: u64,
    peers: Arc<[P]>,
    out: mpsc::UnboundedSender<Outbound<P>>,
}

impl<P> Clone for ChannelSender<P> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel,
            peers: self.peers.clone(),
            out: self.out.clone(),
        }
    }
}

impl<P: PublicKey> LimitedSender for ChannelSender<P> {
    type PublicKey = P;
    type Checked<'a>
        = ChannelCheckedSender<P>
    where
        Self: 'a;

    fn check(&mut self, recipients: Recipients<P>) -> Result<Self::Checked<'_>, SystemTime> {
        // No rate limiting on the consensus committee (small, authenticated set).
        let recipients = match recipients {
            Recipients::All => self.peers.iter().cloned().collect(),
            Recipients::Some(r) => r,
            Recipients::One(r) => vec![r],
        };
        Ok(ChannelCheckedSender {
            channel: self.channel,
            recipients,
            out: self.out.clone(),
        })
    }
}

// `Sender` is auto-implemented for any `LimitedSender` via a blanket impl.

/// Checked sender returned by [`ChannelSender`].
pub struct ChannelCheckedSender<P> {
    channel: u64,
    recipients: Vec<P>,
    out: mpsc::UnboundedSender<Outbound<P>>,
}

impl<P: PublicKey> CheckedSender for ChannelCheckedSender<P> {
    type PublicKey = P;

    fn recipients(&self) -> Vec<P> {
        self.recipients.clone()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let mut bufs: IoBufs = message.into();
        let bytes = bufs.copy_to_bytes(bufs.remaining()).to_vec();
        let _ = self.out.send(Outbound {
            channel: self.channel,
            recipients: self.recipients,
            bytes,
            priority,
        });
        Unreliable::new(Feedback::Ok)
    }
}

/// commonware-p2p `Receiver` that yields messages the node fed in.
#[derive(Debug)]
pub struct ChannelReceiver<P> {
    rx: mpsc::UnboundedReceiver<Message<P>>,
}

impl<P: PublicKey> Receiver for ChannelReceiver<P> {
    type Error = Closed;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<P>, Self::Error> {
        self.rx.recv().await.ok_or(Closed)
    }
}

/// A wired-up channel: the `(sender, receiver)` pair for `engine.start`, plus
/// the `inbound_tx` the node uses to deliver demuxed `:8340` messages.
pub struct P2pChannel<P> {
    pub sender: ChannelSender<P>,
    pub receiver: ChannelReceiver<P>,
    /// Node feeds `(from_pubkey, IoBuf)` here for messages received on this channel.
    pub inbound_tx: mpsc::UnboundedSender<Message<P>>,
}

/// Build one simplex channel bound to the shared outbound queue.
pub fn build_channel<P: PublicKey>(
    channel: u64,
    peers: Arc<[P]>,
    out: mpsc::UnboundedSender<Outbound<P>>,
) -> P2pChannel<P> {
    let (inbound_tx, rx) = mpsc::unbounded_channel();
    P2pChannel {
        sender: ChannelSender { channel, peers, out },
        receiver: ChannelReceiver { rx },
        inbound_tx,
    }
}

/// Helper for the node's inbound path: wrap raw bytes + sender into a `Message`.
pub fn inbound_message<P: PublicKey>(from: P, bytes: Vec<u8>) -> Message<P> {
    (from, IoBuf::from(bytes))
}

/// No-op `Blocker`: the global committee is a small, mTLS-authenticated set, so
/// there is no adversarial peer to disconnect (blocking is handled at the mTLS
/// layer, not by consensus).
pub struct NoopBlocker<P>(std::marker::PhantomData<P>);

impl<P> Default for NoopBlocker<P> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}
impl<P> Clone for NoopBlocker<P> {
    fn clone(&self) -> Self {
        Self(std::marker::PhantomData)
    }
}
impl<P: PublicKey> commonware_p2p::Blocker for NoopBlocker<P> {
    type PublicKey = P;
    fn block(&mut self, _peer: P) -> Feedback {
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_base::{FalconPrivateKey, FalconPublicKey};
    // Only the tests call `ChannelSender::send` through the trait; the module
    // itself implements it, so the import belongs here rather than at the top.
    use commonware_p2p::Sender as _;
    use commonware_cryptography::Signer as _;
    use commonware_math::algebra::Random;

    fn pk() -> FalconPublicKey {
        FalconPrivateKey::random(commonware_utils::test_rng()).public_key()
    }

    #[test]
    fn outbound_enqueues_bytes_and_recipients() {
        let a = pk();
        let b = pk();
        let peers: Arc<[FalconPublicKey]> = Arc::from(vec![a.clone(), b.clone()]);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Outbound<FalconPublicKey>>();
        let mut ch = build_channel(0, peers.clone(), out_tx);

        // Sender::send (default) → check → CheckedSender::send.
        let sent = ch.sender.send(Recipients::All, b"vote-msg".to_vec(), true);
        assert_eq!(sent.len(), 2, "All expands to the committee");

        let msg = out_rx.try_recv().expect("enqueued");
        assert_eq!(msg.channel, 0);
        assert_eq!(msg.bytes, b"vote-msg");
        assert_eq!(msg.recipients.len(), 2);
        assert!(msg.priority);
    }

    #[test]
    fn inbound_delivers_to_receiver() {
        let a = pk();
        let peers: Arc<[FalconPublicKey]> = Arc::from(vec![a.clone()]);
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut ch = build_channel(1, peers, out_tx);

        ch.inbound_tx
            .send(inbound_message(a.clone(), b"cert-msg".to_vec()))
            .unwrap();

        let (from, buf) = futures::executor::block_on(ch.receiver.recv()).expect("recv");
        assert_eq!(from, a);
        assert_eq!(buf.as_ref(), b"cert-msg");
    }
}
