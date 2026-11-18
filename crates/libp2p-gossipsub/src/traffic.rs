//! QUILIBRIUM: an always-on hook that reports every message copy this
//! behaviour receives, forwards or publishes, so the node can count its
//! gossip traffic by topic class without the per-topic metric families.

use crate::TopicHash;

/// The point at which a message copy is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficKind {
    /// A copy received from a peer, before the duplicate check.
    Received,
    /// The first copy of a message: it passed the duplicate check.
    FirstReceived,
    /// A copy queued for a peer: our own publish or a forward.
    Sent,
    /// A message this node published, counted once however many peers it
    /// was sent to.
    Published,
}

/// Receives every observed message copy with its encoded size (the message
/// as framed in the RPC, without the RPC and transport overhead).
///
/// It runs on the behaviour's poll path, once per copy, so an implementation
/// must be cheap, must not block and must not allocate.
pub trait TrafficObserver: Send + Sync {
    /// One copy of a message with payload `data` on `topic`, `bytes` long
    /// encoded, observed as `kind`.
    fn observe(&self, kind: TrafficKind, topic: &TopicHash, data: &[u8], bytes: usize);
}
