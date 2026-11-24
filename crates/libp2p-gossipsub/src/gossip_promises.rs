// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::collections::{HashMap, VecDeque};

use libp2p_identity::PeerId;
use web_time::Instant;

use crate::{peer_score::RejectReason, MessageId, ValidationError};

/// Tracks recently sent `IWANT` messages and checks if peers respond to them.
#[derive(Default)]
pub(crate) struct GossipPromises {
    /// Stores for each tracked message id and peer the instant when this promise expires.
    ///
    /// If the peer didn't respond until then we consider the promise as broken and penalize the
    /// peer.
    promises: HashMap<MessageId, HashMap<PeerId, Instant>>,
    /// QUILIBRIUM: for a message with an open promise, the peers that announced it after we
    /// asked another, oldest first, at most [`MAX_FALLBACK_ANNOUNCERS`]. When every promise for
    /// it breaks, the next is asked ([`GossipPromises::take_unserved_fallbacks`]): a mesh peer
    /// announces a message once, so without this a message whose announcer never answers
    /// would wait for a later IHAVE from heartbeat gossip, if one comes.
    fallbacks: HashMap<MessageId, VecDeque<PeerId>>,
}

/// QUILIBRIUM: the most later announcers kept per message with an open promise; a mesh holds
/// at most `mesh_n_high` (12) peers, and each kept one costs a peer id until the message
/// arrives or its promises break.
pub(crate) const MAX_FALLBACK_ANNOUNCERS: usize = 8;

impl GossipPromises {
    /// Returns true if the message id exists in the promises.
    pub(crate) fn contains(&self, message: &MessageId) -> bool {
        self.promises.contains_key(message)
    }

    /// QUILIBRIUM: whether we sent `peer` an IWANT for `message` that it has not answered.
    pub(crate) fn promised_by(&self, message: &MessageId, peer: &PeerId) -> bool {
        self.promises
            .get(message)
            .is_some_and(|peers| peers.contains_key(peer))
    }

    /// Get the peers we sent IWANT the input message id.
    pub(crate) fn peers_for_message(&self, message_id: &MessageId) -> Vec<PeerId> {
        self.promises
            .get(message_id)
            .map(|peers| peers.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Track a promise to deliver a message from a list of [`MessageId`]s we are requesting.
    pub(crate) fn add_promise(&mut self, peer: PeerId, messages: &[MessageId], expires: Instant) {
        for message_id in messages {
            // If a promise for this message id and peer already exists we don't update the expiry!
            self.promises
                .entry(message_id.clone())
                .or_default()
                .entry(peer)
                .or_insert(expires);
        }
    }

    /// QUILIBRIUM: keep `peer`, which announced `message` while a promise for it is open, to
    /// ask if every open promise for it breaks. Returns whether it was kept: not when no
    /// promise is open, when `peer` already promised it or is kept, or at
    /// [`MAX_FALLBACK_ANNOUNCERS`].
    pub(crate) fn add_fallback(&mut self, message: &MessageId, peer: PeerId) -> bool {
        if self
            .promises
            .get(message)
            .is_none_or(|peers| peers.contains_key(&peer))
        {
            return false;
        }
        let kept = self.fallbacks.entry(message.clone()).or_default();
        if kept.len() >= MAX_FALLBACK_ANNOUNCERS || kept.contains(&peer) {
            return false;
        }
        kept.push_back(peer);
        true
    }

    /// QUILIBRIUM: the later announcers of each message whose promises have all broken
    /// ([`GossipPromises::get_broken_promises`]), oldest first; the caller asks the first it
    /// can and returns the rest with [`GossipPromises::keep_fallbacks`] once it has a new
    /// promise for the message.
    pub(crate) fn take_unserved_fallbacks(&mut self) -> Vec<(MessageId, VecDeque<PeerId>)> {
        let unserved: Vec<MessageId> = self
            .fallbacks
            .keys()
            .filter(|id| !self.promises.contains_key(*id))
            .cloned()
            .collect();
        unserved
            .into_iter()
            .filter_map(|id| self.fallbacks.remove_entry(&id))
            .collect()
    }

    /// QUILIBRIUM: return the announcers not yet asked for `message`, after the caller has
    /// made a new promise for it (dropped otherwise).
    pub(crate) fn keep_fallbacks(&mut self, message: MessageId, peers: VecDeque<PeerId>) {
        if !peers.is_empty() && self.promises.contains_key(&message) {
            self.fallbacks.insert(message, peers);
        }
    }

    pub(crate) fn message_delivered(&mut self, message_id: &MessageId) {
        // Someone delivered a message, we can stop tracking all promises for it.
        self.promises.remove(message_id);
        self.fallbacks.remove(message_id);
    }

    pub(crate) fn reject_message(&mut self, message_id: &MessageId, reason: &RejectReason) {
        // QUILIBRIUM: nobody is asked again for a rejected message.
        self.fallbacks.remove(message_id);
        // A message got rejected, so we can stop tracking promises and let the score penalty apply
        // from invalid message delivery.
        // We do take exception and apply promise penalty regardless in the following cases, where
        // the peer delivered an obviously invalid message.
        match reason {
            RejectReason::ValidationError(ValidationError::InvalidSignature) => (),
            RejectReason::SelfOrigin => (),
            _ => {
                self.promises.remove(message_id);
            }
        };
    }

    /// Returns the number of broken promises for each peer who didn't follow up on an IWANT
    /// request.
    /// This should be called not too often relative to the expire times, since it iterates over
    /// the whole stored data.
    pub(crate) fn get_broken_promises(&mut self) -> HashMap<PeerId, usize> {
        let now = Instant::now();
        let mut result = HashMap::new();
        self.promises.retain(|msg, peers| {
            peers.retain(|peer_id, expires| {
                if *expires < now {
                    let count = result.entry(*peer_id).or_insert(0);
                    *count += 1;
                    tracing::debug!(
                        peer=%peer_id,
                        message=%msg,
                        "[Penalty] The peer broke the promise to deliver message in time!"
                    );
                    false
                } else {
                    true
                }
            });
            !peers.is_empty()
        });
        result
    }
}
