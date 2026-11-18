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

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{stream::Peekable, Stream, StreamExt};

use crate::types::RpcOut;

/// QUILIBRIUM: the most message bytes (published and forwarded messages) one
/// peer's queues may hold. The queues were bounded by count only, so a peer
/// that stopped reading could hold thousands of messages of up to the frame
/// size each, released only on disconnect. A message is always queued when
/// none is, so the largest message still goes out.
pub(crate) const MAX_QUEUED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// QUILIBRIUM: the bytes `rpc` holds towards [`MAX_QUEUED_MESSAGE_BYTES`].
fn queued_bytes(rpc: &RpcOut) -> usize {
    match rpc {
        RpcOut::Publish { message, .. } | RpcOut::Forward { message, .. } => {
            message.data.len()
                + message.signature.as_ref().map_or(0, Vec::len)
                + message.key.as_ref().map_or(0, Vec::len)
        }
        _ => 0,
    }
}

/// `RpcOut` sender that is priority aware.
#[derive(Debug)]
pub(crate) struct Sender {
    /// Capacity of the priority channel for `Publish` messages.
    priority_cap: usize,
    len: Arc<AtomicUsize>,
    /// QUILIBRIUM: message bytes queued, shared with the receivers.
    bytes: Arc<AtomicUsize>,
    pub(crate) priority_sender: async_channel::Sender<RpcOut>,
    pub(crate) non_priority_sender: async_channel::Sender<RpcOut>,
    priority_receiver: async_channel::Receiver<RpcOut>,
    non_priority_receiver: async_channel::Receiver<RpcOut>,
}

impl Sender {
    /// Create a RpcSender.
    pub(crate) fn new(cap: usize) -> Sender {
        // We intentionally do not bound the channel, as we still need to send control messages
        // such as `GRAFT`, `PRUNE`, `SUBSCRIBE`, and `UNSUBSCRIBE`.
        // That's also why we define `cap` and divide it by two,
        // to ensure there is capacity for both priority and non_priority messages.
        let (priority_sender, priority_receiver) = async_channel::unbounded();
        let (non_priority_sender, non_priority_receiver) = async_channel::bounded(cap / 2);
        let len = Arc::new(AtomicUsize::new(0));
        Sender {
            priority_cap: cap / 2,
            len,
            bytes: Arc::new(AtomicUsize::new(0)),
            priority_sender,
            non_priority_sender,
            priority_receiver,
            non_priority_receiver,
        }
    }

    /// Create a new Receiver to the sender.
    pub(crate) fn new_receiver(&self) -> Receiver {
        Receiver {
            priority_queue_len: self.len.clone(),
            queued_bytes: self.bytes.clone(),
            priority: Box::pin(self.priority_receiver.clone().peekable()),
            non_priority: Box::pin(self.non_priority_receiver.clone().peekable()),
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn send_message(&self, rpc: RpcOut) -> Result<(), RpcOut> {
        // QUILIBRIUM: refuse a message past the byte budget, as a full queue.
        let bytes = queued_bytes(&rpc);
        let queued = self.bytes.load(Ordering::Relaxed);
        if bytes > 0 && queued > 0 && queued.saturating_add(bytes) > MAX_QUEUED_MESSAGE_BYTES {
            return Err(rpc);
        }
        if let RpcOut::Publish { .. } = rpc {
            // Update number of publish message in queue.
            let len = self.len.load(Ordering::Relaxed);
            if len >= self.priority_cap {
                return Err(rpc);
            }
            self.len.store(len + 1, Ordering::Relaxed);
        }
        let sender = match rpc {
            RpcOut::Publish { .. }
            | RpcOut::Graft(_)
            | RpcOut::Prune(_)
            | RpcOut::Subscribe(_)
            | RpcOut::Unsubscribe(_) => &self.priority_sender,
            // QUILIBRIUM: an IDONTWANT only helps if it reaches the peer before
            // the peer sends the message, so it does not wait behind queued
            // forwards. A peer whose priority queue is already backed up gets
            // it on the bounded queue as before.
            RpcOut::IDontWant(_) if self.priority_sender.len() < self.priority_cap => {
                &self.priority_sender
            }
            RpcOut::Forward { .. } | RpcOut::IHave(_) | RpcOut::IWant(_) | RpcOut::IDontWant(_) => {
                &self.non_priority_sender
            }
        };
        // QUILIBRIUM: counted before it is queued, so the receiver never
        // releases bytes that were not added.
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        sender.try_send(rpc).map_err(|err| {
            self.bytes.fetch_sub(bytes, Ordering::Relaxed);
            err.into_inner()
        })
    }

    /// QUILIBRIUM: the number of messages in the priority queue (control
    /// messages and publishes).
    pub(crate) fn priority_len(&self) -> usize {
        self.priority_sender.len()
    }

    /// Returns the current size of the priority queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn priority_queue_len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Returns the current size of the non-priority queue.
    #[cfg(feature = "metrics")]
    pub(crate) fn non_priority_queue_len(&self) -> usize {
        self.non_priority_sender.len()
    }
}

/// `RpcOut` sender that is priority aware.
#[derive(Debug)]
pub struct Receiver {
    /// The maximum length of the priority queue.
    pub(crate) priority_queue_len: Arc<AtomicUsize>,
    /// QUILIBRIUM: message bytes queued, shared with the sender.
    pub(crate) queued_bytes: Arc<AtomicUsize>,
    /// The priority queue receiver.
    pub(crate) priority: Pin<Box<Peekable<async_channel::Receiver<RpcOut>>>>,
    /// The non priority queue receiver.
    pub(crate) non_priority: Pin<Box<Peekable<async_channel::Receiver<RpcOut>>>>,
}

impl Receiver {
    /// QUILIBRIUM: releases the bytes of a message leaving the queues.
    fn release(&self, rpc: &RpcOut) {
        self.queued_bytes
            .fetch_sub(queued_bytes(rpc), Ordering::Relaxed);
    }

    // Peek the next message in the queues and return it if its timeout has elapsed.
    // Returns `None` if there aren't any more messages on the stream or none is stale.
    pub(crate) fn poll_stale(&mut self, cx: &mut Context<'_>) -> Poll<Option<RpcOut>> {
        // Peek priority queue.
        let priority = match self.priority.as_mut().poll_peek_mut(cx) {
            Poll::Ready(Some(RpcOut::Publish {
                message: _,
                ref mut timeout,
            })) => {
                if Pin::new(timeout).poll(cx).is_ready() {
                    // Return the message.
                    let dropped = futures::ready!(self.priority.poll_next_unpin(cx))
                        .expect("There should be a message");
                    self.release(&dropped);
                    return Poll::Ready(Some(dropped));
                }
                Poll::Ready(None)
            }
            poll => poll,
        };

        let non_priority = match self.non_priority.as_mut().poll_peek_mut(cx) {
            Poll::Ready(Some(RpcOut::Forward {
                message: _,
                ref mut timeout,
            })) => {
                if Pin::new(timeout).poll(cx).is_ready() {
                    // Return the message.
                    let dropped = futures::ready!(self.non_priority.poll_next_unpin(cx))
                        .expect("There should be a message");
                    self.release(&dropped);
                    return Poll::Ready(Some(dropped));
                }
                Poll::Ready(None)
            }
            poll => poll,
        };

        match (priority, non_priority) {
            (Poll::Ready(None), Poll::Ready(None)) => Poll::Ready(None),
            _ => Poll::Pending,
        }
    }

    /// Poll queues and return true if both are empty.
    pub(crate) fn poll_is_empty(&mut self, cx: &mut Context<'_>) -> bool {
        matches!(
            (
                self.priority.as_mut().poll_peek(cx),
                self.non_priority.as_mut().poll_peek(cx),
            ),
            (Poll::Ready(None), Poll::Ready(None))
        )
    }
}

impl Stream for Receiver {
    type Item = RpcOut;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // The priority queue is first polled.
        if let Poll::Ready(rpc) = Pin::new(&mut self.priority).poll_next(cx) {
            if let Some(RpcOut::Publish { .. }) = rpc {
                self.priority_queue_len.fetch_sub(1, Ordering::Relaxed);
            }
            if let Some(rpc) = &rpc {
                self.release(rpc);
            }
            return Poll::Ready(rpc);
        }
        // Then we poll the non priority.
        let rpc = futures::ready!(Pin::new(&mut self.non_priority).poll_next(cx));
        if let Some(rpc) = &rpc {
            self.release(rpc);
        }
        Poll::Ready(rpc)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_timer::Delay;

    use super::*;
    use crate::{
        types::{Graft, IDontWant, RawMessage},
        MessageId, TopicHash,
    };

    fn forward(len: usize) -> RpcOut {
        RpcOut::Forward {
            message: RawMessage {
                source: None,
                data: vec![0; len],
                sequence_number: None,
                topic: TopicHash::from_raw("topic"),
                signature: None,
                key: None,
                validated: true,
            },
            timeout: Delay::new(Duration::from_secs(60)),
        }
    }

    /// QUILIBRIUM: a message is queued when none is, whatever its size; bytes
    /// leave the budget as their messages leave the queue; control messages
    /// are not counted.
    #[test]
    fn queued_message_bytes_are_released_on_receipt() {
        let sender = Sender::new(100);
        let mut receiver = sender.new_receiver();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        sender
            .send_message(forward(MAX_QUEUED_MESSAGE_BYTES + 1))
            .unwrap();
        assert!(sender.send_message(forward(1)).is_err());
        sender
            .send_message(RpcOut::Graft(Graft {
                topic_hash: TopicHash::from_raw("topic"),
            }))
            .unwrap();

        assert!(matches!(
            Pin::new(&mut receiver).poll_next(&mut cx),
            Poll::Ready(Some(RpcOut::Graft(_)))
        ));
        assert!(matches!(
            Pin::new(&mut receiver).poll_next(&mut cx),
            Poll::Ready(Some(RpcOut::Forward { .. }))
        ));
        assert_eq!(sender.bytes.load(Ordering::Relaxed), 0);
        sender
            .send_message(forward(MAX_QUEUED_MESSAGE_BYTES / 2))
            .unwrap();
        sender
            .send_message(forward(MAX_QUEUED_MESSAGE_BYTES / 2))
            .unwrap();
        assert!(sender.send_message(forward(1)).is_err());
    }

    /// QUILIBRIUM: IDONTWANT goes on the priority queue until that queue holds
    /// `priority_cap` messages, then on the bounded queue.
    #[test]
    fn idontwant_is_prioritized_until_the_priority_queue_backs_up() {
        let sender = Sender::new(4);
        let idontwant = || {
            RpcOut::IDontWant(IDontWant {
                message_ids: vec![MessageId::new(&[1])],
            })
        };
        let graft = RpcOut::Graft(Graft {
            topic_hash: TopicHash::from_raw("topic"),
        });

        sender.send_message(idontwant()).unwrap();
        sender.send_message(graft).unwrap();
        sender.send_message(idontwant()).unwrap();

        assert_eq!(sender.priority_sender.len(), 2);
        assert_eq!(sender.non_priority_sender.len(), 1);
    }

    /// The queues of a peer that reads nothing must not hold messages without
    /// bound: they were bounded by message count, at up to the frame size each.
    #[test]
    fn reproduces_unbounded_queued_message_bytes() {
        const MIB: usize = 1024 * 1024;
        let forward = || RpcOut::Forward {
            message: crate::types::RawMessage {
                source: None,
                data: vec![0; 48 * MIB],
                sequence_number: None,
                topic: TopicHash::from_raw("topic"),
                signature: None,
                key: None,
                validated: true,
            },
            timeout: futures_timer::Delay::new(std::time::Duration::from_secs(60)),
        };
        let sender = Sender::new(100);
        let _receiver = sender.new_receiver();
        let queued = (0..4)
            .filter(|_| sender.send_message(forward()).is_ok())
            .count();
        assert!(
            queued * 48 <= 64,
            "{queued} forwards of 48 MiB ({} MiB) were queued for a peer that reads nothing",
            queued * 48
        );
    }
}
