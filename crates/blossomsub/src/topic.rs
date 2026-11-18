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

//! BlossomSub topics.
//!
//! In BlossomSub a "topic" is a **bitmask** (`Vec<u8>`), not a string hash. A
//! message tagged with bitmask `M` is delivered to peers subscribed to exactly
//! `M` (plain exact-match semantics; overlap routing is a later stage). The
//! [`TopicHash`] therefore simply wraps the raw bitmask bytes.

use prometheus_client::encoding::{
    EncodeLabelSet, EncodeLabelValue, LabelSetEncoder, LabelValueEncoder,
};
use std::fmt::{self, Write};

/// A generic trait that can be extended for various hashing types for a topic.
pub trait Hasher {
    /// The function that takes the raw topic bytes (bitmask) and creates a topic hash.
    fn hash(bitmask: Vec<u8>) -> TopicHash;
}

/// A type for representing topics who use the identity hash.
///
/// For BlossomSub the topic *is* its bitmask, so this is the canonical hasher.
#[derive(Debug, Clone)]
pub struct IdentityHash {}
impl Hasher for IdentityHash {
    /// Returns the bitmask verbatim as the [`TopicHash`].
    fn hash(bitmask: Vec<u8>) -> TopicHash {
        TopicHash { hash: bitmask }
    }
}

/// Retained only so the [`crate::Sha256Topic`] type alias keeps compiling.
///
/// In BlossomSub a topic is its bitmask, so there is no separate SHA-256 topic
/// namespace; this behaves as identity.
#[derive(Debug, Clone)]
pub struct Sha256Hash {}
impl Hasher for Sha256Hash {
    fn hash(bitmask: Vec<u8>) -> TopicHash {
        TopicHash { hash: bitmask }
    }
}

/// A BlossomSub topic: the raw bitmask bytes.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TopicHash {
    /// The topic bitmask.
    hash: Vec<u8>,
}

impl TopicHash {
    pub fn from_raw(hash: impl Into<Vec<u8>>) -> TopicHash {
        TopicHash { hash: hash.into() }
    }

    /// Consumes the [`TopicHash`], returning the raw bitmask bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.hash
    }

    /// Borrows the raw bitmask bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.hash
    }
}

/// A BlossomSub topic wrapping a bitmask.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Topic<H: Hasher> {
    topic: Vec<u8>,
    phantom_data: std::marker::PhantomData<H>,
}

impl<H: Hasher> From<Topic<H>> for TopicHash {
    fn from(topic: Topic<H>) -> TopicHash {
        topic.hash()
    }
}

impl<H: Hasher> Topic<H> {
    /// Creates a topic from anything convertible to bytes (a bitmask). String
    /// literals are accepted too (their UTF-8 bytes become the bitmask), which
    /// keeps the ergonomic `Topic::new("...")` form working in tests.
    pub fn new(topic: impl AsRef<[u8]>) -> Self {
        Topic {
            topic: topic.as_ref().to_vec(),
            phantom_data: std::marker::PhantomData,
        }
    }

    pub fn hash(&self) -> TopicHash {
        H::hash(self.topic.clone())
    }
}

impl<H: Hasher> fmt::Display for Topic<H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.topic))
    }
}

impl fmt::Display for TopicHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.hash))
    }
}

impl fmt::Debug for TopicHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicHash({})", hex_fmt::HexFmt(&self.hash))
    }
}

// Prometheus labels must be strings, so a bitmask topic is emitted as its hex
// encoding. `Family<TopicHash, M>` uses the [`EncodeLabelSet`] impl; the
// [`EncodeLabelValue`] impl lets a `TopicHash` also be used as a label value.
impl EncodeLabelSet for TopicHash {
    fn encode(&self, encoder: LabelSetEncoder) -> Result<(), fmt::Error> {
        [("bitmask", self.to_string())].encode(encoder)
    }
}

impl EncodeLabelValue for TopicHash {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), fmt::Error> {
        encoder.write_str(&self.to_string())
    }
}
