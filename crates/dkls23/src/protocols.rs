//! `DKLs23` main protocols and related ones.
//!
//! Some structs appearing in most of the protocols are defined here.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::protocols::derivation::DerivData;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::zero_shares::ZeroShare;
use crate::DklsCurve;

pub mod derivation;
pub mod dkg;
pub mod re_key;
pub mod refresh;
pub mod signing;

/// Contains the values `t` and  `n` from `DKLs23`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Parameters {
    pub threshold: u8,   //t
    pub share_count: u8, //n
}

/// Represents a party after key generation ready to sign a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize, C::AffinePoint: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>, C::AffinePoint: Deserialize<'de>"
))]
pub struct Party<C: DklsCurve> {
    pub parameters: Parameters,
    pub party_index: u8,
    pub session_id: Vec<u8>,

    /// Behaves as the secret key share.
    pub poly_point: C::Scalar,
    /// Public key.
    pub pk: C::AffinePoint,

    /// Used for computing shares of zero during signing.
    pub zero_share: ZeroShare,

    /// Initializations for two-party multiplication.
    /// The key in the `BTreeMap` represents the other party.
    pub mul_senders: BTreeMap<u8, MulSender<C>>,
    pub mul_receivers: BTreeMap<u8, MulReceiver<C>>,

    /// Data for BIP-32 derivation.
    pub derivation_data: DerivData<C>,

    /// Ethereum address calculated from the public key.
    pub eth_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abort {
    /// Index of the party generating the abort message.
    pub index: u8,
    pub description: String,
}

impl Abort {
    /// Creates an instance of `Abort`.
    #[must_use]
    pub fn new(index: u8, description: &str) -> Abort {
        Abort {
            index,
            description: String::from(description),
        }
    }
}

/// Saves the sender and receiver of a message.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PartiesMessage {
    pub sender: u8,
    pub receiver: u8,
}

impl PartiesMessage {
    /// Swaps the sender with the receiver, returning another instance of `PartiesMessage`.
    #[must_use]
    pub fn reverse(&self) -> PartiesMessage {
        PartiesMessage {
            sender: self.receiver,
            receiver: self.sender,
        }
    }
}
