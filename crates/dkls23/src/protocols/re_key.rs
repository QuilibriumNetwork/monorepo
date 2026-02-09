//! Splits a secret key into a threshold signature scheme.
//!
//! This file implements a re-key function: if the user already has
//! an address, he can split his secret key into a threshold signature
//! scheme. Since he starts with the secret key, we consider him as a
//! "trusted dealer" that can manipulate all the data from `DKLs23` to the
//! other parties. Hence, this function is computed locally and doesn't
//! need any communication.

use std::collections::BTreeMap;

use elliptic_curve::group::{Curve as _, GroupEncoding};
use elliptic_curve::Field;

use crate::utilities::rng;
use crate::DklsCurve;
use rand::Rng;

use crate::protocols::derivation::{ChainCode, DerivData};
use crate::protocols::dkg::compute_eth_address;
use crate::protocols::{Parameters, Party};

use crate::utilities::hashes::HashOutput;
use crate::utilities::multiplication::{MulReceiver, MulSender};
use crate::utilities::ot::{
    self,
    extension::{OTEReceiver, OTESender},
};
use crate::utilities::zero_shares::{self, ZeroShare};

/// Given a secret key, computes the data needed to make
/// `DKLs23` signatures under the corresponding public key.
///
/// The output is a vector of [`Party`]'s which should be
/// distributed to different users.
///
/// We also include an option to put a chain code if the original
/// wallet followed BIP-32 for key derivation ([read more](super::derivation)).
#[must_use]
pub fn re_key<C: DklsCurve>(
    parameters: &Parameters,
    session_id: &[u8],
    secret_key: &C::Scalar,
    option_chain_code: Option<ChainCode>,
) -> Vec<Party<C>>
where
    C::Scalar: Field,
    C::AffinePoint: GroupEncoding,
{
    // Public key.
    let pk = (C::ProjectivePoint::from(crate::generator::<C>()) * secret_key).to_affine();

    // We will compute "poly_point" for each party with this polynomial
    // via Shamir's secret sharing.
    let mut polynomial: Vec<C::Scalar> = Vec::with_capacity(parameters.threshold as usize);
    polynomial.push(*secret_key);
    for _ in 1..parameters.threshold {
        polynomial.push(C::Scalar::random(rng::get_rng()));
    }

    // Zero shares.

    // We compute the common seed each pair of parties must save.
    // The vector below should interpreted as follows: its first entry
    // is a vector containing the seeds for the pair of parties (1,2),
    // (1,3), ..., (1,n). The second entry contains the seeds for the pairs
    // (2,3), (2,4), ..., (2,n), and so on. The last entry contains the
    // seed for the pair (n-1, n).
    let mut common_seeds: Vec<Vec<zero_shares::Seed>> =
        Vec::with_capacity((parameters.share_count - 1) as usize);
    for lower_index in 1..parameters.share_count {
        let mut seeds_with_lower_index: Vec<zero_shares::Seed> =
            Vec::with_capacity((parameters.share_count - lower_index) as usize);
        for _ in (lower_index + 1)..=parameters.share_count {
            let seed = rng::get_rng().gen::<zero_shares::Seed>();
            seeds_with_lower_index.push(seed);
        }
        common_seeds.push(seeds_with_lower_index);
    }

    // We can now finish the initialization.
    let mut zero_shares: Vec<ZeroShare> = Vec::with_capacity(parameters.share_count as usize);
    for party in 1..=parameters.share_count {
        let mut seeds: Vec<zero_shares::SeedPair> =
            Vec::with_capacity((parameters.share_count - 1) as usize);

        // We compute the pairs for which we have the highest index.
        if party > 1 {
            for counterparty in 1..party {
                seeds.push(zero_shares::SeedPair {
                    lowest_index: false,
                    index_counterparty: counterparty,
                    seed: common_seeds[(counterparty - 1) as usize]
                        [(party - counterparty - 1) as usize],
                });
            }
        }

        // We compute the pairs for which we have the lowest index.
        if party < parameters.share_count {
            for counterparty in (party + 1)..=parameters.share_count {
                seeds.push(zero_shares::SeedPair {
                    lowest_index: true,
                    index_counterparty: counterparty,
                    seed: common_seeds[(party - 1) as usize][(counterparty - party - 1) as usize],
                });
            }
        }

        zero_shares.push(ZeroShare::initialize(seeds));
    }

    // Two-party multiplication.

    // These will store the result of initialization for each party.
    let mut all_mul_receivers: Vec<BTreeMap<u8, MulReceiver<C>>> =
        vec![BTreeMap::new(); parameters.share_count as usize];
    let mut all_mul_senders: Vec<BTreeMap<u8, MulSender<C>>> =
        vec![BTreeMap::new(); parameters.share_count as usize];

    for receiver in 1..=parameters.share_count {
        for sender in 1..=parameters.share_count {
            if sender == receiver {
                continue;
            }

            // We first compute the data for the OT extension.

            // Receiver: Sample the seeds.
            let mut seeds0: Vec<HashOutput> = Vec::with_capacity(ot::extension::KAPPA as usize);
            let mut seeds1: Vec<HashOutput> = Vec::with_capacity(ot::extension::KAPPA as usize);
            for _ in 0..ot::extension::KAPPA {
                seeds0.push(rng::get_rng().gen::<HashOutput>());
                seeds1.push(rng::get_rng().gen::<HashOutput>());
            }

            // Sender: Sample the correlation and choose the correct seed.
            // The choice bits are sampled randomly.
            let mut correlation: Vec<bool> = Vec::with_capacity(ot::extension::KAPPA as usize);
            let mut seeds: Vec<HashOutput> = Vec::with_capacity(ot::extension::KAPPA as usize);
            for i in 0..ot::extension::KAPPA {
                let current_bit: bool = rng::get_rng().gen();
                if current_bit {
                    seeds.push(seeds1[i as usize]);
                } else {
                    seeds.push(seeds0[i as usize]);
                }
                correlation.push(current_bit);
            }

            let ote_receiver = OTEReceiver { seeds0, seeds1 };

            let ote_sender = OTESender { correlation, seeds };

            // We sample the public gadget vector.
            let mut public_gadget: Vec<C::Scalar> =
                Vec::with_capacity(ot::extension::BATCH_SIZE as usize);
            for _ in 0..ot::extension::BATCH_SIZE {
                public_gadget.push(C::Scalar::random(rng::get_rng()));
            }

            // We finish the initialization.
            let mul_receiver = MulReceiver {
                public_gadget: public_gadget.clone(),
                ote_receiver,
            };

            let mul_sender = MulSender {
                public_gadget,
                ote_sender,
            };

            // We save the results.
            all_mul_receivers[(receiver - 1) as usize].insert(sender, mul_receiver);
            all_mul_senders[(sender - 1) as usize].insert(receiver, mul_sender);
        }
    }

    // Key derivation - BIP-32.
    // We use the chain code given or we sample a new one.
    let chain_code = match option_chain_code {
        Some(cc) => cc,
        None => rng::get_rng().gen::<ChainCode>(),
    };

    // We create the parties.
    let mut parties: Vec<Party<C>> = Vec::with_capacity(parameters.share_count as usize);
    for index in 1..=parameters.share_count {
        // poly_point is polynomial evaluated at index.
        let mut poly_point = C::Scalar::ZERO;
        let mut power_of_index = C::Scalar::ONE;
        for i in 0..parameters.threshold {
            poly_point += polynomial[i as usize] * power_of_index;
            power_of_index *= C::Scalar::from(u64::from(index));
        }

        // Remark: There is a very tiny probability that poly_point is trivial.
        // However, the person that will receive this data should apply the
        // refresh protocol to guarantee their key share is really secret.
        // This reduces the probability even more, so we are not going to
        // introduce an "Abort" case here.

        let derivation_data = DerivData {
            depth: 0,
            child_number: 0, // These three values are initialized as zero for the master node.
            parent_fingerprint: [0; 4],
            poly_point,
            pk,
            chain_code,
        };

        parties.push(Party {
            parameters: parameters.clone(),
            party_index: index,
            session_id: session_id.to_vec(),
            poly_point,
            pk,
            zero_share: zero_shares[(index - 1) as usize].clone(),
            mul_senders: all_mul_senders[(index - 1) as usize].clone(),
            mul_receivers: all_mul_receivers[(index - 1) as usize].clone(),
            derivation_data,
            eth_address: compute_eth_address::<C>(&pk),
        });
    }

    parties
}

// For tests, see the file signing.rs. It uses the function above.
