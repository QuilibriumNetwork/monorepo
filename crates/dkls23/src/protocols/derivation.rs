//! Adaptation of BIP-32 to the threshold setting.
//!
//! This file implements a key derivation mechanism for threshold wallets
//! based on BIP-32 (<https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>).
//! Each party can derive their key share individually so that the secret
//! key reconstructed corresponds to the derivation (via BIP-32) of the
//! original secret key.
//!
//! We follow mainly this repository:
//! <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/src/bip32.rs>.
//!
//! ATTENTION: Since no party has the full secret key, it is not convenient
//! to do hardened derivation. Thus, we only implement normal derivation.

use bitcoin_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};

use elliptic_curve::bigint::U256;
use elliptic_curve::group::{Curve as _, GroupEncoding};
use elliptic_curve::ops::Reduce;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::{Field, PrimeField};
use serde::{Deserialize, Serialize};

use crate::protocols::Party;
use crate::utilities::hashes::point_to_bytes;
use crate::DklsCurve;

use super::dkg::compute_eth_address;

/// Fingerprint of a key as in BIP-32.
///
/// See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
pub type Fingerprint = [u8; 4];
/// Chaincode of a key as in BIP-32.
///
/// See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
pub type ChainCode = [u8; 32];

/// Represents an error during the derivation protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ErrorDeriv {
    pub description: String,
}

impl ErrorDeriv {
    /// Creates an instance of `ErrorDeriv`.
    #[must_use]
    pub fn new(description: &str) -> ErrorDeriv {
        ErrorDeriv {
            description: String::from(description),
        }
    }
}

/// Contains all the data needed for derivation.
///
/// The values that are really needed are only `poly_point`,
/// `pk` and `chain_code`, but we also include the other ones
/// if someone wants to retrieve the full extended public key
/// as in BIP-32. The only field missing is the one for the
/// network, but it can be easily inferred from context.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    serialize = "C::Scalar: Serialize, C::AffinePoint: Serialize",
    deserialize = "C::Scalar: Deserialize<'de>, C::AffinePoint: Deserialize<'de>"
))]
pub struct DerivData<C: CurveArithmetic> {
    /// Counts after how many derivations this key is obtained from the master node.
    pub depth: u8,
    /// Index used to obtain this key from its parent.
    pub child_number: u32,
    /// Identifier of the parent key.
    pub parent_fingerprint: Fingerprint,
    /// Behaves as the secret key share.
    pub poly_point: C::Scalar,
    /// Public key.
    pub pk: C::AffinePoint,
    /// Extra entropy given by BIP-32.
    pub chain_code: ChainCode,
}

/// Maximum depth.
pub const MAX_DEPTH: u8 = 255;
/// Maximum child number.
///
/// This is the limit since we are not implementing hardened derivation.
pub const MAX_CHILD_NUMBER: u32 = 0x7FFF_FFFF;

impl<C: DklsCurve> DerivData<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding + Default,
{
    /// Computes the "tweak" needed to derive a secret key. In the process,
    /// it also produces the chain code and the parent fingerprint.
    ///
    /// This is an adaptation of `ckd_pub_tweak` from the repository:
    /// <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/src/bip32.rs>.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the HMAC result is too big (very unlikely).
    pub fn child_tweak(
        &self,
        child_number: u32,
    ) -> Result<(C::Scalar, ChainCode, Fingerprint), ErrorDeriv> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);

        let pk_as_bytes = point_to_bytes::<C>(&self.pk);
        hmac_engine.input(&pk_as_bytes);
        hmac_engine.input(&child_number.to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let number_for_tweak = U256::from_be_slice(&hmac_result[..32]);
        let tweak = C::Scalar::reduce(number_for_tweak);

        // If reduce produced zero (vanishingly unlikely), return None.
        // This is the generic equivalent of the BIP-32 check "if tweak >= n".
        if tweak.is_zero().into() {
            return Err(ErrorDeriv::new(
                "Very improbable: Child index results in value not allowed by BIP-32!",
            ));
        }

        let chain_code: ChainCode = hmac_result[32..]
            .try_into()
            .expect("Half of hmac is guaranteed to be 32 bytes!");

        // We also calculate the fingerprint here for convenience.
        let mut engine = hash160::Hash::engine();
        engine.input(&pk_as_bytes);
        let fingerprint: Fingerprint = hash160::Hash::from_engine(engine)[0..4]
            .try_into()
            .expect("4 is the fingerprint length!");

        Ok((tweak, chain_code, fingerprint))
    }

    /// Derives an instance of `DerivData` given a child number.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the depth is already at the maximum value,
    /// if the child number is invalid or if `child_tweak` fails.
    /// It will also fail if the new public key is invalid (very unlikely).
    pub fn derive_child(&self, child_number: u32) -> Result<DerivData<C>, ErrorDeriv> {
        if self.depth == MAX_DEPTH {
            return Err(ErrorDeriv::new("We are already at maximum depth!"));
        }

        if child_number > MAX_CHILD_NUMBER {
            return Err(ErrorDeriv::new(
                "Child index should be between 0 and 2^31 - 1!",
            ));
        }

        let (tweak, new_chain_code, parent_fingerprint) = self.child_tweak(child_number)?;

        // If every party shifts their poly_point by the same tweak,
        // the resulting secret key also shifts by the same amount.
        // Note that the tweak depends only on public data.
        let new_poly_point = self.poly_point + tweak;
        let new_pk = (C::ProjectivePoint::from(crate::generator::<C>()) * tweak + C::ProjectivePoint::from(self.pk)).to_affine();

        if new_pk == crate::identity::<C>() {
            return Err(ErrorDeriv::new(
                "Very improbable: Child index results in value not allowed by BIP-32!",
            ));
        }

        Ok(DerivData {
            depth: self.depth + 1,
            child_number,
            parent_fingerprint,
            poly_point: new_poly_point,
            pk: new_pk,
            chain_code: new_chain_code,
        })
    }

    /// Derives an instance of `DerivData` following a path
    /// on the "key tree".
    ///
    /// See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
    /// for the description of a possible path (and don't forget that
    /// hardened derivations are not implemented).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the path is invalid or if `derive_child` fails.
    pub fn derive_from_path(&self, path: &str) -> Result<DerivData<C>, ErrorDeriv> {
        let path_parsed = parse_path(path)?;

        let mut final_data = self.clone();
        for child_number in path_parsed {
            final_data = final_data.derive_child(child_number)?;
        }

        Ok(final_data)
    }
}

// We implement the derivation functions for Party as well.

/// Implementations related to BIP-32 derivation ([read more](self)).
impl<C: DklsCurve + 'static> Party<C>
where
    C::Scalar: Reduce<U256> + PrimeField,
    C::AffinePoint: GroupEncoding + Default,
{
    /// Derives an instance of `Party` given a child number.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the `DerivData::derive_child` fails.
    pub fn derive_child(&self, child_number: u32) -> Result<Party<C>, ErrorDeriv> {
        let new_derivation_data = self.derivation_data.derive_child(child_number)?;

        // We don't change information relating other parties,
        // we only update our key share, our public key and the address.
        let new_address = compute_eth_address::<C>(&new_derivation_data.pk);

        Ok(Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: self.session_id.clone(),

            poly_point: new_derivation_data.poly_point,
            pk: new_derivation_data.pk,

            zero_share: self.zero_share.clone(),

            mul_senders: self.mul_senders.clone(),
            mul_receivers: self.mul_receivers.clone(),

            derivation_data: new_derivation_data,

            eth_address: new_address,
        })
    }

    /// Derives an instance of `Party` following a path
    /// on the "key tree".
    ///
    /// See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
    /// for the description of a possible path (and don't forget that
    /// hardened derivations are not implemented).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the `DerivData::derive_from_path` fails.
    pub fn derive_from_path(&self, path: &str) -> Result<Party<C>, ErrorDeriv> {
        let new_derivation_data = self.derivation_data.derive_from_path(path)?;

        // We don't change information relating other parties,
        // we only update our key share, our public key and the address.
        let new_address = compute_eth_address::<C>(&new_derivation_data.pk);

        Ok(Party {
            parameters: self.parameters.clone(),
            party_index: self.party_index,
            session_id: self.session_id.clone(),

            poly_point: new_derivation_data.poly_point,
            pk: new_derivation_data.pk,

            zero_share: self.zero_share.clone(),

            mul_senders: self.mul_senders.clone(),
            mul_receivers: self.mul_receivers.clone(),

            derivation_data: new_derivation_data,

            eth_address: new_address,
        })
    }
}

/// Takes a path as in BIP-32 (for normal derivation),
/// and transforms it into a vector of child numbers.
///
/// # Errors
///
/// Will return `Err` if the path is not valid or empty.
pub fn parse_path(path: &str) -> Result<Vec<u32>, ErrorDeriv> {
    let mut parts = path.split('/');

    if parts.next().unwrap_or_default() != "m" {
        return Err(ErrorDeriv::new("Invalid path format!"));
    }

    let mut path_parsed = Vec::new();

    for part in parts {
        match part.parse::<u32>() {
            Ok(num) if num <= MAX_CHILD_NUMBER => path_parsed.push(num),
            _ => {
                return Err(ErrorDeriv::new(
                    "Invalid path format or index out of bounds!",
                ))
            }
        }
    }

    if path_parsed.len() > MAX_DEPTH as usize {
        return Err(ErrorDeriv::new("The path is too long!"));
    }

    Ok(path_parsed)
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::protocols::re_key::re_key;
    use crate::protocols::signing::*;
    use crate::protocols::Parameters;

    use crate::utilities::hashes::*;

    use crate::utilities::rng;
    use hex;
    use k256::elliptic_curve::Field;
    use rand::Rng;
    use std::collections::BTreeMap;

    type C = k256::Secp256k1;
    type ProjectivePoint = <C as CurveArithmetic>::ProjectivePoint;

    /// Tests if the method `derive_from_path` from [`DerivData`]
    /// works properly by checking its output against a known value.
    ///
    /// Since this function calls the other methods in this struct,
    /// they are implicitly tested as well.
    #[test]
    fn test_derivation() {
        // The following values were calculated at random with: https://bitaps.com/bip32.
        // You should test other values as well.
        let sk = <k256::Scalar as Reduce<U256>>::reduce(U256::from_be_hex(
            "6728f18f7163f7a0c11cc0ad53140afb4e345d760f966176865a860041549903",
        ));
        let pk = (ProjectivePoint::from(crate::generator::<C>()) * sk).to_affine();
        let chain_code: ChainCode =
            hex::decode("6f990adb9337033001af2487a8617f68586c4ea17433492bbf1659f6e4cf9564")
                .unwrap()
                .try_into()
                .unwrap();

        let data: DerivData<C> = DerivData {
            depth: 0,
            child_number: 0,
            parent_fingerprint: [0u8; 4],
            poly_point: sk,
            pk,
            chain_code,
        };

        // You should try other paths as well.
        let path = "m/0/1/2/3";
        let try_derive = data.derive_from_path(path);

        match try_derive {
            Err(error) => {
                panic!("Error: {:?}", error.description);
            }
            Ok(child) => {
                assert_eq!(child.depth, 4);
                assert_eq!(child.child_number, 3);
                assert_eq!(hex::encode(child.parent_fingerprint), "9502bb8b");
                assert_eq!(
                    hex::encode(scalar_to_bytes::<C>(&child.poly_point)),
                    "bdebf4ed48fae0b5b3ed6671496f7e1d741996dbb30d79f990933892c8ed316a"
                );
                assert_eq!(
                    hex::encode(point_to_bytes::<C>(&child.pk)),
                    "037c892dca96d4c940aafb3a1e65f470e43fba57b3146efeb312c2a39a208fffaa"
                );
                assert_eq!(
                    hex::encode(child.chain_code),
                    "c6536c2f5c232aa7613652831b7a3b21e97f4baa3114a3837de3764759f5b2aa"
                );
            }
        }
    }

    /// Tests if the key shares are still capable of executing
    /// the signing protocol after being derived.
    #[test]
    fn test_derivation_and_signing() {
        let threshold = rng::get_rng().gen_range(2..=5); // You can change the ranges here.
        let offset = rng::get_rng().gen_range(0..=5);

        let parameters = Parameters {
            threshold,
            share_count: threshold + offset,
        }; // You can fix the parameters if you prefer.

        // We use the re_key function to quickly sample the parties.
        let session_id = rng::get_rng().gen::<[u8; 32]>();
        let secret_key = <k256::Scalar as Field>::random(rng::get_rng());
        let parties = re_key::<C>(&parameters, &session_id, &secret_key, None);

        // DERIVATION

        let path = "m/0/1/2/3";

        let mut derived_parties: Vec<Party<C>> = Vec::with_capacity(parameters.share_count as usize);
        for i in 0..parameters.share_count {
            let result = parties[i as usize].derive_from_path(path);
            match result {
                Err(error) => {
                    panic!("Error for Party {}: {:?}", i, error.description);
                }
                Ok(party) => {
                    derived_parties.push(party);
                }
            }
        }

        let parties = derived_parties;

        // SIGNING (as in test_signing)

        let sign_id = rng::get_rng().gen::<[u8; 32]>();
        let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

        // For simplicity, we are testing only the first parties.
        let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

        // Each party prepares their data for this signing session.
        let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            //Gather the counterparties
            let mut counterparties = executing_parties.clone();
            counterparties.retain(|index| *index != party_index);

            all_data.insert(
                party_index,
                SignData {
                    sign_id: sign_id.to_vec(),
                    counterparties,
                    message_hash: message_to_sign,
                },
            );
        }

        // Phase 1
        let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2<C>> = BTreeMap::new();
        let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2<C>>> = BTreeMap::new();
        let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
                .sign_phase1(all_data.get(&party_index).unwrap());

            unique_kept_1to2.insert(party_index, unique_keep);
            kept_1to2.insert(party_index, keep);
            transmit_1to2.insert(party_index, transmit);
        }

        // Communication round 1
        let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

        // Iterate over each party_index in executing_parties
        for &party_index in &executing_parties {
            let new_row: Vec<TransmitPhase1to2> = transmit_1to2
                .iter()
                .flat_map(|(_, messages)| {
                    messages
                        .iter()
                        .filter(|message| message.parties.receiver == party_index)
                        .cloned()
                })
                .collect();

            received_1to2.insert(party_index, new_row);
        }

        // Phase 2
        let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3<C>> = BTreeMap::new();
        let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3<C>>> = BTreeMap::new();
        let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase2(
                all_data.get(&party_index).unwrap(),
                unique_kept_1to2.get(&party_index).unwrap(),
                kept_1to2.get(&party_index).unwrap(),
                received_1to2.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((unique_keep, keep, transmit)) => {
                    unique_kept_2to3.insert(party_index, unique_keep);
                    kept_2to3.insert(party_index, keep);
                    transmit_2to3.insert(party_index, transmit);
                }
            }
        }

        // Communication round 2
        let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();

        // Use references to avoid cloning executing_parties
        for &party_index in &executing_parties {
            let filtered_messages: Vec<TransmitPhase2to3<C>> = transmit_2to3
                .iter()
                .flat_map(|(_, messages)| {
                    messages
                        .iter()
                        .filter(|message| message.parties.receiver == party_index)
                })
                .cloned()
                .collect();

            received_2to3.insert(party_index, filtered_messages);
        }

        // Phase 3
        let mut x_coords: Vec<String> = Vec::with_capacity(parameters.threshold as usize);
        let mut broadcast_3to4: Vec<Broadcast3to4<C>> =
            Vec::with_capacity(parameters.threshold as usize);
        for party_index in executing_parties.clone() {
            let result = parties[(party_index - 1) as usize].sign_phase3(
                all_data.get(&party_index).unwrap(),
                unique_kept_2to3.get(&party_index).unwrap(),
                kept_2to3.get(&party_index).unwrap(),
                received_2to3.get(&party_index).unwrap(),
            );
            match result {
                Err(abort) => {
                    panic!("Party {} aborted: {:?}", abort.index, abort.description);
                }
                Ok((x_coord, broadcast)) => {
                    x_coords.push(x_coord);
                    broadcast_3to4.push(broadcast);
                }
            }
        }

        // We verify all parties got the same x coordinate.
        let x_coord = x_coords[0].clone(); // We take the first one as reference.
        for i in 1..parameters.threshold {
            assert_eq!(x_coord, x_coords[i as usize]);
        }

        // Communication round 3
        // This is a broadcast to all parties. The desired result is already broadcast_3to4.

        // Phase 4
        let some_index = executing_parties[0];
        let result = parties[(some_index - 1) as usize].sign_phase4(
            all_data.get(&some_index).unwrap(),
            &x_coord,
            &broadcast_3to4,
            true,
        );
        if let Err(abort) = result {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}
