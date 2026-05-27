// Copyright 2021 Lolo_32
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::convert::TryFrom;

use num_bigint::{BigInt, Sign};

use crate::{
    init_sig,
    point::Point,
    private_key::PrivateKey,
    {shake256, Ed448Error, PreHash, KEY_LENGTH, SIG_LENGTH},
};

/// This is a public key. _Should be distributed._
///
/// You can extract a `PublicKey` by calling [`Self::from()`].
#[derive(Clone)]
pub struct PublicKey(Point);

opaque_debug::implement!(PublicKey);

impl PublicKey {
    /// Convert the public key to an easily exportable format.
    #[inline]
    #[must_use]
    pub fn as_byte(&self) -> [u8; 57] {
        // 4.  The public key A is the encoding of the point [s]B.
        self.0.encode()
    }

    /// Verify signature with public key.
    ///
    /// # Example
    ///
    /// ```
    /// # use rand_core::OsRng;
    /// use ed448_rust::{PublicKey, Ed448Error};
    /// # let private_key = ed448_rust::PrivateKey::new(&mut OsRng);
    /// let message = b"Signed message to verify";
    /// # let retrieve_signature = || private_key.sign(message, None).unwrap();
    /// # let retrieve_pubkey = || PublicKey::from(&private_key);
    /// let public_key = retrieve_pubkey();
    /// let signature = retrieve_signature();
    /// match public_key.verify(message, &signature, None) {
    ///     Ok(()) => {
    ///         // Signature OK, use the message
    ///     }
    ///     Err(Ed448Error::InvalidSignature) => {
    ///         // The verification of the signature is invalid
    ///     }
    ///     Err(Ed448Error::ContextTooLong) => {
    ///         // The used context is more than 255 bytes length
    ///     }
    ///     Err(Ed448Error::WrongSignatureLength) => {
    ///         // The signature is not 144 bytes length
    ///     }
    ///     Err(_) => unreachable!()
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// * [`Ed448Error::InvalidSignature`] if the signature is not valid, either the public key
    ///   or the signature used are not the right, or the message has been altered.
    /// * [`Ed448Error::ContextTooLong`] if the optional context is more than 255 byte length.
    /// * [`Ed448Error::WrongSignatureLength`] if the signature is not `SIG_LENGTH` byte.
    #[inline]
    pub fn verify(&self, msg: &[u8], sign: &[u8], ctx: Option<&[u8]>) -> crate::Result<()> {
        self.verify_real(msg, sign, ctx, PreHash::False)
    }

    /// Verify signature with public key. Message is pre-hashed before checked.
    ///
    /// See [`PublicKey::verify`] for more information.
    ///
    /// # Errors
    ///
    /// * [`Ed448Error::InvalidSignature`] if the signature is not valid, either the public key
    ///   or the signature used are not the right, or the message has been altered.
    /// * [`Ed448Error::ContextTooLong`] if the optional context is more than 255 byte length.
    /// * [`Ed448Error::WrongSignatureLength`] if the signature is not `SIG_LENGTH` byte.
    #[inline]
    pub fn verify_ph(&self, msg: &[u8], sign: &[u8], ctx: Option<&[u8]>) -> crate::Result<()> {
        self.verify_real(msg, sign, ctx, PreHash::True)
    }

    fn verify_real(
        &self,
        msg: &[u8],
        sign: &[u8],
        ctx: Option<&[u8]>,
        pre_hash: PreHash,
    ) -> crate::Result<()> {
        // Sanity-check sizes.
        if sign.len() < SIG_LENGTH {
            return Err(Ed448Error::WrongSignatureLength);
        }

        // Split signature into R and S, and parse.
        let (Rraw, Sraw) = sign.split_at(KEY_LENGTH);
        let (R, S) = (
            Point::decode(Rraw).map_err(|_| Ed448Error::InvalidSignature)?,
            BigInt::from_bytes_le(Sign::Plus, Sraw),
        );
        // Parse public key.
        let A = Point::decode(&self.as_byte()).map_err(|_| Ed448Error::InvalidSignature)?;
        if &S >= Point::l() {
            return Err(Ed448Error::InvalidSignature);
        }
        // Calculate h.
        let h = {
            let (ctx, msg) = init_sig(ctx, pre_hash, msg)?;
            shake256(vec![Rraw, &self.as_byte(), &msg], ctx.as_ref(), pre_hash)
        };
        let h = BigInt::from_bytes_le(Sign::Plus, &h) % Point::l();
        // Calculate left and right sides of check eq.
        let rhs = R + (A * h);
        let lhs = Point::default() * S;
        // Check eq. holds?
        if lhs.double().double() == rhs.double().double() {
            Ok(())
        } else {
            Err(Ed448Error::InvalidSignature)
        }
    }
}

/// Instantiate a `PublicKey` from the `PrivateKey`.
impl From<&PrivateKey> for PublicKey {
    #[inline]
    fn from(private_key: &PrivateKey) -> Self {
        let (s, _) = &private_key.expand();
        // 3.  Interpret the buffer as the little-endian integer, forming a
        //     secret scalar s.
        Self::from(BigInt::from_bytes_le(Sign::Plus, s))
    }
}

/// Do not use, it's for internal use only to generate the PublicKey
#[doc(hidden)]
impl From<BigInt> for PublicKey {
    #[inline]
    fn from(s: BigInt) -> Self {
        //     Perform a known-base-point scalar multiplication [s]B.
        let A = Point::default() * s;

        // 4.  The public key A is the encoding of the point [s]B.
        Self(A)
    }
}

impl From<[u8; KEY_LENGTH]> for PublicKey {
    #[inline]
    fn from(array: [u8; KEY_LENGTH]) -> Self {
        Self(Point::decode(&array).expect("bad ed448 public key"))
    }
}

impl From<&'_ [u8; KEY_LENGTH]> for PublicKey {
    #[inline]
    fn from(array: &'_ [u8; KEY_LENGTH]) -> Self {
       Self(Point::decode(array).expect("bad ed448 public key")) 
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Ed448Error;

    #[inline]
    fn try_from(array: &[u8]) -> Result<Self, Self::Error> {
        if array.len() != KEY_LENGTH {
            return Err(Ed448Error::WrongPublicKeyLength);
        }
        Ok(Self(Point::decode(array)?))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_vectors_rfc8032_public() {
        let secret_vec = hex::decode(
            "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3\
                528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
        )
        .unwrap();
        let ref_public = hex::decode(
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778\
                edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        )
        .unwrap();

        let secret = PrivateKey::try_from(&secret_vec[..]).unwrap();
        let public = PublicKey::from(&secret);

        assert_eq!(&public.as_byte()[..], &ref_public[..]);
    }

    #[test]
    fn wrong_verification_with_another_pub_key() {
        let secret_1 = PrivateKey::new(&mut OsRng);
        let msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec.";
        let sig_1 = secret_1.sign(msg, None).unwrap();
        let public_2 = PublicKey::from(&PrivateKey::new(&mut OsRng));
        assert_eq!(
            public_2.verify(msg, &sig_1, None).unwrap_err(),
            Ed448Error::InvalidSignature
        );
    }

    #[test]
    fn wrong_pubkey_length() {
        let pub_key = PublicKey::try_from(&[0x01_u8][..]);
        assert_eq!(pub_key.unwrap_err(), Ed448Error::WrongPublicKeyLength);
    }

    #[test]
    fn wrong_sign_length() {
        let pubkey = PublicKey::from(&PrivateKey::new(&mut OsRng));
        let sig = [0x01; SIG_LENGTH - 1];
        assert_eq!(
            pubkey.verify(b"message", &sig, None).unwrap_err(),
            Ed448Error::WrongSignatureLength
        );
    }

    #[test]
    fn instantiate_pubkey() {
        let pkey = PrivateKey::new(&mut OsRng);
        let pub_key = PublicKey::from(&pkey);
        let pub_bytes = pub_key.as_byte();
        let pub_key1 = PublicKey::from(&pub_bytes);
        let pub_key2 = PublicKey::from(pub_bytes);

        assert_eq!(pub_key1.as_byte(), pub_key2.as_byte());
    }

    #[test]
    fn wrong_with_altered_message() {
        let secret = PrivateKey::new(&mut OsRng);
        let public = PublicKey::from(&PrivateKey::new(&mut OsRng));
        let msg_1 = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec.";
        // One dot missing at the end
        let msg_2 = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec";
        let sig = secret.sign(msg_1, None).unwrap();
        assert_eq!(
            public.verify(msg_2, &sig, None).unwrap_err(),
            Ed448Error::InvalidSignature
        );
    }

    #[test]
    fn wrong_with_forged_pub_key() {
        let secret = PrivateKey::new(&mut OsRng);
        let wrong_public = PublicKey::from(&PrivateKey::new(&mut OsRng));
        let msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec.";
        let sig = secret.sign(msg, None).unwrap();
        assert_eq!(
            wrong_public.verify(msg, &sig, None).unwrap_err(),
            Ed448Error::InvalidSignature
        );
    }

    #[test]
    fn wrong_with_forged_signature() {
        let secret = PrivateKey::new(&mut OsRng);
        let public = PublicKey::from(&secret);
        let msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec.";
        // One dot missing at the end
        let sig = [1; SIG_LENGTH];
        assert_eq!(
            public.verify(msg, &sig, None).unwrap_err(),
            Ed448Error::InvalidSignature
        );
    }
}
