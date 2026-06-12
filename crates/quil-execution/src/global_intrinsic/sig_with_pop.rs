//! `BLS48581SignatureWithProofOfPossession` canonical-bytes envelope.
//!
//! Wire format (type 0x011A):
//!
//! ```text
//! [u32 BE type_prefix = 0x011A]
//! [u32 BE sig_len = 74]    [74 bytes signature]
//! [u32 BE pubkey_len]      [pubkey canonical bytes if > 0]
//! [u32 BE pop_sig_len = 74][74 bytes pop_signature]
//! ```

use quil_types::error::{QuilError, Result};

use crate::canonical_cursor::{put_u32, read_u32, read_bytes};

pub const TYPE_BLS48581_SIG_WITH_POP: u32 = 0x011A;

const SIG_LEN: usize = 74;
const WRAPPED_PUBKEY_LEN: usize = 589; // 4 type prefix + 585 key

/// Mirror of `protobufs.BLS48581SignatureWithProofOfPossession`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureWithPop {
    /// BLS48-581 signature, exactly 74 bytes.
    pub signature: Vec<u8>,
    /// Optional BLS48-581 G2 public key (585 raw bytes; serialized
    /// with its own type prefix as 589 bytes).
    pub public_key: Option<Vec<u8>>,
    /// Proof-of-possession signature, exactly 74 bytes.
    pub pop_signature: Vec<u8>,
}

impl SignatureWithPop {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_SIG_WITH_POP);

        // signature
        put_u32(&mut out, self.signature.len() as u32);
        out.extend_from_slice(&self.signature);

        // public_key (nested canonical bytes of BLS48581G2PublicKey)
        match &self.public_key {
            Some(pk) => {
                // Wrap with the G2 public key type prefix (0x0117)
                let mut pk_canonical = Vec::with_capacity(4 + pk.len());
                put_u32(&mut pk_canonical, 0x0117); // TYPE_BLS48581_G2_PUBLIC_KEY
                pk_canonical.extend_from_slice(pk);
                put_u32(&mut out, pk_canonical.len() as u32);
                out.extend_from_slice(&pk_canonical);
            }
            None => put_u32(&mut out, 0),
        }

        // pop_signature
        put_u32(&mut out, self.pop_signature.len() as u32);
        out.extend_from_slice(&self.pop_signature);

        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let type_prefix = read_u32(data, &mut cursor)?;
        if type_prefix != TYPE_BLS48581_SIG_WITH_POP {
            return Err(QuilError::InvalidArgument(format!(
                "SignatureWithPop: invalid type prefix 0x{:08x}",
                type_prefix
            )));
        }

        // signature — must be exactly 74
        let sig_len = read_u32(data, &mut cursor)? as usize;
        if sig_len != SIG_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "SignatureWithPop: invalid signature length {}",
                sig_len
            )));
        }
        let signature = read_bytes(data, &mut cursor, sig_len)?;

        // public_key — 0 or 589
        let pk_len = read_u32(data, &mut cursor)? as usize;
        let public_key = if pk_len > 0 {
            if pk_len != WRAPPED_PUBKEY_LEN {
                return Err(QuilError::InvalidArgument(format!(
                    "SignatureWithPop: invalid pubkey length {}",
                    pk_len
                )));
            }
            let pk_bytes = read_bytes(data, &mut cursor, pk_len)?;
            // Strip the 4-byte type prefix to get the raw 585-byte key
            if pk_bytes.len() < 4 {
                return Err(QuilError::InvalidArgument(
                    "SignatureWithPop: pubkey too short for type prefix".into(),
                ));
            }
            Some(pk_bytes[4..].to_vec())
        } else {
            None
        };

        // pop_signature — must be exactly 74
        let pop_len = read_u32(data, &mut cursor)? as usize;
        if pop_len != SIG_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "SignatureWithPop: invalid pop signature length {}",
                pop_len
            )));
        }
        let pop_signature = read_bytes(data, &mut cursor, pop_len)?;

        Ok(Self {
            signature,
            public_key,
            pop_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sig_with_pop() -> SignatureWithPop {
        SignatureWithPop {
            signature: vec![0xAAu8; SIG_LEN],
            public_key: Some(vec![0xBBu8; 585]),
            pop_signature: vec![0xCCu8; SIG_LEN],
        }
    }

    #[test]
    fn round_trip_with_pubkey() {
        let s = sample_sig_with_pop();
        let bytes = s.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..4], &TYPE_BLS48581_SIG_WITH_POP.to_be_bytes());
        let restored = SignatureWithPop::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, s);
    }

    #[test]
    fn round_trip_without_pubkey() {
        let s = SignatureWithPop {
            signature: vec![0x11u8; SIG_LEN],
            public_key: None,
            pop_signature: vec![0x22u8; SIG_LEN],
        };
        let bytes = s.to_canonical_bytes().unwrap();
        let restored = SignatureWithPop::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(restored, s);
    }

    #[test]
    fn decode_rejects_bad_sig_length() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_SIG_WITH_POP);
        put_u32(&mut out, 100); // not 74
        out.extend_from_slice(&[0u8; 100]);
        assert!(SignatureWithPop::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn decode_rejects_bad_pop_length() {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_BLS48581_SIG_WITH_POP);
        put_u32(&mut out, 74);
        out.extend_from_slice(&[0u8; 74]);
        put_u32(&mut out, 0); // no pubkey
        put_u32(&mut out, 50); // not 74
        out.extend_from_slice(&[0u8; 50]);
        assert!(SignatureWithPop::from_canonical_bytes(&out).is_err());
    }

    #[test]
    fn total_envelope_size_with_pubkey() {
        let s = sample_sig_with_pop();
        let bytes = s.to_canonical_bytes().unwrap();
        // 4 type + (4+74) sig + (4+589) pubkey + (4+74) pop = 753
        assert_eq!(bytes.len(), 753);
    }
}
