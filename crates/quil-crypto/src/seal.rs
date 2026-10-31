//! Seal a payload to an sntrup761 public key, for its holder alone.
//!
//! The sender encapsulates to the recipient's key, derives an AES-256-GCM
//! key from the shared secret and the caller's associated data with
//! SHA3-256, and encrypts the payload in chunks of [`CHUNK_LEN`] bytes, so a
//! large payload never needs one AEAD call over all of it. Each chunk's nonce
//! is its index and whether it is the last, so a reordered, dropped,
//! appended or truncated chunk fails to open, like a flipped byte, another
//! secret key or other associated data. The key is fresh per seal (a new
//! encapsulation), so counter nonces never repeat under one key.
//!
//! Layout: `MAGIC (8) ‖ kem_ct (1039) ‖ chunk…`, where each chunk is a
//! `u32` little-endian length and the AES-GCM ciphertext with its 16-byte
//! tag. Every chunk but the last holds exactly [`CHUNK_LEN`] plaintext bytes;
//! an empty payload is one empty last chunk.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha3::{Digest, Sha3_256};

use quil_types::error::{QuilError, Result};

use crate::sntrup761::{decapsulate, encapsulate, SNTRUP761_CIPHERTEXT_LEN};

/// The format and version of a sealed payload.
pub const MAGIC: &[u8; 8] = b"QSEAL\0\0\x01";
/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// Largest payload [`seal`] accepts.
pub const MAX_PLAINTEXT: usize = 256 * 1024 * 1024;

const HEADER_LEN: usize = MAGIC.len() + SNTRUP761_CIPHERTEXT_LEN;
const KDF_TAG: &[u8] = b"quil/seal/aead-key/v1";

/// The sealed length of a payload of `plaintext_len` bytes.
pub fn sealed_len(plaintext_len: usize) -> usize {
    let chunks = plaintext_len.div_ceil(CHUNK_LEN).max(1);
    HEADER_LEN + plaintext_len + chunks * (4 + TAG_LEN)
}

fn aead(shared_secret: &[u8], aad: &[u8]) -> Result<Aes256Gcm> {
    let mut h = Sha3_256::new();
    h.update(KDF_TAG);
    h.update(shared_secret);
    h.update((aad.len() as u64).to_le_bytes());
    h.update(aad);
    let key: [u8; 32] = h.finalize().into();
    Aes256Gcm::new_from_slice(&key).map_err(|_| QuilError::Crypto("seal: AEAD key".into()))
}

fn nonce(index: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&index.to_be_bytes());
    nonce[8] = u8::from(last);
    nonce
}

/// Seal `plaintext` to `recipient_public_key`, bound to `aad`.
pub fn seal(plaintext: &[u8], recipient_public_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    seal_capped(plaintext, recipient_public_key, aad, MAX_PLAINTEXT)
}

fn seal_capped(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    aad: &[u8],
    cap: usize,
) -> Result<Vec<u8>> {
    if plaintext.len() > cap {
        return Err(QuilError::InvalidArgument(format!(
            "seal: payload of {} bytes exceeds {cap}",
            plaintext.len()
        )));
    }
    let (shared_secret, kem_ct) = encapsulate(recipient_public_key)?;
    let cipher = aead(&shared_secret, aad)?;
    let mut out = Vec::with_capacity(sealed_len(plaintext.len()));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&kem_ct);
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(CHUNK_LEN).collect()
    };
    let count = chunks.len();
    for (index, chunk) in chunks.into_iter().enumerate() {
        let nonce = nonce(index as u64, index + 1 == count);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: chunk, aad })
            .map_err(|_| QuilError::Crypto("seal: encrypt".into()))?;
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Open a payload sealed to the holder of `recipient_secret_key` with the
/// same `aad`. Any change to it, another key or other `aad` is an error.
pub fn open(sealed: &[u8], recipient_secret_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let refused = || QuilError::Crypto("sealed payload does not open with this key".into());
    if sealed.len() < HEADER_LEN || &sealed[..MAGIC.len()] != MAGIC {
        return Err(QuilError::InvalidArgument(
            "not a sealed payload of this version".into(),
        ));
    }
    let shared_secret = decapsulate(&sealed[MAGIC.len()..HEADER_LEN], recipient_secret_key)?;
    let cipher = aead(&shared_secret, aad)?;
    let mut plaintext = Vec::with_capacity(sealed.len().saturating_sub(HEADER_LEN));
    let mut at = HEADER_LEN;
    let mut index = 0u64;
    loop {
        let len_bytes: [u8; 4] = sealed
            .get(at..at + 4)
            .ok_or_else(refused)?
            .try_into()
            .map_err(|_| refused())?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if !(TAG_LEN..=CHUNK_LEN + TAG_LEN).contains(&len) {
            return Err(refused());
        }
        let body = sealed.get(at + 4..at + 4 + len).ok_or_else(refused)?;
        at += 4 + len;
        let last = at == sealed.len();
        if !last && len != CHUNK_LEN + TAG_LEN {
            return Err(refused());
        }
        let chunk = cipher
            .decrypt(
                Nonce::from_slice(&nonce(index, last)),
                Payload { msg: body, aad },
            )
            .map_err(|_| refused())?;
        plaintext.extend_from_slice(&chunk);
        if last {
            return Ok(plaintext);
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sntrup761::Sntrup761KeyPair;

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn payloads_of_every_size_round_trip() {
        let key = Sntrup761KeyPair::generate();
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN + CHUNK_LEN / 2,
        ] {
            let plaintext = payload(len);
            let sealed = seal(&plaintext, &key.public, b"request").unwrap();
            assert_eq!(sealed.len(), sealed_len(len), "{len}");
            assert!(
                !sealed
                    .windows(16.min(len.max(1)))
                    .any(|w| len >= 16 && w == &plaintext[..16]),
                "{len}: plaintext visible"
            );
            assert_eq!(
                open(&sealed, &key.secret, b"request").unwrap(),
                plaintext,
                "{len}"
            );
        }
        let a = seal(b"same", &key.public, b"x").unwrap();
        let b = seal(b"same", &key.public, b"x").unwrap();
        assert_ne!(a, b, "each seal encapsulates afresh");
    }

    #[test]
    fn another_key_or_other_associated_data_does_not_open() {
        let (key, other) = (Sntrup761KeyPair::generate(), Sntrup761KeyPair::generate());
        let sealed = seal(&payload(1000), &key.public, b"request-1").unwrap();
        assert!(open(&sealed, &other.secret, b"request-1").is_err());
        assert!(open(&sealed, &key.secret, b"request-2").is_err());
        assert!(open(&sealed, &key.secret, b"").is_err());
        assert!(
            seal(b"x", &[0u8; 10], b"").is_err(),
            "a malformed public key is an error"
        );
    }

    #[test]
    fn a_tampered_payload_does_not_open() {
        let key = Sntrup761KeyPair::generate();
        let sealed = seal(&payload(2 * CHUNK_LEN + 100), &key.public, b"aad").unwrap();
        let first = HEADER_LEN;
        let second = first + 4 + CHUNK_LEN + TAG_LEN;
        let third = second + 4 + CHUNK_LEN + TAG_LEN;
        for at in [
            0,
            9,
            HEADER_LEN - 1,
            first,
            first + 4,
            first + 4 + CHUNK_LEN + 3,
            second + 100,
            third + 4,
            sealed.len() - 1,
        ] {
            let mut flipped = sealed.clone();
            flipped[at] ^= 0x01;
            assert!(
                open(&flipped, &key.secret, b"aad").is_err(),
                "flipped byte {at} opened"
            );
        }
        assert!(
            open(&sealed[..third], &key.secret, b"aad").is_err(),
            "last chunk dropped"
        );
        assert!(
            open(&sealed[..sealed.len() - 1], &key.secret, b"aad").is_err(),
            "truncated"
        );
        let mut appended = sealed.clone();
        appended.extend_from_slice(&sealed[second..third]);
        assert!(
            open(&appended, &key.secret, b"aad").is_err(),
            "chunk appended"
        );
        let mut swapped = sealed[..first].to_vec();
        swapped.extend_from_slice(&sealed[second..third]);
        swapped.extend_from_slice(&sealed[first..second]);
        swapped.extend_from_slice(&sealed[third..]);
        assert!(
            open(&swapped, &key.secret, b"aad").is_err(),
            "chunks reordered"
        );
        assert!(
            open(&sealed[..HEADER_LEN], &key.secret, b"aad").is_err(),
            "no chunks"
        );
        assert!(open(b"short", &key.secret, b"aad").is_err());
    }

    #[test]
    fn a_payload_over_the_cap_is_refused() {
        let key = Sntrup761KeyPair::generate();
        assert!(seal_capped(&payload(101), &key.public, b"", 100).is_err());
        assert!(seal_capped(&payload(100), &key.public, b"", 100).is_ok());
    }
}
