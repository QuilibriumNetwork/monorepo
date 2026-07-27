//! Post-quantum **commit-and-encrypt** confidential fields for hypergraph
//! vertices — the replacement for the retired ECC/ElGamal `verenc` path.
//!
//! # What it provides
//!
//! For a confidential vertex field the writer stores three things:
//! - a **32-byte hash commitment** `H(tag ‖ salt ‖ len ‖ plaintext)` — this is
//!   the consensus-bound, tamper-evident binding of the plaintext (it lives in
//!   committed state; nobody can change what was written after the fact, and it
//!   can later be opened by revealing `(salt, plaintext)`);
//! - an **sntrup761 KEM ciphertext** to the designated reader's KEM public key;
//! - an **AES-256-GCM** ciphertext of the opening `(salt ‖ plaintext)` under a
//!   key derived from the KEM shared secret.
//!
//! The reader decapsulates, decrypts, and **checks the recovered opening against
//! the on-chain commitment** — so a writer cannot bind one value in state and
//! deliver a different one. Everything is post-quantum (sntrup761 KEM, AES-256,
//! SHA3-256).
//!
//! # What it deliberately does NOT provide
//!
//! This is *not* universal verifiable encryption: a third party who lacks the
//! reader key cannot verify that the ciphertext is recoverable. That property
//! (which the ECC verenc nominally had, but which the Rust node already accepted
//! on shape-only for the compressed form) was dropped on purpose — a
//! universally-verifiable lattice VE costs tens of KB per field, whereas this is
//! ~1 KB + plaintext. Consensus verifies **structure** only; binding comes from
//! the commitment being stored in state, and recoverability is the reader's
//! check.
//!
//! # ⚠ PRE-AUDIT — confidential-data path.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha3::{Digest, Sha3_256};

use quil_crypto::sntrup761::{decapsulate, encapsulate, SNTRUP761_CIPHERTEXT_LEN};

/// Hash commitment length (SHA3-256).
pub const COMMITMENT_LEN: usize = 32;
/// sntrup761 KEM ciphertext length.
pub const KEM_CT_LEN: usize = SNTRUP761_CIPHERTEXT_LEN; // 1039
/// AES-GCM nonce length (96-bit).
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Commitment/AEAD salt length.
pub const SALT_LEN: usize = 32;
/// Hard cap on a single confidential field's plaintext (DoS bound). Sized so a
/// full encoded field fits the `u16`-length-prefixed VertexAdd chunk list
/// (`64400` headroom after the ~1135-byte field overhead); larger confidential
/// payloads are split across multiple fields.
pub const MAX_PLAINTEXT: usize = 64_000;

const COMMIT_TAG: &[u8] = b"quil/hg-confidential/commit/v1";
const KDF_TAG: &[u8] = b"quil/hg-confidential/aead-key/v1";

/// A commit-and-encrypt confidential field.
///
/// Canonical wire layout (see [`encode`]/[`decode`]):
/// `[commitment 32] [kem_ct 1039] [nonce 12] [u32 LE aead_len] [aead_ct]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialField {
    /// `H(tag ‖ salt ‖ len ‖ plaintext)` — bound in consensus state.
    pub commitment: [u8; 32],
    /// sntrup761 ciphertext to the reader (1039 bytes).
    pub kem_ct: Vec<u8>,
    /// AES-256-GCM nonce (96-bit).
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext of `(salt ‖ plaintext)` incl. the 16-byte tag.
    pub aead_ct: Vec<u8>,
}

/// The hash commitment `H(tag ‖ salt ‖ len ‖ plaintext)`.
pub fn commit(salt: &[u8; SALT_LEN], plaintext: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(COMMIT_TAG);
    h.update(salt);
    h.update((plaintext.len() as u64).to_le_bytes());
    h.update(plaintext);
    h.finalize().into()
}

/// Derive the AES-256 key from the KEM shared secret.
fn aead_key(ss: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KDF_TAG);
    h.update(ss);
    h.finalize().into()
}

/// SEAL (writer/wallet side): commit to `plaintext` and encrypt the opening to
/// the reader's KEM public key. `salt` and `nonce` MUST be fresh random per
/// field (the caller supplies them, so the node code stays free of RNG and this
/// is deterministic given its inputs). Off the consensus path.
pub fn seal(
    plaintext: &[u8],
    reader_kem_pk: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Option<ConfidentialField> {
    if plaintext.len() > MAX_PLAINTEXT {
        return None;
    }
    let commitment = commit(salt, plaintext);
    // `encapsulate` returns `(shared_secret, ciphertext)`.
    let (ss, kem_ct) = encapsulate(reader_kem_pk).ok()?;
    let cipher = Aes256Gcm::new_from_slice(&aead_key(&ss)).ok()?;
    let mut opening = Vec::with_capacity(SALT_LEN + plaintext.len());
    opening.extend_from_slice(salt);
    opening.extend_from_slice(plaintext);
    let aead_ct = cipher.encrypt(Nonce::from_slice(nonce), opening.as_ref()).ok()?;
    Some(ConfidentialField { commitment, kem_ct, nonce: *nonce, aead_ct })
}

/// OPEN (reader side): decapsulate, decrypt, and verify the recovered opening
/// against the on-chain commitment. Returns the plaintext iff everything checks
/// (AEAD tag valid AND `commit(salt, plaintext) == field.commitment`).
pub fn open(field: &ConfidentialField, reader_kem_sk: &[u8]) -> Option<Vec<u8>> {
    let ss = decapsulate(&field.kem_ct, reader_kem_sk).ok()?;
    let cipher = Aes256Gcm::new_from_slice(&aead_key(&ss)).ok()?;
    let opened = cipher
        .decrypt(Nonce::from_slice(&field.nonce), field.aead_ct.as_ref())
        .ok()?;
    if opened.len() < SALT_LEN {
        return None;
    }
    let (salt, plaintext) = opened.split_at(SALT_LEN);
    let salt: [u8; SALT_LEN] = salt.try_into().ok()?;
    // Bind: the delivered opening must match what was committed in state.
    if commit(&salt, plaintext) != field.commitment {
        return None;
    }
    Some(plaintext.to_vec())
}

/// STRUCTURAL verification — the only public/consensus check. Confirms the
/// field is well-formed; binding comes from storing `commitment` in state. Does
/// NOT (and cannot, without the reader key) verify recoverability.
pub fn verify_structural(field: &ConfidentialField) -> bool {
    field.kem_ct.len() == KEM_CT_LEN
        // opening = salt(32) ‖ plaintext, plus the 16-byte GCM tag.
        && field.aead_ct.len() >= SALT_LEN + TAG_LEN
        && field.aead_ct.len() <= SALT_LEN + MAX_PLAINTEXT + TAG_LEN
}

/// Canonical encoding: `[commitment 32][kem_ct 1039][nonce 12][u32 LE aead_len][aead_ct]`.
pub fn encode(field: &ConfidentialField) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMITMENT_LEN + KEM_CT_LEN + NONCE_LEN + 4 + field.aead_ct.len());
    out.extend_from_slice(&field.commitment);
    out.extend_from_slice(&field.kem_ct);
    out.extend_from_slice(&field.nonce);
    out.extend_from_slice(&(field.aead_ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&field.aead_ct);
    out
}

/// Decode a canonical confidential field. Returns `None` on any length error.
pub fn decode(bytes: &[u8]) -> Option<ConfidentialField> {
    let mut c = 0usize;
    let take = |b: &[u8], c: &mut usize, n: usize| -> Option<Vec<u8>> {
        let end = c.checked_add(n)?;
        if end > b.len() {
            return None;
        }
        let v = b[*c..end].to_vec();
        *c = end;
        Some(v)
    };
    let commitment: [u8; 32] = take(bytes, &mut c, COMMITMENT_LEN)?.try_into().ok()?;
    let kem_ct = take(bytes, &mut c, KEM_CT_LEN)?;
    let nonce: [u8; 12] = take(bytes, &mut c, NONCE_LEN)?.try_into().ok()?;
    let len_bytes = take(bytes, &mut c, 4)?;
    let aead_len = u32::from_le_bytes(len_bytes.try_into().ok()?) as usize;
    if aead_len > SALT_LEN + MAX_PLAINTEXT + TAG_LEN {
        return None; // DoS bound before allocating
    }
    let aead_ct = take(bytes, &mut c, aead_len)?;
    if c != bytes.len() {
        return None; // no trailing garbage
    }
    Some(ConfidentialField { commitment, kem_ct, nonce, aead_ct })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::sntrup761::Sntrup761KeyPair;

    fn reader() -> Sntrup761KeyPair {
        Sntrup761KeyPair::generate()
    }

    #[test]
    fn seal_open_round_trips_and_verifies_commitment() {
        let kp = reader();
        let pt = b"confidential hypergraph vertex field payload";
        let salt = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let field = seal(pt, &kp.public, &salt, &nonce).expect("seal");
        assert!(verify_structural(&field));
        // Commitment is exactly the public hash of the opening.
        assert_eq!(field.commitment, commit(&salt, pt));
        // Reader recovers the plaintext and the commitment check passes.
        let got = open(&field, &kp.secret).expect("open");
        assert_eq!(got, pt);
    }

    #[test]
    fn encode_decode_round_trips() {
        let kp = reader();
        let field = seal(b"data", &kp.public, &[7u8; 32], &[9u8; 12]).unwrap();
        let bytes = encode(&field);
        assert_eq!(decode(&bytes).unwrap(), field);
        // Trailing garbage is rejected.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode(&extra).is_none());
        // Truncation is rejected.
        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn wrong_reader_key_cannot_open() {
        let kp = reader();
        let other = reader();
        let field = seal(b"secret", &kp.public, &[1u8; 32], &[2u8; 12]).unwrap();
        assert!(open(&field, &other.secret).is_none(), "wrong KEM key must fail");
    }

    #[test]
    fn tampered_commitment_is_caught_on_open() {
        // A writer who binds one value in state but ships a different opening is
        // caught: the recovered opening won't hash to the (state-bound) commitment.
        let kp = reader();
        let mut field = seal(b"real", &kp.public, &[3u8; 32], &[4u8; 12]).unwrap();
        field.commitment[0] ^= 0xFF; // simulate a mismatched on-chain commitment
        assert!(open(&field, &kp.secret).is_none(), "commitment mismatch must reject");
    }

    #[test]
    fn tampered_ciphertext_fails_aead() {
        let kp = reader();
        let mut field = seal(b"payload", &kp.public, &[5u8; 32], &[6u8; 12]).unwrap();
        *field.aead_ct.last_mut().unwrap() ^= 0x01; // flip a tag/ciphertext bit
        assert!(open(&field, &kp.secret).is_none(), "AEAD tag must reject tampering");
    }

    #[test]
    fn structural_rejects_bad_sizes() {
        let kp = reader();
        let mut field = seal(b"x", &kp.public, &[0u8; 32], &[0u8; 12]).unwrap();
        assert!(verify_structural(&field));
        field.kem_ct.truncate(KEM_CT_LEN - 1);
        assert!(!verify_structural(&field), "short KEM ct rejected");
    }

    #[test]
    fn empty_plaintext_is_allowed() {
        let kp = reader();
        let field = seal(b"", &kp.public, &[0u8; 32], &[1u8; 12]).unwrap();
        assert!(verify_structural(&field));
        assert_eq!(open(&field, &kp.secret).unwrap(), Vec::<u8>::new());
    }
}
