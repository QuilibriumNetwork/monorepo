//! Recipient memo: SNTRUP761, SHAKE256 KDF, AES-256-GCM.
//! Wire: KEM ciphertext[1039] || nonce[12] || ciphertext[48] || tag[16].
//! Plaintext is amount[u128 LE] || note seed[32]. Recipient spend secrets never
//! enter sender APIs or memos. Complete erasure of underlying library
//! temporaries is not guaranteed.

use super::{
    relation::membership::{MembershipKey, NoteSecrets, RecipientSecret},
    transfer::{Output, MEMO_BYTES},
    *,
};
use super::relation::membership::IDENTITY_BYTES;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const KEM_BYTES: usize = 1039;
const NONCE_END: usize = KEM_BYTES + 12;
const BODY_END: usize = NONCE_END + 48;
const _: () = assert!(BODY_END + 16 == MEMO_BYTES);

#[derive(Debug, PartialEq, Eq)]
pub enum MemoError {
    Key,
    Context,
    Random,
    Authentication,
    InconsistentOutput,
}

/// Sender receives the output and amount opening needed for the range/balance
/// proof, but no recipient spend secret or ownership witness.
pub struct CreatedOutput {
    pub output: Output,
    pub opening: AmountOpening,
}

/// Recovery data for one escrow authority, not an independently spendable coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowRecoveryMemo {
    pub owner: [u8; IDENTITY_BYTES],
    pub ciphertext: [u8; MEMO_BYTES],
}

pub struct CreatedEscrowRecovery {
    pub commitment: AmountCommitment,
    pub opening: AmountOpening,
    pub recipient: EscrowRecoveryMemo,
    pub refund: EscrowRecoveryMemo,
}

/// Exposes only the amount opening required by a claim/refund amount proof.
/// Recovery confers no authority to consume an escrow.
pub struct OpenedEscrow(OpenedOutput);
impl OpenedEscrow {
    pub fn amount(&self) -> u128 { self.0.amount }
    pub fn opening(&self) -> &AmountOpening { &self.0.secrets.opening }
}

/// Encrypt one fresh escrow opening independently to both recovery addresses.
/// Neither recipient's spend secret enters this API. The enclosing pending
/// creation proof must bind both memos and its separate authority policy, and
/// storage must keep the escrow out of the ordinary coin accumulator.
pub fn create_escrow_recovery(
    context: &[u8; 32],
    recipient: &super::address::RecipientAddress,
    refund: &super::address::RecipientAddress,
    amount: u128,
) -> Result<CreatedEscrowRecovery, MemoError> {
    if recipient.context() != context || refund.context() != context { return Err(MemoError::Context); }
    let recipient_key = sntrup761::PublicKey::from_bytes(recipient.kem_public_key()).map_err(|_| MemoError::Key)?;
    let refund_key = sntrup761::PublicKey::from_bytes(refund.kem_public_key()).map_err(|_| MemoError::Key)?;
    let mut seed = Zeroizing::new([0; 32]);
    OsRng.try_fill_bytes(&mut seed[..]).map_err(|_| MemoError::Random)?;
    let CreatedOutput { output: to, opening } = create_output_with_seed(context, &recipient_key, recipient.recipient_key(), amount, &seed)?;
    let back = create_output_with_seed(context, &refund_key, refund.recipient_key(), amount, &seed)?;
    if to.commitment != back.output.commitment { return Err(MemoError::InconsistentOutput); }
    Ok(CreatedEscrowRecovery {
        commitment: to.commitment, opening,
        recipient: EscrowRecoveryMemo { owner: to.owner, ciphertext: to.memo },
        refund: EscrowRecoveryMemo { owner: back.output.owner, ciphertext: back.output.memo },
    })
}

pub fn open_escrow_recovery(
    context: &[u8; 32],
    kem_secret_key: &[u8],
    recipient: &RecipientSecret,
    commitment: &AmountCommitment,
    memo: &EscrowRecoveryMemo,
) -> Result<OpenedEscrow, MemoError> {
    open_output(context, kem_secret_key, recipient, &Output {
        commitment: commitment.clone(), owner: memo.owner, memo: memo.ciphertext,
    }).map(OpenedEscrow)
}

pub struct OpenedOutput {
    pub amount: u128,
    pub secrets: NoteSecrets,
}
impl Drop for OpenedOutput {
    fn drop(&mut self) {
        self.amount.zeroize();
    }
}

fn aead_key(context: &[u8; 32], kem: &[u8], shared_secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Shake256::default();
    hash.update(b"quil/token/memo-key/v2\0");
    hash.update(context);
    hash.update(kem);
    hash.update(shared_secret);
    let mut result = Zeroizing::new([0; 32]);
    hash.finalize_xof().read(&mut result[..]);
    result
}

fn associated_data(context: &[u8; 32], recipient: &[u8; IDENTITY_BYTES], output: &Output) -> Vec<u8> {
    let mut aad = b"quil/token/memo-aad/v2\0".to_vec();
    aad.extend_from_slice(context);
    aad.extend_from_slice(recipient);
    aad.extend_from_slice(&output.commitment.to_bytes());
    aad.extend_from_slice(&output.owner);
    aad.extend_from_slice(&output.memo[..KEM_BYTES]);
    aad
}

/// Create an output for a public reusable recipient address. The caller must
/// authenticate that address and use the transfer's fixed parameter context.
/// Fresh note seed, KEM encapsulation and AEAD nonce are sampled internally.
pub fn create_output(
    context: &[u8; 32],
    address: &super::address::RecipientAddress,
    amount: u128,
) -> Result<CreatedOutput, MemoError> {
    if address.context() != context {
        return Err(MemoError::Context);
    }
    create_output_inner(
        context,
        address.kem_public_key(),
        address.recipient_key(),
        amount,
    )
}

/// [`create_output`] with a caller-chosen note nonce. The nonce determines the
/// coin's opening and owner; a caller that publishes it (a public payment)
/// lets anyone check the coin's amount and payee. Never reuse a nonce.
pub fn create_output_with_nonce(
    context: &[u8; 32],
    address: &super::address::RecipientAddress,
    amount: u128,
    nonce: &[u8; 32],
) -> Result<CreatedOutput, MemoError> {
    if address.context() != context {
        return Err(MemoError::Context);
    }
    let public = sntrup761::PublicKey::from_bytes(address.kem_public_key()).map_err(|_| MemoError::Key)?;
    create_output_with_seed(context, &public, address.recipient_key(), amount, nonce)
}

fn create_output_inner(
    context: &[u8; 32],
    kem_public_key: &[u8],
    recipient: &[u8; IDENTITY_BYTES],
    amount: u128,
) -> Result<CreatedOutput, MemoError> {
    let public = sntrup761::PublicKey::from_bytes(kem_public_key).map_err(|_| MemoError::Key)?;
    let mut seed = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(&mut seed[..])
        .map_err(|_| MemoError::Random)?;
    create_output_with_seed(context, &public, recipient, amount, &seed)
}

fn create_output_with_seed(
    context: &[u8; 32],
    public: &sntrup761::PublicKey,
    recipient: &[u8; IDENTITY_BYTES],
    amount: u128,
    seed: &[u8; 32],
) -> Result<CreatedOutput, MemoError> {
    let opening = AmountOpening::from_seed(context, seed);
    let mut output = Output {
        commitment: CommitmentKey::derive(context).commit(amount, &opening),
        owner: MembershipKey::derive(context)
            .output_owner(recipient, seed)
            .ok_or(MemoError::InconsistentOutput)?
            .identity_bytes()
            .map_err(|_| MemoError::InconsistentOutput)?,
        memo: [0; MEMO_BYTES],
    };
    let (shared_secret, ciphertext) = sntrup761::encapsulate(public);
    output.memo[..KEM_BYTES].copy_from_slice(ciphertext.as_bytes());
    OsRng
        .try_fill_bytes(&mut output.memo[KEM_BYTES..NONCE_END])
        .map_err(|_| MemoError::Random)?;
    let key = aead_key(context, ciphertext.as_bytes(), shared_secret.as_bytes());
    let aad = associated_data(context, recipient, &output);
    let mut plain = Zeroizing::new([0; 48]);
    plain[..16].copy_from_slice(&amount.to_le_bytes());
    plain[16..].copy_from_slice(&seed[..]);
    let tag = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| MemoError::Key)?
        .encrypt_in_place_detached(
            Nonce::from_slice(&output.memo[KEM_BYTES..NONCE_END]),
            &aad,
            &mut plain[..],
        )
        .map_err(|_| MemoError::Authentication)?;
    output.memo[NONCE_END..BODY_END].copy_from_slice(&plain[..]);
    output.memo[BODY_END..].copy_from_slice(&tag);
    Ok(CreatedOutput { output, opening })
}

/// Authenticate, decrypt, and check both the value commitment and recipient
/// owner identity before returning a spend witness to the recipient wallet.
pub fn open_output(
    context: &[u8; 32],
    kem_secret_key: &[u8],
    recipient: &RecipientSecret,
    output: &Output,
) -> Result<OpenedOutput, MemoError> {
    let secret = sntrup761::SecretKey::from_bytes(kem_secret_key).map_err(|_| MemoError::Key)?;
    let kem =
        sntrup761::Ciphertext::from_bytes(&output.memo[..KEM_BYTES]).map_err(|_| MemoError::Key)?;
    let shared_secret = sntrup761::decapsulate(&kem, &secret);
    let key = aead_key(context, kem.as_bytes(), shared_secret.as_bytes());
    let membership = MembershipKey::derive(context);
    let aad = associated_data(context, &membership.recipient_key(recipient), output);
    let mut plain = Zeroizing::new([0; 48]);
    plain.copy_from_slice(&output.memo[NONCE_END..BODY_END]);
    Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| MemoError::Key)?
        .decrypt_in_place_detached(
            Nonce::from_slice(&output.memo[KEM_BYTES..NONCE_END]),
            &aad,
            &mut plain[..],
            Tag::from_slice(&output.memo[BODY_END..]),
        )
        .map_err(|_| MemoError::Authentication)?;
    let amount = u128::from_le_bytes(
        plain[..16]
            .try_into()
            .map_err(|_| MemoError::Authentication)?,
    );
    let seed = Zeroizing::new(
        plain[16..]
            .try_into()
            .map_err(|_| MemoError::Authentication)?,
    );
    let secrets = NoteSecrets::from_seeds(context, recipient, &seed);
    if CommitmentKey::derive(context).commit(amount, &secrets.opening) != output.commitment
        || membership
            .owner_key(&secrets.owner)
            .identity_bytes()
            .map_err(|_| MemoError::InconsistentOutput)?
            != output.owner
    {
        return Err(MemoError::InconsistentOutput);
    }
    Ok(OpenedOutput { amount, secrets })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escrow_recovery_gives_both_parties_the_same_opening_without_cross_key_access() {
        let context = [91; 32];
        let (to_public, to_secret) = sntrup761::keypair();
        let (back_public, back_secret) = sntrup761::keypair();
        let to = RecipientSecret::from_seed(&context, &[92; 32]);
        let back = RecipientSecret::from_seed(&context, &[93; 32]);
        let to_address = super::super::address::RecipientAddress::new(&context, &to, to_public.as_bytes()).unwrap();
        let back_address = super::super::address::RecipientAddress::new(&context, &back, back_public.as_bytes()).unwrap();
        let key = CommitmentKey::derive(&context);
        for amount in [0, u128::MAX] {
            let created = create_escrow_recovery(&context, &to_address, &back_address, amount).unwrap();
            assert_ne!(created.recipient.owner, created.refund.owner);
            assert_ne!(created.recipient.ciphertext, created.refund.ciphertext);
            let recipient = open_escrow_recovery(&context, to_secret.as_bytes(), &to,
                &created.commitment, &created.recipient).unwrap();
            let refund = open_escrow_recovery(&context, back_secret.as_bytes(), &back,
                &created.commitment, &created.refund).unwrap();
            for recovered in [&recipient, &refund] {
                assert_eq!(recovered.amount(), amount);
                assert_eq!(key.commit(recovered.amount(), recovered.opening()), created.commitment);
            }
            assert_eq!(key.commit(amount, &created.opening), created.commitment);
            assert!(open_escrow_recovery(&context, to_secret.as_bytes(), &to,
                &created.commitment, &created.refund).is_err());
            assert!(open_escrow_recovery(&context, back_secret.as_bytes(), &back,
                &created.commitment, &created.recipient).is_err());
            assert!(open_escrow_recovery(&context, to_secret.as_bytes(), &back,
                &created.commitment, &created.recipient).is_err());
            for index in [0, KEM_BYTES, NONCE_END, BODY_END] {
                let mut changed = created.recipient.clone();
                changed.ciphertext[index] ^= 1;
                assert!(open_escrow_recovery(&context, to_secret.as_bytes(), &to,
                    &created.commitment, &changed).is_err());
            }
            assert!(open_escrow_recovery(&[94; 32], to_secret.as_bytes(), &to,
                &created.commitment, &created.recipient).is_err());
            let changed_commitment = key.commit(amount ^ 1, &created.opening);
            assert!(open_escrow_recovery(&context, to_secret.as_bytes(), &to,
                &changed_commitment, &created.recipient).is_err());
            let fresh = create_escrow_recovery(&context, &to_address, &back_address, amount).unwrap();
            assert_ne!(fresh.commitment, created.commitment);
        }
        let other_address = super::super::address::RecipientAddress::new(&[94; 32], &back, back_public.as_bytes()).unwrap();
        assert!(matches!(create_escrow_recovery(&context, &to_address, &other_address, 1), Err(MemoError::Context)));
        assert!(matches!(create_escrow_recovery(&context, &other_address, &back_address, 1), Err(MemoError::Context)));
    }

    #[test]
    fn kdf_and_associated_data_match_independent_hashlib_vector() {
        let context = [3; 32];
        let mut output = Output {
            commitment: AmountCommitment::from_bytes(&[0; COMMITMENT_BYTES]).unwrap(),
            owner: [5; IDENTITY_BYTES],
            memo: [0; MEMO_BYTES],
        };
        output.memo[..KEM_BYTES].fill(7);
        let key = aead_key(&context, &output.memo[..KEM_BYTES], &[9; 32]);
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(&key[..]),
            "35c96761491afc2b0310b9721d0e63b9a619edc1f8c91a4119ded463271da3c3"
        );
        let aad = associated_data(&context, &[11; IDENTITY_BYTES], &output);
        assert_eq!(aad.len(), 18758);
        let mut hash = Shake256::default();
        hash.update(&aad);
        let mut digest = [0; 32];
        hash.finalize_xof().read(&mut digest);
        assert_eq!(
            hex(&digest),
            "e419e02152ce2c181b3a17453b07cd9cb3c18aa830792c73e0b47aa076afd4a2"
        );
    }
    #[test]
    fn real_kem_roundtrip_full_amounts_and_fresh_notes() {
        let context = [3; 32];
        let (public, secret) = sntrup761::keypair();
        let recipient = RecipientSecret::from_seed(&context, &[9; 32]);
        let membership = MembershipKey::derive(&context);
        let address =
            super::super::address::RecipientAddress::new(&context, &recipient, public.as_bytes())
                .unwrap();
        let address =
            super::super::address::RecipientAddress::decode(&address.encode(), &context).unwrap();
        assert!(matches!(
            create_output(&[4; 32], &address, 1),
            Err(MemoError::Context)
        ));
        let mut owners = Vec::new();
        let mut images = Vec::new();
        for amount in [0, 1, u128::MAX, u128::MAX] {
            let created = create_output(&context, &address, amount).unwrap();
            assert_eq!(created.output.memo.len(), 1115);
            assert_eq!(
                CommitmentKey::derive(&context).commit(amount, &created.opening),
                created.output.commitment
            );
            let opened =
                open_output(&context, secret.as_bytes(), &recipient, &created.output).unwrap();
            assert_eq!(opened.amount, amount);
            owners.push(created.output.owner);
            images.push(membership.key_image(&opened.secrets.owner));
        }
        for i in 0..owners.len() {
            for j in i + 1..owners.len() {
                assert_ne!(owners[i], owners[j]);
                assert_ne!(images[i], images[j]);
            }
        }
    }
    #[test]
    fn rejects_tampering_wrong_keys_and_changed_public_context() {
        let context = [3; 32];
        let (public, secret) = sntrup761::keypair();
        let (_, wrong_secret) = sntrup761::keypair();
        let recipient = RecipientSecret::from_seed(&context, &[9; 32]);
        let membership = MembershipKey::derive(&context);
        let output = create_output_inner(
            &context,
            public.as_bytes(),
            &membership.recipient_key(&recipient),
            7,
        )
        .unwrap()
        .output;
        for offset in [
            0,
            KEM_BYTES - 1,
            KEM_BYTES,
            NONCE_END - 1,
            NONCE_END,
            BODY_END - 1,
            BODY_END,
            MEMO_BYTES - 1,
        ] {
            let mut bad = output.clone();
            bad.memo[offset] ^= 1;
            assert!(matches!(
                open_output(&context, secret.as_bytes(), &recipient, &bad),
                Err(MemoError::Authentication)
            ));
        }
        assert!(open_output(&context, wrong_secret.as_bytes(), &recipient, &output).is_err());
        assert!(open_output(&[4; 32], secret.as_bytes(), &recipient, &output).is_err());
        let wrong_recipient = RecipientSecret::from_seed(&context, &[8; 32]);
        assert!(open_output(&context, secret.as_bytes(), &wrong_recipient, &output).is_err());
        let mut bad = output.clone();
        bad.owner[0] ^= 1;
        assert!(open_output(&context, secret.as_bytes(), &recipient, &bad).is_err());
        let mut bad = output.clone();
        bad.commitment =
            CommitmentKey::derive(&context).commit(8, &AmountOpening::from_seed(&context, &[0; 32]));
        assert!(open_output(&context, secret.as_bytes(), &recipient, &bad).is_err());
        assert!(matches!(
            create_output_inner(&context, &[], &membership.recipient_key(&recipient), 0),
            Err(MemoError::Key)
        ));
        assert!(matches!(
            open_output(&context, &[], &recipient, &output),
            Err(MemoError::Key)
        ));
    }
    #[test]
    fn rejects_authenticated_payload_that_does_not_open_output() {
        let context = [3; 32];
        let (public, secret) = sntrup761::keypair();
        let recipient = RecipientSecret::from_seed(&context, &[9; 32]);
        let address = MembershipKey::derive(&context).recipient_key(&recipient);
        let mut output = create_output_inner(&context, public.as_bytes(), &address, 7)
            .unwrap()
            .output;
        let ciphertext = sntrup761::Ciphertext::from_bytes(&output.memo[..KEM_BYTES]).unwrap();
        let shared = sntrup761::decapsulate(&ciphertext, &secret);
        let key = aead_key(&context, ciphertext.as_bytes(), shared.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&key[..]).unwrap();
        let aad = associated_data(&context, &address, &output);
        let nonce_bytes: [u8; 12] = output.memo[KEM_BYTES..NONCE_END].try_into().unwrap();
        let mut plain = [0; 48];
        plain.copy_from_slice(&output.memo[NONCE_END..BODY_END]);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                &aad,
                &mut plain,
                Tag::from_slice(&output.memo[BODY_END..]),
            )
            .unwrap();
        plain[..16].copy_from_slice(&8u128.to_le_bytes());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut plain)
            .unwrap();
        output.memo[NONCE_END..BODY_END].copy_from_slice(&plain);
        output.memo[BODY_END..].copy_from_slice(&tag);
        assert!(matches!(
            open_output(&context, secret.as_bytes(), &recipient, &output),
            Err(MemoError::InconsistentOutput)
        ));
    }
}
