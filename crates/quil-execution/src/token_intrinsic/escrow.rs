//! Typed escrow storage. These records are not ordinary coins.
//! Construction does not admit a proof, authorize a claim, or mutate state.

#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use num_bigint::BigInt;
use quil_lattice_ct::confidential::{
    memo::EscrowRecoveryMemo,
    pending_claim::EscrowPolicy,
    transfer::Output,
    AmountCommitment,
};
use quil_tries::VectorCommitmentTree;
use quil_types::error::{QuilError, Result};

use super::materialize::coin_content_address;

pub const MAX_ESCROW_BLOB_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct StoredEscrow {
    pub frame_number: u64,
    /// Escrow commitment and recipient recovery, never an accumulator coin.
    pub output: Output,
    pub policy: EscrowPolicy,
    pub refund_recovery: EscrowRecoveryMemo,
}

impl StoredEscrow {
    pub fn encode(&self, context: &[u8; 32]) -> Result<([u8; 32], Vec<u8>)> {
        let (address, tree) = create_escrow(context, self.frame_number, &self.output, &self.policy, &self.refund_recovery)?;
        let bytes = quil_tries::serialize_go_tree(tree.root.as_ref())
            .map_err(|e| QuilError::Internal(format!("escrow encoding: {e}")))?;
        if bytes.len() > MAX_ESCROW_BLOB_BYTES {
            return Err(QuilError::Internal("escrow exceeds blob limit".into()));
        }
        Ok((address, bytes))
    }
}

/// Bounded untrusted RPC blob decoding. Exact re-encoding rejects trailing
/// data and noncanonical encodings before returning the content-bound record.
/// This does not establish canonical inclusion or current unspent status.
pub fn decode_escrow_blob(bytes: &[u8], context: &[u8; 32], address: &[u8; 32]) -> Result<StoredEscrow> {
    let invalid = || QuilError::InvalidArgument("invalid escrow blob".into());
    if bytes.is_empty() || bytes.len() > MAX_ESCROW_BLOB_BYTES { return Err(invalid()); }
    let tree = VectorCommitmentTree { root: quil_tries::deserialize_go_tree(bytes).map_err(|_| invalid())? };
    if quil_tries::serialize_go_tree(tree.root.as_ref()).map_err(|_| invalid())? != bytes { return Err(invalid()); }
    read_escrow(&tree, context, address)?.ok_or_else(invalid)
}

fn type_hash(context: &[u8; 32]) -> Result<[u8; 32]> {
    let mut bytes = Vec::from(b"quil/escrow/QCT3/v3\0".as_slice());
    bytes.extend_from_slice(context);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// Prepare a content-addressed vertex for an admitted operation's changeset.
/// The caller must stage consumption of funding inputs and change atomically.
pub fn create_escrow(
    context: &[u8; 32],
    frame_number: u64,
    output: &Output,
    policy: &EscrowPolicy,
    refund_recovery: &EscrowRecoveryMemo,
) -> Result<([u8; 32], VectorCommitmentTree)> {
    let mut tree = VectorCommitmentTree::new();
    for (field, value) in [
        (0, frame_number.to_be_bytes().to_vec()),
        (4, output.commitment.to_bytes().to_vec()),
        (8, policy.recipient.to_vec()),
        (12, policy.refund.to_vec()),
        (16, policy.refund_after_global_frame.to_be_bytes().to_vec()),
        (20, output.owner.to_vec()),
        (24, output.memo.to_vec()),
        (28, refund_recovery.owner.to_vec()),
        (32, refund_recovery.ciphertext.to_vec()),
    ] {
        tree.insert(&[field], &value, &[], &BigInt::from(value.len()))
            .map_err(|e| QuilError::Internal(format!("escrow: {e}")))?;
    }
    tree.insert(&[0xff; 32], &type_hash(context)?, &[], &BigInt::from(32))
        .map_err(|e| QuilError::Internal(format!("escrow: {e}")))?;
    Ok((coin_content_address(&tree)?, tree))
}

/// Ignore other types/domains; reject malformed records bearing our marker.
/// Verify the requested content address before returning policy to admission.
pub fn read_escrow(
    tree: &VectorCommitmentTree,
    context: &[u8; 32],
    address: &[u8; 32],
) -> Result<Option<StoredEscrow>> {
    if tree.get(&[0xff; 32]) != Some(type_hash(context)?.as_slice()) {
        return Ok(None);
    }
    let invalid = || QuilError::Internal("escrow: malformed stored record".into());
    if tree.leaves().len() != 10 || &coin_content_address(tree)? != address {
        return Err(invalid());
    }
    let field = |key| tree.get(&[key]).ok_or_else(invalid);
    Ok(Some(StoredEscrow {
        frame_number: u64::from_be_bytes(field(0)?.try_into().map_err(|_| invalid())?),
        output: Output {
            commitment: AmountCommitment::from_bytes(field(4)?).map_err(|_| invalid())?,
            owner: field(20)?.try_into().map_err(|_| invalid())?,
            memo: field(24)?.try_into().map_err(|_| invalid())?,
        },
        policy: EscrowPolicy {
            recipient: field(8)?.try_into().map_err(|_| invalid())?,
            refund: field(12)?.try_into().map_err(|_| invalid())?,
            refund_after_global_frame: u64::from_be_bytes(field(16)?.try_into().map_err(|_| invalid())?),
        },
        refund_recovery: EscrowRecoveryMemo {
            owner: field(28)?.try_into().map_err(|_| invalid())?,
            ciphertext: field(32)?.try_into().map_err(|_| invalid())?,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{
        mint::FALCON_PUBLIC_BYTES, transfer::{parameter_context, MEMO_BYTES},
        AmountOpening, CommitmentKey, COMMITMENT_BYTES,
    };

    fn fixture(context: &[u8; 32]) -> StoredEscrow {
        StoredEscrow {
            frame_number: 42,
            output: Output {
                commitment: CommitmentKey::derive(context).commit(u128::MAX, &AmountOpening::from_seed(context, &[81; 32])),
                owner: [82; IDENTITY_BYTES], memo: [83; MEMO_BYTES],
            },
            policy: EscrowPolicy { recipient: [84; FALCON_PUBLIC_BYTES], refund: [85; FALCON_PUBLIC_BYTES], refund_after_global_frame: u64::MAX },
            refund_recovery: EscrowRecoveryMemo { owner: [86; IDENTITY_BYTES], ciphertext: [87; MEMO_BYTES] },
        }
    }

    #[test]
    fn escrow_roundtrips_and_is_excluded_from_coin_snapshots() {
        let application = [80; 32];
        let context = parameter_context(&[79; 32], &application);
        let record = fixture(&context);
        let (address, tree) = create_escrow(&context, record.frame_number, &record.output, &record.policy, &record.refund_recovery).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert_eq!(record.encode(&context).unwrap(), (address, blob.clone()));
        assert_eq!(decode_escrow_blob(&blob, &context, &address).unwrap(), record);
        let mut trailing = blob.clone(); trailing.push(0);
        assert!(decode_escrow_blob(&trailing, &context, &address).is_err());
        assert!(decode_escrow_blob(&blob[..blob.len() - 1], &context, &address).is_err());
        assert!(decode_escrow_blob(&vec![0; MAX_ESCROW_BLOB_BYTES + 1], &context, &address).is_err());
        let restored = VectorCommitmentTree { root: quil_tries::deserialize_go_tree(&blob).unwrap() };
        assert_eq!(read_escrow(&restored, &context, &address).unwrap(), Some(record));
        assert!(read_escrow(&restored, &[78; 32], &address).unwrap().is_none());
        assert!(read_escrow(&restored, &context, &[0; 32]).is_err());
        assert!(super::super::state::read_coin(&restored, &context).unwrap().is_none());
        let mut key = application.to_vec(); key.extend_from_slice(&address);
        assert!(super::super::state::decode_snapshot_coin(&context, &application, &key, &blob).unwrap().is_none());
        let ordinary = fixture(&context).output;
        let (coin_address, coin) = super::super::state::create_coin(&context, 42, &ordinary, 0).unwrap();
        assert!(read_escrow(&coin, &context, &coin_address).unwrap().is_none());
    }

    #[test]
    fn escrow_rejects_malformed_fields_and_binds_all_content() {
        let context = [88; 32];
        let record = fixture(&context);
        for (key, size) in [(0, 8), (4, COMMITMENT_BYTES), (8, FALCON_PUBLIC_BYTES),
            (12, FALCON_PUBLIC_BYTES), (16, 8), (20, IDENTITY_BYTES), (24, MEMO_BYTES), (28, IDENTITY_BYTES), (32, MEMO_BYTES)] {
            let (address, mut tree) = create_escrow(&context, record.frame_number, &record.output, &record.policy, &record.refund_recovery).unwrap();
            let mut changed = tree.get(&[key]).unwrap().to_vec(); changed[0] ^= 1;
            tree.insert(&[key], &changed, &[], &BigInt::from(changed.len())).unwrap();
            assert_ne!(coin_content_address(&tree).unwrap(), address);
            assert!(read_escrow(&tree, &context, &address).is_err());
            let short = vec![0; size - 1];
            tree.insert(&[key], &short, &[], &BigInt::from(short.len())).unwrap();
            assert!(read_escrow(&tree, &context, &coin_content_address(&tree).unwrap()).is_err());
        }
        let (_, mut tree) = create_escrow(&context, record.frame_number, &record.output, &record.policy, &record.refund_recovery).unwrap();
        let bad = vec![255; COMMITMENT_BYTES];
        tree.insert(&[4], &bad, &[], &BigInt::from(bad.len())).unwrap();
        assert!(read_escrow(&tree, &context, &coin_content_address(&tree).unwrap()).is_err());
        let (_, mut tree) = create_escrow(&context, record.frame_number, &record.output, &record.policy, &record.refund_recovery).unwrap();
        tree.insert(&[36], &[0], &[], &BigInt::from(1)).unwrap();
        assert!(read_escrow(&tree, &context, &coin_content_address(&tree).unwrap()).is_err());
    }
}
