//! World-state growth priced by a confidential token operation.
//!
//! Every execution primitive is charged with the shared PoMW pricing
//! (`crate::pricing`): the cost unit is the number of bytes an admitted
//! operation adds to the world state, and the price per byte follows from the
//! current world-state size, the certified difficulty and the frame's fee
//! multiplier vote. Token operations use the same standard here: the cost is
//! the exact byte length of the vertices their admission stages (new coins,
//! an escrow, spent/consumption markers and mint receipts). Root and frontier
//! records are rewritten in place with bounded size and are not growth. The
//! proof payload is not stored and is not charged.
//!
//! Record sizes depend only on the fixed field widths of the suite, never on
//! amounts, keys or frame numbers, so the wallet can price an operation from
//! its shape before proving and execution recomputes the same value from the
//! encoded operation. Both sides must agree: this is consensus-critical.
use quil_lattice_ct::confidential::{
    custom_mint::{self, CustomMint},
    memo::EscrowRecoveryMemo,
    mint::{Mint, FALCON_PUBLIC_BYTES},
    mint_claim::MintClaim,
    pending_claim::{EscrowPolicy, PendingClaim},
    pending_create::PendingCreate,
    relation::membership::IDENTITY_BYTES,
    settlement::Settlement,
    shield::Shield,
    transfer::{parameter_context, Output, Transfer, MEMO_BYTES},
    AmountCommitment, COMMITMENT_BYTES,
};
use quil_types::error::{QuilError, Result};

/// The shape of an operation for pricing before its outputs exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// New accumulator coins written by admission.
    pub coins: usize,
    /// Spent-image, consumption or receipt markers written by admission.
    pub markers: usize,
    /// One escrow vertex for a pending transfer.
    pub escrow: bool,
}

fn placeholder_output() -> Result<Output> {
    Ok(Output {
        commitment: AmountCommitment::from_bytes(&[0; COMMITMENT_BYTES])
            .map_err(|e| QuilError::Internal(format!("placeholder commitment: {e:?}")))?,
        owner: [0; IDENTITY_BYTES],
        memo: [0; MEMO_BYTES],
    })
}

fn serialized(tree: &quil_tries::VectorCommitmentTree) -> Result<u64> {
    let bytes = quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|e| QuilError::Internal(format!("cost encoding: {e}")))?;
    Ok(bytes.len() as u64)
}

/// Bytes of one coin vertex in `context`.
pub fn coin_bytes(context: &[u8; 32]) -> Result<u64> {
    let (_, tree) = super::state::create_coin(context, 0, &placeholder_output()?, 0)?;
    serialized(&tree)
}

/// Bytes of one spent, consumption or receipt marker vertex.
pub fn marker_bytes() -> Result<u64> {
    serialized(&super::materialize::create_spent_marker_tree()?)
}

/// Bytes of one escrow vertex in `context`.
pub fn escrow_bytes(context: &[u8; 32]) -> Result<u64> {
    let policy = EscrowPolicy {
        recipient: [0; FALCON_PUBLIC_BYTES],
        refund: [0; FALCON_PUBLIC_BYTES],
        refund_after_global_frame: 0,
    };
    let recovery = EscrowRecoveryMemo { owner: [0; IDENTITY_BYTES], ciphertext: [0; MEMO_BYTES] };
    let (_, tree) = super::escrow::create_escrow(context, 0, &placeholder_output()?, &policy, &recovery)?;
    serialized(&tree)
}

/// World-state growth of an operation with the given shape in `context`.
pub fn shape_growth(context: &[u8; 32], shape: Shape) -> Result<u64> {
    let coins = coin_bytes(context)?
        .checked_mul(shape.coins as u64)
        .ok_or_else(|| QuilError::InvalidArgument("cost overflow".into()))?;
    let markers = marker_bytes()?
        .checked_mul(shape.markers as u64)
        .ok_or_else(|| QuilError::InvalidArgument("cost overflow".into()))?;
    let escrow = if shape.escrow { escrow_bytes(context)? } else { 0 };
    coins
        .checked_add(markers)
        .and_then(|sum| sum.checked_add(escrow))
        .ok_or_else(|| QuilError::InvalidArgument("cost overflow".into()))
}

/// The staged shape of an encoded operation, read through the typed codecs
/// against the envelope's own network and application. Structural only.
pub fn shape(bytes: &[u8]) -> Result<([u8; 32], Shape)> {
    let invalid = || QuilError::InvalidArgument("invalid confidential token operation".into());
    let application = super::wire::domain(bytes)?;
    let network: [u8; 32] = bytes[12..44].try_into().unwrap();
    let context = parameter_context(&network, &application);
    let shape = match u32::from_be_bytes(bytes[..4].try_into().unwrap()) {
        0x0512 => {
            let s = Transfer::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            Shape { coins: s.outputs.len(), markers: s.images.len(), escrow: false }
        }
        0x0513 if &bytes[4..12] == custom_mint::VERSION => {
            let s = CustomMint::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            // The receipt marker, plus the entitlement's consumption marker
            // under the proof basis.
            Shape { coins: s.outputs.len(), markers: 1 + usize::from(!s.entitlement_proof.is_empty()), escrow: false }
        }
        0x0513 => {
            let s = Mint::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            Shape { coins: s.outputs.len(), markers: 1, escrow: false }
        }
        0x0514 => {
            let s = PendingCreate::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            // One of the funding outputs is the escrow; the rest are change coins.
            let change = s.funding.outputs.len().saturating_sub(1);
            Shape { coins: change, markers: s.funding.images.len(), escrow: true }
        }
        0x0515 => {
            let s = PendingClaim::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            Shape { coins: s.outputs.len(), markers: 1, escrow: false }
        }
        0x0516 => {
            let s = Shield::decode(bytes, &network, &application).map_err(|_| invalid())?.statement;
            Shape { coins: s.outputs.len(), markers: 1, escrow: false }
        }
        0x0517 => {
            let c = MintClaim::decode(bytes, &network, &application).map_err(|_| invalid())?;
            Shape { coins: c.outputs.len(), markers: 1, escrow: false }
        }
        0x0518 => {
            let s = Settlement::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.funding;
            Shape { coins: s.outputs.len(), markers: s.images.len(), escrow: false }
        }
        _ => return Err(invalid()),
    };
    Ok((context, shape))
}

/// World-state growth in bytes of an encoded operation. This is the token
/// engine's cost and the quantity a QUIL operation's proof-bound fee must
/// cover at the frame's price per byte.
pub fn state_growth(bytes: &[u8]) -> Result<u64> {
    let (context, shape) = shape(bytes)?;
    let growth = shape_growth(&context, shape)?;
    if bytes.get(..4) == Some(0x0518u32.to_be_bytes().as_slice()) {
        return growth
            .checked_add(super::settlement_record::record_bytes()?)
            .ok_or_else(|| QuilError::InvalidArgument("cost overflow".into()));
    }
    Ok(growth)
}

/// Growth of a settlement with the given spend shape: its QUIL-shard writes
/// plus the GLOBAL record the relay writes.
pub fn settlement_growth(context: &[u8; 32], spend: Shape) -> Result<u64> {
    shape_growth(context, spend)?
        .checked_add(super::settlement_record::record_bytes()?)
        .ok_or_else(|| QuilError::InvalidArgument("cost overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sizes_are_fixed_and_shape_growth_adds_them() {
        let context = parameter_context(&[1; 32], &[2; 32]);
        let coin = coin_bytes(&context).unwrap();
        let marker = marker_bytes().unwrap();
        let escrow = escrow_bytes(&context).unwrap();
        assert!(coin > COMMITMENT_BYTES as u64 + IDENTITY_BYTES as u64 + MEMO_BYTES as u64);
        assert!(marker > 0 && marker < 128);
        assert!(escrow > coin);
        // A different context changes addresses, not record sizes.
        assert_eq!(coin, coin_bytes(&parameter_context(&[3; 32], &[4; 32])).unwrap());
        assert_eq!(
            shape_growth(&context, Shape { coins: 2, markers: 4, escrow: true }).unwrap(),
            2 * coin + 4 * marker + escrow
        );
        assert_eq!(shape_growth(&context, Shape { coins: 0, markers: 0, escrow: false }).unwrap(), 0);
    }
}
