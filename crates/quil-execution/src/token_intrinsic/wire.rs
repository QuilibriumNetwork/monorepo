//! Structural transport checks only. Execution must decode the complete
//! operation and verify its context, authorization, proof and state transition.
use quil_types::error::{QuilError, Result};
#[cfg(all(test, feature = "confidential-tokens"))]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;

pub fn domain(bytes: &[u8]) -> Result<[u8; 32]> {
    let invalid = || QuilError::InvalidArgument("invalid confidential token carrier".into());
    if bytes.len() < 76 || bytes.len() >= 1024 * 1024 {
        return Err(invalid());
    }
    let versions: &[&[u8; 8]] = match u32::from_be_bytes(bytes[..4].try_into().unwrap()) {
        0x0512 => &[b"QCT3TX\0\x02"],
        // Reward mint (QUIL) and custom-token issuance share the prefix.
        0x0513 => &[b"QCT3MT\0\x02", b"QCT3CM\0\x02"],
        0x0514 => &[b"QCT3PE\0\x02"],
        0x0515 => &[b"QCT3PC\0\x02"],
        // A single legacy coin, or a batch (version 3).
        0x0516 => &[b"QCT3SH\0\x02", b"QCT3SH\0\x03"],
        0x0517 => &[b"QCT3MC\0\x02"],
        0x0518 => &[b"QCT3ST\0\x02"],
        // Settlement claim, carried in the destination application's bundle.
        0x0519 => &[b"QCT3SC\0\x02"],
        // Delivery of a globally committed output to its owning shard.
        0x051A => &[b"QCT3DL\0\x01", b"QCT3DE\0\x01"],
        _ => return Err(invalid()),
    };
    if !versions.iter().any(|version| &bytes[4..12] == version.as_slice()) {
        return Err(invalid());
    }
    let domain: [u8; 32] = bytes[44..76].try_into().unwrap();
    if domain == crate::domains::GLOBAL || domain == crate::domains::COMPUTE {
        return Err(invalid());
    }
    Ok(domain)
}

/// Proof-bound QUIL fee carried by a token operation, read through the
/// typed codecs against the envelope's own network/application. Custom-token
/// issuance carries no QUIL fee. Structural only: admission verifies the proof.
#[cfg(feature = "confidential-tokens")]
pub fn fee(bytes: &[u8]) -> Result<u128> {
    use quil_lattice_ct::confidential::{
        custom_mint::{self, CustomMint}, mint::Mint, mint_claim::MintClaim,
        pending_claim::PendingClaim, pending_create::PendingCreate, settlement::Settlement, shield::AnyShield,
        transfer::Transfer,
    };
    let invalid = || QuilError::InvalidArgument("invalid confidential token operation".into());
    let application = domain(bytes)?;
    let network: [u8; 32] = bytes[12..44].try_into().unwrap();
    let fee = match u32::from_be_bytes(bytes[..4].try_into().unwrap()) {
        0x0512 => Transfer::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.fee,
        0x0513 if &bytes[4..12] == custom_mint::VERSION => {
            CustomMint::decode(bytes, &network, &application).map_err(|_| invalid())?;
            0
        }
        0x0513 => Mint::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.fee,
        0x0514 => PendingCreate::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.funding.fee,
        0x0515 => PendingClaim::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.fee,
        0x0516 => AnyShield::decode(bytes, &network, &application).map_err(|_| invalid())?.fee(),
        0x0517 => MintClaim::decode(bytes, &network, &application).map_err(|_| invalid())?.fee,
        // The operation's own gas; the settlement amount is not a fee.
        0x0518 => Settlement::decode(bytes, &network, &application).map_err(|_| invalid())?.statement.fee,
        _ => return Err(invalid()),
    };
    Ok(fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_carrier_checks_bound_version_and_embedded_domain() {
        for (prefix, version) in [
            (0x0512u32, b"QCT3TX\0\x02"),
            (0x0513, b"QCT3MT\0\x02"),
            (0x0513, b"QCT3CM\0\x02"),
            (0x0514, b"QCT3PE\0\x02"),
            (0x0515, b"QCT3PC\0\x02"),
            (0x0516, b"QCT3SH\0\x02"),
            (0x0516, b"QCT3SH\0\x03"),
            (0x0517, b"QCT3MC\0\x02"),
        ] {
            let mut bytes = vec![0; 76];
            bytes[..4].copy_from_slice(&prefix.to_be_bytes());
            bytes[4..12].copy_from_slice(version);
            bytes[44..76].copy_from_slice(&crate::domains::QUIL_TOKEN);
            assert_eq!(domain(&bytes).unwrap(), crate::domains::QUIL_TOKEN);
            assert!(domain(&bytes[..75]).is_err());
            let mut oversized = bytes.clone();
            oversized.resize(1024 * 1024, 0);
            assert!(domain(&oversized).is_err());
            for system in [crate::domains::GLOBAL, crate::domains::COMPUTE] {
                let mut altered = bytes.clone();
                altered[44..76].copy_from_slice(&system);
                assert!(domain(&altered).is_err());
            }
            bytes[4] ^= 1;
            assert!(domain(&bytes).is_err());
        }
    }

    #[cfg(feature = "confidential-tokens")]
    #[test]
    fn token_fee_peek_reads_each_operation_through_its_codec() {
        use quil_lattice_ct::confidential::{
            custom_mint::{CustomMint, CustomMintStatement},
            relation::membership::{Node, NODE_BYTES},
            shield::{Shield, ShieldStatement},
            transfer::{parameter_context, Output, Transfer, TransferStatement, MEMO_BYTES},
            AmountOpening, CommitmentKey,
        };
        let network = [1; 32];
        let application = crate::domains::QUIL_TOKEN;
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[2; 32]);
        let output = Output { commitment: key.commit(10, &opening), owner: [3; IDENTITY_BYTES], memo: [4; MEMO_BYTES] };
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        // Structural fixtures: framing only, no valid proofs.
        let transfer = Transfer { statement: TransferStatement { network, application, depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[5; IDENTITY_BYTES]], fee: 7, outputs: vec![output.clone()] }, proof: proof.clone() };
        let bytes = transfer.encode().unwrap();
        assert_eq!(fee(&bytes).unwrap(), 7);
        let shield = Shield { statement: ShieldStatement { network, application, transparent_address: [6; 32],
            owner_public_key: [7; 57], amount: 12, fee: 2, outputs: vec![output.clone()] }, signature: [0; 114], proof: proof.clone() };
        assert_eq!(fee(&shield.encode().unwrap()).unwrap(), 2);
        let custom = CustomMint { statement: CustomMintStatement { network, application: [8; 32], authority_key_type: 0,
            authority_public_key: Vec::new(), entitlement_proof: Vec::new(), nonce: [9; 32], amount: 10, outputs: vec![Output {
                commitment: CommitmentKey::derive(&parameter_context(&network, &[8; 32])).commit(10, &opening), ..output.clone() }] },
            signature: Vec::new(), proof };
        assert_eq!(fee(&custom.encode().unwrap()).unwrap(), 0);
        // Truncated or unknown carriers are rejected, not priced at zero.
        assert!(fee(&bytes[..bytes.len() - 1]).is_err());
        let mut unknown = bytes.clone();
        unknown[3] = 0x18;
        assert!(fee(&unknown).is_err());
    }
}
