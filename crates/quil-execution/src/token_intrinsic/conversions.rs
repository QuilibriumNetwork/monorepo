//! Conversions between prost-generated token proto types and the
//! canonical-bytes types in this module.

use quil_types::error::Result;
use quil_types::proto::keys as keys_pb;
use quil_types::proto::token as pb;

use super::config::{Authority, FeeBasisStruct, TokenConfiguration, TokenMintStrategy};
use super::deploy::{TokenDeploy, TokenUpdate};
use super::mint::{MintTransaction, MintTransactionInput, MintTransactionOutput};
use super::pending::{PendingTransaction, PendingTransactionInput, PendingTransactionOutput};
use super::transaction::{
    RecipientBundle, Transaction, TransactionInput, TransactionOutput,
};

// =====================================================================
// Authority
// =====================================================================

pub fn authority_from_proto(p: &pb::Authority) -> Authority {
    Authority {
        key_type: p.key_type,
        public_key: p.public_key.clone(),
        can_burn: p.can_burn,
    }
}

pub fn authority_to_proto(a: &Authority) -> pb::Authority {
    pb::Authority {
        key_type: a.key_type,
        public_key: a.public_key.clone(),
        can_burn: a.can_burn,
    }
}

// =====================================================================
// FeeBasisStruct ↔ FeeBasis
// =====================================================================

pub fn fee_basis_from_proto(p: &pb::FeeBasis) -> FeeBasisStruct {
    FeeBasisStruct {
        fee_type: p.r#type as u32,
        baseline: p.baseline.clone(),
    }
}

pub fn fee_basis_to_proto(f: &FeeBasisStruct) -> pb::FeeBasis {
    pb::FeeBasis {
        r#type: f.fee_type as i32,
        baseline: f.baseline.clone(),
    }
}

// =====================================================================
// TokenMintStrategy — nested canonical bytes for authority + fee_basis
// =====================================================================

pub fn mint_strategy_from_proto(p: &pb::TokenMintStrategy) -> Result<TokenMintStrategy> {
    let authority = match &p.authority {
        Some(a) => authority_from_proto(a).to_canonical_bytes()?,
        None => Vec::new(),
    };
    let fee_basis = match &p.fee_basis {
        Some(f) => fee_basis_from_proto(f).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenMintStrategy {
        mint_behavior: p.mint_behavior as u32,
        proof_basis: p.proof_basis as u32,
        verkle_root: p.verkle_root.clone(),
        authority,
        payment_address: p.payment_address.clone(),
        fee_basis,
    })
}

pub fn mint_strategy_to_proto(m: &TokenMintStrategy) -> Result<pb::TokenMintStrategy> {
    let authority = if !m.authority.is_empty() {
        Some(authority_to_proto(
            &Authority::from_canonical_bytes(&m.authority)?,
        ))
    } else {
        None
    };
    let fee_basis = if !m.fee_basis.is_empty() {
        Some(fee_basis_to_proto(
            &FeeBasisStruct::from_canonical_bytes(&m.fee_basis)?,
        ))
    } else {
        None
    };
    Ok(pb::TokenMintStrategy {
        mint_behavior: m.mint_behavior as i32,
        proof_basis: m.proof_basis as i32,
        verkle_root: m.verkle_root.clone(),
        authority,
        payment_address: m.payment_address.clone(),
        fee_basis,
    })
}

// =====================================================================
// TokenConfiguration
// =====================================================================

pub fn token_config_from_proto(p: &pb::TokenConfiguration) -> Result<TokenConfiguration> {
    let mint_strategy = match &p.mint_strategy {
        Some(ms) => mint_strategy_from_proto(ms)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenConfiguration {
        behavior: p.behavior,
        mint_strategy,
        units: p.units.clone(),
        supply: p.supply.clone(),
        name: p.name.as_bytes().to_vec(),
        symbol: p.symbol.as_bytes().to_vec(),
        additional_reference: p.additional_reference.clone(),
        owner_public_key: p.owner_public_key.clone(),
    })
}

pub fn token_config_to_proto(c: &TokenConfiguration) -> Result<pb::TokenConfiguration> {
    let mint_strategy = if !c.mint_strategy.is_empty() {
        let ms = TokenMintStrategy::from_canonical_bytes(&c.mint_strategy)?;
        Some(mint_strategy_to_proto(&ms)?)
    } else {
        None
    };
    Ok(pb::TokenConfiguration {
        behavior: c.behavior,
        mint_strategy,
        units: c.units.clone(),
        supply: c.supply.clone(),
        name: String::from_utf8_lossy(&c.name).into_owned(),
        symbol: String::from_utf8_lossy(&c.symbol).into_owned(),
        additional_reference: c.additional_reference.clone(),
        owner_public_key: c.owner_public_key.clone(),
    })
}

// =====================================================================
// TokenDeploy / TokenUpdate
// =====================================================================

pub fn token_deploy_from_proto(p: &pb::TokenDeploy) -> Result<TokenDeploy> {
    let config = match &p.config {
        Some(c) => token_config_from_proto(c)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenDeploy {
        config,
        rdf_schema: p.rdf_schema.clone(),
    })
}

pub fn token_deploy_to_proto(d: &TokenDeploy) -> Result<pb::TokenDeploy> {
    let config = if !d.config.is_empty() {
        Some(token_config_to_proto(
            &TokenConfiguration::from_canonical_bytes(&d.config)?,
        )?)
    } else {
        None
    };
    Ok(pb::TokenDeploy {
        config,
        rdf_schema: d.rdf_schema.clone(),
    })
}

pub fn token_update_from_proto(p: &pb::TokenUpdate) -> Result<TokenUpdate> {
    let config = match &p.config {
        Some(c) => token_config_from_proto(c)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    // The canonical field carries the RAW Falcon signature bytes (the verify
    // path `engines.rs` passes it straight to `validate_signature`/falcon_verify
    // — no 0x011C aggregate envelope). Use the proto's inner `signature` field,
    // not the wrapped envelope.
    let sig = match &p.public_key_signature_bls48581 {
        Some(s) => s.signature.clone(),
        None => Vec::new(),
    };
    Ok(TokenUpdate {
        config,
        rdf_schema: p.rdf_schema.clone(),
        public_key_signature_bls48581: sig,
    })
}

pub fn token_update_to_proto(u: &TokenUpdate) -> Result<pb::TokenUpdate> {
    let config = if !u.config.is_empty() {
        Some(token_config_to_proto(
            &TokenConfiguration::from_canonical_bytes(&u.config)?,
        )?)
    } else {
        None
    };
    // The canonical field carries the RAW inner signature bytes (see
    // `token_update_from_proto`); re-wrap it into the proto's inner
    // `signature` field only, leaving pubkey/bitmask empty.
    let public_key_signature_bls48581 = if u.public_key_signature_bls48581.is_empty() {
        None
    } else {
        Some(keys_pb::Bls48581AggregateSignature {
            signature: u.public_key_signature_bls48581.clone(),
            public_key: None,
            bitmask: Vec::new(),
        })
    };
    Ok(pb::TokenUpdate {
        config,
        rdf_schema: u.rdf_schema.clone(),
        public_key_signature_bls48581,
    })
}

// =====================================================================
// RecipientBundle
// =====================================================================

pub fn recipient_bundle_from_proto(p: &pb::RecipientBundle) -> RecipientBundle {
    RecipientBundle {
        one_time_key: p.one_time_key.clone(),
        verification_key: p.verification_key.clone(),
        coin_balance: p.coin_balance.clone(),
        mask: p.mask.clone(),
        additional_reference: p.additional_reference.clone(),
        additional_reference_key: p.additional_reference_key.clone(),
    }
}

pub fn recipient_bundle_to_proto(r: &RecipientBundle) -> pb::RecipientBundle {
    pb::RecipientBundle {
        one_time_key: r.one_time_key.clone(),
        verification_key: r.verification_key.clone(),
        coin_balance: r.coin_balance.clone(),
        mask: r.mask.clone(),
        additional_reference: r.additional_reference.clone(),
        additional_reference_key: r.additional_reference_key.clone(),
    }
}

// =====================================================================
// Transaction / Input / Output (flat field copies — nested messages
// stored as canonical bytes in the canonical type)
// =====================================================================

pub fn transaction_input_from_proto(p: &pb::TransactionInput) -> TransactionInput {
    TransactionInput {
        commitment: p.commitment.clone(),
        signature: p.signature.clone(),
        proofs: p.proofs.clone(),
    }
}

pub fn transaction_output_from_proto(p: &pb::TransactionOutput) -> Result<TransactionOutput> {
    let recipient = match &p.recipient_output {
        Some(r) => recipient_bundle_from_proto(r).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TransactionOutput {
        frame_number: p.frame_number.clone(),
        commitment: p.commitment.clone(),
        recipient_output: recipient,
    })
}

pub fn transaction_from_proto(p: &pb::Transaction) -> Result<Transaction> {
    let inputs: Vec<Vec<u8>> = p.inputs.iter()
        .map(|i| transaction_input_from_proto(i).to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<Vec<u8>> = p.outputs.iter()
        .map(|o| transaction_output_from_proto(o))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|o| o.to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    Ok(Transaction {
        domain: p.domain.clone(),
        inputs,
        outputs,
        fees: p.fees.clone(),
        range_proof: p.range_proof.clone(),
        // TraversalProof is a nested proto stored raw-prost in canonical
        // (same convention as ProverKick); re-encode it so the request
        // round-trips faithfully through the materializer.
        traversal_proof: p
            .traversal_proof
            .as_ref()
            .map(prost::Message::encode_to_vec)
            .unwrap_or_default(),
    })
}

pub fn transaction_input_to_proto(i: &TransactionInput) -> pb::TransactionInput {
    pb::TransactionInput {
        commitment: i.commitment.clone(),
        signature: i.signature.clone(),
        proofs: i.proofs.clone(),
    }
}

pub fn transaction_output_to_proto(o: &TransactionOutput) -> Result<pb::TransactionOutput> {
    let recipient_output = if o.recipient_output.is_empty() {
        None
    } else {
        Some(recipient_bundle_to_proto(&RecipientBundle::from_canonical_bytes(
            &o.recipient_output,
        )?))
    };
    Ok(pb::TransactionOutput {
        frame_number: o.frame_number.clone(),
        commitment: o.commitment.clone(),
        recipient_output,
    })
}

pub fn transaction_to_proto(t: &Transaction) -> Result<pb::Transaction> {
    let inputs: Vec<pb::TransactionInput> = t
        .inputs
        .iter()
        .map(|b| Ok(transaction_input_to_proto(&TransactionInput::from_canonical_bytes(b)?)))
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<pb::TransactionOutput> = t
        .outputs
        .iter()
        .map(|b| transaction_output_to_proto(&TransactionOutput::from_canonical_bytes(b)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(pb::Transaction {
        domain: t.domain.clone(),
        inputs,
        outputs,
        fees: t.fees.clone(),
        range_proof: t.range_proof.clone(),
        traversal_proof: if t.traversal_proof.is_empty() {
            None
        } else {
            prost::Message::decode(t.traversal_proof.as_slice()).ok()
        },
    })
}

// =====================================================================
// PendingTransaction / Input / Output
// =====================================================================

pub fn pending_transaction_input_from_proto(
    p: &pb::PendingTransactionInput,
) -> PendingTransactionInput {
    PendingTransactionInput {
        commitment: p.commitment.clone(),
        signature: p.signature.clone(),
        proofs: p.proofs.clone(),
    }
}

pub fn pending_transaction_input_to_proto(
    i: &PendingTransactionInput,
) -> pb::PendingTransactionInput {
    pb::PendingTransactionInput {
        commitment: i.commitment.clone(),
        signature: i.signature.clone(),
        proofs: i.proofs.clone(),
    }
}

pub fn pending_transaction_output_from_proto(
    p: &pb::PendingTransactionOutput,
) -> Result<PendingTransactionOutput> {
    let to = match &p.to {
        Some(r) => recipient_bundle_from_proto(r).to_canonical_bytes()?,
        None => Vec::new(),
    };
    let refund = match &p.refund {
        Some(r) => recipient_bundle_from_proto(r).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(PendingTransactionOutput {
        frame_number: p.frame_number.clone(),
        commitment: p.commitment.clone(),
        to,
        refund,
        expiration: p.expiration,
    })
}

pub fn pending_transaction_output_to_proto(
    o: &PendingTransactionOutput,
) -> Result<pb::PendingTransactionOutput> {
    let to = if o.to.is_empty() {
        None
    } else {
        Some(recipient_bundle_to_proto(&RecipientBundle::from_canonical_bytes(&o.to)?))
    };
    let refund = if o.refund.is_empty() {
        None
    } else {
        Some(recipient_bundle_to_proto(&RecipientBundle::from_canonical_bytes(&o.refund)?))
    };
    Ok(pb::PendingTransactionOutput {
        frame_number: o.frame_number.clone(),
        commitment: o.commitment.clone(),
        to,
        refund,
        expiration: o.expiration,
    })
}

pub fn pending_transaction_from_proto(p: &pb::PendingTransaction) -> Result<PendingTransaction> {
    let inputs: Vec<Vec<u8>> = p
        .inputs
        .iter()
        .map(|i| pending_transaction_input_from_proto(i).to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<Vec<u8>> = p
        .outputs
        .iter()
        .map(|o| pending_transaction_output_from_proto(o)?.to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    Ok(PendingTransaction {
        domain: p.domain.clone(),
        inputs,
        outputs,
        fees: p.fees.clone(),
        range_proof: p.range_proof.clone(),
        traversal_proof: p
            .traversal_proof
            .as_ref()
            .map(prost::Message::encode_to_vec)
            .unwrap_or_default(),
    })
}

pub fn pending_transaction_to_proto(t: &PendingTransaction) -> Result<pb::PendingTransaction> {
    let inputs: Vec<pb::PendingTransactionInput> = t
        .inputs
        .iter()
        .map(|b| {
            Ok(pending_transaction_input_to_proto(
                &PendingTransactionInput::from_canonical_bytes(b)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<pb::PendingTransactionOutput> = t
        .outputs
        .iter()
        .map(|b| pending_transaction_output_to_proto(&PendingTransactionOutput::from_canonical_bytes(b)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(pb::PendingTransaction {
        domain: t.domain.clone(),
        inputs,
        outputs,
        fees: t.fees.clone(),
        range_proof: t.range_proof.clone(),
        traversal_proof: if t.traversal_proof.is_empty() {
            None
        } else {
            prost::Message::decode(t.traversal_proof.as_slice()).ok()
        },
    })
}

// =====================================================================
// MintTransaction / Input / Output
// =====================================================================

pub fn mint_transaction_input_from_proto(p: &pb::MintTransactionInput) -> MintTransactionInput {
    MintTransactionInput {
        value: p.value.clone(),
        commitment: p.commitment.clone(),
        signature: p.signature.clone(),
        proofs: p.proofs.clone(),
        additional_reference: p.additional_reference.clone(),
        additional_reference_key: p.additional_reference_key.clone(),
    }
}

pub fn mint_transaction_input_to_proto(i: &MintTransactionInput) -> pb::MintTransactionInput {
    pb::MintTransactionInput {
        value: i.value.clone(),
        commitment: i.commitment.clone(),
        signature: i.signature.clone(),
        proofs: i.proofs.clone(),
        additional_reference: i.additional_reference.clone(),
        additional_reference_key: i.additional_reference_key.clone(),
    }
}

pub fn mint_transaction_output_from_proto(
    p: &pb::MintTransactionOutput,
) -> Result<MintTransactionOutput> {
    let recipient_output = match &p.recipient_output {
        Some(r) => recipient_bundle_from_proto(r).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(MintTransactionOutput {
        frame_number: p.frame_number.clone(),
        commitment: p.commitment.clone(),
        recipient_output,
    })
}

pub fn mint_transaction_output_to_proto(
    o: &MintTransactionOutput,
) -> Result<pb::MintTransactionOutput> {
    let recipient_output = if o.recipient_output.is_empty() {
        None
    } else {
        Some(recipient_bundle_to_proto(&RecipientBundle::from_canonical_bytes(
            &o.recipient_output,
        )?))
    };
    Ok(pb::MintTransactionOutput {
        frame_number: o.frame_number.clone(),
        commitment: o.commitment.clone(),
        recipient_output,
    })
}

pub fn mint_transaction_from_proto(p: &pb::MintTransaction) -> Result<MintTransaction> {
    let inputs: Vec<Vec<u8>> = p
        .inputs
        .iter()
        .map(|i| mint_transaction_input_from_proto(i).to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<Vec<u8>> = p
        .outputs
        .iter()
        .map(|o| mint_transaction_output_from_proto(o)?.to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    Ok(MintTransaction {
        domain: p.domain.clone(),
        inputs,
        outputs,
        fees: p.fees.clone(),
        range_proof: p.range_proof.clone(),
    })
}

pub fn mint_transaction_to_proto(t: &MintTransaction) -> Result<pb::MintTransaction> {
    let inputs: Vec<pb::MintTransactionInput> = t
        .inputs
        .iter()
        .map(|b| Ok(mint_transaction_input_to_proto(&MintTransactionInput::from_canonical_bytes(b)?)))
        .collect::<Result<Vec<_>>>()?;
    let outputs: Vec<pb::MintTransactionOutput> = t
        .outputs
        .iter()
        .map(|b| mint_transaction_output_to_proto(&MintTransactionOutput::from_canonical_bytes(b)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(pb::MintTransaction {
        domain: t.domain.clone(),
        inputs,
        outputs,
        fees: t.fees.clone(),
        range_proof: t.range_proof.clone(),
    })
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_round_trip() {
        let pb = pb::Authority { key_type: 2, public_key: vec![0xAAu8; 585], can_burn: true };
        let a = authority_from_proto(&pb);
        let back = authority_to_proto(&a);
        assert_eq!(back, pb);
    }

    #[test]
    fn fee_basis_round_trip() {
        let pb = pb::FeeBasis { r#type: 1, baseline: vec![0xBBu8; 32] };
        let f = fee_basis_from_proto(&pb);
        let back = fee_basis_to_proto(&f);
        assert_eq!(back, pb);
    }

    #[test]
    fn token_config_round_trip() {
        let pb = pb::TokenConfiguration {
            behavior: 0x3F,
            mint_strategy: Some(pb::TokenMintStrategy {
                mint_behavior: 1, proof_basis: 0,
                verkle_root: vec![], authority: None,
                payment_address: vec![], fee_basis: None,
            }),
            units: vec![0x01], supply: vec![0xFF; 32],
            name: "QUIL".into(), symbol: "Q".into(),
            additional_reference: vec![vec![0xAAu8; 64]],
            owner_public_key: vec![0xBBu8; 585],
        };
        let c = token_config_from_proto(&pb).unwrap();
        let back = token_config_to_proto(&c).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn token_config_canonical_round_trip() {
        let pb = pb::TokenConfiguration {
            behavior: 7, mint_strategy: None,
            units: vec![], supply: vec![], name: "T".into(), symbol: "T".into(),
            additional_reference: vec![], owner_public_key: vec![0xCCu8; 585],
        };
        let c = token_config_from_proto(&pb).unwrap();
        let cb = c.to_canonical_bytes().unwrap();
        let c2 = TokenConfiguration::from_canonical_bytes(&cb).unwrap();
        let back = token_config_to_proto(&c2).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn token_deploy_round_trip() {
        let pb = pb::TokenDeploy {
            config: Some(pb::TokenConfiguration {
                behavior: 1, mint_strategy: None, units: vec![], supply: vec![],
                name: "X".into(), symbol: "X".into(),
                additional_reference: vec![], owner_public_key: vec![0xAAu8; 585],
            }),
            rdf_schema: b"schema".to_vec(),
        };
        let d = token_deploy_from_proto(&pb).unwrap();
        let back = token_deploy_to_proto(&d).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn recipient_bundle_round_trip() {
        let pb = pb::RecipientBundle {
            one_time_key: vec![1u8; 57], verification_key: vec![2u8; 57],
            coin_balance: vec![3u8; 32], mask: vec![4u8; 32],
            additional_reference: vec![5u8; 64], additional_reference_key: vec![6u8; 57],
        };
        let r = recipient_bundle_from_proto(&pb);
        let back = recipient_bundle_to_proto(&r);
        assert_eq!(back, pb);
    }
}
