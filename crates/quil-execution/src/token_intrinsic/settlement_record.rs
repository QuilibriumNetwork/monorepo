//! Global settlement records: the identity, relay entry and GLOBAL vertex of a
//! cross-domain QUIL settlement.
//!
//! A settlement executes on the QUIL shard. Its entry rides the next certified
//! QUIL shard frame header to the global materializer, which writes the record
//! below into GLOBAL state. The destination application consumes it once, by a
//! membership proof against a cited canonical global root. Record construction
//! confers no authority on its own.
#[cfg(feature = "confidential-tokens")]
use quil_lattice_ct::confidential::{settlement::SettlementStatement, transfer::parameter_context};
use quil_types::error::{QuilError, Result};
#[cfg(feature = "confidential-tokens")]
use sha3::{Digest, Sha3_256};

/// Bytes of one entry: receipt ‖ parameter_context ‖ destination ‖ context ‖
/// settlement (u128 BE) ‖ payment address ‖ payment (u128 BE) ‖ claimant.
pub const ENTRY_BYTES: usize = 32 + 32 + 32 + 32 + 16 + 32 + 16 + 32;
/// Bytes of one relayed entry: source shard frame (u64 BE) ‖ entry.
pub const RELAY_ENTRY_BYTES: usize = 8 + ENTRY_BYTES;
/// Settlements one shard frame may execute. Enforced deterministically at
/// materialization; later settlements in the frame are skipped.
pub const MAX_ENTRIES_PER_FRAME: usize = 64;
/// Shard frames whose entries every header re-carries. Global leaders drop
/// shard headers that miss the anchor lockstep window, so one lost header must
/// not lose a paid settlement: frame N's header carries frames N-32 ..= N-1 and
/// the global writer skips receipts it already recorded. A settlement is lost
/// only if every one of those 32 headers misses the global chain.
pub const RELAY_WINDOW_FRAMES: u64 = 32;
/// Upper bound on relayed entries in one header.
pub const MAX_RELAY_ENTRIES: usize = MAX_ENTRIES_PER_FRAME * RELAY_WINDOW_FRAMES as usize;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("settlement record: {message}"))
}

/// What the global materializer needs to write one settlement record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SettlementEntry {
    pub receipt: [u8; 32],
    /// `parameter_context(network, QUIL)` of the paying shard. Carried so the
    /// global writer needs no network configuration; consumers check it.
    pub parameter_context: [u8; 32],
    pub destination: [u8; 32],
    /// SHA3-256 of the funded bundle, zero for a pre-funded settlement.
    pub context: [u8; 32],
    pub settlement: u128,
    /// [`payment_address`] of the payee of the settlement's public payment
    /// coin, zero without a payment.
    pub payment_address: [u8; 32],
    /// The payment coin's public value, zero without a payment.
    pub payment: u128,
    /// [`claimant_address`] of the key that may name the funded bundle of a
    /// pre-funded settlement, zero when the settlement names a `context`.
    /// Exactly one of `context` and `claimant` is set.
    pub claimant: [u8; 32],
}

/// The 32-byte identity of a pre-funded settlement's claimant key. The global
/// record carries only this, so the claim must present the exact key and type.
pub fn claimant_address(key_type: u32, public_key: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = b"quil/settlement/claimant/v1\0".to_vec();
    bytes.extend_from_slice(&key_type.to_be_bytes());
    bytes.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    bytes.extend_from_slice(public_key);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// A payee's 32-byte payment address (a token's `payment_address`): a hash of
/// the payee's complete encoded QUIL recipient address, so neither the owner
/// key nor the memo key can be substituted.
pub fn payment_address(encoded_recipient_address: &[u8]) -> Result<[u8; 32]> {
    let mut bytes = b"quil/token/payment-address/v1\0".to_vec();
    bytes.extend_from_slice(encoded_recipient_address);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

#[cfg(feature = "confidential-tokens")]
/// Stable identity shared by the QUIL shard, the global materializer, the paying
/// wallet and the consumer. Content-addressed by the proof-excluding statement.
pub fn receipt_address(statement: &SettlementStatement) -> Result<[u8; 32]> {
    let context = statement.context_bytes().map_err(|_| invalid("invalid statement"))?;
    let mut bytes = Vec::from(b"quil/settlement/v1\0".as_slice());
    bytes.extend_from_slice(&parameter_context(&statement.funding.network, &statement.funding.application));
    bytes.extend_from_slice(&Sha3_256::digest(context));
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

#[cfg(feature = "confidential-tokens")]
pub fn entry(statement: &SettlementStatement) -> Result<SettlementEntry> {
    Ok(SettlementEntry {
        receipt: receipt_address(statement)?,
        parameter_context: parameter_context(&statement.funding.network, &statement.funding.application),
        destination: statement.destination,
        context: statement.context,
        settlement: statement.settlement,
        payment_address: match &statement.payment {
            Some(payment) => payment_address(&payment.payee.encode())?,
            None => [0; 32],
        },
        payment: statement.payment.as_ref().map_or(0, |payment| payment.value),
        claimant: match &statement.claimant {
            Some(claimant) => claimant_address(claimant.key_type, &claimant.public_key)?,
            None => [0; 32],
        },
    })
}

/// The relay entry of an encoded settlement operation (`0x0518`), read against
/// the envelope's own network and application; `None` for any other type.
/// Structural only: admission verifies the proof and the network.
#[cfg(feature = "confidential-tokens")]
pub fn operation_entry(bytes: &[u8]) -> Result<Option<SettlementEntry>> {
    use quil_lattice_ct::confidential::settlement::Settlement;
    if bytes.len() < 4 || u32::from_be_bytes(bytes[..4].try_into().unwrap()) != 0x0518 {
        return Ok(None);
    }
    let application = super::wire::domain(bytes)?;
    let network: [u8; 32] = bytes[12..44].try_into().unwrap();
    let settlement = Settlement::decode(bytes, &network, &application).map_err(|_| invalid("invalid settlement"))?;
    entry(&settlement.statement).map(Some)
}

fn put_entry(bytes: &mut Vec<u8>, e: &SettlementEntry) {
    bytes.extend_from_slice(&e.receipt);
    bytes.extend_from_slice(&e.parameter_context);
    bytes.extend_from_slice(&e.destination);
    bytes.extend_from_slice(&e.context);
    bytes.extend_from_slice(&e.settlement.to_be_bytes());
    bytes.extend_from_slice(&e.payment_address);
    bytes.extend_from_slice(&e.payment.to_be_bytes());
    bytes.extend_from_slice(&e.claimant);
}

fn read_entry(c: &[u8]) -> SettlementEntry {
    SettlementEntry {
        receipt: c[..32].try_into().unwrap(),
        parameter_context: c[32..64].try_into().unwrap(),
        destination: c[64..96].try_into().unwrap(),
        context: c[96..128].try_into().unwrap(),
        settlement: u128::from_be_bytes(c[128..144].try_into().unwrap()),
        payment_address: c[144..176].try_into().unwrap(),
        payment: u128::from_be_bytes(c[176..192].try_into().unwrap()),
        claimant: c[192..224].try_into().unwrap(),
    }
}

fn canonical(entries: &[SettlementEntry]) -> bool {
    entries.len() <= MAX_ENTRIES_PER_FRAME
        && entries.windows(2).all(|w| w[0].receipt < w[1].receipt)
        && entries.iter().all(|e| {
            e.settlement != 0
                && (e.payment == 0) == (e.payment_address == [0; 32])
                // Exactly one binding, as the statement requires.
                && (e.context == [0; 32]) != (e.claimant == [0; 32])
        })
}

/// Sort one frame's entries into canonical order (by receipt). Fails on a
/// duplicate receipt, a zero amount or more than [`MAX_ENTRIES_PER_FRAME`].
pub fn canonical_frame_entries(entries: &[SettlementEntry]) -> Result<Vec<SettlementEntry>> {
    let mut sorted = entries.to_vec();
    sorted.sort();
    if !canonical(&sorted) {
        return Err(invalid("noncanonical frame entries"));
    }
    Ok(sorted)
}

/// Encoding of one frame's entries (clock store record). Empty for none.
pub fn encode_entries(entries: &[SettlementEntry]) -> Result<Vec<u8>> {
    let sorted = canonical_frame_entries(entries)?;
    let mut bytes = Vec::with_capacity(sorted.len() * ENTRY_BYTES);
    sorted.iter().for_each(|e| put_entry(&mut bytes, e));
    Ok(bytes)
}

/// Decode and require the canonical form produced by [`encode_entries`].
pub fn decode_entries(bytes: &[u8]) -> Result<Vec<SettlementEntry>> {
    if bytes.len() % ENTRY_BYTES != 0 || bytes.len() / ENTRY_BYTES > MAX_ENTRIES_PER_FRAME {
        return Err(invalid("malformed entry list"));
    }
    let entries: Vec<SettlementEntry> = bytes.chunks_exact(ENTRY_BYTES).map(read_entry).collect();
    if !canonical(&entries) {
        return Err(invalid("noncanonical entry list"));
    }
    Ok(entries)
}

/// Source frames header `frame_number` relays: `N-32 ..= N-1`, never frame 0
/// (genesis executes nothing).
pub fn relay_window(frame_number: u64) -> std::ops::RangeInclusive<u64> {
    frame_number.saturating_sub(RELAY_WINDOW_FRAMES).max(1)..=frame_number.saturating_sub(1)
}

/// Header encoding of the relay window: frames ascending, each frame's entries
/// in canonical order. Frames without settlements contribute nothing.
pub fn encode_relay(frames: &[(u64, Vec<SettlementEntry>)]) -> Result<Vec<u8>> {
    if frames.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(invalid("relay frames out of order"));
    }
    let mut bytes = Vec::new();
    for (frame, entries) in frames {
        for e in canonical_frame_entries(entries)? {
            bytes.extend_from_slice(&frame.to_be_bytes());
            put_entry(&mut bytes, &e);
        }
    }
    if bytes.len() / RELAY_ENTRY_BYTES > MAX_RELAY_ENTRIES {
        return Err(invalid("too many relayed entries"));
    }
    Ok(bytes)
}

/// Decode a header's relay window, requiring canonical form and that every
/// source frame lies in [`relay_window`] of the carrying header. Frames without
/// entries are absent from the result.
pub fn decode_relay(header_frame: u64, bytes: &[u8]) -> Result<Vec<(u64, Vec<SettlementEntry>)>> {
    if bytes.len() % RELAY_ENTRY_BYTES != 0 || bytes.len() / RELAY_ENTRY_BYTES > MAX_RELAY_ENTRIES {
        return Err(invalid("malformed relay"));
    }
    let window = relay_window(header_frame);
    let mut frames: Vec<(u64, Vec<SettlementEntry>)> = Vec::new();
    for chunk in bytes.chunks_exact(RELAY_ENTRY_BYTES) {
        let frame = u64::from_be_bytes(chunk[..8].try_into().unwrap());
        if !window.contains(&frame) {
            return Err(invalid("relayed frame outside the window"));
        }
        let entry = read_entry(&chunk[8..]);
        match frames.last_mut() {
            Some((last, entries)) if *last == frame => entries.push(entry),
            Some((last, _)) if *last > frame => return Err(invalid("relay frames out of order")),
            _ => frames.push((frame, vec![entry])),
        }
    }
    if frames.iter().any(|(_, entries)| !canonical(entries)) {
        return Err(invalid("noncanonical relay"));
    }
    Ok(frames)
}

/// Field layout of the GLOBAL record.
pub fn fields(entry: &SettlementEntry) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut tag = b"quil/settlement-record/v1\0".to_vec();
    tag.extend_from_slice(&entry.parameter_context);
    let kind = quil_crypto::poseidon::hash_bytes_to_32(&tag)?;
    Ok(vec![
        (vec![0xff; 32], kind.to_vec()),
        (vec![0], entry.parameter_context.to_vec()),
        (vec![4], entry.destination.to_vec()),
        (vec![8], entry.context.to_vec()),
        (vec![12], entry.settlement.to_be_bytes().to_vec()),
        (vec![16], entry.payment_address.to_vec()),
        (vec![20], entry.payment.to_be_bytes().to_vec()),
        (vec![24], entry.claimant.to_vec()),
    ])
}

pub fn create_record(entry: &SettlementEntry) -> Result<Vec<u8>> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in fields(entry)? {
        tree.insert(&key, &value, &[], &num_bigint::BigInt::from(value.len()))?;
    }
    quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| QuilError::ExecutionUnavailable("cannot encode settlement record".into()))
}

/// Bytes the GLOBAL record adds to world state (priced with the settlement).
pub fn record_bytes() -> Result<u64> {
    let entry = SettlementEntry { receipt: [0; 32], parameter_context: [0; 32], destination: [0; 32], context: [0; 32], settlement: 1, payment_address: [0; 32], payment: 0, claimant: [0; 32] };
    Ok(create_record(&entry)?.len() as u64)
}

#[cfg(feature = "confidential-tokens")]
/// Authenticate a settlement record at `root` (a canonical GLOBAL prover-shard
/// root). Consumption and the root's canonicity are the caller's duties.
pub fn verify_membership(network: &[u8; 32], entry: &SettlementEntry, root: &[u8; 32], proof: &[u8]) -> Result<()> {
    if entry.parameter_context != parameter_context(network, &crate::domains::QUIL_TOKEN) {
        return Err(invalid("settlement belongs to another network"));
    }
    if proof.len() > super::reward_witness::MAX_REWARD_PROOF_BYTES {
        return Err(invalid("oversized proof"));
    }
    let membership = quil_forest::MembershipProof::from_bytes(proof).map_err(|_| invalid("malformed proof"))?;
    let mut address = crate::domains::GLOBAL.to_vec();
    address.extend_from_slice(&entry.receipt);
    if membership.inputs.len() != 1 || membership.inputs[0].vertex_address != address {
        return Err(invalid("proof does not address the receipt"));
    }
    quil_forest::verify_vertex_membership(root, &membership.inputs[0], &fields(entry)?)
        .map_err(|_| invalid("record not proven at the cited root"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with(receipt: u8, settlement: u128) -> SettlementEntry {
        SettlementEntry { receipt: [receipt; 32], parameter_context: [6; 32], destination: [7; 32], context: [8; 32], settlement, payment_address: [0; 32], payment: 0, claimant: [0; 32] }
    }

    #[test]
    fn entry_lists_are_canonical_sorted_and_bounded() {
        let entries = vec![entry_with(3, 30), entry_with(1, 10), entry_with(2, 20)];
        let bytes = encode_entries(&entries).unwrap();
        assert_eq!(bytes.len(), 3 * ENTRY_BYTES);
        let decoded = decode_entries(&bytes).unwrap();
        assert_eq!(decoded.iter().map(|e| e.receipt[0]).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(encode_entries(&decoded).unwrap(), bytes);
        assert!(encode_entries(&[]).unwrap().is_empty());
        assert!(decode_entries(&[]).unwrap().is_empty());
        assert!(encode_entries(&[entry_with(1, 10), entry_with(1, 11)]).is_err());
        assert!(decode_entries(&bytes[..bytes.len() - 1]).is_err());
        let mut unsorted = Vec::new();
        unsorted.extend_from_slice(&bytes[ENTRY_BYTES..2 * ENTRY_BYTES]);
        unsorted.extend_from_slice(&bytes[..ENTRY_BYTES]);
        assert!(decode_entries(&unsorted).is_err());
        assert!(encode_entries(&[SettlementEntry { settlement: 0, ..entry_with(4, 1) }]).is_err());
        // A payment amount without a payee (or the reverse) is not canonical.
        assert!(encode_entries(&[SettlementEntry { payment: 5, ..entry_with(4, 1) }]).is_err());
        assert!(encode_entries(&[SettlementEntry { payment_address: [1; 32], ..entry_with(4, 1) }]).is_err());
        // Both bindings, or neither, is not a settlement entry.
        assert!(encode_entries(&[SettlementEntry { claimant: [1; 32], ..entry_with(4, 1) }]).is_err());
        assert!(encode_entries(&[SettlementEntry { context: [0; 32], ..entry_with(4, 1) }]).is_err());
        // A pre-funded entry round-trips.
        let prefunded = SettlementEntry { context: [0; 32], claimant: [1; 32], ..entry_with(4, 1) };
        assert_eq!(decode_entries(&encode_entries(&[prefunded]).unwrap()).unwrap(), vec![prefunded]);
        let too_many: Vec<_> = (0..=MAX_ENTRIES_PER_FRAME as u8).map(|i| entry_with(i, 1)).collect();
        assert!(encode_entries(&too_many).is_err());
    }

    #[test]
    fn relay_window_is_canonical_and_bounded_to_the_carrying_header() {
        assert!(relay_window(0).is_empty());
        assert!(relay_window(1).is_empty());
        assert_eq!(relay_window(2), 1..=1);
        assert_eq!(relay_window(40), 8..=39);
        let frames = vec![(8, vec![entry_with(2, 5), entry_with(1, 4)]), (39, vec![entry_with(3, 6)])];
        let bytes = encode_relay(&frames).unwrap();
        assert_eq!(bytes.len(), 3 * RELAY_ENTRY_BYTES);
        let decoded = decode_relay(40, &bytes).unwrap();
        assert_eq!(decoded[0].0, 8);
        assert_eq!(decoded[0].1.iter().map(|e| e.receipt[0]).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(encode_relay(&decoded).unwrap(), bytes);
        // The same bytes carried by a header whose window excludes a frame fail.
        assert!(decode_relay(41, &bytes).is_err());
        assert!(decode_relay(39, &bytes).is_err());
        assert!(decode_relay(40, &[]).unwrap().is_empty());
        assert!(encode_relay(&[(9, vec![entry_with(1, 1)]), (8, vec![entry_with(2, 1)])]).is_err());
        // Frames out of order in the bytes are refused.
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&bytes[2 * RELAY_ENTRY_BYTES..]);
        swapped.extend_from_slice(&bytes[..2 * RELAY_ENTRY_BYTES]);
        assert!(decode_relay(40, &swapped).is_err());
        assert!(decode_relay(40, &bytes[1..]).is_err());
    }

    #[test]
    fn record_binds_destination_context_and_amount() {
        let a = entry_with(1, 10);
        let fields_a = fields(&a).unwrap();
        for changed in [
            SettlementEntry { destination: [0; 32], ..a },
            SettlementEntry { context: [0; 32], ..a },
            SettlementEntry { settlement: 11, ..a },
            SettlementEntry { parameter_context: [0; 32], ..a },
            SettlementEntry { payment_address: [9; 32], payment: 5, ..a },
            SettlementEntry { payment_address: [9; 32], payment: 6, ..a },
            SettlementEntry { context: [0; 32], claimant: [9; 32], ..a },
        ] {
            assert_ne!(fields(&changed).unwrap(), fields_a);
        }
        assert!(record_bytes().unwrap() > 0);
        assert_ne!(claimant_address(3, &[1; 897]).unwrap(), claimant_address(4, &[1; 897]).unwrap());
        assert_ne!(claimant_address(3, &[1; 897]).unwrap(), claimant_address(3, &[1; 896]).unwrap());
        assert_eq!(create_record(&a).unwrap().len() as u64, record_bytes().unwrap());
        // A record of another network is refused before any proof work.
        #[cfg(feature = "confidential-tokens")]
        assert!(verify_membership(&[9; 32], &a, &[0; 32], &[]).is_err());
    }
}
