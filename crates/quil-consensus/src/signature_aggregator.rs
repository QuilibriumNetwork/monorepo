//! Weighted signature aggregator traits. Mirror of
//! `consensus/consensus_signature.go`.
//!
//! These traits describe the interfaces consumed by the vote / timeout
//! collectors. Concrete implementations (BLS aggregate-key, Ed448
//! threshold sigs, etc.) live in adapter crates like `quil-engine`.
//!
//! [`WeightedSignatureAggregatorImpl`] is a completely generic,
//! production-ready implementation that wraps a raw
//! [`SignatureAggregator`] (verify + aggregate over raw bytes) with
//! committee-membership bookkeeping + duplicate-signer tracking.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::models::{AggregatedSignature, Identity, WeightedIdentity};
use quil_types::error::{QuilError, Result};

/// Raw signature aggregator. Mirror of Go's
/// `SignatureAggregator` — scheme-agnostic verify + aggregate over
/// byte slices. BLS, Ed25519, Schnorr, etc. impls live in crypto
/// crates.
pub trait SignatureAggregator: Send + Sync {
    /// Verify `signature` over `message` using `public_key` and the
    /// supplied domain separation tag. Returns `true` on valid sig.
    fn verify_signature_raw(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
        ds_tag: &[u8],
    ) -> bool;

    /// Verify that `signature` is a valid aggregate over `messages`
    /// from `public_keys`, with the supplied DS tag. Mirror of
    /// `VerifySignatureMultiMessage`.
    fn verify_signature_multi_message(
        &self,
        public_keys: &[&[u8]],
        signature: &[u8],
        messages: &[&[u8]],
        ds_tag: &[u8],
    ) -> bool;

    /// Aggregate a set of `signatures` under `public_keys` into a
    /// single [`AggregatedSignature`]. Used by the committee-aware
    /// aggregator once it has enough individual signatures.
    fn aggregate(
        &self,
        public_keys: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<Arc<dyn AggregatedSignature>>;
}

/// Aggregates signatures of the same signature scheme and the same
/// message from different signers. Mirror of Go's
/// `WeightedSignatureAggregator`.
///
/// Implementations MUST be concurrency-safe.
pub trait WeightedSignatureAggregator: Send + Sync {
    /// Verify a single signature under the stored public keys and
    /// message. Returns:
    /// - `Ok(())` on valid signature from a valid signer
    /// - `Err(QuilError::InvalidSigner)` if `signer_id` isn't a
    ///   committee member
    /// - `Err(QuilError::InvalidSignature)` if the signature is bad
    fn verify(&self, signer_id: &Identity, sig: &[u8]) -> Result<()>;

    /// Add a (pre-verified) signature. Returns the running total
    /// weight. Duplicates surface as
    /// `Err(QuilError::DuplicatedSigner)`, invalid signers as
    /// `Err(QuilError::InvalidSigner)`. The total-weight counter is
    /// updated regardless of whether the returned result is `Ok` or
    /// `Err`.
    fn trusted_add(&self, signer_id: &Identity, sig: &[u8]) -> Result<u64>;

    /// Variant of `trusted_add` that also carries a per-signer aux
    /// payload (e.g. an app shard voter's 516-byte VDF multi-proof
    /// contribution). The aggregator stores aux per signer alongside
    /// the BLS signature and packs them into the final wire blob
    /// during `aggregate()`. Default impl drops the aux and forwards
    /// to `trusted_add` — callers that don't need aux (e.g. global
    /// consensus) get the existing behavior.
    fn trusted_add_with_aux(
        &self,
        signer_id: &Identity,
        sig: &[u8],
        _aux: &[u8],
    ) -> Result<u64> {
        self.trusted_add(signer_id, sig)
    }

    /// Current total weight of all collected signatures.
    fn total_weight(&self) -> u64;

    /// Aggregate all collected signatures into a single
    /// [`AggregatedSignature`]. The result is guaranteed to verify
    /// under the aggregate public key. Errors:
    /// - `InsufficientSignatures` if no signatures collected
    /// - `InvalidSignature` if any component sig is malformed
    ///
    /// Returns the list of weighted signers that contributed plus the
    /// aggregated signature.
    fn aggregate(&self) -> Result<(Vec<Box<dyn WeightedIdentity>>, Arc<dyn AggregatedSignature>)>;
}

/// Timeout-signature aggregator — aggregates TO votes for a single
/// rank, each potentially signed over a different `(rank, newestQCRank)`
/// message. Mirror of Go's `TimeoutSignatureAggregator`.
pub trait TimeoutSignatureAggregator: Send + Sync {
    /// Verify and add a timeout signature for a specific `newest_qc_rank`.
    /// Valid signatures mutate internal state and the returned total
    /// weight reflects the update.
    fn verify_and_add(
        &self,
        signer_id: &Identity,
        sig: &[u8],
        newest_qc_rank: u64,
    ) -> Result<u64>;

    fn total_weight(&self) -> u64;
    fn rank(&self) -> u64;

    /// Aggregate all collected timeout signatures. Returns
    /// per-signer QC-rank info plus the aggregated signature.
    fn aggregate(
        &self,
    ) -> Result<(Vec<TimeoutSignerInfo>, Arc<dyn AggregatedSignature>)>;
}

/// Per-signer QC-rank contribution to a TC. Mirror of Go's
/// `TimeoutSignerInfo`.
#[derive(Debug, Clone)]
pub struct TimeoutSignerInfo {
    pub newest_qc_rank: u64,
    pub signer: Identity,
}

/// Wraps an existing [`AggregatedSignature`] and overrides its bitmask.
/// Raw BLS aggregators (the production one in `quil-engine`) don't know
/// about committee membership, so they return an empty bitmask. The
/// committee-aware [`WeightedSignatureAggregatorImpl`] and
/// [`TimeoutSignatureAggregatorImpl`] use this wrapper at aggregation
/// time to encode "which committee indices contributed" into the
/// signature object — without that, the downstream validator's weight
/// check `decode_signers` errors with "bitmask length 0 too short for
/// committee size N".
#[derive(Debug)]
pub struct BitmaskedAggregatedSignature {
    inner: Arc<dyn AggregatedSignature>,
    bitmask: Vec<u8>,
}

impl BitmaskedAggregatedSignature {
    pub fn new(inner: Arc<dyn AggregatedSignature>, bitmask: Vec<u8>) -> Self {
        Self { inner, bitmask }
    }
}

impl AggregatedSignature for BitmaskedAggregatedSignature {
    fn signature(&self) -> &[u8] { self.inner.signature() }
    fn public_key(&self) -> &[u8] { self.inner.public_key() }
    fn bitmask(&self) -> &[u8] { &self.bitmask }
}

/// [`AggregatedSignature`] carrying a fully-packed wire blob:
/// `bls_agg(74) || u32_be(count) || concat(multi_proofs)`. Used when
/// the weighted aggregator has collected per-signer VDF multi-proof
/// aux payloads from app-shard votes — the packed blob matches Go's
/// `FrameHeader.PublicKeySignatureBLS48581.Signature` layout exactly.
/// The aggregated pubkey and committee bitmask travel alongside.
#[derive(Debug)]
pub struct PackedAggregatedSignature {
    signature_packed: Vec<u8>,
    public_key: Vec<u8>,
    bitmask: Vec<u8>,
}

impl PackedAggregatedSignature {
    pub fn new(signature_packed: Vec<u8>, public_key: Vec<u8>, bitmask: Vec<u8>) -> Self {
        Self { signature_packed, public_key, bitmask }
    }
}

impl AggregatedSignature for PackedAggregatedSignature {
    fn signature(&self) -> &[u8] { &self.signature_packed }
    fn public_key(&self) -> &[u8] { &self.public_key }
    fn bitmask(&self) -> &[u8] { &self.bitmask }
}

/// Build a packed bitmask from `committee_size` total slots, with bit
/// `index` set for each entry in `signer_indices`. Bytes are big-endian
/// (Go layout: byte 0 holds bits 0-7, byte 1 holds bits 8-15, etc.).
/// Returns an empty `Vec` when the committee is empty.
pub fn build_bitmask(committee_size: usize, signer_indices: &[usize]) -> Vec<u8> {
    if committee_size == 0 {
        return Vec::new();
    }
    let len = (committee_size + 7) / 8;
    let mut bm = vec![0u8; len];
    for &i in signer_indices {
        if i >= committee_size {
            continue;
        }
        let byte = i / 8;
        let bit = i % 8;
        bm[byte] |= 1u8 << bit;
    }
    bm
}

// =====================================================================
// WeightedSignatureAggregatorImpl: concrete committee-aware wrapper
// =====================================================================

/// Per-signer metadata stored in the weighted aggregator's index.
#[derive(Debug, Clone)]
struct SignerInfo {
    weight: u64,
    public_key: Vec<u8>,
    /// Index into the original `ids` list — preserves stable ordering
    /// for `aggregate()`.
    index: usize,
}

/// Wraps a cloneable trait object around a [`WeightedIdentity`]. We
/// can't `Clone` `Box<dyn WeightedIdentity>` directly, so we store
/// identity metadata in a plain struct.
#[derive(Debug, Clone)]
struct StoredIdentity {
    id: Identity,
    public_key: Vec<u8>,
    weight: u64,
}

impl WeightedIdentity for StoredIdentity {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn identity(&self) -> &Identity {
        &self.id
    }
    fn weight(&self) -> u64 {
        self.weight
    }
}

struct WeightedAggState {
    /// Identities whose signatures have been collected so far.
    collected: HashMap<Identity, Vec<u8>>,
    /// Per-signer auxiliary payload (e.g. VDF multi-proof). Parallel
    /// to `collected`; absent entries are treated as empty during
    /// aggregation. Packed into the final wire blob in committee-
    /// index order.
    aux: HashMap<Identity, Vec<u8>>,
    total_weight: u64,
}

/// Concrete [`WeightedSignatureAggregator`]. Mirror of Go's
/// `consensus/signature/weighted_signature_aggregator.go`.
///
/// This struct wraps a scheme-agnostic [`SignatureAggregator`] with
/// committee-membership knowledge:
///
/// - **Constructor**: take identities + pubkeys + the signing
///   message + DS tag. The aggregator assumes proofs-of-possession
///   for all identity keys have been validated externally.
/// - **`verify`**: look up the signer's pubkey, delegate to the raw
///   aggregator, translate failures into `InvalidSigner` /
///   `InvalidSignature` sentinels.
/// - **`trusted_add`**: atomically dedup + increment total weight.
/// - **`aggregate`**: stable-ordered aggregate call into the raw
///   aggregator, returning the collected weighted identities plus the
///   aggregate signature.
///
/// A weighted aggregator is used for exactly one aggregation — after
/// calling `aggregate()`, construct a fresh instance for the next
/// signature round.
pub struct WeightedSignatureAggregatorImpl {
    aggregator: Arc<dyn SignatureAggregator>,
    ids: Vec<StoredIdentity>,
    id_to_info: HashMap<Identity, SignerInfo>,
    message: Vec<u8>,
    ds_tag: Vec<u8>,
    state: RwLock<WeightedAggState>,
}

impl WeightedSignatureAggregatorImpl {
    /// Build a new weighted aggregator. Errors if `ids` and `pks`
    /// have mismatched lengths.
    pub fn new(
        ids: Vec<Box<dyn WeightedIdentity>>,
        pks: Vec<Vec<u8>>,
        message: Vec<u8>,
        ds_tag: Vec<u8>,
        aggregator: Arc<dyn SignatureAggregator>,
    ) -> Result<Self> {
        if ids.len() != pks.len() {
            return Err(QuilError::InvalidArgument(format!(
                "keys length {} and identities length {} do not match",
                pks.len(),
                ids.len()
            )));
        }
        let mut id_to_info = HashMap::new();
        let mut stored_ids = Vec::with_capacity(ids.len());
        for (i, (id, pk)) in ids.into_iter().zip(pks.into_iter()).enumerate() {
            let identity = id.identity().clone();
            let weight = id.weight();
            id_to_info.insert(
                identity.clone(),
                SignerInfo {
                    weight,
                    public_key: pk.clone(),
                    index: i,
                },
            );
            stored_ids.push(StoredIdentity {
                id: identity,
                public_key: pk,
                weight,
            });
        }
        Ok(Self {
            aggregator,
            ids: stored_ids,
            id_to_info,
            message,
            ds_tag,
            state: RwLock::new(WeightedAggState {
                collected: HashMap::new(),
                aux: HashMap::new(),
                total_weight: 0,
            }),
        })
    }
}

impl WeightedSignatureAggregator for WeightedSignatureAggregatorImpl {
    fn verify(&self, signer_id: &Identity, sig: &[u8]) -> Result<()> {
        let info = self.id_to_info.get(signer_id).ok_or_else(|| {
            QuilError::InvalidSigner(format!("{} is not an authorized signer", hex::encode(signer_id)))
        })?;
        let ok = self.aggregator.verify_signature_raw(
            &info.public_key,
            sig,
            &self.message,
            &self.ds_tag,
        );
        if !ok {
            return Err(QuilError::InvalidSignature(format!(
                "invalid signature from {}",
                hex::encode(signer_id)
            )));
        }
        Ok(())
    }

    fn trusted_add(&self, signer_id: &Identity, sig: &[u8]) -> Result<u64> {
        self.trusted_add_with_aux(signer_id, sig, &[])
    }

    fn trusted_add_with_aux(
        &self,
        signer_id: &Identity,
        sig: &[u8],
        aux: &[u8],
    ) -> Result<u64> {
        let info = self.id_to_info.get(signer_id).ok_or_else(|| {
            QuilError::InvalidSigner(format!("{} is not an authorized signer", hex::encode(signer_id)))
        })?;
        let mut guard = self.state.write().unwrap();
        if guard.collected.contains_key(signer_id) {
            return Err(QuilError::DuplicatedSigner(format!(
                "signature from {} was already added",
                hex::encode(signer_id)
            )));
        }
        guard.collected.insert(signer_id.clone(), sig.to_vec());
        if !aux.is_empty() {
            guard.aux.insert(signer_id.clone(), aux.to_vec());
        }
        guard.total_weight += info.weight;
        Ok(guard.total_weight)
    }

    fn total_weight(&self) -> u64 {
        self.state.read().unwrap().total_weight
    }

    fn aggregate(
        &self,
    ) -> Result<(Vec<Box<dyn WeightedIdentity>>, Arc<dyn AggregatedSignature>)> {
        let guard = self.state.read().unwrap();
        if guard.collected.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "no signatures collected".into(),
            ));
        }

        // Collect (index, pk, sig, identity) tuples then sort by index
        // to match Go's stable ordering (which iterates a map but
        // threads original indices through `w.ids[w.idToInfo[id].index]`).
        let mut tuples: Vec<(usize, &[u8], &[u8], &StoredIdentity)> = Vec::new();
        for (id, sig) in guard.collected.iter() {
            let info = self
                .id_to_info
                .get(id)
                .expect("internal: collected signer not in id_to_info");
            let stored = &self.ids[info.index];
            tuples.push((info.index, &info.public_key, sig.as_slice(), stored));
        }
        tuples.sort_by_key(|(idx, _, _, _)| *idx);

        let pks: Vec<&[u8]> = tuples.iter().map(|(_, pk, _, _)| *pk).collect();
        let sigs: Vec<&[u8]> = tuples.iter().map(|(_, _, sig, _)| *sig).collect();
        let signers: Vec<Box<dyn WeightedIdentity>> = tuples
            .iter()
            .map(|(_, _, _, stored)| {
                Box::new((*stored).clone()) as Box<dyn WeightedIdentity>
            })
            .collect();
        let indices: Vec<usize> = tuples.iter().map(|(idx, _, _, _)| *idx).collect();

        let raw_agg = self.aggregator.aggregate(&pks, &sigs)?;
        // Wrap with a bitmask identifying which committee positions
        // contributed. Without this the downstream validator's
        // `decode_signers` weight check rejects the QC for "bitmask
        // length 0 too short for committee size N".
        let bitmask = build_bitmask(self.ids.len(), &indices);

        // App shard votes carry per-voter VDF multi-proof contributions
        // in their `aux` payload. When any signer supplied a multi-proof,
        // pack the final signature blob as Go does:
        //   bls_agg(74) || u32_be(count) || concat(multi_proofs)
        // The multi-proofs are emitted in committee-index order so the
        // verifier's `verify_multi_proof` walks them in lockstep with
        // the bitmask-derived participant ids.
        let any_aux = tuples
            .iter()
            .any(|(_, _, _, stored)| {
                guard
                    .aux
                    .get(stored.identity())
                    .map(|v| !v.is_empty())
                    .unwrap_or(false)
            });
        let agg_sig: Arc<dyn AggregatedSignature> = if any_aux {
            let mut multi_proofs: Vec<Vec<u8>> = Vec::with_capacity(tuples.len());
            for (_, _, _, stored) in &tuples {
                let mp = guard
                    .aux
                    .get(stored.identity())
                    .cloned()
                    .unwrap_or_default();
                multi_proofs.push(mp);
            }
            let mut packed: Vec<u8> = Vec::with_capacity(
                raw_agg.signature().len()
                    + 4
                    + multi_proofs.iter().map(|v| v.len()).sum::<usize>(),
            );
            packed.extend_from_slice(raw_agg.signature());
            let count = u32::try_from(multi_proofs.len()).unwrap_or(0);
            packed.extend_from_slice(&count.to_be_bytes());
            for mp in &multi_proofs {
                packed.extend_from_slice(mp);
            }
            Arc::new(PackedAggregatedSignature::new(
                packed,
                raw_agg.public_key().to_vec(),
                bitmask,
            ))
        } else {
            Arc::new(BitmaskedAggregatedSignature::new(raw_agg, bitmask))
                as Arc<dyn AggregatedSignature>
        };
        Ok((signers, agg_sig))
    }
}

// =====================================================================
// TimeoutSignatureAggregatorImpl: per-rank timeout aggregator
// =====================================================================

use crate::verification::make_timeout_message;

struct TimeoutSigEntry {
    sig: Vec<u8>,
    newest_qc_rank: u64,
}

struct TimeoutAggState {
    signatures: HashMap<Identity, TimeoutSigEntry>,
    total_weight: u64,
}

/// Concrete [`TimeoutSignatureAggregator`]. Mirror of Go's
/// `consensus/timeoutcollector/aggregation.go::TimeoutSignatureAggregator`.
///
/// Unlike the vote aggregator, each signer contributes a signature
/// over a potentially-different message (`MakeTimeoutMessage(filter,
/// rank, newest_qc_rank)`), because replicas include their own
/// highest-known QC rank. The aggregator verifies each signature
/// against the signer-specific message before accepting it, then
/// aggregates all collected signatures in one shot via the raw
/// [`SignatureAggregator`].
pub struct TimeoutSignatureAggregatorImpl {
    aggregator: Arc<dyn SignatureAggregator>,
    filter: Vec<u8>,
    ds_tag: Vec<u8>,
    rank: u64,
    id_to_info: HashMap<Identity, SignerInfo>,
    state: RwLock<TimeoutAggState>,
}

impl TimeoutSignatureAggregatorImpl {
    /// Build a new timeout aggregator for `rank`. Errors if the list
    /// of authorized signers is empty.
    pub fn new(
        aggregator: Arc<dyn SignatureAggregator>,
        filter: Vec<u8>,
        rank: u64,
        ids: Vec<Box<dyn WeightedIdentity>>,
        ds_tag: Vec<u8>,
    ) -> Result<Self> {
        if ids.is_empty() {
            return Err(QuilError::InvalidArgument(
                "number of participants must be larger than 0".into(),
            ));
        }
        let mut id_to_info = HashMap::new();
        for (i, id) in ids.into_iter().enumerate() {
            let identity = id.identity().clone();
            id_to_info.insert(
                identity,
                SignerInfo {
                    weight: id.weight(),
                    public_key: id.public_key().to_vec(),
                    index: i,
                },
            );
        }
        Ok(Self {
            aggregator,
            filter,
            ds_tag,
            rank,
            id_to_info,
            state: RwLock::new(TimeoutAggState {
                signatures: HashMap::new(),
                total_weight: 0,
            }),
        })
    }
}

impl TimeoutSignatureAggregator for TimeoutSignatureAggregatorImpl {
    fn verify_and_add(
        &self,
        signer_id: &Identity,
        sig: &[u8],
        newest_qc_rank: u64,
    ) -> Result<u64> {
        let info = self.id_to_info.get(signer_id).ok_or_else(|| {
            QuilError::InvalidSigner(format!("{} is not an authorized signer", hex::encode(signer_id)))
        })?;

        // Fast check: already added?
        {
            let guard = self.state.read().unwrap();
            if guard.signatures.contains_key(signer_id) {
                return Err(QuilError::DuplicatedSigner(format!(
                    "signature from {} was already added",
                    hex::encode(signer_id)
                )));
            }
        }

        // Expensive verify before the write lock.
        let msg = make_timeout_message(&self.filter, self.rank, newest_qc_rank);
        let valid = self.aggregator.verify_signature_raw(
            &info.public_key,
            sig,
            &msg,
            &self.ds_tag,
        );
        if !valid {
            return Err(QuilError::InvalidSignature(format!(
                "invalid signature from {}",
                hex::encode(signer_id)
            )));
        }

        let mut guard = self.state.write().unwrap();
        // Double-check under the write lock.
        if guard.signatures.contains_key(signer_id) {
            return Err(QuilError::DuplicatedSigner(format!(
                "signature from {} was already added",
                hex::encode(signer_id)
            )));
        }
        guard.signatures.insert(
            signer_id.clone(),
            TimeoutSigEntry {
                sig: sig.to_vec(),
                newest_qc_rank,
            },
        );
        guard.total_weight += info.weight;
        Ok(guard.total_weight)
    }

    fn total_weight(&self) -> u64 {
        self.state.read().unwrap().total_weight
    }

    fn rank(&self) -> u64 {
        self.rank
    }

    fn aggregate(
        &self,
    ) -> Result<(Vec<TimeoutSignerInfo>, Arc<dyn AggregatedSignature>)> {
        let guard = self.state.read().unwrap();
        if guard.signatures.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "cannot aggregate an empty list of signatures".into(),
            ));
        }

        // Stable order by original signer index (matches Go's
        // implementation within the aggregator context).
        let mut tuples: Vec<(usize, &[u8], &[u8], Identity, u64)> = Vec::new();
        for (id, entry) in guard.signatures.iter() {
            let info = self
                .id_to_info
                .get(id)
                .expect("internal: collected signer missing from id_to_info");
            tuples.push((
                info.index,
                &info.public_key,
                entry.sig.as_slice(),
                id.clone(),
                entry.newest_qc_rank,
            ));
        }
        tuples.sort_by_key(|(idx, _, _, _, _)| *idx);

        let pks: Vec<&[u8]> = tuples.iter().map(|(_, pk, _, _, _)| *pk).collect();
        let sigs: Vec<&[u8]> = tuples.iter().map(|(_, _, sig, _, _)| *sig).collect();
        let signers: Vec<TimeoutSignerInfo> = tuples
            .iter()
            .map(|(_, _, _, id, qc_rank)| TimeoutSignerInfo {
                newest_qc_rank: *qc_rank,
                signer: id.clone(),
            })
            .collect();
        let indices: Vec<usize> = tuples.iter().map(|(idx, _, _, _, _)| *idx).collect();

        let raw_agg = self.aggregator.aggregate(&pks, &sigs)?;
        // Same as `WeightedSignatureAggregatorImpl::aggregate` — wrap
        // the raw BLS aggregate with a bitmask so the downstream TC
        // validator (`validate_timeout_certificate`) can decode the
        // signer subset against committee size. `id_to_info.len()` is
        // the count of authorized signers passed to `new`.
        let bitmask = build_bitmask(self.id_to_info.len(), &indices);
        let agg_sig: Arc<dyn AggregatedSignature> = Arc::new(
            BitmaskedAggregatedSignature::new(raw_agg, bitmask),
        );
        Ok((signers, agg_sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex;

    // A stub signature aggregator that:
    // - accepts any sig whose bytes == b"good"
    // - aggregates by concatenating input sigs into a single buffer
    #[derive(Default)]
    struct StubRawAgg {
        aggregates_seen: Mutex<StdHashMap<Vec<u8>, usize>>,
    }
    impl SignatureAggregator for StubRawAgg {
        fn verify_signature_raw(
            &self,
            _public_key: &[u8],
            signature: &[u8],
            _message: &[u8],
            _ds_tag: &[u8],
        ) -> bool {
            signature == b"good"
        }
        fn verify_signature_multi_message(
            &self,
            _public_keys: &[&[u8]],
            _signature: &[u8],
            _messages: &[&[u8]],
            _ds_tag: &[u8],
        ) -> bool {
            true
        }
        fn aggregate(
            &self,
            public_keys: &[&[u8]],
            signatures: &[&[u8]],
        ) -> Result<Arc<dyn AggregatedSignature>> {
            let mut concat = Vec::new();
            for s in signatures {
                concat.extend_from_slice(s);
            }
            let mut pkcat = Vec::new();
            for p in public_keys {
                pkcat.extend_from_slice(p);
            }
            let mut seen = self.aggregates_seen.lock().unwrap();
            *seen.entry(concat.clone()).or_insert(0) += 1;
            Ok(Arc::new(StubAggregated {
                sig: concat,
                pk: pkcat,
            }))
        }
    }

    #[derive(Debug)]
    struct StubAggregated {
        sig: Vec<u8>,
        pk: Vec<u8>,
    }
    impl AggregatedSignature for StubAggregated {
        fn signature(&self) -> &[u8] {
            &self.sig
        }
        fn public_key(&self) -> &[u8] {
            &self.pk
        }
        fn bitmask(&self) -> &[u8] {
            &[]
        }
    }

    // Minimal WeightedIdentity for tests.
    #[derive(Debug, Clone)]
    struct TestId {
        id: Identity,
        pk: Vec<u8>,
        weight: u64,
    }
    impl WeightedIdentity for TestId {
        fn public_key(&self) -> &[u8] {
            &self.pk
        }
        fn identity(&self) -> &Identity {
            &self.id
        }
        fn weight(&self) -> u64 {
            self.weight
        }
    }

    fn build_agg(
        ids: Vec<(&str, &[u8], u64)>,
    ) -> WeightedSignatureAggregatorImpl {
        let mut weighted_ids: Vec<Box<dyn WeightedIdentity>> = Vec::new();
        let mut pks: Vec<Vec<u8>> = Vec::new();
        for (name, pk, weight) in ids {
            let pk_vec = pk.to_vec();
            weighted_ids.push(Box::new(TestId {
                id: name.into(),
                pk: pk_vec.clone(),
                weight,
            }));
            pks.push(pk_vec);
        }
        let raw: Arc<dyn SignatureAggregator> = Arc::new(StubRawAgg::default());
        WeightedSignatureAggregatorImpl::new(
            weighted_ids,
            pks,
            b"message".to_vec(),
            b"dstag".to_vec(),
            raw,
        )
        .unwrap()
    }

    #[test]
    fn constructor_length_mismatch_errors() {
        let raw: Arc<dyn SignatureAggregator> = Arc::new(StubRawAgg::default());
        let ids: Vec<Box<dyn WeightedIdentity>> = vec![Box::new(TestId {
            id: "alice".into(),
            pk: b"pkA".to_vec(),
            weight: 1,
        })];
        let pks = vec![b"pkA".to_vec(), b"pkB".to_vec()];
        match WeightedSignatureAggregatorImpl::new(
            ids,
            pks,
            b"msg".to_vec(),
            b"ds".to_vec(),
            raw,
        ) {
            Ok(_) => panic!("expected length mismatch error"),
            Err(QuilError::InvalidArgument(_)) => {}
            Err(e) => panic!("expected InvalidArgument, got {:?}", e),
        }
    }

    #[test]
    fn verify_unknown_signer_is_invalid_signer() {
        let agg = build_agg(vec![("alice", b"pkA", 1)]);
        let err = agg.verify(&b"bob".to_vec(), b"good").unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn verify_bad_signature_is_invalid_signature() {
        let agg = build_agg(vec![("alice", b"pkA", 1)]);
        let err = agg.verify(&b"alice".to_vec(), b"bad").unwrap_err();
        assert!(err.is_invalid_signature());
    }

    #[test]
    fn verify_good_signature_succeeds() {
        let agg = build_agg(vec![("alice", b"pkA", 1)]);
        agg.verify(&b"alice".to_vec(), b"good").unwrap();
    }

    #[test]
    fn trusted_add_increments_total_weight() {
        let agg = build_agg(vec![
            ("alice", b"pkA", 3),
            ("bob", b"pkB", 5),
        ]);
        assert_eq!(agg.total_weight(), 0);
        let w1 = agg.trusted_add(&b"alice".to_vec(), b"good").unwrap();
        assert_eq!(w1, 3);
        let w2 = agg.trusted_add(&b"bob".to_vec(), b"good").unwrap();
        assert_eq!(w2, 8);
        assert_eq!(agg.total_weight(), 8);
    }

    #[test]
    fn trusted_add_duplicate_errors() {
        let agg = build_agg(vec![("alice", b"pkA", 3)]);
        agg.trusted_add(&b"alice".to_vec(), b"good").unwrap();
        let err = agg.trusted_add(&b"alice".to_vec(), b"good").unwrap_err();
        assert!(err.is_duplicated_signer());
        // Weight stays unchanged after duplicate.
        assert_eq!(agg.total_weight(), 3);
    }

    #[test]
    fn trusted_add_unknown_signer_errors() {
        let agg = build_agg(vec![("alice", b"pkA", 3)]);
        let err = agg.trusted_add(&b"stranger".to_vec(), b"good").unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn aggregate_empty_errors() {
        let agg = build_agg(vec![("alice", b"pkA", 1)]);
        let err = agg.aggregate().unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn aggregate_returns_stable_ordering() {
        let agg = build_agg(vec![
            ("alice", b"pkA", 1),
            ("bob", b"pkB", 1),
            ("carol", b"pkC", 1),
        ]);
        // Add in reverse order.
        agg.trusted_add(&b"carol".to_vec(), b"sC").unwrap();
        agg.trusted_add(&b"alice".to_vec(), b"sA").unwrap();
        agg.trusted_add(&b"bob".to_vec(), b"sB").unwrap();
        let (signers, agg_sig) = agg.aggregate().unwrap();
        // Stable ordering: by original index (alice, bob, carol).
        assert_eq!(signers.len(), 3);
        assert_eq!(signers[0].identity(), &b"alice".to_vec());
        assert_eq!(signers[1].identity(), &b"bob".to_vec());
        assert_eq!(signers[2].identity(), &b"carol".to_vec());
        // Aggregated sig is the concatenation in that same order.
        assert_eq!(agg_sig.signature(), b"sAsBsC");
        assert_eq!(agg_sig.public_key(), b"pkApkBpkC");
    }

    // =================================================================
    // Timeout signature aggregator tests
    // =================================================================

    /// Raw aggregator that accepts *any* signature (used when we only
    /// care about bookkeeping, not signature validity).
    #[derive(Default)]
    struct PermissiveRawAgg;
    impl SignatureAggregator for PermissiveRawAgg {
        fn verify_signature_raw(
            &self,
            _public_key: &[u8],
            _signature: &[u8],
            _message: &[u8],
            _ds_tag: &[u8],
        ) -> bool {
            true
        }
        fn verify_signature_multi_message(
            &self,
            _public_keys: &[&[u8]],
            _signature: &[u8],
            _messages: &[&[u8]],
            _ds_tag: &[u8],
        ) -> bool {
            true
        }
        fn aggregate(
            &self,
            public_keys: &[&[u8]],
            signatures: &[&[u8]],
        ) -> Result<Arc<dyn AggregatedSignature>> {
            let mut sig = Vec::new();
            for s in signatures {
                sig.extend_from_slice(s);
            }
            let mut pk = Vec::new();
            for p in public_keys {
                pk.extend_from_slice(p);
            }
            Ok(Arc::new(StubAggregated { sig, pk }))
        }
    }

    fn build_timeout_agg(
        rank: u64,
        ids: Vec<(&str, &[u8], u64)>,
    ) -> TimeoutSignatureAggregatorImpl {
        let weighted: Vec<Box<dyn WeightedIdentity>> = ids
            .into_iter()
            .map(|(id, pk, w)| {
                Box::new(TestId {
                    id: id.into(),
                    pk: pk.to_vec(),
                    weight: w,
                }) as Box<dyn WeightedIdentity>
            })
            .collect();
        let raw: Arc<dyn SignatureAggregator> = Arc::new(PermissiveRawAgg);
        TimeoutSignatureAggregatorImpl::new(
            raw,
            b"filter".to_vec(),
            rank,
            weighted,
            b"dstag".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn timeout_constructor_rejects_empty_ids() {
        let raw: Arc<dyn SignatureAggregator> = Arc::new(PermissiveRawAgg);
        match TimeoutSignatureAggregatorImpl::new(
            raw,
            b"f".to_vec(),
            5,
            vec![],
            b"ds".to_vec(),
        ) {
            Ok(_) => panic!("expected empty-ids rejection"),
            Err(QuilError::InvalidArgument(_)) => {}
            Err(e) => panic!("expected InvalidArgument, got {:?}", e),
        }
    }

    #[test]
    fn timeout_verify_and_add_increments_weight() {
        let agg = build_timeout_agg(
            5,
            vec![("alice", b"pkA", 3), ("bob", b"pkB", 5)],
        );
        assert_eq!(agg.rank(), 5);
        assert_eq!(agg.total_weight(), 0);
        let w1 = agg.verify_and_add(&b"alice".to_vec(), b"sA", 4).unwrap();
        assert_eq!(w1, 3);
        let w2 = agg.verify_and_add(&b"bob".to_vec(), b"sB", 3).unwrap();
        assert_eq!(w2, 8);
        assert_eq!(agg.total_weight(), 8);
    }

    #[test]
    fn timeout_duplicate_signer_errors() {
        let agg = build_timeout_agg(5, vec![("alice", b"pkA", 3)]);
        agg.verify_and_add(&b"alice".to_vec(), b"sA", 4).unwrap();
        let err = agg
            .verify_and_add(&b"alice".to_vec(), b"sA", 4)
            .unwrap_err();
        assert!(err.is_duplicated_signer());
    }

    #[test]
    fn timeout_unknown_signer_errors() {
        let agg = build_timeout_agg(5, vec![("alice", b"pkA", 3)]);
        let err = agg
            .verify_and_add(&b"stranger".to_vec(), b"sig", 4)
            .unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn timeout_invalid_signature_errors() {
        // Use StubRawAgg which only accepts b"good".
        let weighted: Vec<Box<dyn WeightedIdentity>> = vec![Box::new(TestId {
            id: "alice".into(),
            pk: b"pkA".to_vec(),
            weight: 1,
        })];
        let raw: Arc<dyn SignatureAggregator> = Arc::new(StubRawAgg::default());
        let agg = TimeoutSignatureAggregatorImpl::new(
            raw,
            b"f".to_vec(),
            5,
            weighted,
            b"ds".to_vec(),
        )
        .unwrap();
        let err = agg
            .verify_and_add(&b"alice".to_vec(), b"bad", 4)
            .unwrap_err();
        assert!(err.is_invalid_signature());
    }

    #[test]
    fn timeout_aggregate_empty_errors() {
        let agg = build_timeout_agg(5, vec![("alice", b"pkA", 1)]);
        let err = agg.aggregate().unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn timeout_aggregate_preserves_signer_qc_ranks() {
        let agg = build_timeout_agg(
            10,
            vec![
                ("alice", b"pkA", 1),
                ("bob", b"pkB", 1),
                ("carol", b"pkC", 1),
            ],
        );
        agg.verify_and_add(&b"alice".to_vec(), b"sA", 9).unwrap();
        agg.verify_and_add(&b"carol".to_vec(), b"sC", 7).unwrap();
        agg.verify_and_add(&b"bob".to_vec(), b"sB", 8).unwrap();
        let (signers, _sig) = agg.aggregate().unwrap();
        // Stable order by index: alice (9), bob (8), carol (7).
        assert_eq!(signers.len(), 3);
        assert_eq!(signers[0].signer, b"alice".to_vec());
        assert_eq!(signers[0].newest_qc_rank, 9);
        assert_eq!(signers[1].signer, b"bob".to_vec());
        assert_eq!(signers[1].newest_qc_rank, 8);
        assert_eq!(signers[2].signer, b"carol".to_vec());
        assert_eq!(signers[2].newest_qc_rank, 7);
    }
}
