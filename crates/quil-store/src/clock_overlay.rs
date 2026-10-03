//! Clock records in the same bounded overlay as tentative application state.
//! Each composite read retains one generation. Callers serialize branch
//! execution; this adapter neither selects a parent nor finalizes a branch.
use crate::{
    encoding as e,
    overlay::{OverlayDb, OverlayDbSnapshot, OverlayTxn},
};
use num_bigint::{BigInt, Sign};
use prost::Message;
use quil_forest::ExecutionOverlay;
use quil_types::{
    error::{QuilError, Result},
    proto::global as g,
    store::{self, ClockStore, Transaction},
};
use std::{collections::HashMap, sync::Arc};

pub struct OverlayClockStore {
    db: OverlayDb,
}

fn unavailable(error: impl std::fmt::Display) -> QuilError {
    QuilError::ExecutionUnavailable(format!("tentative clock: {error}"))
}
fn malformed(message: &str) -> QuilError {
    QuilError::Serialization(message.into())
}
fn missing() -> QuilError {
    QuilError::NotFound("clock record unavailable in captured state".into())
}
fn u64_value(bytes: Option<Vec<u8>>) -> Result<Option<u64>> {
    bytes
        .map(|b| {
            b.as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| malformed("invalid clock index length"))
        })
        .transpose()
}
fn upper(prefix: &[u8]) -> Result<Vec<u8>> {
    let mut key = prefix.to_vec();
    while key.last() == Some(&255) {
        key.pop();
    }
    let last = key
        .last_mut()
        .ok_or_else(|| malformed("unbounded clock range"))?;
    *last += 1;
    Ok(key)
}
fn optional<T>(value: Result<T>) -> Result<Option<T>> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(QuilError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

struct Read {
    snapshot: OverlayDbSnapshot,
}
impl Read {
    fn delete_exact(&self, t: &OverlayTxn, prefix: &[u8], length: usize) -> Result<()> {
        for row in self.snapshot.range(prefix.to_vec(), upper(prefix)?) {
            let (key, _) = row.map_err(unavailable)?;
            if key.len() == length {
                t.delete(&key).map_err(unavailable)?;
            }
        }
        Ok(())
    }
    fn shard(&self, filter: &[u8], number: u64) -> Result<g::AppShardFrame> {
        let frame: g::AppShardFrame = self.message(&e::clock_shard_frame_key(filter, number))?;
        if !frame
            .header
            .as_ref()
            .is_some_and(|h| h.frame_number == number && h.address == filter)
        {
            return Err(malformed("shard clock frame mismatch"));
        }
        Ok(frame)
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.snapshot.get(key).map_err(unavailable)
    }
    fn index(&self, key: &[u8]) -> Result<u64> {
        u64_value(self.get(key)?)?.ok_or_else(missing)
    }
    fn message<M: Message + Default>(&self, key: &[u8]) -> Result<M> {
        M::decode(self.get(key)?.ok_or_else(missing)?.as_slice())
            .map_err(|e| malformed(&e.to_string()))
    }
    fn messages<M: Message + Default>(&self, prefix: &[u8]) -> Result<Vec<M>> {
        self.snapshot
            .range(prefix.to_vec(), upper(prefix)?)
            .map(|row| {
                let (_, value) = row.map_err(unavailable)?;
                M::decode(value.as_ref()).map_err(|e| malformed(&e.to_string()))
            })
            .collect()
    }
    fn requests(&self, prefix: &[u8]) -> Result<Vec<g::MessageBundle>> {
        let mut requests = Vec::new();
        for row in self.snapshot.range(prefix.to_vec(), upper(prefix)?) {
            let (key, value) = row.map_err(unavailable)?;
            if key.len() != prefix.len() + 2
                || usize::from(u16::from_be_bytes(key[prefix.len()..].try_into().unwrap()))
                    != requests.len()
            {
                return Err(malformed("non-contiguous clock frame requests"));
            }
            requests.push(
                g::MessageBundle::decode(value.as_ref()).map_err(|e| malformed(&e.to_string()))?,
            );
        }
        Ok(requests)
    }
    fn global(&self, number: u64) -> Result<g::GlobalFrame> {
        let header: g::GlobalFrameHeader = self.message(&e::clock_global_frame_key(number))?;
        if header.frame_number != number {
            return Err(malformed("clock frame number mismatch"));
        }
        let key = e::clock_global_frame_request_key(number, 0);
        Ok(g::GlobalFrame {
            header: Some(header),
            requests: self.requests(&key[..key.len() - 2])?,
        })
    }
    fn candidate(&self, number: u64, selector: &[u8]) -> Result<g::GlobalFrame> {
        let validate = |header: &g::GlobalFrameHeader| -> bool {
            header.frame_number == number
                && quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                    .is_ok_and(|identity| identity.as_slice() == selector)
        };
        let Some(bytes) = self.get(&e::clock_global_frame_candidate_key(number, selector))? else {
            let frame = self.global(number)?;
            if !frame.header.as_ref().is_some_and(validate) {
                return Err(missing());
            }
            return Ok(frame);
        };
        // Accept both historical header-only and older whole-frame records,
        // but never resolve a different candidate at the requested height.
        let mut frame = match g::GlobalFrameHeader::decode(bytes.as_slice()) {
            Ok(header) if validate(&header) => g::GlobalFrame {
                header: Some(header),
                requests: Vec::new(),
            },
            _ => {
                let frame = g::GlobalFrame::decode(bytes.as_slice())
                    .map_err(|e| malformed(&e.to_string()))?;
                if !frame.header.as_ref().is_some_and(validate) {
                    return Err(malformed("clock candidate identity mismatch"));
                }
                frame
            }
        };
        if frame.requests.is_empty() {
            let key = e::clock_global_frame_request_candidate_key(selector, number, 0);
            frame.requests = self.requests(&key[..key.len() - 2])?;
        }
        Ok(frame)
    }
    fn certified(&self, rank: u64) -> Result<g::GlobalProposal> {
        let bytes = self
            .get(&e::clock_global_certified_state_key(rank))?
            .ok_or_else(missing)?;
        if bytes.len() != 24 {
            return Err(malformed("invalid certified clock record length"));
        }
        let number = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let qc = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let tc = u64::from_be_bytes(bytes[16..].try_into().unwrap());
        let mut proposal = g::GlobalProposal::default();
        if number != u64::MAX {
            proposal.state = optional(self.global(number))?;
            if let Some(header) = proposal.state.as_ref().and_then(|f| f.header.as_ref()) {
                proposal.vote = optional(self.message(&e::clock_proposal_vote_key(
                    &[],
                    header.rank,
                    &header.prover,
                )))?;
            }
        }
        if qc != u64::MAX {
            proposal.parent_quorum_certificate =
                optional(self.message(&e::clock_quorum_certificate_key(qc, &[])))?;
        }
        if tc != u64::MAX {
            proposal.prior_rank_timeout_certificate =
                optional(self.message(&e::clock_timeout_certificate_key(tc, &[])))?;
        }
        Ok(proposal)
    }
}

impl OverlayClockStore {
    pub fn new(overlay: Arc<ExecutionOverlay>) -> Self {
        Self {
            db: OverlayDb(overlay),
        }
    }
    fn read(&self) -> Result<Read> {
        let snapshot = self.db.snapshot();
        snapshot.check().map_err(unavailable)?;
        Ok(Read { snapshot })
    }
    fn check_size(&self, key: usize, value: usize) -> Result<()> {
        let limits = self.db.0.limits();
        if key
            .checked_add(value)
            .is_none_or(|n| n > limits.max_record_bytes)
        {
            return Err(unavailable("record byte limit"));
        }
        Ok(())
    }
    fn write<T>(
        &self,
        txn: &dyn Transaction,
        f: impl FnOnce(&OverlayTxn) -> Result<T>,
    ) -> Result<T> {
        let txn = OverlayTxn::for_store(txn, &self.db).map_err(unavailable)?;
        let result = if self.db.0.stats().closed {
            Err(unavailable("overlay closed"))
        } else {
            f(txn).map_err(|error| match error {
                e @ QuilError::Store(_) => unavailable(e),
                e => e,
            })
        };
        if let Err(error) = &result {
            txn.poison(error);
        }
        result
    }
    fn atomic(&self, f: impl FnOnce(&OverlayTxn) -> Result<()>) -> Result<()> {
        let txn = OverlayTxn::new(self.db.clone());
        self.write(&txn, f)?;
        Box::new(txn).commit().map_err(unavailable)
    }
    fn put_message(&self, t: &OverlayTxn, key: &[u8], value: &impl Message) -> Result<()> {
        self.check_size(key.len(), value.encoded_len())?;
        if key.len().saturating_add(value.encoded_len()) > self.db.0.limits().max_delta_bytes {
            return Err(unavailable("transaction byte limit"));
        }
        t.set(key, &value.encode_to_vec()).map_err(unavailable)
    }
    fn index(&self, t: &OverlayTxn, key: &[u8], value: u64, minimum: bool) -> Result<()> {
        let old = u64_value(t.get_staged(key).map_err(unavailable)?)?;
        if old.is_none_or(|old| if minimum { value < old } else { value > old }) {
            t.set(key, &value.to_be_bytes()).map_err(unavailable)?;
        }
        Ok(())
    }
    fn stage_global(&self, t: &OverlayTxn, frame: &g::GlobalFrame, candidate: bool) -> Result<()> {
        let h = frame
            .header
            .as_ref()
            .ok_or_else(|| malformed("clock frame missing header"))?;
        if frame.requests.len() > usize::from(u16::MAX) + 1 {
            return Err(malformed("too many clock requests"));
        }
        self.check_size(if candidate { 42 } else { 10 }, h.encoded_len())?;
        let selector = if candidate {
            Some(quil_crypto::poseidon::hash_bytes_to_32(&h.output).map_err(unavailable)?)
        } else {
            None
        };
        let key = selector.as_ref().map_or_else(
            || e::clock_global_frame_key(h.frame_number),
            |s| e::clock_global_frame_candidate_key(h.frame_number, s),
        );
        self.put_message(t, &key, h)?;
        let request_key = |i| {
            selector.as_ref().map_or_else(
                || e::clock_global_frame_request_key(h.frame_number, i),
                |s| e::clock_global_frame_request_candidate_key(s, h.frame_number, i),
            )
        };
        let first = request_key(0);
        let prefix = &first[..first.len() - 2];
        t.delete_range(prefix, &upper(prefix)?)
            .map_err(unavailable)?;
        for (i, request) in frame.requests.iter().enumerate() {
            self.put_message(t, &request_key(i as u16), request)?;
        }
        if !candidate {
            self.index(t, &e::clock_global_latest_index(), h.frame_number, false)?;
            self.index(t, &e::clock_global_earliest_index(), h.frame_number, true)?;
        }
        Ok(())
    }
}

impl ClockStore for OverlayClockStore {
    fn backing_store_identity(&self) -> Option<store::BackingStoreIdentity> {
        Some(store::BackingStoreIdentity::of(&self.db.0))
    }
    fn new_transaction(&self, _: bool) -> Result<Box<dyn Transaction>> {
        if self.db.0.stats().closed {
            return Err(unavailable("overlay closed"));
        }
        Ok(Box::new(OverlayTxn::new(self.db.clone())))
    }
    fn get_latest_global_clock_frame(&self) -> Result<g::GlobalFrame> {
        let r = self.read()?;
        r.global(r.index(&e::clock_global_latest_index())?)
    }
    fn get_earliest_global_clock_frame(&self) -> Result<g::GlobalFrame> {
        let r = self.read()?;
        r.global(r.index(&e::clock_global_earliest_index())?)
    }
    fn get_global_clock_frame(&self, number: u64) -> Result<g::GlobalFrame> {
        self.read()?.global(number)
    }
    fn put_global_clock_frame(&self, frame: &g::GlobalFrame, t: &dyn Transaction) -> Result<()> {
        self.write(t, |t| self.stage_global(t, frame, false))
    }
    fn put_global_clock_frame_candidate(
        &self,
        frame: &g::GlobalFrame,
        t: &dyn Transaction,
    ) -> Result<()> {
        self.write(t, |t| self.stage_global(t, frame, true))
    }
    fn get_global_clock_frame_candidate(
        &self,
        number: u64,
        selector: &[u8],
    ) -> Result<g::GlobalFrame> {
        if selector.len() != 32 {
            return Err(malformed("clock candidate selector must contain 32 bytes"));
        }
        self.read()?.candidate(number, selector)
    }
    fn range_global_clock_frame_candidates(
        &self,
        min: u64,
        max: u64,
        limit: usize,
    ) -> Result<Vec<g::GlobalFrame>> {
        if min > max || limit == 0 {
            return Ok(Vec::new());
        }
        let r = self.read()?;
        let lower = e::clock_global_frame_candidate_key(min, &[]);
        let end = upper(&e::clock_global_frame_candidate_key(max, &[255; 32]))?;
        let mut frames = Vec::new();
        for row in r.snapshot.range(lower, end).take(limit) {
            let (key, _) = row.map_err(unavailable)?;
            if key.len() != 42 {
                return Err(malformed("invalid clock candidate key"));
            }
            let number = u64::from_be_bytes(key[2..10].try_into().unwrap());
            frames.push(r.candidate(number, &key[10..])?);
        }
        Ok(frames)
    }
    fn put_global_clock_frame_outcomes(
        &self,
        number: u64,
        outcomes: &[store::RequestOutcome],
    ) -> Result<()> {
        let key = e::clock_global_frame_outcomes_key(number);
        let bytes = crate::clock_codec::encode_outcomes(
            outcomes,
            self.db
                .0
                .limits()
                .max_record_bytes
                .saturating_sub(key.len()),
        )?;
        self.db.put(key, bytes).map_err(unavailable)
    }
    fn get_global_clock_frame_outcomes(&self, number: u64) -> Result<Vec<store::RequestOutcome>> {
        let r = self.read()?;
        match r.get(&e::clock_global_frame_outcomes_key(number))? {
            Some(bytes) => crate::clock_codec::decode_outcomes(&bytes),
            None => crate::clock_codec::decode_legacy_outcomes(
                r.get(&e::clock_global_certified_state_key(number))?,
            ),
        }
    }
    fn delete_global_clock_frame_range(&self, min: u64, max: u64) -> Result<()> {
        self.atomic(|t| {
            t.delete_range(
                &e::clock_global_frame_key(min),
                &e::clock_global_frame_key(max),
            )
            .map_err(unavailable)
        })
    }
    fn reset_global_clock_frames(&self) -> Result<()> {
        self.atomic(|t| {
            t.delete_range(
                &e::clock_global_frame_key(0),
                &[e::CLOCK_FRAME, e::CLOCK_GLOBAL_FRAME + 1],
            )?;
            t.delete(&e::clock_global_earliest_index())?;
            t.delete(&e::clock_global_latest_index())
        })
        .map_err(unavailable)
    }
    fn get_latest_certified_global_state(&self) -> Result<g::GlobalProposal> {
        let r = self.read()?;
        r.certified(r.index(&e::clock_global_certified_state_latest_index())?)
    }
    fn get_earliest_certified_global_state(&self) -> Result<g::GlobalProposal> {
        let r = self.read()?;
        r.certified(r.index(&e::clock_global_certified_state_earliest_index())?)
    }
    fn get_certified_global_state(&self, rank: u64) -> Result<g::GlobalProposal> {
        self.read()?.certified(rank)
    }
    fn put_certified_global_state(
        &self,
        state: &g::GlobalProposal,
        t: &dyn Transaction,
    ) -> Result<()> {
        self.write(t, |t| {
            let (mut rank, mut frame, mut qc, mut tc) = (0u64, u64::MAX, u64::MAX, u64::MAX);
            if let Some(f) = &state.state {
                self.stage_global(t, f, false)?;
                let h = f.header.as_ref().unwrap();
                rank = rank.max(h.rank);
                frame = h.frame_number;
                if let Some(vote) = &state.vote {
                    self.put_proposal_vote(t, vote)?;
                }
            }
            if let Some(certificate) = &state.parent_quorum_certificate {
                self.put_quorum_certificate(certificate, t)?;
                qc = certificate.rank;
                rank = rank.max(qc);
            }
            if let Some(certificate) = &state.prior_rank_timeout_certificate {
                self.put_timeout_certificate(certificate, t)?;
                tc = certificate.rank;
                rank = rank.max(tc);
            }
            let mut value = Vec::with_capacity(24);
            for n in [frame, qc, tc] {
                value.extend_from_slice(&n.to_be_bytes());
            }
            t.set(&e::clock_global_certified_state_key(rank), &value)?;
            self.index(
                t,
                &e::clock_global_certified_state_earliest_index(),
                rank,
                true,
            )?;
            self.index(
                t,
                &e::clock_global_certified_state_latest_index(),
                rank,
                false,
            )
        })
    }
    fn get_latest_quorum_certificate(&self, filter: &[u8]) -> Result<g::QuorumCertificate> {
        self.check_size(filter.len(), 2)?;
        let r = self.read()?;
        r.message(&e::clock_quorum_certificate_key(
            r.index(&e::clock_quorum_certificate_latest_index(filter))?,
            filter,
        ))
    }
    fn get_quorum_certificate(&self, filter: &[u8], rank: u64) -> Result<g::QuorumCertificate> {
        self.read()?
            .message(&e::clock_quorum_certificate_key(rank, filter))
    }
    fn put_quorum_certificate(&self, qc: &g::QuorumCertificate, t: &dyn Transaction) -> Result<()> {
        self.write(t, |t| {
            self.put_message(t, &e::clock_quorum_certificate_key(qc.rank, &[]), qc)?;
            self.index(
                t,
                &e::clock_quorum_certificate_latest_index(&[]),
                qc.rank,
                false,
            )
        })
    }
    fn get_latest_timeout_certificate(&self, filter: &[u8]) -> Result<g::TimeoutCertificate> {
        self.check_size(filter.len(), 2)?;
        let r = self.read()?;
        r.message(&e::clock_timeout_certificate_key(
            r.index(&e::clock_timeout_certificate_latest_index(filter))?,
            filter,
        ))
    }
    fn get_timeout_certificate(&self, filter: &[u8], rank: u64) -> Result<g::TimeoutCertificate> {
        self.read()?
            .message(&e::clock_timeout_certificate_key(rank, filter))
    }
    fn put_timeout_certificate(
        &self,
        tc: &g::TimeoutCertificate,
        t: &dyn Transaction,
    ) -> Result<()> {
        self.write(t, |t| {
            self.put_message(
                t,
                &e::clock_timeout_certificate_key(tc.rank, &tc.filter),
                tc,
            )?;
            self.index(
                t,
                &e::clock_timeout_certificate_earliest_index(&tc.filter),
                tc.rank,
                true,
            )?;
            self.index(
                t,
                &e::clock_timeout_certificate_latest_index(&tc.filter),
                tc.rank,
                false,
            )
        })
    }
    fn get_latest_shard_clock_frame(&self, filter: &[u8]) -> Result<g::AppShardFrame> {
        self.check_size(filter.len(), 10)?;
        let r = self.read()?;
        r.shard(filter, r.index(&e::clock_shard_latest_index(filter))?)
    }
    fn get_shard_clock_frame(
        &self,
        filter: &[u8],
        number: u64,
        _: bool,
    ) -> Result<g::AppShardFrame> {
        self.check_size(filter.len(), 10)?;
        self.read()?.shard(filter, number)
    }
    fn commit_shard_clock_frame(
        &self,
        filter: &[u8],
        number: u64,
        selector: &[u8],
        t: &dyn Transaction,
        backfill: bool,
    ) -> Result<()> {
        self.write(t, |t| {
            self.check_size(filter.len(), 10)?;
            self.check_size(selector.len(), 10)?;
            let key = e::clock_shard_frame_key(filter, number);
            let staged_key = e::clock_shard_staged_key(selector, number);
            let frame = t.get_staged(&staged_key).map_err(unavailable)?;
            let have_frame = if let Some(bytes) = frame {
                let frame = g::AppShardFrame::decode(bytes.as_slice())
                    .map_err(|e| malformed(&e.to_string()))?;
                if !frame
                    .header
                    .as_ref()
                    .is_some_and(|h| h.frame_number == number && h.address == filter)
                {
                    return Err(malformed(
                        "staged shard frame does not match its destination",
                    ));
                }
                t.set(&key, &bytes)?;
                // Mirrors the durable store: the staged copy is dropped.
                t.delete(&staged_key)?;
                true
            } else {
                t.get_staged(&key).map_err(unavailable)?.is_some()
            };
            if !backfill && have_frame {
                self.index(t, &e::clock_shard_latest_index(filter), number, false)?;
            }
            Ok(())
        })
    }
    fn stage_shard_clock_frame(
        &self,
        selector: &[u8],
        frame: &g::AppShardFrame,
        t: &dyn Transaction,
    ) -> Result<()> {
        self.write(t, |t| {
            self.check_size(selector.len(), 10)?;
            let header = frame
                .header
                .as_ref()
                .ok_or_else(|| malformed("shard frame missing header"))?;
            self.put_message(
                t,
                &e::clock_shard_staged_key(selector, header.frame_number),
                frame,
            )
        })
    }
    fn get_staged_shard_clock_frame(
        &self,
        filter: &[u8],
        number: u64,
        selector: &[u8],
        _: bool,
    ) -> Result<g::AppShardFrame> {
        self.check_size(selector.len(), 10)?;
        let frame: g::AppShardFrame = self
            .read()?
            .message(&e::clock_shard_staged_key(selector, number))?;
        if !frame
            .header
            .as_ref()
            .is_some_and(|h| h.frame_number == number && h.address == filter)
        {
            return Err(malformed("staged shard frame mismatch"));
        }
        Ok(frame)
    }
    fn set_latest_shard_clock_frame_number(&self, filter: &[u8], number: u64) -> Result<()> {
        self.check_size(filter.len(), 10)?;
        self.db
            .put(e::clock_shard_latest_index(filter), number.to_be_bytes())
            .map_err(unavailable)
    }
    fn delete_shard_clock_frame_range(&self, filter: &[u8], min: u64, max: u64) -> Result<()> {
        self.check_size(filter.len(), 42)?;
        if min > max {
            return Err(malformed("reversed shard frame range"));
        }
        let r = self.read()?;
        self.atomic(|t| {
            for n in min..max {
                // Staging is entry/byte bounded, including empty frame ranges.
                let parent = e::clock_shard_parent_index_key(filter, n, &[]);
                let prefix = &parent[..parent.len() - 32];
                r.delete_exact(t, prefix, parent.len())?;
                t.delete(&e::clock_shard_frame_key(filter, n))?;
                for ring in 0..=u16::MAX {
                    let key = e::clock_prover_trie_key(filter, ring, n);
                    if t.get_staged(&key)?.is_none() {
                        break;
                    }
                    t.delete(&key)?;
                }
                let distance = e::clock_data_total_distance_key(filter, n, &[]);
                let prefix = &distance[..distance.len() - 32];
                r.delete_exact(t, prefix, distance.len())?;
            }
            Ok(())
        })
        .map_err(unavailable)
    }
    fn reset_shard_clock_frames(&self, filter: &[u8]) -> Result<()> {
        self.check_size(filter.len(), 10)?;
        let first = e::clock_shard_frame_key(filter, 0);
        let prefix = &first[..first.len() - 8];
        let r = self.read()?;
        self.atomic(|t| {
            // Variable-length filters can share a byte prefix. Delete only
            // this filter's exact-length keys, including frame u64::MAX.
            r.delete_exact(t, prefix, first.len())?;
            t.delete(&e::clock_shard_latest_index(filter))
        })
        .map_err(unavailable)
    }
    fn get_latest_certified_app_shard_state(&self, filter: &[u8]) -> Result<g::AppShardProposal> {
        self.check_size(filter.len(), 10)?;
        let r = self.read()?;
        r.message(&e::clock_app_certified_state_key(
            filter,
            r.index(&e::clock_app_certified_state_latest_index(filter))?,
        ))
    }
    fn put_certified_app_shard_state(
        &self,
        state: &g::AppShardProposal,
        t: &dyn Transaction,
    ) -> Result<()> {
        self.write(t, |t| {
            self.check_size(10, state.encoded_len())?;
            let h = state
                .state
                .as_ref()
                .and_then(|s| s.header.as_ref())
                .ok_or_else(|| malformed("app proposal missing frame header"))?;
            self.put_message(
                t,
                &e::clock_app_certified_state_key(&h.address, h.frame_number),
                state,
            )?;
            self.index(
                t,
                &e::clock_app_certified_state_latest_index(&h.address),
                h.frame_number,
                false,
            )
        })
    }
    fn put_proposal_vote(&self, t: &dyn Transaction, vote: &g::ProposalVote) -> Result<()> {
        self.write(t, |t| {
            self.check_size(10, vote.encoded_len())?;
            self.put_message(
                t,
                &e::clock_proposal_vote_key(&vote.filter, vote.rank, &vote.selector),
                vote,
            )
        })
    }
    fn get_proposal_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<g::ProposalVote> {
        self.check_size(filter.len().saturating_add(identity.len()), 10)?;
        self.read()?
            .message(&e::clock_proposal_vote_key(filter, rank, identity))
    }
    fn get_proposal_votes(&self, filter: &[u8], rank: u64) -> Result<Vec<g::ProposalVote>> {
        self.check_size(filter.len(), 10)?;
        let mut votes: Vec<g::ProposalVote> = self
            .read()?
            .messages(&e::clock_proposal_vote_prefix(filter, rank))?;
        votes.retain(|vote| vote.filter == filter && vote.rank == rank);
        Ok(votes)
    }
    fn put_timeout_vote(&self, t: &dyn Transaction, vote: &g::TimeoutState) -> Result<()> {
        self.write(t, |t| {
            self.check_size(10, vote.encoded_len())?;
            let filter = vote
                .latest_quorum_certificate
                .as_ref()
                .map_or(&[][..], |q| q.filter.as_slice());
            let identity = vote
                .vote
                .as_ref()
                .map_or(&[][..], |v| v.selector.as_slice());
            self.put_message(
                t,
                &e::clock_timeout_vote_key(filter, vote.timeout_tick, identity),
                vote,
            )
        })
    }
    fn get_timeout_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<g::TimeoutState> {
        self.check_size(filter.len().saturating_add(identity.len()), 10)?;
        self.read()?
            .message(&e::clock_timeout_vote_key(filter, rank, identity))
    }
    fn get_timeout_votes(&self, filter: &[u8], rank: u64) -> Result<Vec<g::TimeoutState>> {
        self.check_size(filter.len(), 10)?;
        let mut votes: Vec<g::TimeoutState> = self
            .read()?
            .messages(&e::clock_timeout_vote_prefix(filter, rank))?;
        votes.retain(|vote| {
            vote.timeout_tick == rank
                && vote
                    .latest_quorum_certificate
                    .as_ref()
                    .map_or(&[][..], |qc| qc.filter.as_slice())
                    == filter
        });
        Ok(votes)
    }
    fn get_total_distance(&self, filter: &[u8], number: u64, selector: &[u8]) -> Result<BigInt> {
        self.check_size(filter.len().saturating_add(selector.len()), 10)?;
        Ok(BigInt::from_bytes_be(
            Sign::Plus,
            &self
                .read()?
                .get(&e::clock_total_distance_key(filter, number, selector))?
                .unwrap_or_default(),
        ))
    }
    fn set_total_distance(
        &self,
        filter: &[u8],
        number: u64,
        selector: &[u8],
        distance: &BigInt,
    ) -> Result<()> {
        let key_len = filter
            .len()
            .saturating_add(selector.len())
            .saturating_add(10);
        self.check_size(
            key_len,
            usize::try_from(distance.bits().div_ceil(8)).map_err(unavailable)?,
        )?;
        self.db
            .put(
                e::clock_total_distance_key(filter, number, selector),
                distance.to_bytes_be().1,
            )
            .map_err(unavailable)
    }
    fn get_peer_seniority_map(&self, filter: &[u8]) -> Result<HashMap<String, u64>> {
        self.check_size(filter.len(), 2)?;
        match self.read()?.get(&e::clock_peer_seniority_key(filter))? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| malformed(&e.to_string())),
            None => Ok(HashMap::new()),
        }
    }
    fn put_peer_seniority_map(
        &self,
        t: &dyn Transaction,
        filter: &[u8],
        values: &HashMap<String, u64>,
    ) -> Result<()> {
        self.write(t, |t| {
            self.check_size(filter.len(), 2)?;
            let key = e::clock_peer_seniority_key(filter);
            let mut writer = LimitedWriter {
                bytes: Vec::new(),
                limit: self
                    .db
                    .0
                    .limits()
                    .max_record_bytes
                    .saturating_sub(key.len()),
            };
            serde_json::to_writer(&mut writer, values).map_err(unavailable)?;
            t.set(&key, &writer.bytes).map_err(unavailable)
        })
    }
    fn put_shard_frame_fee_total(&self, filter: &[u8], n: u64, value: u128) -> Result<()> {
        self.check_size(filter.len(), 26)?;
        self.db
            .put(
                e::clock_shard_frame_fee_total_key(filter, n),
                value.to_be_bytes(),
            )
            .map_err(unavailable)
    }
    fn get_shard_frame_fee_total(&self, filter: &[u8], n: u64) -> Result<Option<u128>> {
        self.check_size(filter.len(), 10)?;
        self.read()?
            .get(&e::clock_shard_frame_fee_total_key(filter, n))?
            .map(|v| {
                v.as_slice()
                    .try_into()
                    .map(u128::from_be_bytes)
                    .map_err(|_| malformed("invalid shard fee record length"))
            })
            .transpose()
    }
    fn put_shard_frame_settlements(&self, filter: &[u8], n: u64, bytes: &[u8]) -> Result<()> {
        self.check_size(filter.len().saturating_add(10), bytes.len())?;
        self.db
            .put(e::clock_shard_frame_settlements_key(filter, n), bytes)
            .map_err(unavailable)
    }
    fn get_shard_frame_settlements(&self, filter: &[u8], n: u64) -> Result<Option<Vec<u8>>> {
        self.check_size(filter.len(), 10)?;
        self.read()?
            .get(&e::clock_shard_frame_settlements_key(filter, n))
    }
    fn put_shard_frame_spends(&self, filter: &[u8], n: u64, bytes: &[u8]) -> Result<()> {
        self.check_size(filter.len().saturating_add(10), bytes.len())?;
        self.db
            .put(e::clock_shard_frame_spends_key(filter, n), bytes)
            .map_err(unavailable)
    }
    fn get_shard_frame_spends(&self, filter: &[u8], n: u64) -> Result<Option<Vec<u8>>> {
        self.check_size(filter.len(), 10)?;
        self.read()?
            .get(&e::clock_shard_frame_spends_key(filter, n))
    }
    fn put_shard_frame_accumulator(
        &self,
        filter: &[u8],
        n: u64,
        digest: &[u8],
        report: &[u8],
    ) -> Result<()> {
        self.check_size(
            filter.len().saturating_add(digest.len()).saturating_add(10),
            report.len(),
        )?;
        self.atomic(|t| {
            if !digest.is_empty() && !report.is_empty() {
                let key = e::clock_shard_accumulator_report_key(filter, digest);
                match t.get_staged(&key)? {
                    Some(old) if old != report => {
                        return Err(malformed("conflicting accumulator report"))
                    }
                    None => t.set(&key, report)?,
                    _ => {}
                }
            }
            t.set(&e::clock_shard_frame_accumulator_key(filter, n), digest)
        })
        .map_err(unavailable)
    }
    fn get_shard_frame_accumulator(&self, filter: &[u8], n: u64) -> Result<Option<Vec<u8>>> {
        self.check_size(filter.len(), 10)?;
        self.read()?
            .get(&e::clock_shard_frame_accumulator_key(filter, n))
    }
    fn get_shard_accumulator_report(
        &self,
        filter: &[u8],
        digest: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.check_size(filter.len().saturating_add(digest.len()), 2)?;
        self.read()?
            .get(&e::clock_shard_accumulator_report_key(filter, digest))
    }
    fn compact_data(&self, _: &[u8]) -> Result<()> {
        Err(unavailable(
            "physical compaction is not an execution effect",
        ))
    }
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(std::io::Error::other("clock serialization byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "clock_overlay_tests.rs"]
mod tests;
