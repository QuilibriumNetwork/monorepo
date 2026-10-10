//! Local execution provenance. This record is not a consensus certificate and
//! does not authorize selecting or finalizing a frame by itself.
use super::*;
use prost::Message;
use quil_types::proto::global::GlobalFrame;
use sha2::{Digest, Sha256};

const VERSION: u8 = 2;
/// Receipts whose state summary also bound bucket roots and world size. They
/// are read as absent: the certified canonical head then serves as the base.
const LEGACY_VERSION: u8 = 1;
const ENCODED_LEN: usize = 1 + 8 + 32 + 32 + 32;

/// What startup did with an unfinished-execution marker for a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfinishedExecution {
    /// Its state batch never landed; the frame executes again.
    NotApplied(u64),
    /// Its state batch landed with the cursor.
    Applied(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalExecutionCheckpoint {
    frame_number: u64,
    frame_identity: [u8; 32],
    input_hash: [u8; 32],
    state_hash: [u8; 32],
}

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

impl GlobalExecutionCheckpoint {
    pub fn frame_number(&self) -> u64 {
        self.frame_number
    }
    pub fn frame_identity(&self) -> [u8; 32] {
        self.frame_identity
    }

    /// Match the executed header and ordered request body. Authentication of
    /// this input, its ancestry and consensus coordinates is a separate check.
    /// Different certificates for the same executed input remain equivalent.
    pub fn matches_frame(&self, frame: &GlobalFrame) -> Result<bool> {
        let input = Self::for_frame(frame)?;
        Ok(self.frame_number == input.frame_number
            && self.frame_identity == input.frame_identity
            && self.input_hash == input.input_hash)
    }

    fn for_frame(frame: &GlobalFrame) -> Result<Self> {
        let mut header = frame
            .header
            .clone()
            .ok_or_else(|| unavailable("execution input has no header"))?;
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
            .map_err(|_| unavailable("execution input has no identity"))?;
        // This carrier changes when consensus attaches or replaces a valid
        // finalization certificate; it never changes execution of the frame.
        header.public_key_signature_bls48581 = None;
        let mut hash = Sha256::new();
        hash.update(b"quil/global-execution-input/v1");
        let header_bytes = header.encode_to_vec();
        hash.update((header_bytes.len() as u64).to_be_bytes());
        hash.update(header_bytes);
        hash.update((frame.requests.len() as u64).to_be_bytes());
        // Bound transient encoding to one bundle rather than another full
        // copy of the frame. Owning branches check their input budget first.
        for bundle in &frame.requests {
            let bytes = bundle.encode_to_vec();
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(Self {
            frame_number: header.frame_number,
            frame_identity: identity,
            input_hash: hash.finalize().into(),
            state_hash: [0; 32],
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCODED_LEN);
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.frame_number.to_be_bytes());
        bytes.extend_from_slice(&self.frame_identity);
        bytes.extend_from_slice(&self.input_hash);
        bytes.extend_from_slice(&self.state_hash);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Option<Self>> {
        if bytes.len() == ENCODED_LEN && bytes[0] == LEGACY_VERSION {
            return Ok(None);
        }
        if bytes.len() != ENCODED_LEN || bytes[0] != VERSION {
            return Err(unavailable("invalid GLOBAL execution checkpoint"));
        }
        Ok(Some(Self {
            frame_number: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            frame_identity: bytes[9..41].try_into().unwrap(),
            input_hash: bytes[41..73].try_into().unwrap(),
            state_hash: bytes[73..105].try_into().unwrap(),
        }))
    }
}

/// Binds the GLOBAL-owned prover tree. Bucket roots and world size also cover
/// application data that archives ingest between GLOBAL frames, so binding
/// them would invalidate the receipt on the first state-changing ingest and
/// halt GLOBAL. Incomplete bucket state is still refused.
fn state_hash(crdt: &quil_hypergraph::HypergraphCrdt) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"quil/global-execution-state/v2");
    for phase in 0..4 {
        hash.update(crdt.current_forest_phase_root(&[0xff; 32], phase)?);
    }
    crdt.global_commitments_checked()?;
    Ok(hash.finalize().into())
}

pub(super) fn read_completed(
    store: &dyn HypergraphStore,
    crdt: &quil_hypergraph::HypergraphCrdt,
    cursor: u64,
) -> Result<Option<GlobalExecutionCheckpoint>> {
    let txn = store.new_transaction(false)?;
    let pending = txn.get(&quil_store::encoding::global_execution_pending_key())?;
    let bytes = txn.get(&quil_store::encoding::global_execution_checkpoint_key())?;
    txn.abort()?;
    if pending.is_some() {
        return Err(unavailable("unfinished GLOBAL execution requires recovery"));
    }
    let Some(bytes) = bytes else { return Ok(None) };
    let Some(checkpoint) = GlobalExecutionCheckpoint::decode(&bytes)? else {
        return Ok(None);
    };
    if checkpoint.frame_number != cursor || checkpoint.state_hash != state_hash(crdt)? {
        // The prover tree changed outside execution: a peer reconcile after a
        // divergence, or a state jump. The receipt no longer describes this
        // state. Refusing on it wedges reconciled archives (GLOBAL halts once
        // two of four have reconciled); instead the certified head serves
        // as the base, and its next certified child authenticates the state.
        tracing::warn!(cursor, receipt = checkpoint.frame_number,
            "GLOBAL execution receipt no longer matches the prover tree; treating it as absent");
        return Ok(None);
    }
    Ok(Some(checkpoint))
}

impl FrameMaterializer {
    fn checkpoint_store_available(&self) -> Result<bool> {
        let Some(identity) = self.hypergraph.backing_store_identity() else {
            return Ok(false);
        };
        if self.hypergraph_store.backing_store_identity().as_ref() != Some(&identity)
            || self.clock_store.backing_store_identity().as_ref() != Some(&identity)
        {
            return Err(unavailable(
                "GLOBAL checkpoint providers do not share the execution store",
            ));
        }
        Ok(true)
    }

    pub(super) fn ensure_no_pending_execution(&self) -> Result<()> {
        if self.checkpoint_store_available()?
            && self
                .hypergraph
                .read_execution_record(&quil_store::encoding::global_execution_pending_key())?
                .is_some()
        {
            return Err(unavailable(
                "unfinished GLOBAL execution requires recovery before retry",
            ));
        }
        Ok(())
    }

    /// Resolve the unfinished-execution marker a process leaves when it stops
    /// inside the in-place path. Call at startup, before any execution.
    ///
    /// A frame's execution state and its cursor land in one batch, so the
    /// durable cursor says whether that batch did: one below the marked frame
    /// ([`UnfinishedExecution::NotApplied`], the frame runs again) or at it
    /// ([`UnfinishedExecution::Applied`]; effects after that batch, such as an
    /// eviction flush, may be missing). Any other cursor is refused.
    ///
    /// The completed receipt is kept only while it still describes the state
    /// at the cursor (as [`read_completed`] judges it). Otherwise the store is
    /// left receipt-less, the state older stores already have: publication
    /// then requires a certified child's parent roots to equal the local state,
    /// and a mismatch takes the existing reconcile. That also covers mutations
    /// a failed attempt staged and a later commit published without its
    /// cursor. Refused while this process still holds staged mutations.
    pub fn recover_unfinished_execution(&self) -> Result<Option<UnfinishedExecution>> {
        let _execution = self
            .frame_execution
            .lock()
            .map_err(|_| unavailable("materializer frame lock poisoned"))?;
        if !self.checkpoint_store_available()? {
            return Ok(None);
        }
        let _forest = self.hypergraph.lock_forest_writes();
        let txn = self.hypergraph_store.new_transaction(false)?;
        let pending_key = quil_store::encoding::global_execution_pending_key();
        let resolved = (|| -> Result<Option<(UnfinishedExecution, u64)>> {
            let Some(pending) = txn.get(&pending_key)? else { return Ok(None) };
            let Some(marked) = GlobalExecutionCheckpoint::decode(&pending)? else {
                return Err(unavailable("unfinished GLOBAL execution marker has a retired encoding"));
            };
            let frame = marked.frame_number;
            if self.hypergraph.has_staged_mutations() {
                return Err(QuilError::ExecutionUnavailable(format!(
                    "unfinished GLOBAL execution of frame {frame}: this process still holds its \
                     staged mutations; restart to recover"
                )));
            }
            let cursor = match txn.get(&quil_store::encoding::global_materialized_cursor_key())? {
                None => 0,
                Some(bytes) => u64::from_be_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| unavailable("malformed GLOBAL materialized cursor"))?,
                ),
            };
            if cursor.checked_add(1) == Some(frame) {
                Ok(Some((UnfinishedExecution::NotApplied(frame), cursor)))
            } else if cursor == frame {
                Ok(Some((UnfinishedExecution::Applied(frame), cursor)))
            } else {
                Err(QuilError::ExecutionUnavailable(format!(
                    "unfinished GLOBAL execution of frame {frame} does not match the cursor \
                     {cursor}; the state must be resynced"
                )))
            }
        })();
        let (outcome, cursor) = match resolved {
            Ok(Some(resolved)) => resolved,
            other => {
                txn.abort()?;
                return other.map(|_| None);
            }
        };
        let frame = match outcome {
            UnfinishedExecution::NotApplied(frame) | UnfinishedExecution::Applied(frame) => frame,
        };
        let receipt_key = quil_store::encoding::global_execution_checkpoint_key();
        let receipt_holds = match txn.get(&receipt_key)? {
            None => true,
            Some(bytes) => GlobalExecutionCheckpoint::decode(&bytes)?.is_some_and(|receipt| {
                receipt.frame_number == cursor
                    && state_hash(&self.hypergraph).is_ok_and(|state| state == receipt.state_hash)
            }),
        };
        if !receipt_holds {
            txn.delete(&receipt_key)?;
        }
        txn.delete(&pending_key)?;
        txn.commit()?;
        self.last_materialized_frame.fetch_max(cursor, Ordering::SeqCst);
        warn!(
            frame, cursor, receipt_kept = receipt_holds, ?outcome,
            "recovered unfinished GLOBAL execution; the next certified frame authenticates the state"
        );
        Ok(Some(outcome))
    }

    pub(super) fn verify_execution_replay(&self, frame: &GlobalFrame, cursor: u64) -> Result<()> {
        if !self.checkpoint_store_available()? {
            return Ok(());
        }
        let _guard = self.hypergraph.lock_forest_writes();
        let Some(checkpoint) =
            read_completed(self.hypergraph_store.as_ref(), &self.hypergraph, cursor)?
        else {
            // A legacy cursor still lacks identity evidence. Skipping it does
            // not create a completion record or authorize a selected parent.
            return Ok(());
        };
        if frame
            .header
            .as_ref()
            .is_some_and(|h| h.frame_number == cursor)
            && !checkpoint.matches_frame(frame)?
        {
            return Err(unavailable(
                "GLOBAL replay differs from the completed execution input",
            ));
        }
        Ok(())
    }

    pub(super) fn begin_execution_checkpoint(
        &self,
        frame: &GlobalFrame,
    ) -> Result<Option<GlobalExecutionCheckpoint>> {
        // Legacy/nonpersistent test adapters cannot supply an execution-bound
        // checkpoint. They keep their existing behavior and never get one.
        if !self.checkpoint_store_available()? {
            return Ok(None);
        }
        let checkpoint = GlobalExecutionCheckpoint::for_frame(frame)?;
        let txn = self.hypergraph_store.new_transaction(false)?;
        let key = quil_store::encoding::global_execution_pending_key();
        if txn.get(&key)?.is_some() {
            return Err(unavailable(
                "unfinished GLOBAL execution requires recovery before retry",
            ));
        }
        txn.set(&key, &checkpoint.encode())?;
        txn.commit()?;
        Ok(Some(checkpoint))
    }

    pub(super) fn finish_execution_checkpoint(
        &self,
        checkpoint: Option<GlobalExecutionCheckpoint>,
    ) -> Result<()> {
        let Some(mut checkpoint) = checkpoint else {
            return Ok(());
        };
        let pending = checkpoint.encode();
        checkpoint.state_hash = state_hash(&self.hypergraph)?;
        let txn = self.hypergraph_store.new_transaction(false)?;
        let pending_key = quil_store::encoding::global_execution_pending_key();
        if txn.get(&pending_key)?.as_deref() != Some(pending.as_slice())
            || txn
                .get(&quil_store::encoding::global_materialized_cursor_key())?
                .as_deref()
                != Some(checkpoint.frame_number.to_be_bytes().as_slice())
        {
            return Err(unavailable(
                "GLOBAL execution completion lost its pending input or cursor",
            ));
        }
        txn.set(
            &quil_store::encoding::global_execution_checkpoint_key(),
            &checkpoint.encode(),
        )?;
        txn.delete(&pending_key)?;
        txn.commit()
    }
}
