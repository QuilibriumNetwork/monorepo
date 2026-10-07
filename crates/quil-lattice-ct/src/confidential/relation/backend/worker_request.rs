//! Local IPC envelope. Network/application and limits come from the caller's
//! trusted policy, independently of the transaction being checked.
use crate::confidential::transfer::CompileLimits;
use super::worker_process::MAX_REQUEST_BYTES;

const MAGIC: &[u8; 8] = b"QCTW1\0\0\0";
pub(super) const HEADER_BYTES: usize = 96;
const HEADER: usize = HEADER_BYTES;
pub const MAX_TRANSACTION_BYTES: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError { Invalid, Allocation }

pub struct WorkerRequest<'a> {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub limits: CompileLimits,
    /// Submission accounting only, not a process memory cap.
    pub submission_bytes: usize,
    pub transaction: &'a [u8],
}

impl<'a> WorkerRequest<'a> {
    fn validate(&self) -> Result<(), RequestError> {
        if !(1..=128).contains(&self.limits.max_inputs)
            || !(1..=128).contains(&self.limits.max_outputs)
            || !(1..=32).contains(&self.limits.max_depth)
            || self.transaction.len() < 4
            || self.transaction.len() >= MAX_TRANSACTION_BYTES
        { return Err(RequestError::Invalid); }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, RequestError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(HEADER + self.transaction.len()).map_err(|_| RequestError::Allocation)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        for value in [self.limits.max_inputs, self.limits.max_outputs, self.limits.max_depth] {
            bytes.extend_from_slice(&(value as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&(self.submission_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.transaction.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.transaction);
        Ok(bytes)
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, RequestError> {
        if bytes.len() < HEADER || bytes.len() >= MAX_REQUEST_BYTES || &bytes[..8] != MAGIC {
            return Err(RequestError::Invalid);
        }
        let u32_at = |i| u32::from_le_bytes(bytes[i..i+4].try_into().unwrap()) as usize;
        if u32_at(92) != bytes.len() - HEADER { return Err(RequestError::Invalid); }
        let result = Self {
            network: bytes[8..40].try_into().unwrap(),
            application: bytes[40..72].try_into().unwrap(),
            limits: CompileLimits { max_inputs: u32_at(72), max_outputs: u32_at(76), max_depth: u32_at(80) },
            submission_bytes: u64::from_le_bytes(bytes[84..92].try_into().unwrap())
                .try_into().map_err(|_| RequestError::Invalid)?,
            transaction: &bytes[HEADER..],
        };
        result.validate()?;
        Ok(result)
    }
}

/// Amount-proof verification only. The caller must independently validate
/// retained roots, signatures, source rewards/coins, fees and replay state.
#[cfg(feature = "native-proof")]
pub fn verify_amount_proof(request: &WorkerRequest<'_>) -> Result<bool, super::native::NativeError> {
    use crate::confidential::{custom_mint::{self, CustomMint}, mint::Mint, pending_create::PendingCreate, pending_claim::PendingClaim, settlement::Settlement, shield::AnyShield, transfer::Transfer};
    use super::native::{self, NativeBudget};
    request.validate().map_err(|_| native::NativeError::InvalidRelation)?;
    let prefix = u32::from_be_bytes(request.transaction[..4].try_into().unwrap());
    // Keep public relation construction within the worker process as well.
    let (relation, proof) = match prefix {
        0x0512 => {
            let Ok(tx) = Transfer::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits) else { return Ok(false); };
            (relation, tx.proof)
        }
        // 0x0513 carries both the QUIL reward mint (QCT3MT) and custom-token
        // issuance (QCT3CM); the version bytes select the decoder.
        0x0513 if request.transaction.get(4..12) == Some(custom_mint::VERSION.as_slice()) => {
            let Ok(tx) = CustomMint::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits.max_outputs) else { return Ok(false); };
            (relation, tx.proof)
        }
        0x0513 => {
            let Ok(tx) = Mint::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits.max_inputs, request.limits.max_outputs) else { return Ok(false); };
            (relation, tx.proof)
        }
        0x0514 => {
            let Ok(tx) = PendingCreate::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits) else { return Ok(false); };
            (relation, tx.proof)
        }
        0x0515 => {
            let Ok(tx) = PendingClaim::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits.max_outputs) else { return Ok(false); };
            (relation, tx.proof)
        }
        // One legacy coin (version 2) or a batch (version 3).
        0x0516 => {
            let Ok(tx) = AnyShield::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.public_relation(request.limits.max_outputs) else { return Ok(false); };
            (relation, tx.proof().to_vec())
        }
        0x0518 => {
            let Ok(tx) = Settlement::decode(request.transaction, &request.network, &request.application) else { return Ok(false); };
            let Ok(relation) = tx.statement.public_relation(request.limits) else { return Ok(false); };
            (relation, tx.proof)
        }
        _ => return Ok(false),
    };
    native::verify_owned(relation, &proof, NativeBudget { max_native_bytes: request.submission_bytes })
}

/// The worker process's entry point, shared by the standalone
/// `quil-amount-proof-worker` binary and a node that runs itself as its worker:
/// apply the requested OS limits, read one request from stdin, verify it, and
/// return the process exit code. `args` excludes the program name.
#[cfg(feature = "native-proof")]
pub fn run_worker(args: &[String]) -> i32 {
    use super::worker_limits::{apply_address_space_limit, apply_to_current_worker, exit_when_orphaned};
    use super::worker_process::{INVALID_EXIT, READINESS_REQUEST, VALID_EXIT};
    use std::io::Read;
    let cpu = if (args.len() == 2 || args.len() == 4) && args[0] == "--cpu-seconds" {
        args[1].parse::<u64>().ok()
    } else { None };
    if cpu.map_or(true, |seconds| apply_to_current_worker(seconds).is_err()) {
        return 82;
    }
    if args.len() == 4 && (args[2] != "--address-space-bytes"
        || args[3].parse::<u64>().ok().map_or(true, |bytes| apply_address_space_limit(bytes).is_err())) {
        return 82;
    }
    if exit_when_orphaned().is_err() {
        return 82;
    }
    let mut bytes = Vec::new();
    if std::io::stdin().take(MAX_REQUEST_BYTES as u64).read_to_end(&mut bytes).is_err() {
        82
    } else if bytes == READINESS_REQUEST {
        // Reached only after loader startup and configured OS limits succeed.
        // This is a local ABI check, not a native proof self-test.
        VALID_EXIT
    } else if let Ok(request) = WorkerRequest::decode(&bytes) {
        match verify_amount_proof(&request) {
            Ok(true) => VALID_EXIT,
            Ok(false) => INVALID_EXIT,
            Err(_) => 82,
        }
    } else { 82 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_request_bounds_and_context_roundtrip() {
        let tx = [0, 0, 5, 0x12, 99];
        let request = WorkerRequest { network: [1; 32], application: [2; 32],
            limits: CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 32 },
            submission_bytes: 123456, transaction: &tx };
        let bytes = request.encode().unwrap();
        let decoded = WorkerRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.network, request.network);
        assert_eq!(decoded.application, request.application);
        assert_eq!(decoded.limits, request.limits);
        assert_eq!(decoded.submission_bytes, request.submission_bytes);
        assert_eq!(decoded.transaction, tx);
        for end in 0..bytes.len() { assert!(WorkerRequest::decode(&bytes[..end]).is_err()); }
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(WorkerRequest::decode(&trailing).is_err());
        for offset in [0, 72, 76, 80, 92] {
            let mut malformed = bytes.clone(); malformed[offset..offset+4].fill(255);
            assert!(WorkerRequest::decode(&malformed).is_err());
        }
        // Local framing must not consume the network transaction allowance.
        // These are transport fixtures, not valid transaction/proof encodings.
        let largest = vec![0; MAX_TRANSACTION_BYTES - 1];
        let framed = WorkerRequest { transaction: &largest, ..request }.encode().unwrap();
        assert_eq!(framed.len(), MAX_TRANSACTION_BYTES - 1 + HEADER);
        assert!(framed.len() < MAX_REQUEST_BYTES);
        assert_eq!(WorkerRequest::decode(&framed).unwrap().transaction, largest);
        let oversized = vec![0; MAX_TRANSACTION_BYTES];
        assert!(WorkerRequest { transaction: &oversized, ..request }.encode().is_err());
        let mut oversized_frame = framed;
        oversized_frame.push(0);
        oversized_frame[92..96].copy_from_slice(&(MAX_TRANSACTION_BYTES as u32).to_le_bytes());
        assert!(WorkerRequest::decode(&oversized_frame).is_err());
    }
}
