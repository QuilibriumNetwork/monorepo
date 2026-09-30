//! Trusted local worker; no networking, state lookup, or transaction admission.
use quil_lattice_ct::confidential::relation::backend::{
    worker_process::{MAX_REQUEST_BYTES, VALID_EXIT, INVALID_EXIT, READINESS_REQUEST},
    worker_request::{WorkerRequest, verify_amount_proof},
    worker_limits::{apply_to_current_worker, apply_address_space_limit, exit_when_orphaned},
};
use std::io::Read;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let cpu = if (args.len() == 2 || args.len() == 4) && args[0] == "--cpu-seconds" {
        args[1].parse::<u64>().ok()
    } else { None };
    if cpu.map_or(true, |seconds| apply_to_current_worker(seconds).is_err()) {
        std::process::exit(82);
    }
    if args.len() == 4 && (args[2] != "--address-space-bytes"
        || args[3].parse::<u64>().ok().map_or(true, |bytes| apply_address_space_limit(bytes).is_err())) {
        std::process::exit(82);
    }
    if exit_when_orphaned().is_err() {
        std::process::exit(82);
    }
    let mut bytes = Vec::new();
    let code = if std::io::stdin().take(MAX_REQUEST_BYTES as u64).read_to_end(&mut bytes).is_err() {
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
    } else { 82 };
    std::process::exit(code);
}
