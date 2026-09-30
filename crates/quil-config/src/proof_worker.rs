//! Operator-tunable settings for the token proof verifier worker
//! (`quil-amount-proof-worker`). Consensus-critical policy (circuit limits,
//! minimum fee) is NOT here: it is a compiled per-network constant in the
//! execution crate so nodes cannot drift by editing a config file.
//!
//! Node processes sharing the same local base DB directory share one verifier
//! admission slot through `.proof-worker-admission.lock`, even with separate
//! shard DB paths. Keep that file in place while the node runs. Contention is
//! local execution unavailability. Within one process, callers may wait
//! (`admissionWaitMs`) and are served fairly across execution managers; across
//! processes the lock file is polled without ordering. `maxResidentBytes` is a
//! sampled per-verifier memory cap. None of this coordinates nodes on
//! different machines.
use serde::{Deserialize, Serialize};

/// Hard ceiling shared with the worker client (`WorkerVerifier::new`).
pub const MAX_WORKER_LIMIT_SECS: u64 = 3600;

fn default_cpu_seconds() -> u64 {
    1800
}
fn default_wall_timeout_secs() -> u64 {
    1800
}
fn default_max_concurrent() -> usize {
    2
}
fn default_native_threads() -> u8 {
    4
}
fn default_verify_budget_secs() -> u64 {
    6
}
fn default_admission_wait_ms() -> u64 {
    1500
}
fn default_max_resident_bytes() -> u64 {
    // About three times the largest resident size recorded for a depth-32
    // admission (2.73 GB): a guard against a runaway child, not a tight budget.
    8 << 30
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProofWorkerConfig {
    /// Absolute path to `quil-amount-proof-worker`. Empty means: use
    /// `QUIL_AMOUNT_WORKER_PATH` if set, else the file of that name beside
    /// the node executable.
    #[serde(default)]
    pub path: String,
    /// CPU-time limit applied inside the verifier child (seconds, 1..=3600).
    #[serde(default = "default_cpu_seconds")]
    pub cpu_seconds: u64,
    /// Wall-clock deadline for one verification (seconds, 1..=3600).
    #[serde(default = "default_wall_timeout_secs")]
    pub wall_timeout_secs: u64,
    /// Linux-only `RLIMIT_AS` for the child in bytes; 0 leaves it unset.
    /// Ignored on other platforms.
    #[serde(default)]
    pub address_space_bytes: u64,
    /// Verifications admitted concurrently per node (1..=64), shared by every
    /// execution manager and node process through the admission file. Each
    /// child needs about 1 GB at depth 32; keep `maxConcurrent × nativeThreads`
    /// at or below the machine's cores.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Native aggregation threads per verifier child (1..=8). Aggregation
    /// scales to about four threads per verification; beyond that prefer more
    /// concurrent children.
    #[serde(default = "default_native_threads")]
    pub native_threads: u8,
    /// Proof-verification time a shard proposal may schedule per frame
    /// (seconds, 1..=10). Confidential operations beyond the budget are
    /// deferred to the next frame instead of stalling materialization.
    #[serde(default = "default_verify_budget_secs")]
    pub verify_budget_secs: u64,
    /// How long a verification may wait for a free verifier slot before it is
    /// reported unavailable (milliseconds, 0..=60000; 0 refuses at once).
    /// Waiting callers are served fairly across execution managers.
    #[serde(default = "default_admission_wait_ms")]
    pub admission_wait_ms: u64,
    /// Resident-memory cap per verifier child in bytes, enforced by the node
    /// on Linux and macOS by sampling; 0 disables it. A child over the cap is
    /// killed and the verification reported unavailable.
    #[serde(default = "default_max_resident_bytes")]
    pub max_resident_bytes: u64,
    /// Explicitly disable the token suite. The node then rejects every
    /// confidential token operation ("token suite is not
    /// configured") instead of falling back to any older proof system.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for ProofWorkerConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            cpu_seconds: default_cpu_seconds(),
            wall_timeout_secs: default_wall_timeout_secs(),
            address_space_bytes: 0,
            max_concurrent: default_max_concurrent(),
            native_threads: default_native_threads(),
            verify_budget_secs: default_verify_budget_secs(),
            admission_wait_ms: default_admission_wait_ms(),
            max_resident_bytes: default_max_resident_bytes(),
            disabled: false,
        }
    }
}

impl ProofWorkerConfig {
    pub fn apply_defaults(&mut self) {
        if self.cpu_seconds == 0 {
            self.cpu_seconds = default_cpu_seconds();
        }
        if self.wall_timeout_secs == 0 {
            self.wall_timeout_secs = default_wall_timeout_secs();
        }
    }

    /// Range and shape checks matching the worker client's own guards, so a
    /// bad value fails at config load rather than at first verification.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_WORKER_LIMIT_SECS).contains(&self.cpu_seconds) {
            return Err(format!(
                "proofWorker.cpuSeconds must be within 1..={MAX_WORKER_LIMIT_SECS}, got {}",
                self.cpu_seconds
            ));
        }
        if !(1..=MAX_WORKER_LIMIT_SECS).contains(&self.wall_timeout_secs) {
            return Err(format!(
                "proofWorker.wallTimeoutSecs must be within 1..={MAX_WORKER_LIMIT_SECS}, got {}",
                self.wall_timeout_secs
            ));
        }
        if self.wall_timeout_secs < self.cpu_seconds {
            return Err(
                "proofWorker.wallTimeoutSecs must be at least proofWorker.cpuSeconds".into(),
            );
        }
        if self.address_space_bytes >= i64::MAX as u64 {
            return Err("proofWorker.addressSpaceBytes is out of range".into());
        }
        if !(1..=64).contains(&self.max_concurrent) {
            return Err(format!("proofWorker.maxConcurrent must be within 1..=64, got {}", self.max_concurrent));
        }
        if !(1..=8).contains(&self.native_threads) {
            return Err(format!("proofWorker.nativeThreads must be within 1..=8, got {}", self.native_threads));
        }
        if !(1..=10).contains(&self.verify_budget_secs) {
            return Err(format!("proofWorker.verifyBudgetSecs must be within 1..=10, got {}", self.verify_budget_secs));
        }
        if self.admission_wait_ms > 60_000 {
            return Err(format!("proofWorker.admissionWaitMs must be within 0..=60000, got {}", self.admission_wait_ms));
        }
        if self.max_resident_bytes != 0 && self.max_resident_bytes < (256 << 20) {
            return Err("proofWorker.maxResidentBytes must be 0 (off) or at least 256 MiB".into());
        }
        if !self.path.is_empty() && !std::path::Path::new(&self.path).is_absolute() {
            return Err(format!("proofWorker.path must be absolute, got {:?}", self.path));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_yaml_round_trips() {
        let mut config = ProofWorkerConfig::default();
        config.validate().unwrap();
        config.cpu_seconds = 0;
        config.wall_timeout_secs = 0;
        config.apply_defaults();
        assert_eq!(config, ProofWorkerConfig::default());
        let parsed: ProofWorkerConfig = serde_yaml::from_str(
            "path: /opt/quil/quil-amount-proof-worker\ncpuSeconds: 600\nwallTimeoutSecs: 900\naddressSpaceBytes: 8589934592\ndisabled: false\n",
        )
        .unwrap();
        assert_eq!(parsed.path, "/opt/quil/quil-amount-proof-worker");
        assert_eq!((parsed.cpu_seconds, parsed.wall_timeout_secs, parsed.address_space_bytes), (600, 900, 8 << 30));
        parsed.validate().unwrap();
        let empty: ProofWorkerConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(empty, ProofWorkerConfig::default());
        let encoded = serde_yaml::to_string(&parsed).unwrap();
        assert_eq!(serde_yaml::from_str::<ProofWorkerConfig>(&encoded).unwrap(), parsed);
    }

    #[test]
    fn validation_rejects_out_of_range_and_relative_paths() {
        let base = ProofWorkerConfig::default();
        assert!(ProofWorkerConfig { cpu_seconds: 3601, wall_timeout_secs: 3601, ..base.clone() }.validate().is_err());
        assert!(ProofWorkerConfig { cpu_seconds: 1800, wall_timeout_secs: 600, ..base.clone() }.validate().is_err());
        assert!(ProofWorkerConfig { address_space_bytes: u64::MAX, ..base.clone() }.validate().is_err());
        assert!(ProofWorkerConfig { path: "relative/worker".into(), ..base.clone() }.validate().is_err());
        assert!(ProofWorkerConfig { path: "/abs/worker".into(), ..base }.validate().is_ok());
    }
}
