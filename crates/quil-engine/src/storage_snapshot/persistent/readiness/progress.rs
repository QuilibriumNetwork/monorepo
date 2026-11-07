//! Atomic, synced checkpoints survive cancellation before an allocation finishes.
use super::*;
use serde_json::{json, Value};
use std::sync::{Mutex, PoisonError};

pub(super) fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::create_dir_all(path.parent().unwrap()).map_err(io)?;
    let temporary = path.with_extension("json.tmp");
    let mut file = fs::File::create(&temporary).map_err(io)?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|e| unavailable(format!("benchmark progress: {e}")))?;
    file.sync_all().map_err(io)?;
    fs::rename(temporary, path).map_err(io)?;
    Ok(())
}

pub(super) fn registration(
    directory: &Path,
    filter: &str,
    prefix: &impl Serialize,
    round: usize,
    stage: &str,
    timing: &RoundMeasurement,
) -> Result<()> {
    let prefix = serde_json::to_vec(prefix).map_err(|e| unavailable(e.to_string()))?;
    let id = hex::encode(digest(&prefix));
    save(
        &directory
            .join("progress")
            .join(filter)
            .join(format!("round-{round}-{id}.json")),
        &json!({"kind":"registration_sector","filter":filter,"round":round,"stage":stage,"timings":timing}),
    )
}

pub(super) struct Journal {
    path: PathBuf,
    started: Instant,
    record: Mutex<Value>,
}
impl Journal {
    pub(super) fn new(
        directory: &Path,
        filter: &str,
        index: usize,
        total: usize,
        n: u64,
    ) -> Result<Self> {
        let journal = Self {
            path: directory
                .join("progress")
                .join(filter)
                .join(format!("{index:05}.json")),
            started: Instant::now(),
            record: Mutex::new(json!({"kind":"sector","filter":filter,"sector_index":index,
                "sectors_in_shard":total,"nodes":n,"layers_completed":0,
                "layer_completed_after_seconds":[],"admission_wait_seconds":0.})),
        };
        journal.stage("waiting_for_admission", &SnapshotMeasurement::default())?;
        Ok(journal)
    }
    pub(super) fn stage(&self, stage: &str, measured: &SnapshotMeasurement) -> Result<()> {
        let mut record = self.record.lock().unwrap_or_else(PoisonError::into_inner);
        record["stage"] = json!(stage);
        record["elapsed_seconds"] = json!(self.started.elapsed().as_secs_f64());
        record["timings"] = json!({
            "cold_label_seconds":measured.cold_label_seconds,
            "certificate_witness_seconds":measured.certificate_witness_seconds,
            "certificate_prove_seconds":measured.certificate_prove_seconds,
            "certificate_verify_seconds":measured.certificate_verify_seconds,
            "certificate_message_bytes":measured.certificate_message_bytes});
        save(&self.path, &*record)
    }
    pub(super) fn admitted(&self, sector: &[u8; 32]) -> Result<()> {
        let mut record = self.record.lock().unwrap_or_else(PoisonError::into_inner);
        record["sector"] = json!(hex::encode(sector));
        record["admission_wait_seconds"] = json!(self.started.elapsed().as_secs_f64());
        record["stage"] = json!("labelling");
        save(&self.path, &*record)
    }
    pub(super) fn layer(&self, layers: usize) -> Result<()> {
        let mut record = self.record.lock().unwrap_or_else(PoisonError::into_inner);
        record["layers_completed"] = json!(layers);
        let elapsed = self.started.elapsed().as_secs_f64();
        record["elapsed_seconds"] = json!(elapsed);
        record["layer_completed_after_seconds"]
            .as_array_mut()
            .unwrap()
            .push(json!(elapsed));
        save(&self.path, &*record)
    }
    pub(super) fn failed(&self, error: &QuilError) -> Result<()> {
        let mut record = self.record.lock().unwrap_or_else(PoisonError::into_inner);
        record["failed_during"] = record["stage"].clone();
        record["stage"] = json!("failed");
        record["error"] = json!(error.to_string());
        record["elapsed_seconds"] = json!(self.started.elapsed().as_secs_f64());
        save(&self.path, &*record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_retains_completed_stages_and_the_last_layer() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path(), "filter", 1, 80, 16_777_216).unwrap();
        journal.admitted(&[3; 32]).unwrap();
        journal.layer(1).unwrap();
        let stats = SnapshotMeasurement {
            cold_label_seconds: 123.,
            ..Default::default()
        };
        journal.stage("certificate_proof", &stats).unwrap();
        journal.failed(&unavailable("deadline".into())).unwrap();
        let record: Value = serde_json::from_slice(&fs::read(&journal.path).unwrap()).unwrap();
        assert_eq!(record["stage"], "failed");
        assert_eq!(record["failed_during"], "certificate_proof");
        assert_eq!(record["layers_completed"], 1);
        assert_eq!(record["timings"]["cold_label_seconds"], 123.);
        assert!(!journal.path.with_extension("json.tmp").exists());
    }
}
