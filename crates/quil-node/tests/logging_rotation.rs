//! Verifies the zap-parity logging module's rotation + compression
//! behavior end-to-end. Matches the Go lumberjack semantics:
//!   * `max_size` triggers size-based rotation (MB in config → bytes here)
//!   * `max_backups` bounds retained rotations
//!   * `compress: true` gzips rotated files
//!
//! Uses a scratch tempdir so tests are hermetic.

use std::io::{Read, Write};

use file_rotate::{
    compression::Compression,
    suffix::{AppendTimestamp, FileLimit},
    ContentLimit, FileRotate,
};

#[test]
fn size_limit_triggers_rotation_and_gzip() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("master.log");

    // Tiny 500-byte cap so we rotate deterministically from a few writes.
    let mut rotate = FileRotate::new(
        log_path.as_path(),
        AppendTimestamp::default(FileLimit::MaxFiles(3)),
        ContentLimit::BytesSurpassed(500),
        Compression::OnRotate(0),
        #[cfg(unix)]
        None,
    );

    // Write 1_200 bytes of log data (should produce at least 2 rotations).
    let line = "2026-04-22T03:00:00Z\tinfo\tquil_node/src/main.rs:42\thello\t{\"coreId\":0}\n";
    for _ in 0..20 {
        rotate.write_all(line.as_bytes()).unwrap();
    }
    drop(rotate); // flush

    // Count rotated files: they should have timestamp suffixes and .gz extension.
    let mut gz_count = 0;
    let mut plain_count = 0;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "master.log" {
            continue;
        }
        if name.ends_with(".gz") {
            gz_count += 1;
            // Validate the gzipped content is recoverable.
            let data = std::fs::read(entry.path()).unwrap();
            let mut gz = flate2::read::GzDecoder::new(&data[..]);
            let mut decoded = String::new();
            gz.read_to_string(&mut decoded).unwrap();
            assert!(decoded.contains("hello"), "rotated gz should contain a log line");
        } else if name.starts_with("master.log.") {
            plain_count += 1;
        }
    }
    assert!(
        gz_count >= 1,
        "expected at least one .gz rotated file, got {} plain + {} gz",
        plain_count,
        gz_count
    );
}

#[test]
fn size_limit_without_compression_rotates_plain_files() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("worker-1.log");

    let mut rotate = FileRotate::new(
        log_path.as_path(),
        AppendTimestamp::default(FileLimit::MaxFiles(3)),
        ContentLimit::BytesSurpassed(300),
        Compression::None,
        #[cfg(unix)]
        None,
    );

    for i in 0..10 {
        let line = format!("2026-04-22T03:00:{:02}Z\tinfo\tsrc/main.rs:1\tmsg\t{{\"coreId\":1}}\n", i);
        rotate.write_all(line.as_bytes()).unwrap();
    }
    drop(rotate);

    // No .gz files should exist with compression=None.
    let mut has_rotated = false;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "worker-1.log" {
            continue;
        }
        assert!(!name.ends_with(".gz"), "compress=None should not produce .gz, got {}", name);
        if name.starts_with("worker-1.log.") {
            has_rotated = true;
        }
    }
    assert!(has_rotated, "expected at least one rotation");
}

#[test]
fn max_backups_enforced_on_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("master.log");

    // Very small content limit, 2-file backup cap.
    let mut rotate = FileRotate::new(
        log_path.as_path(),
        AppendTimestamp::default(FileLimit::MaxFiles(2)),
        ContentLimit::BytesSurpassed(100),
        Compression::None,
        #[cfg(unix)]
        None,
    );

    let line = "2026-04-22T03:00:00Z\tinfo\tsrc/main.rs:1\tx\t{\"coreId\":0}\n";
    for _ in 0..50 {
        rotate.write_all(line.as_bytes()).unwrap();
        // file-rotate enforces cap on rotate — give it a chance to observe
        // by sleeping briefly between writes so the timestamp suffix differs.
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    drop(rotate);

    let rotated: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("master.log.") && !n.contains("/"))
        .collect();
    assert!(
        rotated.len() <= 2,
        "max_backups=2 but found {} rotated files: {:?}",
        rotated.len(),
        rotated
    );
}
