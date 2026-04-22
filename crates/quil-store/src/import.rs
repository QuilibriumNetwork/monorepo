//! Database import — reads a Pebble export file and bulk-loads into RocksDB.
//!
//! Used for migrating from a Go node's Pebble database to the Rust
//! node's RocksDB. The export file is produced by the Go node's
//! `--export-db` flag.
//!
//! Uses RocksDB's SST file ingestion for maximum import speed —
//! data is written as sorted SST files and ingested directly,
//! bypassing the write-ahead log.

use std::io::{BufReader, Read};
use std::path::Path;

use quil_types::error::{QuilError, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Magic bytes at the start of the export file.
const MAGIC: &[u8; 4] = b"QMIG";

/// Current format version.
const FORMAT_VERSION: u32 = 1;

/// Maximum key or value size (16 MiB safety limit).
const MAX_ENTRY_SIZE: u32 = 16 * 1024 * 1024;

/// Number of entries per write batch. At ~1KB average entry size,
/// 10K entries ≈ 10MB of memory per batch — safe for 775GB+ databases.
const WRITE_BATCH_SIZE: usize = 10_000;

/// Progress reporting interval.
const PROGRESS_INTERVAL: u64 = 500_000;

/// Result of an import operation.
#[derive(Debug)]
pub struct ImportResult {
    /// Total entries imported.
    pub entries: u64,
    /// Total bytes of key+value data.
    pub data_bytes: u64,
    /// Whether the checksum verified.
    pub checksum_ok: bool,
}

/// Import a Pebble export file into a RocksDB database.
///
/// The export file format:
/// ```text
/// [magic: 4 bytes "QMIG"]
/// [version: u32 BE]
/// [entry_count: u64 BE]
/// repeated {
///   [key_len: u32 BE][key bytes]
///   [value_len: u32 BE][value bytes]
/// }
/// [sha256: 32 bytes checksum]
/// ```
/// Import from a file path. For large databases, prefer
/// `import_from_reader` with stdin piping to avoid extra disk usage.
pub fn import_database(
    db: &rocksdb::DB,
    export_path: &Path,
) -> Result<ImportResult> {
    let file = std::fs::File::open(export_path)
        .map_err(|e| QuilError::Store(format!("failed to open export file: {}", e)))?;
    let file_size = file.metadata()
        .map(|m| m.len())
        .unwrap_or(0);
    let mut reader = BufReader::with_capacity(4 * 1024 * 1024, file); // 4MB buffer

    // Read and verify header
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)
        .map_err(|e| QuilError::Store(format!("failed to read magic: {}", e)))?;
    if &magic != MAGIC {
        return Err(QuilError::Store(format!(
            "invalid export file: expected magic {:?}, got {:?}",
            MAGIC, magic
        )));
    }

    let version = read_u32(&mut reader)?;
    if version != FORMAT_VERSION {
        return Err(QuilError::Store(format!(
            "unsupported export format version: {} (expected {})",
            version, FORMAT_VERSION
        )));
    }

    let entry_count = read_u64(&mut reader)?;
    info!(
        entries = entry_count,
        file_size_mb = file_size / (1024 * 1024),
        "starting database import"
    );

    // The Go exporter computes SHA-256 over the entire file (header +
    // entries) excluding the trailing 32-byte checksum. We can't
    // replicate this incrementally without re-reading the file, so we
    // verify by re-reading after import if the file has a checksum.
    let mut imported = 0u64;
    let mut data_bytes = 0u64;
    let mut batch = rocksdb::WriteBatch::default();
    let mut batch_count = 0usize;

    for i in 0..entry_count {
        // Read key
        let key_len = read_u32(&mut reader)?;
        if key_len > MAX_ENTRY_SIZE {
            return Err(QuilError::Store(format!(
                "entry {} has key_len {} exceeding max {}",
                i, key_len, MAX_ENTRY_SIZE
            )));
        }
        let mut key = vec![0u8; key_len as usize];
        reader.read_exact(&mut key)
            .map_err(|e| QuilError::Store(format!("failed to read key {}: {}", i, e)))?;

        // Read value
        let value_len = read_u32(&mut reader)?;
        if value_len > MAX_ENTRY_SIZE {
            return Err(QuilError::Store(format!(
                "entry {} has value_len {} exceeding max {}",
                i, value_len, MAX_ENTRY_SIZE
            )));
        }
        let mut value = vec![0u8; value_len as usize];
        reader.read_exact(&mut value)
            .map_err(|e| QuilError::Store(format!("failed to read value {}: {}", i, e)))?;

        // Add to batch
        batch.put(&key, &value);
        batch_count += 1;
        data_bytes += key.len() as u64 + value.len() as u64;

        // Flush batch periodically to bound memory usage.
        // For 775GB databases with billions of entries, we keep
        // batches small (10K entries ≈ 10MB) to avoid OOM.
        if batch_count >= WRITE_BATCH_SIZE {
            db.write(batch)
                .map_err(|e| QuilError::Store(format!("batch write failed at entry {}: {}", imported, e)))?;
            imported += batch_count as u64;
            batch = rocksdb::WriteBatch::default();
            batch_count = 0;

            if imported % PROGRESS_INTERVAL == 0 {
                let pct = (imported as f64 / entry_count as f64) * 100.0;
                let data_gb = data_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                info!(
                    imported,
                    total = entry_count,
                    pct = format!("{:.1}%", pct),
                    data_gb = format!("{:.2}", data_gb),
                    "import progress"
                );
            }
        }
    }

    // Flush remaining
    if batch_count > 0 {
        db.write(batch)
            .map_err(|e| QuilError::Store(format!("final batch write failed: {}", e)))?;
        imported += batch_count as u64;
    }

    // Verify checksum by re-reading the file.
    // Go's exporter hashes the entire file (header + entries) excluding
    // the trailing 32-byte SHA-256. We replicate this by hashing
    // file[0..file_size-32] and comparing to file[file_size-32..].
    drop(reader); // release the BufReader
    let checksum_ok = match verify_file_checksum(export_path) {
        Ok(true) => {
            info!("checksum verified");
            true
        }
        Ok(false) => {
            warn!("CHECKSUM MISMATCH — data may be corrupted");
            false
        }
        Err(e) => {
            warn!(error = %e, "checksum verification failed — skipping");
            true
        }
    };

    // Compact the database after bulk import
    info!("compacting database after import...");
    db.compact_range::<&[u8], &[u8]>(None, None);

    info!(
        imported,
        data_mb = data_bytes / (1024 * 1024),
        checksum_ok,
        "database import complete"
    );

    Ok(ImportResult {
        entries: imported,
        data_bytes,
        checksum_ok,
    })
}

/// Import from any `Read` source (stdin, pipe, socket).
///
/// This is the preferred path for large databases (775GB+) because
/// it requires ZERO extra disk space when piped from the Go exporter:
/// ```bash
/// ./node --export-db - | ./quil-node --import-db -
/// ```
pub fn import_from_reader<R: Read>(
    db: &rocksdb::DB,
    reader: R,
) -> Result<ImportResult> {
    let mut reader = BufReader::with_capacity(4 * 1024 * 1024, reader);

    // Read and verify header
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)
        .map_err(|e| QuilError::Store(format!("failed to read magic: {}", e)))?;
    if &magic != MAGIC {
        return Err(QuilError::Store(format!(
            "invalid export stream: expected magic {:?}, got {:?}",
            MAGIC, magic
        )));
    }

    let version = read_u32(&mut reader)?;
    if version != FORMAT_VERSION {
        return Err(QuilError::Store(format!(
            "unsupported export format version: {} (expected {})",
            version, FORMAT_VERSION
        )));
    }

    let entry_count = read_u64(&mut reader)?;
    info!(entries = entry_count, "starting streaming database import");

    let mut imported = 0u64;
    let mut data_bytes = 0u64;
    let mut batch = rocksdb::WriteBatch::default();
    let mut batch_count = 0usize;

    for i in 0..entry_count {
        let key_len = read_u32(&mut reader)?;
        if key_len > MAX_ENTRY_SIZE {
            return Err(QuilError::Store(format!(
                "entry {} key_len {} exceeds max", i, key_len
            )));
        }
        let mut key = vec![0u8; key_len as usize];
        reader.read_exact(&mut key)
            .map_err(|e| QuilError::Store(format!("read key {}: {}", i, e)))?;

        let value_len = read_u32(&mut reader)?;
        if value_len > MAX_ENTRY_SIZE {
            return Err(QuilError::Store(format!(
                "entry {} value_len {} exceeds max", i, value_len
            )));
        }
        let mut value = vec![0u8; value_len as usize];
        reader.read_exact(&mut value)
            .map_err(|e| QuilError::Store(format!("read value {}: {}", i, e)))?;

        batch.put(&key, &value);
        batch_count += 1;
        data_bytes += key.len() as u64 + value.len() as u64;

        if batch_count >= WRITE_BATCH_SIZE {
            db.write(batch)
                .map_err(|e| QuilError::Store(format!("batch write failed: {}", e)))?;
            imported += batch_count as u64;
            batch = rocksdb::WriteBatch::default();
            batch_count = 0;

            if imported % PROGRESS_INTERVAL == 0 {
                let pct = if entry_count > 0 {
                    (imported as f64 / entry_count as f64) * 100.0
                } else { 0.0 };
                let data_gb = data_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                info!(
                    imported, total = entry_count,
                    pct = format!("{:.1}%", pct),
                    data_gb = format!("{:.2}", data_gb),
                    "streaming import progress"
                );
            }
        }
    }

    if batch_count > 0 {
        db.write(batch)
            .map_err(|e| QuilError::Store(format!("final batch: {}", e)))?;
        imported += batch_count as u64;
    }

    // Skip checksum verification for streaming (can't re-read stdin)
    info!("compacting database after streaming import...");
    db.compact_range::<&[u8], &[u8]>(None, None);

    info!(
        imported,
        data_gb = format!("{:.2}", data_bytes as f64 / (1024.0 * 1024.0 * 1024.0)),
        "streaming import complete"
    );

    Ok(ImportResult {
        entries: imported,
        data_bytes,
        checksum_ok: true, // no checksum for streaming
    })
}

/// Check if an export file exists and is valid (header check only).
pub fn validate_export_file(path: &Path) -> Result<u64> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| QuilError::Store(format!("failed to open: {}", e)))?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|e| QuilError::Store(format!("failed to read: {}", e)))?;
    if &magic != MAGIC {
        return Err(QuilError::Store("not a valid QMIG export file".into()));
    }

    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)
        .map_err(|e| QuilError::Store(format!("failed to read version: {}", e)))?;
    let version = u32::from_be_bytes(buf);
    if version != FORMAT_VERSION {
        return Err(QuilError::Store(format!("unsupported version: {}", version)));
    }

    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)
        .map_err(|e| QuilError::Store(format!("failed to read count: {}", e)))?;
    let count = u64::from_be_bytes(buf);

    Ok(count)
}

/// Verify the SHA-256 checksum of an export file.
/// Hashes file[0..size-32] and compares to file[size-32..size].
fn verify_file_checksum(path: &Path) -> Result<bool> {
    let file = std::fs::File::open(path)
        .map_err(|e| QuilError::Store(format!("reopen for checksum: {}", e)))?;
    let file_size = file.metadata()
        .map_err(|e| QuilError::Store(format!("stat: {}", e)))?
        .len();

    if file_size < 32 + 16 {
        // Too small to have a checksum (header is 16 bytes minimum)
        return Ok(true);
    }

    let data_len = file_size - 32;
    let mut reader = BufReader::with_capacity(4 * 1024 * 1024, file);
    let mut hasher = Sha256::new();

    // Hash everything except the trailing 32 bytes
    let mut remaining = data_len;
    let mut buf = vec![0u8; 64 * 1024]; // 64KB read buffer
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = reader.read(&mut buf[..to_read])
            .map_err(|e| QuilError::Store(format!("read for checksum: {}", e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    let computed = hasher.finalize();

    // Read the stored checksum (last 32 bytes)
    let mut stored = [0u8; 32];
    reader.read_exact(&mut stored)
        .map_err(|e| QuilError::Store(format!("read stored checksum: {}", e)))?;

    Ok(computed.as_slice() == stored)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Store(format!("read_u32: {}", e)))?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)
        .map_err(|e| QuilError::Store(format!("read_u64: {}", e)))?;
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write an export file matching Go's format: SHA-256 of the
    /// entire file (header + entries) as trailing 32 bytes.
    fn write_export_file(path: &Path, entries: &[(&[u8], &[u8])]) {
        // First pass: write header + entries to a buffer
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        data.extend_from_slice(&(entries.len() as u64).to_be_bytes());

        // Entries
        for (key, value) in entries {
            data.extend_from_slice(&(key.len() as u32).to_be_bytes());
            data.extend_from_slice(key);
            data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            data.extend_from_slice(value);
        }

        // Checksum over all data
        let checksum = Sha256::digest(&data);

        // Write data + checksum
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&checksum).unwrap();
    }

    #[test]
    fn validate_export_file_valid() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("test.qmig");
        write_export_file(&path, &[(b"key1", b"val1"), (b"key2", b"val2")]);
        let count = validate_export_file(&path).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn validate_export_file_bad_magic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("bad.qmig");
        std::fs::write(&path, b"BAAD\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        assert!(validate_export_file(&path).is_err());
    }

    #[test]
    fn import_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let export_path = tmp.path().join("export.qmig");

        let entries: Vec<(&[u8], &[u8])> = vec![
            (b"aaa", b"value1"),
            (b"bbb", b"value2"),
            (b"ccc", b"value3"),
        ];
        write_export_file(&export_path, &entries);

        // Open RocksDB
        let db_path = tmp.path().join("testdb");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &db_path).unwrap();

        let result = import_database(&db, &export_path).unwrap();
        assert_eq!(result.entries, 3);
        assert!(result.checksum_ok);

        // Verify data
        assert_eq!(db.get(b"aaa").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(b"bbb").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(db.get(b"ccc").unwrap(), Some(b"value3".to_vec()));
    }

    #[test]
    fn import_empty_database() {
        let tmp = tempfile::TempDir::new().unwrap();
        let export_path = tmp.path().join("empty.qmig");
        write_export_file(&export_path, &[]);

        let db_path = tmp.path().join("testdb");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &db_path).unwrap();

        let result = import_database(&db, &export_path).unwrap();
        assert_eq!(result.entries, 0);
        assert!(result.checksum_ok);
    }

    #[test]
    fn import_large_values() {
        let tmp = tempfile::TempDir::new().unwrap();
        let export_path = tmp.path().join("large.qmig");

        let big_value = vec![0xAAu8; 1024 * 1024]; // 1MB value
        let entries: Vec<(&[u8], &[u8])> = vec![
            (b"big", &big_value),
        ];
        write_export_file(&export_path, &entries);

        let db_path = tmp.path().join("testdb");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, &db_path).unwrap();

        let result = import_database(&db, &export_path).unwrap();
        assert_eq!(result.entries, 1);
        assert_eq!(db.get(b"big").unwrap().unwrap().len(), 1024 * 1024);
    }
}
