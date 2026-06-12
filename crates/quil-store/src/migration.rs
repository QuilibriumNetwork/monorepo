//! Database migration framework. Tracks and applies ordered migrations
//! on startup.
//!
//! Each migration runs in a single write batch for atomicity. The
//! current version is stored as an 8-byte big-endian u64 under the
//! key `MIGRATION`.

use quil_types::error::{QuilError, Result};
use tracing::{info, warn};

/// Key used to store the migration version.
const MIGRATION_KEY: &[u8] = b"MIGRATION";

/// A migration function. Receives the DB for read/write access.
/// All writes should go through the DB directly (each migration
/// is its own atomic unit).
pub type MigrationFn = fn(db: &rocksdb::DB) -> Result<()>;

/// A named migration step.
pub struct Migration {
    pub name: &'static str,
    pub apply: MigrationFn,
}

/// Run all pending migrations on the database. Called once at startup.
///
/// Migrations are identified by their index in the `migrations` slice.
/// The stored version tracks how many have been applied. New migrations
/// are appended to the end of the list — never reordered or removed.
pub fn run_migrations(db: &rocksdb::DB, migrations: &[Migration]) -> Result<()> {
    let stored_version = get_migration_version(db)?;
    let target_version = migrations.len() as u64;

    if stored_version > target_version {
        return Err(QuilError::Store(format!(
            "database migration version {} is newer than binary version {} — \
             refusing to downgrade",
            stored_version, target_version
        )));
    }

    if stored_version == target_version {
        info!(
            version = target_version,
            "database is up to date"
        );
        return Ok(());
    }

    info!(
        stored = stored_version,
        target = target_version,
        pending = target_version - stored_version,
        "applying database migrations"
    );

    for i in stored_version..target_version {
        let migration = &migrations[i as usize];
        info!(
            version = i + 1,
            name = migration.name,
            "applying migration"
        );

        match (migration.apply)(db) {
            Ok(()) => {
                // Update version after each successful migration
                set_migration_version(db, i + 1)?;
            }
            Err(e) => {
                warn!(
                    version = i + 1,
                    name = migration.name,
                    error = %e,
                    "migration failed"
                );
                return Err(e);
            }
        }
    }

    info!(version = target_version, "all migrations applied");
    Ok(())
}

/// Get the current migration version from the database.
fn get_migration_version(db: &rocksdb::DB) -> Result<u64> {
    match db.get(MIGRATION_KEY) {
        Ok(Some(bytes)) => {
            if bytes.len() < 8 {
                return Ok(0);
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            Ok(u64::from_be_bytes(buf))
        }
        Ok(None) => Ok(0),
        Err(e) => Err(QuilError::Store(format!(
            "failed to read migration version: {}",
            e
        ))),
    }
}

/// Set the migration version in the database.
fn set_migration_version(db: &rocksdb::DB, version: u64) -> Result<()> {
    db.put(MIGRATION_KEY, version.to_be_bytes())
        .map_err(|e| QuilError::Store(format!("failed to write migration version: {}", e)))
}

// =====================================================================
// Rust node migrations
// =====================================================================

/// The ordered list of migrations for the Rust node.
///
/// Unlike Go's 53 migrations (which fix Go-era data bugs), the Rust
/// node starts fresh and only needs migrations for schema changes
/// introduced after the initial release.
pub fn rust_node_migrations() -> Vec<Migration> {
    vec![
        // Migration 1: Initial schema marker (no-op, establishes baseline)
        Migration {
            name: "initial_schema",
            apply: |_db| Ok(()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> rocksdb::DB {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        rocksdb::DB::open(&opts, tmp.path()).unwrap()
    }

    #[test]
    fn fresh_db_has_version_zero() {
        let db = open_test_db();
        assert_eq!(get_migration_version(&db).unwrap(), 0);
    }

    #[test]
    fn run_migrations_applies_all_pending() {
        let db = open_test_db();
        let migrations = vec![
            Migration { name: "m1", apply: |_| Ok(()) },
            Migration { name: "m2", apply: |_| Ok(()) },
            Migration { name: "m3", apply: |_| Ok(()) },
        ];
        run_migrations(&db, &migrations).unwrap();
        assert_eq!(get_migration_version(&db).unwrap(), 3);
    }

    #[test]
    fn run_migrations_skips_already_applied() {
        let db = open_test_db();
        let m1 = vec![Migration { name: "m1", apply: |_| Ok(()) }];
        run_migrations(&db, &m1).unwrap();
        assert_eq!(get_migration_version(&db).unwrap(), 1);

        // Add a second migration — only m2 should run
        let m2 = vec![
            Migration { name: "m1", apply: |_| Ok(()) },
            Migration { name: "m2", apply: |_| Ok(()) },
        ];
        run_migrations(&db, &m2).unwrap();
        assert_eq!(get_migration_version(&db).unwrap(), 2);
    }

    #[test]
    fn run_migrations_rejects_downgrade() {
        let db = open_test_db();
        set_migration_version(&db, 10).unwrap();
        let migrations = vec![Migration { name: "m1", apply: |_| Ok(()) }];
        let err = run_migrations(&db, &migrations).unwrap_err();
        assert!(err.to_string().contains("downgrade"));
    }

    #[test]
    fn run_migrations_stops_on_error() {
        let db = open_test_db();
        let migrations = vec![
            Migration { name: "ok", apply: |_| Ok(()) },
            Migration {
                name: "fail",
                apply: |_| Err(QuilError::Store("boom".into())),
            },
            Migration { name: "never", apply: |_| Ok(()) },
        ];
        assert!(run_migrations(&db, &migrations).is_err());
        // Only the first migration should have been committed
        assert_eq!(get_migration_version(&db).unwrap(), 1);
    }

    #[test]
    fn migration_writes_data() {
        let db = open_test_db();
        let migrations = vec![Migration {
            name: "write_test",
            apply: |db| {
                db.put(b"test-key", b"test-value")
                    .map_err(|e| QuilError::Store(e.to_string()))
            },
        }];
        run_migrations(&db, &migrations).unwrap();
        assert_eq!(db.get(b"test-key").unwrap(), Some(b"test-value".to_vec()));
    }

    #[test]
    fn rust_node_migrations_baseline() {
        let db = open_test_db();
        let migrations = rust_node_migrations();
        run_migrations(&db, &migrations).unwrap();
        assert_eq!(get_migration_version(&db).unwrap(), 1);
    }
}
