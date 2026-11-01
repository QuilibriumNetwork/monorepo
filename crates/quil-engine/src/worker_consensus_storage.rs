//! Removes app consensus storage a worker kept for shards it no longer serves.
//! Each shard's journals, sealed bodies, session fingerprint, archived journals
//! and finalized records live under `cw-app-consensus`, named by the full shard
//! filter, and nothing removes them when the worker moves to another shard.
//! A later assignment opens a new session and recovers frames through sync, so
//! none of it is needed to serve that shard again.

use std::path::Path;

use quil_types::error::{QuilError, Result};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub entries: usize,
    pub bytes: u64,
}

/// The shard filter an entry belongs to: `app-<filter>[.ext]` or
/// `finalized-<filter>`. Other names are not ours to remove.
fn entry_filter(name: &str) -> Option<Vec<u8>> {
    let rest = name
        .strip_prefix("app-")
        .or_else(|| name.strip_prefix("finalized-"))?;
    let hex_filter = rest.split_once('.').map_or(rest, |(filter, _)| filter);
    hex::decode(hex_filter)
        .ok()
        .filter(|filter| !filter.is_empty())
}

fn size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    std::fs::read_dir(path).map_or(0, |entries| {
        entries.flatten().map(|e| size(&e.path())).sum()
    })
}

/// Remove every entry under `base/cw-app-consensus` whose shard is neither in
/// `keep` nor `retained` (a committee this worker still owes a vote or seal).
/// The caller guarantees no engine of this worker runs outside `keep`.
pub fn remove_outside(
    base: &Path,
    keep: &[Vec<u8>],
    retained: impl Fn(&[u8]) -> bool,
) -> Result<Outcome> {
    let root = base.join("cw-app-consensus");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::default()),
        Err(e) => return Err(QuilError::Store(format!("list app consensus storage: {e}"))),
    };
    let mut outcome = Outcome::default();
    for entry in entries {
        let entry =
            entry.map_err(|e| QuilError::Store(format!("list app consensus storage: {e}")))?;
        let Some(filter) = entry.file_name().to_str().and_then(entry_filter) else {
            continue;
        };
        if keep.contains(&filter) || retained(&filter) {
            continue;
        }
        let path = entry.path();
        let bytes = size(&path);
        let removed = if entry
            .file_type()
            .map_err(|e| QuilError::Store(e.to_string()))?
            .is_dir()
        {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|e| QuilError::Store(format!("remove {}: {e}", path.display())))?;
        outcome.entries += 1;
        outcome.bytes += bytes;
    }
    std::fs::File::open(&root)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| QuilError::Store(format!("sync app consensus storage: {e}")))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_unserved_and_unretained_shards() {
        let base = std::env::temp_dir().join(format!(
            "quil-cw-storage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("cw-app-consensus");
        let (served, retained, left) = (vec![0xaa, 0x01], vec![0xaa, 0x02], vec![0xaa, 0x03]);
        let names = |filter: &[u8]| {
            let f = hex::encode(filter);
            [
                format!("app-{f}"),
                format!("app-{f}.bodies"),
                format!("app-{f}.retired"),
                format!("finalized-{f}"),
            ]
        };
        for filter in [&served, &retained, &left] {
            for name in names(filter) {
                std::fs::create_dir_all(root.join(&name).join("session-1")).unwrap();
                std::fs::write(root.join(&name).join("session-1").join("blob"), [7u8; 100])
                    .unwrap();
            }
            std::fs::write(
                root.join(format!("app-{}.cw-fp", hex::encode(filter))),
                [1u8; 10],
            )
            .unwrap();
        }
        std::fs::create_dir_all(root.join("unrelated")).unwrap();

        let outcome =
            remove_outside(&base, &[served.clone()], |f| f == retained.as_slice()).unwrap();
        assert_eq!(
            outcome,
            Outcome {
                entries: 5,
                bytes: 410
            }
        );
        for name in names(&left) {
            assert!(!root.join(name).exists());
        }
        assert!(!root
            .join(format!("app-{}.cw-fp", hex::encode(&left)))
            .exists());
        for filter in [&served, &retained] {
            for name in names(filter) {
                assert!(root.join(name).join("session-1").join("blob").exists());
            }
        }
        assert!(root.join("unrelated").exists());
        assert_eq!(
            remove_outside(&base, &[served], |f| f == retained.as_slice()).unwrap(),
            Outcome::default()
        );
        assert_eq!(
            remove_outside(&base.join("absent"), &[], |_| false).unwrap(),
            Outcome::default()
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
