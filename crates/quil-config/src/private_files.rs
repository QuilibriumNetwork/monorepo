//! Files that hold private keys: the config (the keystore's encryption key
//! and the Ed448 peer key) and the keystore. They are created readable by
//! their owner only, as the Go node created them, whatever the umask.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::Path;

/// Create `dir` and its missing parents, a new directory accessible by its
/// owner only (mode 0700). An existing directory keeps its mode.
pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Open `path` for writing as an empty file readable by its owner only: a
/// new file is created with mode 0600, and an existing one that group or
/// others can access is restricted to 0600 before it is emptied, so a
/// failure leaves its contents in place.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    file.set_len(0)?;
    Ok(file)
}

/// Write `contents` to `path` through [`create_private_file`] and flush
/// them to disk.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Flush the directory holding `path` to disk, so a rename into it
/// survives a crash. Best effort: some file systems refuse it.
pub fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Restrict an existing regular file that group or others can access to
/// its owner (mode 0600). Returns the mode it had when it changed it, and
/// `None` when the file is missing, not a regular file or already private,
/// and on systems without Unix permissions.
pub fn restrict_private_file(path: &Path) -> io::Result<Option<u32>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mode = metadata.permissions().mode() & 0o7777;
        if !metadata.is_file() || mode & 0o077 == 0 {
            return Ok(None);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Some(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir(name: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "quil-config-private-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A new file is created owner-only; an existing readable one is
    /// restricted and its old contents replaced.
    #[test]
    fn private_files_are_owner_only() {
        let dir = tempdir("write");
        let fresh = dir.join("fresh");
        write_private_file(&fresh, b"secret").unwrap();
        assert_eq!(mode(&fresh), 0o600);
        assert_eq!(std::fs::read(&fresh).unwrap(), b"secret");

        let existing = dir.join("existing");
        std::fs::write(&existing, b"an older and longer secret").unwrap();
        set_mode(&existing, 0o644);
        write_private_file(&existing, b"new").unwrap();
        assert_eq!(mode(&existing), 0o600);
        assert_eq!(std::fs::read(&existing).unwrap(), b"new");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// New directories, parents included, are owner-only; an existing one
    /// keeps its mode.
    #[test]
    fn private_dirs_are_owner_only() {
        let dir = tempdir("dirs");
        let nested = dir.join("a").join("b");
        create_private_dir_all(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&dir.join("a")), 0o700);
        set_mode(&dir, 0o755);
        create_private_dir_all(&dir).unwrap();
        assert_eq!(mode(&dir), 0o755);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a regular file that group or others can access is restricted,
    /// and the old mode is reported.
    #[test]
    fn restricting_reports_the_old_mode() {
        let dir = tempdir("restrict");
        let path = dir.join("config.yml");
        assert_eq!(restrict_private_file(&path).unwrap(), None, "missing");
        std::fs::write(&path, b"x").unwrap();
        set_mode(&path, 0o644);
        assert_eq!(restrict_private_file(&path).unwrap(), Some(0o644));
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            restrict_private_file(&path).unwrap(),
            None,
            "already private"
        );
        set_mode(&path, 0o640);
        assert_eq!(restrict_private_file(&path).unwrap(), Some(0o640));
        assert_eq!(mode(&path), 0o600);
        set_mode(&path, 0o400);
        assert_eq!(restrict_private_file(&path).unwrap(), None);
        assert_eq!(mode(&path), 0o400, "an owner-only mode is kept");
        set_mode(&dir, 0o755);
        assert_eq!(restrict_private_file(&dir).unwrap(), None, "a directory");
        assert_eq!(mode(&dir), 0o755);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
