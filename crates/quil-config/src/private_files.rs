//! Files that hold private keys: the config (the keystore's encryption key
//! and the Ed448 peer key) and the keystore. They are created readable by
//! their owner only, as the Go node created them, whatever the umask.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Replace `path` with `contents` readable by its owner only (mode 0600,
/// or an existing file's narrower mode) through [`atomic_write`]: a failure
/// at any step leaves the previous file whole.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write(path, contents, 0o600)
}

/// Replace the file at `path` with `contents` so that it holds either its
/// previous or its new contents whatever fails (a full disk, an I/O error,
/// a crash or a power loss): the contents go to a new temporary file in
/// the same directory, which is flushed to disk and renamed over `path`,
/// and the directory is flushed. A new file gets `mode` less the umask; an
/// existing one keeps its mode within `mode`. A symbolic link at `path` is
/// followed, so its target is replaced and the link kept. On failure the
/// temporary file is removed.
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let existing = match std::fs::metadata(&target) {
        Ok(meta) => Some(meta.permissions()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let tmp = temporary_path(&target);
    let written = write_new_file(&tmp, contents, mode, existing)
        .and_then(|()| std::fs::rename(&tmp, &target));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_parent_dir(&target);
    Ok(())
}

/// A name in `target`'s directory no other writer uses: `.<name>.<pid>.<n>.tmp`.
fn temporary_path(target: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    target.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Create `tmp` (it must not exist), write `contents` and flush them,
/// with the mode [`atomic_write`] gives its target.
fn write_new_file(
    tmp: &Path,
    contents: &[u8],
    mode: u32,
    existing: Option<std::fs::Permissions>,
) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(tmp)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(existing) = existing {
            let kept = existing.mode() & mode & 0o7777;
            file.set_permissions(std::fs::Permissions::from_mode(kept))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (mode, existing);
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

    /// A write that fails part way, here at the file size limit, leaves the
    /// previous config whole and no temporary file behind.
    #[test]
    fn a_failed_write_keeps_the_previous_file() {
        if let Ok(path) = std::env::var(FAILING_WRITE) {
            // The child: write past the limit its parent set.
            let result = write_private_file(Path::new(&path), &[b'n'; 64 * 1024]);
            assert!(result.is_err(), "the write must hit the file size limit");
            return;
        }
        let dir = tempdir("failing");
        let path = dir.join("config.yml");
        let old = b"encryptionKey: the only copy\n".repeat(4);
        write_private_file(&path, &old).unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("trap '' XFSZ; ulimit -f 8; exec \"$0\" --exact \"$1\" --nocapture")
            .arg(std::env::current_exe().unwrap())
            .arg("private_files::tests::a_failed_write_keeps_the_previous_file")
            .env(FAILING_WRITE, &path)
            .status()
            .unwrap();
        assert!(status.success(), "the child write failed as planned");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            old,
            "the previous config.yml survives a failed write whole"
        );
        assert_eq!(mode(&path), 0o600);
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("config.yml")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    const FAILING_WRITE: &str = "QUIL_CONFIG_TEST_FAILING_WRITE";

    /// The replaced file keeps an owner-only mode narrower than 0600, and
    /// a symbolic link to it stays a link.
    #[test]
    fn atomic_writes_keep_the_mode_and_follow_links() {
        let dir = tempdir("atomic");
        let path = dir.join("keys.yml");
        write_private_file(&path, b"one").unwrap();
        set_mode(&path, 0o400);
        write_private_file(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(mode(&path), 0o400);
        let link = dir.join("link.yml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        set_mode(&path, 0o600);
        write_private_file(&link, b"three").unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        let public = dir.join("public.yaml");
        atomic_write(&public, b"a", 0o644).unwrap();
        assert_eq!(mode(&public) & 0o700, 0o600, "the owner can rewrite it");
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
