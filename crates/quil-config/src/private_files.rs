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
/// existing one keeps its mode within `mode`, and its owner and group, so
/// `sudo qclient` leaves a node directory readable by the user the node
/// runs as. A user who may not give the replacement that owner gets a
/// `PermissionDenied` error naming the file and its owner, and the file
/// is left as it was. A symbolic link at `path` is followed, so its target
/// is replaced and the link kept. On failure the temporary file is
/// removed.
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let existing = match std::fs::metadata(&target) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let tmp = temporary_path(&target);
    let written = write_new_file(&tmp, &target, contents, mode, existing.as_ref())
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
/// with the owner and mode [`atomic_write`] gives `target`, which has the
/// metadata `existing` unless it is new.
fn write_new_file(
    tmp: &Path,
    target: &Path,
    contents: &[u8],
    mode: u32,
    existing: Option<&std::fs::Metadata>,
) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(existing) = existing {
            let kept = existing.permissions().mode() & mode & 0o7777;
            keep_owner(&file, target, existing, kept)?;
            file.set_permissions(std::fs::Permissions::from_mode(kept))?;
        }
    }
    #[cfg(not(unix))]
    let _ = (target, mode, existing);
    file.write_all(contents)?;
    file.sync_all()
}

/// Give `file`, the replacement of `target`, the owner and group of
/// `existing` (`target`'s metadata), so that a root run leaves another
/// user's file theirs. Without the right to, a file of another user is
/// refused rather than taken over; only a group that `kept` (the new
/// mode) gives no access may stay ours.
#[cfg(unix)]
fn keep_owner(
    file: &File,
    target: &Path,
    existing: &std::fs::Metadata,
    kept: u32,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let ours = file.metadata()?;
    let (uid, gid) = (existing.uid(), existing.gid());
    if (ours.uid(), ours.gid()) == (uid, gid) {
        return Ok(());
    }
    match std::os::unix::fs::fchown(file, Some(uid), Some(gid)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            if ours.uid() == uid && kept & 0o070 == 0 {
                return Ok(());
            }
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by uid {uid} gid {gid}, which this user (uid {} \
                     gid {}) may not give its replacement: run this as root or \
                     as that user; the file is unchanged",
                    target.display(),
                    ours.uid(),
                    ours.gid()
                ),
            ))
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "keep the owner of {}: {e}; the file is unchanged",
                target.display()
            ),
        )),
    }
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

    /// The user and group `nobody`, which tests run as root give files.
    const NOBODY: u32 = 65_534;

    /// Whether this process runs as root, read from a file it creates in
    /// `dir`.
    fn running_as_root(dir: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let probe = dir.join("probe");
        std::fs::write(&probe, b"").unwrap();
        let root = std::fs::metadata(&probe).unwrap().uid() == 0;
        std::fs::remove_file(&probe).unwrap();
        root
    }

    fn owner(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).unwrap();
        (meta.uid(), meta.gid())
    }

    /// Run as root (`sudo qclient ...`) on the node directory of the user
    /// the node runs as, a replaced key or state file stays that user's,
    /// so the node can still read it; a new file is root's as before.
    #[test]
    fn replaced_files_keep_their_owner() {
        let dir = tempdir("owner");
        if !running_as_root(&dir) {
            println!("skipped: only root can give a file another owner");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let config = dir.join("config.yml");
        write_private_file(&config, b"old").unwrap();
        std::os::unix::fs::chown(&config, Some(NOBODY), Some(NOBODY)).unwrap();
        write_private_file(&config, b"new").unwrap();
        assert_eq!(
            owner(&config),
            (NOBODY, NOBODY),
            "config.yml replaced by root keeps its owner"
        );
        assert_eq!(std::fs::read(&config).unwrap(), b"new");
        assert_eq!(mode(&config), 0o600);

        let aliases = dir.join("aliases.yaml");
        atomic_write(&aliases, b"a", 0o644).unwrap();
        std::os::unix::fs::chown(&aliases, Some(NOBODY), Some(NOBODY)).unwrap();
        atomic_write(&aliases, b"b", 0o644).unwrap();
        assert_eq!(
            owner(&aliases),
            (NOBODY, NOBODY),
            "aliases keep their owner"
        );

        let fresh = dir.join("keys.yml");
        write_private_file(&fresh, b"null:\n").unwrap();
        assert_eq!(owner(&fresh).0, 0, "a new file is root's");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A user who may not give a replacement the owner of the file it
    /// replaces is refused, with the file and its owner named, and the file
    /// is left whole and its owner's: here `nobody` in a directory open to
    /// all, replacing a file of root's.
    #[test]
    fn another_users_file_is_refused() {
        if let Ok(path) = std::env::var(FOREIGN_OWNER) {
            // The child, run as `nobody`.
            let path = Path::new(&path);
            let err = write_private_file(path, b"taken over")
                .expect_err("nobody must not replace a file of root's");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            let text = err.to_string();
            assert!(text.contains(&path.display().to_string()), "{text}");
            assert!(text.contains("owned by uid 0"), "{text}");
            return;
        }
        let dir = tempdir("foreign");
        if !running_as_root(&dir) {
            println!("skipped: only root can run the test as another user");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        set_mode(&dir, 0o777);
        let path = dir.join("config.yml");
        write_private_file(&path, b"root's").unwrap();
        let status = {
            use std::os::unix::process::CommandExt;
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("private_files::tests::another_users_file_is_refused")
                .arg("--nocapture")
                .env(FOREIGN_OWNER, &path)
                .uid(NOBODY)
                .gid(NOBODY)
                .status()
                .expect("run the test as nobody")
        };
        assert!(status.success(), "the write as nobody was refused");
        assert_eq!(std::fs::read(&path).unwrap(), b"root's");
        assert_eq!(owner(&path), (0, 0), "the file stays root's");
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("config.yml")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    const FOREIGN_OWNER: &str = "QUIL_CONFIG_TEST_FOREIGN_OWNER";

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
