//! Files whose loss or a torn copy costs keys or consensus state are
//! written only through `quil_config::atomic_write` (directly or via
//! `write_private_file`), never by a call that truncates or writes the
//! file in place, and so keep their owner when `sudo qclient` replaces
//! them. Each entry names the function writing one such file; a write
//! added to it in place fails here. Every other write in the code qclient
//! runs is listed with why it needs neither, so a new writer fails until
//! it is listed in one or the other.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `(source file, function, the file it writes)`.
const WRITERS: &[(&str, &str, &str)] = &[
    ("quil-config/src/lib.rs", "save_config", "config.yml"),
    (
        "quil-config/src/private_files.rs",
        "write_private_file",
        "private files",
    ),
    (
        "quil-keys/src/file_key_manager.rs",
        "save_to_file",
        "keys.yml",
    ),
    (
        "quil-keys/src/identity_guard.rs",
        "write_record",
        "identity record",
    ),
    ("quil-client/src/config.rs", "save", "qclient-config.yaml"),
    ("quil-client/src/alias_store.rs", "save", "aliases"),
    (
        "quil-client/src/commands/node/prover/manage/settings.rs",
        "write",
        "view settings",
    ),
    (
        "quil-client/src/commands/token/wallet.rs",
        "write_prefunded",
        "pre-funded settlement journal",
    ),
    (
        "quil-client/src/commands/token/legacy.rs",
        "record_shielded",
        "shield-all journal",
    ),
    (
        "quil-client/src/commands/node/nodeconfig.rs",
        "replace_file",
        "node config.yml",
    ),
];

/// The source of the code qclient runs, often as root on the node
/// directory of another user.
const SCANNED: &[&str] = &["quil-client/src", "quil-config/src", "quil-keys/src"];

/// Calls that create, replace or extend a file.
const WRITES: &[&str] = &[
    "rename(",
    "fs::write(",
    "fs::copy(",
    "File::create(",
    "File::options(",
    "OpenOptions::new(",
    ".append(true)",
    ".truncate(true)",
    "set_len(",
];

/// `(source file, function, call, why)` for each write in [`SCANNED`]
/// outside the tests and [`WRITERS`]: none replaces a key or state file.
const OTHER_WRITES: &[(&str, &str, &str, &str)] = &[
    (
        "quil-config/src/private_files.rs",
        "atomic_write",
        "rename(",
        "the atomic replacement itself",
    ),
    (
        "quil-config/src/private_files.rs",
        "write_new_file",
        "OpenOptions::new(",
        "the atomic replacement's new temporary file",
    ),
    (
        "quil-client/src/release_source.rs",
        "write_checked",
        "OpenOptions::new(",
        "the release-source file's new temporary file, at mode 0644 so the node's startup check, run as another user, reads it",
    ),
    (
        "quil-client/src/release_source.rs",
        "write_checked",
        "rename(",
        "the release-source file's atomic replacement",
    ),
    (
        "quil-client/src/release.rs",
        "move_into",
        "rename(",
        "a verified release binary or signature file into its install directory",
    ),
    (
        "quil-client/src/commands/deploy/get.rs",
        "run",
        "fs::write(",
        "a download to the output path the user names",
    ),
    (
        "quil-client/src/commands/node/diagnostics_logs.rs",
        "write_bundle",
        "fs::write(",
        "a fetched bundle into a new staging directory",
    ),
    (
        "quil-client/src/commands/node/diagnostics_logs.rs",
        "write_bundle",
        "rename(",
        "the new bundle directory into a free name",
    ),
    (
        "quil-client/src/commands/node/diagnostics_logs.rs",
        "write_private",
        "OpenOptions::new(",
        "a new request key file, never replaced",
    ),
    (
        "quil-client/src/commands/node/log/export.rs",
        "run",
        "File::create(",
        "a log export into a new staging directory",
    ),
    (
        "quil-client/src/commands/node/log/export.rs",
        "run",
        "fs::write(",
        "a log export into a new staging directory",
    ),
    (
        "quil-client/src/commands/node/log/export.rs",
        "run",
        "rename(",
        "the new export directory into a free name",
    ),
    (
        "quil-client/src/commands/node/lifecycle.rs",
        "lock_node_updates",
        "OpenOptions::new(",
        "a lock file, never written",
    ),
    (
        "quil-client/src/commands/node/nodeconfig.rs",
        "new_private_file",
        "OpenOptions::new(",
        "a new config backup, never replaced",
    ),
    (
        "quil-client/src/commands/node/nodeconfig.rs",
        "copy_dir",
        "fs::copy(",
        "an imported config into a new directory",
    ),
    (
        "quil-client/src/commands/token/action_log.rs",
        "open_append",
        "OpenOptions::new(",
        "appends to the private action log in place, keeping its owner",
    ),
    (
        "quil-client/src/commands/token/action_log.rs",
        "open_append",
        ".append(true)",
        "appends to the private action log in place, keeping its owner",
    ),
    (
        "quil-client/src/release.rs",
        "write_atomic",
        "OpenOptions::new(",
        "a release binary or signature, installed as root",
    ),
    (
        "quil-client/src/release.rs",
        "write_atomic",
        "rename(",
        "a release binary or signature, installed as root",
    ),
    (
        "quil-client/src/release.rs",
        "switch_symlink",
        "rename(",
        "the installed binary's link, repointed as root",
    ),
];

/// Calls that write a file in place, extend it or truncate it.
const IN_PLACE: &[&str] = &[
    "fs::write(",
    "File::create(",
    ".truncate(true)",
    ".append(true)",
    "set_len(0)",
    "fs::rename(",
];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn source(rel: &str) -> String {
    std::fs::read_to_string(crates_dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The body of the one `fn name(` in `text`, braces balanced.
fn body<'a>(text: &'a str, name: &str, rel: &str) -> &'a str {
    let needle = format!("fn {name}(");
    let mut starts = text.match_indices(&needle);
    let (start, _) = starts
        .next()
        .unwrap_or_else(|| panic!("{rel}: no `fn {name}(`"));
    assert!(starts.next().is_none(), "{rel}: more than one `fn {name}(`");
    let open = start + text[start..].find('{').unwrap();
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("{rel}: unbalanced `fn {name}(`")
}

fn in_place_calls(body: &str) -> Vec<&'static str> {
    IN_PLACE
        .iter()
        .copied()
        .filter(|call| body.contains(call))
        .collect()
}

/// `text` with its comments and the contents of its string and character
/// literals blanked, so that only code is read.
fn code_only(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        let to = to.min(out.len());
        for c in &mut out[from.min(to)..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied();
        let raw = b[i] == b'r'
            && matches!(next, Some(b'"' | b'#'))
            && (i == 0 || !ident(b[i - 1]) || (b[i - 1] == b'b' && (i < 2 || !ident(b[i - 2]))));
        if b[i] == b'/' && next == Some(b'/') {
            let end = text[i..].find('\n').map_or(b.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
        } else if b[i] == b'/' && next == Some(b'*') {
            let (mut depth, mut j) = (0usize, i);
            while j < b.len() {
                if b[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if b[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if raw {
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                i += 1;
                continue;
            }
            let close = format!("\"{}", "#".repeat(j - i - 1));
            let end = text[j + 1..].find(&close).map_or(b.len(), |n| j + 1 + n);
            blank(&mut out, j + 1, end);
            i = end + close.len();
        } else if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if b[i] == b'\'' {
            // A character literal, else a lifetime or a label.
            let rest = &text[i + 1..];
            let close = if rest.starts_with('\\') {
                rest.get(2..).and_then(|r| r.find('\'')).map(|n| n + 2)
            } else {
                rest.chars()
                    .next()
                    .map(char::len_utf8)
                    .filter(|&n| rest[n..].starts_with('\''))
            };
            match close {
                Some(n) => {
                    blank(&mut out, i + 1, i + 1 + n);
                    i += n + 2;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("only whole characters are blanked")
}

/// `code` (see [`code_only`]) without the items compiled for tests only.
fn without_tests(code: &str) -> String {
    const TEST_ONLY: &[&str] = &["#[cfg(test)]", "#[cfg(all(test", "#[cfg(any(test"];
    let mut out = String::new();
    let mut rest = code;
    while let Some(at) = TEST_ONLY.iter().filter_map(|a| rest.find(a)).min() {
        out.push_str(&rest[..at]);
        let item = at + rest[at..].find(']').expect("the attribute ends") + 1;
        let open = rest[item..].find('{').map(|n| item + n);
        let semi = rest[item..].find(';').map(|n| item + n);
        let end = match (open, semi) {
            (Some(open), Some(semi)) if semi < open => semi,
            (None, Some(semi)) => semi,
            (Some(open), _) => {
                let mut depth = 0usize;
                let mut end = None;
                for (i, c) in rest[open..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(open + i);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                end.expect("a test item's braces balance")
            }
            (None, None) => rest.len() - 1,
        };
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The name of the last function declared in `code`, or `?`.
fn enclosing_fn(code: &str) -> String {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    for (at, _) in code.rmatch_indices("fn ") {
        if code[..at].chars().next_back().is_some_and(ident) {
            continue;
        }
        let after = code[at + 3..].trim_start();
        let name: String = after.chars().take_while(|&c| ident(c)).collect();
        if !name.is_empty()
            && matches!(
                after[name.len()..].trim_start().chars().next(),
                Some('(' | '<')
            )
        {
            return name;
        }
    }
    "?".into()
}

/// `(function, call)` for each write in `text` outside its tests.
fn writes(text: &str) -> Vec<(String, &'static str)> {
    let code = without_tests(&code_only(text));
    let mut found = Vec::new();
    for call in WRITES {
        for (at, _) in code.match_indices(call) {
            found.push((enclosing_fn(&code[..at]), *call));
        }
    }
    found
}

/// The Rust sources under `dir`, test modules in their own files aside.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            sources(&path, out);
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

#[test]
fn state_files_are_written_atomically() {
    for (rel, name, file) in WRITERS {
        let text = source(rel);
        let body = body(&text, name, rel);
        let found = in_place_calls(body);
        assert!(
            found.is_empty(),
            "{rel} `{name}` writes the {file} in place with {found:?}; use quil_config::atomic_write"
        );
        assert!(
            body.contains("atomic_write(") || body.contains("write_private_file("),
            "{rel} `{name}` no longer writes the {file} through quil_config::atomic_write"
        );
    }
}

/// The CW genesis marker: a torn one reads as none, which wipes the
/// consensus journal at every start.
#[test]
fn the_cw_genesis_marker_is_written_atomically() {
    let rel = "quil-node/src/master_node/archive_sync.rs";
    let text = source(rel);
    let start = text
        .find("let marker_path = {")
        .unwrap_or_else(|| panic!("{rel}: no CW genesis marker"));
    let end = start
        + text[start..]
            .find("let genesis_digest")
            .unwrap_or_else(|| panic!("{rel}: the marker block has no end"));
    let block = &text[start..end];
    let found = in_place_calls(block);
    assert!(
        found.is_empty(),
        "{rel} writes the CW genesis marker in place with {found:?}"
    );
    assert!(
        block.contains("quil_config::atomic_write("),
        "{rel} no longer writes the CW genesis marker atomically"
    );
}

/// The checks see a write in place, and only inside the named function.
#[test]
fn the_check_finds_writes_in_place() {
    let planted = "fn save(path: &Path) { std::fs::write(path, b\"x\").unwrap(); }";
    assert_eq!(
        in_place_calls(body(planted, "save", "planted")),
        vec!["fs::write("]
    );
    let nested = "fn write() { if a { b(); } std::fs::rename(a, b) }\nfn other() { fs::write(x) }";
    assert_eq!(
        in_place_calls(body(nested, "write", "nested")),
        vec!["fs::rename("]
    );
}

/// Each write in the code qclient runs is in a [`WRITERS`] function or in
/// [`OTHER_WRITES`], and each `OTHER_WRITES` entry is still found.
#[test]
fn every_write_is_listed() {
    let crates = crates_dir();
    let mut files = Vec::new();
    for dir in SCANNED {
        sources(&crates.join(dir), &mut files);
    }
    let mut found = BTreeSet::new();
    let mut unlisted = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&crates)
            .unwrap()
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        for (function, call) in writes(&std::fs::read_to_string(&file).unwrap()) {
            let writer = WRITERS.iter().any(|(r, f, _)| *r == rel && *f == function);
            let other = OTHER_WRITES
                .iter()
                .any(|(r, f, c, _)| *r == rel && *f == function && *c == call);
            if !writer && !other {
                unlisted.push(format!("{rel} `{function}` {call}"));
            }
            found.insert((rel.clone(), function, call));
        }
    }
    assert!(
        unlisted.is_empty(),
        "writes no list names: write key and state files through quil_config::atomic_write \
         and add the function to WRITERS, else add the write to OTHER_WRITES with why:\n{}",
        unlisted.join("\n")
    );
    let stale: Vec<_> = OTHER_WRITES
        .iter()
        .filter(|(r, f, c, _)| !found.contains(&(r.to_string(), f.to_string(), *c)))
        .collect();
    assert!(
        stale.is_empty(),
        "OTHER_WRITES entries no longer found: {stale:?}"
    );
}

/// The census reads code only: a write in a comment, a string or a test
/// item is not one, and a write is named by its function.
#[test]
fn the_census_reads_code_only() {
    let planted = r##"
/// Calls `fs::write(` in a doc comment.
fn quiet() -> char {
    let _ = "std::fs::rename(a, b) { in a string";
    let _ = r#"File::create("x")"#;
    let _: &'static str = "";
    '{'
}
fn loud<'a>(path: &'a Path) {
    if true { let _ = '\''; }
    std::fs::rename(path, path).unwrap();
}
#[cfg(test)]
mod tests {
    fn helper() { std::fs::write("x", b"{").unwrap(); }
}
#[cfg(all(test, unix))]
fn unix_helper() { std::fs::File::create("x").unwrap(); }
fn after() { std::fs::OpenOptions::new().append(true); }
"##;
    let mut found = writes(planted);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("after".to_string(), ".append(true)"),
            ("after".to_string(), "OpenOptions::new("),
            ("loud".to_string(), "rename("),
        ]
    );
}
