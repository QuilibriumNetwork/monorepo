//! Files whose loss or a torn copy costs keys or consensus state are
//! written only through `quil_config::atomic_write` (directly or via
//! `write_private_file`), never by a call that truncates or writes the
//! file in place. Each entry names the function writing one such file; a
//! write added to it in place fails here.

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
];

/// Calls that write a file in place or truncate it.
const IN_PLACE: &[&str] = &[
    "fs::write(",
    "File::create(",
    ".truncate(true)",
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
