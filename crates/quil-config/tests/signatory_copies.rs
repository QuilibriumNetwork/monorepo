//! The release signatories have copies outside [`SIGNATORIES`]: the list
//! `install-qclient.sh` verifies with, and the public keys signers verify
//! with (`signers/pems/<i>.pem`, up to the Taskfile's `MAX_KEY_ID`). Each
//! copy must hold the same keys in the same order, since the i-th key
//! verifies `.dgst.sig.<i>`: a copy that drifts rejects releases the others
//! accept, or checks a signature against another signer's key.

use quil_config::SIGNATORIES;
use std::path::{Path, PathBuf};

fn repo_file(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> String {
    let path = repo_file(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The value of `NAME="..."` in a shell script.
fn shell_string(script: &str, name: &str) -> String {
    let prefix = format!("{name}=\"");
    let line = script
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {name}=\"...\" line"));
    line.strip_suffix('"')
        .unwrap_or_else(|| panic!("{name} is not one quoted string"))
        .to_string()
}

/// The words of the shell array `NAME=( ... )`.
fn shell_array(script: &str, name: &str) -> Vec<String> {
    let open = format!("{name}=(");
    let mut lines = script.lines().skip_while(|l| l.trim() != open);
    assert!(lines.next().is_some(), "no {open} line");
    let mut words = Vec::new();
    for line in lines {
        let line = line.trim();
        if line == ")" {
            return words;
        }
        words.extend(line.split_whitespace().map(str::to_string));
    }
    panic!("{open} is never closed");
}

/// Standard base64 with padding, as PEM bodies carry it.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|&c| c != b'=') {
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("{:?} is not base64", c as char));
        acc = (acc << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// The DER body of a PEM public key file, hex encoded.
fn pem_public_key_hex(pem: &str) -> String {
    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    assert_eq!(lines.next(), Some("-----BEGIN PUBLIC KEY-----"));
    let body: String = lines
        .take_while(|l| *l != "-----END PUBLIC KEY-----")
        .collect();
    hex::encode(base64_decode(&body))
}

#[test]
fn install_script_lists_the_signatories_in_order() {
    let script = read("install-qclient.sh");
    assert_eq!(
        shell_array(&script, "SIGNATORIES"),
        SIGNATORIES,
        "install-qclient.sh lists other signatories"
    );
}

#[test]
fn signer_pems_hold_the_signatories_by_index() {
    // Each file is the Ed448 SubjectPublicKeyInfo the script builds from a
    // listed key: its DER prefix, then the key.
    let spki_prefix = shell_string(&read("install-qclient.sh"), "ED448_SPKI_PREFIX");
    for (i, key) in SIGNATORIES.iter().enumerate() {
        let rel = format!("signers/pems/{}.pem", i + 1);
        assert_eq!(
            pem_public_key_hex(&read(&rel)),
            format!("{spki_prefix}{key}"),
            "{rel} is not signatory {}",
            i + 1
        );
    }
    let pems = std::fs::read_dir(repo_file("signers/pems"))
        .expect("read signers/pems")
        .filter(|e| {
            e.as_ref()
                .is_ok_and(|e| e.path().extension().is_some_and(|x| x == "pem"))
        })
        .count();
    assert_eq!(pems, SIGNATORIES.len(), "signers/pems holds other keys");
}

#[test]
fn signer_tasks_check_every_signatory() {
    let taskfile = read("signers/Taskfile.yaml");
    let max_key_id = taskfile
        .lines()
        .find_map(|l| l.trim().strip_prefix("MAX_KEY_ID:"))
        .expect("no MAX_KEY_ID in signers/Taskfile.yaml");
    assert_eq!(
        max_key_id.trim().parse::<usize>(),
        Ok(SIGNATORIES.len()),
        "signers/Taskfile.yaml MAX_KEY_ID skips signatories"
    );
}
