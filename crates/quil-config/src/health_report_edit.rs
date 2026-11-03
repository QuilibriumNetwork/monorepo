//! Setting `diagnostics.healthReport` in an operator's config, for `qclient
//! node diagnostics allow|revoke`.
//!
//! A line editor like [`crate::clean_retired_keys`]: every line outside
//! that block stays as written, including comments and the key order; a
//! comment inside the block goes with it. The result is verified by parsing
//! it again: it must load, hold the new block and keep every other value.
//! YAML the editor cannot change safely is refused.

use serde_yaml::{Mapping, Value};

use crate::clean::{block_end, has_node_property, scan, split_lines};
use crate::{CleanError, Config, HealthReportConfig};

const PARENT: &str = "diagnostics";
const KEY: &str = "healthReport";

/// `contents` with `diagnostics.healthReport` set to `report`.
pub fn with_health_report(
    contents: &str,
    report: &HealthReportConfig,
) -> Result<String, CleanError> {
    let path = format!("{PARENT}.{KEY}");
    serde_yaml::from_str::<Config>(contents).map_err(|e| CleanError::Parse(e.to_string()))?;
    let refuse = |reason: &str| CleanError::Unsafe {
        key: path.clone(),
        reason: reason.to_string(),
    };
    let lines = split_lines(contents);
    let scan = scan(&lines);
    let find = |wanted: &str| scan.keys.iter().find(|key| key.path == wanted);
    let block = |indent: usize| {
        let body = serde_yaml::to_string(report).map_err(|e| refuse(&e.to_string()))?;
        let mut text = format!("{:indent$}{KEY}:\n", "");
        for line in body.lines() {
            text += &format!("{:indent$}  {line}\n", "");
        }
        Ok::<String, CleanError>(text)
    };
    let mut edited = String::with_capacity(contents.len() + 256);
    let whole = |edited: &mut String, range: std::ops::Range<usize>| {
        for line in &lines[range] {
            edited.push_str(line.text);
            edited.push_str(line.eol);
        }
    };
    if let Some(key) = find(&path) {
        if has_node_property(&lines[key.line].text[key.value_offset..]) {
            return Err(refuse("it uses an anchor, alias or tag"));
        }
        let last = block_end(&lines, &scan, key.line, key.indent);
        whole(&mut edited, 0..key.line);
        edited += &block(key.indent)?;
        whole(&mut edited, last + 1..lines.len());
    } else if let Some(parent) = find(PARENT) {
        let value = lines[parent.line].text[parent.value_offset..].trim();
        if !(value.is_empty() || value.starts_with('#')) {
            return Err(refuse("diagnostics is not a block mapping"));
        }
        let child_indent = scan
            .keys
            .iter()
            .find(|key| key.path.starts_with("diagnostics."))
            .map_or(parent.indent + 2, |key| key.indent);
        whole(&mut edited, 0..parent.line + 1);
        if !edited.ends_with('\n') {
            edited.push('\n');
        }
        edited += &block(child_indent)?;
        whole(&mut edited, parent.line + 1..lines.len());
    } else {
        edited.push_str(contents);
        if !edited.is_empty() && !edited.ends_with('\n') {
            edited.push('\n');
        }
        edited += &format!("{PARENT}:\n");
        edited += &block(2)?;
    }
    verify_health_report(contents, &edited, report)?;
    Ok(edited)
}

/// `edited` must load, hold `report` and differ from `original` in nothing
/// else.
fn verify_health_report(
    original: &str,
    edited: &str,
    report: &HealthReportConfig,
) -> Result<(), CleanError> {
    let fail = |reason: String| CleanError::Verification(reason);
    let config: Config =
        serde_yaml::from_str(edited).map_err(|e| fail(format!("it no longer loads: {e}")))?;
    if config.diagnostics.health_report != *report {
        return Err(fail("the health report settings differ".to_string()));
    }
    let mut expected: Value = serde_yaml::from_str(original).map_err(|e| fail(e.to_string()))?;
    let wanted = serde_yaml::to_value(report).map_err(|e| fail(e.to_string()))?;
    let root = expected
        .as_mapping_mut()
        .ok_or_else(|| fail("the config is not a mapping".to_string()))?;
    if root.get(PARENT).is_none_or(Value::is_null) {
        root.insert(Value::from(PARENT), Value::Mapping(Mapping::new()));
    }
    root.get_mut(PARENT)
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| fail("diagnostics is not a mapping".to_string()))?
        .insert(Value::from(KEY), wanted);
    let actual: Value = serde_yaml::from_str(edited).map_err(|e| fail(e.to_string()))?;
    if expected != actual {
        return Err(fail("another setting changed".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> HealthReportConfig {
        let mut report = HealthReportConfig {
            enabled: true,
            allowed_peers: vec!["QmPeer".to_string()],
            ..Default::default()
        };
        report
            .allowed_until
            .insert("QmPeer".to_string(), 1_800_000_000);
        report
    }

    const BLOCK: &str = "healthReport:\n    enabled: true\n    allowedPeers:\n    - QmPeer\n    allowedUntil:\n      QmPeer: 1800000000\n    minIntervalSecs: 60\n";

    #[test]
    fn the_block_is_replaced_and_every_other_line_stays_as_written() {
        let original = "# my node\np2p:\n  network: 1  # testnet\n\ndiagnostics:\n  # opt-in\n  healthReport:\n    enabled: false\n    allowedPeers: []\n  # logs\n  logRequests:\n    enabled: true\nengine:\n  dataWorkerCount: 3\n";
        let edited = with_health_report(original, &report()).unwrap();
        assert_eq!(
            edited,
            format!(
                "# my node\np2p:\n  network: 1  # testnet\n\ndiagnostics:\n  # opt-in\n  {BLOCK}  # logs\n  logRequests:\n    enabled: true\nengine:\n  dataWorkerCount: 3\n"
            )
        );
    }

    #[test]
    fn a_config_without_the_block_gains_it() {
        // Under an existing diagnostics section, at its children's indent.
        let edited = with_health_report(
            "diagnostics:\n    logRequests:\n        enabled: true\np2p:\n  network: 1\n",
            &report(),
        )
        .unwrap();
        assert!(
            edited.starts_with("diagnostics:\n    healthReport:\n      enabled: true\n"),
            "{edited}"
        );
        assert!(
            edited.contains("    logRequests:\n        enabled: true\n"),
            "{edited}"
        );
        // No section at all, and no newline at the end of the file.
        let edited = with_health_report("p2p:\n  network: 1", &report()).unwrap();
        assert_eq!(
            edited,
            format!("p2p:\n  network: 1\ndiagnostics:\n  {BLOCK}")
        );
        // An empty section.
        let edited = with_health_report("diagnostics:\np2p:\n  network: 1\n", &report()).unwrap();
        assert_eq!(
            edited,
            format!("diagnostics:\n  {BLOCK}p2p:\n  network: 1\n")
        );
    }

    #[test]
    fn a_second_edit_changes_only_the_block_again() {
        let once = with_health_report("p2p:\n  network: 1\n", &report()).unwrap();
        let none = HealthReportConfig {
            enabled: true,
            ..Default::default()
        };
        let twice = with_health_report(&once, &none).unwrap();
        assert_eq!(
            twice,
            "p2p:\n  network: 1\ndiagnostics:\n  healthReport:\n    enabled: true\n    allowedPeers: []\n    minIntervalSecs: 60\n"
        );
        assert_eq!(with_health_report(&twice, &report()).unwrap(), once);
    }

    #[test]
    fn yaml_it_cannot_change_safely_is_refused() {
        for original in [
            "diagnostics: {logRequests: {enabled: true}}\n",
            "diagnostics:\n  healthReport: &report\n    enabled: false\n",
            "diagnostics: null\n",
        ] {
            assert!(
                matches!(
                    with_health_report(original, &report()),
                    Err(CleanError::Unsafe { .. })
                ),
                "{original}"
            );
        }
        assert!(matches!(
            with_health_report("p2p: [", &report()),
            Err(CleanError::Parse(_))
        ));
        // The block holds an anchor another key's alias needs.
        let anchored = "diagnostics:\n  healthReport:\n    allowedPeers: &peers [QmPeer]\n  logRequests:\n    allowedPeers: *peers\n";
        assert!(matches!(
            with_health_report(anchored, &report()),
            Err(CleanError::Verification(_))
        ));
    }

    #[test]
    fn verification_sees_another_setting_change() {
        let original = "p2p:\n  network: 1\n";
        let edited = with_health_report(original, &report()).unwrap();
        verify_health_report(original, &edited, &report()).unwrap();
        for (other, reason) in [
            (
                edited.replace("network: 1", "network: 2"),
                "another setting",
            ),
            (edited.replace("1800000000", "1800000001"), "health report"),
            ("p2p: [".to_string(), "no longer loads"),
        ] {
            let error = verify_health_report(original, &other, &report())
                .unwrap_err()
                .to_string();
            assert!(error.contains(reason), "{error}");
        }
    }
}
