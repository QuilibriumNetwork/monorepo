//! Network-partition schedule types for the devnet harness.
//!
//! A [`ViewPartitionEntry`] describes a bipartite split of the node set to apply
//! when a specific simplex consensus view is observed. This module parses a
//! schedule from JSON into per-view entries.
//!
//! The schedule is a point trigger with an implicit heal: an entry applies when
//! its view is observed, and the first observed view with no entry clears all
//! partitions. To hold a partition across several views, repeat the same entry
//! at consecutive views.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A partition configuration to apply when a specific simplex view is observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewPartitionEntry {
    pub view: u64,
    pub partition1: Vec<String>,
    pub partition2: Vec<String>,
}

/// Parses a JSON-encoded list of [`ViewPartitionEntry`] values and returns a
/// lookup map keyed by view number. Rejects duplicate view numbers and requires
/// all fields (`view`, `partition1`, `partition2`) to be present in each entry.
pub fn parse_view_partitions(raw: &str) -> anyhow::Result<BTreeMap<u64, ViewPartitionEntry>> {
    // Decode to generic values first so we can enforce that every required field
    // is present (serde would otherwise happily default missing arrays).
    let raw_entries: Vec<serde_json::Value> =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;

    let mut m = BTreeMap::new();
    for (i, raw_entry) in raw_entries.iter().enumerate() {
        let obj = raw_entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("entry {i}: expected a JSON object"))?;
        for required in ["view", "partition1", "partition2"] {
            if !obj.contains_key(required) {
                anyhow::bail!("entry {i}: missing required field {required:?}");
            }
        }
        let e: ViewPartitionEntry = serde_json::from_value(raw_entry.clone())
            .map_err(|err| anyhow::anyhow!("entry {i}: {err}"))?;
        if m.contains_key(&e.view) {
            anyhow::bail!("duplicate view number {}", e.view);
        }
        m.insert(e.view, e);
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_view_partitions_basic() {
        let raw = r#"[{"view":5,"partition1":["archive-1"],"partition2":["archive-3"]}]"#;
        let m = parse_view_partitions(raw).unwrap();
        assert_eq!(m.len(), 1);
        let e = &m[&5];
        assert_eq!(e.partition1, s(&["archive-1"]));
        assert_eq!(e.partition2, s(&["archive-3"]));
    }

    /// Repeating an entry across consecutive views is the documented way to hold
    /// a partition open, so a multi-view schedule must parse in view order.
    #[test]
    fn parse_view_partitions_holds_across_views() {
        let raw = r#"[
            {"view":4,"partition1":["A"],"partition2":["B"]},
            {"view":3,"partition1":["A"],"partition2":["B"]},
            {"view":5,"partition1":["A"],"partition2":["B"]}
        ]"#;
        let m = parse_view_partitions(raw).unwrap();
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![3, 4, 5]);
    }

    #[test]
    fn parse_view_partitions_missing_field() {
        let raw = r#"[{"view":5,"partition1":["archive-1"]}]"#;
        let err = parse_view_partitions(raw).unwrap_err().to_string();
        assert!(err.contains("partition2"), "unexpected error: {err}");
    }

    #[test]
    fn parse_view_partitions_duplicate_view() {
        let raw = r#"[
            {"view":1,"partition1":["A"],"partition2":["B"]},
            {"view":1,"partition1":["A"],"partition2":["B"]}
        ]"#;
        let err = parse_view_partitions(raw).unwrap_err().to_string();
        assert!(err.contains("duplicate view"), "unexpected error: {err}");
    }
}
