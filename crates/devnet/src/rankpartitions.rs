//! Network-partition schedule types for the devnet harness.
//!
//! A [`RankPartitionEntry`] describes a bipartite split of the node set to apply
//! when a specific consensus rank is observed over gossip. This module parses a
//! schedule from JSON into per-rank entries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A partition configuration to apply when a specific rank number is observed
/// over gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankPartitionEntry {
    pub rank: u64,
    pub partition1: Vec<String>,
    pub partition2: Vec<String>,
}

/// Parses a JSON-encoded list of [`RankPartitionEntry`] values and returns a
/// lookup map keyed by rank number. Rejects duplicate rank numbers and requires
/// all fields (`rank`, `partition1`, `partition2`) to be present in each entry.
pub fn parse_rank_partitions(raw: &str) -> anyhow::Result<BTreeMap<u64, RankPartitionEntry>> {
    // Decode to generic values first so we can enforce that every required field
    // is present (serde would otherwise happily default missing arrays).
    let raw_entries: Vec<serde_json::Value> =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;

    let mut m = BTreeMap::new();
    for (i, raw_entry) in raw_entries.iter().enumerate() {
        let obj = raw_entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("entry {i}: expected a JSON object"))?;
        for required in ["rank", "partition1", "partition2"] {
            if !obj.contains_key(required) {
                anyhow::bail!("entry {i}: missing required field {required:?}");
            }
        }
        let e: RankPartitionEntry = serde_json::from_value(raw_entry.clone())
            .map_err(|err| anyhow::anyhow!("entry {i}: {err}"))?;
        if m.contains_key(&e.rank) {
            anyhow::bail!("duplicate rank number {}", e.rank);
        }
        m.insert(e.rank, e);
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
    fn parse_rank_partitions_basic() {
        let raw = r#"[{"rank":5,"partition1":["archive-1"],"partition2":["archive-3"]}]"#;
        let m = parse_rank_partitions(raw).unwrap();
        assert_eq!(m.len(), 1);
        let e = &m[&5];
        assert_eq!(e.partition1, s(&["archive-1"]));
        assert_eq!(e.partition2, s(&["archive-3"]));
    }

    #[test]
    fn parse_rank_partitions_missing_field() {
        let raw = r#"[{"rank":5,"partition1":["archive-1"]}]"#;
        let err = parse_rank_partitions(raw).unwrap_err().to_string();
        assert!(err.contains("partition2"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rank_partitions_duplicate_rank() {
        let raw = r#"[
            {"rank":1,"partition1":["A"],"partition2":["B"]},
            {"rank":1,"partition1":["A"],"partition2":["B"]}
        ]"#;
        let err = parse_rank_partitions(raw).unwrap_err().to_string();
        assert!(err.contains("duplicate rank"), "unexpected error: {err}");
    }
}
