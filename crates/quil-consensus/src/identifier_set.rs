//! Append-only identifier set. Mirror of
//! `consensus/votecollector/common.go::AppendOnlyIdentifierSet`.
//!
//! Used by the vote/timeout collectors to track which replicas have
//! already contributed, without ever removing entries (append-only
//! semantics simplify concurrency reasoning).

use std::collections::HashSet;
use std::sync::Mutex;

use crate::models::Identity;

/// Append-only set of identities, concurrency-safe.
#[derive(Debug, Default)]
pub struct AppendOnlyIdentifierSet {
    inner: Mutex<HashSet<Identity>>,
}

impl AppendOnlyIdentifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an identifier. Returns `true` if newly added, `false` if
    /// already present.
    pub fn add(&self, id: Identity) -> bool {
        let mut guard = self.inner.lock().unwrap();
        guard.insert(id)
    }

    /// `true` if the id has been added.
    pub fn contains(&self, id: &Identity) -> bool {
        self.inner.lock().unwrap().contains(id)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_returns_true_for_new_entries() {
        let set = AppendOnlyIdentifierSet::new();
        assert!(set.add("alice".into()));
        assert!(set.add("bob".into()));
    }

    #[test]
    fn add_returns_false_for_duplicates() {
        let set = AppendOnlyIdentifierSet::new();
        set.add("alice".into());
        assert!(!set.add("alice".into()));
    }

    #[test]
    fn contains_works() {
        let set = AppendOnlyIdentifierSet::new();
        set.add("alice".into());
        assert!(set.contains(&b"alice".to_vec()));
        assert!(!set.contains(&b"bob".to_vec()));
    }

    #[test]
    fn len_tracks_entries() {
        let set = AppendOnlyIdentifierSet::new();
        assert!(set.is_empty());
        set.add("a".into());
        set.add("b".into());
        set.add("a".into()); // dup
        assert_eq!(set.len(), 2);
    }
}
