//! GLOBAL finalizations this node learned without holding the frame's body.
//!
//! Consensus can finalize a GLOBAL frame here from its certificate alone,
//! before the frame's body arrives. The finalizer then has nothing to queue
//! for publication, so nothing told a proposal or vote that its parent was
//! finalized: an archive executed the parent privately, without the
//! application frames its publication ingests, declared a prover root the
//! published execution did not reproduce, and the other archives refused the
//! proposal until the next view (about 1.5 an hour on one archive,
//! 2026-10-31).
//!
//! [`UnheldFinalizations`] remembers such finalizations until their frame
//! publishes. A proposal or vote whose parent descends from one first hands a
//! body that has arrived since to the finalizer, and otherwise waits for it or
//! for the publication, at most [`UNHELD_PATIENCE`] after the finalization.
//! Then it proceeds as before: a body that never arrives costs that delay
//! once, never a refusal.

use quil_cw_consensus::adapters::Digest;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Longest a proposal or vote waits, after a finalization this node holds
/// only the certificate of, for the frame's body or its publication. A view's
/// proposal retries for 20 s and a vote defers for 20 s; executing and proving
/// the parent takes most of the rest.
pub(crate) const UNHELD_PATIENCE: Duration = Duration::from_secs(10);

/// Finalizations remembered at most. Each is either published within a few
/// views or past its patience; the oldest goes first.
const UNHELD_KEPT: usize = 16;

struct Entry {
    digest: Digest,
    cert: Option<Vec<u8>>,
    since: Instant,
    /// Hash of the last body the finalizer refused for it, so a refused body
    /// is not handed over again on every retry.
    refused: Option<u64>,
    /// A proposal or vote waited for it: its end is logged.
    waited: bool,
    /// Its patience ran out: logged once.
    overran: bool,
}

/// A finalization whose body has arrived, to hand to the finalizer.
pub(crate) struct Arrived {
    pub view: u64,
    pub digest: Digest,
    pub cert: Option<Vec<u8>>,
}

/// What a proposal or vote does about the finalizations below its parent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// None is pending below the parent, or each is past its patience.
    Proceed,
    /// Wait for the finalization at `view`, finalized `since` ago; `began`
    /// on the first wait for it.
    Wait {
        view: u64,
        since: Duration,
        began: bool,
    },
}

/// A finalization no longer pending, with how long after it was learned it
/// ended, if a proposal or vote waited for it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ended {
    pub view: u64,
    pub waited: Option<Duration>,
    pub overran: bool,
}

/// See the module docs.
#[derive(Default)]
pub(crate) struct UnheldFinalizations {
    entries: BTreeMap<u64, Entry>,
}

impl UnheldFinalizations {
    /// Consensus finalized `digest` at `view` without its body here.
    pub(crate) fn note(&mut self, view: u64, digest: Digest, cert: Option<Vec<u8>>, now: Instant) {
        self.entries.entry(view).or_insert(Entry {
            digest,
            cert,
            since: now,
            refused: None,
            waited: false,
            overran: false,
        });
        while self.entries.len() > UNHELD_KEPT {
            self.entries.pop_first();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The published GLOBAL head has rank `rank`: every finalization at or
    /// below it is published, since the finalized chain is linear.
    pub(crate) fn published_through(&mut self, rank: u64, now: Instant) -> Vec<Ended> {
        let kept = self.entries.split_off(&rank.saturating_add(1));
        let published = std::mem::replace(&mut self.entries, kept);
        published
            .into_iter()
            .map(|(view, entry)| Self::ended(view, entry, now))
            .collect()
    }

    fn ended(view: u64, entry: Entry, now: Instant) -> Ended {
        Ended {
            view,
            waited: entry
                .waited
                .then(|| now.saturating_duration_since(entry.since)),
            overran: entry.overran,
        }
    }

    /// The finalizations below `parent_view` whose body `body` now returns,
    /// except a body the finalizer already refused, with each body. A parent
    /// descends from each finalization at or below its view: consensus
    /// extends every finalized block.
    pub(crate) fn arrived(
        &self,
        parent_view: u64,
        body: impl Fn(&Digest) -> Option<Vec<u8>>,
    ) -> Vec<(Arrived, Vec<u8>)> {
        self.entries
            .range(..=parent_view)
            .filter_map(|(view, entry)| {
                let bytes = body(&entry.digest)?;
                (entry.refused != Some(hash(&bytes))).then(|| {
                    (
                        Arrived {
                            view: *view,
                            digest: entry.digest,
                            cert: entry.cert.clone(),
                        },
                        bytes,
                    )
                })
            })
            .collect()
    }

    /// The finalizer took the body of the finalization at `view`.
    pub(crate) fn taken(&mut self, view: u64, now: Instant) -> Option<Ended> {
        let entry = self.entries.remove(&view)?;
        Some(Self::ended(view, entry, now))
    }

    /// The finalizer refused `bytes` as the body of the finalization at `view`.
    pub(crate) fn refused(&mut self, view: u64, bytes: &[u8]) {
        if let Some(entry) = self.entries.get_mut(&view) {
            entry.refused = Some(hash(bytes));
        }
    }

    /// Whether a proposal or vote on a parent at `parent_view` waits, and the
    /// finalizations whose patience ran out just now (each reported once).
    pub(crate) fn decide(
        &mut self,
        parent_view: u64,
        patience: Duration,
        now: Instant,
    ) -> (Decision, Vec<(u64, Duration)>) {
        let mut overran = Vec::new();
        let mut decision = Decision::Proceed;
        for (view, entry) in self.entries.range_mut(..=parent_view) {
            let since = now.saturating_duration_since(entry.since);
            if since < patience {
                if decision == Decision::Proceed {
                    decision = Decision::Wait {
                        view: *view,
                        since,
                        began: !entry.waited,
                    };
                    entry.waited = true;
                }
            } else if !entry.overran {
                entry.overran = true;
                entry.waited = true;
                overran.push((*view, since));
            }
        }
        (decision, overran)
    }
}

fn hash(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_cw_consensus::adapters::digest_from_identity;

    fn digest(n: u8) -> Digest {
        digest_from_identity([n; 32])
    }

    /// A parent waits only for the finalizations it descends from, within
    /// their patience, and each that runs out of patience is reported once;
    /// then the parent proceeds.
    #[test]
    fn a_parent_waits_for_the_finalizations_below_it_until_their_patience_runs_out() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let patience = Duration::from_millis(100);
        let mut unheld = UnheldFinalizations::default();
        unheld.note(10, digest(1), None, at(0));
        assert_eq!(
            unheld.decide(9, patience, at(1)),
            (Decision::Proceed, vec![]),
            "a parent below the finalization does not descend from it"
        );
        assert_eq!(
            unheld.decide(10, patience, at(1)),
            (
                Decision::Wait {
                    view: 10,
                    since: Duration::from_millis(1),
                    began: true
                },
                vec![]
            )
        );
        assert_eq!(
            unheld.decide(12, patience, at(50)),
            (
                Decision::Wait {
                    view: 10,
                    since: Duration::from_millis(50),
                    began: false
                },
                vec![]
            ),
            "a descendant waits too, and the start is reported once"
        );
        assert_eq!(
            unheld.decide(12, patience, at(100)),
            (Decision::Proceed, vec![(10, Duration::from_millis(100))]),
            "at its patience the parent proceeds, reported once"
        );
        assert_eq!(
            unheld.decide(12, patience, at(150)),
            (Decision::Proceed, vec![])
        );
        // A later finalization has its own patience.
        unheld.note(13, digest(2), None, at(150));
        assert!(matches!(
            unheld.decide(13, patience, at(160)),
            (Decision::Wait { view: 13, .. }, ref overran) if overran.is_empty()
        ));
    }

    /// Publication ends every finalization at or below the published rank,
    /// with how long after it was learned, if anything waited for it.
    #[test]
    fn publication_ends_the_finalizations_at_or_below_it() {
        let start = Instant::now();
        let at = |ms: u64| start + Duration::from_millis(ms);
        let mut unheld = UnheldFinalizations::default();
        unheld.note(10, digest(1), None, at(0));
        unheld.note(11, digest(2), None, at(0));
        unheld.note(14, digest(3), None, at(0));
        let _ = unheld.decide(10, Duration::from_secs(1), at(5));
        assert_eq!(
            unheld.published_through(11, at(30)),
            vec![
                Ended {
                    view: 10,
                    waited: Some(Duration::from_millis(30)),
                    overran: false
                },
                Ended {
                    view: 11,
                    waited: None,
                    overran: false
                },
            ]
        );
        assert!(!unheld.is_empty());
        assert_eq!(
            unheld.published_through(14, at(40)).len(),
            1,
            "the rank itself is published"
        );
        assert!(unheld.is_empty());
    }

    /// A body is offered once per distinct body: one the finalizer refused is
    /// not handed over again, another body at the digest is.
    #[test]
    fn a_refused_body_is_not_handed_over_again() {
        let mut unheld = UnheldFinalizations::default();
        unheld.note(10, digest(1), Some(vec![7]), Instant::now());
        let held = std::cell::RefCell::new(None::<Vec<u8>>);
        let body = |_: &Digest| held.borrow().clone();
        assert!(unheld.arrived(10, body).is_empty(), "no body yet");
        *held.borrow_mut() = Some(vec![1, 2, 3]);
        assert!(unheld.arrived(9, body).is_empty(), "not below this parent");
        let arrived = unheld.arrived(10, body);
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].0.view, 10);
        assert_eq!(arrived[0].0.cert, Some(vec![7]));
        unheld.refused(10, &arrived[0].1);
        assert!(unheld.arrived(10, body).is_empty(), "refused once");
        *held.borrow_mut() = Some(vec![4, 5, 6]);
        assert_eq!(unheld.arrived(10, body).len(), 1, "another body is offered");
        assert_eq!(
            unheld.taken(10, Instant::now()).map(|ended| ended.view),
            Some(10)
        );
        assert!(unheld.arrived(10, body).is_empty());
    }

    /// At most [`UNHELD_KEPT`] finalizations are remembered; the oldest goes.
    #[test]
    fn at_most_the_newest_finalizations_are_kept() {
        let now = Instant::now();
        let mut unheld = UnheldFinalizations::default();
        for view in 0..(UNHELD_KEPT as u64 + 4) {
            unheld.note(view, digest(view as u8), None, now);
        }
        assert_eq!(unheld.entries.len(), UNHELD_KEPT);
        assert_eq!(unheld.entries.first_key_value().map(|(v, _)| *v), Some(4));
    }
}
