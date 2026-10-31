//! In-memory signer registry populated from inbound KeyRegistry
//! broadcasts. Given an Ed448 identity key (peer identity), callers
//! can look up the associated BLS48-581 G2 prover public key — this
//! is required to verify BLS signatures on consensus messages from
//! peers whose identity↔prover binding was announced over the
//! `GLOBAL_PEER_INFO` bitmask.
//!
//! Mirrors the subset of `CachedSignerRegistry` in
//! `node/consensus/registration/cached_signer_registry.go` that the
//! runtime actually queries from consensus/materializer paths.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use quil_types::crypto::BlsConstructor;

use crate::peer_info::CanonicalKeyRegistry;

/// Domain-separation tag for the KeyRegistry identity↔prover cross
/// signatures. Byte-for-byte identical to Go's `keyRegistryDomain`
/// (`node/consensus/global/message_processors.go:36`,
/// `node/consensus/app/message_processors.go:30`):
///
/// ```go
/// var keyRegistryDomain = []byte("KEY_REGISTRY")
/// ```
pub const KEY_REGISTRY_DOMAIN: &[u8] = b"KEY_REGISTRY";

/// Verify the bidirectional identity↔prover cross-signatures carried in a
/// decoded KeyRegistry record. This is the crux of Finding B: without it,
/// any peer can broadcast an arbitrary Ed448→BLS binding and have it
/// silently trusted for consensus BLS-signature verification.
///
/// Replicates Go's `processKeyRegistry` verification exactly
/// (`node/consensus/global/message_processors.go:588-634`,
/// mirrored in `node/consensus/app/message_processors.go:767-808` and
/// `node/explorer/main.go:2943-2985`):
///
/// 1. **identity_to_prover** — the Ed448 *identity* key signs
/// `KEY_REGISTRY ‖ prover_pubkey_bytes`:
/// ```go
/// identityMsg := slices.Concat(keyRegistryDomain, keyRegistry.ProverKey.KeyValue)
/// ValidateSignature(KeyTypeEd448, IdentityKey.KeyValue, identityMsg,
/// IdentityToProver.Signature, nil)
/// ```
/// Ed448 `ValidateSignature` (`node/keys/inmem.go:33-39`) verifies
/// `ed448.Verify(pubkey, concat(domain=nil, msg), sig, "")` — i.e. the
/// domain is already baked into `identityMsg`, ctx empty. Mirrored by
/// [`quil_crypto::ed448_verify`].
///
/// 2. **prover_to_identity** — the BLS48-581 *prover* key signs the
/// Ed448 identity pubkey bytes under the `KEY_REGISTRY` domain:
/// ```go
/// ValidateSignature(KeyTypeBLS48581G1, ProverKey.KeyValue,
/// IdentityKey.KeyValue, ProverToIdentity.Signature,
/// keyRegistryDomain)
/// ```
/// BLS `ValidateSignature` (`node/keys/inmem.go:40-48`) forwards to
/// `VerifySignatureRaw(pubkey, sig, message, domain)`, which hashes
/// `domain ‖ message` — identical to [`bls48581::bls_verify`] used
/// here via [`quil_crypto::FalconKeyConstructor`]. The prover pubkey
/// is the 585-byte G2 key; the signature is the G1 point.
///
/// Both signatures must be present and valid, matching Go's hard
/// rejection of missing/invalid cross-signatures.
fn verify_key_registry_bindings(reg: &CanonicalKeyRegistry) -> bool {
    // Go rejects missing cross-signatures outright.
    if reg.identity_to_prover_sig.is_empty() || reg.prover_to_identity_sig.is_empty() {
        return false;
    }

    // (1) Ed448 identity key signs KEY_REGISTRY || bls_pubkey.
    let mut identity_msg = Vec::with_capacity(KEY_REGISTRY_DOMAIN.len() + reg.bls_pubkey.len());
    identity_msg.extend_from_slice(KEY_REGISTRY_DOMAIN);
    identity_msg.extend_from_slice(&reg.bls_pubkey);
    if !quil_crypto::ed448_verify(
        &reg.ed448_pubkey,
        &identity_msg,
        &reg.identity_to_prover_sig,
    ) {
        return false;
    }

    // (2) Falcon consensus key signs the Ed448 identity pubkey under the
    // KEY_REGISTRY domain (post-BLS cutover).
    let bls = quil_crypto::FalconKeyConstructor;
    if !bls.verify_signature_raw(
        &reg.bls_pubkey,
        &reg.prover_to_identity_sig,
        &reg.ed448_pubkey,
        KEY_REGISTRY_DOMAIN,
    ) {
        return false;
    }

    true
}

/// Hard cap on the bindings of registered provers the registry retains
/// (only a registered prover's binding authorizes anything). Each entry is
/// about 2 KB (57-byte Ed448 key, 897-byte Falcon key, two signatures and
/// indexes), so 65536 entries are about 130 MB at worst; the live signer
/// set is far smaller.
pub const MAX_SIGNER_ENTRIES: usize = 65_536;

/// Hard cap on the bindings of identities that are not registered provers
/// (a prover announcing itself before its join lands). Anyone can create
/// such bindings, so they have their own quota and never evict a
/// registered prover's binding.
pub const MAX_UNREGISTERED_SIGNER_ENTRIES: usize = 4_096;

/// One entry per registered identity.
#[derive(Debug, Clone, Default)]
pub struct SignerEntry {
    pub ed448_pubkey: Vec<u8>,
    pub bls_pubkey: Vec<u8>,
    pub identity_to_prover_sig: Vec<u8>,
    pub prover_to_identity_sig: Vec<u8>,
    pub last_updated_ms: u64,
}

impl SignerEntry {
    /// Whether `reg` carries this entry's binding, signatures included: an
    /// already verified binding, whatever its timestamp.
    fn same_binding(&self, reg: &CanonicalKeyRegistry) -> bool {
        self.bls_pubkey == reg.bls_pubkey
            && self.identity_to_prover_sig == reg.identity_to_prover_sig
            && self.prover_to_identity_sig == reg.prover_to_identity_sig
    }
}

struct Held {
    entry: SignerEntry,
    /// Whether the prover key was a registered prover's when stored.
    registered: bool,
    /// Position in `Inner::order`.
    seq: u64,
}

/// Joint state behind a single `RwLock`. Held together so eviction
/// stays atomic across the indexes; otherwise an evicted entry
/// could linger in one map after disappearing from the other.
#[derive(Default)]
struct Inner {
    by_identity: HashMap<Vec<u8>, Held>,
    /// Reverse index prover pubkey → Ed448 identity. A prover key is bound
    /// to one identity: its newest binding.
    by_prover: HashMap<Vec<u8>, Vec<u8>>,
    /// Index libp2p `PeerId::to_bytes()` → prover (consensus/Falcon) pubkey.
    /// Derived from the Falcon prover pubkey (`peer_id_from_falcon_pubkey`, the
    /// network identity) at insert time. Lets an inbound connection —
    /// authenticated by peer_id from
    /// the PQNoise handshake, which carries no raw Ed448 pubkey — be resolved to
    /// its prover so submit auth can require an ACTIVE prover (Go
    /// `authenticateProverFromContext`).
    by_peer_id: HashMap<Vec<u8>, Vec<u8>>,
    /// Update order of the identities, per tier (`[unregistered,
    /// registered]`): sequence number → identity, least recently updated
    /// first. Evicts within a tier when it is full.
    order: [BTreeMap<u64, Vec<u8>>; 2],
    next_seq: u64,
}

impl Inner {
    /// Whether `identity` holds a binding dated `ms` or later.
    fn holds_since(&self, identity: &[u8], ms: u64) -> bool {
        self.by_identity
            .get(identity)
            .is_some_and(|held| held.entry.last_updated_ms >= ms)
    }

    /// Remove `identity`'s entry from every index.
    fn remove_identity(&mut self, identity: &[u8]) -> Option<SignerEntry> {
        let held = self.by_identity.remove(identity)?;
        self.order[usize::from(held.registered)].remove(&held.seq);
        let prover = &held.entry.bls_pubkey;
        if self.by_prover.get(prover).is_some_and(|id| id == identity) {
            self.by_prover.remove(prover);
        }
        let peer = crate::falcon_identity::peer_id_from_falcon_pubkey(prover);
        if self.by_peer_id.get(&peer) == Some(prover) {
            self.by_peer_id.remove(&peer);
        }
        Some(held.entry)
    }
}

/// Thread-safe in-memory store. Indexes by 57-byte Ed448 pubkey and
/// prover pubkey. `update` is last-write-wins scoped by `last_updated_ms`
/// and capped per tier ([`MAX_SIGNER_ENTRIES`] registered provers,
/// [`MAX_UNREGISTERED_SIGNER_ENTRIES`] others), evicting the least
/// recently updated binding of the tier.
#[derive(Default)]
pub struct SignerRegistry {
    inner: RwLock<Inner>,
}

impl SignerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// [`update_with`](Self::update_with) for a binding that is not a
    /// registered prover's, accepting an unsigned timestamp.
    pub fn update(&self, reg: CanonicalKeyRegistry) -> bool {
        self.update_with(reg, false, |_| false)
    }

    /// Accept a decoded KeyRegistry record. The identity↔prover
    /// cross-signatures are verified at this boundary (Finding B) so an
    /// unverified binding never lands in the registry — a peer cannot
    /// inject an arbitrary Ed448→BLS pairing. A record that repeats a
    /// stored binding with a newer timestamp only refreshes it, without
    /// verifying the cross-signatures again. A timestamp signature, when
    /// present, must verify; `require_signed_timestamp` refuses records
    /// without one. `is_registered` tells whether a prover key is a
    /// registered prover's, which picks the binding's quota.
    ///
    /// Returns `true` if the record was accepted (inserted or updated),
    /// `false` if it was rejected for any reason.
    pub fn update_with(
        &self,
        reg: CanonicalKeyRegistry,
        require_signed_timestamp: bool,
        is_registered: impl FnOnce(&[u8]) -> bool,
    ) -> bool {
        if reg.ed448_pubkey.is_empty() || reg.bls_pubkey.is_empty() {
            return false;
        }
        if reg.timestamp_signature.is_empty() {
            if require_signed_timestamp {
                return false;
            }
        } else if !crate::peer_info::verify_key_registry_timestamp(&reg) {
            return false;
        }
        let known = {
            let inner = self.inner.read().unwrap();
            match inner.by_identity.get(&reg.ed448_pubkey) {
                Some(held) if held.entry.last_updated_ms >= reg.last_updated_ms => return false,
                Some(held) if held.entry.same_binding(&reg) => Some(held.registered),
                _ => None,
            }
        };
        let registered = match known {
            Some(true) => true,
            Some(false) => is_registered(&reg.bls_pubkey),
            None => {
                // Finding B: reject bindings whose cross-signatures don't
                // verify BEFORE they reach the in-memory maps.
                if !verify_key_registry_bindings(&reg) {
                    return false;
                }
                is_registered(&reg.bls_pubkey)
            }
        };
        self.insert_verified_in(reg, registered)
    }

    /// [`insert_verified_in`](Self::insert_verified_in) as a registered
    /// prover's binding.
    #[cfg(test)]
    fn insert_verified(&self, reg: CanonicalKeyRegistry) -> bool {
        self.insert_verified_in(reg, true)
    }

    /// Insert an already-verified KeyRegistry record into the in-memory
    /// indexes. Enforces timestamp-monotonicity (older replays ignored),
    /// one identity per prover key and the tier's capacity. Returns `true`
    /// if the record was stored, `false` if skipped as a stale replay.
    ///
    /// Callers other than tests MUST go through
    /// [`update_with`](Self::update_with), which
    /// gates on cross-signature verification first.
    fn insert_verified_in(&self, reg: CanonicalKeyRegistry, registered: bool) -> bool {
        let mut inner = self.inner.write().unwrap();
        if inner.holds_since(&reg.ed448_pubkey, reg.last_updated_ms) {
            return false;
        }
        // The prover key's holder signed both bindings; the newer stands.
        let other = inner
            .by_prover
            .get(&reg.bls_pubkey)
            .filter(|identity| **identity != reg.ed448_pubkey)
            .cloned();
        if let Some(other) = other {
            if inner.holds_since(&other, reg.last_updated_ms) {
                return false;
            }
            inner.remove_identity(&other);
        }
        // Replacing drops the old prover key's indexes, its peer ID too.
        inner.remove_identity(&reg.ed448_pubkey);
        let tier = usize::from(registered);
        let cap = if registered {
            MAX_SIGNER_ENTRIES
        } else {
            MAX_UNREGISTERED_SIGNER_ENTRIES
        };
        while inner.order[tier].len() >= cap {
            let Some((_, victim)) = inner.order[tier].pop_first() else {
                break;
            };
            inner.remove_identity(&victim);
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.order[tier].insert(seq, reg.ed448_pubkey.clone());
        // peer_id (libp2p multihash of the FALCON prover key — the network
        // identity) → prover pubkey. The Ed448 pubkey remains the KeyRegistry
        // index (`by_identity`) + seniority root, but the live connection
        // identity is the Falcon prover key, so `by_peer_id` keys on it.
        let peer_id = crate::falcon_identity::peer_id_from_falcon_pubkey(&reg.bls_pubkey);
        inner.by_peer_id.insert(peer_id, reg.bls_pubkey.clone());
        inner
            .by_prover
            .insert(reg.bls_pubkey.clone(), reg.ed448_pubkey.clone());
        let entry = SignerEntry {
            ed448_pubkey: reg.ed448_pubkey.clone(),
            bls_pubkey: reg.bls_pubkey,
            identity_to_prover_sig: reg.identity_to_prover_sig,
            prover_to_identity_sig: reg.prover_to_identity_sig,
            last_updated_ms: reg.last_updated_ms,
        };
        inner.by_identity.insert(
            reg.ed448_pubkey,
            Held {
                entry,
                registered,
                seq,
            },
        );
        true
    }

    /// Resolve an inbound connection's libp2p `PeerId::to_bytes()` to the prover
    /// (consensus/Falcon) pubkey it published in its KeyRegistry, or `None` if no
    /// verified binding is known. The submit-auth path hashes this to a prover
    /// address and requires it to be ACTIVE.
    pub fn prover_key_for_peer_id(&self, peer_id: &[u8]) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner.by_peer_id.get(peer_id).cloned()
    }

    /// Look up the BLS G2 pubkey associated with an Ed448 identity.
    pub fn bls_pubkey_for_identity(&self, ed448_pubkey: &[u8]) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner
            .by_identity
            .get(ed448_pubkey)
            .map(|held| held.entry.bls_pubkey.clone())
    }

    /// Look up the Ed448 identity for a given BLS G2 prover pubkey.
    pub fn identity_for_prover(&self, bls_pubkey: &[u8]) -> Option<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        inner.by_prover.get(bls_pubkey).cloned()
    }

    /// Full entry by identity.
    pub fn get_by_identity(&self, ed448_pubkey: &[u8]) -> Option<SignerEntry> {
        let inner = self.inner.read().unwrap();
        inner
            .by_identity
            .get(ed448_pubkey)
            .map(|held| held.entry.clone())
    }

    /// Current entry count (identity-keyed).
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().by_identity.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_and_lookup() {
        let reg = SignerRegistry::new();
        let entry = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0x22; 585],
            identity_to_prover_sig: vec![0x33; 114],
            prover_to_identity_sig: vec![0x44; 74],
            keys_by_purpose: Vec::new(),
            last_updated_ms: 1,
            timestamp_signature: Vec::new(),
        };
        reg.insert_verified(entry);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0x22; 585]);
        let id = reg.identity_for_prover(&[0x22; 585]).unwrap();
        assert_eq!(id, vec![0x11; 57]);
    }

    #[test]
    fn newer_timestamp_wins() {
        let reg = SignerRegistry::new();
        let old = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xAA; 585],
            last_updated_ms: 10,
            ..Default::default()
        };
        let new = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xBB; 585],
            last_updated_ms: 20,
            ..Default::default()
        };
        reg.insert_verified(old);
        reg.insert_verified(new);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0xBB; 585], "newer ts should win");
    }

    #[test]
    fn older_timestamp_ignored() {
        let reg = SignerRegistry::new();
        let new = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xBB; 585],
            last_updated_ms: 20,
            ..Default::default()
        };
        let old = CanonicalKeyRegistry {
            ed448_pubkey: vec![0x11; 57],
            bls_pubkey: vec![0xAA; 585],
            last_updated_ms: 10,
            ..Default::default()
        };
        reg.insert_verified(new);
        reg.insert_verified(old);
        let pk = reg.bls_pubkey_for_identity(&[0x11; 57]).unwrap();
        assert_eq!(pk, vec![0xBB; 585], "older ts replay should be ignored");
    }

    /// Build a unique 57-byte Ed448 pubkey for test purposes.
    fn ed448_key(i: u32) -> Vec<u8> {
        let mut v = vec![0u8; 57];
        v[..4].copy_from_slice(&i.to_be_bytes());
        v
    }

    /// Build a unique 585-byte BLS pubkey for test purposes.
    fn bls_key(i: u32) -> Vec<u8> {
        let mut v = vec![0u8; 585];
        v[..4].copy_from_slice(&i.to_be_bytes());
        v
    }

    #[test]
    fn lru_evicts_oldest_when_at_capacity() {
        // Sanity-cap the test by using a smaller MAX via direct
        // exercise: we push MAX + 5 distinct identities and assert
        // the first 5 are evicted.
        let reg = SignerRegistry::new();
        let total = MAX_SIGNER_ENTRIES + 5;
        for i in 0..total {
            reg.insert_verified(CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(i as u32),
                bls_pubkey: bls_key(i as u32),
                last_updated_ms: 100 + i as u64,
                ..Default::default()
            });
        }
        assert_eq!(reg.len(), MAX_SIGNER_ENTRIES);
        // First 5 identities should be evicted from BOTH indexes.
        for i in 0..5 {
            assert!(
                reg.bls_pubkey_for_identity(&ed448_key(i)).is_none(),
                "expected identity {} evicted from by_identity",
                i,
            );
            assert!(
                reg.identity_for_prover(&bls_key(i)).is_none(),
                "expected bls key {} evicted from by_prover",
                i,
            );
        }
        // Tail entries retained.
        for i in 5..total {
            assert!(
                reg.bls_pubkey_for_identity(&ed448_key(i as u32)).is_some(),
                "expected identity {} retained",
                i,
            );
        }
    }

    #[test]
    fn update_refreshes_order_so_recent_entries_survive() {
        // Insert MAX entries, then update entry 0 (oldest by insertion).
        // It should move to the back of the eviction queue. Then push
        // one more new entry; entry 1 (now the oldest) should evict,
        // entry 0 should survive.
        let reg = SignerRegistry::new();
        for i in 0..MAX_SIGNER_ENTRIES {
            reg.insert_verified(CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(i as u32),
                bls_pubkey: bls_key(i as u32),
                last_updated_ms: 100 + i as u64,
                ..Default::default()
            });
        }
        // Refresh entry 0 with a newer timestamp.
        reg.insert_verified(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(0),
            last_updated_ms: 100 + MAX_SIGNER_ENTRIES as u64 + 1,
            ..Default::default()
        });
        // Add one more new entry to trigger eviction.
        let new_idx = MAX_SIGNER_ENTRIES as u32;
        reg.insert_verified(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(new_idx),
            bls_pubkey: bls_key(new_idx),
            last_updated_ms: 100 + MAX_SIGNER_ENTRIES as u64 + 2,
            ..Default::default()
        });
        assert!(
            reg.bls_pubkey_for_identity(&ed448_key(0)).is_some(),
            "refreshed entry 0 should survive eviction",
        );
        assert!(
            reg.bls_pubkey_for_identity(&ed448_key(1)).is_none(),
            "entry 1 (oldest after refresh) should be evicted",
        );
    }

    #[test]
    fn bls_pubkey_change_drops_stale_reverse_index() {
        // An identity rotating its BLS pubkey should NOT leave the
        // old BLS pubkey pointing at it in `by_prover` — otherwise
        // `identity_for_prover(old_bls)` would return a stale answer.
        let reg = SignerRegistry::new();
        reg.insert_verified(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(0),
            last_updated_ms: 100,
            ..Default::default()
        });
        reg.insert_verified(CanonicalKeyRegistry {
            ed448_pubkey: ed448_key(0),
            bls_pubkey: bls_key(1),
            last_updated_ms: 200,
            ..Default::default()
        });
        assert_eq!(
            reg.identity_for_prover(&bls_key(1)),
            Some(ed448_key(0)),
            "new bls key should resolve to the identity",
        );
        assert_eq!(
            reg.identity_for_prover(&bls_key(0)),
            None,
            "old bls key should no longer resolve",
        );
    }

    // -----------------------------------------------------------------
    // Finding B: cross-signature verification at the ingestion boundary
    // -----------------------------------------------------------------

    /// Build a KeyRegistry record with valid identity↔prover
    /// cross-signatures, mirroring exactly what a well-behaved peer
    /// (and Go) produce. Returns `(reg, ed448_pubkey, bls_pubkey)`.
    fn valid_key_registry(
        seed_byte: u8,
        last_updated_ms: u64,
    ) -> (CanonicalKeyRegistry, Vec<u8>, Vec<u8>) {
        use quil_types::crypto::{BlsConstructor, Signer};

        quil_crypto::init();

        // Ed448 identity keypair.
        let seed = [seed_byte; 57];
        let ed_signer = quil_crypto::Ed448Signer::from_bytes(&seed, &{
            // derive the matching public key
            quil_crypto::Ed448Signer::derive_public(&seed).unwrap()
        })
        .unwrap();
        let ed448_pubkey = ed_signer.public_key().to_vec();

        // BLS48-581 prover keypair.
        let bls = quil_crypto::FalconKeyConstructor;
        let (bls_signer, bls_pubkey) = bls.new_key().unwrap();

        // identity_to_prover: Ed448 signs KEY_REGISTRY || bls_pubkey
        // (domain baked into the message, empty ctx).
        let mut id_msg = KEY_REGISTRY_DOMAIN.to_vec();
        id_msg.extend_from_slice(&bls_pubkey);
        let identity_to_prover_sig = ed_signer.sign(&id_msg).unwrap();

        // prover_to_identity: BLS signs ed448_pubkey under KEY_REGISTRY.
        let prover_to_identity_sig = bls_signer
            .sign_with_domain(&ed448_pubkey, KEY_REGISTRY_DOMAIN)
            .unwrap();

        let reg = CanonicalKeyRegistry {
            ed448_pubkey: ed448_pubkey.clone(),
            bls_pubkey: bls_pubkey.clone(),
            identity_to_prover_sig,
            prover_to_identity_sig,
            keys_by_purpose: Vec::new(),
            last_updated_ms,
            timestamp_signature: Vec::new(),
        };
        (reg, ed448_pubkey, bls_pubkey)
    }

    #[test]
    fn valid_cross_signed_binding_accepted() {
        let reg = SignerRegistry::new();
        let (rec, ed448_pubkey, bls_pubkey) = valid_key_registry(0x07, 1);
        assert!(reg.update(rec), "valid binding must be accepted");
        assert_eq!(
            reg.bls_pubkey_for_identity(&ed448_pubkey),
            Some(bls_pubkey.clone())
        );
        assert_eq!(reg.identity_for_prover(&bls_pubkey), Some(ed448_pubkey));
    }

    #[test]
    fn forged_identity_to_prover_sig_rejected() {
        // Real prover-side sig, garbage identity-side sig: the Ed448
        // check must fail and nothing lands in the registry.
        let reg = SignerRegistry::new();
        let (mut rec, ed448_pubkey, bls_pubkey) = valid_key_registry(0x09, 1);
        rec.identity_to_prover_sig = vec![0xAB; 114]; // forged
        assert!(!reg.update(rec), "forged identity sig must be rejected");
        assert!(reg.bls_pubkey_for_identity(&ed448_pubkey).is_none());
        assert!(reg.identity_for_prover(&bls_pubkey).is_none());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn forged_prover_to_identity_sig_rejected() {
        // Real identity-side sig, garbage prover-side sig: the BLS
        // check must fail.
        let reg = SignerRegistry::new();
        let (mut rec, ed448_pubkey, _bls_pubkey) = valid_key_registry(0x0B, 1);
        rec.prover_to_identity_sig = vec![0xCD; 74]; // forged
        assert!(!reg.update(rec), "forged prover sig must be rejected");
        assert!(reg.bls_pubkey_for_identity(&ed448_pubkey).is_none());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn rebound_prover_key_rejected() {
        // Attacker takes a victim's valid record and swaps in their own
        // BLS prover key, keeping the victim's (now mismatched) sigs.
        // Both cross-signatures must fail to verify against the new key.
        let reg = SignerRegistry::new();
        let (victim, _, _) = valid_key_registry(0x0D, 1);
        let (attacker, _, attacker_bls) = valid_key_registry(0x0E, 1);
        let forged = CanonicalKeyRegistry {
            ed448_pubkey: victim.ed448_pubkey.clone(),
            bls_pubkey: attacker_bls.clone(), // attacker's prover key
            identity_to_prover_sig: victim.identity_to_prover_sig.clone(),
            prover_to_identity_sig: attacker.prover_to_identity_sig.clone(),
            keys_by_purpose: Vec::new(),
            last_updated_ms: 2,
            timestamp_signature: Vec::new(),
        };
        assert!(!reg.update(forged), "rebound prover key must be rejected");
        assert!(reg.identity_for_prover(&attacker_bls).is_none());
    }

    #[test]
    fn missing_cross_signatures_rejected() {
        let reg = SignerRegistry::new();
        let (mut rec, _, _) = valid_key_registry(0x0F, 1);
        rec.identity_to_prover_sig = Vec::new();
        assert!(!reg.update(rec), "missing identity sig must be rejected");
        assert_eq!(reg.len(), 0);
    }

    /// `valid_key_registry` with the prover's signature over its timestamp.
    fn timestamped_key_registry(seed_byte: u8, last_updated_ms: u64) -> CanonicalKeyRegistry {
        use quil_types::crypto::BlsConstructor as _;
        let (mut rec, _, _) = valid_key_registry(seed_byte, last_updated_ms);
        // Re-key the prover: valid_key_registry does not return its signer.
        let (prover, prover_key) = quil_crypto::FalconKeyConstructor.new_key().unwrap();
        let seed = [seed_byte; 57];
        let identity = quil_crypto::Ed448Signer::from_bytes(
            &seed,
            &quil_crypto::Ed448Signer::derive_public(&seed).unwrap(),
        )
        .unwrap();
        use quil_types::crypto::Signer as _;
        let mut id_msg = KEY_REGISTRY_DOMAIN.to_vec();
        id_msg.extend_from_slice(&prover_key);
        rec.identity_to_prover_sig = identity.sign(&id_msg).unwrap();
        rec.prover_to_identity_sig = prover
            .sign_with_domain(&rec.ed448_pubkey, KEY_REGISTRY_DOMAIN)
            .unwrap();
        rec.bls_pubkey = prover_key.clone();
        let message = crate::peer_info::key_registry_timestamp_message(
            &rec.ed448_pubkey,
            &prover_key,
            last_updated_ms,
        );
        rec.timestamp_signature = prover
            .sign_with_domain(&message, crate::peer_info::KEY_REGISTRY_TIMESTAMP_DOMAIN)
            .unwrap();
        rec
    }

    #[test]
    fn a_strict_registry_takes_only_bindings_whose_timestamp_is_signed() {
        let reg = SignerRegistry::new();
        let (legacy, _, _) = valid_key_registry(0x21, 1);
        assert!(!reg.update_with(legacy.clone(), true, |_| true));
        assert!(
            reg.update_with(legacy, false, |_| true),
            "accepted before strict"
        );
        let signed = timestamped_key_registry(0x22, 5);
        assert!(reg.update_with(signed.clone(), true, |_| true));
        // Restamped: the timestamp signature no longer verifies.
        let mut restamped = signed;
        restamped.last_updated_ms = 6;
        assert!(!reg.update_with(restamped.clone(), false, |_| true));
        assert!(!reg.update_with(restamped, true, |_| true));
    }

    #[test]
    fn a_repeated_binding_is_refreshed_and_a_forged_variant_is_not() {
        let reg = SignerRegistry::new();
        let (rec, ed448_pubkey, _) = valid_key_registry(0x23, 1);
        assert!(reg.update(rec.clone()));
        // Only an already verified binding can skip verification: a forged
        // signature in an otherwise identical record is not the same binding.
        let mut forged = rec.clone();
        forged.identity_to_prover_sig = vec![0xAB; 114];
        forged.last_updated_ms = 2;
        assert!(!reg.update(forged));
        let mut repeated = rec;
        repeated.last_updated_ms = 3;
        assert!(reg.update(repeated));
        assert_eq!(
            reg.get_by_identity(&ed448_pubkey).unwrap().last_updated_ms,
            3
        );
    }

    #[test]
    fn rebinding_an_identity_drops_its_old_peer_id() {
        let reg = SignerRegistry::new();
        let (first, _, first_key) = valid_key_registry(0x24, 1);
        let (second, _, second_key) = valid_key_registry(0x24, 2);
        assert!(reg.update(first));
        assert!(reg.update(second));
        let old_peer = crate::falcon_identity::peer_id_from_falcon_pubkey(&first_key);
        let new_peer = crate::falcon_identity::peer_id_from_falcon_pubkey(&second_key);
        assert_eq!(reg.prover_key_for_peer_id(&old_peer), None);
        assert_eq!(reg.prover_key_for_peer_id(&new_peer), Some(second_key));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn a_prover_key_keeps_one_identity() {
        let reg = SignerRegistry::new();
        for i in 0..10u32 {
            reg.insert_verified(CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(i),
                bls_pubkey: bls_key(0),
                last_updated_ms: 100 + i as u64,
                ..Default::default()
            });
        }
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.identity_for_prover(&bls_key(0)), Some(ed448_key(9)));
    }

    #[test]
    fn unregistered_bindings_cannot_evict_registered_ones() {
        let reg = SignerRegistry::new();
        reg.insert_verified_in(
            CanonicalKeyRegistry {
                ed448_pubkey: ed448_key(0),
                bls_pubkey: bls_key(0),
                last_updated_ms: 1,
                ..Default::default()
            },
            true,
        );
        let total = MAX_UNREGISTERED_SIGNER_ENTRIES as u32 + 10;
        for i in 1..=total {
            reg.insert_verified_in(
                CanonicalKeyRegistry {
                    ed448_pubkey: ed448_key(i),
                    bls_pubkey: bls_key(i),
                    last_updated_ms: 100 + i as u64,
                    ..Default::default()
                },
                false,
            );
        }
        assert_eq!(reg.len(), MAX_UNREGISTERED_SIGNER_ENTRIES + 1);
        assert_eq!(reg.bls_pubkey_for_identity(&ed448_key(0)), Some(bls_key(0)));
        let first_peer = crate::falcon_identity::peer_id_from_falcon_pubkey(&bls_key(1));
        assert_eq!(reg.prover_key_for_peer_id(&first_peer), None, "evicted");
        assert!(reg.identity_for_prover(&bls_key(total)).is_some());
    }
}
