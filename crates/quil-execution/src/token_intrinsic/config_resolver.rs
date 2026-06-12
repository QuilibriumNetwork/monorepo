//! Token-config lookup trait used by the mint dispatcher to route to
//! the correct `MintBehavior` + `ProofBasis` variant for a given
//! deployed token (domain address).
//!
//! The hypergraph stores each token's configuration at
//! `[domain || HYPERGRAPH_METADATA_ADDRESS]` (see Go
//! `LoadTokenIntrinsic` at `token_intrinsic.go:1023-1082`). Reading it
//! requires walking the vertex's underlying-data tree and decoding
//! the RDF-multiprover-packed `config:TokenConfiguration`. We expose a
//! trait here so the engine can defer the full walk to a caller-
//! injected resolver (or to a future helper once the token-config
//! metadata RDF schema is fully ported).
//!
//! QUIL-specific config is baked in via
//! [`QuilOnlyConfigResolver`]: returns the `MintWithProof +
//! ProofOfMeaningfulWork` variant for `QUIL_TOKEN` and `None` for
//! every other domain. Nodes that need non-QUIL mint routing should
//! install a richer resolver.

use super::constants::{
    MINT_WITH_AUTHORITY, MINT_WITH_PAYMENT, MINT_WITH_PROOF,
    MINT_WITH_SIGNATURE, NO_MINT_BEHAVIOR, PROOF_OF_MEANINGFUL_WORK,
    VERKLE_MULTIPROOF_WITH_SIGNATURE,
};

/// Routing decision for a MintTransaction's `MintBehavior`+`ProofBasis`
/// pair. Derived from the token's deployed `TokenConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintVariant {
    /// `MintWithAuthority`.
    Authority,
    /// `MintWithSignature` — functionally identical to Authority but
    /// with a different declared behavior flag.
    Signature,
    /// `MintWithProof + ProofOfMeaningfulWork`.
    ProofOfMeaningfulWork,
    /// `MintWithProof + VerkleMultiproofWithSignature`.
    VerkleMultiproofWithSignature,
    /// `MintWithPayment`.
    Payment,
    /// `NoMintBehavior` — non-mintable token; minting should reject.
    NoMint,
    /// Unknown combination. Engine should reject.
    Unknown,
}

impl MintVariant {
    /// Derive the variant from the `mint_behavior` + `proof_basis`
    /// fields of a `TokenMintStrategy`. Mirrors Go's switch dispatch
    /// at `token_intrinsic_mint_transaction.go:1071-1115`.
    pub fn from_flags(mint_behavior: u16, proof_basis: u16) -> Self {
        match mint_behavior {
            NO_MINT_BEHAVIOR => MintVariant::NoMint,
            MINT_WITH_AUTHORITY => MintVariant::Authority,
            MINT_WITH_SIGNATURE => MintVariant::Signature,
            MINT_WITH_PAYMENT => MintVariant::Payment,
            MINT_WITH_PROOF => match proof_basis {
                PROOF_OF_MEANINGFUL_WORK => MintVariant::ProofOfMeaningfulWork,
                VERKLE_MULTIPROOF_WITH_SIGNATURE => {
                    MintVariant::VerkleMultiproofWithSignature
                }
                _ => MintVariant::Unknown,
            },
            _ => MintVariant::Unknown,
        }
    }
}

/// Resolver for per-token mint dispatch. Given a token's domain
/// address, returns the configured `MintVariant` or `None` if the
/// resolver has no configuration for that domain.
///
/// Non-QUIL tokens need this wired to the hypergraph so the engine
/// can dispatch correctly; the built-in [`QuilOnlyConfigResolver`]
/// handles the QUIL case inline.
pub trait TokenConfigResolver: Send + Sync {
    fn mint_variant_for_domain(&self, domain: &[u8]) -> Option<MintVariant>;

    /// For Authority/Signature variants: the key type of the
    /// authority's public key. Returns `None` for non-authority
    /// variants or when the resolver has no configuration.
    fn authority_key_type(&self, domain: &[u8]) -> Option<u32>;

    /// For Authority/Signature variants: the authority's public key.
    fn authority_public_key(&self, domain: &[u8]) -> Option<Vec<u8>>;

    /// For VerkleMultiproofWithSignature: the configured verkle root.
    fn verkle_root(&self, domain: &[u8]) -> Option<Vec<u8>>;

    /// For MintWithPayment: the fee baseline (None = free mint).
    fn payment_fee_baseline(&self, domain: &[u8]) -> Option<num_bigint::BigInt>;

    /// For MintWithPayment: the payment address.
    fn payment_address(&self, domain: &[u8]) -> Option<Vec<u8>>;

    /// Invalidate any cached entry for `domain`. Called by the engine
    /// after a TokenUpdate or TokenDeploy is processed so the next
    /// mint dispatch re-reads the on-chain config. Default no-op for
    /// stateless resolvers.
    fn invalidate(&self, _domain: &[u8]) {}
}

/// Default resolver that only knows about the QUIL token. Returns
/// `ProofOfMeaningfulWork` for the QUIL domain and `None` otherwise.
pub struct QuilOnlyConfigResolver;

impl TokenConfigResolver for QuilOnlyConfigResolver {
    fn mint_variant_for_domain(&self, domain: &[u8]) -> Option<MintVariant> {
        if domain == &crate::domains::QUIL_TOKEN[..] {
            Some(MintVariant::ProofOfMeaningfulWork)
        } else {
            None
        }
    }
    fn authority_key_type(&self, _domain: &[u8]) -> Option<u32> { None }
    fn authority_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> { None }
    fn verkle_root(&self, _domain: &[u8]) -> Option<Vec<u8>> { None }
    fn payment_fee_baseline(&self, _domain: &[u8]) -> Option<num_bigint::BigInt> { None }
    fn payment_address(&self, _domain: &[u8]) -> Option<Vec<u8>> { None }
}

/// Per-domain mint config entry. Populates a `StaticTokenConfigResolver`
/// with the fields needed by the mint verify dispatcher.
#[derive(Debug, Clone, Default)]
pub struct StaticTokenEntry {
    pub variant: MintVariant,
    pub authority_key_type: Option<u32>,
    pub authority_public_key: Option<Vec<u8>>,
    pub verkle_root: Option<Vec<u8>>,
    pub payment_fee_baseline: Option<num_bigint::BigInt>,
    pub payment_address: Option<Vec<u8>>,
}

impl Default for MintVariant {
    fn default() -> Self { MintVariant::Unknown }
}

/// In-memory resolver that looks up configs from a pre-populated map.
/// Suitable for nodes that receive deploy events and construct a
/// `StaticTokenEntry` from the packed MintStrategy bytes via
/// `token_intrinsic::config::decode_mint_strategy_packed`.
pub struct StaticTokenConfigResolver {
    entries: std::collections::HashMap<Vec<u8>, StaticTokenEntry>,
}

impl StaticTokenConfigResolver {
    pub fn new() -> Self {
        Self { entries: std::collections::HashMap::new() }
    }

    /// Seed the resolver with the baked-in QUIL config.
    pub fn with_quil_default() -> Self {
        let mut r = Self::new();
        r.insert(
            crate::domains::QUIL_TOKEN.to_vec(),
            StaticTokenEntry {
                variant: MintVariant::ProofOfMeaningfulWork,
                ..Default::default()
            },
        );
        r
    }

    pub fn insert(&mut self, domain: Vec<u8>, entry: StaticTokenEntry) {
        self.entries.insert(domain, entry);
    }

    /// Construct a `StaticTokenEntry` from a decoded `TokenMintStrategy`
    /// (the packed-binary form produced by Go deploys and decoded via
    /// `decode_mint_strategy_packed`). Surfaces the fields the engine
    /// needs for dispatch.
    pub fn entry_from_mint_strategy(
        strategy: &super::config::TokenMintStrategy,
    ) -> Result<StaticTokenEntry, quil_types::error::QuilError> {
        use num_bigint::{BigInt, Sign};

        let variant = MintVariant::from_flags(
            strategy.mint_behavior as u16,
            strategy.proof_basis as u16,
        );

        let mut authority_key_type = None;
        let mut authority_public_key = None;
        if !strategy.authority.is_empty() {
            let a = super::config::Authority::from_canonical_bytes(&strategy.authority)?;
            authority_key_type = Some(a.key_type);
            authority_public_key = Some(a.public_key);
        }

        let verkle_root = if strategy.verkle_root.is_empty() {
            None
        } else {
            Some(strategy.verkle_root.clone())
        };

        let mut payment_fee_baseline = None;
        if !strategy.fee_basis.is_empty() {
            let fb = super::config::FeeBasisStruct::from_canonical_bytes(&strategy.fee_basis)?;
            if !fb.baseline.is_empty() {
                payment_fee_baseline = Some(BigInt::from_bytes_be(
                    Sign::Plus, &fb.baseline,
                ));
            }
        }

        let payment_address = if strategy.payment_address.is_empty() {
            None
        } else {
            Some(strategy.payment_address.clone())
        };

        Ok(StaticTokenEntry {
            variant,
            authority_key_type,
            authority_public_key,
            verkle_root,
            payment_fee_baseline,
            payment_address,
        })
    }
}

impl Default for StaticTokenConfigResolver {
    fn default() -> Self {
        Self::with_quil_default()
    }
}

impl TokenConfigResolver for StaticTokenConfigResolver {
    fn mint_variant_for_domain(&self, domain: &[u8]) -> Option<MintVariant> {
        self.entries.get(domain).map(|e| e.variant.clone())
    }
    fn authority_key_type(&self, domain: &[u8]) -> Option<u32> {
        self.entries.get(domain).and_then(|e| e.authority_key_type)
    }
    fn authority_public_key(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(domain).and_then(|e| e.authority_public_key.clone())
    }
    fn verkle_root(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(domain).and_then(|e| e.verkle_root.clone())
    }
    fn payment_fee_baseline(&self, domain: &[u8]) -> Option<num_bigint::BigInt> {
        self.entries.get(domain).and_then(|e| e.payment_fee_baseline.clone())
    }
    fn payment_address(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(domain).and_then(|e| e.payment_address.clone())
    }
}

/// Live resolver that reads `config:TokenConfiguration` from the
/// hypergraph at `[domain || HYPERGRAPH_METADATA_ADDRESS]` on each
/// lookup. Suitable for nodes that want dispatch to follow the on-
/// chain state without a separate subscription to deploy events.
///
/// Results are cached in memory keyed by domain to avoid re-reading
/// the tree on every mint. Cache invalidation on token-update
/// messages is the caller's responsibility (call
/// `invalidate(&domain)` when a TokenUpdate is processed).
pub struct HypergraphTokenConfigResolver {
    hypergraph: std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
    cache: std::sync::RwLock<std::collections::HashMap<Vec<u8>, StaticTokenEntry>>,
    /// Fallback for QUIL: the token config isn't stored on-chain for
    /// QUIL — it's baked into genesis. Route QUIL→PoMW unconditionally.
    quil_default: StaticTokenEntry,
}

impl HypergraphTokenConfigResolver {
    pub fn new(hypergraph: std::sync::Arc<quil_hypergraph::HypergraphCrdt>) -> Self {
        Self {
            hypergraph,
            cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            quil_default: StaticTokenEntry {
                variant: MintVariant::ProofOfMeaningfulWork,
                ..Default::default()
            },
        }
    }

    /// Drop the cached entry for a domain. Callers should invoke this
    /// after a successful TokenUpdate so the next mint reflects the
    /// new config.
    pub fn invalidate(&self, domain: &[u8]) {
        if let Ok(mut c) = self.cache.write() {
            c.remove(domain);
        }
    }

    fn load_entry(&self, domain: &[u8]) -> Option<StaticTokenEntry> {
        if domain == &crate::domains::QUIL_TOKEN[..] {
            return Some(self.quil_default.clone());
        }
        if let Ok(cache) = self.cache.read() {
            if let Some(e) = cache.get(domain) {
                return Some(e.clone());
            }
        }
        // Cache miss — read from the hypergraph.
        if domain.len() != 32 {
            return None;
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(domain);
        let tree = super::metadata_schema::load_token_config_tree(&self.hypergraph, &d).ok()??;
        let config = super::metadata_schema::decode_token_config_from_tree(&tree).ok()?;
        if config.mint_strategy.is_empty() {
            return None;
        }
        let strategy = super::config::TokenMintStrategy::from_canonical_bytes(
            &config.mint_strategy,
        ).ok()?;
        let entry = Self::entry_from_strategy(&strategy).ok()?;
        if let Ok(mut c) = self.cache.write() {
            c.insert(domain.to_vec(), entry.clone());
        }
        Some(entry)
    }

    fn entry_from_strategy(
        strategy: &super::config::TokenMintStrategy,
    ) -> quil_types::error::Result<StaticTokenEntry> {
        StaticTokenConfigResolver::entry_from_mint_strategy(strategy)
    }
}

impl TokenConfigResolver for HypergraphTokenConfigResolver {
    fn mint_variant_for_domain(&self, domain: &[u8]) -> Option<MintVariant> {
        self.load_entry(domain).map(|e| e.variant)
    }
    fn authority_key_type(&self, domain: &[u8]) -> Option<u32> {
        self.load_entry(domain).and_then(|e| e.authority_key_type)
    }
    fn authority_public_key(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.load_entry(domain).and_then(|e| e.authority_public_key)
    }
    fn verkle_root(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.load_entry(domain).and_then(|e| e.verkle_root)
    }
    fn payment_fee_baseline(&self, domain: &[u8]) -> Option<num_bigint::BigInt> {
        self.load_entry(domain).and_then(|e| e.payment_fee_baseline)
    }
    fn payment_address(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.load_entry(domain).and_then(|e| e.payment_address)
    }
    fn invalidate(&self, domain: &[u8]) {
        HypergraphTokenConfigResolver::invalidate(self, domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_flags_routes_known_combinations() {
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_AUTHORITY, 0),
            MintVariant::Authority,
        );
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_SIGNATURE, 0),
            MintVariant::Signature,
        );
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_PAYMENT, 0),
            MintVariant::Payment,
        );
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_PROOF, PROOF_OF_MEANINGFUL_WORK),
            MintVariant::ProofOfMeaningfulWork,
        );
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_PROOF, VERKLE_MULTIPROOF_WITH_SIGNATURE),
            MintVariant::VerkleMultiproofWithSignature,
        );
        assert_eq!(
            MintVariant::from_flags(NO_MINT_BEHAVIOR, 0),
            MintVariant::NoMint,
        );
    }

    #[test]
    fn from_flags_handles_unknown() {
        // MintWithProof + unrecognized ProofBasis
        assert_eq!(
            MintVariant::from_flags(MINT_WITH_PROOF, 99),
            MintVariant::Unknown,
        );
        // Unknown MintBehavior bit pattern
        assert_eq!(
            MintVariant::from_flags(0xFF, 0),
            MintVariant::Unknown,
        );
    }

    #[test]
    fn quil_only_resolver_returns_pomw_for_quil() {
        let r = QuilOnlyConfigResolver;
        assert_eq!(
            r.mint_variant_for_domain(&crate::domains::QUIL_TOKEN),
            Some(MintVariant::ProofOfMeaningfulWork),
        );
        assert_eq!(r.mint_variant_for_domain(&[0xAAu8; 32]), None);
    }

    #[test]
    fn static_resolver_routes_registered_domain() {
        let mut r = StaticTokenConfigResolver::new();
        let custom_domain = vec![0xCCu8; 32];
        r.insert(custom_domain.clone(), StaticTokenEntry {
            variant: MintVariant::Authority,
            authority_key_type: Some(1),
            authority_public_key: Some(vec![0xAAu8; 57]),
            ..Default::default()
        });
        assert_eq!(
            r.mint_variant_for_domain(&custom_domain),
            Some(MintVariant::Authority),
        );
        assert_eq!(r.authority_key_type(&custom_domain), Some(1));
    }

    #[test]
    fn hypergraph_resolver_returns_pomw_for_quil_without_on_chain_data() {
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let r = HypergraphTokenConfigResolver::new(crdt);
        assert_eq!(
            r.mint_variant_for_domain(&crate::domains::QUIL_TOKEN),
            Some(MintVariant::ProofOfMeaningfulWork),
        );
    }

    #[test]
    fn hypergraph_resolver_invalidate_drops_cached_entry() {
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let r = HypergraphTokenConfigResolver::new(crdt);
        // Seed the cache via an explicit write (bypassing the read
        // path so we don't need a real on-chain vertex).
        let domain = vec![0x77u8; 32];
        {
            let mut c = r.cache.write().unwrap();
            c.insert(domain.clone(), StaticTokenEntry {
                variant: MintVariant::Authority,
                ..Default::default()
            });
        }
        assert_eq!(
            r.mint_variant_for_domain(&domain),
            Some(MintVariant::Authority),
        );
        // Invalidate and confirm cache is empty so the next read goes
        // back to the (empty) chain → None.
        r.invalidate(&domain);
        assert_eq!(r.mint_variant_for_domain(&domain), None);
    }

    #[test]
    fn hypergraph_resolver_returns_none_for_unknown_domain() {
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let r = HypergraphTokenConfigResolver::new(crdt);
        assert_eq!(r.mint_variant_for_domain(&[0xCCu8; 32]), None);
    }

    #[test]
    fn entry_from_mint_strategy_builds_authority_entry() {
        let strat = super::super::config::TokenMintStrategy {
            mint_behavior: MINT_WITH_AUTHORITY as u32,
            proof_basis: 0,
            verkle_root: vec![],
            authority: super::super::config::Authority {
                key_type: 5,
                public_key: vec![0xBBu8; 97],
                can_burn: true,
            }.to_canonical_bytes().unwrap(),
            payment_address: vec![],
            fee_basis: vec![],
        };
        let entry = StaticTokenConfigResolver::entry_from_mint_strategy(&strat).unwrap();
        assert_eq!(entry.variant, MintVariant::Authority);
        assert_eq!(entry.authority_key_type, Some(5));
        assert_eq!(entry.authority_public_key, Some(vec![0xBBu8; 97]));
        assert!(entry.verkle_root.is_none());
        assert!(entry.payment_fee_baseline.is_none());
    }
}
