//! Application configurations move only forward. A deploy carries no
//! signature and derives its application's domain from its configuration
//! alone, and an owner's update was signed over its own bytes alone, so
//! either one submitted again restored the configuration (owner key, mint
//! authority, schema) a later update had replaced. From
//! [`config_replay_frame`] on:
//! - a token, hypergraph or compute deploy onto a domain that already holds a
//!   metadata vertex is refused ([`refuse_redeploy`]): a deploy creates an
//!   application, an owner-signed update changes it;
//! - an owner's update of a token, hypergraph or compute application signs
//!   the content digest of the metadata vertex it replaces
//!   ([`update_signing_domain`], [`stored_binding`]), and each update advances
//!   the vertex's update sequence ([`advance_update_sequence`]), so an update
//!   applies once: not after a later one, nor after the configuration returns
//!   to the one it was signed against.
//!
//! Before the frame both behave as older builds do, so history replays
//! unchanged.

use quil_types::error::{QuilError, Result};
use quil_types::execution::FrameExecutionContext;

/// The GLOBAL frame from which deploys and updates cannot be replayed.
/// Consensus-affecting for GLOBAL, where deploys execute, and for application
/// shards, where updates execute: every archive and prover must run a build
/// with it before the frame, and from it an owner updates an application only
/// with a client that signs the new domain (an older client's update is
/// refused as not verifying). Mainnet epoch 1513, two days of adoption after
/// the release that can carry it first, ending in the maintainer's working day.
/// `QUIL_CONFIG_REPLAY_FRAME` elsewhere, zero (always) by default.
pub const MAINNET_CONFIG_REPLAY_FRAME: u64 = 1_089_360;

/// The setting naming the frame on a test network.
pub const CONFIG_REPLAY_FRAME_SETTING: &str = "QUIL_CONFIG_REPLAY_FRAME";

static CONFIG_REPLAY_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static CONFIG_REPLAY_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn config_replay_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_CONFIG_REPLAY_FRAME;
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(0)
}

/// Fix this process's config replay frame from its network, and return it.
/// Called at startup before any frame is processed, and by the client before
/// it signs an update; the first call decides.
pub fn init_config_replay_frame(network: u8) -> u64 {
    *CONFIG_REPLAY_FRAME.get_or_init(|| {
        config_replay_frame_for(
            network,
            std::env::var(CONFIG_REPLAY_FRAME_SETTING).ok().as_deref(),
        )
    })
}

pub fn config_replay_frame() -> u64 {
    if let Some(frame) = CONFIG_REPLAY_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *CONFIG_REPLAY_FRAME.get_or_init(|| {
        std::env::var(CONFIG_REPLAY_FRAME_SETTING)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    })
}

/// Set the config replay frame for the calling thread only (tests).
pub fn set_config_replay_frame_for_thread(frame: Option<u64>) {
    CONFIG_REPLAY_OVERRIDE.with(|cell| cell.set(frame));
}

/// Whether GLOBAL frame `frame` refuses replayed deploys and unbound updates.
pub fn config_replay_guarded_at(frame: u64) -> bool {
    frame >= config_replay_frame()
}

/// Whether a frame executing in `context` refuses them: an application
/// shard's frame by its certified GLOBAL anchor, a GLOBAL frame by its own
/// number.
pub fn config_replay_guarded(context: FrameExecutionContext) -> bool {
    config_replay_guarded_at(
        context
            .finalized_global_frame
            .unwrap_or(context.frame_number),
    )
}

/// Refuse a `kind` deploy onto `domain` once the domain holds a metadata
/// vertex.
pub fn refuse_redeploy(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8; 32],
    kind: &str,
) -> Result<()> {
    let adds = crate::hypergraph_state::vertex_adds_discriminator()?;
    let deployed = state
        .get(
            domain,
            &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
            &adds,
        )?
        .is_some_and(|blob| !blob.is_empty());
    if deployed {
        return Err(QuilError::InvalidArgument(format!(
            "{kind} deploy: {} is already deployed; its owner changes it by an update",
            hex::encode(domain)
        )));
    }
    Ok(())
}

/// The separator a token update is signed under after its domain.
pub const TOKEN_UPDATE_TAG: &[u8] = b"TOKEN_UPDATE";
/// The separator a hypergraph update is signed under after its domain.
pub const HYPERGRAPH_UPDATE_TAG: &[u8] = b"HYPERGRAPH_UPDATE";
/// The separator a compute update is signed under after its domain.
pub const COMPUTE_UPDATE_TAG: &[u8] = b"COMPUTE_UPDATE";

/// Key of an application's metadata vertex holding its update sequence: the
/// number of updates applied from [`config_replay_frame`], eight bytes
/// big-endian, absent before the first. The first metadata key above every
/// one in use (`[16 << 2]`, the configuration, is the highest).
pub const UPDATE_SEQUENCE_KEY: [u8; 1] = [17u8 << 2];

/// The domain an owner signs an update under: `address ‖ tag`, then, from
/// [`config_replay_frame`], `binding`, the digest of the metadata vertex the
/// update replaces ([`metadata_vertex_binding`]; `None` before the frame).
pub fn update_signing_domain(address: &[u8], tag: &[u8], binding: Option<&[u8]>) -> Vec<u8> {
    let mut domain = [address, tag].concat();
    if let Some(binding) = binding {
        domain.extend_from_slice(binding);
    }
    domain
}

/// What an update of the application whose metadata vertex is `vertex`
/// signs over: the vertex's content digest, covering its configuration,
/// schema and update sequence.
pub fn metadata_vertex_binding(vertex: &[u8]) -> Result<Vec<u8>> {
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(vertex)
            .map_err(|e| QuilError::InvalidArgument(format!("metadata vertex: {e}")))?,
    };
    Ok(crate::hypergraph_state::tree_content_digest(&outer))
}

fn metadata_vertex(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
) -> Result<Option<Vec<u8>>> {
    let adds = crate::hypergraph_state::vertex_adds_discriminator()?;
    Ok(state
        .get(
            domain,
            &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
            &adds,
        )?
        .filter(|blob| !blob.is_empty()))
}

/// The binding of `domain`'s metadata vertex as `state` holds it; `None`
/// when it holds none.
pub fn stored_binding(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
) -> Result<Option<Vec<u8>>> {
    metadata_vertex(state, domain)?
        .map(|vertex| metadata_vertex_binding(&vertex))
        .transpose()
}

/// The separator a frame (`context`) verifies an owner's update of
/// `address` under: from the config replay frame bound to the metadata
/// vertex `state` holds for it, unbound before.
pub fn update_separator(
    state: &crate::hypergraph_state::HypergraphState,
    address: &[u8],
    tag: &[u8],
    context: FrameExecutionContext,
) -> Result<Vec<u8>> {
    let binding = if config_replay_guarded(context) {
        stored_binding(state, address)?
    } else {
        None
    };
    Ok(update_signing_domain(address, tag, binding.as_deref()))
}

fn sequence_value(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| QuilError::InvalidArgument("update sequence: not eight bytes".into()))?;
    Ok(u64::from_be_bytes(bytes))
}

/// After an update applied in a guarded frame: advance `domain`'s update
/// sequence, so no binding repeats even when a configuration does.
pub fn advance_update_sequence(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    frame_number: u64,
) -> Result<()> {
    let vertex = metadata_vertex(state, domain)?
        .ok_or_else(|| QuilError::InvalidArgument("update sequence: no metadata vertex".into()))?;
    let mut outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&vertex)
            .map_err(|e| QuilError::InvalidArgument(format!("metadata vertex: {e}")))?,
    };
    let sequence = match outer.get(&UPDATE_SEQUENCE_KEY) {
        None => 0,
        Some(bytes) => sequence_value(bytes)?,
    };
    let next = sequence
        .checked_add(1)
        .ok_or_else(|| QuilError::InvalidArgument("update sequence exhausted".into()))?;
    outer
        .insert(
            &UPDATE_SEQUENCE_KEY,
            &next.to_be_bytes(),
            &[],
            &num_bigint::BigInt::from(8),
        )
        .map_err(|e| QuilError::Internal(format!("update sequence: insert: {e}")))?;
    let blob = quil_tries::serialize_go_tree(outer.root.as_ref())
        .map_err(|e| QuilError::Internal(format!("update sequence: serialize: {e}")))?;
    state.set(
        domain,
        &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
        &crate::hypergraph_state::vertex_adds_discriminator()?,
        frame_number,
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_test_network_reads_the_config_replay_setting() {
        for setting in [None, Some("5"), Some("bad")] {
            assert_eq!(
                config_replay_frame_for(0, setting),
                MAINNET_CONFIG_REPLAY_FRAME
            );
        }
        assert_eq!(config_replay_frame_for(1, Some("4")), 4);
        assert_eq!(config_replay_frame_for(1, None), 0);
        assert_eq!(config_replay_frame_for(1, Some("bad")), 0);
        assert_eq!(
            MAINNET_CONFIG_REPLAY_FRAME,
            1513 * quil_types::consensus::EPOCH_LENGTH_FRAMES
        );
    }

    #[test]
    fn an_application_frame_is_guarded_by_its_global_anchor() {
        set_config_replay_frame_for_thread(Some(100));
        let at = |frame_number, finalized_global_frame| {
            config_replay_guarded(FrameExecutionContext {
                frame_number,
                finalized_global_frame,
                shard: quil_types::execution::ShardPath::WHOLE,
                venue: None,
            })
        };
        assert!(!at(500, Some(99)));
        assert!(at(5, Some(100)));
        assert!(!at(99, None));
        assert!(at(100, None));
        set_config_replay_frame_for_thread(None);
    }

    #[test]
    fn each_update_sequence_step_changes_the_binding_and_nothing_else() {
        let state = crate::hypergraph_state::HypergraphState::new(std::sync::Arc::new(
            quil_hypergraph::HypergraphCrdt::new(
                std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
                std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
            ),
        ));
        let config = crate::token_intrinsic::TokenConfiguration {
            behavior: 1,
            name: b"seq".to_vec(),
            owner_public_key: vec![7; 897],
            ..Default::default()
        };
        let domain = crate::token_intrinsic::materialize::materialize_token_deploy_init(
            &state,
            &config,
            1,
            &quil_types::crypto::NoopInclusionProver,
        )
        .unwrap();
        let config_tree = |state: &crate::hypergraph_state::HypergraphState| {
            let vertex = metadata_vertex(state, &domain).unwrap().unwrap();
            let outer = quil_tries::VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(&vertex).unwrap(),
            };
            outer
                .get(&crate::token_intrinsic::materialize::TOKEN_CONFIG_OUTER_KEY)
                .unwrap()
                .to_vec()
        };
        let before = config_tree(&state);
        let mut seen = vec![stored_binding(&state, &domain).unwrap().unwrap()];
        for _ in 0..3 {
            advance_update_sequence(&state, &domain, 2).unwrap();
            let binding = stored_binding(&state, &domain).unwrap().unwrap();
            assert!(!seen.contains(&binding), "a binding repeated");
            seen.push(binding);
        }
        assert_eq!(
            config_tree(&state),
            before,
            "the sequence changed the config"
        );

        let address = [3u8; 32];
        let unbound = update_signing_domain(&address, TOKEN_UPDATE_TAG, None);
        assert_eq!(unbound, [&address[..], b"TOKEN_UPDATE"].concat());
        let bound = update_signing_domain(&address, TOKEN_UPDATE_TAG, Some(&seen[0]));
        assert!(bound.starts_with(&unbound) && bound.len() == unbound.len() + 64);
    }
}
