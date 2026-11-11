//! A compute CodeExecute or CodeDeployment writes a vertex into the domain
//! it names, while its routing address chooses the engine, the fee and the
//! shard. From [`compute_domain_frame`] on, both are refused unless they
//! name the application they are routed to, and never a system-managed
//! domain ([`crate::compute_intrinsic::intrinsic::check_op_domain`]).
//!
//! Before the frame they execute as older builds execute them, so replayed
//! history and a network still running older builds agree.
//!
//! An application shard's frame is judged by its GLOBAL anchor, which its
//! leader picks among the GLOBAL frames its voters hold. A voter whose own
//! latest GLOBAL frame has reached the domain frame therefore refuses a
//! proposal anchored before it that carries an op [`crosses_domain`] finds,
//! so no leader runs one by citing an older anchor. Only a shard the
//! compute engine executes is judged, and a leader near the frame leaves
//! such bundles out rather than have its proposal refused.

use quil_types::execution::FrameExecutionContext;

/// The GLOBAL frame from which compute ops are bound to their routing
/// domain. Consensus-affecting for GLOBAL and for application shards, where
/// compute bundles execute: from the frame, a build without the binding
/// admits a cross-domain op that a build with it refuses, so the two states
/// diverge on any bundle carrying one. Not scheduled on mainnet until a
/// devnet crossing and a census of archives and workers running a release
/// that carries it; `QUIL_COMPUTE_DOMAIN_FRAME` elsewhere, zero (always) by
/// default.
pub const MAINNET_COMPUTE_DOMAIN_FRAME: Option<u64> = None;

// A shard frame naming no GLOBAL anchor is judged by its own number in
// execution and as before the domain frame by a voter. On mainnet no voter
// takes one at or after the domain frame: from the required-anchor epoch it
// refuses such a frame first. So the domain frame must follow that epoch.
const _: () = assert!(match MAINNET_COMPUTE_DOMAIN_FRAME {
    Some(frame) => match quil_types::consensus::MAINNET_REQUIRED_ANCHOR_EPOCH {
        Some(epoch) => frame / quil_types::consensus::EPOCH_LENGTH_FRAMES >= epoch,
        None => false,
    },
    None => true,
});

/// The setting naming the frame on a test network.
pub const COMPUTE_DOMAIN_FRAME_SETTING: &str = "QUIL_COMPUTE_DOMAIN_FRAME";

static COMPUTE_DOMAIN_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

fn compute_domain_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_COMPUTE_DOMAIN_FRAME.unwrap_or(u64::MAX);
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(0)
}

/// Fix this process's compute domain frame from its network, and return it
/// (`u64::MAX`: never). Called at startup before any frame is processed;
/// the first call decides.
pub fn init_compute_domain_frame(network: u8) -> u64 {
    *COMPUTE_DOMAIN_FRAME.get_or_init(|| {
        compute_domain_frame_for(
            network,
            std::env::var(COMPUTE_DOMAIN_FRAME_SETTING).ok().as_deref(),
        )
    })
}

pub fn compute_domain_frame() -> u64 {
    *COMPUTE_DOMAIN_FRAME.get_or_init(|| {
        std::env::var(COMPUTE_DOMAIN_FRAME_SETTING)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    })
}

/// Whether GLOBAL frame `frame` binds compute ops to their routing domain.
pub fn compute_domain_guarded_at(frame: u64) -> bool {
    frame >= compute_domain_frame()
}

/// Whether a frame executing in `context` binds them, judged by the GLOBAL
/// frame it names: an application shard's frame by its certified GLOBAL
/// anchor, a GLOBAL frame by the frame before it (the GLOBAL materializer
/// passes `frame - 1`), so GLOBAL refuses from the frame after the domain
/// frame. A context naming none is judged by its own number.
pub fn compute_domain_guarded(context: FrameExecutionContext) -> bool {
    compute_domain_guarded_at(
        context
            .finalized_global_frame
            .unwrap_or(context.frame_number),
    )
}

/// Whether `message`, a canonical message bundle or request routed to
/// `routing`, carries a CodeDeployment or CodeExecute that a frame bound by
/// the domain frame refuses and an earlier frame executes, when `routing`
/// selects the compute engine (only it runs these ops; see
/// [`crate::ExecutionEngineManager::routes_to_compute`]): one naming a
/// domain other than `routing`, or a system-managed one. An op or message
/// that does not decode is refused on both sides of the frame, so it is
/// not counted.
pub fn crosses_domain(routing: &[u8], message: &[u8]) -> bool {
    use crate::compute_intrinsic::{
        intrinsic::check_op_domain, CodeDeployment, CodeExecute, TYPE_CODE_DEPLOYMENT,
        TYPE_CODE_EXECUTE,
    };
    use crate::message_envelope::{
        CanonicalMessageBundle, CanonicalMessageRequest, TYPE_MESSAGE_BUNDLE, TYPE_MESSAGE_REQUEST,
    };
    let requests = match message
        .get(..4)
        .map(|prefix| u32::from_be_bytes(prefix.try_into().unwrap()))
    {
        Some(TYPE_MESSAGE_BUNDLE) => match CanonicalMessageBundle::from_canonical_bytes(message) {
            Ok(bundle) => bundle.requests.into_iter().flatten().collect(),
            Err(_) => return false,
        },
        Some(TYPE_MESSAGE_REQUEST) => {
            match CanonicalMessageRequest::from_canonical_bytes(message) {
                Ok(request) => vec![request],
                Err(_) => return false,
            }
        }
        _ => return false,
    };
    requests
        .iter()
        .any(|request| match request.inner_type_prefix {
            TYPE_CODE_DEPLOYMENT => CodeDeployment::from_canonical_bytes(&request.inner_bytes)
                .is_ok_and(|op| check_op_domain("code deploy", &op.domain, routing).is_err()),
            TYPE_CODE_EXECUTE => CodeExecute::from_canonical_bytes(&request.inner_bytes)
                .is_ok_and(|op| check_op_domain("code execute", &op.domain, routing).is_err()),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_test_network_reads_the_compute_domain_setting() {
        assert_eq!(MAINNET_COMPUTE_DOMAIN_FRAME, None);
        for setting in [None, Some("5"), Some("bad")] {
            assert_eq!(
                compute_domain_frame_for(0, setting),
                u64::MAX,
                "mainnet read the setting {setting:?}"
            );
        }
        assert_eq!(compute_domain_frame_for(1, Some("4")), 4);
        assert_eq!(compute_domain_frame_for(1, None), 0);
        assert_eq!(compute_domain_frame_for(1, Some("bad")), 0);
        // The engine tests pin the frame through this setting by name.
        assert_eq!(COMPUTE_DOMAIN_FRAME_SETTING, "QUIL_COMPUTE_DOMAIN_FRAME");
    }
}
