//! `quil-client` — the Rust port of the Quilibrium `qclient` CLI.
//!
//! The binary lives in `main.rs`; this library exposes the reusable
//! pieces (config, node-config resolution, key manager, gRPC connection,
//! and the `Send` helper) so they can be unit- and integration-tested
//! independently of `clap` argument parsing.

pub mod alias_store;
pub mod config;
pub mod context;
pub mod keys;
pub mod nodeconfig;
pub mod release;
pub mod rpc;
pub mod send;
pub mod system;
pub mod util;
pub mod vertex_write;

pub mod commands;

/// Install qclient's log subscriber: `RUST_LOG` (default `warn`) on
/// stderr, except while the node manager runs a token command, whose
/// screen a print would overwrite: then each event goes to the manager as
/// one line, as the command's progress lines do.
pub fn init_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with(commands::token::output::log_layers(std::io::stderr))
        .init();
}

/// Acceptance tests: each request the client emits is run through the node's
/// own signature/structure verification. See the module for scope.
#[cfg(test)]
mod request_acceptance_tests;
