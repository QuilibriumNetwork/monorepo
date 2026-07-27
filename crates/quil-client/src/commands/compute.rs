//! `qclient compute execute <FullAddress|Alias> [Rendezvous] [PartyId] [k=v...]`.
//!
//! Port of `client/cmd/compute/compute.go` `ExecuteCmd`, rebuilt for PQ:
//! the proof-of-payment is a **Falcon** signature over the rendezvous
//! (domain-separated by the compute domain) — `[payer_pubkey, sig]` — the
//! post-quantum replacement for the Go decaf `SimpleSign`
//! (`compute_intrinsic/intrinsic.rs::verify_code_execute`).

use clap::{Args, Subcommand};
use rand::RngCore;

use quil_types::crypto::Signer;
use quil_types::proto::compute::{
    Application, CodeExecute, ExecuteOperation, ExecutionContext,
};
use quil_types::proto::global::{message_request::Request, MessageRequest};

use crate::alias_store::{self, Store};
use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

#[derive(Debug, Args)]
pub struct ComputeArgs {
    #[command(subcommand)]
    pub command: ComputeCommand,
}

#[derive(Debug, Subcommand)]
pub enum ComputeCommand {
    /// Execute a compute operation on a domain.
    Execute {
        /// Domain full address or alias (32-byte app address).
        address: String,
        /// Optional 32-byte hex rendezvous (random if omitted), party id,
        /// and `key=value` arguments.
        rest: Vec<String>,
    },
}

pub async fn run(global: GlobalArgs, args: &ComputeArgs) -> anyhow::Result<()> {
    match &args.command {
        ComputeCommand::Execute { address, rest } => execute(global, address, rest).await,
    }
}

fn resolve(store: &Option<Store>, input: &str, expected: usize) -> anyhow::Result<Vec<u8>> {
    if let Some(s) = store {
        if let Some((addr, _)) = s.resolve(input) {
            if addr.len() != expected {
                anyhow::bail!("alias {input:?} resolved to {} bytes, expected {expected}", addr.len());
            }
            return Ok(addr);
        }
    }
    let b = hex::decode(input.strip_prefix("0x").unwrap_or(input))
        .map_err(|e| anyhow::anyhow!("must be an alias or hex address: {e}"))?;
    if b.len() != expected {
        anyhow::bail!("expected {expected} bytes, got {}", b.len());
    }
    Ok(b)
}

async fn execute(global: GlobalArgs, address: &str, rest: &[String]) -> anyhow::Result<()> {
    let ctx = Context::load(global)?;
    let (node_config, dir) = ctx.load_node_config("default")?;
    let alias_store = alias_store::try_load_for_config_dir(&dir);
    let key_manager = ctx.key_manager(&node_config, &dir)?;

    let domain = resolve(&alias_store, address, 32)?;

    // Parse optional [rendezvous] [partyId] [k=v...].
    let mut rendezvous_hex: Option<String> = None;
    let mut party_id: Option<String> = None;
    let mut arguments: Vec<String> = Vec::new();
    for a in rest {
        if a.contains('=') {
            arguments.push(a.clone());
        } else if rendezvous_hex.is_none() {
            rendezvous_hex = Some(a.clone());
        } else if party_id.is_none() {
            party_id = Some(a.clone());
        }
    }

    let rendezvous: Vec<u8> = match rendezvous_hex {
        Some(h) => {
            let b = hex::decode(h.strip_prefix("0x").unwrap_or(&h))
                .map_err(|e| anyhow::anyhow!("invalid rendezvous hex: {e}"))?;
            if b.len() != 32 {
                anyhow::bail!("rendezvous must be 32 bytes, got {}", b.len());
            }
            b
        }
        None => {
            let mut r = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut r);
            r.to_vec()
        }
    };
    // The reserved metadata address [0xFF;32] is rejected by the node.
    if rendezvous.iter().all(|&b| b == 0xFF) {
        anyhow::bail!("rendezvous collides with the reserved metadata address");
    }

    // Identifier: concatenated k=v args, else party id, else "default".
    let identifier: Vec<u8> = if !arguments.is_empty() {
        arguments.concat().into_bytes()
    } else if let Some(p) = &party_id {
        let n: u64 = p.parse().map_err(|_| anyhow::anyhow!("invalid party ID: {p}"))?;
        format!("party_{n}").into_bytes()
    } else {
        b"default".to_vec()
    };

    let main_op = ExecuteOperation {
        application: Some(Application {
            address: domain.clone(),
            execution_context: ExecutionContext::Hypergraph as i32,
        }),
        identifier,
        dependencies: Vec::new(),
    };

    // Falcon proof-of-payment: [payer_pubkey, sign(rendezvous, ctx=domain)].
    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get payer key (q-prover-key): {e}"))?;
    let payer = signer.public_key().to_vec();
    let payment_sig = signer
        .sign_with_domain(&rendezvous, &domain)
        .map_err(|e| anyhow::anyhow!("sign proof of payment: {e}"))?;

    let op = CodeExecute {
        proof_of_payment: vec![payer, payment_sig],
        domain: domain.clone(),
        rendezvous: rendezvous.clone(),
        execute_operations: vec![main_op],
    };

    let connect_opts = ConnectOpts {
        public_rpc: false,
        custom_rpc: String::new(),
        listen_grpc_multiaddr: node_config.listen_grpc_multiaddr.clone(),
    };
    let mut client = crate::rpc::connect_node_service(&connect_opts).await?;
    let request = MessageRequest {
        request: Some(Request::CodeExecute(op)),
        timestamp: 0,
    };
    crate::send::send_message_request(&mut client, &key_manager, domain, request).await?;

    println!("Compute execution submitted successfully");
    println!("Rendezvous: {}", hex::encode(&rendezvous));
    Ok(())
}
