//! Prover lifecycle write ops: leave / confirm / reject / pause / resume /
//! delegate.
//!
//! Port of `proverLeave.go`, `proverConfirm.go`, `proverReject.go`,
//! `proverPause.go`, `proverResume.go`, `proverDelegate.go`. Each op:
//! 1. fetches the current global head frame,
//! 2. signs the op with `q-prover-key` (Falcon, [`super::sign`]),
//! 3. wraps it in the matching `MessageRequest` variant, and
//! 4. submits via `Send` with the `0xFF×32` global domain (outer Ed448
//!    `q-peer-key` auth).

use quil_types::crypto::Signer;
use quil_types::proto::global::{
    message_request::Request, AltShardUpdate, MessageRequest, ProverConfirm, ProverLeave,
    ProverPause, ProverReject, ProverResume, ProverUpdate,
};

use super::{sign, ProverCtx};

/// All-0xFF 32-byte filter — the "all shards" default.
fn default_filter() -> Vec<u8> {
    vec![0xFFu8; 32]
}

/// Parse hex filter args, defaulting to a single all-0xFF filter.
fn parse_filters(args: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    if args.is_empty() {
        return Ok(vec![default_filter()]);
    }
    args.iter()
        .map(|a| hex::decode(a).map_err(|e| anyhow::anyhow!("invalid filter hex {a:?}: {e}")))
        .collect()
}

/// Parse a single optional hex filter, defaulting to all-0xFF.
fn parse_single_filter(arg: Option<&str>) -> anyhow::Result<Vec<u8>> {
    match arg {
        None => Ok(default_filter()),
        Some(a) => hex::decode(a).map_err(|e| anyhow::anyhow!("invalid filter hex {a:?}: {e}")),
    }
}

pub async fn leave(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::leave_sig(&pc.key_manager, &filters, frame)?;
    let op = ProverLeave {
        filters,
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Leave(op))).await?;
    println!("Prover leave sent successfully");
    Ok(())
}

// `filter` is deprecated in global.proto in favour of the repeated `filters`,
// but it is still on the wire: peers that predate the change send it, and
// dropping it here would change the encoded bytes. Carried through verbatim
// until the field is retired from the proto.
#[allow(deprecated)]
pub async fn confirm(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::confirm_sig(&pc.key_manager, &filters, frame)?;
    let op = ProverConfirm {
        filter: Vec::new(), // deprecated field
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
        filters,
        leaf_roots: Vec::new(),
    };
    pc.send_global(&mut client, wrap(Request::Confirm(op))).await?;
    println!("Prover confirm sent successfully");
    Ok(())
}

#[allow(deprecated)] // see `confirm`
pub async fn reject(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::reject_sig(&pc.key_manager, &filters, frame)?;
    let op = ProverReject {
        filter: Vec::new(), // deprecated field
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
        filters,
    };
    pc.send_global(&mut client, wrap(Request::Reject(op))).await?;
    println!("Prover reject sent successfully");
    Ok(())
}

pub async fn pause(pc: &ProverCtx, filter_arg: Option<&str>) -> anyhow::Result<()> {
    let filter = parse_single_filter(filter_arg)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::pause_sig(&pc.key_manager, &filter, frame)?;
    let op = ProverPause {
        filter,
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Pause(op))).await?;
    println!("Prover pause sent successfully");
    Ok(())
}

pub async fn resume(pc: &ProverCtx, filter_arg: Option<&str>) -> anyhow::Result<()> {
    let filter = parse_single_filter(filter_arg)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    let sig = sign::resume_sig(&pc.key_manager, &filter, frame)?;
    let op = ProverResume {
        filter,
        frame_number: frame,
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Resume(op))).await?;
    println!("Prover resume sent successfully");
    Ok(())
}

pub async fn delegate(pc: &ProverCtx, address: &str) -> anyhow::Result<()> {
    let addr_hex = address.strip_prefix("0x").unwrap_or(address);
    let delegate_address =
        hex::decode(addr_hex).map_err(|_| anyhow::anyhow!("Invalid delegate address: must be 32 bytes hex-encoded"))?;
    if delegate_address.len() != 32 {
        anyhow::bail!("Invalid delegate address: must be 32 bytes hex-encoded");
    }

    let mut client = pc.connect().await?;
    // The delegate signature covers only the delegate address (no frame),
    // but Go still fetches node info first; we skip that as it's unused.
    let sig = sign::update_sig(&pc.key_manager, &delegate_address)?;
    let op = ProverUpdate {
        delegate_address: delegate_address.clone(),
        public_key_signature_bls48581: Some(sig),
    };
    pc.send_global(&mut client, wrap(Request::Update(op))).await?;
    println!("Delegate address updated to 0x{}", hex::encode(&delegate_address));
    Ok(())
}

/// `alt-shard-update <v-adds> <v-removes> <he-adds> <he-removes>` — an
/// external shard's signed root commitment. Signs `frame ‖ roots` with the
/// Falcon `q-prover-key` under the `ALT_SHARD_UPDATE` domain.
pub async fn alt_shard_update(pc: &ProverCtx, roots_hex: &[String]) -> anyhow::Result<()> {
    if roots_hex.len() != 4 {
        anyhow::bail!(
            "alt-shard-update requires 4 root args: <vertex-adds> <vertex-removes> \
             <hyperedge-adds> <hyperedge-removes>"
        );
    }
    let root_names = [
        "vertex-adds-root",
        "vertex-removes-root",
        "hyperedge-adds-root",
        "hyperedge-removes-root",
    ];
    let mut roots: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (i, arg) in roots_hex.iter().enumerate() {
        roots.push(hex::decode(arg).map_err(|e| anyhow::anyhow!("invalid {} hex: {e}", root_names[i]))?);
    }

    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;

    let signer: Box<dyn Signer> = pc
        .key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key: {e}"))?;
    let public_key = signer.public_key().to_vec();

    // message = frame(8 BE) ‖ vAdds ‖ vRems ‖ heAdds ‖ heRems
    let mut message = Vec::with_capacity(8 + roots.iter().map(|r| r.len()).sum::<usize>());
    message.extend_from_slice(&frame.to_be_bytes());
    for r in &roots {
        message.extend_from_slice(r);
    }
    let domain =
        quil_execution::global_intrinsic::alt_shard_update_materialize::alt_shard_update_domain()
            .map_err(|e| anyhow::anyhow!("alt shard update domain: {e}"))?;
    let signature = signer
        .sign_with_domain(&message, &domain)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    let op = AltShardUpdate {
        public_key,
        frame_number: frame,
        vertex_adds_root: roots[0].clone(),
        vertex_removes_root: roots[1].clone(),
        hyperedge_adds_root: roots[2].clone(),
        hyperedge_removes_root: roots[3].clone(),
        signature,
    };
    pc.send_global(&mut client, wrap(Request::AltShardUpdate(op))).await?;
    println!("Alt shard update sent successfully");
    Ok(())
}

fn wrap(request: Request) -> MessageRequest {
    MessageRequest {
        request: Some(request),
        timestamp: 0,
    }
}
