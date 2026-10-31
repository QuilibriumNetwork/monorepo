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
    message_request::Request, AltShardUpdate, MessageRequest, ProverLeave, ProverPause,
    ProverReject, ProverResume, ProverUpdate,
};

use quil_types::proto::node::node_service_client::NodeServiceClient;
use tonic::transport::Channel;

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

/// Sign and send a multi-filter op as several ops when `filters` exceed what
/// one carries (see [`sign::op_chunks`]), each built by `build` over its own
/// filters at the same frame. Every op is signed before the first is sent, so
/// a filter no node decodes stops the command before anything goes out; a
/// failed send stops the rest and says how many filters went out.
async fn send_split(
    pc: &ProverCtx,
    client: &mut NodeServiceClient<Channel>,
    op: &str,
    filters: &[Vec<u8>],
    build: impl Fn(&[Vec<u8>]) -> anyhow::Result<Request>,
) -> anyhow::Result<()> {
    let chunks: Vec<&[Vec<u8>]> = sign::op_chunks(filters).collect();
    let requests = chunks
        .iter()
        .map(|chunk| build(*chunk))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let count = requests.len();
    let mut sent = 0;
    for (index, (request, chunk)) in requests.into_iter().zip(&chunks).enumerate() {
        pc.send_global(client, wrap(request))
            .await
            .map_err(|e| split_send_error(op, index, count, filters, sent, e))?;
        sent += chunk.len();
    }
    if count > 1 {
        println!(
            "Prover {op} sent successfully as {count} messages for {} filters",
            filters.len()
        );
    } else {
        println!("Prover {op} sent successfully");
    }
    Ok(())
}

/// The error of a split op whose message `index` (from 0) of `count` was not
/// sent after the first `sent` filters went out. After a partial send it
/// lists the unsent filters as the arguments of a follow-up command, so a
/// re-run does not resend the published ones.
fn split_send_error(
    op: &str,
    index: usize,
    count: usize,
    filters: &[Vec<u8>],
    sent: usize,
    err: impl std::fmt::Display,
) -> anyhow::Error {
    let mut message = format!(
        "prover {op} message {}/{count} not sent ({sent}/{} filters sent): {err}",
        index + 1,
        filters.len()
    );
    if sent > 0 {
        let unsent: Vec<String> = filters[sent..].iter().map(hex::encode).collect();
        message.push_str(&format!(
            "\nsend the {} unsent filters with: qclient node prover {op} {}",
            unsent.len(),
            unsent.join(" ")
        ));
    }
    anyhow::anyhow!(message)
}

pub async fn leave(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    send_split(pc, &mut client, "leave", &filters, |chunk| {
        let sig = sign::leave_sig(&pc.key_manager, chunk, frame)?;
        Ok(Request::Leave(ProverLeave {
            filters: chunk.to_vec(),
            frame_number: frame,
            public_key_signature_bls48581: Some(sig),
        }))
    })
    .await
}

pub async fn confirm(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    send_split(pc, &mut client, "confirm", &filters, |chunk| {
        Ok(Request::Confirm(sign::confirm_op(
            &pc.key_manager,
            chunk,
            frame,
        )?))
    })
    .await
}

// `filter` is deprecated in global.proto in favour of the repeated `filters`,
// but it is still on the wire: peers that predate the change send it, and
// dropping it here would change the encoded bytes. Carried through verbatim
// until the field is retired from the proto.
#[allow(deprecated)]
pub async fn reject(pc: &ProverCtx, filter_args: &[String]) -> anyhow::Result<()> {
    let filters = parse_filters(filter_args)?;
    let mut client = pc.connect().await?;
    let frame = pc.last_global_head_frame(&mut client).await?;
    send_split(pc, &mut client, "reject", &filters, |chunk| {
        let sig = sign::reject_sig(&pc.key_manager, chunk, frame)?;
        Ok(Request::Reject(ProverReject {
            filter: Vec::new(), // deprecated field
            frame_number: frame,
            public_key_signature_bls48581: Some(sig),
            filters: chunk.to_vec(),
        }))
    })
    .await
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
    pc.send_global(&mut client, wrap(Request::Pause(op)))
        .await?;
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
    pc.send_global(&mut client, wrap(Request::Resume(op)))
        .await?;
    println!("Prover resume sent successfully");
    Ok(())
}

pub async fn delegate(pc: &ProverCtx, address: &str) -> anyhow::Result<()> {
    let addr_hex = address.strip_prefix("0x").unwrap_or(address);
    let delegate_address = hex::decode(addr_hex)
        .map_err(|_| anyhow::anyhow!("Invalid delegate address: must be 32 bytes hex-encoded"))?;
    if delegate_address.len() != 32 {
        anyhow::bail!("Invalid delegate address: must be 32 bytes hex-encoded");
    }

    let mut client = pc.connect().await?;
    let info = client
        .get_node_info(tonic::Request::new(
            quil_types::proto::node::GetNodeInfoRequest::default(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    if info.epoch_length_frames > 0 {
        quil_types::consensus::set_epoch_length_frames(info.epoch_length_frames);
    }
    quil_types::consensus::init_prover_op_replay_guard_epoch(pc.node_config.p2p.network);
    // From the prover operation replay guard epoch the update signs the head
    // frame, so it cannot be submitted again later; before it the signature
    // covers the delegate address alone (frame 0).
    let frame = quil_execution::global_intrinsic::prover_ops::ProverUpdate::signed_frame(
        info.last_global_head_frame,
    );
    let sig = sign::update_sig(&pc.key_manager, &delegate_address, frame)?;
    let op = ProverUpdate {
        delegate_address: delegate_address.clone(),
        public_key_signature_bls48581: Some(sig),
        frame_number: frame,
    };
    pc.send_global(&mut client, wrap(Request::Update(op)))
        .await?;
    println!(
        "Delegate address updated to 0x{}",
        hex::encode(&delegate_address)
    );
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
        roots.push(
            hex::decode(arg).map_err(|e| anyhow::anyhow!("invalid {} hex: {e}", root_names[i]))?,
        );
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
    pc.send_global(&mut client, wrap(Request::AltShardUpdate(op)))
        .await?;
    println!("Alt shard update sent successfully");
    Ok(())
}

fn wrap(request: Request) -> MessageRequest {
    MessageRequest {
        request: Some(request),
        timestamp: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partial send names the unsent filters as follow-up arguments, so a
    /// re-run does not resend the published messages; a first failure has
    /// nothing to leave out.
    #[test]
    fn a_partial_split_send_lists_the_unsent_filters() {
        let filters: Vec<Vec<u8>> = (0..250u16).map(|n| n.to_be_bytes().to_vec()).collect();
        let error = split_send_error("leave", 1, 3, &filters, 100, "boom").to_string();
        let (head, follow_up) = error.split_once('\n').expect("a follow-up line");
        assert_eq!(
            head,
            "prover leave message 2/3 not sent (100/250 filters sent): boom"
        );
        let args: Vec<&str> = follow_up
            .strip_prefix("send the 150 unsent filters with: qclient node prover leave ")
            .expect("the follow-up command")
            .split(' ')
            .collect();
        assert_eq!(args.len(), 150);
        assert_eq!((args[0], args[149]), ("0064", "00f9"));
        let first = split_send_error("leave", 0, 3, &filters, 0, "boom").to_string();
        assert_eq!(
            first,
            "prover leave message 1/3 not sent (0/250 filters sent): boom"
        );
    }
}
