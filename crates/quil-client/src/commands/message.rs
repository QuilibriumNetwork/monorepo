//! `qclient message …` — inbox messaging via the node's DispatchService.
//!
//! Port of `client/cmd/message/message.go`. Connects to the node's stream
//! endpoint (`:8340`) over the PQNoise transport (the Rust node retired
//! Ed448-TLS on `:8340`), authenticating with the node's Falcon
//! `q-prover-key`.

use std::io::Read;

use clap::{Args, Subcommand};

use quil_types::proto::channel::{
    InboxMessage, InboxMessagePut, InboxMessageRequest, InboxMessageResponse,
};

use crate::alias_store::{self, Store};
use crate::context::{Context, GlobalArgs};
use crate::rpc;

#[derive(Debug, Args)]
pub struct MessageArgs {
    /// DispatchService address (host:port). Defaults to the node's stream
    /// listen address.
    #[arg(long = "rpc", global = true, default_value = "")]
    pub rpc: String,
    #[command(subcommand)]
    pub command: MessageCommand,
}

#[derive(Debug, Subcommand)]
pub enum MessageCommand {
    /// Retrieve messages for an inbox (or `--all`).
    Retrieve {
        inbox: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Output format: text|hex|json.
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Send a message: `<inbox> <recipient|hex> <message|->`.
    Send {
        inbox: String,
        recipient: String,
        message: String,
        /// Interpret the message input as hex.
        #[arg(long)]
        hex: bool,
    },
    /// Display stored messages for an inbox (alias of `retrieve`).
    Show { inbox: String },
    /// Delete a message (unsupported; messages auto-expire after 7 days).
    Delete { inbox: String, message_id: String },
}

struct MessageCtx {
    dispatch_addr: String,
    falcon_key: Vec<u8>,
    alias_store: Option<Store>,
}

impl MessageCtx {
    fn load(global: GlobalArgs, rpc_override: &str) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        let (node_config, dir) = ctx.load_node_config("default")?;
        let alias_store = alias_store::try_load_for_config_dir(&dir);

        let dispatch_addr = if !rpc_override.is_empty() {
            rpc_override.to_string()
        } else {
            let stream = if node_config.p2p.stream_listen_multiaddr.is_empty() {
                "/ip4/0.0.0.0/tcp/8340".to_string()
            } else {
                node_config.p2p.stream_listen_multiaddr.clone()
            };
            let addr = rpc::grpc_multiaddr_to_host_port(&stream)?;
            // Dial localhost for a 0.0.0.0 listener.
            addr.replace("0.0.0.0", "127.0.0.1")
        };

        let key_manager = ctx.key_manager(&node_config, &dir)?;
        let signer = key_manager
            .get_signer_by_id("q-prover-key")
            .map_err(|e| anyhow::anyhow!("get q-prover-key for transport auth: {e}"))?;
        let falcon_key = signer.private_key().to_vec();

        Ok(Self {
            dispatch_addr,
            falcon_key,
            alias_store,
        })
    }

    fn resolve(&self, input: &str) -> Option<Vec<u8>> {
        if let Some(store) = &self.alias_store {
            if let Some((addr, _)) = store.resolve(input) {
                return Some(addr);
            }
        }
        hex::decode(input.strip_prefix("0x").unwrap_or(input)).ok()
    }
}

pub async fn run(global: GlobalArgs, args: &MessageArgs) -> anyhow::Result<()> {
    // `delete` needs no connection.
    if let MessageCommand::Delete { .. } = args.command {
        println!("Manual deletion is not currently supported by the DispatchService.");
        println!("Messages auto-expire after 7 days.");
        return Ok(());
    }

    let mc = MessageCtx::load(global, &args.rpc)?;
    let mut client =
        rpc::connect_dispatch_mtls(&mc.dispatch_addr, mc.falcon_key.clone()).await?;

    match &args.command {
        MessageCommand::Retrieve {
            inbox,
            all,
            since,
            format,
        } => retrieve(&mc, &mut client, inbox.as_deref(), *all, *since, format).await,
        MessageCommand::Show { inbox } => {
            retrieve(&mc, &mut client, Some(inbox), false, 0, "text").await
        }
        MessageCommand::Send {
            inbox,
            recipient,
            message,
            hex,
        } => send(&mc, &mut client, inbox, recipient, message, *hex).await,
        MessageCommand::Delete { .. } => unreachable!(),
    }
}

async fn retrieve(
    mc: &MessageCtx,
    client: &mut quil_types::proto::global::dispatch_service_client::DispatchServiceClient<
        tonic::transport::Channel,
    >,
    inbox: Option<&str>,
    all: bool,
    since: u64,
    format: &str,
) -> anyhow::Result<()> {
    let inbox_name = inbox.unwrap_or("");
    if inbox_name.is_empty() && !all {
        anyhow::bail!(
            "either specify <inbox> or use --all (explicitly acknowledging privacy tradeoffs)"
        );
    }

    let address: Vec<u8> = if !inbox_name.is_empty() {
        mc.resolve(inbox_name)
            .ok_or_else(|| anyhow::anyhow!("inbox must be an alias or hex address"))?
    } else {
        Vec::new()
    };

    // Bloom filter over the first 32 address bytes.
    let filter: Vec<u8> = if address.len() >= 32 {
        quil_hypergraph::addressing::get_bloom_filter_indices(&address[..32], 256, 3).to_vec()
    } else {
        Vec::new()
    };

    let resp: InboxMessageResponse = client
        .get_inbox_messages(tonic::Request::new(InboxMessageRequest {
            filter,
            address: address.clone(),
            from_timestamp: since,
            ..Default::default()
        }))
        .await
        .map_err(|e| anyhow::anyhow!("GetInboxMessages: {e}"))?
        .into_inner();

    if resp.messages.is_empty() {
        if all {
            println!("No messages across all inboxes.");
        } else {
            println!("No messages for inbox {inbox_name:?}.");
        }
        return Ok(());
    }

    for m in &resp.messages {
        println!("- ts={} addr={}", m.timestamp, hex::encode(&m.address));
        println!("{}", fmt_msg(&m.message, format));
        println!();
    }
    Ok(())
}

fn fmt_msg(b: &[u8], format: &str) -> String {
    match format {
        "hex" => hex::encode(b),
        "json" => format!(r#"{{"data":"{}"}}"#, hex::encode(b)),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

async fn send(
    mc: &MessageCtx,
    client: &mut quil_types::proto::global::dispatch_service_client::DispatchServiceClient<
        tonic::transport::Channel,
    >,
    _inbox: &str,
    recipient: &str,
    message: &str,
    as_hex: bool,
) -> anyhow::Result<()> {
    let recipient_addr = mc
        .resolve(recipient)
        .ok_or_else(|| anyhow::anyhow!("recipient must be an alias or hex address"))?;
    if let Some(store) = &mc.alias_store {
        if store.get(recipient).is_some() {
            println!(
                "Resolved alias {recipient:?} to address {}",
                hex::encode(&recipient_addr)
            );
        }
    }

    let msg: Vec<u8> = if message == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        // Trim a single trailing newline (matches Go).
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        buf
    } else if as_hex {
        hex::decode(message.strip_prefix("0x").unwrap_or(message))
            .map_err(|e| anyhow::anyhow!("decode --hex message: {e}"))?
    } else {
        message.as_bytes().to_vec()
    };

    client
        .put_inbox_message(tonic::Request::new(InboxMessagePut {
            message: Some(InboxMessage {
                address: recipient_addr.clone(),
                timestamp: crate::send::now_millis() as u64,
                message: msg.clone(),
                ..Default::default()
            }),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("PutInboxMessage: {e}"))?;

    println!("Sent {} bytes to {}", msg.len(), hex::encode(&recipient_addr));
    Ok(())
}
