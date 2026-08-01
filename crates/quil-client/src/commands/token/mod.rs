//! `qclient token …` — token operations.
//!
//! Read-only subcommands (`account`, `balance`, `coins`) are implemented
//! here; the crypto write subcommands (`transfer`, `mint`, …) are added in
//! a later phase. Shared setup (client + node config, key manager,
//! connection options, managing peer id) is gathered in [`TokenCtx`],
//! mirroring the Go `TokenCmd` `PersistentPreRun`.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand};

use quil_config::Config;
use quil_keys::FileKeyManager;
use quil_p2p::ed448_identity::Ed448Identity;

use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

mod account;
mod address;
mod balance;
mod coins;
mod lattice;
mod merge;
mod mint;
mod pending;
mod split;
mod transfer;

/// Flags shared by every `token` subcommand (Go `TokenCmd` persistent
/// flags).
#[derive(Debug, Args)]
pub struct TokenCommonArgs {
    /// Use public RPC for token operations.
    #[arg(long = "public-rpc", global = true, default_value_t = false)]
    pub public_rpc: bool,
    /// Path to the node config directory.
    #[arg(long = "config", global = true, default_value = "")]
    pub config: String,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(flatten)]
    pub common: TokenCommonArgs,
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Shows the account address of the managing account.
    Account,
    /// Lists the total balance of tokens in the managing account.
    Balance,
    /// Lists all coins under control of the managing account.
    Coins,
    /// Transfer a confidential amount to a recipient lattice address.
    Transfer {
        /// Recipient address: hex(kem_pk ‖ wire(B)).
        recipient: String,
        /// Amount in base units.
        amount: String,
    },
    /// Print this wallet's confidential (lattice) receiving address.
    ConfidentialAddress,
    /// Merge several coins into one: `merge [all | <Coin>...]`.
    Merge {
        /// `all` (default), or coin identifiers (address or one-time key).
        coins: Vec<String>,
    },
    /// Split one coin into several: `split <Coin> <Amounts>... | --parts N`.
    Split {
        /// Coin to split (address as shown by `token coins`, or one-time key).
        coin: String,
        /// Explicit output amounts in base units (mutually exclusive with --parts).
        amounts: Vec<String>,
        /// Split into N parts instead of explicit amounts.
        #[arg(long)]
        parts: Option<u32>,
        /// With --parts, each part's amount (base units); remainder returned.
        #[arg(long = "part-amount")]
        part_amount: Option<String>,
    },
    /// Create an acceptable (escrow) transfer to a recipient's pending address.
    PendingTransfer {
        /// Recipient escrow address: hex(kem_pk ‖ falcon_pk) (see `confidential-address`).
        recipient: String,
        /// Amount in base units.
        amount: String,
        /// Frame at/after which the sender may reclaim (default: head + ~1 day).
        #[arg(long)]
        expiration: Option<u64>,
    },
    /// Accept a pending transfer addressed to this wallet: `accept <Escrow>`.
    Accept {
        /// Escrow address (hex) as shown by `token coins`.
        escrow: String,
    },
    /// Reject/refund a pending transfer (refunder only, after expiration): `reject <Escrow>`.
    Reject {
        /// Escrow address (hex) as shown by `token coins`.
        escrow: String,
    },
    /// Claim this prover's reward balance as new coins: `mint [<RecipientAddress>]`.
    Mint {
        /// Optional recipient confidential address (default: self).
        recipient: Option<String>,
    },
}

/// Resolved per-invocation token context (Go `TokenCmd.PersistentPreRun`).
pub struct TokenCtx {
    pub node_config: Config,
    #[allow(dead_code)]
    pub config_dir: PathBuf,
    pub key_manager: Arc<FileKeyManager>,
    pub connect_opts: ConnectOpts,
    /// The managing peer id bytes (34-byte libp2p multihash) derived from
    /// `config.p2p.peer_priv_key`.
    pub peer_id_bytes: Vec<u8>,
}

impl TokenCtx {
    /// Legacy coin address = `poseidon(peerId)` (32 bytes).
    pub fn legacy_address(&self) -> anyhow::Result<Vec<u8>> {
        Ok(quil_crypto::poseidon::hash_bytes_to_32(&self.peer_id_bytes)
            .map_err(|e| anyhow::anyhow!("poseidon address: {e}"))?
            .to_vec())
    }

    /// Token account address = `view_public ‖ spend_public` (112 bytes),
    /// creating the Decaf448 agreement keys on first use.
    pub fn view_spend_address(&self) -> anyhow::Result<Vec<u8>> {
        let vk = get_or_create_agreement(&self.key_manager, "q-view-key")?;
        let sk = get_or_create_agreement(&self.key_manager, "q-spend-key")?;
        Ok([vk, sk].concat())
    }

    /// Connect a `NodeServiceClient` per the resolved connection options.
    pub async fn connect(
        &self,
    ) -> anyhow::Result<
        quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
    > {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    fn load(global: GlobalArgs, common: &TokenCommonArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        println!("Loading node config...");
        let (node_config, config_dir) = ctx.load_node_config(&common.config)?;

        let identity = Ed448Identity::from_config_hex(&node_config.p2p.peer_priv_key)
            .map_err(|e| anyhow::anyhow!("derive peer id: {e}"))?;
        println!("{}", identity.peer_id_base58());

        let key_manager = ctx.key_manager(&node_config, &config_dir)?;
        let connect_opts = ctx.connect_opts(&node_config, common.public_rpc);

        Ok(Self {
            node_config,
            config_dir,
            key_manager,
            connect_opts,
            peer_id_bytes: identity.peer_id_bytes,
        })
    }
}

/// Get an agreement key's public bytes, creating a Decaf448 key on first
/// use. Mirrors Go's `GetAgreementKey`-or-`CreateAgreementKey` fallback.
fn get_or_create_agreement(km: &FileKeyManager, id: &str) -> anyhow::Result<Vec<u8>> {
    if let Some(pk) = km.public_key_by_id(id)? {
        return Ok(pk);
    }
    km.create_agreement_key(id, 4) // Decaf448
        .map_err(|e| anyhow::anyhow!("create {id}: {e}"))?;
    km.public_key_by_id(id)?
        .ok_or_else(|| anyhow::anyhow!("agreement key {id} missing after create"))
}

pub async fn run(global: GlobalArgs, args: &TokenArgs) -> anyhow::Result<()> {
    let tc = TokenCtx::load(global, &args.common)?;
    match &args.command {
        TokenCommand::Account => account::run(&tc),
        TokenCommand::Balance => balance::run(&tc).await,
        TokenCommand::Coins => coins::run(&tc).await,
        TokenCommand::Transfer { recipient, amount } => transfer::run(&tc, recipient, amount).await,
        TokenCommand::ConfidentialAddress => address::run(&tc),
        TokenCommand::Merge { coins } => merge::run(&tc, coins).await,
        TokenCommand::Split {
            coin,
            amounts,
            parts,
            part_amount,
        } => split::run(&tc, coin, amounts, *parts, part_amount.as_deref()).await,
        TokenCommand::PendingTransfer {
            recipient,
            amount,
            expiration,
        } => pending::create(&tc, recipient, amount, *expiration).await,
        TokenCommand::Accept { escrow } => pending::claim(&tc, escrow, true).await,
        TokenCommand::Reject { escrow } => pending::claim(&tc, escrow, false).await,
        TokenCommand::Mint { recipient } => mint::run(&tc, recipient.as_deref()).await,
    }
}
