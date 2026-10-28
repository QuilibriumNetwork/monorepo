//! `qclient token …` — token operations.
//!
//! QCT3 wallet operations and shared node/RPC/key configuration.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand};

use quil_config::Config;
use quil_keys::FileKeyManager;
use quil_p2p::ed448_identity::Ed448Identity;

use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

mod account;
#[cfg(feature = "confidential-tokens")]
pub(crate) mod balance;
mod legacy;
#[cfg(feature = "confidential-tokens")]
mod wallet;

/// Flags shared by every `token` subcommand (Go `TokenCmd` persistent
/// flags).
#[derive(Debug, Args)]
pub struct TokenCommonArgs {
    /// Use public RPC for token operations.
    #[arg(long = "public-rpc", global = true, default_value_t = false)]
    pub public_rpc: bool,
    /// Path to the node config directory, the one holding config.yml
    /// (default: the default node config). A directory without config.yml is
    /// refused. `token legacy` takes it more than once, after `legacy`.
    #[arg(long = "config", global = true, value_name = "DIR", action = clap::ArgAction::Append)]
    pub config: Vec<String>,
    /// Read wallet state (coins, escrows, witnesses) and other applications'
    /// fee quotes from this node's gRPC multiaddr instead of the configured
    /// node. QUIL fee quotes and submissions still go to the configured node,
    /// whose peer key authenticates them. Use when the configured node does
    /// not hold the application's state (a regular node's master process does
    /// not serve its workers' shard state). The connection is plaintext: a
    /// host other than this one also needs --insecure-read-rpc.
    #[arg(long = "read-rpc", global = true)]
    pub read_rpc: Option<String>,
    /// Allow --read-rpc to name another host over plaintext gRPC, which
    /// anyone on the network path can read and alter.
    #[arg(long = "insecure-read-rpc", global = true, default_value_t = false)]
    pub insecure_read_rpc: bool,
    /// Largest fee in base units paid from a node's quote, and largest QUIL
    /// settlement paid for another application's bundle (default: 0.1 QUIL).
    /// A larger quote is refused; an explicit --fee is not limited.
    #[arg(
        long = "max-fee",
        global = true,
        env = "QUILIBRIUM_MAX_FEE",
        default_value_t = DEFAULT_MAX_AUTOMATIC_FEE
    )]
    pub max_fee: u128,
}

/// Default limit on an automatic fee or bundle settlement: 0.1 QUIL. A QUIL
/// operation's quoted fee is orders of magnitude lower; a settlement reaches it
/// only for a bundle near the 1 MiB quote bound at several times the default
/// application fee vote.
pub const DEFAULT_MAX_AUTOMATIC_FEE: u128 = 800_000_000;

/// Environment variable behind `--max-fee`, also read by paid deploy and
/// hypergraph writes, which have no fee flags of their own.
#[cfg(feature = "native-proof")]
const MAX_FEE_ENV: &str = "QUILIBRIUM_MAX_FEE";

/// The automatic fee limit for a paid write outside `qclient token`.
#[cfg(feature = "native-proof")]
fn max_fee_from_env() -> anyhow::Result<u128> {
    match std::env::var(MAX_FEE_ENV) {
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("{MAX_FEE_ENV} {value:?}: {e}")),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_MAX_AUTOMATIC_FEE),
        Err(e) => Err(anyhow::anyhow!("{MAX_FEE_ENV}: {e}")),
    }
}

impl TokenCommonArgs {
    /// The one `--config` of a command other than `token legacy` (empty: the
    /// default node config).
    fn single_config(&self) -> anyhow::Result<&str> {
        match self.config.as_slice() {
            [] => Ok(""),
            [one] => Ok(one.as_str()),
            several => anyhow::bail!(
                "--config is given {} times; only `token legacy` reads several node configs",
                several.len()
            ),
        }
    }
}

/// Where the node a command reads from was named, for errors that say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeSource {
    /// `--read-rpc`.
    ReadRpc,
    /// `listenGrpcMultiaddr` of the node config in this directory.
    Config(PathBuf),
    /// No node config names one: the node's default listener.
    Default,
}

/// A node to read from, and where it was named.
#[derive(Debug, Clone)]
pub(crate) struct ReadNode {
    pub opts: ConnectOpts,
    pub source: NodeSource,
}

impl ReadNode {
    /// The node as an operator would look it up: its address, then where
    /// that address came from.
    pub(crate) fn describe(&self) -> String {
        if self.opts.is_light_node() {
            return if self.opts.custom_rpc.is_empty() {
                format!(
                    "the public RPC {} (--public-rpc, or publicRpc in the qclient config)",
                    crate::rpc::PUBLIC_RPC_ADDR
                )
            } else {
                format!("{} (customRpc in the qclient config)", self.opts.custom_rpc)
            };
        }
        let multiaddr = self.multiaddr();
        match &self.source {
            NodeSource::ReadRpc => format!("{multiaddr} (--read-rpc)"),
            NodeSource::Config(dir) if self.opts.listen_grpc_multiaddr.is_empty() => format!(
                "{multiaddr} (the node default: {} sets no listenGrpcMultiaddr)",
                dir.join("config.yml").display()
            ),
            NodeSource::Config(dir) => format!(
                "{multiaddr} (listenGrpcMultiaddr in {})",
                dir.join("config.yml").display()
            ),
            NodeSource::Default => format!("{multiaddr} (the node default; no node config found)"),
        }
    }

    /// The gRPC multiaddr dialed, for a node that is not a public RPC.
    pub(crate) fn multiaddr(&self) -> &str {
        if self.opts.listen_grpc_multiaddr.is_empty() {
            quil_config::DEFAULT_LISTEN_GRPC_MULTIADDR
        } else {
            &self.opts.listen_grpc_multiaddr
        }
    }

    /// One key per distinct endpoint, so a command dials each node once.
    pub(crate) fn endpoint_key(&self) -> String {
        if self.opts.is_light_node() {
            format!("rpc:{}", self.opts.custom_rpc)
        } else {
            format!("grpc:{}", self.multiaddr())
        }
    }

    /// What the operator can do when this node does not answer. `default`
    /// is the default node config's listener, suggested when it differs.
    fn remedy(&self, default: Option<&str>) -> String {
        if self.opts.is_light_node() {
            return "Check this host's network access, or read through a running node with \
                    --read-rpc <its listenGrpcMultiaddr>"
                .into();
        }
        let mut remedy = match self.source {
            NodeSource::ReadRpc => "Check that a node runs and listens there: a node's address is \
                 listenGrpcMultiaddr in its own config.yml"
                .to_string(),
            _ => "Is that node running? Pass --read-rpc <multiaddr of a running node>: a \
                  node's address is listenGrpcMultiaddr in its own config.yml"
                .to_string(),
        };
        if let Some(default) = default.filter(|default| *default != self.multiaddr()) {
            remedy.push_str(&format!(" (the default node config has {default})"));
        }
        remedy
    }

    /// Connect, or say which node did not answer, where it was named and
    /// what to do about it.
    pub(crate) async fn connect(
        &self,
        default: Option<&str>,
    ) -> anyhow::Result<
        quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    > {
        crate::rpc::connect_node_service(&self.opts)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot reach the node at {}: {error:#}. {}",
                    self.describe(),
                    self.remedy(default)
                )
            })
    }
}

/// Connection options for `--read-rpc`. The read connection is plaintext h2,
/// so a host other than this one is dialed only with `--insecure-read-rpc`.
fn read_rpc_opts(multiaddr: &str, insecure: bool) -> anyhow::Result<ConnectOpts> {
    anyhow::ensure!(
        insecure || crate::rpc::is_local_multiaddr(multiaddr)?,
        "--read-rpc {multiaddr} is not on this host, and its gRPC connection is plaintext: \
         anyone on the network path can read and alter the wallet state it returns; \
         read through a node on this host, or pass --insecure-read-rpc to accept that"
    );
    Ok(ConnectOpts {
        public_rpc: false,
        custom_rpc: String::new(),
        listen_grpc_multiaddr: multiaddr.to_string(),
    })
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(flatten)]
    pub common: TokenCommonArgs,
    /// Application identifier in hexadecimal (default: QUIL).
    #[arg(long, global = true)]
    pub application: Option<String>,
    /// Maximum discovery pages (up to 8 confidential coins or escrows each);
    /// exhaustion fails rather than returning a partial balance.
    #[arg(long, global = true, default_value_t = 2048)]
    pub max_pages: usize,
    /// Maximum recovered unspent coins retained during discovery.
    #[arg(long, global = true, default_value_t = 1024)]
    pub max_coins: usize,
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
    /// Lists legacy (pre-2.1) coins, their unshielded total and shield readiness.
    ///
    /// Identities: the node config (--config, repeatable after `legacy`;
    /// default: the default node config), every node under --configs-under,
    /// and Ed448 public keys, peer IDs or owner addresses given without any
    /// config. Only config.yml's Ed448 public key is read, never keys.yml.
    /// Coins are read from --read-rpc, else the public RPC (--public-rpc),
    /// else each config's listenGrpcMultiaddr; identities given without a
    /// config ask the default node config's node, else the node default
    /// /ip4/127.0.0.1/tcp/8337.
    #[command(after_long_help = legacy::AFTER_HELP)]
    Legacy(legacy::LegacyArgs),
    /// Transfer a confidential amount to a recipient address (`confidential-address`).
    Transfer {
        /// Recipient QCT3 address.
        recipient: String,
        /// Amount in base units.
        amount: String,
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Print this wallet's confidential (lattice) receiving address.
    ConfidentialAddress,
    /// Discover recoverable pending transfers; admission determines claim eligibility.
    #[cfg(feature = "confidential-tokens")]
    Escrows {
        #[arg(long, default_value_t = 1024)]
        max_escrows: usize,
    },
    /// Shield a transparent coin into a confidential coin owned by this wallet.
    #[cfg(feature = "native-proof")]
    Shield {
        /// Transparent coin address in hexadecimal.
        source: String,
        /// Full transparent amount in base units.
        amount: u128,
        /// Fee in base units (default: node estimate for QUIL, zero for custom tokens).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Shield every unshielded legacy coin of this identity, in batches of up
    /// to 96 legacy coins from one shard each.
    ///
    /// On mainnet, where every legacy coin came from the migration, shields
    /// are admitted from GLOBAL frame 943,920 (the first frame of epoch 1311),
    /// when admission starts matching owners in their migrated form; earlier
    /// shields are refused ("source owner mismatch"), so this command refuses
    /// to start before the node's GLOBAL head reaches it. Batches themselves
    /// are admitted from frame 864,000. `token legacy` shows the plan.
    #[cfg(feature = "native-proof")]
    ShieldAll {
        /// Legacy coins per batch (1 to 96).
        #[arg(long, default_value_t = 96)]
        max_per_batch: usize,
    },
    /// Mint a custom token under its deployed policy.
    #[cfg(feature = "native-proof")]
    CustomMint {
        /// Positive amount in base units.
        amount: u128,
        #[arg(long)]
        recipient: Option<String>,
        #[arg(long = "authority-key", default_value = "q-prover-key")]
        authority_key: String,
        /// Use a free permissionless mint policy.
        #[arg(long)]
        permissionless: bool,
        /// Paid mint policy: the token's payee QUIL address (hex, from
        /// `token payment-address`). The price is paid to it in QUIL.
        #[arg(long)]
        payee: Option<String>,
        /// Paid mint policy: the price in QUIL base units (the token's fee
        /// basis times the amount). The node rejects an underpayment.
        #[arg(long)]
        price: Option<u128>,
        /// Seconds to wait for the payment settlement to be certified.
        #[arg(long, default_value_t = 900)]
        pay_wait: u64,
        /// Proof-basis policy: this mint's entitlement proof (hex), from
        /// `token entitlements`. The authority key must be the entitled key
        /// and the amount the entitled amount.
        #[arg(long)]
        entitlement: Option<String>,
    },
    /// Build a token's mint-entitlement tree: prints the root for the token's
    /// configuration and one proof per entitlement. Each line of the file is
    /// `<Falcon-512 public key hex> <amount>` — application authority keys are
    /// post-quantum only.
    #[cfg(feature = "native-proof")]
    Entitlements {
        /// File listing the entitlements, one per line.
        file: PathBuf,
    },
    /// Print this wallet's QUIL payee address and its 32-byte payment address,
    /// the value a paid-mint token's `payment_address` must hold.
    #[cfg(feature = "native-proof")]
    PaymentAddress,
    /// Merge several coins into one: `merge [all | <Coin>...]` (at most four per transaction).
    Merge {
        /// `all` (default), or coin identifiers (address or one-time key).
        coins: Vec<String>,
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Split one coin into several: `split <Coin> <Amounts>... | --parts N` (at most two outputs per transaction).
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
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Create an acceptable (escrow) transfer to a recipient's escrow address.
    PendingTransfer {
        /// Recipient escrow address from `confidential-address`.
        recipient: String,
        /// Amount in base units.
        amount: String,
        /// Global frame at/after which the sender may reclaim (default: head + ~1 day).
        #[arg(long)]
        expiration: Option<u64>,
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Accept a pending transfer addressed to this wallet: `accept <Escrow>`.
    Accept {
        /// Escrow address (hex) as shown by `token escrows`.
        escrow: String,
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Reject/refund a pending transfer (refunder only, after expiration): `reject <Escrow>`.
    Reject {
        /// Escrow address (hex) as shown by `token escrows`.
        escrow: String,
        /// Fee in base units (default: conservative node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Pay QUIL to another application for one bundle: `pay <Destination> <Amount> <Context>`.
    /// `Context` is the SHA3-256 binding of the destination bundle (all requests
    /// after its claim). Prints the settlement receipt.
    #[cfg(feature = "native-proof")]
    Pay {
        /// Destination application (32-byte hex).
        destination: String,
        /// Settlement amount in base units, available to the destination bundle.
        amount: String,
        /// 32-byte hex binding of the destination bundle.
        context: String,
        /// This settlement's own fee in base units (default: node estimate).
        #[arg(long)]
        fee: Option<u128>,
    },
    /// Pay QUIL to another application for a bundle chosen later:
    /// `prefund <Destination> <Amount>`. The settlement names a claimant key
    /// instead of a bundle; later paid submissions to that application claim it
    /// automatically, and any bundle that key signs may spend it once.
    #[cfg(feature = "native-proof")]
    Prefund {
        /// Destination application (32-byte hex).
        destination: String,
        /// Settlement amount in base units.
        amount: String,
        /// This settlement's own fee in base units (default: node estimate).
        #[arg(long)]
        fee: Option<u128>,
        /// Keystore id of the claimant key that will name the funded bundle.
        /// Must be a Falcon-512 key: claimants are post-quantum only.
        #[arg(long, default_value = "q-prover-key")]
        claimant_key: String,
    },
    /// List this wallet's unconsumed pre-funded settlements.
    #[cfg(feature = "native-proof")]
    Prefunded,
    /// Print the claim (hex) that spends a certified settlement in its destination
    /// bundle: `settlement-claim <Destination> <Receipt> <Amount> <Context>`.
    #[cfg(feature = "native-proof")]
    SettlementClaim {
        destination: String,
        receipt: String,
        amount: String,
        context: String,
        /// Seconds to wait for the settlement's GLOBAL record to be certified.
        #[arg(long, default_value_t = 0)]
        wait: u64,
    },
    /// Claim this prover's reward balance as new coins: `mint [<RecipientAddress>]`.
    /// The reward mint is two-stage: authorize, then `--claim <file>` once finalized.
    Mint {
        /// Optional recipient confidential address (default: self).
        recipient: Option<String>,
        /// Fee in base units paid from the reward (default: the quoted dynamic charge).
        #[arg(long)]
        fee: Option<u128>,
        /// Saved authorization bytes from the first stage; builds and submits the claim.
        #[arg(long)]
        claim: Option<PathBuf>,
    },
}

/// Resolved per-invocation token context (Go `TokenCmd.PersistentPreRun`).
pub struct TokenCtx {
    pub node_config: Config,
    pub config_dir: PathBuf,
    pub key_manager: Arc<FileKeyManager>,
    pub connect_opts: ConnectOpts,
    /// Connection to the configured node for authenticated submissions.
    pub submit_opts: ConnectOpts,
    /// The managing peer id bytes (34-byte libp2p multihash) derived from
    /// `config.p2p.peer_priv_key`. EMPTY on a Falcon-only node, which carries
    /// no pre-migration Ed448 key.
    pub peer_id_bytes: Vec<u8>,
    /// Largest automatic fee or bundle settlement, in base units, paid from a
    /// node's quote (`--max-fee`).
    pub max_fee: u128,
}

impl TokenCtx {
    /// Legacy coin address = `poseidon(peerId)` (32 bytes). Only a node that
    /// still carries its pre-migration Ed448 key has one.
    pub fn legacy_address(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            !self.peer_id_bytes.is_empty(),
            "this node has no Ed448 identity, so it has no legacy coin address"
        );
        Ok(quil_crypto::poseidon::hash_bytes_to_32(&self.peer_id_bytes)
            .map_err(|e| anyhow::anyhow!("poseidon address: {e}"))?
            .to_vec())
    }

    /// Connect a `NodeServiceClient` per the resolved connection options.
    pub async fn connect(
        &self,
    ) -> anyhow::Result<
        quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    > {
        // Read options differ from the submission's only by --read-rpc.
        let read_rpc = self.connect_opts.listen_grpc_multiaddr
            != self.submit_opts.listen_grpc_multiaddr
            || self.connect_opts.is_light_node() != self.submit_opts.is_light_node();
        ReadNode {
            opts: self.connect_opts.clone(),
            source: if read_rpc {
                NodeSource::ReadRpc
            } else {
                NodeSource::Config(self.config_dir.clone())
            },
        }
        .connect(None)
        .await
    }

    /// Connect to the configured node for an authenticated submission.
    pub async fn connect_submit(
        &self,
    ) -> anyhow::Result<
        quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    > {
        ReadNode {
            opts: self.submit_opts.clone(),
            source: NodeSource::Config(self.config_dir.clone()),
        }
        .connect(None)
        .await
    }

    fn load(global: GlobalArgs, common: &TokenCommonArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        println!("Loading node config...");
        let (node_config, config_dir) = ctx.load_node_config(common.single_config()?)?;

        // The Ed448 identity is kept ONLY for the legacy coin address
        // (`poseidon(ed448 peerId)`, `legacy_address()` below). The peer id we
        // DISPLAY is the current FALCON network identity — the Ed448 one is the
        // pre-migration peer id and printing it is misleading.
        // A Falcon-only node carries no Ed448 key at all, and nothing a wallet
        // does needs one: it survives here only for the legacy coin address
        // and as a display fallback. Refusing to open a wallet because a
        // pre-migration field is absent locks a holder out of their coins.
        let identity = Ed448Identity::from_config_hex(&node_config.p2p.peer_priv_key).ok();

        let key_manager = ctx.key_manager(&node_config, &config_dir)?;
        match key_manager.get_public_key_bytes_by_id("q-prover-key") {
            Ok(falcon_pub) => {
                println!(
                    "{}",
                    quil_p2p::peer_id_base58_from_falcon_pubkey(&falcon_pub)
                );
            }
            // Fall back to the legacy Ed448 peer id only if the Falcon network key
            // is absent (a pre-migration keystore).
            Err(_) => match &identity {
                Some(identity) => println!("{}", identity.peer_id_base58()),
                None => println!("(no network identity configured)"),
            },
        }
        let submit_opts = ctx.connect_opts(&node_config, common.public_rpc);
        let connect_opts = match &common.read_rpc {
            Some(multiaddr) => read_rpc_opts(multiaddr, common.insecure_read_rpc)?,
            None => submit_opts.clone(),
        };

        Ok(Self {
            node_config,
            config_dir,
            key_manager,
            connect_opts,
            submit_opts,
            peer_id_bytes: identity
                .map(|identity| identity.peer_id_bytes)
                .unwrap_or_default(),
            max_fee: common.max_fee,
        })
    }
}

/// Price a QUIL operation by the world state its admission will add. Input
/// markers are counted at the circuit's input limit (a few dozen bytes each)
/// because coin selection follows the fee; outputs are counted exactly.
#[cfg(feature = "native-proof")]
async fn operation_fee(
    tc: &TokenCtx,
    application: &str,
    explicit: Option<u128>,
    shape: quil_execution::token_intrinsic::cost::Shape,
) -> anyhow::Result<u128> {
    let decoded = hex::decode(application)?;
    anyhow::ensure!(decoded.len() == 32, "application must be exactly 32 bytes");
    if decoded == quil_execution::domains::QUIL_TOKEN {
        wallet::quoted_quil_fee(tc, explicit, shape, false).await
    } else {
        let fee = explicit.unwrap_or(0);
        // Custom-token outflow carries no token fee; the operation's QUIL fee
        // is paid by a settlement claim submitted with it.
        anyhow::ensure!(
            fee == 0,
            "custom-token operations carry no token fee; their QUIL fee is paid by a settlement"
        );
        Ok(fee)
    }
}

/// Pay, in QUIL from this node's wallet, for a bundle of writes to another
/// application, and return the claim to place first in that bundle.
///
/// `rest` is the destination bundle with its first request left empty; the
/// claim replaces it. The settlement covers the destination venue's quoted
/// charge for the bundle's state growth (plus the claim's marker) with the
/// automatic headroom, and is bound to `rest` by `bundle_context`. Waits up to
/// `wait` for the settlement's GLOBAL record to be certified.
#[cfg(feature = "native-proof")]
pub(crate) async fn pay_for_bundle(
    global: GlobalArgs,
    destination: [u8; 32],
    rest: &quil_execution::message_envelope::CanonicalMessageBundle,
    wait: std::time::Duration,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let common = TokenCommonArgs {
        public_rpc: false,
        config: Vec::new(),
        read_rpc: None,
        insecure_read_rpc: false,
        max_fee: max_fee_from_env()?,
    };
    let tc = TokenCtx::load(global, &common)?;
    wallet::pay_for_bundle(&tc, destination, rest, None, wait).await
}

pub async fn run(global: GlobalArgs, args: &TokenArgs) -> anyhow::Result<()> {
    // Legacy coins are listed by public key alone: no keystore, and possibly
    // several identities.
    if let TokenCommand::Legacy(listing) = &args.command {
        return legacy::run(global, &args.common, &application(args)?, listing).await;
    }
    let tc = TokenCtx::load(global, &args.common)?;
    run_with_context(&tc, args).await
}

/// The `--application` identifier (default: QUIL).
fn application(args: &TokenArgs) -> anyhow::Result<[u8; 32]> {
    match &args.application {
        None => Ok(quil_execution::domains::QUIL_TOKEN),
        Some(application) => hex::decode(application)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("application must be exactly 32 bytes")),
    }
}

/// Shared command dispatch after configuration and keys have been loaded.
async fn run_with_context(tc: &TokenCtx, args: &TokenArgs) -> anyhow::Result<()> {
    let application = args
        .application
        .clone()
        .unwrap_or_else(|| hex::encode(quil_execution::domains::QUIL_TOKEN));
    let decoded = hex::decode(&application)?;
    anyhow::ensure!(decoded.len() == 32, "application must be exactly 32 bytes");
    #[cfg(feature = "confidential-tokens")]
    match &args.command {
        TokenCommand::Balance => {
            return wallet::run_balance(&tc, &application, args.max_pages, args.max_coins).await
        }
        TokenCommand::Coins => {
            return wallet::run_coins(&tc, &application, args.max_pages, args.max_coins).await
        }
        TokenCommand::ConfidentialAddress => {
            wallet::run(&tc, &application, false)?;
            return wallet::run(&tc, &application, true);
        }
        TokenCommand::Escrows { max_escrows } => {
            return wallet::run_escrows(&tc, &application, args.max_pages, *max_escrows).await
        }
        _ => {}
    }
    #[cfg(feature = "native-proof")]
    {
        let parse_amount = |value: &str| {
            value
                .parse::<u128>()
                .map_err(|e| anyhow::anyhow!("amount {value:?}: {e}"))
        };
        let parse_id = |value: &str| -> anyhow::Result<[u8; 32]> {
            hex::decode(value.trim_start_matches("0x"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{value:?} must be exactly 32 bytes of hex"))
        };
        use quil_execution::token_intrinsic::cost::Shape;
        let max_inputs = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
            tc.node_config.p2p.network,
        )
        .limits
        .max_inputs;
        let spend = |coins: usize| Shape {
            coins,
            markers: max_inputs,
            escrow: false,
        };
        match &args.command {
            TokenCommand::Transfer {
                recipient,
                amount,
                fee,
            } => {
                return wallet::run_transfer(
                    &tc,
                    &application,
                    recipient,
                    parse_amount(amount)?,
                    *fee,
                    args.max_pages,
                    args.max_coins,
                )
                .await
            }
            TokenCommand::Merge { coins, fee } => {
                return wallet::run_merge(
                    &tc,
                    &application,
                    coins,
                    operation_fee(&tc, &application, *fee, spend(1)).await?,
                    args.max_pages,
                    args.max_coins,
                )
                .await
            }
            TokenCommand::Split {
                coin,
                amounts,
                parts,
                part_amount,
                fee,
            } => {
                let pieces: Vec<u128> = match (parts, part_amount) {
                    (Some(parts), Some(part_amount)) => {
                        anyhow::ensure!(*parts <= 2, "split supports at most two outputs");
                        vec![parse_amount(part_amount)?; *parts as usize]
                    }
                    (Some(_), None) => anyhow::bail!("--parts requires --part-amount"),
                    (None, _) => amounts
                        .iter()
                        .map(|amount| parse_amount(amount))
                        .collect::<anyhow::Result<_>>()?,
                };
                return wallet::run_split(
                    &tc,
                    &application,
                    coin,
                    &pieces,
                    operation_fee(
                        &tc,
                        &application,
                        *fee,
                        Shape {
                            coins: pieces.len().max(1),
                            markers: 1,
                            escrow: false,
                        },
                    )
                    .await?,
                    args.max_pages,
                    args.max_coins,
                )
                .await;
            }
            TokenCommand::PendingTransfer {
                recipient,
                amount,
                expiration,
                fee,
            } => {
                return wallet::run_pending_create(
                    &tc,
                    &application,
                    recipient,
                    parse_amount(amount)?,
                    operation_fee(
                        &tc,
                        &application,
                        *fee,
                        Shape {
                            coins: 1,
                            markers: max_inputs,
                            escrow: true,
                        },
                    )
                    .await?,
                    *expiration,
                    args.max_pages,
                    args.max_coins,
                )
                .await
            }
            TokenCommand::Accept { escrow, fee } => {
                return wallet::run_claim(
                    &tc,
                    &application,
                    escrow,
                    operation_fee(
                        &tc,
                        &application,
                        *fee,
                        Shape {
                            coins: 1,
                            markers: 1,
                            escrow: false,
                        },
                    )
                    .await?,
                    false,
                )
                .await
            }
            TokenCommand::Reject { escrow, fee } => {
                return wallet::run_claim(
                    &tc,
                    &application,
                    escrow,
                    operation_fee(
                        &tc,
                        &application,
                        *fee,
                        Shape {
                            coins: 1,
                            markers: 1,
                            escrow: false,
                        },
                    )
                    .await?,
                    true,
                )
                .await
            }
            TokenCommand::Mint {
                recipient,
                fee,
                claim,
            } => {
                anyhow::ensure!(
                    decoded == quil_execution::domains::QUIL_TOKEN,
                    "reward mint requires the QUIL application; use custom-mint for custom tokens"
                );
                // The mint pays its own state-growth charge (one coin and the
                // receipt marker) out of the minted amount.
                let mint_fee = if claim.is_some() {
                    0
                } else {
                    // Reward mints execute in the global venue: quote its pricing.
                    wallet::quoted_quil_fee(
                        &tc,
                        *fee,
                        Shape {
                            coins: 1,
                            markers: 1,
                            escrow: false,
                        },
                        true,
                    )
                    .await?
                };
                return wallet::run_mint(&tc, recipient.as_deref(), mint_fee, claim.as_deref())
                    .await;
            }
            TokenCommand::ShieldAll { max_per_batch } => {
                return wallet::run_shield_all(&tc, &application, *max_per_batch).await
            }
            TokenCommand::Shield {
                source,
                amount,
                fee,
            } => {
                return wallet::run_shield(
                    &tc,
                    &application,
                    source,
                    *amount,
                    operation_fee(
                        &tc,
                        &application,
                        *fee,
                        Shape {
                            coins: 1,
                            markers: 1,
                            escrow: false,
                        },
                    )
                    .await?,
                )
                .await
            }
            TokenCommand::Pay {
                destination,
                amount,
                context,
                fee,
            } => {
                wallet::run_pay(
                    &tc,
                    parse_id(destination)?,
                    parse_amount(amount)?,
                    wallet::SettlementBinding::Bundle(parse_id(context)?),
                    *fee,
                    None,
                    args.max_pages,
                    args.max_coins,
                )
                .await?;
                return Ok(());
            }
            TokenCommand::Prefund {
                destination,
                amount,
                fee,
                claimant_key,
            } => {
                return wallet::run_prefund(
                    &tc,
                    parse_id(destination)?,
                    parse_amount(amount)?,
                    *fee,
                    claimant_key,
                    args.max_pages,
                    args.max_coins,
                )
                .await
            }
            TokenCommand::Prefunded => return wallet::run_prefunded(&tc).await,
            TokenCommand::SettlementClaim {
                destination,
                receipt,
                amount,
                context,
                wait,
            } => {
                let claim = wallet::settlement_claim(
                    &tc,
                    parse_id(destination)?,
                    parse_id(receipt)?,
                    parse_amount(amount)?,
                    &wallet::ClaimBinding::Bundle(parse_id(context)?),
                    None,
                    std::time::Duration::from_secs(*wait),
                )
                .await?;
                println!("{}", hex::encode(claim));
                return Ok(());
            }
            TokenCommand::Entitlements { file } => return wallet::run_entitlements(&tc, file),
            TokenCommand::CustomMint {
                amount,
                recipient,
                authority_key,
                permissionless,
                payee,
                price,
                pay_wait,
                entitlement,
            } => {
                let paid = match (payee, price) {
                    (Some(payee), Some(price)) => Some((
                        payee.as_str(),
                        *price,
                        std::time::Duration::from_secs(*pay_wait),
                    )),
                    (None, None) => None,
                    _ => anyhow::bail!("a paid mint needs both --payee and --price"),
                };
                let entitlement = match entitlement {
                    Some(hex) => hex::decode(hex.strip_prefix("0x").unwrap_or(hex))?,
                    None => Vec::new(),
                };
                return wallet::run_custom_mint(
                    &tc,
                    &application,
                    *amount,
                    recipient.as_deref(),
                    authority_key,
                    *permissionless,
                    paid,
                    entitlement,
                )
                .await;
            }
            TokenCommand::PaymentAddress => return wallet::run_payment_address(&tc),
            _ => {}
        }
    }
    match &args.command {
        TokenCommand::Account => account::run(&tc),
        TokenCommand::Legacy(listing) => {
            let application: [u8; 32] = decoded.as_slice().try_into().expect("checked above");
            legacy::run_loaded(tc, &application, listing).await
        }
        _ => anyhow::bail!(
            "this build does not include support for this confidential token operation"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TokenCli {
        #[command(flatten)]
        token: TokenArgs,
    }

    #[test]
    fn token_cli_uses_one_command_family_for_all_applications() {
        let app = hex::encode([7; 32]);
        let parsed = TokenCli::try_parse_from([
            "token",
            "transfer",
            "recipient",
            "9",
            "--application",
            &app,
            "--fee",
            "0",
            "--max-pages",
            "4",
            "--max-coins",
            "8",
        ])
        .unwrap();
        assert_eq!(parsed.token.application.as_deref(), Some(app.as_str()));
        assert_eq!((parsed.token.max_pages, parsed.token.max_coins), (4, 8));
        assert!(matches!(
            parsed.token.command,
            TokenCommand::Transfer { fee: Some(0), .. }
        ));
        #[cfg(feature = "native-proof")]
        {
            assert!(TokenCli::try_parse_from(["token", "shield", "coin", "9"]).is_ok());
            assert!(
                TokenCli::try_parse_from(["token", "custom-mint", "9", "--application", &app])
                    .is_ok()
            );
            // Paid and proof-basis mints, and the entitlement tree builder.
            assert!(TokenCli::try_parse_from([
                "token",
                "custom-mint",
                "9",
                "--application",
                &app,
                "--payee",
                "00",
                "--price",
                "5"
            ])
            .is_ok());
            assert!(matches!(
                TokenCli::try_parse_from([
                    "token",
                    "custom-mint",
                    "9",
                    "--application",
                    &app,
                    "--entitlement",
                    "00"
                ])
                .unwrap()
                .token
                .command,
                TokenCommand::CustomMint {
                    entitlement: Some(_),
                    ..
                }
            ));
            assert!(matches!(
                TokenCli::try_parse_from(["token", "entitlements", "list.txt"])
                    .unwrap()
                    .token
                    .command,
                TokenCommand::Entitlements { .. }
            ));
            assert!(TokenCli::try_parse_from(["token", "payment-address"]).is_ok());
            // Pre-funding: a settlement paid before its bundle exists.
            assert!(
                matches!(TokenCli::try_parse_from(["token", "prefund", &app, "500"]).unwrap().token.command,
                TokenCommand::Prefund { claimant_key, .. } if claimant_key == "q-prover-key")
            );
            assert!(TokenCli::try_parse_from(["token", "prefunded"]).is_ok());
            assert!(
                TokenCli::try_parse_from(["token", "mint", "--claim", "authorization.bin"]).is_ok()
            );
        }
    }

    #[test]
    fn token_cli_takes_the_fee_limit_and_the_insecure_read_switch() {
        let parsed = TokenCli::try_parse_from(["token", "balance"]).unwrap();
        assert!(!parsed.token.common.insecure_read_rpc);
        let parsed = TokenCli::try_parse_from([
            "token",
            "--read-rpc",
            "/ip4/192.0.2.7/tcp/8337",
            "balance",
            "--insecure-read-rpc",
            "--max-fee",
            "5000",
        ])
        .unwrap();
        assert!(parsed.token.common.insecure_read_rpc);
        assert_eq!(parsed.token.common.max_fee, 5000);
    }

    #[test]
    fn read_rpc_to_another_host_needs_the_insecure_switch() {
        for local in [
            "/ip4/127.0.0.1/tcp/8337",
            "/ip4/0.0.0.0/tcp/8337",
            "/ip6/::1/tcp/8337",
            "/dns/localhost/tcp/8337",
        ] {
            let opts = read_rpc_opts(local, false).unwrap();
            assert_eq!(opts.listen_grpc_multiaddr, local);
            assert!(!opts.is_light_node());
        }
        for remote in [
            "/ip4/192.0.2.7/tcp/8337",
            "/ip6/2001:db8::7/tcp/8337",
            "/dns4/rpc.example.com/tcp/8337",
        ] {
            let error = read_rpc_opts(remote, false).unwrap_err().to_string();
            assert!(error.contains("--insecure-read-rpc"), "{error}");
            assert_eq!(
                read_rpc_opts(remote, true).unwrap().listen_grpc_multiaddr,
                remote
            );
        }
        assert!(read_rpc_opts("not-a-multiaddr", false).is_err());
    }

    /// `token legacy` takes several identities and output switches; every
    /// other command still reads exactly one config.
    #[test]
    fn token_legacy_takes_identities_and_other_commands_one_config() {
        let owner = format!("0x{}", hex::encode([3; 32]));
        let parsed = TokenCli::try_parse_from([
            "token",
            "legacy",
            "--config",
            "one/.config",
            "--config",
            "two/.config",
            "--configs-under",
            "nodes",
            "--ed448-pub",
            "00",
            "--peer-id",
            "QmPeer",
            "--owner",
            &owner,
            "--summary",
            "--json",
        ])
        .unwrap();
        assert_eq!(parsed.token.common.config, ["one/.config", "two/.config"]);
        let TokenCommand::Legacy(listing) = &parsed.token.command else {
            panic!("not the legacy command");
        };
        assert_eq!(listing.configs_under, [PathBuf::from("nodes")]);
        assert_eq!(
            (
                &listing.ed448_pub[..],
                &listing.peer_id[..],
                &listing.owner[..]
            ),
            (
                &["00".to_string()][..],
                &["QmPeer".to_string()][..],
                &[owner][..]
            )
        );
        assert!(listing.summary && listing.json);
        // Nothing given: the default config, per-coin text.
        let TokenCommand::Legacy(plain) = TokenCli::try_parse_from(["token", "legacy"])
            .unwrap()
            .token
            .command
        else {
            panic!("not the legacy command");
        };
        assert!(!plain.summary && !plain.json && plain.ed448_pub.is_empty());

        // The output switches belong to `legacy` alone.
        assert!(TokenCli::try_parse_from(["token", "balance", "--summary"]).is_err());
        assert!(TokenCli::try_parse_from(["token", "balance", "--json"]).is_err());
        let once = TokenCli::try_parse_from(["token", "--config", "one", "balance"]).unwrap();
        assert_eq!(once.token.common.single_config().unwrap(), "one");
        let none = TokenCli::try_parse_from(["token", "balance"]).unwrap();
        assert_eq!(none.token.common.single_config().unwrap(), "");
        let twice =
            TokenCli::try_parse_from(["token", "balance", "--config", "a", "--config", "b"])
                .unwrap();
        let error = twice.token.common.single_config().unwrap_err().to_string();
        assert!(error.contains("only `token legacy`"), "{error}");
    }

    /// `token legacy --help` documents its JSON schema, and `shield-all`'s
    /// help names the frame mainnet admits shields of migrated coins from.
    #[test]
    fn token_help_documents_the_legacy_schema_and_the_shield_frame() {
        use clap::CommandFactory;
        let mut command = TokenCli::command();
        let legacy = command
            .find_subcommand_mut("legacy")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(legacy.contains(legacy::JSON_SCHEMA), "{legacy}");
        assert!(legacy.contains("--configs-under"), "{legacy}");
        #[cfg(feature = "native-proof")]
        {
            let shield_all = command
                .find_subcommand_mut("shield-all")
                .unwrap()
                .render_long_help()
                .to_string();
            use quil_execution::token_intrinsic::legacy_migration::MAINNET_MIGRATED_OWNER_FRAME;
            assert_eq!(
                MAINNET_MIGRATED_OWNER_FRAME, 943_920,
                "update the shield-all help"
            );
            assert!(shield_all.contains("943,920"), "{shield_all}");
        }
    }

    /// An unreachable node is named with where its address came from and
    /// what to do, not only as a transport error.
    #[tokio::test]
    async fn an_unreachable_node_is_named_with_its_source_and_the_fix() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        drop(listener);
        let config_dir = PathBuf::from("old-node").join(".config");
        let node = ReadNode {
            opts: ConnectOpts {
                public_rpc: false,
                custom_rpc: String::new(),
                listen_grpc_multiaddr: dead.clone(),
            },
            source: NodeSource::Config(config_dir.clone()),
        };
        let error = node
            .connect(Some("/ip4/127.0.0.1/tcp/8888"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with(&format!("cannot reach the node at {dead}")),
            "{error}"
        );
        assert!(
            error.contains(&format!(
                "(listenGrpcMultiaddr in {})",
                config_dir.join("config.yml").display()
            )),
            "{error}"
        );
        assert!(error.contains("Pass --read-rpc"), "{error}");
        assert!(
            error.contains("(the default node config has /ip4/127.0.0.1/tcp/8888)"),
            "{error}"
        );
        // The default node config's own listener is not suggested back.
        let error = node
            .connect(Some(dead.as_str()))
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("the default node config has"), "{error}");

        let read = ReadNode {
            source: NodeSource::ReadRpc,
            ..node.clone()
        };
        assert_eq!(read.describe(), format!("{dead} (--read-rpc)"));
        let default = ReadNode {
            opts: ConnectOpts::default(),
            source: NodeSource::Default,
        };
        assert_eq!(
            default.describe(),
            "/ip4/127.0.0.1/tcp/8337 (the node default; no node config found)"
        );
        let public = ReadNode {
            opts: ConnectOpts {
                public_rpc: true,
                ..ConnectOpts::default()
            },
            source: NodeSource::Default,
        };
        assert!(public.describe().starts_with("the public RPC"));
        assert_ne!(public.endpoint_key(), default.endpoint_key());
    }

    #[test]
    fn token_cli_has_no_retired_suite_switch() {
        let parsed = TokenCli::try_parse_from(["token", "balance"]).unwrap();
        assert!(matches!(parsed.token.command, TokenCommand::Balance));
        assert!(TokenCli::try_parse_from(["token", "--legacy", "balance"]).is_err());
        assert!(TokenCli::try_parse_from(["token", "balance", "--legacy"]).is_err());
    }
}
