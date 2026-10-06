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
mod balance;
#[cfg(feature = "confidential-tokens")]
mod wallet;

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
    /// Read wallet state (coins, escrows, witnesses, fee quotes) from this
    /// node's gRPC multiaddr instead of the configured node. Submissions still
    /// go to the configured node, whose peer key authenticates them. Use when
    /// the configured node does not hold the application's state (a regular
    /// node's master process does not serve its workers' shard state).
    #[arg(long = "read-rpc", global = true)]
    pub read_rpc: Option<String>,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(flatten)]
    pub common: TokenCommonArgs,
    /// Application identifier in hexadecimal (default: QUIL).
    #[arg(long, global = true)]
    pub application: Option<String>,
    /// Maximum discovery pages; exhaustion fails rather than returning a partial balance.
    #[arg(long, global = true, default_value_t = 128)]
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
    #[allow(dead_code)]
    pub config_dir: PathBuf,
    pub key_manager: Arc<FileKeyManager>,
    pub connect_opts: ConnectOpts,
    /// Connection to the configured node for authenticated submissions.
    pub submit_opts: ConnectOpts,
    /// The managing peer id bytes (34-byte libp2p multihash) derived from
    /// `config.p2p.peer_priv_key`. EMPTY on a Falcon-only node, which carries
    /// no pre-migration Ed448 key.
    pub peer_id_bytes: Vec<u8>,
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
        quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
    > {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// Connect to the configured node for an authenticated submission.
    pub async fn connect_submit(
        &self,
    ) -> anyhow::Result<
        quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
    > {
        crate::rpc::connect_node_service(&self.submit_opts).await
    }

    fn load(global: GlobalArgs, common: &TokenCommonArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        println!("Loading node config...");
        let (node_config, config_dir) = ctx.load_node_config(&common.config)?;

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
                println!("{}", quil_p2p::peer_id_base58_from_falcon_pubkey(&falcon_pub));
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
            Some(multiaddr) => ConnectOpts {
                public_rpc: false, custom_rpc: String::new(), listen_grpc_multiaddr: multiaddr.clone(),
            },
            None => submit_opts.clone(),
        };

        Ok(Self {
            node_config,
            config_dir,
            key_manager,
            connect_opts,
            submit_opts,
            peer_id_bytes: identity.map(|identity| identity.peer_id_bytes).unwrap_or_default(),
        })
    }
}

/// Price a QUIL operation by the world state its admission will add. Input
/// markers are counted at the circuit's input limit (a few dozen bytes each)
/// because coin selection follows the fee; outputs are counted exactly.
#[cfg(feature = "native-proof")]
async fn operation_fee(
    tc: &TokenCtx, application: &str, explicit: Option<u128>,
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
        anyhow::ensure!(fee == 0, "custom-token operations carry no token fee; their QUIL fee is paid by a settlement");
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
    let common = TokenCommonArgs { public_rpc: false, config: String::new(), read_rpc: None };
    let tc = TokenCtx::load(global, &common)?;
    wallet::pay_for_bundle(&tc, destination, rest, None, wait).await
}

pub async fn run(global: GlobalArgs, args: &TokenArgs) -> anyhow::Result<()> {
    let tc = TokenCtx::load(global, &args.common)?;
    run_with_context(&tc, args).await
}

/// Shared command dispatch after configuration and keys have been loaded.
async fn run_with_context(tc: &TokenCtx, args: &TokenArgs) -> anyhow::Result<()> {
    let application = args.application.clone().unwrap_or_else(|| hex::encode(quil_execution::domains::QUIL_TOKEN));
    let decoded = hex::decode(&application)?;
    anyhow::ensure!(decoded.len() == 32, "application must be exactly 32 bytes");
    #[cfg(feature = "confidential-tokens")]
    match &args.command {
        TokenCommand::Balance => return wallet::run_balance(&tc, &application, args.max_pages, args.max_coins).await,
        TokenCommand::Coins => return wallet::run_coins(&tc, &application, args.max_pages, args.max_coins).await,
        TokenCommand::ConfidentialAddress => {
            wallet::run(&tc, &application, false)?;
            return wallet::run(&tc, &application, true);
        }
        TokenCommand::Escrows { max_escrows } =>
            return wallet::run_escrows(&tc, &application, args.max_pages, *max_escrows).await,
        _ => {}
    }
    #[cfg(feature = "native-proof")]
    {
        let parse_amount = |value: &str| value.parse::<u128>().map_err(|e| anyhow::anyhow!("amount {value:?}: {e}"));
        let parse_id = |value: &str| -> anyhow::Result<[u8; 32]> {
            hex::decode(value.trim_start_matches("0x"))?.try_into()
                .map_err(|_| anyhow::anyhow!("{value:?} must be exactly 32 bytes of hex"))
        };
        use quil_execution::token_intrinsic::cost::Shape;
        let max_inputs = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(tc.node_config.p2p.network).limits.max_inputs;
        let spend = |coins: usize| Shape { coins, markers: max_inputs, escrow: false };
        match &args.command {
            TokenCommand::Transfer { recipient, amount, fee } =>
                return wallet::run_transfer(&tc, &application, recipient, parse_amount(amount)?, *fee, args.max_pages, args.max_coins).await,
            TokenCommand::Merge { coins, fee } =>
                return wallet::run_merge(&tc, &application, coins, operation_fee(&tc, &application, *fee, spend(1)).await?, args.max_pages, args.max_coins).await,
            TokenCommand::Split { coin, amounts, parts, part_amount, fee } => {
                let pieces: Vec<u128> = match (parts, part_amount) {
                    (Some(parts), Some(part_amount)) => {
                        anyhow::ensure!(*parts <= 2, "split supports at most two outputs");
                        vec![parse_amount(part_amount)?; *parts as usize]
                    }
                    (Some(_), None) => anyhow::bail!("--parts requires --part-amount"),
                    (None, _) => amounts.iter().map(|amount| parse_amount(amount)).collect::<anyhow::Result<_>>()?,
                };
                return wallet::run_split(&tc, &application, coin, &pieces, operation_fee(&tc, &application, *fee, Shape { coins: pieces.len().max(1), markers: 1, escrow: false }).await?, args.max_pages, args.max_coins).await;
            }
            TokenCommand::PendingTransfer { recipient, amount, expiration, fee } =>
                return wallet::run_pending_create(&tc, &application, recipient, parse_amount(amount)?, operation_fee(&tc, &application, *fee, Shape { coins: 1, markers: max_inputs, escrow: true }).await?, *expiration, args.max_pages, args.max_coins).await,
            TokenCommand::Accept { escrow, fee } =>
                return wallet::run_claim(&tc, &application, escrow, operation_fee(&tc, &application, *fee, Shape { coins: 1, markers: 1, escrow: false }).await?, false).await,
            TokenCommand::Reject { escrow, fee } =>
                return wallet::run_claim(&tc, &application, escrow, operation_fee(&tc, &application, *fee, Shape { coins: 1, markers: 1, escrow: false }).await?, true).await,
            TokenCommand::Mint { recipient, fee, claim } => {
                anyhow::ensure!(decoded == quil_execution::domains::QUIL_TOKEN, "reward mint requires the QUIL application; use custom-mint for custom tokens");
                // The mint pays its own state-growth charge (one coin and the
                // receipt marker) out of the minted amount.
                let mint_fee = if claim.is_some() { 0 } else {
                    // Reward mints execute in the global venue: quote its pricing.
                    wallet::quoted_quil_fee(&tc, *fee, Shape { coins: 1, markers: 1, escrow: false }, true).await?
                };
                return wallet::run_mint(&tc, recipient.as_deref(), mint_fee, claim.as_deref()).await;
            }
            TokenCommand::Shield { source, amount, fee } =>
                return wallet::run_shield(&tc, &application, source, *amount, operation_fee(&tc, &application, *fee, Shape { coins: 1, markers: 1, escrow: false }).await?).await,
            TokenCommand::Pay { destination, amount, context, fee } => {
                wallet::run_pay(&tc, parse_id(destination)?, parse_amount(amount)?,
                    wallet::SettlementBinding::Bundle(parse_id(context)?), *fee, None,
                    args.max_pages, args.max_coins).await?;
                return Ok(());
            }
            TokenCommand::Prefund { destination, amount, fee, claimant_key } =>
                return wallet::run_prefund(&tc, parse_id(destination)?, parse_amount(amount)?, *fee, claimant_key,
                    args.max_pages, args.max_coins).await,
            TokenCommand::Prefunded => return wallet::run_prefunded(&tc).await,
            TokenCommand::SettlementClaim { destination, receipt, amount, context, wait } => {
                let claim = wallet::settlement_claim(&tc, parse_id(destination)?, parse_id(receipt)?, parse_amount(amount)?,
                    &wallet::ClaimBinding::Bundle(parse_id(context)?), None, std::time::Duration::from_secs(*wait)).await?;
                println!("{}", hex::encode(claim));
                return Ok(());
            }
            TokenCommand::Entitlements { file } => return wallet::run_entitlements(&tc, file),
            TokenCommand::CustomMint { amount, recipient, authority_key, permissionless, payee, price, pay_wait, entitlement } => {
                let paid = match (payee, price) {
                    (Some(payee), Some(price)) => Some((payee.as_str(), *price, std::time::Duration::from_secs(*pay_wait))),
                    (None, None) => None,
                    _ => anyhow::bail!("a paid mint needs both --payee and --price"),
                };
                let entitlement = match entitlement {
                    Some(hex) => hex::decode(hex.strip_prefix("0x").unwrap_or(hex))?,
                    None => Vec::new(),
                };
                return wallet::run_custom_mint(&tc, &application, *amount, recipient.as_deref(), authority_key, *permissionless, paid, entitlement).await;
            }
            TokenCommand::PaymentAddress => return wallet::run_payment_address(&tc),
            _ => {}
        }
    }
    match &args.command {
        TokenCommand::Account => account::run(&tc),
        _ => anyhow::bail!("this build does not include support for this confidential token operation"),
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
        let parsed = TokenCli::try_parse_from(["token", "transfer", "recipient", "9", "--application", &app,
            "--fee", "0", "--max-pages", "4", "--max-coins", "8"]).unwrap();
        assert_eq!(parsed.token.application.as_deref(), Some(app.as_str()));
        assert_eq!((parsed.token.max_pages, parsed.token.max_coins), (4, 8));
        assert!(matches!(parsed.token.command, TokenCommand::Transfer { fee: Some(0), .. }));
        #[cfg(feature = "native-proof")]
        {
            assert!(TokenCli::try_parse_from(["token", "shield", "coin", "9"]).is_ok());
            assert!(TokenCli::try_parse_from(["token", "custom-mint", "9", "--application", &app]).is_ok());
            // Paid and proof-basis mints, and the entitlement tree builder.
            assert!(TokenCli::try_parse_from(["token", "custom-mint", "9", "--application", &app,
                "--payee", "00", "--price", "5"]).is_ok());
            assert!(matches!(TokenCli::try_parse_from(["token", "custom-mint", "9", "--application", &app,
                "--entitlement", "00"]).unwrap().token.command, TokenCommand::CustomMint { entitlement: Some(_), .. }));
            assert!(matches!(TokenCli::try_parse_from(["token", "entitlements", "list.txt"]).unwrap().token.command,
                TokenCommand::Entitlements { .. }));
            assert!(TokenCli::try_parse_from(["token", "payment-address"]).is_ok());
            // Pre-funding: a settlement paid before its bundle exists.
            assert!(matches!(TokenCli::try_parse_from(["token", "prefund", &app, "500"]).unwrap().token.command,
                TokenCommand::Prefund { claimant_key, .. } if claimant_key == "q-prover-key"));
            assert!(TokenCli::try_parse_from(["token", "prefunded"]).is_ok());
            assert!(TokenCli::try_parse_from(["token", "mint", "--claim", "authorization.bin"]).is_ok());
        }
    }

    #[test]
    fn token_cli_has_no_retired_suite_switch() {
        let parsed = TokenCli::try_parse_from(["token", "balance"]).unwrap();
        assert!(matches!(parsed.token.command, TokenCommand::Balance));
        assert!(TokenCli::try_parse_from(["token", "--legacy", "balance"]).is_err());
        assert!(TokenCli::try_parse_from(["token", "balance", "--legacy"]).is_err());
    }
}
