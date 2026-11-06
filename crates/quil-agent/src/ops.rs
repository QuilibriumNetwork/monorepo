//! Tool implementations. Reads run immediately. Anything that signs or
//! sends is stored as a confirmation and runs only from [`confirm`] on this host.

use std::collections::HashMap;
use std::time::Instant;

use quil_client::commands::token::{self, AgentQuote, TokenArgs};
use quil_client::context::{Context, GlobalArgs};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::auth::Access;
use crate::config::{Settings, CONFIRM_TTL};
use crate::slippage;

/// A quote waiting for its confirmation id.
#[derive(Clone)]
pub struct Pending {
    argv: Vec<String>,
    quote: AgentQuote,
    created: Instant,
}

#[derive(Default)]
pub struct PendingStore {
    items: HashMap<String, Pending>,
}

impl PendingStore {
    pub fn insert(&mut self, argv: Vec<String>, quote: AgentQuote, now: Instant) -> String {
        self.sweep(now);
        let id = crate::config::random_hex(16);
        self.items.insert(
            id.clone(),
            Pending {
                argv,
                quote,
                created: now,
            },
        );
        id
    }

    fn sweep(&mut self, now: Instant) {
        self.items
            .retain(|_, pending| now.saturating_duration_since(pending.created) < CONFIRM_TTL);
    }

    pub fn take(&mut self, id: &str, now: Instant) -> Result<Pending, &'static str> {
        self.sweep(now);
        match self.items.remove(id) {
            Some(pending) if now.saturating_duration_since(pending.created) < CONFIRM_TTL => {
                Ok(pending)
            }
            Some(_) => Err("that confirmation expired; prepare the command again"),
            None => Err("unknown confirmation; prepare the command again"),
        }
    }

    pub fn restore(&mut self, id: String, pending: Pending) {
        self.items.insert(id, pending);
    }

    /// Quotes still inside the confirmation window, oldest first.
    pub fn waiting(&mut self, now: Instant) -> Vec<(String, AgentQuote)> {
        self.sweep(now);
        let mut items: Vec<_> = self
            .items
            .iter()
            .map(|(id, pending)| (pending.created, id.clone(), pending.quote.clone()))
            .collect();
        items.sort_by_key(|(created, _, _)| *created);
        items
            .into_iter()
            .map(|(_, id, quote)| (id, quote))
            .collect()
    }
}

/// A tool result. `is_error` is the MCP tool error flag.
pub struct ToolOutput {
    pub text: String,
    pub is_error: bool,
}

impl ToolOutput {
    fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    pub(crate) fn err(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

fn global_args(settings: &Settings) -> GlobalArgs {
    GlobalArgs {
        network: settings.network.clone(),
        yes: false,
    }
}

/// Insert `--config` when the operator named a node config and the
/// arguments did not.
pub fn prepare_argv(argv: Vec<String>, settings: &Settings) -> Vec<String> {
    let mut argv = argv;
    if !settings.node_config.is_empty() && !argv.iter().any(|arg| arg == "--config") {
        argv.insert(0, settings.node_config.clone());
        argv.insert(0, "--config".into());
    }
    argv
}

/// The agent's cap applies when the arguments omit `--max-fee`. An explicit
/// `--max-fee` cannot raise that cap.
pub fn apply_fee_cap(mut args: TokenArgs, argv: &[String], cap: u128) -> TokenArgs {
    if argv.iter().any(|arg| arg == "--max-fee") {
        args.common.max_fee = args.common.max_fee.min(cap);
    } else {
        args.common.max_fee = cap;
    }
    args
}

fn parse(argv: &[String], settings: &Settings) -> Result<TokenArgs, ToolOutput> {
    let args = token::parse_token_argv(argv).map_err(|err| ToolOutput::err(err.to_string()))?;
    Ok(apply_fee_cap(args, argv, settings.max_fee))
}

/// What the MCP client may see. `host` is printed on this machine only.
pub struct Outcome {
    pub client: ToolOutput,
    pub host: String,
}

impl Outcome {
    pub(crate) fn client(output: ToolOutput) -> Self {
        Self {
            client: output,
            host: String::new(),
        }
    }

    fn both(client: ToolOutput, host: impl Into<String>) -> Self {
        Self {
            client,
            host: host.into(),
        }
    }
}

/// Client-facing failure. The operator's terminal gets the underlying error.
pub const BALANCE_UNAVAILABLE: &str = "balance unavailable";
/// Client-facing failure for `node_info`.
pub const NODE_UNAVAILABLE: &str = "node info unavailable";
/// Client-facing failure for `token_prepare`.
pub const QUOTE_UNAVAILABLE: &str = "quote unavailable";
/// What a quote tool returns. The confirmation id is not in it.
pub const QUOTE_WAITING: &str = "A quote is waiting on the qagent terminal. Nothing has been sent. Tell the user to look at that terminal. Do not invent a confirmation id. This session cannot submit.";
/// A quote tool's arguments could not be turned into a command.
pub const COMMAND_NOT_UNDERSTOOD: &str = "That command was not understood. Use transfer_quote, mint_quote, shield_quote, merge_quote, split_quote, pay_quote, or accept_quote. Amounts are QUIL, such as 1 or 0.5. 1 QUIL is 8000000000 base units. Do not pass base units.";
/// `token_submit` and address-listing reads are not MCP tools.
pub const CANNOT_SUBMIT: &str = "this session cannot submit or list addresses";

const PATH_FLAGS: &[&str] = &[
    "--config",
    "--submit-config",
    "--configs-under",
    "--read-rpc",
];
const PATH_SWITCHES: &[&str] = &["--public-rpc", "--insecure-read-rpc"];

/// Drop flags that would point a command at a different config, keystore, or RPC.
pub fn strip_client_paths(argv: Vec<String>) -> Vec<String> {
    let mut kept = Vec::with_capacity(argv.len());
    let mut skip_value = false;
    for arg in argv {
        if skip_value {
            skip_value = false;
            continue;
        }
        let flag = arg
            .split_once('=')
            .map(|(flag, _)| flag)
            .unwrap_or(arg.as_str());
        if PATH_SWITCHES.contains(&flag) {
            continue;
        }
        if PATH_FLAGS.contains(&flag) {
            if !arg.contains('=') {
                skip_value = true;
            }
            continue;
        }
        kept.push(arg);
    }
    kept
}

/// Node status. The peer id is included only for a full key, and the config path never is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFacts {
    pub version: String,
    pub peer_id: String,
    pub running_workers: String,
    pub allocated_workers: String,
    pub worker_capacity: String,
    pub last_global_head_frame: String,
    pub last_received_frame: String,
    pub current_epoch: String,
    pub epoch_length_frames: String,
    pub reachable: String,
}

impl NodeFacts {
    /// Text for an MCP client. A read-only key does not receive the peer id.
    pub fn for_client(&self, access: Access) -> String {
        let mut lines = vec![
            format!("Version: {}", self.version),
            format!(
                "Workers: {} running, {} allocated, capacity {}",
                self.running_workers, self.allocated_workers, self.worker_capacity
            ),
            format!("Global head frame: {}", self.last_global_head_frame),
            format!("Last received frame: {}", self.last_received_frame),
            format!(
                "Epoch: {} ({} frames)",
                self.current_epoch, self.epoch_length_frames
            ),
            format!("Reachable: {}", self.reachable),
        ];
        if access == Access::Full {
            lines.insert(1, format!("Peer: {}", self.peer_id));
        }
        lines.join("\n")
    }
}

/// Runs token and node work. [`Host::Process`] does it in a helper that exits.
/// The MCP process does not open the keystore.
#[derive(Clone)]
pub enum Host {
    /// Spawn `qagent worker` and wait for it to exit.
    Process,
    /// Canned answers for tests.
    #[cfg(test)]
    Script(std::sync::Arc<Script>),
}

/// Canned helper results.
#[cfg(test)]
pub struct Script {
    pub balance: std::sync::Mutex<Result<String, String>>,
    pub node: std::sync::Mutex<Result<NodeFacts, String>>,
    pub previews: std::sync::Mutex<Vec<Result<AgentQuote, String>>>,
    pub execute: std::sync::Mutex<Result<String, String>>,
}

impl Host {
    pub fn process() -> Self {
        Self::Process
    }

    #[cfg(test)]
    pub fn script(script: Script) -> Self {
        Self::Script(std::sync::Arc::new(script))
    }

    pub async fn balance(&self, settings: &Settings) -> Result<String, String> {
        match self {
            Self::Process => crate::worker::balance(settings).await,
            #[cfg(test)]
            Self::Script(script) => script.balance.lock().expect("balance script").clone(),
        }
    }

    pub async fn node_info(&self, settings: &Settings) -> Result<NodeFacts, String> {
        match self {
            Self::Process => crate::worker::node_info(settings).await,
            #[cfg(test)]
            Self::Script(script) => script.node.lock().expect("node script").clone(),
        }
    }

    pub async fn preview(
        &self,
        settings: &Settings,
        argv: Vec<String>,
    ) -> Result<AgentQuote, String> {
        match self {
            Self::Process => crate::worker::preview(settings, argv).await,
            #[cfg(test)]
            Self::Script(script) => script
                .previews
                .lock()
                .expect("preview script")
                .pop()
                .unwrap_or_else(|| Err("no scripted preview".into())),
        }
    }

    pub async fn execute(&self, settings: &Settings, argv: Vec<String>) -> Result<String, String> {
        match self {
            Self::Process => crate::worker::execute(settings, argv).await,
            #[cfg(test)]
            Self::Script(script) => script.execute.lock().expect("execute script").clone(),
        }
    }
}

/// Totals only. The helper always runs `token balance`, never the client's argv.
pub async fn balance(host: &Host, settings: &Settings) -> Outcome {
    match host.balance(settings).await {
        Ok(text) => Outcome::client(ToolOutput::ok(text)),
        Err(err) => {
            tracing::warn!("balance unavailable");
            tell_host("Balance", &err);
            Outcome::client(ToolOutput::err(BALANCE_UNAVAILABLE))
        }
    }
}

/// Worker counts and frames. The peer id is omitted for a read-only key.
pub async fn node_info(host: &Host, settings: &Settings, access: Access) -> Outcome {
    match host.node_info(settings).await {
        Ok(facts) => Outcome::client(ToolOutput::ok(facts.for_client(access))),
        Err(err) => {
            tracing::warn!("node info unavailable");
            tell_host("Node info", &err);
            Outcome::client(ToolOutput::err(NODE_UNAVAILABLE))
        }
    }
}

/// Quote a submitting command. The client hears that a quote is waiting.
/// The quote and its confirmation id are returned in [`Outcome::host`].
pub async fn prepare(
    host: &Host,
    settings: &Settings,
    pending: &Mutex<PendingStore>,
    argv: Vec<String>,
    now: Instant,
) -> Outcome {
    let argv = prepare_argv(strip_client_paths(argv), settings);
    let args = match parse(&argv, settings) {
        Ok(args) => args,
        Err(output) => {
            tell_host("Quote", &output.text);
            return Outcome::client(ToolOutput::err(COMMAND_NOT_UNDERSTOOD));
        }
    };
    if !args.command.submits() {
        return Outcome::client(ToolOutput::err("this command only reads; call balance"));
    }
    let quote = match host.preview(settings, argv.clone()).await {
        Ok(quote) if quote.submits => quote,
        Ok(_) => {
            return Outcome::client(ToolOutput::err("this command only reads; call balance"));
        }
        Err(err) => {
            tracing::warn!("quote unavailable");
            tell_host("Quote", &err);
            return Outcome::client(ToolOutput::err(QUOTE_UNAVAILABLE));
        }
    };
    let id = pending.lock().await.insert(argv, quote.clone(), now);
    Outcome::both(
        ToolOutput::ok(QUOTE_WAITING),
        format!(
            "Quote waiting.\n{}",
            slippage::confirmation_text(&quote, &id, settings.fee_slippage_bps)
        ),
    )
}

/// Submit `id` from the host. The reply is for the operator, including a new
/// confirmation id when the quote moved.
pub async fn confirm(
    host: &Host,
    settings: &Settings,
    pending: &Mutex<PendingStore>,
    id: &str,
    now: Instant,
) -> String {
    let stored = match pending.lock().await.take(id, now) {
        Ok(stored) => stored,
        Err(err) => return err.to_string(),
    };
    let latest = match host.preview(settings, stored.argv.clone()).await {
        Ok(latest) => latest,
        Err(err) => {
            pending.lock().await.restore(id.to_string(), stored);
            return format!(
                "{err}\n\nThe confirmation is still valid until it expires.\n{}",
                crate::guide::failure_hint()
            );
        }
    };
    if let Err(drift) = slippage::accept_requote(&stored.quote, &latest, settings.fee_slippage_bps)
    {
        let new_id = pending
            .lock()
            .await
            .insert(stored.argv, latest.clone(), now);
        return format!(
            "The quote moved ({drift}), so nothing was sent.\n{}",
            slippage::confirmation_text(&latest, &new_id, settings.fee_slippage_bps)
        );
    }
    match host.execute(settings, stored.argv).await {
        Ok(text) => {
            let mut message = String::from(
                "Submitted. Inclusion is not final until the node admits the transaction.",
            );
            if !text.is_empty() {
                message.push('\n');
                message.push_str(&text);
            }
            message
        }
        Err(err) => format!(
            "{err}\n\nNothing was sent, and nothing was retried. Ask for the quote again before another confirm.\n{}",
            crate::guide::failure_hint()
        ),
    }
}

/// `token balance` in the helper. This opens the keystore.
pub async fn run_balance(settings: &Settings) -> Result<String, String> {
    let argv = prepare_argv(vec!["balance".into()], settings);
    let args = parse(&argv, settings).map_err(|output| output.text)?;
    token::agent_execute(global_args(settings), &args)
        .await
        .map_err(|err| format!("{err:#}"))
}

/// Node status in the helper.
pub async fn run_node_info(settings: &Settings) -> Result<NodeFacts, String> {
    read_node_info(settings)
        .await
        .map_err(|err| format!("{err:#}"))
}

/// Quote in the helper. This opens the keystore and does not submit.
pub async fn run_preview(settings: &Settings, argv: Vec<String>) -> Result<AgentQuote, String> {
    let args = parse(&argv, settings).map_err(|output| output.text)?;
    token::agent_preview(global_args(settings), &args)
        .await
        .map_err(|err| format!("{err:#}"))
}

/// Sign and submit in the helper.
pub async fn run_execute(settings: &Settings, argv: Vec<String>) -> Result<String, String> {
    let args = parse(&argv, settings).map_err(|output| output.text)?;
    token::agent_execute(global_args(settings), &args)
        .await
        .map_err(|err| format!("{err:#}"))
}

async fn read_node_info(settings: &Settings) -> anyhow::Result<NodeFacts> {
    let ctx = Context::load(global_args(settings))?;
    let (node_config, _config_dir) = ctx.load_node_config(&settings.node_config)?;
    let opts = ctx.connect_opts(&node_config, false);
    let mut client = quil_client::rpc::connect_node_service(&opts).await?;
    let info = client
        .get_node_info(tonic::Request::new(
            quil_types::proto::node::GetNodeInfoRequest {},
        ))
        .await?
        .into_inner();
    Ok(NodeFacts {
        version: String::from_utf8_lossy(&info.version).into_owned(),
        peer_id: info.peer_id,
        running_workers: info.running_workers.to_string(),
        allocated_workers: info.allocated_workers.to_string(),
        worker_capacity: info.worker_capacity.to_string(),
        last_global_head_frame: info.last_global_head_frame.to_string(),
        last_received_frame: info.last_received_frame.to_string(),
        current_epoch: info.current_epoch.to_string(),
        epoch_length_frames: info.epoch_length_frames.to_string(),
        reachable: info.reachable.to_string(),
    })
}

fn tell_host(what: &str, err: &str) {
    eprintln!(
        "{what} failed.\n\n{err}\n\n{}",
        crate::guide::failure_hint()
    );
}

/// What `qagent status` prints when this process is the one that is running.
pub async fn status_report(
    settings: &Settings,
    pending: &Mutex<PendingStore>,
    now: Instant,
) -> String {
    let waiting = pending.lock().await.waiting(now);
    let quotes = waiting
        .iter()
        .map(|(id, quote)| crate::guide::WaitingQuote {
            id: id.clone(),
            detail: slippage::confirmation_text(quote, id, settings.fee_slippage_bps),
        })
        .collect::<Vec<_>>();
    crate::guide::status(settings, Some(&quotes))
}

/// Turn a QUIL decimal such as `1` or `0.5` into base units.
/// A large whole number is refused: it is almost always base units pasted by mistake.
pub fn quil_to_base(amount: &str) -> Result<u128, String> {
    let amount = amount.trim();
    if amount.is_empty() {
        return Err("Say the amount in QUIL, such as 1 or 0.5.".into());
    }
    if !amount.contains('.') {
        let digits = amount.trim_start_matches('+');
        if digits.len() >= 7 && digits.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(format!(
                "{amount} is too large to be a QUIL amount. Amounts are in QUIL, such as 1 or 0.5. 1 QUIL is 8000000000 base units. Do not paste base units."
            ));
        }
    }
    let units = quil_client::util::parse_quil_amount(amount)
        .map_err(|err| format!("Amount must be QUIL, such as 1 or 0.5. {err}"))?;
    if units == 0 {
        return Err("Amount must be more than zero QUIL.".into());
    }
    Ok(units)
}

fn reject_flag(value: &str, what: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("Say the {what}."));
    }
    if value.starts_with('-') {
        return Err(format!(
            "The {what} cannot start with '-'. Pass the {what} itself, not a flag."
        ));
    }
    Ok(())
}

fn push_fee(argv: &mut Vec<String>, fee_quil: Option<&str>) -> Result<(), String> {
    let Some(fee) = fee_quil.map(str::trim).filter(|fee| !fee.is_empty()) else {
        return Ok(());
    };
    argv.push("--fee".into());
    argv.push(quil_to_base(fee)?.to_string());
    Ok(())
}

/// `transfer` of `quil` (a decimal such as `1`) to `recipient`.
pub fn transfer_argv(
    recipient: &str,
    quil: &str,
    fee_quil: Option<&str>,
) -> Result<Vec<String>, String> {
    reject_flag(recipient, "recipient address")?;
    let mut argv = vec![
        "transfer".into(),
        recipient.trim().to_string(),
        quil_to_base(quil)?.to_string(),
    ];
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// First step of claiming a prover reward. The claim file stays on this computer.
pub fn mint_argv(recipient: Option<&str>, fee_quil: Option<&str>) -> Result<Vec<String>, String> {
    let mut argv = vec!["mint".into()];
    if let Some(recipient) = recipient.map(str::trim).filter(|value| !value.is_empty()) {
        reject_flag(recipient, "recipient address")?;
        argv.push(recipient.to_string());
    }
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// Shield one transparent coin. `quil` is that coin's full amount.
pub fn shield_argv(
    source: &str,
    quil: &str,
    fee_quil: Option<&str>,
) -> Result<Vec<String>, String> {
    reject_flag(source, "coin address")?;
    let mut argv = vec![
        "shield".into(),
        source.trim().to_string(),
        quil_to_base(quil)?.to_string(),
    ];
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// Merge every coin, or the coins named in `coins`.
pub fn merge_argv(coins: &[String], fee_quil: Option<&str>) -> Result<Vec<String>, String> {
    let mut argv = vec!["merge".into()];
    if coins.is_empty() {
        argv.push("all".into());
    } else {
        for coin in coins {
            reject_flag(coin, "coin address")?;
            argv.push(coin.trim().to_string());
        }
    }
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// Split `coin` into QUIL `amounts`, or into `parts` of `part_quil` each.
pub fn split_argv(
    coin: &str,
    amounts_quil: &[String],
    parts: Option<u32>,
    part_quil: Option<&str>,
    fee_quil: Option<&str>,
) -> Result<Vec<String>, String> {
    reject_flag(coin, "coin address")?;
    let mut argv = vec!["split".into(), coin.trim().to_string()];
    match (amounts_quil.is_empty(), parts) {
        (false, Some(_)) => {
            return Err(
                "Say either the output amounts in QUIL, or parts and part_quil. Not both.".into(),
            );
        }
        (true, None) => {
            return Err(
                "Say how to split the coin: amounts in QUIL, such as [\"0.5\", \"0.5\"], or parts and part_quil."
                    .into(),
            );
        }
        (false, None) => {
            for amount in amounts_quil {
                argv.push(quil_to_base(amount)?.to_string());
            }
        }
        (true, Some(parts)) => {
            if parts != 2 {
                return Err("A split makes 2 parts. Pass parts as 2 and part_quil as the size of each part in QUIL.".into());
            }
            let Some(part_quil) = part_quil.map(str::trim).filter(|value| !value.is_empty()) else {
                return Err(
                    "parts needs part_quil, the size of each part in QUIL, such as 0.5.".into(),
                );
            };
            argv.push("--parts".into());
            argv.push(parts.to_string());
            argv.push("--part-amount".into());
            argv.push(quil_to_base(part_quil)?.to_string());
        }
    }
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// Pay `quil` to an application's `destination`. `context` is the 32-byte hex binding.
pub fn pay_argv(
    destination: &str,
    quil: &str,
    context: &str,
    fee_quil: Option<&str>,
) -> Result<Vec<String>, String> {
    reject_flag(destination, "destination")?;
    reject_flag(context, "context")?;
    let mut argv = vec![
        "pay".into(),
        destination.trim().to_string(),
        quil_to_base(quil)?.to_string(),
        context.trim().to_string(),
    ];
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

/// Accept a pending transfer. `escrow` is the escrow address.
pub fn accept_argv(escrow: &str, fee_quil: Option<&str>) -> Result<Vec<String>, String> {
    reject_flag(escrow, "escrow address")?;
    let mut argv = vec!["accept".into(), escrow.trim().to_string()];
    push_fee(&mut argv, fee_quil)?;
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Access;
    use crate::config::{ApiKey, KeyAccess};
    use std::time::Instant;
    use tokio::sync::Mutex;

    fn settings(cap: u128) -> Settings {
        Settings {
            listen: "127.0.0.1:8350".into(),
            keys: vec![
                ApiKey::new("operator", "k", KeyAccess::Full),
                ApiKey::new("read-only", "r", KeyAccess::ReadOnly),
            ],
            fee_slippage_bps: 200,
            max_fee: cap,
            node_config: String::new(),
            network: None,
            config_path: std::path::PathBuf::from("qagent.yaml"),
        }
    }

    #[test]
    fn the_agent_cap_replaces_an_omitted_max_fee_and_limits_a_named_one() {
        let bare = token::parse_token_argv(["balance"]).unwrap();
        let capped = apply_fee_cap(bare, &["balance".into()], 25);
        assert_eq!(capped.common.max_fee, 25);
        let named = token::parse_token_argv(["balance", "--max-fee", "40"]).unwrap();
        let capped = apply_fee_cap(
            named,
            &["balance".into(), "--max-fee".into(), "40".into()],
            25,
        );
        assert_eq!(capped.common.max_fee, 25);
        let named = token::parse_token_argv(["balance", "--max-fee", "10"]).unwrap();
        let capped = apply_fee_cap(
            named,
            &["balance".into(), "--max-fee".into(), "10".into()],
            25,
        );
        assert_eq!(capped.common.max_fee, 10);
    }

    #[test]
    fn a_configured_node_is_inserted_unless_the_arguments_already_name_one() {
        let settings = Settings {
            node_config: "/node".into(),
            ..settings(1)
        };
        assert_eq!(
            prepare_argv(vec!["balance".into()], &settings),
            vec!["--config", "/node", "balance"]
        );
        assert_eq!(
            prepare_argv(
                vec!["--config".into(), "/other".into(), "balance".into()],
                &settings
            ),
            vec!["--config", "/other", "balance"]
        );
    }

    fn quote(text: &str, fee: u128) -> AgentQuote {
        AgentQuote {
            submits: true,
            text: text.into(),
            fee: Some(fee),
            fee_explicit: false,
            max_fee: 1_000_000,
            variable_amount: None,
        }
    }

    fn facts() -> NodeFacts {
        NodeFacts {
            version: "1".into(),
            peer_id: "peer-secret".into(),
            running_workers: "1".into(),
            allocated_workers: "2".into(),
            worker_capacity: "3".into(),
            last_global_head_frame: "4".into(),
            last_received_frame: "5".into(),
            current_epoch: "6".into(),
            epoch_length_frames: "7".into(),
            reachable: "true".into(),
        }
    }

    fn script(preview: Result<AgentQuote, String>) -> Host {
        Host::script(Script {
            balance: std::sync::Mutex::new(Ok("1 QUIL".into())),
            node: std::sync::Mutex::new(Ok(facts())),
            previews: std::sync::Mutex::new(vec![preview]),
            execute: std::sync::Mutex::new(Ok("sent".into())),
        })
    }

    #[test]
    fn a_client_config_path_is_removed_and_a_fee_flag_stays() {
        assert_eq!(
            strip_client_paths(vec![
                "transfer".into(),
                "to".into(),
                "1".into(),
                "--config".into(),
                "/evil".into(),
                "--config=/also".into(),
                "--public-rpc".into(),
                "--fee".into(),
                "9".into(),
            ]),
            vec!["transfer", "to", "1", "--fee", "9"]
        );
    }

    #[test]
    fn a_read_only_status_omits_the_peer_id() {
        let facts = facts();
        let read_only = facts.for_client(Access::ReadOnly);
        assert!(!read_only.contains("peer-secret"), "{read_only}");
        assert!(!read_only.contains("Config"), "{read_only}");
        assert!(read_only.contains("Workers: 1 running"));
        assert!(facts.for_client(Access::Full).contains("Peer: peer-secret"));
    }

    #[tokio::test]
    async fn prepare_refuses_a_read_and_an_unknown_confirmation_does_not_submit() {
        let settings = settings(1);
        let pending = Mutex::new(PendingStore::default());
        let prepared = prepare(
            &Host::process(),
            &settings,
            &pending,
            vec!["balance".into()],
            Instant::now(),
        )
        .await;
        assert!(prepared.client.is_error, "{}", prepared.client.text);
        assert!(prepared.host.is_empty());
        assert!(pending.lock().await.items.is_empty());
        let output = confirm(
            &Host::process(),
            &settings,
            &pending,
            "missing",
            Instant::now(),
        )
        .await;
        assert!(output.contains("unknown confirmation"), "{output}");
    }

    #[tokio::test]
    async fn a_prepared_quote_stays_on_the_host() {
        let settings = Settings {
            node_config: "/node".into(),
            ..settings(1_000_000)
        };
        let pending = Mutex::new(PendingStore::default());
        let outcome = prepare(
            &script(Ok(quote("To 0xrecipientsecret", 10))),
            &settings,
            &pending,
            vec![
                "transfer".into(),
                "to".into(),
                "1".into(),
                "--config".into(),
                "/evil".into(),
            ],
            Instant::now(),
        )
        .await;
        assert_eq!(outcome.client.text, QUOTE_WAITING);
        assert!(!outcome.client.is_error);
        assert!(!outcome.client.text.contains("0xrecipientsecret"));
        assert!(!outcome.client.text.contains("Confirm this id"));
        assert!(
            outcome.host.contains("0xrecipientsecret"),
            "{}",
            outcome.host
        );
        assert!(outcome.host.contains("Confirm this id"), "{}", outcome.host);
        let stored = pending
            .lock()
            .await
            .items
            .values()
            .next()
            .unwrap()
            .argv
            .clone();
        assert_eq!(stored, vec!["--config", "/node", "transfer", "to", "1"]);
    }

    #[tokio::test]
    async fn a_moved_quote_is_reconfirmed_on_the_host() {
        let settings = settings(1_000_000);
        let pending = Mutex::new(PendingStore::default());
        let id = pending.lock().await.insert(
            vec!["transfer".into(), "to".into(), "1".into()],
            quote("To 0xrecipientsecret", 1_000),
            Instant::now(),
        );
        let reply = confirm(
            &script(Ok(quote("To 0xrecipientsecret", 5_000))),
            &settings,
            &pending,
            &id,
            Instant::now(),
        )
        .await;
        assert!(reply.contains("nothing was sent"), "{reply}");
        assert!(reply.contains("Confirm this id"), "{reply}");
        assert!(!reply.contains(&id), "{reply}");
        assert!(!pending.lock().await.items.contains_key(&id));
    }

    #[test]
    fn one_quil_is_eight_billion_base_units_and_a_base_unit_paste_is_refused() {
        assert_eq!(
            transfer_argv("0xabc", "1", Some("0.01")).unwrap(),
            vec!["transfer", "0xabc", "8000000000", "--fee", "80000000"]
        );
        assert_eq!(
            transfer_argv("0xabc", "0.5", None).unwrap(),
            vec!["transfer", "0xabc", "4000000000"]
        );
        let pasted = transfer_argv("0xabc", "8000000000", None).unwrap_err();
        assert!(pasted.contains("Do not paste base units"), "{pasted}");
        assert!(transfer_argv("--config", "1", None).is_err());
    }

    #[test]
    fn named_actions_build_the_qclient_words() {
        assert_eq!(mint_argv(None, None).unwrap(), vec!["mint"]);
        assert_eq!(mint_argv(Some("0xme"), None).unwrap(), vec!["mint", "0xme"]);
        assert_eq!(merge_argv(&[], None).unwrap(), vec!["merge", "all"]);
        assert_eq!(
            split_argv("0xcoin", &["0.5".into(), "0.5".into()], None, None, None).unwrap(),
            vec!["split", "0xcoin", "4000000000", "4000000000"]
        );
        assert!(split_argv("0xcoin", &[], Some(3), Some("0.5"), None).is_err());
        assert_eq!(
            pay_argv("0xdest", "1", "0xctx", None).unwrap(),
            vec!["pay", "0xdest", "8000000000", "0xctx"]
        );
        assert_eq!(
            accept_argv("0xescrow", None).unwrap(),
            vec!["accept", "0xescrow"]
        );
    }

    #[tokio::test]
    async fn status_names_a_waiting_quote_and_hides_the_key() {
        let settings = settings(1_000_000);
        let pending = Mutex::new(PendingStore::default());
        let id = pending.lock().await.insert(
            vec!["transfer".into(), "0xabc".into(), "1".into()],
            quote("To 0xrecipientsecret", 8_000_000_000),
            Instant::now(),
        );
        let text = status_report(&settings, &pending, Instant::now()).await;
        assert!(text.contains("qagent is running."), "{text}");
        assert!(text.contains("Yours: operator"), "{text}");
        assert!(text.contains(&format!("qagent confirm {id}")), "{text}");
        assert!(text.contains("1.000000000000 QUIL"), "{text}");
    }
}
