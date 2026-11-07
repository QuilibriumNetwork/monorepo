//! One-shot helper. It opens the keystore, does one balance, status, quote,
//! or submit, writes a JSON result, and exits. The MCP process never calls
//! these functions itself.

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use quil_client::commands::token::AgentQuote;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::config::Settings;
use crate::disclosure;
use crate::ops::{self, NodeFacts};
use crate::warnings;

/// A helper failure. `warnings` are redacted node-log lines for the assistant.
#[derive(Debug)]
pub struct HelperFailure {
    pub message: String,
    pub warnings: Vec<String>,
}

impl HelperFailure {
    pub fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Job {
    op: String,
    argv: Vec<String>,
    node_config: String,
    network: Option<String>,
    max_fee: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuoteWire {
    submits: bool,
    text: String,
    fee: Option<String>,
    fee_explicit: bool,
    max_fee: String,
    variable_amount: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobResult {
    ok: bool,
    error: String,
    text: String,
    node: Option<NodeFacts>,
    quote: Option<QuoteWire>,
    #[serde(default)]
    warnings: Vec<String>,
}

impl JobResult {
    fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
            text: String::new(),
            node: None,
            quote: None,
            warnings: Vec::new(),
        }
    }

    fn text(text: String) -> Self {
        Self {
            ok: true,
            error: String::new(),
            text,
            node: None,
            quote: None,
            warnings: Vec::new(),
        }
    }
}

/// Entry point for `qagent worker`. Stdout is the JSON result; progress lines
/// go to the terminal.
pub fn run() -> anyhow::Result<()> {
    let mut result_out = redirect_stdout_to_stderr()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let job: Job = serde_json::from_str(&input)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = withhold(runtime.block_on(perform(job)));
    serde_json::to_writer(&mut result_out, &result)?;
    writeln!(result_out)?;
    Ok(())
}

/// Point fd 1 at stderr and return the previous stdout, which the parent reads.
fn redirect_stdout_to_stderr() -> std::io::Result<File> {
    use std::os::unix::io::FromRawFd;
    extern "C" {
        fn dup(fd: i32) -> i32;
        fn dup2(src: i32, dst: i32) -> i32;
    }
    // SAFETY: dup/dup2 only duplicate file descriptors. The saved descriptor
    // is the pipe the parent reads, and it is owned by the returned File.
    unsafe {
        let saved = dup(1);
        if saved < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if dup2(2, 1) < 0 {
            let _ = File::from_raw_fd(saved);
            return Err(std::io::Error::last_os_error());
        }
        Ok(File::from_raw_fd(saved))
    }
}

/// Drop a result that carries `peerPrivKey` or keystore material before it
/// is written for the parent. The refusal names neither value.
fn withhold(result: JobResult) -> JobResult {
    let mut parts = vec![result.error.clone(), result.text.clone()];
    if let Some(quote) = &result.quote {
        parts.push(quote.text.clone());
    }
    if let Some(node) = &result.node {
        parts.extend([
            node.version.clone(),
            node.peer_id.clone(),
            node.running_workers.clone(),
            node.allocated_workers.clone(),
            node.worker_capacity.clone(),
            node.last_global_head_frame.clone(),
            node.last_received_frame.clone(),
            node.current_epoch.clone(),
            node.epoch_length_frames.clone(),
            node.reachable.clone(),
            node.health.clone(),
        ]);
    }
    parts.extend(result.warnings.iter().cloned());
    if parts.iter().any(|part| disclosure::holds_config_secret(part)) {
        return JobResult::err(
            "withheld: the result included node config or keystore material",
        );
    }
    result
}

async fn perform(job: Job) -> JobResult {
    let settings = match settings_from(&job) {
        Ok(settings) => settings,
        Err(err) => return JobResult::err(err),
    };
    let mut result = match job.op.as_str() {
        "balance" => match ops::run_balance(&settings).await {
            Ok(text) => JobResult::text(text),
            Err(err) => JobResult::err(err),
        },
        "node" => match ops::run_node_info(&settings).await {
            Ok(facts) => JobResult {
                ok: true,
                error: String::new(),
                text: String::new(),
                node: Some(facts),
                quote: None,
                warnings: Vec::new(),
            },
            Err(err) => JobResult::err(err),
        },
        "preview" => match ops::run_preview(&settings, job.argv).await {
            Ok(quote) => JobResult {
                ok: true,
                error: String::new(),
                text: String::new(),
                node: None,
                quote: Some(wire_from(&quote)),
                warnings: Vec::new(),
            },
            Err(err) => JobResult::err(err),
        },
        "execute" => match ops::run_execute(&settings, job.argv).await {
            Ok(text) => JobResult::text(text),
            Err(err) => JobResult::err(err),
        },
        other => JobResult::err(format!("unknown helper operation {other}")),
    };
    if !result.ok {
        result.warnings = warnings::collect(&settings);
    }
    result
}

fn settings_from(job: &Job) -> Result<Settings, String> {
    let max_fee = job
        .max_fee
        .parse::<u128>()
        .map_err(|err| format!("max fee: {err}"))?;
    Ok(Settings {
        listen: String::new(),
        keys: Vec::new(),
        fee_slippage_bps: 0,
        max_fee,
        node_config: job.node_config.clone(),
        network: job.network.clone(),
        config_path: PathBuf::new(),
    })
}

pub async fn balance(settings: &Settings) -> Result<String, HelperFailure> {
    let result = spawn(&Job {
        op: "balance".into(),
        argv: Vec::new(),
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await
    .map_err(HelperFailure::plain)?;
    finish_text(result)
}

pub async fn node_info(settings: &Settings) -> Result<NodeFacts, HelperFailure> {
    let result = spawn(&Job {
        op: "node".into(),
        argv: Vec::new(),
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await
    .map_err(HelperFailure::plain)?;
    if !result.ok {
        return Err(failure(result));
    }
    result
        .node
        .ok_or_else(|| HelperFailure::plain("helper returned no node status"))
}

pub async fn preview(settings: &Settings, argv: Vec<String>) -> Result<AgentQuote, HelperFailure> {
    let result = spawn(&Job {
        op: "preview".into(),
        argv,
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await
    .map_err(HelperFailure::plain)?;
    if !result.ok {
        return Err(failure(result));
    }
    let warnings = result.warnings;
    result
        .quote
        .ok_or_else(|| HelperFailure::plain("helper returned no quote"))
        .and_then(|wire| quote_from(wire).map_err(HelperFailure::plain))
        .map_err(|err| HelperFailure {
            warnings,
            ..err
        })
}

pub async fn execute(settings: &Settings, argv: Vec<String>) -> Result<String, HelperFailure> {
    let result = spawn(&Job {
        op: "execute".into(),
        argv,
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await
    .map_err(HelperFailure::plain)?;
    finish_text(result)
}

fn failure(result: JobResult) -> HelperFailure {
    HelperFailure {
        message: result.error,
        warnings: result.warnings,
    }
}

fn finish_text(result: JobResult) -> Result<String, HelperFailure> {
    if result.ok {
        Ok(result.text)
    } else {
        Err(failure(result))
    }
}

async fn spawn(job: &Job) -> Result<JobResult, String> {
    let exe = std::env::current_exe().map_err(|err| format!("find qagent: {err}"))?;
    let mut child = Command::new(exe)
        .arg("worker")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("start helper: {err}"))?;
    let mut stdin = child.stdin.take().ok_or("helper stdin was not piped")?;
    let request = serde_json::to_vec(job).map_err(|err| format!("encode helper request: {err}"))?;
    stdin
        .write_all(&request)
        .await
        .map_err(|err| format!("write helper request: {err}"))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .map_err(|err| format!("wait for helper: {err}"))?;
    if output.stdout.is_empty() {
        return Err(format!("helper exited {}", output.status));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| format!("helper reply: {err}"))
}

fn wire_from(quote: &AgentQuote) -> QuoteWire {
    QuoteWire {
        submits: quote.submits,
        text: quote.text.clone(),
        fee: quote.fee.map(|fee| fee.to_string()),
        fee_explicit: quote.fee_explicit,
        max_fee: quote.max_fee.to_string(),
        variable_amount: quote.variable_amount.map(|amount| amount.to_string()),
    }
}

fn quote_from(wire: QuoteWire) -> Result<AgentQuote, String> {
    let parse = |value: &str, what: &str| {
        value
            .parse::<u128>()
            .map_err(|err| format!("{what}: {err}"))
    };
    Ok(AgentQuote {
        submits: wire.submits,
        text: wire.text,
        fee: wire
            .fee
            .as_deref()
            .map(|fee| parse(fee, "fee"))
            .transpose()?,
        fee_explicit: wire.fee_explicit,
        max_fee: parse(&wire.max_fee, "max fee")?,
        variable_amount: wire
            .variable_amount
            .as_deref()
            .map(|amount| parse(amount, "amount"))
            .transpose()?,
    })
}
