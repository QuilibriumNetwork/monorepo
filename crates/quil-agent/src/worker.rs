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
use crate::ops::{self, NodeFacts};

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
}

impl JobResult {
    fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
            text: String::new(),
            node: None,
            quote: None,
        }
    }

    fn text(text: String) -> Self {
        Self {
            ok: true,
            error: String::new(),
            text,
            node: None,
            quote: None,
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
    let result = runtime.block_on(perform(job));
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

async fn perform(job: Job) -> JobResult {
    let settings = match settings_from(&job) {
        Ok(settings) => settings,
        Err(err) => return JobResult::err(err),
    };
    match job.op.as_str() {
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
            },
            Err(err) => JobResult::err(err),
        },
        "execute" => match ops::run_execute(&settings, job.argv).await {
            Ok(text) => JobResult::text(text),
            Err(err) => JobResult::err(err),
        },
        other => JobResult::err(format!("unknown helper operation {other}")),
    }
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

pub async fn balance(settings: &Settings) -> Result<String, String> {
    let result = spawn(&Job {
        op: "balance".into(),
        argv: Vec::new(),
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await?;
    finish_text(result)
}

pub async fn node_info(settings: &Settings) -> Result<NodeFacts, String> {
    let result = spawn(&Job {
        op: "node".into(),
        argv: Vec::new(),
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await?;
    if !result.ok {
        return Err(result.error);
    }
    result
        .node
        .ok_or_else(|| "helper returned no node status".into())
}

pub async fn preview(settings: &Settings, argv: Vec<String>) -> Result<AgentQuote, String> {
    let result = spawn(&Job {
        op: "preview".into(),
        argv,
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await?;
    if !result.ok {
        return Err(result.error);
    }
    result
        .quote
        .ok_or_else(|| "helper returned no quote".into())
        .and_then(quote_from)
}

pub async fn execute(settings: &Settings, argv: Vec<String>) -> Result<String, String> {
    let result = spawn(&Job {
        op: "execute".into(),
        argv,
        node_config: settings.node_config.clone(),
        network: settings.network.clone(),
        max_fee: settings.max_fee.to_string(),
    })
    .await?;
    finish_text(result)
}

fn finish_text(result: JobResult) -> Result<String, String> {
    if result.ok {
        Ok(result.text)
    } else {
        Err(result.error)
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
