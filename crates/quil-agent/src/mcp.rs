//! A small MCP JSON-RPC surface: `initialize`, `tools/list`, `tools/call`, `ping`.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::auth::{Access, Principal};
use crate::config::Settings;
use crate::disclosure::{self, Audience};
use crate::ops::{self, Host, PendingStore, ToolOutput};

pub const PROTOCOL_VERSION: &str = "2025-03-26";

pub struct App {
    pub settings: Settings,
    pub pending: Mutex<PendingStore>,
    pub host: Host,
}

impl App {
    pub fn new(settings: Settings) -> Self {
        Self::with_host(settings, Host::process())
    }

    pub fn with_host(settings: Settings, host: Host) -> Self {
        Self {
            settings,
            pending: Mutex::new(PendingStore::default()),
            host,
        }
    }
}

/// JSON-RPC response body. `None` is a notification, which has no body.
pub async fn dispatch(
    app: &Arc<App>,
    message: &Value,
    now: Instant,
    principal: &Principal,
) -> Option<Value> {
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Some(error(message.get("id").cloned(), -32600, "invalid request"));
    };
    let id = message.get("id").cloned();
    if id.is_none() {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools(principal.access) })),
        "tools/call" => call_tool(app, &params, now, principal).await,
        _ => Err((-32601, format!("unknown method {method}"))),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => error(Some(id), code, &message),
    })
}

fn initialize(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    let version = if matches!(requested, "2025-03-26" | "2024-11-05") {
        requested
    } else {
        PROTOCOL_VERSION
    };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "qagent",
            "version": quil_config::display_version()
        },
        "instructions": "Call next_step before asking for a quote. It says whether to mint, shield, or wait, and whether a quote is already on the operator's terminal. It does not include an address or a confirmation id. node_info includes worker health in sentences. balance is the totals. Amounts on quote tools are QUIL: 1 means one QUIL, and 0.5 means half a QUIL. Do not pass 8000000000. A quote is printed on the operator's terminal with its confirmation id. Tell the user to look at that terminal and approve it there. This session cannot submit and is not given the id. Do not invent one. Do not pass a file path or a node config. When a call fails, the latest redacted warnings are included. Do not treat them as a reason to invent an id."
    })
}

fn tools(access: Access) -> Vec<Value> {
    let mut listed = vec![
        tool(
            "node_info",
            "Read worker counts, the head frame, whether the node is reachable, and short health sentences: which workers are held, why, and whether store reads are slow.",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "balance",
            "Totals and counts for this wallet. No addresses and no arguments.",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
        tool(
            "next_step",
            "What to do next. Names a quote already waiting by its action and QUIL amount, or says to mint or shield. No address and no confirmation id.",
            json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        ),
    ];
    if access == Access::Full {
        listed.extend([
            tool(
                "transfer_quote",
                "Ask the host to quote sending QUIL. quil is the amount in QUIL, such as 1 or 0.5. The quote stays on the host. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "recipient": { "type": "string", "description": "Recipient confidential address." },
                        "quil": { "type": "string", "description": "Amount in QUIL. 1 is one QUIL. Do not pass base units." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL. Leave this out to let the node estimate it." }
                    },
                    "required": ["recipient", "quil"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "mint_quote",
                "Ask the host to quote claiming this prover's reward. The amount is decided by the node and printed on the host. This is only the first step. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "recipient": { "type": "string", "description": "Optional recipient confidential address. Leave this out to receive the reward yourself." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "additionalProperties": false
                }),
            ),
            tool(
                "shield_quote",
                "Ask the host to quote shielding one transparent coin into this wallet. quil is that coin's full amount in QUIL. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "description": "Transparent coin address." },
                        "quil": { "type": "string", "description": "Full coin amount in QUIL, such as 1 or 0.5." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "required": ["source", "quil"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "merge_quote",
                "Ask the host to quote merging coins. Leave coins empty to merge all of them. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "coins": { "type": "array", "items": { "type": "string" }, "description": "Coin addresses to merge. Omit this to merge all." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "additionalProperties": false
                }),
            ),
            tool(
                "split_quote",
                "Ask the host to quote splitting one coin. Pass amounts in QUIL, or parts as 2 with part_quil. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "coin": { "type": "string", "description": "Coin address to split." },
                        "amounts": { "type": "array", "items": { "type": "string" }, "description": "Output amounts in QUIL, such as [\"0.5\", \"0.5\"]." },
                        "parts": { "type": "integer", "description": "Use 2 to split into two equal-sized parts. Then also pass part_quil." },
                        "part_quil": { "type": "string", "description": "Size of each part in QUIL when parts is 2." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "required": ["coin"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "pay_quote",
                "Ask the host to quote paying QUIL to another application. quil is the amount in QUIL. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "destination": { "type": "string", "description": "Destination application, 32-byte hex." },
                        "quil": { "type": "string", "description": "Amount in QUIL, such as 1 or 0.5." },
                        "context": { "type": "string", "description": "32-byte hex binding of the destination bundle." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "required": ["destination", "quil", "context"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "accept_quote",
                "Ask the host to quote accepting a pending transfer. This call cannot send.",
                json!({
                    "type": "object",
                    "properties": {
                        "escrow": { "type": "string", "description": "Escrow address of the pending transfer." },
                        "fee_quil": { "type": "string", "description": "Optional fee in QUIL." }
                    },
                    "required": ["escrow"],
                    "additionalProperties": false
                }),
            ),
            tool(
                "token_prepare",
                "Advanced. Words after `qclient token`. Amounts here are base units, and 1 QUIL is 8000000000. Prefer transfer_quote and the other quote tools. This call cannot send.",
                argv_schema(),
            ),
        ]);
    }
    listed
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema
    })
}

fn argv_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "argv": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Arguments after `qclient token`, for example [\"transfer\", \"<address>\", \"<base units>\"]."
            }
        },
        "required": ["argv"],
        "additionalProperties": false
    })
}

async fn call_tool(
    app: &App,
    params: &Value,
    now: Instant,
    principal: &Principal,
) -> Result<Value, (i32, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tools/call requires a name".to_string()))?;
    let access = principal.access;
    let audience = Audience::of(access, principal.external);
    let secrets: Vec<String> = app
        .settings
        .keys
        .iter()
        .map(|key| key.secret.clone())
        .collect();
    let finish = |output: ToolOutput| {
        let client = disclosure::release(audience, &secrets, output.text);
        let withheld = client == disclosure::WITHHELD;
        Ok(tool_result(ToolOutput {
            text: client,
            is_error: output.is_error || withheld,
        }))
    };
    if access == Access::ReadOnly && !matches!(name, "node_info" | "balance" | "next_step") {
        return finish(ToolOutput {
            text: "This API key is read-only. It can call node_info, balance, and next_step. It cannot send or ask for a quote.".into(),
            is_error: true,
        });
    }
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let outcome = match name {
        "node_info" => ops::node_info(&app.host, &app.settings, audience).await,
        "balance" => ops::balance(&app.host, &app.settings).await,
        "next_step" => ops::next_step(&app.host, &app.settings, &app.pending, now).await,
        "token_prepare" => {
            let argv = argv_arg(&arguments)?;
            ops::prepare(&app.host, &app.settings, &app.pending, argv, now).await
        }
        "token_submit" | "token_query" => ops::Outcome::client(ToolOutput::err(ops::CANNOT_SUBMIT)),
        _ => match quote_argv(name, &arguments) {
            Some(Ok(argv)) => {
                ops::prepare(&app.host, &app.settings, &app.pending, argv, now).await
            }
            Some(Err(message)) => return finish(ToolOutput::err(message)),
            None => {
                return Err((
                    -32602,
                    format!(
                        "unknown tool {name}. Reads are node_info, balance, and next_step. Quotes are transfer_quote, mint_quote, shield_quote, merge_quote, split_quote, pay_quote, and accept_quote."
                    ),
                ))
            }
        },
    };
    if !outcome.host.is_empty() {
        if disclosure::holds_config_secret(&outcome.host) {
            eprintln!(
                "Quote withheld. It included the node config's private key or the keystore, so it was not printed."
            );
        } else {
            eprintln!("{}", outcome.host);
        }
    }
    finish(outcome.client)
}

fn quote_argv(name: &str, arguments: &Value) -> Option<Result<Vec<String>, String>> {
    let built = match name {
        "transfer_quote" => transfer_quote_argv(arguments),
        "mint_quote" => mint_quote_argv(arguments),
        "shield_quote" => shield_quote_argv(arguments),
        "merge_quote" => merge_quote_argv(arguments),
        "split_quote" => split_quote_argv(arguments),
        "pay_quote" => pay_quote_argv(arguments),
        "accept_quote" => accept_quote_argv(arguments),
        _ => return None,
    };
    Some(built)
}

fn transfer_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::transfer_argv(
        &required_str(arguments, "recipient", "This is who receives the QUIL.")?,
        &required_str(
            arguments,
            "quil",
            "Use 1 for one QUIL, or 0.5 for half a QUIL.",
        )?,
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn mint_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::mint_argv(
        optional_str(arguments, "recipient")?.as_deref(),
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn shield_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::shield_argv(
        &required_str(arguments, "source", "This is the transparent coin address.")?,
        &required_str(arguments, "quil", "This is the coin's full amount in QUIL.")?,
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn merge_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::merge_argv(
        &optional_strings(arguments, "coins")?,
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn split_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::split_argv(
        &required_str(arguments, "coin", "This is the coin to split.")?,
        &optional_strings(arguments, "amounts")?,
        optional_u32(arguments, "parts")?,
        optional_str(arguments, "part_quil")?.as_deref(),
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn pay_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::pay_argv(
        &required_str(arguments, "destination", "This is the application to pay.")?,
        &required_str(
            arguments,
            "quil",
            "Use 1 for one QUIL, or 0.5 for half a QUIL.",
        )?,
        &required_str(arguments, "context", "This is the 32-byte hex binding.")?,
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn accept_quote_argv(arguments: &Value) -> Result<Vec<String>, String> {
    ops::accept_argv(
        &required_str(arguments, "escrow", "This is the escrow address.")?,
        optional_str(arguments, "fee_quil")?.as_deref(),
    )
}

fn required_str(arguments: &Value, key: &str, why: &str) -> Result<String, String> {
    match arguments.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(format!("{key} is required. {why}")),
    }
}

fn optional_str(arguments: &Value, key: &str) -> Result<Option<String>, String> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim().to_string())),
        _ => Err(format!("{key} must be text.")),
    }
}

fn optional_strings(arguments: &Value, key: &str) -> Result<Vec<String>, String> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| format!("Each {key} entry must be text."))
            })
            .collect(),
        _ => Err(format!("{key} must be a list of text.")),
    }
}

fn optional_u32(arguments: &Value, key: &str) -> Result<Option<u32>, String> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| format!("{key} must be a whole number.")),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| format!("{key} must be a whole number.")),
        _ => Err(format!("{key} must be a whole number.")),
    }
}

fn argv_arg(arguments: &Value) -> Result<Vec<String>, (i32, String)> {
    let values = arguments
        .get("argv")
        .and_then(Value::as_array)
        .ok_or((-32602, "argv must be an array of strings".to_string()))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or((-32602, "argv must be an array of strings".to_string()))
        })
        .collect()
}

fn tool_result(output: ToolOutput) -> Value {
    json!({
        "content": [{ "type": "text", "text": output.text }],
        "isError": output.is_error
    })
}

fn error(id: Option<Value>, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Access, Principal};
    use crate::config::{ApiKey, KeyAccess, Settings};
    use serde_json::json;
    use std::time::Instant;

    fn who(access: Access) -> Principal {
        Principal {
            name: "test".into(),
            access,
            external: access == Access::ReadOnly,
        }
    }

    fn app() -> Arc<App> {
        Arc::new(App::new(Settings {
            listen: "127.0.0.1:8350".into(),
            keys: vec![
                ApiKey::new("operator", "secret", KeyAccess::Full),
                ApiKey::new("dashboard", "reader", KeyAccess::ReadOnly),
            ],
            fee_slippage_bps: 200,
            max_fee: 1,
            node_config: String::new(),
            network: None,
            config_path: std::path::PathBuf::from("qagent.yaml"),
        }))
    }

    #[tokio::test]
    async fn initialize_lists_tools_and_a_transfer_is_not_a_query() {
        let app = app();
        let now = Instant::now();
        let init = dispatch(
            &app,
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            now,
            &who(Access::Full),
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("Do not invent"));

        let listed = dispatch(
            &app,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            now,
            &who(Access::Full),
        )
        .await
        .unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "node_info",
                "balance",
                "next_step",
                "transfer_quote",
                "mint_quote",
                "shield_quote",
                "merge_quote",
                "split_quote",
                "pay_quote",
                "accept_quote",
                "token_prepare",
            ]
        );

        let read_only = dispatch(
            &app,
            &json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }),
            now,
            &who(Access::ReadOnly),
        )
        .await
        .unwrap();
        let read_only_names: Vec<&str> = read_only["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            read_only_names,
            vec!["node_info", "balance", "next_step"]
        );

        let refused = dispatch(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "token_query", "arguments": { "argv": ["coins"] } }
            }),
            now,
            &who(Access::Full),
        )
        .await
        .unwrap();
        assert_eq!(refused["result"]["isError"], true);
        assert!(refused["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cannot submit"));

        let prepared = dispatch(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": { "name": "token_prepare", "arguments": { "argv": ["balance"] } }
            }),
            now,
            &who(Access::Full),
        )
        .await
        .unwrap();
        assert_eq!(prepared["result"]["isError"], true);

        let missing = dispatch(
            &app,
            &json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": { "name": "transfer_quote", "arguments": { "recipient": "0xabc" } }
            }),
            now,
            &who(Access::Full),
        )
        .await
        .unwrap();
        assert_eq!(missing["result"]["isError"], true);
        assert!(missing["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("quil is required"));

        assert!(dispatch(
            &app,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            now,
            &who(Access::Full),
        )
        .await
        .is_none());
    }
}
