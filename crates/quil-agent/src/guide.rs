//! Sentences for the person at the keyboard. Secrets are never included.

use crate::config::{KeyAccess, Settings};

/// One quote the running server is holding. `detail` is the host-only text.
pub struct WaitingQuote {
    pub id: String,
    pub detail: String,
}

/// Printed once the confirm socket is up and nothing has been prepared.
pub fn startup(settings: &Settings) -> String {
    render(settings, "qagent is ready.", Some(&[]))
}

/// `waiting` is `None` when no server is running to ask.
pub fn status(settings: &Settings, waiting: Option<&[WaitingQuote]>) -> String {
    let headline = if waiting.is_some() {
        "qagent is running."
    } else {
        "qagent is not running."
    };
    render(settings, headline, waiting)
}

/// What to print under a real error. The assistant does not receive this.
pub fn failure_hint() -> &'static str {
    "The assistant was not given this detail. Read it here.\n\
If the message mentions a file, a keystore, or a config: stop qagent and start it again with --node-config set to the config file you use for the node. Inside that file, the keystore path (key.keyManagerFile.path) must be absolute, such as /home/you/.quilibrium/configs/NAME/keys.yml.\n\
If the message mentions a connection or a refused port: start the node. It usually listens on 127.0.0.1:8337.\n\
Then try the same request again."
}

fn render(settings: &Settings, headline: &str, waiting: Option<&[WaitingQuote]>) -> String {
    format!(
        "{headline}\n\n\
The assistant connects to http://{listen}/mcp\n\
Every request must include the API key, either as\n\
  Authorization: Bearer <the key>\n\
or as the header X-Api-Key.\n\n\
Put a read-only key in the assistant. Yours: {read_only}\n\
A read-only key, and any full key other than the first one, sees the node the way a diagnostics health report does: workers, frames, and whether it is reachable. It is not shown the peer id, addresses, the config, or anything from the keystore. A read-only key cannot send and cannot ask for a quote. It can call next_step, which says whether to mint, shield, or wait, without an address or a confirmation id.\n\n\
Do not put the first full key in the assistant. Yours: {full}\n\
That key can ask for a quote, and it is the only key shown this node's peer id. The quote is printed on the qagent screen. You approve it there. The assistant is not given the confirmation id. No key is given peerPrivKey or the keystore.\n\n\
{quotes}\n\n\
{node}\n\n\
Settings file: {config}\n\
See the key names again with: qagent key list\n\
That command prints names only, not the keys themselves.\n\
Ask whether a quote is waiting with: qagent status",
        listen = settings.listen,
        read_only = names(settings, KeyAccess::ReadOnly),
        full = names(settings, KeyAccess::Full),
        quotes = quotes(waiting),
        node = node_config_line(settings),
        config = settings.config_path.display(),
    )
}

fn names(settings: &Settings, access: KeyAccess) -> String {
    let found: Vec<&str> = settings
        .keys
        .iter()
        .filter(|key| key.access == access)
        .map(|key| key.name.as_str())
        .collect();
    if found.is_empty() {
        "none".to_string()
    } else {
        found.join(", ")
    }
}

fn node_config_line(settings: &Settings) -> String {
    if settings.node_config.is_empty() {
        "Node config: the default qclient config.\n\
If a call fails, stop qagent and start it again with --node-config and the config file you use for the node. The keystore path inside that file must be absolute."
            .to_string()
    } else {
        format!(
            "Node config: {}\n\
This is the node qagent talks to. The keystore path inside that file must be absolute.",
            settings.node_config
        )
    }
}

fn quotes(waiting: Option<&[WaitingQuote]>) -> String {
    match waiting {
        None => "\
qagent is not running, so no quote can be waiting.
Start it with: qagent
Leave that terminal open. That screen is where you approve a send."
            .to_string(),
        Some([]) => "\
No quote is waiting.
Nothing will be sent until a quote is printed on the qagent screen and you approve it."
            .to_string(),
        Some(items) => {
            let mut text = format!(
                "{} quote{} waiting. Nothing has been sent yet.",
                items.len(),
                if items.len() == 1 { " is" } else { "s are" }
            );
            for quote in items {
                text.push_str("\n\n");
                text.push_str(&quote.detail);
            }
            text
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, KeyAccess};

    fn settings() -> Settings {
        Settings {
            listen: "127.0.0.1:8350".into(),
            keys: vec![
                ApiKey::new("operator", "full-secret-value", KeyAccess::Full),
                ApiKey::new("cursor", "read-secret-value", KeyAccess::ReadOnly),
            ],
            fee_slippage_bps: 200,
            max_fee: 1,
            node_config: String::new(),
            network: None,
            config_path: std::path::PathBuf::from("/home/someone/.quilibrium/qagent.yaml"),
        }
    }

    #[test]
    fn startup_names_the_read_only_key_and_hides_the_secret() {
        let text = startup(&settings());
        assert!(text.contains("http://127.0.0.1:8350/mcp"), "{text}");
        assert!(text.contains("Yours: cursor"), "{text}");
        assert!(text.contains("Yours: operator"), "{text}");
        assert!(text.contains("No quote is waiting"), "{text}");
        assert!(!text.contains("full-secret-value"), "{text}");
        assert!(!text.contains("read-secret-value"), "{text}");
        assert!(!text.contains("confirm <"), "{text}");
        assert!(text.contains("default qclient config"), "{text}");
    }

    #[test]
    fn status_of_a_waiting_quote_prints_the_exact_command() {
        let waiting = [WaitingQuote {
            id: "abc".into(),
            detail: "Approve it with:\n  qagent confirm abc".into(),
        }];
        let text = status(&settings(), Some(&waiting));
        assert!(text.contains("qagent is running."), "{text}");
        assert!(text.contains("qagent confirm abc"), "{text}");
        assert!(!text.contains("full-secret-value"), "{text}");
    }

    #[test]
    fn status_offline_says_to_start_qagent() {
        let text = status(&settings(), None);
        assert!(text.contains("qagent is not running."), "{text}");
        assert!(text.contains("Start it with: qagent"), "{text}");
        assert!(!text.contains("confirm <"), "{text}");
    }
}
