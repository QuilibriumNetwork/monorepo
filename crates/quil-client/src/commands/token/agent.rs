//! The small surface qagent uses. A read runs the token command and returns
//! its printed lines. A send is not previewed here: running it would submit.

use clap::Parser;

use crate::context::GlobalArgs;

use super::output;
use super::{run, TokenArgs};

/// A quoted token command. qagent prints `text` on the host and keeps the
/// confirmation id there.
#[derive(Clone, Debug)]
pub struct AgentQuote {
    pub submits: bool,
    pub text: String,
    pub fee: Option<u128>,
    pub fee_explicit: bool,
    pub max_fee: u128,
    pub variable_amount: Option<u128>,
}

/// Parse arguments that follow `qclient token`.
pub fn parse_token_argv<I, T>(argv: I) -> Result<TokenArgs, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut full = vec![std::ffi::OsString::from("token")];
    full.extend(argv.into_iter().map(Into::into));
    Ok(TokenCli::try_parse_from(full)?.args)
}

/// Run a token command and return the lines it printed.
pub async fn agent_execute(global: GlobalArgs, args: &TokenArgs) -> anyhow::Result<String> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(tx, run(global, args)).await;
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    result?;
    Ok(lines.join("\n"))
}

/// Read commands return their printed lines. A command that would submit is
/// refused: there is no preview that stops before the send.
pub async fn agent_preview(global: GlobalArgs, args: &TokenArgs) -> anyhow::Result<AgentQuote> {
    if args.command.submits() {
        anyhow::bail!(
            "this command would submit, and qagent has no preview that stops before the send"
        );
    }
    let text = agent_execute(global, args).await?;
    Ok(AgentQuote {
        submits: false,
        text,
        fee: None,
        fee_explicit: false,
        max_fee: args.common.max_fee,
        variable_amount: None,
    })
}

#[derive(Parser)]
struct TokenCli {
    #[command(flatten)]
    args: TokenArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_parses_and_does_not_submit() {
        let args = parse_token_argv(["balance"]).unwrap();
        assert!(!args.command.submits());
        let capped = parse_token_argv(["balance", "--max-fee", "40"]).unwrap();
        assert_eq!(capped.common.max_fee, 40);
    }
}
