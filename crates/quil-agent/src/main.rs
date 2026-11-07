//! `qagent` — MCP server for the local node and qclient.
//!
//! Build it with the same task targets as qclient, for example
//! `task build_qagent_amd64_linux`. Point an MCP client at
//! `http://<host>:<port>/mcp` and send the API key on every request.

use std::path::PathBuf;

use clap::Parser;

use quil_agent::config::{self, KeyAccess, Overrides, Settings};
use quil_agent::mcp::App;

#[derive(Debug, Parser)]
#[command(
    name = "qagent",
    about = "Authenticated MCP server for a Quilibrium node",
    long_about = "qagent lets an assistant look at your node. The assistant can see if the node is up and what the balance totals are. It cannot see addresses and it cannot spend.\n\n\
                  Run qagent and leave this terminal open. The first screen tells you the address, which key to put in the assistant, and which node config is in use.\n\n\
                  Put a read-only key in the assistant. A full key can ask for a quote. The quote is printed here. You approve it here. Run qagent status to see whether a quote is waiting.\n\n\
                  Amounts are in QUIL. 1 is one QUIL. 1 QUIL is 8000000000 base units."
)]
struct Cli {
    /// Listen address. The default accepts connections from this machine only.
    #[arg(long)]
    listen: Option<String>,
    /// API key. Overrides the first full key for this process and is not written.
    #[arg(long, env = "QUILIBRIUM_AGENT_API_KEY")]
    api_key: Option<String>,
    /// How far a quoted fee may rise between confirmation and submit, in basis points (200 = 2%).
    #[arg(long)]
    fee_slippage_bps: Option<u32>,
    /// Largest automatic fee, in base units. A quote above this is refused.
    #[arg(long)]
    max_fee: Option<u64>,
    /// Config file of the node this agent talks to, the same one you pass to qclient --config.
    /// The keystore path inside that file must be absolute. Empty uses the default qclient config.
    #[arg(long)]
    node_config: Option<String>,
    /// Network config name, as `qclient --network`.
    #[arg(long, env = "QUILIBRIUM_NETWORK")]
    network: Option<String>,
    /// Settings file. Default: ~/.quilibrium/qagent.yaml.
    #[arg(long, global = true)]
    config_file: Option<PathBuf>,
    /// Print the first full API key stored in the settings file and exit.
    #[arg(long)]
    print_api_key: bool,
    /// Print the first read-only API key stored in the settings file and exit.
    /// Creates the key when the file does not have one.
    #[arg(long)]
    print_read_only_api_key: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Create, list, and remove named API keys.
    Key {
        #[command(subcommand)]
        action: KeyCommand,
    },
    /// Show the assistant address, the key names, the node config, and whether a quote is waiting.
    Status,
    /// Approve the quote whose confirmation id was printed on the qagent screen.
    Confirm {
        /// Confirmation id printed under the quote on the qagent screen.
        id: String,
    },
    /// Run one keystore operation and exit. The server spawns this itself.
    #[command(hide = true)]
    Worker,
}

#[derive(Debug, clap::Subcommand)]
enum KeyCommand {
    /// Create a named API key and print its secret.
    ///
    /// The name is what the log shows when a request uses this key.
    Issue {
        /// Name recorded in the log when this key is used.
        name: String,
        /// This key may only call node_info, balance, and next_step.
        #[arg(long)]
        read_only: bool,
    },
    /// Show each key's name and access. Secrets are not printed.
    List,
    /// Remove a key by name.
    ///
    /// The next start creates a new operator or read-only key when that access has none.
    Revoke {
        /// Name of the key to remove.
        name: String,
    },
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Some(Command::Worker)) {
        return quil_agent::worker::run();
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let path = match cli.config_file {
        Some(path) => path,
        None => config::default_path()?,
    };
    match cli.command {
        Some(Command::Key { action }) => return run_key_command(&path, action),
        Some(Command::Status) => return status_on_host(&path),
        Some(Command::Confirm { id }) => return confirm_on_host(&path, &id),
        Some(Command::Worker) => unreachable!("worker returns before the server starts"),
        None => {}
    }
    if cli.print_api_key {
        println!("{}", Settings::reveal_key(&path)?);
        return Ok(());
    }
    if cli.print_read_only_api_key {
        println!("{}", Settings::reveal_read_only_key(&path)?);
        return Ok(());
    }
    let settings = Settings::load(
        &path,
        &Overrides {
            listen: cli.listen,
            api_key: cli.api_key,
            fee_slippage_bps: cli.fee_slippage_bps,
            max_fee: cli.max_fee,
            node_config: cli.node_config,
            network: cli.network,
        },
    )?;
    if config::listens_beyond_loopback(&settings.listen) {
        tracing::warn!(
            listen = %settings.listen,
            "qagent accepts connections from other hosts; requests without the API key are rejected"
        );
    }
    let key_names = settings
        .keys
        .iter()
        .map(|key| format!("{} ({})", key.name, key.access))
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(
        listen = %settings.listen,
        config = %settings.config_path.display(),
        slippage_bps = settings.fee_slippage_bps,
        keys = %key_names,
        "qagent listening on http://{}/mcp — send Authorization: Bearer <api key> or X-Api-Key",
        settings.listen
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(quil_agent::serve(App::new(settings), async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

fn status_on_host(config: &std::path::Path) -> anyhow::Result<()> {
    match ask_running(config, "status\n") {
        Ok(response) => {
            print_reply(&response);
            Ok(())
        }
        Err(_) => {
            let settings = Settings::load(config, &Overrides::default())?;
            println!("{}", quil_agent::guide::status(&settings, None));
            Ok(())
        }
    }
}

fn confirm_on_host(config: &std::path::Path, id: &str) -> anyhow::Result<()> {
    let response = ask_running(config, &format!("confirm {id}\n")).map_err(|err| {
        anyhow::anyhow!(
            "{err}\nStart qagent and leave that terminal open. The confirmation id is printed there when a quote is waiting. Run qagent status."
        )
    })?;
    print_reply(&response);
    Ok(())
}

fn ask_running(config: &std::path::Path, line: &str) -> anyhow::Result<String> {
    let path = quil_agent::control::socket_path(config);
    let mut stream = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|_| anyhow::anyhow!("qagent is not running (no socket at {}).", path.display()))?;
    use std::io::{Read, Write};
    stream.write_all(line.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn print_reply(response: &str) {
    print!("{response}");
    if !response.ends_with('\n') {
        println!();
    }
}

fn run_key_command(path: &std::path::Path, action: KeyCommand) -> anyhow::Result<()> {
    match action {
        KeyCommand::Issue { name, read_only } => {
            let access = if read_only {
                KeyAccess::ReadOnly
            } else {
                KeyAccess::Full
            };
            let key = Settings::issue_key(path, &name, access)?;
            println!("name: {}", key.name);
            println!("access: {}", key.access);
            println!("secret: {}", key.secret);
        }
        KeyCommand::List => {
            for key in Settings::list_keys(path)? {
                println!("{}\t{}", key.name, key.access);
            }
        }
        KeyCommand::Revoke { name } => {
            Settings::revoke_key(path, &name)?;
            println!("revoked {name}");
        }
    }
    Ok(())
}
