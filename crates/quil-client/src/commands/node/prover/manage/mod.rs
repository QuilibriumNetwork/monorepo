//! `qclient node manage` — interactive shard-management TUI; its alias
//! `qclient node prover manage` takes the same flags and opens the same view.
//!
//! Port of the bubbletea program in `client/cmd/node/prover/` (proverManage.go
//! + manage_model.go + manage_actions.go). The bubbletea Elm loop is
//! reimplemented as a ratatui + crossterm async event loop:
//!
//! * [`model`] holds all state (the `manageModel` struct),
//! * [`update`] applies messages + key events (`Update`/`handleKey`),
//! * [`actions`] performs the async RPC commands (the `tea.Cmd`s),
//! * [`view`] renders (the `View`),
//! * [`coins`] holds the Coins tab's state and conditions,
//! * [`settings`] keeps the view settings between runs.

mod actions;
#[cfg(test)]
mod cadence;
mod coins;
mod filter;
mod mint;
mod model;
mod msg;
mod settings;
mod shield;
mod transfer;
mod update;
mod util;
mod view;

use std::io::Stdout;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    Semaphore,
};
use tonic::transport::Channel;

use quil_keys::FileKeyManager;
use quil_types::proto::node::node_service_client::NodeServiceClient;

use crate::context::GlobalArgs;

use self::model::Model;
use self::msg::Msg;
use self::update::{apply_msg, handle_key, Cmd};
use super::ProverCtx;

type Client = NodeServiceClient<Channel>;
type Term = Terminal<CrosstermBackend<Stdout>>;

/// Flags of `qclient node manage` and of its alias `qclient node prover
/// manage`: one definition, so the two entries cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ManageArgs {
    /// Print one frame as plain text and exit, after fetching once and
    /// applying --keys, with the saved view settings; never runs joins,
    /// lifecycle operations or worker changes, nor saves settings.
    #[arg(long)]
    pub render: bool,
    /// Print the TUI help as plain text and exit.
    #[arg(long)]
    pub help_text: bool,
    /// Width of --render and --help-text, in columns.
    #[arg(long, default_value_t = 160)]
    pub width: u16,
    /// Height of --render, in rows.
    #[arg(long, default_value_t = 50)]
    pub height: u16,
    /// Keys applied before --render draws, space-separated (e.g. "n Tab Down").
    #[arg(long, default_value = "")]
    pub keys: String,
    /// Draw --render with colors on, as interactively; plain text then
    /// loses the warnings that the default marks with `!`.
    #[arg(long)]
    pub color: bool,
    /// Seconds --render waits for the node's answers.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
    /// Show private wallet fields in --render: a confirmation's amount and
    /// the recipient's address, and shielded amounts. Without it a render,
    /// which may be shared, shows them as hidden.
    #[arg(long)]
    pub reveal: bool,
    /// Do not record wallet actions in the private action log
    /// (<node config dir>/wallet/actions.jsonl, owner-only); `noActionLog:
    /// true` in the qclient config does the same for every command.
    #[arg(long)]
    pub no_action_log: bool,
    /// Restore the view settings kept between runs (columns, KPIs, panel
    /// edges, sort, colors, notice level, refresh, key rows) to their
    /// defaults, then start.
    #[arg(long)]
    pub reset_ui: bool,
    /// Largest fee in base units one shield batch, mint or transfer action
    /// (transfer, pending transfer, accept, refund, merge) pays from the
    /// node's quote (default: 0.1 QUIL); a larger quote stops a shield run
    /// and refuses the others, as in `qclient token`.
    #[arg(
        long,
        env = "QUILIBRIUM_MAX_FEE",
        default_value_t = crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE
    )]
    pub max_fee: u128,
}

/// What an invocation does, decided by its flags alone.
enum Mode {
    /// `--help-text`, which wins over `--render`.
    HelpText(u16),
    Render(RenderOptions),
    Interactive,
}

impl ManageArgs {
    fn mode(&self) -> Mode {
        if self.help_text {
            Mode::HelpText(self.width)
        } else if self.render {
            Mode::Render(RenderOptions {
                width: self.width,
                height: self.height,
                keys: self.keys.split_whitespace().map(str::to_string).collect(),
                color: self.color,
                timeout: Duration::from_secs(self.timeout),
                reveal: self.reveal,
            })
        } else {
            Mode::Interactive
        }
    }
}

/// Entry point of `qclient node manage` and `qclient node prover manage`.
pub(in crate::commands::node) async fn command(
    global: GlobalArgs,
    args: &ManageArgs,
) -> anyhow::Result<()> {
    if args.reset_ui {
        if let Some(path) = settings::default_path() {
            settings::reset(&path)?;
            eprintln!("View settings restored to their defaults.");
        }
    }
    match args.mode() {
        Mode::HelpText(width) => {
            print!("{}", help_text(width));
            Ok(())
        }
        Mode::Render(opts) => {
            let pc = ProverCtx::load(global.clone())?;
            // A render never runs an action, so it writes no action log.
            let refresh = RefreshState::for_node(&pc, global, args.max_fee, true);
            render(&pc, refresh, opts).await
        }
        Mode::Interactive => {
            let pc = ProverCtx::load(global.clone())?;
            let refresh = RefreshState::for_node(&pc, global, args.max_fee, args.no_action_log);
            run(&pc, refresh).await
        }
    }
}

/// The interactive TUI (`NodeProverManageCmd.Run`).
async fn run(pc: &ProverCtx, refresh_state: RefreshState) -> anyhow::Result<()> {
    let client = pc.connect().await?;
    let km = pc.key_manager.clone();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = event_loop(&mut terminal, client, km, refresh_state).await;

    // Restore the terminal regardless of the loop outcome.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn event_loop(
    terminal: &mut Term,
    client: Client,
    km: Arc<FileKeyManager>,
    refresh_state: RefreshState,
) -> anyhow::Result<()> {
    let mut model = Model::new();
    let mut saved = settings::Store::open(settings::default_path(), &mut model);
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();

    // Kick off the initial fetch + auto-refresh + spinner tickers.
    spawn_action(&client, &km, &tx, &refresh_state, Cmd::Fetch);
    let mut polling_seconds = model.refresh_seconds;
    let mut refresh = tokio::time::interval(Duration::from_secs(polling_seconds));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await; // consume the immediate first tick
    let mut spin = tokio::time::interval(Duration::from_millis(120));

    let mut events = EventStream::new();

    terminal.draw(|f| view::draw(f, &mut model))?;

    loop {
        let mut cmds: Vec<Cmd> = tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                        handle_key(&mut model, key)
                    }
                    Some(Ok(Event::Resize(_, _))) => Vec::new(),
                    Some(Err(_)) | None => break,
                    _ => Vec::new(),
                }
            }
            Some(msg) = rx.recv() => {
                apply_msg(&mut model, msg)
            }
            _ = refresh.tick() => {
                spawn_action(&client, &km, &tx, &refresh_state, Cmd::Fetch);
                Vec::new()
            }
            _ = spin.tick() => {
                model.spinner_frame = model.spinner_frame.wrapping_add(1);
                Vec::new()
            }
        };

        cmds.extend(coins::due(&mut model, std::time::Instant::now()));
        if let Some(error) = saved.sync(&model) {
            model.status_msg = format!("View settings: not saved ({error}).");
            model.status_is_error = true;
        }

        if model.refresh_seconds != polling_seconds {
            polling_seconds = model.refresh_seconds;
            let period = Duration::from_secs(polling_seconds);
            refresh = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }

        for cmd in cmds {
            if matches!(cmd, Cmd::Quit) {
                return Ok(());
            }
            spawn_action(&client, &km, &tx, &refresh_state, cmd);
        }

        terminal.draw(|f| view::draw(f, &mut model))?;
    }
    Ok(())
}

/// Options of a one-shot render: see [`render`].
struct RenderOptions {
    width: u16,
    height: u16,
    /// Keys applied before drawing, e.g. `n`, `Tab`, `Down`, `Ctrl+o`.
    keys: Vec<String>,
    /// Draw with colors on; when false, warnings carry the colorless `!`.
    color: bool,
    /// How long to wait for the node's answers.
    timeout: Duration,
    /// Show private wallet fields (`--reveal`); else they are masked.
    reveal: bool,
}

impl RenderOptions {
    /// Set up the model a render draws: private wallet fields masked
    /// unless `--reveal`.
    fn prepare(&self, model: &mut Model) {
        model.mask_private = !self.reveal;
    }
}

/// `qclient node manage --render`: fetch the node's data once, apply
/// the given keys, draw one frame and print it as plain text. Read-only: the
/// commands keys or results would start (joins, lifecycle operations, worker
/// changes, follow-up checks) are dropped and reported on stderr.
async fn render(
    pc: &ProverCtx,
    refresh_state: RefreshState,
    opts: RenderOptions,
) -> anyhow::Result<()> {
    let client = pc.connect().await?;
    let km = pc.key_manager.clone();
    let mut model = Model::new();
    if let Some(path) = settings::default_path() {
        settings::apply(&mut model, &settings::read(&path));
    }
    model.color_coding = opts.color;
    opts.prepare(&mut model);
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    spawn_action(&client, &km, &tx, &refresh_state, Cmd::Fetch);
    // The start's legacy read, as interactively.
    for cmd in coins::due(&mut model, std::time::Instant::now()) {
        spawn_action(&client, &km, &tx, &refresh_state, cmd);
    }
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let mut dropped = Vec::new();
    // One node, shard, reward and legacy answer each.
    let mut pending = 4;
    while pending > 0 {
        let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
            eprintln!(
                "render: {pending} of 4 node answers missing after {}s",
                opts.timeout.as_secs()
            );
            break;
        };
        if matches!(
            msg,
            Msg::RewardRefresh(_)
                | Msg::ShardRefresh(_)
                | Msg::DataRefresh { .. }
                | Msg::LegacyRefresh { .. }
        ) {
            pending -= 1;
        }
        dropped.extend(
            apply_msg(&mut model, msg)
                .into_iter()
                .filter(|cmd| !matches!(cmd, Cmd::Fetch)),
        );
    }
    // Keys apply in order. A read a key starts (legacy coins, a shield's
    // reads and quotes) is read-only, so it runs and the next key waits for
    // its answer; every other command is dropped.
    for key in &opts.keys {
        for cmd in handle_key(&mut model, parse_key(key)?) {
            let answer: fn(&Msg) -> bool = match cmd {
                Cmd::Fetch => continue,
                Cmd::FetchLegacy => |msg| matches!(msg, Msg::LegacyRefresh { .. }),
                Cmd::ShieldPrepare => |msg| matches!(msg, Msg::ShieldPreview(_)),
                Cmd::MintPrepare | Cmd::ClaimPrepare(..) => {
                    |msg| matches!(msg, Msg::MintPreview(_))
                }
                Cmd::FetchShielded => |msg| matches!(msg, Msg::Shielded(_)),
                Cmd::TransferPrepare(_) => |msg| matches!(msg, Msg::TransferPreview(_)),
                other => {
                    dropped.push(other);
                    continue;
                }
            };
            let what = command_name(&cmd);
            spawn_action(&client, &km, &tx, &refresh_state, cmd);
            let deadline = tokio::time::Instant::now() + opts.timeout;
            loop {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(msg)) => {
                        let done = answer(&msg);
                        dropped.extend(
                            apply_msg(&mut model, msg)
                                .into_iter()
                                .filter(|cmd| !matches!(cmd, Cmd::Fetch)),
                        );
                        if done {
                            break;
                        }
                    }
                    _ => {
                        eprintln!("render: {what} missing after {}s", opts.timeout.as_secs());
                        break;
                    }
                }
            }
        }
    }
    let frame = view::render_text(&mut model, opts.width, opts.height);
    for cmd in &dropped {
        eprintln!("render: not run (read-only): {}", command_name(cmd));
    }
    print!("{frame}");
    Ok(())
}

/// Apply the render's keys to the model; returns the commands they would
/// start, refreshes aside.
#[cfg(test)]
fn apply_keys(model: &mut Model, keys: &[String]) -> anyhow::Result<Vec<Cmd>> {
    let mut started = Vec::new();
    for key in keys {
        started.extend(
            handle_key(model, parse_key(key)?)
                .into_iter()
                .filter(|cmd| !matches!(cmd, Cmd::Fetch)),
        );
    }
    Ok(started)
}

/// Apply the render's keys to the model and draw the frame; also returns
/// the commands the keys would start.
#[cfg(test)]
fn render_frame(model: &mut Model, opts: &RenderOptions) -> anyhow::Result<(String, Vec<Cmd>)> {
    opts.prepare(model);
    let started = apply_keys(model, &opts.keys)?;
    Ok((view::render_text(model, opts.width, opts.height), started))
}

/// `qclient node manage --help-text`: the TUI's help as plain text.
fn help_text(width: u16) -> String {
    view::help_text(width)
}

/// A key name for `--keys`: a character, `Tab`, `BackTab`, `Enter`, `Esc`,
/// `Space`, `Backspace`, arrows, `PageUp`/`PageDown`, `Home`/`End`, optionally
/// prefixed with `Ctrl+`.
fn parse_key(name: &str) -> anyhow::Result<KeyEvent> {
    let (modifiers, key) = match name
        .strip_prefix("Ctrl+")
        .or_else(|| name.strip_prefix("ctrl+"))
    {
        Some(key) => (KeyModifiers::CONTROL, key),
        None => (KeyModifiers::NONE, name),
    };
    let code = match key {
        "Tab" => KeyCode::Tab,
        "BackTab" => KeyCode::BackTab,
        "Enter" => KeyCode::Enter,
        "Esc" => KeyCode::Esc,
        "Space" => KeyCode::Char(' '),
        "Backspace" => KeyCode::Backspace,
        "Up" => KeyCode::Up,
        "Down" => KeyCode::Down,
        "Left" => KeyCode::Left,
        "Right" => KeyCode::Right,
        "PageUp" => KeyCode::PageUp,
        "PageDown" => KeyCode::PageDown,
        "Home" => KeyCode::Home,
        "End" => KeyCode::End,
        _ => {
            let mut chars = key.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => KeyCode::Char(c),
                _ => anyhow::bail!("unknown key `{name}`"),
            }
        }
    };
    Ok(KeyEvent::new(code, modifiers))
}

fn command_name(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::Fetch => "refresh",
        Cmd::FetchLegacy => "legacy read",
        Cmd::ShieldPrepare => "shield reads and quotes",
        Cmd::ShieldRun(_) => "shield",
        Cmd::MintPrepare => "mint reads and quote",
        Cmd::ClaimPrepare(..) => "mint claim reads",
        Cmd::MintRun(_) => "mint",
        Cmd::FetchShielded => "shielded coins read",
        Cmd::TransferPrepare(_) => "transfer reads and quote",
        Cmd::TransferRun(_) => "transfer action",
        Cmd::Join(_) => "join",
        Cmd::Lifecycle { .. } => "lifecycle operation",
        Cmd::ToggleManual { .. } | Cmd::MarkManual(_) => "worker mode change",
        Cmd::CheckAllocation { .. } | Cmd::ScheduleAwaitCheck(_) => "allocation check",
        Cmd::Quit => "quit",
    }
}

struct RefreshState {
    node: Arc<Semaphore>,
    shards: Arc<Semaphore>,
    rewards: Arc<Semaphore>,
    legacy: Arc<Semaphore>,
    /// The node config's Ed448 key and network, whose legacy coins the
    /// Coins tab reads, and its directory (shield-all's journal).
    identity: (Option<[u8; 57]>, u8),
    config_dir: Option<std::path::PathBuf>,
    /// What the shield action loads `qclient token`'s context from, and
    /// its `--max-fee`.
    token: Option<(GlobalArgs, u128)>,
    /// The private action log a shield, a mint or a transfer action
    /// records itself in, unless off.
    action_log: Option<crate::commands::token::action_log::ActionLog>,
}

impl Default for RefreshState {
    fn default() -> Self {
        Self {
            node: Arc::new(Semaphore::new(1)),
            shards: Arc::new(Semaphore::new(1)),
            rewards: Arc::new(Semaphore::new(1)),
            legacy: Arc::new(Semaphore::new(1)),
            identity: (None, 0),
            config_dir: None,
            token: None,
            action_log: None,
        }
    }
}

impl RefreshState {
    /// `no_action_log`: `--no-action-log`, or a render.
    fn for_node(pc: &ProverCtx, global: GlobalArgs, max_fee: u128, no_action_log: bool) -> Self {
        let p2p = &pc.node_config.p2p;
        Self {
            identity: (
                crate::commands::token::legacy::config_public_key(&p2p.peer_priv_key),
                p2p.network,
            ),
            config_dir: Some(pc.config_dir.clone()),
            token: Some((global, max_fee)),
            action_log: crate::commands::token::action_log::ActionLog::enabled(
                &pc.config_dir,
                no_action_log,
            ),
            ..Self::default()
        }
    }
}

/// Each refresh stream has one in-flight request, including manual refreshes.
/// The owned permit also releases on cancellation or task failure.
fn spawn_refresh(
    gate: &Arc<Semaphore>,
    tx: &UnboundedSender<Msg>,
    loading: Option<Msg>,
    fetch: impl std::future::Future<Output = Msg> + Send + 'static,
) {
    let Ok(permit) = gate.clone().try_acquire_owned() else {
        return;
    };
    let tx = tx.clone();
    if let Some(loading) = loading {
        let _ = tx.send(loading);
    }
    tokio::spawn(async move {
        let _permit = permit;
        let _ = tx.send(fetch.await);
    });
}

/// Execute a command by spawning its asynchronous action.
fn spawn_action(
    client: &Client,
    km: &Arc<FileKeyManager>,
    tx: &UnboundedSender<Msg>,
    refresh: &RefreshState,
    cmd: Cmd,
) {
    let client = client.clone();
    let km = km.clone();
    let tx = tx.clone();
    match cmd {
        Cmd::Quit => {}
        Cmd::Fetch => {
            spawn_refresh(
                &refresh.node,
                &tx,
                None,
                actions::fetch_data(client.clone()),
            );
            spawn_refresh(
                &refresh.rewards,
                &tx,
                None,
                actions::fetch_rewards(client.clone(), km),
            );
            spawn_refresh(
                &refresh.shards,
                &tx,
                Some(Msg::ShardLoading),
                actions::fetch_shards(client),
            );
        }
        Cmd::FetchLegacy => {
            let (public, network) = refresh.identity;
            spawn_refresh(
                &refresh.legacy,
                &tx,
                None,
                actions::fetch_legacy(client, public, network, refresh.config_dir.clone()),
            );
        }
        Cmd::ShieldPrepare => {
            let token = refresh.token.clone();
            tokio::spawn(async move {
                let _ = tx.send(actions::shield_prepare(token).await);
            });
        }
        Cmd::FetchShielded => {
            let token = refresh.token.clone();
            tokio::spawn(async move {
                let _ = tx.send(actions::fetch_shielded(token).await);
            });
        }
        Cmd::TransferPrepare(kind) => {
            let token = refresh.token.clone();
            tokio::spawn(async move {
                let _ = tx.send(actions::transfer_prepare(token, kind).await);
            });
        }
        Cmd::TransferRun(preview) => {
            let token = refresh.token.clone();
            let log = refresh.action_log.clone();
            tokio::spawn(async move {
                let progress = tx.clone();
                let _ = tx.send(actions::transfer_run(token, preview, progress, log).await);
            });
        }
        Cmd::MintPrepare => {
            let token = refresh.token.clone();
            tokio::spawn(async move {
                let _ = tx.send(actions::mint_prepare(token).await);
            });
        }
        Cmd::ClaimPrepare(path, cited_frame) => {
            let token = refresh.token.clone();
            tokio::spawn(async move {
                let _ = tx.send(actions::claim_prepare(token, path, cited_frame).await);
            });
        }
        Cmd::MintRun(preview) => {
            let token = refresh.token.clone();
            let log = refresh.action_log.clone();
            tokio::spawn(async move {
                let progress = tx.clone();
                let _ = tx.send(actions::mint_run(token, preview, progress, log).await);
            });
        }
        Cmd::ShieldRun(preview) => {
            let token = refresh.token.clone();
            let log = refresh.action_log.clone();
            tokio::spawn(async move {
                let progress = tx.clone();
                let _ = tx.send(actions::shield_run(token, preview, progress, log).await);
            });
        }
        Cmd::Join(filters) => {
            tokio::spawn(async move {
                let _ = tx.send(actions::do_join(client, filters).await);
            });
        }
        Cmd::Lifecycle {
            action,
            filters,
            original_status,
        } => {
            tokio::spawn(async move {
                let _ = tx.send(
                    actions::do_lifecycle(client, km, action, filters, original_status).await,
                );
            });
        }
        Cmd::ToggleManual { core_id, manual } => {
            tokio::spawn(async move {
                let _ = tx.send(actions::do_toggle_manual(client, core_id, manual).await);
            });
        }
        Cmd::MarkManual(ids) => {
            tokio::spawn(async move {
                let _ = tx.send(actions::do_mark_workers_manual(client, ids).await);
            });
        }
        Cmd::CheckAllocation { action, entries } => {
            tokio::spawn(async move {
                let _ = tx.send(actions::check_allocation_status(client, action, entries).await);
            });
        }
        Cmd::ScheduleAwaitCheck(d) => {
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = tx.send(Msg::AwaitCheck);
            });
        }
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;

    #[tokio::test]
    async fn slow_shards_do_not_block_status_or_spawn_duplicate_queries() {
        let state = RefreshState::default();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        spawn_refresh(&state.shards, &tx, Some(Msg::ShardLoading), async move {
            wait.await.unwrap();
            Msg::ShardRefresh(Err("test failure".into()))
        });
        spawn_refresh(&state.shards, &tx, None, async {
            panic!("duplicate shard query")
        });
        spawn_refresh(&state.node, &tx, None, async {
            Msg::DataRefresh {
                node_info: None,
                shard_info: None,
                worker_info: None,
                err: None,
            }
        });
        assert!(matches!(rx.recv().await, Some(Msg::ShardLoading)));
        assert!(matches!(rx.recv().await, Some(Msg::DataRefresh { .. })));
        assert!(rx.try_recv().is_err());
        release.send(()).unwrap();
        assert!(matches!(rx.recv().await, Some(Msg::ShardRefresh(Err(_)))));
        spawn_refresh(&state.shards, &tx, None, async {
            Msg::ShardRefresh(Ok(Default::default()))
        });
        assert!(matches!(rx.recv().await, Some(Msg::ShardRefresh(Ok(_)))));
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

    #[test]
    fn keys_parse_by_name() {
        assert_eq!(
            parse_key("n").unwrap(),
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)
        );
        assert_eq!(parse_key("Tab").unwrap().code, KeyCode::Tab);
        assert_eq!(
            parse_key("Ctrl+o").unwrap(),
            KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL)
        );
        assert_eq!(parse_key("Space").unwrap().code, KeyCode::Char(' '));
        assert!(parse_key("Hyper").is_err());
    }
}

#[cfg(test)]
mod entry_tests {
    use clap::{CommandFactory, Parser};

    use super::super::ProverCommand;
    use super::*;
    use crate::commands::node::NodeCommand;

    #[derive(Parser)]
    struct Qclient {
        #[command(subcommand)]
        node: NodeCommand,
    }

    fn parse(argv: &[&str]) -> ManageArgs {
        let argv = std::iter::once("qclient").chain(argv.iter().copied());
        match Qclient::try_parse_from(argv).unwrap().node {
            NodeCommand::Manage(args)
            | NodeCommand::Prover {
                command: ProverCommand::Manage(args),
            } => args,
            other => panic!("not the manager: {other:?}"),
        }
    }

    /// `qclient node manage <flags>` and `qclient node prover manage <flags>`.
    fn both(flags: &[&str]) -> (ManageArgs, ManageArgs) {
        let entry = [&["manage"][..], flags].concat();
        let alias = [&["prover", "manage"][..], flags].concat();
        (parse(&entry), parse(&alias))
    }

    #[test]
    fn node_manage_takes_the_alias_flags_and_defaults() {
        let (entry, alias) = both(&[]);
        assert_eq!(entry, alias);
        assert_eq!(
            entry,
            ManageArgs {
                render: false,
                help_text: false,
                width: 160,
                height: 50,
                keys: String::new(),
                color: false,
                timeout: 30,
                reveal: false,
                no_action_log: false,
                reset_ui: false,
                max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
            }
        );
        let (entry, alias) = both(&[
            "--render",
            "--width",
            "80",
            "--height",
            "24",
            "--keys",
            "n Tab",
            "--color",
            "--timeout",
            "5",
            "--reset-ui",
            "--max-fee",
            "7",
            "--reveal",
            "--no-action-log",
        ]);
        assert_eq!(entry, alias);
        assert_eq!(
            entry,
            ManageArgs {
                render: true,
                help_text: false,
                width: 80,
                height: 24,
                keys: "n Tab".into(),
                color: true,
                timeout: 5,
                reveal: true,
                no_action_log: true,
                reset_ui: true,
                max_fee: 7,
            }
        );
        // Names, defaults and help of every flag, so help reads the same too.
        let describe = |c: &clap::Command| {
            c.get_arguments()
                .map(|a| {
                    format!(
                        "{:?} {:?} {:?} {:?}",
                        a.get_long(),
                        a.get_default_values(),
                        a.get_help().map(ToString::to_string),
                        a.get_long_help().map(ToString::to_string),
                    )
                })
                .collect::<Vec<_>>()
        };
        let root = Qclient::command();
        let entry = describe(root.find_subcommand("manage").unwrap());
        let alias = describe(
            root.find_subcommand("prover")
                .and_then(|c| c.find_subcommand("manage"))
                .unwrap(),
        );
        assert_eq!(entry.len(), 11);
        assert_eq!(entry, alias);
    }

    /// What an entry prints before any node answer: the help text, or the
    /// frame of a model without data after the render's keys.
    fn offline_output(args: &ManageArgs) -> Option<String> {
        match args.mode() {
            Mode::HelpText(width) => Some(help_text(width)),
            Mode::Render(opts) => Some(render_frame(&mut Model::new(), &opts).unwrap().0),
            Mode::Interactive => None,
        }
    }

    /// The frame drawn straight from the view, with no flag handling between.
    fn direct_frame(keys: &[char], width: u16, height: u16) -> String {
        let mut model = Model::new();
        for &c in keys {
            handle_key(
                &mut model,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            );
        }
        view::render_text(&mut model, width, height)
    }

    /// A render masks private wallet fields unless `--reveal`.
    #[test]
    fn a_render_masks_private_fields_unless_revealed() {
        for (flags, masked) in [
            (&["--render"][..], true),
            (&["--render", "--reveal"][..], false),
        ] {
            let (entry, _) = both(flags);
            let Mode::Render(opts) = entry.mode() else {
                panic!("{flags:?}: not a render");
            };
            let mut model = Model::new();
            assert!(!model.mask_private);
            render_frame(&mut model, &opts).unwrap();
            assert_eq!(model.mask_private, masked, "{flags:?}");
        }
    }

    #[test]
    fn node_manage_prints_what_the_alias_prints() {
        let cases: [(&[&str], Option<String>); 4] = [
            (
                &["--render", "--width", "80", "--height", "24", "--keys", "h"],
                Some(direct_frame(&['h'], 80, 24)),
            ),
            (
                &["--render", "--width", "120", "--height", "30"],
                Some(direct_frame(&[], 120, 30)),
            ),
            (
                &["--render", "--help-text", "--width", "80"],
                Some(view::help_text(80)),
            ),
            (&[], None),
        ];
        for (flags, expected) in cases {
            let (entry, alias) = both(flags);
            let entry = offline_output(&entry);
            assert_eq!(entry, offline_output(&alias), "{flags:?}");
            assert_eq!(entry, expected, "{flags:?}");
        }
        // The help frame is not the main frame, so the keys did apply.
        assert_ne!(direct_frame(&['h'], 80, 24), direct_frame(&[], 80, 24));
    }
}
