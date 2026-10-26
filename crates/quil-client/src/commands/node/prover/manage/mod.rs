//! `qclient node prover manage` — interactive shard-management TUI.
//!
//! Port of the bubbletea program in `client/cmd/node/prover/` (proverManage.go
//! + manage_model.go + manage_actions.go). The bubbletea Elm loop is
//! reimplemented as a ratatui + crossterm async event loop:
//!
//! * [`model`] holds all state (the `manageModel` struct),
//! * [`update`] applies messages + key events (`Update`/`handleKey`),
//! * [`actions`] performs the async RPC commands (the `tea.Cmd`s),
//! * [`view`] renders (the `View`).

mod actions;
#[cfg(test)]
mod cadence;
mod filter;
mod model;
mod msg;
mod update;
mod util;
mod view;

use std::io::Stdout;
use std::sync::Arc;
use std::time::Duration;

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

use self::model::Model;
use self::msg::Msg;
use self::update::{apply_msg, handle_key, Cmd};
use super::ProverCtx;

type Client = NodeServiceClient<Channel>;
type Term = Terminal<CrosstermBackend<Stdout>>;

/// `qclient node prover manage` entry point (`NodeProverManageCmd.Run`).
pub async fn run(pc: &ProverCtx) -> anyhow::Result<()> {
    let client = pc.connect().await?;
    let km = pc.key_manager.clone();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = event_loop(&mut terminal, client, km).await;

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
) -> anyhow::Result<()> {
    let mut model = Model::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();

    let refresh_state = RefreshState::default();

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
        let cmds: Vec<Cmd> = tokio::select! {
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
pub struct RenderOptions {
    pub width: u16,
    pub height: u16,
    /// Keys applied before drawing, e.g. `n`, `Tab`, `Down`, `Ctrl+o`.
    pub keys: Vec<String>,
    /// Draw with colors on; when false, warnings carry the colorless `!`.
    pub color: bool,
    /// How long to wait for the node's answers.
    pub timeout: Duration,
}

/// `qclient node prover manage --render`: fetch the node's data once, apply
/// the given keys, draw one frame and print it as plain text. Read-only: the
/// commands keys or results would start (joins, lifecycle operations, worker
/// changes, follow-up checks) are dropped and reported on stderr.
pub async fn render(pc: &ProverCtx, opts: RenderOptions) -> anyhow::Result<()> {
    let client = pc.connect().await?;
    let km = pc.key_manager.clone();
    let mut model = Model::new();
    model.color_coding = opts.color;
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    spawn_action(&client, &km, &tx, &RefreshState::default(), Cmd::Fetch);
    let deadline = tokio::time::Instant::now() + opts.timeout;
    let mut dropped = Vec::new();
    // One node, shard and reward answer each.
    let mut pending = 3;
    while pending > 0 {
        let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
            eprintln!(
                "render: {pending} of 3 node answers missing after {}s",
                opts.timeout.as_secs()
            );
            break;
        };
        if matches!(
            msg,
            Msg::RewardRefresh(_) | Msg::ShardRefresh(_) | Msg::DataRefresh { .. }
        ) {
            pending -= 1;
        }
        dropped.extend(
            apply_msg(&mut model, msg)
                .into_iter()
                .filter(|cmd| !matches!(cmd, Cmd::Fetch)),
        );
    }
    for key in &opts.keys {
        dropped.extend(
            handle_key(&mut model, parse_key(key)?)
                .into_iter()
                .filter(|cmd| !matches!(cmd, Cmd::Fetch)),
        );
    }
    for cmd in &dropped {
        eprintln!("render: not run (read-only): {}", command_name(cmd));
    }
    print!("{}", view::render_text(&mut model, opts.width, opts.height));
    Ok(())
}

/// `qclient node prover manage --help-text`: the TUI's help as plain text.
pub fn help_text(width: u16) -> String {
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
}

impl Default for RefreshState {
    fn default() -> Self {
        Self {
            node: Arc::new(Semaphore::new(1)),
            shards: Arc::new(Semaphore::new(1)),
            rewards: Arc::new(Semaphore::new(1)),
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
