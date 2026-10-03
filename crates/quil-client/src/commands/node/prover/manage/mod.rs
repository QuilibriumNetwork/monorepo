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
mod filter;
mod model;
mod msg;
mod update;
mod util;
mod view;

use std::io::Stdout;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::execute;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc::{self, UnboundedSender};
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

async fn event_loop(terminal: &mut Term, client: Client, km: Arc<FileKeyManager>) -> anyhow::Result<()> {
    let mut model = Model::new();
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();

    // Kick off the initial fetch + auto-refresh + spinner tickers.
    spawn_action(&client, &km, &tx, Cmd::Fetch);
    let mut refresh = tokio::time::interval(Duration::from_secs(8));
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
                spawn_action(&client, &km, &tx, Cmd::Fetch);
                Vec::new()
            }
            _ = spin.tick() => {
                model.spinner_frame = model.spinner_frame.wrapping_add(1);
                Vec::new()
            }
        };

        for cmd in cmds {
            if matches!(cmd, Cmd::Quit) {
                return Ok(());
            }
            spawn_action(&client, &km, &tx, cmd);
        }

        terminal.draw(|f| view::draw(f, &mut model))?;
    }
    Ok(())
}

/// Execute a [`Cmd`] by spawning the matching async task (or timer); each
/// posts its resulting [`Msg`] back onto the channel.
fn spawn_action(client: &Client, km: &Arc<FileKeyManager>, tx: &UnboundedSender<Msg>, cmd: Cmd) {
    let client = client.clone();
    let km = km.clone();
    let tx = tx.clone();
    match cmd {
        Cmd::Quit => {}
        Cmd::Fetch => {
            tokio::spawn(async move {
                let _ = tx.send(actions::fetch_data(client).await);
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
