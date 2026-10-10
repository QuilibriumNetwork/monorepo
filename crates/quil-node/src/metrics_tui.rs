//! `--metrics-tui`: live terminal dashboard over the running node's metrics.
//!
//! Polls the node's gRPC `NodeService::GetMetrics` (the same endpoint the
//! `--metrics` dump and Prometheus scrapes use, so it attaches to a LIVE
//! node — no restart, no extra config) and renders every series in a
//! filterable, sortable table with live per-second rates.
//!
//! Keys:
//! - `/` edit the substring filter (Enter/Esc to leave edit mode)
//! - `Tab` cycle section (All → P2P → BlossomSub → RPC → Engine → Other)
//! - `s` cycle sort (name → value → rate)
//! - `p` pause/resume polling
//! - `+` / `-` refresh interval (0.5s..10s)
//! - `↑`/`↓`/PgUp/PgDn scroll
//! - `q` / Ctrl-C quit

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

/// One parsed prometheus series: `name{labels} value`.
#[derive(Clone, Debug)]
struct Sample {
    name: String,
    labels: String,
    value: f64,
}

/// Parse prometheus text exposition into samples. Ignores comment/`# TYPE`/
/// `# HELP` lines; histogram/summary series come through as their `_bucket`/
/// `_sum`/`_count` component series, which is what we want to display.
fn parse_prometheus_text(text: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `name{labels} value [timestamp]` or `name value [timestamp]`
        let (series, rest) = if let Some(close) = line.find('}') {
            if let Some(open) = line.find('{') {
                if open < close {
                    (&line[..=close], line[close + 1..].trim_start())
                } else {
                    match line.split_once(char::is_whitespace) {
                        Some((s, r)) => (s, r),
                        None => continue,
                    }
                }
            } else {
                match line.split_once(char::is_whitespace) {
                    Some((s, r)) => (s, r),
                    None => continue,
                }
            }
        } else {
            match line.split_once(char::is_whitespace) {
                Some((s, r)) => (s, r),
                None => continue,
            }
        };
        let value = match rest.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let (name, labels) = match series.split_once('{') {
            Some((n, l)) => (n.to_string(), format!("{{{}", l)),
            None => (series.to_string(), String::new()),
        };
        out.push(Sample { name, labels, value });
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    All,
    P2p,
    Blossomsub,
    Rpc,
    Engine,
    Other,
}

impl Section {
    fn next(self) -> Self {
        match self {
            Section::All => Section::P2p,
            Section::P2p => Section::Blossomsub,
            Section::Blossomsub => Section::Rpc,
            Section::Rpc => Section::Engine,
            Section::Engine => Section::Other,
            Section::Other => Section::All,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Section::All => "All",
            Section::P2p => "P2P",
            Section::Blossomsub => "BlossomSub",
            Section::Rpc => "RPC",
            Section::Engine => "Engine",
            Section::Other => "Other",
        }
    }
    fn matches(self, name: &str) -> bool {
        match self {
            Section::All => true,
            Section::P2p => name.starts_with("libp2p_"),
            Section::Blossomsub => name.starts_with("blossomsub_"),
            Section::Rpc => name.starts_with("rpc_"),
            Section::Engine => {
                name.starts_with("engine_") || name.starts_with("execution_")
            }
            Section::Other => {
                !name.starts_with("libp2p_")
                    && !name.starts_with("blossomsub_")
                    && !name.starts_with("rpc_")
                    && !name.starts_with("engine_")
                    && !name.starts_with("execution_")
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Name,
    Value,
    Rate,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Sort::Name => Sort::Value,
            Sort::Value => Sort::Rate,
            Sort::Rate => Sort::Name,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Sort::Name => "name",
            Sort::Value => "value",
            Sort::Rate => "rate",
        }
    }
}

/// A display row with its computed per-second rate.
struct DisplayRow {
    name: String,
    labels: String,
    value: f64,
    rate: Option<f64>,
}

struct App {
    endpoint: String,
    /// series key (`name{labels}`) → (value, sampled_at) from the PREVIOUS
    /// poll, for rate computation.
    prev: HashMap<String, (f64, Instant)>,
    rows: Vec<DisplayRow>,
    filter: String,
    editing_filter: bool,
    section: Section,
    sort: Sort,
    paused: bool,
    refresh: Duration,
    scroll: usize,
    last_ok: Option<Instant>,
    last_err: Option<String>,
    total_series: usize,
}

impl App {
    fn ingest(&mut self, samples: Vec<Sample>) {
        let now = Instant::now();
        self.total_series = samples.len();
        let mut rows = Vec::with_capacity(samples.len());
        let mut next_prev = HashMap::with_capacity(samples.len());
        for s in samples {
            let key = format!("{}{}", s.name, s.labels);
            let rate = self.prev.get(&key).and_then(|(pv, pt)| {
                let dt = now.duration_since(*pt).as_secs_f64();
                if dt > 0.0 {
                    Some((s.value - pv) / dt)
                } else {
                    None
                }
            });
            next_prev.insert(key, (s.value, now));
            rows.push(DisplayRow {
                name: s.name,
                labels: s.labels,
                value: s.value,
                rate,
            });
        }
        self.prev = next_prev;
        self.rows = rows;
        self.last_ok = Some(now);
        self.last_err = None;
    }

    fn visible(&self) -> Vec<&DisplayRow> {
        let needle = self.filter.to_lowercase();
        let mut rows: Vec<&DisplayRow> = self
            .rows
            .iter()
            .filter(|r| self.section.matches(&r.name))
            .filter(|r| {
                needle.is_empty()
                    || r.name.to_lowercase().contains(&needle)
                    || r.labels.to_lowercase().contains(&needle)
            })
            .collect();
        match self.sort {
            Sort::Name => rows.sort_by(|a, b| (&a.name, &a.labels).cmp(&(&b.name, &b.labels))),
            Sort::Value => rows.sort_by(|a, b| {
                b.value
                    .partial_cmp(&a.value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Sort::Rate => rows.sort_by(|a, b| {
                b.rate
                    .unwrap_or(0.0)
                    .abs()
                    .partial_cmp(&a.rate.unwrap_or(0.0).abs())
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
        }
        rows
    }
}

fn fmt_value(v: f64) -> String {
    if v == 0.0 {
        "0".to_string()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        let i = v as i64;
        if i.abs() >= 1_000_000_000 {
            format!("{:.2}G", v / 1e9)
        } else if i.abs() >= 1_000_000 {
            format!("{:.2}M", v / 1e6)
        } else {
            format!("{}", i)
        }
    } else {
        format!("{:.4}", v)
    }
}

fn fmt_rate(r: Option<f64>) -> String {
    match r {
        None => String::new(),
        Some(r) if r.abs() < 0.005 => "·".to_string(),
        Some(r) => format!("{:+.2}/s", r),
    }
}

/// Fetch one metrics snapshot from the node.
async fn fetch(
    client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<
        tonic::transport::Channel,
    >,
) -> Result<Vec<Sample>, String> {
    let resp = client
        .get_metrics(quil_types::proto::node::GetMetricsRequest {
            filter: String::new(),
        })
        .await
        .map_err(|e| e.to_string())?
        .into_inner();
    Ok(parse_prometheus_text(&String::from_utf8_lossy(&resp.metrics)))
}

/// Restore the terminal even if the draw loop errors/panics.
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    }
}

pub async fn run_metrics_tui(
    config: &quil_config::Config,
    initial_filter: Option<String>,
) -> anyhow::Result<()> {
    // Same dial logic as `--metrics`.
    let addr = {
        let parts: Vec<&str> = config
            .listen_grpc_multiaddr
            .trim_start_matches('/')
            .split('/')
            .collect();
        if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
            let host = if parts[1] == "0.0.0.0" { "127.0.0.1" } else { parts[1] };
            format!("{}:{}", host, parts[3])
        } else {
            "127.0.0.1:8337".to_string()
        }
    };
    let endpoint = format!("http://{addr}");
    let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())?
        .connect_timeout(Duration::from_secs(5))
        // Lazy: keep retrying inside the poll loop so the TUI can start
        // before/across node restarts.
        .connect_lazy();
    let mut client =
        quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);

    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let _guard = TerminalGuard;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut app = App {
        endpoint,
        prev: HashMap::new(),
        rows: Vec::new(),
        filter: initial_filter.unwrap_or_default(),
        editing_filter: false,
        section: Section::All,
        sort: Sort::Name,
        paused: false,
        refresh: Duration::from_secs(1),
        scroll: 0,
        last_ok: None,
        last_err: None,
        total_series: 0,
    };

    let mut events = EventStream::new();
    let mut next_poll = Instant::now();

    loop {
        // Poll when due.
        if !app.paused && Instant::now() >= next_poll {
            match fetch(&mut client).await {
                Ok(samples) => app.ingest(samples),
                Err(e) => app.last_err = Some(e),
            }
            next_poll = Instant::now() + app.refresh;
        }

        terminal.draw(|f| draw(f, &app))?;

        // Wait for a key or the next poll tick.
        let wait = next_poll.saturating_duration_since(Instant::now()).min(Duration::from_millis(250));
        tokio::select! {
            ev = events.next() => {
                let Some(Ok(Event::Key(key))) = ev else { continue };
                if key.kind != crossterm::event::KeyEventKind::Press {
                    continue;
                }
                if app.editing_filter {
                    match key.code {
                        KeyCode::Esc => {
                            app.filter.clear();
                            app.editing_filter = false;
                        }
                        KeyCode::Enter => app.editing_filter = false,
                        KeyCode::Backspace => {
                            app.filter.pop();
                        }
                        KeyCode::Char(c) => app.filter.push(c),
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('/') => app.editing_filter = true,
                    KeyCode::Tab => {
                        app.section = app.section.next();
                        app.scroll = 0;
                    }
                    KeyCode::Char('s') => app.sort = app.sort.next(),
                    KeyCode::Char('p') => app.paused = !app.paused,
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        app.refresh = (app.refresh / 2).max(Duration::from_millis(500));
                    }
                    KeyCode::Char('-') => {
                        app.refresh = (app.refresh * 2).min(Duration::from_secs(10));
                    }
                    KeyCode::Up => app.scroll = app.scroll.saturating_sub(1),
                    KeyCode::Down => app.scroll = app.scroll.saturating_add(1),
                    KeyCode::PageUp => app.scroll = app.scroll.saturating_sub(20),
                    KeyCode::PageDown => app.scroll = app.scroll.saturating_add(20),
                    KeyCode::Home => app.scroll = 0,
                    _ => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
    Ok(())
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(1), // status / filter
            Constraint::Min(1),    // table
            Constraint::Length(1), // key help
        ])
        .split(f.area());

    // Header: endpoint + sections with current highlighted.
    let mut header_spans = vec![
        Span::styled(" quil metrics ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("{}  ", app.endpoint)),
    ];
    let mut s = Section::All;
    loop {
        let style = if s == app.section {
            Style::default().fg(Color::Black).bg(Color::Cyan)
        } else {
            Style::default().fg(Color::Cyan)
        };
        header_spans.push(Span::styled(format!(" {} ", s.label()), style));
        s = s.next();
        if s == Section::All {
            break;
        }
    }
    f.render_widget(Paragraph::new(Line::from(header_spans)), chunks[0]);

    // Status line: refresh / pause / sort / filter / errors.
    let age = app
        .last_ok
        .map(|t| format!("{:.0}s ago", t.elapsed().as_secs_f64()))
        .unwrap_or_else(|| "never".to_string());
    let mut status = vec![Span::raw(format!(
        " every {:.1}s{}  sample {}  sort {}  series {}",
        app.refresh.as_secs_f64(),
        if app.paused { " [PAUSED]" } else { "" },
        age,
        app.sort.label(),
        app.total_series,
    ))];
    if app.editing_filter || !app.filter.is_empty() {
        status.push(Span::styled(
            format!("  filter: {}{}", app.filter, if app.editing_filter { "▏" } else { "" }),
            Style::default().fg(Color::Yellow),
        ));
    }
    if let Some(e) = &app.last_err {
        status.push(Span::styled(
            format!("  fetch error: {}", e),
            Style::default().fg(Color::Red),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(status)), chunks[1]);

    draw_table(f, chunks[2], app);

    let help = " q quit   / filter   Tab section   s sort   p pause   +/- refresh   ↑↓ scroll ";
    f.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

fn draw_table(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let rows_all = app.visible();
    let height = area.height.saturating_sub(2) as usize; // header + border
    let max_scroll = rows_all.len().saturating_sub(height);
    let scroll = app.scroll.min(max_scroll);

    let rows: Vec<Row> = rows_all
        .iter()
        .skip(scroll)
        .take(height)
        .map(|r| {
            let rate = fmt_rate(r.rate);
            let rate_style = match r.rate {
                Some(x) if x > 0.005 => Style::default().fg(Color::Green),
                Some(x) if x < -0.005 => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::DarkGray),
            };
            Row::new(vec![
                Cell::from(r.name.clone()),
                Cell::from(Span::styled(
                    r.labels.clone(),
                    Style::default().fg(Color::DarkGray),
                )),
                Cell::from(fmt_value(r.value)),
                Cell::from(Span::styled(rate, rate_style)),
            ])
        })
        .collect();

    let shown = rows.len();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(38),
            Constraint::Percentage(38),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["metric", "labels", "value", "rate"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::TOP).title(format!(
        " {}/{} series{} ",
        shown,
        rows_all.len(),
        if scroll > 0 { format!(" (scrolled {})", scroll) } else { String::new() },
    )));
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_labeled_series() {
        let text = "\
# HELP engine_frame_number Current frame
# TYPE engine_frame_number gauge
engine_frame_number 673924
rpc_requests_total{path=\"/quilibrium.node.global.pb.GlobalService/GetGlobalFrame\"} 1234
blossomsub_mesh_peer_counts{bitmask=\"00\"} 5
bad line without value
engine_vdf_prove_seconds_bucket{le=\"0.5\"} 17
";
        let samples = parse_prometheus_text(text);
        assert_eq!(samples.len(), 4);
        assert_eq!(samples[0].name, "engine_frame_number");
        assert_eq!(samples[0].value, 673924.0);
        assert_eq!(samples[1].name, "rpc_requests_total");
        assert!(samples[1].labels.contains("GetGlobalFrame"));
        assert_eq!(samples[2].value, 5.0);
        assert_eq!(samples[3].name, "engine_vdf_prove_seconds_bucket");
    }

    #[test]
    fn section_classification() {
        assert!(Section::Blossomsub.matches("blossomsub_mesh_peer_counts"));
        assert!(Section::P2p.matches("libp2p_connections_established"));
        assert!(Section::Rpc.matches("rpc_requests_total"));
        assert!(Section::Engine.matches("engine_frame_number"));
        assert!(Section::Engine.matches("execution_requests_total"));
        assert!(Section::Other.matches("disk_usage"));
        assert!(!Section::Other.matches("engine_frame_number"));
    }
}
