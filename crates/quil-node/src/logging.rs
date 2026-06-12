//! Tab-separated log lines with a JSON tail; `coreId` always present.
//!
//! ```text
//! 2026-04-22T01:00:00Z  info  quil_node:490  P2P identity ready  {"coreId": 0, "peer_id": "Qm..."}
//! ```
//!
//! Per-core file separation (`master.log` / `worker-N.log`) plus
//! size + age + backup retention.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use tracing::{Event, Subscriber};
use tracing_appender::non_blocking::NonBlocking;
use tracing_subscriber::fmt::{
    format::Writer, FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// Worker threads are pinned to one OS thread; a thread-local
// `core_id` covers every event the worker emits between `.await`
// yields.

std::thread_local! {
    static WORKER_CORE_ID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

pub fn set_worker_core_id(core_id: u32) {
    WORKER_CORE_ID.with(|cell| cell.set(Some(core_id)));
}

pub fn current_worker_core_id() -> Option<u32> {
    WORKER_CORE_ID.with(|cell| cell.get())
}

struct PerCoreFiles {
    /// Used when no thread tag is set or the tagged worker hasn't
    /// registered a file yet.
    master: NonBlocking,
    workers: RwLock<HashMap<u32, NonBlocking>>,
    dir: Option<PathBuf>,
    max_size: i32,
    max_backups: i32,
    max_age: i32,
    compress: bool,
    /// Held to keep the master appender alive for the process
    /// lifetime.
    _master_guard: tracing_appender::non_blocking::WorkerGuard,
}

static PER_CORE_FILES: OnceLock<Arc<PerCoreFiles>> = OnceLock::new();

/// First call wins per `core_id`; subsequent calls are a no-op.
pub fn register_worker_log_file(core_id: u32) {
    let Some(files) = PER_CORE_FILES.get() else {
        return;
    };
    {
        let map = files.workers.read().unwrap();
        if map.contains_key(&core_id) {
            return;
        }
    }
    let Some(dir) = files.dir.as_ref() else {
        return;
    };
    let filename = log_filename_for_core(core_id);
    let path = dir.join(&filename);
    let rotate = build_rotating(
        path.as_path(),
        files.max_size,
        files.max_backups,
        files.compress,
    );
    let (nb, guard) = tracing_appender::non_blocking(rotate);
    // `WorkerGuard` must outlive emission for the worker's lifetime.
    Box::leak(Box::new(guard));
    let mut map = files.workers.write().unwrap();
    map.entry(core_id).or_insert(nb);

    if let Some(dir) = files.dir.as_ref() {
        spawn_log_reaper(dir.clone(), &filename, files.max_age, 0);
    }
}

#[derive(Clone)]
struct PerCoreFileWriter {
    files: Arc<PerCoreFiles>,
}

impl<'a> MakeWriter<'a> for PerCoreFileWriter {
    type Writer = WorkerRoutedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        let id = current_worker_core_id();
        let nb = id
            .and_then(|cid| self.files.workers.read().unwrap().get(&cid).cloned())
            .unwrap_or_else(|| self.files.master.clone());
        WorkerRoutedWriter { inner: nb }
    }
}

struct WorkerRoutedWriter {
    inner: NonBlocking,
}

impl Write for WorkerRoutedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Format events as `<ts>\t<level>\t<target>\t<message>\t{<fields>}`.
/// `<ts>` is UTC RFC3339 matching Go's `TimeEncoderOfLayout(time.RFC3339)`.
pub struct ZapConsoleFormat {
    core_id: u32,
}

impl ZapConsoleFormat {
    pub fn new(core_id: u32) -> Self {
        Self { core_id }
    }
}

impl<S, N> FormatEvent<S, N> for ZapConsoleFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // Timestamp — RFC3339, UTC, second precision.
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        write!(writer, "{}\t", ts)?;

        // Level — lowercase ("info", "debug", ...).
        let level = event.metadata().level();
        write!(writer, "{}\t", level.as_str().to_ascii_lowercase())?;

        // Caller — `<package>/<file>:<line>` matching zap's
        // ShortCallerEncoder. Falls back to target if file info is
        // unavailable.
        let target = event.metadata().target();
        match (event.metadata().file(), event.metadata().line()) {
            (Some(file), Some(line)) => {
                // Shorten absolute paths to `<crate>/<basename>` when
                // possible; keep the module target as the prefix so
                // users can grep e.g. `quil_node/main.rs`.
                let short = short_caller(file);
                write!(writer, "{}/{}:{}\t", target.split("::").next().unwrap_or(target), short, line)?;
            }
            (_, Some(line)) => write!(writer, "{}:{}\t", target, line)?,
            _ => write!(writer, "{}\t", target)?,
        }

        // Collect fields into a map so the message is rendered first
        // and everything else as JSON.
        let mut visitor = FieldCollector::default();
        event.record(&mut visitor);

        // Message (Go puts the msg before the fields block).
        let message = visitor.message.unwrap_or_default();
        write!(writer, "{}\t", message)?;

        // Fields — JSON object, always with coreId. The thread-local
        // override, set by worker threads at spawn, takes priority so
        // events emitted from in-process workers carry the worker's
        // own core id rather than the master's `0`.
        let mut fields = visitor.fields;
        let core_id = current_worker_core_id().unwrap_or(self.core_id);
        fields.insert(
            "coreId".to_string(),
            serde_json::Value::Number(core_id.into()),
        );

        // Include span fields (everything up the active span stack).
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let ext = span.extensions();
                if let Some(formatted) = ext.get::<FormattedFields<N>>() {
                    // Parse the span's formatted fields — tracing's
                    // default formatter emits `k=v` pairs. Best-effort
                    // splitting here is fine since span fields are rare.
                    for part in formatted.fields.split(' ') {
                        if let Some((k, v)) = part.split_once('=') {
                            let key = k.trim().to_string();
                            if !key.is_empty() && !fields.contains_key(&key) {
                                fields.insert(
                                    key,
                                    serde_json::Value::String(v.trim().trim_matches('"').to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }

        let json = serde_json::to_string(&fields)
            .unwrap_or_else(|_| "{}".to_string());
        writeln!(writer, "{}", json)?;
        Ok(())
    }
}

/// Short path form — last two segments (e.g. `src/main.rs` →
/// `src/main.rs`, `crates/quil-node/src/main.rs` → `src/main.rs`).
/// Matches zap's `ShortCallerEncoder` which outputs the last two
/// path elements.
fn short_caller(file: &str) -> String {
    let parts: Vec<&str> = file.rsplit('/').take(2).collect();
    if parts.len() == 2 {
        format!("{}/{}", parts[1], parts[0])
    } else {
        file.to_string()
    }
}

/// Visitor that captures the `message` field separately and collects
/// everything else into a JSON object.
#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    fields: BTreeMap<String, serde_json::Value>,
}

impl tracing::field::Visit for FieldCollector {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{:?}", value);
        // tracing uses Debug for all unknown types; strip the surrounding quotes
        // when present (Display-ish behavior) to match Go's presentation.
        let cleaned = s.trim_matches('"').to_string();
        if field.name() == "message" {
            self.message = Some(cleaned);
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(cleaned),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Bool(value),
        );
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields.insert(field.name().to_string(), serde_json::Value::Number(n));
        }
    }
}

/// Compose an `EnvFilter` from the base level + config `logFilters` +
/// optional CLI override. Matches Go's merge order (CLI wins).
pub fn build_env_filter(
    debug: bool,
    config_filters: &std::collections::HashMap<String, String>,
    cli_filter: Option<&str>,
) -> EnvFilter {
    let base = if debug { "debug" } else { "info" };
    let mut directives: Vec<String> = vec![base.to_string()];

    // Third-party noise floor. Routine network failures from the QUIC
    // UDP layer — unreachable IPv6 peers, NAT path closures, etc. —
    // fire as warn from inside `quinn_udp` / `quinn_proto` and were
    // operators' most common false-alarm logs. Cap them at `error`
    // unless the user explicitly opts back in via config or CLI.
    // libp2p subsystems are similarly chatty around connection
    // teardown; cap them at `warn` so legitimate panics still surface.
    directives.push("quinn_udp=error".to_string());
    directives.push("quinn_proto=error".to_string());
    directives.push("quinn=error".to_string());
    directives.push("libp2p_quic=warn".to_string());
    directives.push("libp2p_tcp=warn".to_string());
    directives.push("libp2p_swarm=warn".to_string());

    for (component, level) in config_filters {
        directives.push(format!("{}={}", component, level));
    }
    if let Some(c) = cli_filter {
        // CLI takes priority by being appended last — tracing
        // resolves directives in iteration order, with later
        // overriding earlier matches on the same target.
        directives.push(c.to_string());
    }
    let joined = directives.join(",");
    EnvFilter::try_new(&joined)
        .unwrap_or_else(|_| EnvFilter::new(base))
}

/// `master.log` for `core_id=0`, `worker-N.log` otherwise.
pub fn log_filename_for_core(core_id: u32) -> String {
    if core_id == 0 {
        "master.log".to_string()
    } else {
        format!("worker-{}.log", core_id)
    }
}

/// `cfg.path` empty → stderr only. Otherwise opens a rotating file
/// at `<cfg.path>/<core>.log` and keeps stderr as a mirror.
///
/// Rotation:
///   * `max_size` MB — rotation trigger (0 → daily).
///   * `max_backups` — rotated files retained (0 → 1024 cap).
///   * `max_age` days — reaper deletes older rotations.
///   * `compress` — gzip on rotation.
pub fn init_logging(
    cfg: &quil_config::LogConfig,
    core_id: u32,
    debug: bool,
    cli_filter: Option<&str>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = build_env_filter(debug, &cfg.log_filters, cli_filter);

    let stderr_layer = tracing_subscriber::fmt::layer()
        .event_format(ZapConsoleFormat::new(core_id))
        .with_writer(std::io::stderr)
        .with_ansi(false);

    if cfg.path.is_empty() {
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .init();
        return None;
    }

    let dir = Path::new(&cfg.path);
    let _ = std::fs::create_dir_all(dir);
    let filename = log_filename_for_core(core_id);
    let log_path = dir.join(&filename);

    let rotate = build_rotating(
        log_path.as_path(),
        cfg.max_size,
        cfg.max_backups,
        cfg.compress,
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(rotate);

    let _ = PER_CORE_FILES.set(Arc::new(PerCoreFiles {
        master: non_blocking.clone(),
        workers: RwLock::new(HashMap::new()),
        dir: Some(dir.to_path_buf()),
        max_size: cfg.max_size,
        max_backups: cfg.max_backups,
        max_age: cfg.max_age,
        compress: cfg.compress,
        _master_guard: guard,
    }));
    let files = PER_CORE_FILES.get().expect("PerCoreFiles just set").clone();

    let file_layer = tracing_subscriber::fmt::layer()
        .event_format(ZapConsoleFormat::new(core_id))
        .with_writer(PerCoreFileWriter { files })
        .with_ansi(false);

    spawn_log_reaper(dir.to_path_buf(), &filename, cfg.max_age, 0);

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .init();
    // Master appender is held by `PER_CORE_FILES`.
    None
}

fn build_rotating(
    log_path: &Path,
    max_size: i32,
    max_backups: i32,
    compress: bool,
) -> file_rotate::FileRotate<file_rotate::suffix::AppendTimestamp> {
    let content_limit = if max_size > 0 {
        file_rotate::ContentLimit::BytesSurpassed((max_size as usize) * 1024 * 1024)
    } else {
        file_rotate::ContentLimit::Time(file_rotate::TimeFrequency::Daily)
    };
    let file_limit = if max_backups > 0 {
        file_rotate::suffix::FileLimit::MaxFiles(max_backups as usize)
    } else {
        file_rotate::suffix::FileLimit::MaxFiles(1024)
    };
    let compression = if compress {
        file_rotate::compression::Compression::OnRotate(0)
    } else {
        file_rotate::compression::Compression::None
    };
    file_rotate::FileRotate::new(
        log_path,
        file_rotate::suffix::AppendTimestamp::default(file_limit),
        content_limit,
        compression,
        #[cfg(unix)]
        None,
    )
}

/// Periodically delete rotated log files older than `max_age` days
/// or beyond the `max_backups` count.
///
/// Uses `std::thread` rather than `tokio::spawn` because workers
/// register their per-core log files from non-tokio thread context
/// during init (the worker's `current_thread` runtime hasn't been
/// entered yet). Reaping is pure sync I/O so a plain thread is fine.
fn spawn_log_reaper(dir: std::path::PathBuf, base: &str, max_age: i32, max_backups: i32) {
    if max_age <= 0 && max_backups <= 0 {
        return;
    }
    let base = base.to_string();
    std::thread::Builder::new()
        .name(format!("log-reaper-{}", base))
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            if let Err(e) = reap_once(&dir, &base, max_age, max_backups) {
                eprintln!("log reaper: {}", e);
            }
        })
        .ok();
}

fn reap_once(
    dir: &Path,
    base: &str,
    max_age: i32,
    max_backups: i32,
) -> std::io::Result<()> {
    use std::time::SystemTime;
    let read = std::fs::read_dir(dir)?;
    let mut entries: Vec<(std::path::PathBuf, SystemTime)> = Vec::new();
    for e in read.flatten() {
        let path = e.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        // Skip the live file; only reap rotated suffixed files.
        if !name.starts_with(base) || name == base {
            continue;
        }
        let metadata = e.metadata()?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push((path, mtime));
    }
    // Oldest first.
    entries.sort_by_key(|(_p, t)| *t);

    // Age reap.
    if max_age > 0 {
        let cutoff = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(max_age as u64 * 24 * 3600))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        entries.retain(|(path, mtime)| {
            if *mtime < cutoff {
                let _ = std::fs::remove_file(path);
                false
            } else {
                true
            }
        });
    }
    // Count reap (keep newest `max_backups`).
    if max_backups > 0 && entries.len() > max_backups as usize {
        let drop_count = entries.len() - max_backups as usize;
        for (path, _) in entries.iter().take(drop_count) {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}
