//! Log formatting + file rotation matching Go's zap Console encoder.
//!
//! Users have tooling built around the Go log line shape:
//!
//! ```text
//! 2026-04-22T01:00:00Z  info  quil_node:490  P2P identity ready  {"coreId": 0, "peer_id": "Qm..."}
//! ```
//!
//! Separators are tabs. Each field matches Go's `zap.NewProductionEncoderConfig`
//! with `TimeKey="ts"`, `EncodeTime = RFC3339`, `EncodeLevel = Lowercase`,
//! `EncodeCaller = ShortCaller`. The trailing block is a JSON object of
//! structured fields; `coreId` is always present so Go parsers that key off
//! it keep working.
//!
//! Per-core file separation (`master.log` / `worker-N.log`) and retention
//! mirror `utils/logging/file_logger.go`. Rotation honors the `maxAge`
//! (days) knob via `tracing_appender::rolling::daily`; `maxSize` and
//! `maxBackups` fall through to a post-rotation reaper. `compress` is
//! noted but not yet implemented (TODO: gzip reaped rotations).

use std::collections::BTreeMap;
use std::path::Path;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{
    format::Writer, FmtContext, FormatEvent, FormatFields, FormattedFields,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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

        // Fields — JSON object, always with coreId.
        let mut fields = visitor.fields;
        fields.insert(
            "coreId".to_string(),
            serde_json::Value::Number(self.core_id.into()),
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

/// Per-core filename — `master.log` for `core_id=0`, `worker-N.log`
/// otherwise. Matches Go's `filenameForCore`.
pub fn log_filename_for_core(core_id: u32) -> String {
    if core_id == 0 {
        "master.log".to_string()
    } else {
        format!("worker-{}.log", core_id)
    }
}

/// Initialize logging. If `cfg.path` is empty, logs go to stderr with
/// the zap-console formatter. Otherwise a rotating file is opened at
/// `<cfg.path>/<core>.log` and stderr is kept as a mirror so
/// operators still see output when watching a terminal.
///
/// Rotation semantics (match `utils/logging/file_logger.go` →
/// `lumberjack`):
///   * `max_size` (MB) — primary rotation trigger. When the active
///     file surpasses this size, it's renamed with a timestamp suffix
///     and a new file is created. If 0, falls back to daily rotation.
///   * `max_backups` — keep at most N rotated files; older ones are
///     deleted on rotation (via `file-rotate`'s `FileLimit::MaxFiles`).
///     0 means unlimited.
///   * `max_age` (days) — background reaper deletes rotated files
///     older than N days.
///   * `compress` — rotated files are gzip'd immediately on rotation.
///
/// Returns a `WorkerGuard` that must be held alive for the life of
/// the process; dropping it flushes the file appender.
pub fn init_logging(
    cfg: &quil_config::LogConfig,
    core_id: u32,
    debug: bool,
    cli_filter: Option<&str>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = build_env_filter(debug, &cfg.log_filters, cli_filter);

    // stderr layer — always on so systemd / terminal operators see
    // logs regardless of file configuration.
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

    // Build the rotation policy. file-rotate does size-based rotation
    // with timestamp-suffixed rotated files and optional gzip compression
    // on rotate — matching lumberjack's semantics.
    let content_limit = if cfg.max_size > 0 {
        // Go's lumberjack treats MaxSize as MB.
        file_rotate::ContentLimit::BytesSurpassed((cfg.max_size as usize) * 1024 * 1024)
    } else {
        // No explicit size — fall back to daily rotation so files
        // don't grow unbounded.
        file_rotate::ContentLimit::Time(file_rotate::TimeFrequency::Daily)
    };

    let file_limit = if cfg.max_backups > 0 {
        file_rotate::suffix::FileLimit::MaxFiles(cfg.max_backups as usize)
    } else {
        // Go's default when MaxBackups is 0 is "retain all" — we
        // still want some upper bound to prevent runaway disk use;
        // pick a conservative cap that the reaper can further prune.
        file_rotate::suffix::FileLimit::MaxFiles(1024)
    };

    let compression = if cfg.compress {
        // `OnRotate(0)` gzips every rotated file immediately; the
        // argument is the number of unrotated files to keep uncompressed.
        file_rotate::compression::Compression::OnRotate(0)
    } else {
        file_rotate::compression::Compression::None
    };

    let rotate = file_rotate::FileRotate::new(
        log_path.as_path(),
        file_rotate::suffix::AppendTimestamp::default(file_limit),
        content_limit,
        compression,
        #[cfg(unix)]
        None,
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(rotate);

    let file_layer = tracing_subscriber::fmt::layer()
        .event_format(ZapConsoleFormat::new(core_id))
        .with_writer(non_blocking)
        .with_ansi(false);

    // Age reaper: `max_age` (days) isn't a first-class field of
    // file-rotate; run a periodic sweep that removes rotated files
    // older than the cutoff. Keeps `max_backups` enforcement in
    // file-rotate itself.
    spawn_log_reaper(dir.to_path_buf(), &filename, cfg.max_age, 0);

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .init();
    Some(guard)
}

/// Background task: periodically delete rotated log files older than
/// `max_age` days or beyond the `max_backups` count. Mirrors
/// lumberjack's retention logic.
fn spawn_log_reaper(dir: std::path::PathBuf, base: &str, max_age: i32, max_backups: i32) {
    if max_age <= 0 && max_backups <= 0 {
        return;
    }
    let base = base.to_string();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = reap_once(&dir, &base, max_age, max_backups) {
                eprintln!("log reaper: {}", e);
            }
        }
    });
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
        // Rolling daily files look like `master.log.YYYY-MM-DD` — only
        // reap those that belong to our base and have a date suffix.
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
