//! Where a token command's progress lines go. A CLI command prints them
//! on stdout; the node manager runs the same code with a sink in scope and
//! shows the lines itself, since a print would overwrite its screen. Log
//! events take the same way ([`log_layers`]): the keystore's warning when
//! an action loads keys, say, would otherwise land on the manager's screen.

use tokio::sync::mpsc::UnboundedSender;

tokio::task_local! {
    static SINK: UnboundedSender<String>;
}

/// Print `text` as one stdout line, or send it to the sink in scope (a
/// closed sink drops it: the screen it was for is gone).
pub(crate) fn line(text: String) {
    if SINK
        .try_with(|sink| {
            let _ = sink.send(text.clone());
        })
        .is_err()
    {
        println!("{text}");
    }
}

/// Print `text` as one stderr line, or send it to the sink in scope.
pub(crate) fn err_line(text: String) {
    if SINK
        .try_with(|sink| {
            let _ = sink.send(text.clone());
        })
        .is_err()
    {
        eprintln!("{text}");
    }
}

/// Whether a sink is in scope: then nothing may write to the terminal.
pub(crate) fn captured() -> bool {
    SINK.try_with(|_| ()).is_ok()
}

/// Run `work` with its progress lines sent to `sink`.
pub(crate) async fn capture<F: std::future::Future>(
    sink: UnboundedSender<String>,
    work: F,
) -> F::Output {
    SINK.scope(sink, work).await
}

/// qclient's log output: each event formatted on `terminal` (stderr) as
/// before, but while a sink is in scope as one plain line to the sink
/// (level and message, no time or color codes), like the progress lines.
pub(crate) fn log_layers<S, W>(terminal: W) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::{filter::filter_fn, Layer};
    let terminal = tracing_subscriber::fmt::layer()
        .with_writer(terminal)
        .with_filter(filter_fn(|_| !captured()));
    let sink = tracing_subscriber::fmt::layer()
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .with_writer(|| SinkLine(Vec::new()))
        .with_filter(filter_fn(|_| captured()));
    terminal.and_then(sink)
}

/// One formatted event, sent to the sink in scope once written.
struct SinkLine(Vec<u8>);

impl std::io::Write for SinkLine {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SinkLine {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.0);
        let text = text.trim();
        if !text.is_empty() {
            err_line(text.to_string());
        }
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[tokio::test]
    async fn lines_reach_the_sink_in_scope_only() {
        assert!(!captured());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        capture(tx, async {
            assert!(captured());
            line("one".into());
        })
        .await;
        assert_eq!(rx.recv().await.as_deref(), Some("one"));
        assert!(!captured());
    }

    /// What the terminal writer received.
    #[derive(Clone, Default)]
    struct Terminal(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Terminal {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for Terminal {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// While the manager runs an action, the keystore's warning (keys
    /// loaded without an encryption key, `RUST_LOG` unset) goes to the
    /// sink as one plain line and nothing reaches the terminal; outside a
    /// sink the terminal gets events as before.
    #[tokio::test]
    async fn log_events_reach_the_sink_while_one_is_in_scope() {
        use tracing_subscriber::layer::SubscriberExt;
        let terminal = Terminal::default();
        let writer = terminal.clone();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("warn"))
            .with(log_layers(move || writer.clone()));
        let _default = tracing::subscriber::set_default(subscriber);
        let directory = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        capture(tx, async {
            quil_keys::FileKeyManager::new(
                directory.path().join("keys.yml"),
                "",
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap();
        })
        .await;
        let line = rx.try_recv().unwrap();
        assert!(
            line.starts_with("WARN keystore encryption DISABLED: "),
            "{line:?}"
        );
        assert!(!line.contains('\x1b') && !line.contains('\n'), "{line:?}");
        assert!(rx.try_recv().is_err(), "one line per event");
        assert_eq!(terminal.text(), "", "nothing reached the terminal");
        tracing::warn!("outside the manager");
        assert!(rx.try_recv().is_err());
        assert!(
            terminal.text().contains("outside the manager"),
            "{}",
            terminal.text()
        );
    }
}
