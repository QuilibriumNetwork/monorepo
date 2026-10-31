//! Where a token command's progress lines go. A CLI command prints them
//! on stdout; the node manager runs the same code with a sink in scope and
//! shows the lines itself, since a print would overwrite its screen.

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
}
