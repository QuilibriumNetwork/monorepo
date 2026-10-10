//! HTTP server that receives run-completion notifications from the proxy.
//!
//! The proxy POSTs a JSON [`FrameNotification`] to `/run-notification` with a
//! `Bearer` token. The [`NotificationRouter`] dispatches each notification to
//! the channel registered for its `run_id`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use devnet::shared::FrameNotification;

/// Routes incoming notifications to the channel registered for each run ID.
#[derive(Clone, Default)]
pub struct NotificationRouter {
    channels: Arc<Mutex<HashMap<String, mpsc::Sender<FrameNotification>>>>,
}

impl NotificationRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a run ID and returns the receiver for its notifications.
    pub fn register(&self, run_id: &str) -> mpsc::Receiver<FrameNotification> {
        let (tx, rx) = mpsc::channel(10);
        self.channels.lock().unwrap().insert(run_id.to_string(), tx);
        rx
    }

    pub fn unregister(&self, run_id: &str) {
        self.channels.lock().unwrap().remove(run_id);
    }

    fn route(&self, notification: FrameNotification) {
        let sender = self
            .channels
            .lock()
            .unwrap()
            .get(&notification.run_id)
            .cloned();
        match sender {
            Some(tx) => {
                // try_send never blocks; the buffer (10) comfortably covers the
                // single terminal notification a run produces.
                if let Err(e) = tx.try_send(notification) {
                    tracing::warn!(error = %e, "Failed to deliver notification");
                }
            }
            None => {
                tracing::warn!(run_id = %notification.run_id, "Notification for unknown run ID");
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    router: NotificationRouter,
    bearer_token: Arc<String>,
}

/// Handle to a running notification server; call [`Self::shutdown`] to stop it.
pub struct ServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    /// Triggers graceful shutdown and waits for the server task to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Err(e) = self.join.await {
            tracing::error!(error = %e, "Notification server task panicked");
        }
    }
}

/// Binds and starts the notification server on `0.0.0.0:<port>`.
pub async fn start_notification_server(
    port: &str,
    bearer_token: String,
    router: NotificationRouter,
) -> anyhow::Result<ServerHandle> {
    let state = AppState {
        router,
        bearer_token: Arc::new(bearer_token),
    };
    let app = Router::new()
        .route("/run-notification", post(handle_notification))
        .with_state(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::debug!(port, "HTTP notification server started");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        if let Err(e) = server.await {
            tracing::error!(error = %e, "HTTP server error");
        }
    });

    Ok(ServerHandle {
        shutdown: Some(shutdown_tx),
        join,
    })
}

async fn handle_notification(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let auth = match headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        Some(a) if !a.is_empty() => a,
        Some(_) | None => return (StatusCode::UNAUTHORIZED, "Missing authorization header"),
    };

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid authorization header format",
        );
    };

    if !constant_time_eq(token.as_bytes(), state.bearer_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Invalid bearer token");
    }

    let notification: FrameNotification = match serde_json::from_slice(&body) {
        Ok(n) => n,
        Err(_) => return (StatusCode::BAD_REQUEST, "Failed to decode notification"),
    };

    tracing::trace!(
        run_id = %notification.run_id,
        stop_frame = notification.stop_frame,
        safety_error = %notification.safety_error,
        "Received notification"
    );

    state.router.route(notification);
    (StatusCode::OK, "")
}

/// Length-checked constant-time byte comparison (matches Go's
/// `subtle.ConstantTimeCompare`, which returns 0 on a length mismatch).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}
