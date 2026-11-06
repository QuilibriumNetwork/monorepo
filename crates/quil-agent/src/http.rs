//! HTTP transport for MCP. Unauthenticated requests are rejected before any
//! tool runs, including when the listen address is not loopback.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::auth::{request_access, Principal};
use crate::config::random_hex;
use crate::mcp::{self, App};

const SESSION_HEADER: &str = "mcp-session-id";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Server {
    app: Arc<App>,
    sessions: Mutex<Vec<(String, Instant)>>,
}

impl Server {
    pub fn new(app: App) -> Self {
        Self {
            app: Arc::new(app),
            sessions: Mutex::new(Vec::new()),
        }
    }

    pub fn router(self) -> Router {
        Router::new()
            .route(
                "/mcp",
                post(mcp_post).get(method_not_allowed).delete(mcp_delete),
            )
            .layer(DefaultBodyLimit::max(1024 * 1024))
            .with_state(Arc::new(self))
    }
}

/// Bind `settings.listen` and serve until `shutdown` completes.
pub async fn serve(
    app: App,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listen = app.settings.listen.clone();
    let app = Arc::new(app);
    let control = crate::control::Control::start(Arc::clone(&app))?;
    let guide = crate::guide::startup(&app.settings);
    let router = Server {
        app,
        sessions: Mutex::new(Vec::new()),
    }
    .router();
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|err| anyhow::anyhow!("listen on {listen}: {err}"))?;
    eprintln!("\n{guide}\n");
    let served = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;
    drop(control);
    served.map_err(|err| anyhow::anyhow!("serve {listen}: {err}"))?;
    Ok(())
}

async fn mcp_post(State(server): State<Arc<Server>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(principal) = access_from(&server, &headers) else {
        return unauthorized();
    };
    if !known_session(&server, &headers).await {
        tracing::info!(key = %principal.name, "rejected mcp request: unknown session");
        return StatusCode::NOT_FOUND.into_response();
    }
    let message: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(message) if message.is_object() => message,
        _ => {
            tracing::info!(key = %principal.name, "rejected mcp request: parse error");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": "parse error" }
                })),
            )
                .into_response();
        }
    };
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    tracing::info!(
        method,
        key = %principal.name,
        access = principal.access.as_str(),
        "mcp request"
    );
    let outcome = mcp::dispatch(&server.app, &message, Instant::now(), principal.access).await;
    let Some(body) = outcome else {
        return StatusCode::ACCEPTED.into_response();
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();
    if method == "initialize" {
        let id = random_hex(16);
        let mut sessions = server.sessions.lock().await;
        let now = Instant::now();
        sessions.retain(|(_, created)| now.saturating_duration_since(*created) < SESSION_TTL);
        sessions.push((id.clone(), now));
        response.headers_mut().insert(
            SESSION_HEADER,
            id.parse()
                .unwrap_or_else(|_| header::HeaderValue::from_static("invalid")),
        );
    }
    response
}

async fn mcp_delete(State(server): State<Arc<Server>>, headers: HeaderMap) -> Response {
    let Some(principal) = access_from(&server, &headers) else {
        return unauthorized();
    };
    tracing::info!(key = %principal.name, "mcp session delete");
    if let Some(id) = session_id(&headers) {
        server
            .sessions
            .lock()
            .await
            .retain(|(stored, _)| stored != id);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn method_not_allowed(State(server): State<Arc<Server>>, headers: HeaderMap) -> Response {
    let Some(principal) = access_from(&server, &headers) else {
        return unauthorized();
    };
    tracing::info!(key = %principal.name, access = principal.access.as_str(), "mcp method not allowed");
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

fn access_from(server: &Server, headers: &HeaderMap) -> Option<Principal> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok());
    request_access(authorization, api_key, &server.app.settings.keys)
}

fn unauthorized() -> Response {
    tracing::warn!("rejected an unauthenticated request");
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer realm=\"qagent\""),
    );
    response
}

fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|id| !id.is_empty())
}

async fn known_session(server: &Server, headers: &HeaderMap) -> bool {
    let Some(id) = session_id(headers) else {
        return true;
    };
    let mut sessions = server.sessions.lock().await;
    let now = Instant::now();
    sessions.retain(|(_, created)| now.saturating_duration_since(*created) < SESSION_TTL);
    sessions.iter().any(|(stored, _)| stored == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, KeyAccess, Settings};
    use axum::body::{Body, Bytes};
    use axum::http::{header, HeaderMap, Request, StatusCode};
    use axum::Router;
    use serde_json::Value;
    use tower::ServiceExt;

    fn server() -> Router {
        Server::new(mcp::App::new(Settings {
            listen: "127.0.0.1:8350".into(),
            keys: vec![
                ApiKey::new("operator", "secret", KeyAccess::Full),
                ApiKey::new("dashboard", "reader", KeyAccess::ReadOnly),
            ],
            fee_slippage_bps: 200,
            max_fee: 1,
            node_config: String::new(),
            network: None,
            config_path: std::path::PathBuf::from("qagent.yaml"),
        }))
        .router()
    }

    async fn call(router: Router, builder: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let response = router.oneshot(builder).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, bytes)
    }

    #[tokio::test]
    async fn a_request_without_the_key_does_nothing() {
        let (status, headers, body) = call(
            server(),
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Bearer"));
        assert_eq!(body.as_ref(), br#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn bearer_and_api_key_both_reach_initialize() {
        for (name, value) in [("authorization", "Bearer secret"), ("x-api-key", "secret")] {
            let (status, headers, body) = call(
                server(),
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(name, value)
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert!(headers.get(SESSION_HEADER).is_some(), "{name}");
            let parsed: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(parsed["result"]["serverInfo"]["name"], "qagent");
        }
    }

    #[tokio::test]
    async fn an_unknown_session_is_rejected_after_the_key_checks_out() {
        let (status, _, _) = call(
            server(),
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", "Bearer secret")
                .header(SESSION_HEADER, "not-a-session")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_read_only_key_can_initialize_and_cannot_submit() {
        let (status, _, body) = call(
            server(),
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", "Bearer reader")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["result"]["serverInfo"]["name"], "qagent");

        let (status, _, body) = call(
            server(),
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("x-api-key", "reader")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"token_submit","arguments":{"confirmId":"abc"}}}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["result"]["isError"], true);
        assert!(parsed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("read-only"));
    }
}
