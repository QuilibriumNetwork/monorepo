//! Host confirmation. The socket is mode 0600 beside the config file.
//! `qagent confirm <id>` is the only submit path.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::mcp::App;
use crate::ops;

/// `<config>.sock`, so `~/.quilibrium/qagent.yaml` confirms on `qagent.sock`.
pub fn socket_path(config: &Path) -> PathBuf {
    config.with_extension("sock")
}

/// The accept loop. Dropping it stops the loop and removes the socket.
pub struct Control {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Control {
    pub fn start(app: Arc<App>) -> anyhow::Result<Self> {
        let path = socket_path(&app.settings.config_path);
        if path.exists() {
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(_) => anyhow::bail!("qagent is already running ({})", path.display()),
                Err(_) => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let listener = UnixListener::bind(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(socket = %path.display(), "host confirm socket ready; no quote is waiting");
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let app = Arc::clone(&app);
                        tokio::spawn(handle(stream, app));
                    }
                    Err(err) => {
                        tracing::warn!(%err, "confirm socket closed");
                        break;
                    }
                }
            }
        });
        Ok(Self { path, task })
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.path);
    }
}

async fn handle(mut stream: UnixStream, app: Arc<App>) {
    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let line = String::from_utf8_lossy(&buf[..n]);
    let line = line.trim();
    let now = std::time::Instant::now();
    let response = if line == "status" {
        ops::status_report(&app.settings, &app.pending, now).await
    } else if let Some(id) = line.strip_prefix("confirm ") {
        if !id.is_empty() && !id.contains(char::is_whitespace) {
            ops::confirm(&app.host, &app.settings, &app.pending, id, now).await
        } else {
            "The confirmation id is the long hex value printed on the qagent screen under the quote. Run: qagent status".to_string()
        }
    } else {
        "Run qagent status to see whether a quote is waiting. When a quote is printed on the qagent screen, approve it with qagent confirm and the id from that screen.".to_string()
    };
    let mut bytes = response.into_bytes();
    bytes.push(b'\n');
    let _ = stream.write_all(&bytes).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, KeyAccess, Settings};
    use crate::mcp::App;
    use crate::ops::{Host, NodeFacts, Script};
    use quil_client::commands::token::AgentQuote;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn confirm_on_the_socket_submits_and_the_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("qagent.yaml");
        let quote = AgentQuote {
            submits: true,
            text: "To 0xrecipientsecret".into(),
            fee: Some(10),
            fee_explicit: true,
            max_fee: 100,
            variable_amount: None,
        };
        let app = Arc::new(App::with_host(
            Settings {
                listen: "127.0.0.1:8350".into(),
                keys: vec![ApiKey::new("operator", "k", KeyAccess::Full)],
                fee_slippage_bps: 200,
                max_fee: 100,
                node_config: String::new(),
                network: None,
                config_path: config.clone(),
            },
            Host::script(Script {
                balance: std::sync::Mutex::new(Ok(String::new())),
                node: std::sync::Mutex::new(Ok(NodeFacts {
                    version: "1".into(),
                    peer_id: "peer".into(),
                    running_workers: "0".into(),
                    allocated_workers: "0".into(),
                    worker_capacity: "0".into(),
                    last_global_head_frame: "0".into(),
                    last_received_frame: "0".into(),
                    current_epoch: "0".into(),
                    epoch_length_frames: "0".into(),
                    reachable: "true".into(),
                })),
                previews: std::sync::Mutex::new(vec![Ok(quote.clone())]),
                execute: std::sync::Mutex::new(Ok("included-text".into())),
            }),
        ));
        let id = app.pending.lock().await.insert(
            vec!["transfer".into(), "to".into(), "1".into()],
            quote,
            std::time::Instant::now(),
        );
        let control = Control::start(Arc::clone(&app)).unwrap();
        let mode = fs::metadata(socket_path(&config))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let mut stream = UnixStream::connect(socket_path(&config)).await.unwrap();
        stream
            .write_all(format!("confirm {id}\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.contains("Submitted"), "{response}");
        assert!(response.contains("included-text"), "{response}");
        drop(control);
        assert!(!socket_path(&config).exists());
    }
}
