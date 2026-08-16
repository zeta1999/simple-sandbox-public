//! Unprivileged HTTP CONNECT allowlist proxy.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Running proxy handle. Drop or call `shutdown` to stop.
pub struct ProxyHandle {
    pub port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Start a CONNECT proxy bound to 127.0.0.1:0 (ephemeral port).
///
/// `allow` is a set of `host:port` keys (host lowercased). Empty set denies all.
pub async fn start_allowlist_proxy(allow: HashSet<String>) -> Result<ProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind proxy")?;
    let addr = listener.local_addr()?;
    let port = addr.port();
    let allow = Arc::new(normalize_allow(allow));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    info!(
        port,
        entries = allow.len(),
        "CONNECT allowlist proxy listening"
    );

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("proxy shutdown");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            let allow = Arc::clone(&allow);
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, peer, &allow).await {
                                    debug!(error = %e, "proxy client error");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "proxy accept failed");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(ProxyHandle {
        port,
        shutdown: Some(shutdown_tx),
        join: Some(join),
    })
}

fn normalize_allow(allow: HashSet<String>) -> HashSet<String> {
    allow
        .into_iter()
        .map(|s| {
            let s = s.trim().to_ascii_lowercase();
            if s.contains(':') {
                s
            } else {
                format!("{s}:443")
            }
        })
        .collect()
}

/// Build allow set from host/port pairs.
pub fn allow_from_endpoints(endpoints: impl IntoIterator<Item = (String, u16)>) -> HashSet<String> {
    endpoints
        .into_iter()
        .map(|(host, port)| format!("{}:{port}", host.to_ascii_lowercase()))
        .collect()
}

async fn handle_client(stream: TcpStream, peer: SocketAddr, allow: &HashSet<String>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.is_empty() {
        return Ok(());
    }

    // Drain headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        let mut stream = reader.into_inner();
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await?;
        bail!("only CONNECT supported");
    }

    let target = parts[1].to_ascii_lowercase();
    let key = if target.contains(':') {
        target.clone()
    } else {
        format!("{target}:443")
    };

    let mut stream = reader.into_inner();

    if !allow.contains(&key) {
        warn!(peer = %peer, target = %key, "CONNECT denied");
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }

    let upstream = match TcpStream::connect(&key).await {
        Ok(s) => s,
        Err(e) => {
            warn!(target = %key, error = %e, "CONNECT upstream failed");
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    debug!(peer = %peer, target = %key, "CONNECT allowed");
    relay(stream, upstream).await?;
    Ok(())
}

async fn relay(left: TcpStream, right: TcpStream) -> Result<()> {
    let (mut lr, mut lw) = left.into_split();
    let (mut rr, mut rw) = right.into_split();
    let a = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match lr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if rw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let b = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match rr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if lw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let _ = tokio::join!(a, b);
    Ok(())
}

/// Check whether a host:port would be allowed (for tests / dry-run).
pub fn is_allowed(allow: &HashSet<String>, host: &str, port: u16) -> bool {
    let key = format!("{}:{port}", host.to_ascii_lowercase());
    allow.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn denies_unknown_host() {
        let allow = allow_from_endpoints([("example.com".into(), 443)]);
        let proxy = start_allowlist_proxy(allow).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .unwrap();
        client
            .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 128];
        let n = client.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("403"), "got {resp}");
        proxy.shutdown().await;
    }

    #[test]
    fn allow_helper() {
        let a = allow_from_endpoints([("API.GitHub.com".into(), 443)]);
        assert!(is_allowed(&a, "api.github.com", 443));
        assert!(!is_allowed(&a, "evil.test", 443));
    }
}
