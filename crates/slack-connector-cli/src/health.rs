//! Minimal `/healthz` endpoint. Raw tokio TCP + hand-rolled HTTP/1.1 response
//! to avoid pulling a web framework into the binary.
//!
//! Liveness model: the process reports healthy once sources are wired and the
//! dispatcher is running. If a `stale_after` window is configured and no event
//! has been emitted within it *while sources are active*, the endpoint flips to
//! 503 so an orchestrator can restart a wedged connector.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug)]
pub struct HealthState {
    started: AtomicBool,
    /// Number of enabled sources; 0 means "idle by design", never stale.
    active_sources: AtomicU64,
    last_emit_epoch: AtomicU64,
    events_emitted: AtomicU64,
    start_epoch: u64,
    /// Seconds without an emit (while sources active) before reporting 503. 0 = disabled.
    stale_after_s: u64,
}

impl HealthState {
    pub fn new(stale_after_s: u64) -> Arc<Self> {
        Arc::new(Self {
            started: AtomicBool::new(false),
            active_sources: AtomicU64::new(0),
            last_emit_epoch: AtomicU64::new(now_epoch()),
            events_emitted: AtomicU64::new(0),
            start_epoch: now_epoch(),
            stale_after_s,
        })
    }

    pub fn mark_started(&self, active_sources: u64) {
        self.active_sources.store(active_sources, Ordering::Relaxed);
        self.started.store(true, Ordering::Relaxed);
    }

    pub fn record_emit(&self) {
        self.last_emit_epoch.store(now_epoch(), Ordering::Relaxed);
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// (healthy, json_body)
    fn snapshot(&self) -> (bool, String) {
        let now = now_epoch();
        let started = self.started.load(Ordering::Relaxed);
        let active = self.active_sources.load(Ordering::Relaxed);
        let emitted = self.events_emitted.load(Ordering::Relaxed);
        let last_emit = self.last_emit_epoch.load(Ordering::Relaxed);
        let last_emit_age = now.saturating_sub(last_emit);
        let uptime = now.saturating_sub(self.start_epoch);

        // Stale only applies when we have active sources and a window is set.
        let stale = self.stale_after_s > 0
            && active > 0
            && emitted > 0
            && last_emit_age > self.stale_after_s;

        let healthy = started && !stale;
        let status = if healthy { "ok" } else if !started { "starting" } else { "stale" };

        let body = format!(
            "{{\"status\":\"{status}\",\"uptime_s\":{uptime},\"active_sources\":{active},\"events_emitted\":{emitted},\"last_emit_age_s\":{last_emit_age}}}"
        );
        (healthy, body)
    }
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Spawn the health server. Returns immediately; serves until the task is aborted.
pub async fn serve(bind: &str, state: Arc<HealthState>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("health bind {bind} failed: {e}"))?;
    tracing::info!(%bind, "health endpoint listening on /healthz");

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "health accept failed");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Read (and discard) the request line; we only need the path.
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");

            let (code, reason, body) = if path.starts_with("/healthz") {
                let (healthy, body) = state.snapshot();
                if healthy { (200, "OK", body) } else { (503, "Service Unavailable", body) }
            } else {
                (404, "Not Found", "{\"status\":\"not_found\"}".to_string())
            };

            let resp = format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
