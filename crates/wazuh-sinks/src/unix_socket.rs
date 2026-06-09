#![cfg(unix)]

use async_trait::async_trait;
use slack_connector_core::{NormalizedEvent, WazuhSink};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixDatagram;
use tokio::sync::Mutex;

/// Writes to the Wazuh analysisd queue socket using the OSSEC wire format:
/// `<QUEUE>:<LOCATION>:<MESSAGE>` where QUEUE=`1` (locally-collected) and
/// MESSAGE is the JSON-encoded NormalizedEvent.
pub struct UnixSocketSink {
    path: PathBuf,
    sock: Mutex<UnixDatagram>,
    spool: Option<SpoolWriter>,
}

struct SpoolWriter {
    dir: PathBuf,
    max_bytes: u64,
}

impl UnixSocketSink {
    pub async fn new(path: PathBuf, spool_dir: Option<PathBuf>, spool_max_mb: u64) -> anyhow::Result<Self> {
        let sock = UnixDatagram::unbound()?;
        sock.connect(&path)?;
        let spool = spool_dir.map(|dir| SpoolWriter { dir, max_bytes: spool_max_mb.saturating_mul(1024 * 1024) });
        if let Some(s) = &spool {
            tokio::fs::create_dir_all(&s.dir).await.ok();
        }
        Ok(Self { path, sock: Mutex::new(sock), spool })
    }

    fn wire_format(event: &NormalizedEvent) -> anyhow::Result<Vec<u8>> {
        let location = event.slack.source.location_tag();
        let json = serde_json::to_string(event)?;
        Ok(format!("1:{location}:{json}").into_bytes())
    }

    async fn spool_event(&self, payload: &[u8]) -> anyhow::Result<()> {
        let Some(spool) = &self.spool else {
            anyhow::bail!("sink overloaded and no spool configured");
        };
        let path = spool.dir.join(format!(
            "{}.ndjson",
            chrono::Utc::now().format("%Y%m%dT%H")
        ));
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        use tokio::io::AsyncWriteExt;
        f.write_all(payload).await?;
        f.write_all(b"\n").await?;
        // Best-effort: warn if spool grew past cap.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            if meta.len() > spool.max_bytes {
                tracing::warn!(?path, len = meta.len(), "spool segment exceeds max_bytes");
            }
        }
        Ok(())
    }
}

#[async_trait]
impl WazuhSink for UnixSocketSink {
    async fn emit(&self, event: &NormalizedEvent) -> anyhow::Result<()> {
        let payload = Self::wire_format(event)?;
        const MAX_ATTEMPTS: u32 = 5;
        let mut delay_ms: u64 = 25;
        for attempt in 1..=MAX_ATTEMPTS {
            let sock = self.sock.lock().await;
            match sock.send(&payload).await {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EAGAIN) => {
                    drop(sock);
                    tracing::debug!(attempt, "analysisd queue full, backing off");
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2).min(1000);
                }
                Err(e) => {
                    drop(sock);
                    tracing::error!(?e, path = ?self.path, "unix socket send failed");
                    self.spool_event(&payload).await?;
                    return Ok(());
                }
            }
        }
        tracing::warn!("max retries reached on analysisd socket; spooling");
        self.spool_event(&payload).await?;
        Ok(())
    }
}
