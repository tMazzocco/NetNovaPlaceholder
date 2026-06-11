#![cfg(unix)]

use async_trait::async_trait;
use slack_connector_core::{NormalizedEvent, WazuhSink};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixDatagram;
use tokio::sync::Mutex;

const REPLAY_INTERVAL: Duration = Duration::from_secs(30);

/// Writes to the Wazuh analysisd queue socket using the OSSEC wire format:
/// `<QUEUE>:<LOCATION>:<MESSAGE>` where QUEUE=`1` (locally-collected) and
/// MESSAGE is the JSON-encoded NormalizedEvent.
///
/// Durability model: if analysisd restarts, the connected datagram socket goes
/// stale — `emit` reconnects on send failure. Events that still can't be
/// delivered are appended to the spool; a background task drains the spool back
/// into the socket every [`REPLAY_INTERVAL`] once analysisd is reachable again.
pub struct UnixSocketSink {
    shared: Arc<Shared>,
    replay_handle: Option<tokio::task::JoinHandle<()>>,
}

struct Shared {
    path: PathBuf,
    sock: Mutex<UnixDatagram>,
    spool: Option<SpoolDir>,
}

struct SpoolDir {
    dir: PathBuf,
    max_bytes: u64,
    /// Serializes appends vs. replay so a segment is never appended to while
    /// the replay task is draining/deleting it.
    lock: Mutex<()>,
}

impl UnixSocketSink {
    pub async fn new(path: PathBuf, spool_dir: Option<PathBuf>, spool_max_mb: u64) -> anyhow::Result<Self> {
        let sock = connect(&path)?;
        let spool = spool_dir.map(|dir| SpoolDir {
            dir,
            max_bytes: spool_max_mb.saturating_mul(1024 * 1024),
            lock: Mutex::new(()),
        });
        if let Some(s) = &spool {
            tokio::fs::create_dir_all(&s.dir).await.ok();
        }
        let shared = Arc::new(Shared { path, sock: Mutex::new(sock), spool });
        let replay_handle = shared.spool.is_some().then(|| {
            let shared = shared.clone();
            tokio::spawn(replay_loop(shared))
        });
        Ok(Self { shared, replay_handle })
    }

    fn wire_format(event: &NormalizedEvent) -> anyhow::Result<Vec<u8>> {
        let location = event.slack.source.location_tag();
        let json = serde_json::to_string(event)?;
        Ok(format!("1:{location}:{json}").into_bytes())
    }
}

impl Drop for UnixSocketSink {
    fn drop(&mut self) {
        if let Some(h) = &self.replay_handle {
            h.abort();
        }
    }
}

fn connect(path: &PathBuf) -> std::io::Result<UnixDatagram> {
    let sock = UnixDatagram::unbound()?;
    sock.connect(path)?;
    Ok(sock)
}

impl Shared {
    async fn try_send(&self, payload: &[u8]) -> std::io::Result<()> {
        let sock = self.sock.lock().await;
        sock.send(payload).await.map(|_| ())
    }

    /// Replace the (possibly stale) socket — analysisd recreates its queue
    /// socket on restart, which orphans the previous connection.
    async fn reconnect(&self) -> std::io::Result<()> {
        let fresh = connect(&self.path)?;
        *self.sock.lock().await = fresh;
        Ok(())
    }

    /// Send with reconnect-once semantics. WouldBlock/EAGAIN (queue full) is
    /// returned to the caller for backoff; other errors trigger one reconnect
    /// attempt before giving up.
    async fn send_reconnecting(&self, payload: &[u8]) -> std::io::Result<()> {
        match self.try_send(payload).await {
            Ok(()) => Ok(()),
            Err(e) if is_queue_full(&e) => Err(e),
            Err(e) => {
                tracing::warn!(error = %e, path = ?self.path, "analysisd socket send failed; reconnecting");
                self.reconnect().await?;
                self.try_send(payload).await
            }
        }
    }

    async fn spool_event(&self, payload: &[u8]) -> anyhow::Result<()> {
        let Some(spool) = &self.spool else {
            anyhow::bail!("sink unavailable and no spool configured");
        };
        let _g = spool.lock.lock().await;
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

fn is_queue_full(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EAGAIN)
}

async fn replay_loop(shared: Arc<Shared>) {
    let mut ticker = tokio::time::interval(REPLAY_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = replay_once(&shared).await {
            tracing::debug!(error = %e, "spool replay incomplete; retrying next interval");
        }
    }
}

/// Drain spooled segments oldest-first. On a mid-file send failure the unsent
/// remainder is written back so nothing is lost or duplicated across retries.
async fn replay_once(shared: &Shared) -> anyhow::Result<()> {
    let spool = shared.spool.as_ref().expect("replay only runs with a spool");
    let mut segments = Vec::new();
    let mut rd = match tokio::fs::read_dir(&spool.dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // spool dir not created yet — nothing to do
    };
    while let Some(entry) = rd.next_entry().await? {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "ndjson") {
            segments.push(p);
        }
    }
    if segments.is_empty() {
        return Ok(());
    }
    segments.sort();

    for seg in segments {
        let _g = spool.lock.lock().await;
        let content = tokio::fs::read_to_string(&seg).await?;
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        for (i, line) in lines.iter().enumerate() {
            if let Err(e) = shared.send_reconnecting(line.as_bytes()).await {
                // Write the unsent tail back and stop until the next tick.
                let remainder = lines[i..].join("\n") + "\n";
                tokio::fs::write(&seg, remainder).await?;
                anyhow::bail!("replay interrupted on {:?}: {e}", seg);
            }
        }
        tokio::fs::remove_file(&seg).await?;
        tracing::info!(?seg, replayed = lines.len(), "spool segment replayed into analysisd");
    }
    Ok(())
}

#[async_trait]
impl WazuhSink for UnixSocketSink {
    async fn emit(&self, event: &NormalizedEvent) -> anyhow::Result<()> {
        let payload = Self::wire_format(event)?;
        const MAX_ATTEMPTS: u32 = 5;
        let mut delay_ms: u64 = 25;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.shared.send_reconnecting(&payload).await {
                Ok(()) => return Ok(()),
                Err(e) if is_queue_full(&e) => {
                    tracing::debug!(attempt, "analysisd queue full, backing off");
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = delay_ms.saturating_mul(2).min(1000);
                }
                Err(e) => {
                    tracing::error!(?e, path = ?self.shared.path, "unix socket send failed; spooling");
                    self.shared.spool_event(&payload).await?;
                    return Ok(());
                }
            }
        }
        tracing::warn!("max retries reached on analysisd socket; spooling");
        self.shared.spool_event(&payload).await?;
        Ok(())
    }
}
