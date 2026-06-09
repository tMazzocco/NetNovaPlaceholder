use async_trait::async_trait;
use slack_connector_core::{NormalizedEvent, WazuhSink};
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub struct JsonFileSink {
    inner: Mutex<Inner>,
    rotate_bytes: u64,
}

struct Inner {
    path: PathBuf,
    file: File,
    written: u64,
}

impl JsonFileSink {
    pub async fn new(path: impl AsRef<Path>, rotate_mb: u64) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path).await?;
        let written = file.metadata().await?.len();
        Ok(Self {
            inner: Mutex::new(Inner { path, file, written }),
            rotate_bytes: rotate_mb.saturating_mul(1024 * 1024),
        })
    }

    async fn maybe_rotate(&self, inner: &mut Inner) -> anyhow::Result<()> {
        if self.rotate_bytes == 0 || inner.written < self.rotate_bytes {
            return Ok(());
        }
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let rotated = inner.path.with_extension(format!("ndjson.{ts}"));
        inner.file.flush().await?;
        tokio::fs::rename(&inner.path, &rotated).await?;
        inner.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
            .await?;
        inner.written = 0;
        Ok(())
    }
}

#[async_trait]
impl WazuhSink for JsonFileSink {
    async fn emit(&self, event: &NormalizedEvent) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        let mut g = self.inner.lock().await;
        self.maybe_rotate(&mut g).await?;
        g.file.write_all(&line).await?;
        g.written = g.written.saturating_add(line.len() as u64);
        Ok(())
    }

    async fn flush(&self) -> anyhow::Result<()> {
        let mut g = self.inner.lock().await;
        g.file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use slack_connector_core::{NormalizedEvent, Severity, SlackPayload, SourceTag};

    #[tokio::test]
    async fn writes_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("events.ndjson");
        let sink = JsonFileSink::new(&p, 100).await.unwrap();
        let ev = NormalizedEvent {
            timestamp: Utc::now(),
            slack: SlackPayload {
                source: SourceTag::Events,
                action: "member_joined_channel".into(),
                event_id: "Ev1".into(),
                actor: None,
                entity: None,
                context: None,
            },
            severity: Severity::Low,
            raw: json!({"hello": "world"}),
        };
        sink.emit(&ev).await.unwrap();
        sink.flush().await.unwrap();
        let s = tokio::fs::read_to_string(&p).await.unwrap();
        assert!(s.contains("member_joined_channel"));
        assert!(s.ends_with('\n'));
    }
}
