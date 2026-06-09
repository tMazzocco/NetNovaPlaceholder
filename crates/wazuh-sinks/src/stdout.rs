use async_trait::async_trait;
use slack_connector_core::{NormalizedEvent, WazuhSink};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

pub struct StdoutSink {
    stdout: Mutex<tokio::io::Stdout>,
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self { stdout: Mutex::new(tokio::io::stdout()) }
    }
}

impl StdoutSink {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WazuhSink for StdoutSink {
    async fn emit(&self, event: &NormalizedEvent) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        let mut g = self.stdout.lock().await;
        g.write_all(&line).await?;
        g.flush().await?;
        Ok(())
    }
}
