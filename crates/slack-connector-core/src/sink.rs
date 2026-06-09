use crate::event::NormalizedEvent;
use async_trait::async_trait;

#[async_trait]
pub trait WazuhSink: Send + Sync {
    async fn emit(&self, event: &NormalizedEvent) -> anyhow::Result<()>;
    async fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
