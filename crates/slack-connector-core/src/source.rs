use crate::event::NormalizedEvent;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Audit,
    Events,
    AccessLogs,
    WebInventory,
}

#[async_trait]
pub trait LogSource: Send + Sync {
    fn kind(&self) -> SourceKind;

    /// Spawn the source's run-loop. Implementations push normalized events into `tx`.
    /// Returning Ok(()) means clean shutdown; Err means fatal source failure.
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<NormalizedEvent>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>;
}
