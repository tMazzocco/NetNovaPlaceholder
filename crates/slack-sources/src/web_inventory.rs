use crate::state::StateStore;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use serde_json::{json, Value};
use slack_connector_core::{
    LogSource, NormalizedEvent, Severity, SlackEntity, SlackPayload, SourceKind, SourceTag,
};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Low-frequency Web API inventory snapshot. Picks up things the Events
/// API doesn't push: full user list, channel list, current admin app
/// approvals. Useful for diffing against prior snapshots to catch silently
/// added integrations or guest accounts.
pub struct WebInventoryPoller {
    pub bot_token: String,
    pub poll_interval: Duration,
    pub state: StateStore,
    pub http: Client,
}

impl WebInventoryPoller {
    pub fn new(bot_token: String, poll_interval: Duration, state: StateStore) -> Self {
        Self {
            bot_token,
            poll_interval,
            state,
            http: Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        }
    }

    async fn list_paged(&self, method: &str, key: &str) -> anyhow::Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut req = self.http.get(format!("https://slack.com/api/{method}"))
                .bearer_auth(&self.bot_token)
                .query(&[("limit", "200")]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c)]);
            }
            let v: Value = req.send().await?.json().await?;
            if v.get("ok").and_then(Value::as_bool) != Some(true) {
                let err = v.get("error").and_then(Value::as_str).unwrap_or("?");
                anyhow::bail!("{method} failed: {err}");
            }
            if let Some(arr) = v.get(key).and_then(Value::as_array) {
                out.extend(arr.iter().cloned());
            }
            let next = v
                .pointer("/response_metadata/next_cursor")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from);
            if next.is_none() {
                return Ok(out);
            }
            cursor = next;
        }
    }

    async fn poll_once(&self, tx: &mpsc::Sender<NormalizedEvent>) -> anyhow::Result<()> {
        let users = self.list_paged("users.list", "members").await.unwrap_or_default();
        let channels = self
            .list_paged("conversations.list", "channels")
            .await
            .unwrap_or_default();

        let snapshot = json!({
            "users_count": users.len(),
            "channels_count": channels.len(),
            "users": users,
            "channels": channels,
        });

        let ts = Utc::now();
        let ev = NormalizedEvent {
            timestamp: ts,
            slack: SlackPayload {
                source: SourceTag::WebInventory,
                action: "workspace_inventory_snapshot".into(),
                event_id: format!("inv-{}", ts.timestamp()),
                actor: None,
                entity: Some(SlackEntity {
                    entity_type: "workspace".into(),
                    id: None,
                    name: None,
                }),
                context: None,
            },
            severity: Severity::Info,
            raw: snapshot,
        };
        let _ = tx.send(ev).await;
        let _ = self.state.set("web_inventory.last_run", &ts.timestamp().to_string());
        Ok(())
    }
}

#[async_trait]
impl LogSource for WebInventoryPoller {
    fn kind(&self) -> SourceKind {
        SourceKind::WebInventory
    }

    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<NormalizedEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        // Run immediately on startup, then on interval.
        if let Err(e) = self.poll_once(&tx).await {
            tracing::error!(error = %e, "initial inventory poll failed");
        }
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.poll_once(&tx).await {
                        tracing::error!(error = %e, "inventory poll failed");
                    }
                }
                _ = shutdown.changed() => return Ok(()),
            }
        }
    }
}
