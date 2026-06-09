use crate::normalize::normalize_audit_payload;
use crate::state::StateStore;
use async_trait::async_trait;
use reqwest::{header, Client, StatusCode};
use serde_json::Value;
use slack_connector_core::{LogSource, NormalizedEvent, SourceKind};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Polls Slack's Audit Logs API (Enterprise Grid only) and forwards entries
/// as NormalizedEvents. Cursor + last-seen-date persisted via [`StateStore`]
/// so restarts resume from the same point.
pub struct AuditPoller {
    pub user_token: String,
    pub poll_interval: Duration,
    pub state: StateStore,
    pub http: Client,
}

const STATE_KEY_OLDEST: &str = "audit.oldest";
const STATE_KEY_CURSOR: &str = "audit.cursor";
const AUDIT_URL: &str = "https://api.slack.com/audit/v1/logs";

impl AuditPoller {
    pub fn new(user_token: String, poll_interval: Duration, state: StateStore) -> Self {
        Self {
            user_token,
            poll_interval,
            state,
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client builds"),
        }
    }

    async fn poll_once(&self, tx: &mpsc::Sender<NormalizedEvent>) -> anyhow::Result<()> {
        let oldest = self
            .state
            .get(STATE_KEY_OLDEST)?
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| chrono::Utc::now().timestamp() - 24 * 3600);
        let mut cursor = self.state.get(STATE_KEY_CURSOR)?;
        let mut newest_seen = oldest;

        loop {
            let mut req = self
                .http
                .get(AUDIT_URL)
                .bearer_auth(&self.user_token)
                .header(header::ACCEPT, "application/json")
                .query(&[("oldest", oldest.to_string()), ("limit", "200".to_string())]);
            if let Some(c) = cursor.as_deref() {
                req = req.query(&[("cursor", c)]);
            }

            let resp = req.send().await?;
            match resp.status() {
                StatusCode::OK => {}
                StatusCode::TOO_MANY_REQUESTS => {
                    let wait = resp
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(30);
                    tracing::warn!(wait_s = wait, "audit logs rate-limited; backing off");
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    continue;
                }
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    anyhow::bail!(
                        "audit logs API rejected token (status {}). Enterprise Grid + auditlogs:read required.",
                        resp.status()
                    );
                }
                s => {
                    let body = resp.text().await.unwrap_or_default();
                    anyhow::bail!("audit logs HTTP {}: {}", s, body);
                }
            }

            let json: Value = resp.json().await?;
            let entries = json
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            for entry in entries {
                if let Some(ts) = entry.get("date_create").and_then(Value::as_i64) {
                    if ts > newest_seen {
                        newest_seen = ts;
                    }
                }
                match normalize_audit_payload(entry) {
                    Ok(ev) => {
                        if tx.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "audit normalize failed"),
                }
            }

            let next = json
                .pointer("/response_metadata/next_cursor")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            match next {
                Some(c) => {
                    cursor = Some(c.to_string());
                    self.state.set(STATE_KEY_CURSOR, c)?;
                }
                None => {
                    // Page run complete. Advance oldest, clear cursor.
                    self.state.set(STATE_KEY_OLDEST, &newest_seen.to_string())?;
                    let _ = self.state.set(STATE_KEY_CURSOR, "");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LogSource for AuditPoller {
    fn kind(&self) -> SourceKind {
        SourceKind::Audit
    }

    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<NormalizedEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.poll_once(&tx).await {
                        tracing::error!(error = %e, "audit poll failed");
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("audit poller shutting down");
                    return Ok(());
                }
            }
        }
    }
}
