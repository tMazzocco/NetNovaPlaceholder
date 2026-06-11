use crate::state::StateStore;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use reqwest::Client;
use serde_json::Value;
use slack_connector_core::{
    LogSource, NormalizedEvent, Severity, SlackActor, SlackContext, SlackPayload, SourceKind, SourceTag,
};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Polls `team.accessLogs` for per-user login history. Paid tier (Pro+) only —
/// Free workspaces return `paid_only`.
///
/// Requires a **user token** (`xoxp-`) carrying the `admin` scope: `team.accessLogs`
/// rejects bot tokens with `not_allowed_token_type` (see INSIDER-THREAT-GAPS.md
/// Gap 6). Cursor = last-seen `date_first` epoch.
pub struct AccessLogsPoller {
    pub user_token: String,
    pub poll_interval: Duration,
    pub state: StateStore,
    pub backfill_days: u64,
    pub http: Client,
}

const STATE_KEY: &str = "access_logs.date_first";
const URL: &str = "https://slack.com/api/team.accessLogs";

impl AccessLogsPoller {
    pub fn new(user_token: String, poll_interval: Duration, state: StateStore) -> Self {
        Self::with_backfill(user_token, poll_interval, state, 90)
    }

    pub fn with_backfill(
        user_token: String,
        poll_interval: Duration,
        state: StateStore,
        backfill_days: u64,
    ) -> Self {
        Self {
            user_token,
            poll_interval,
            state,
            backfill_days,
            http: Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        }
    }

    async fn poll_once(&self, tx: &mpsc::Sender<NormalizedEvent>) -> anyhow::Result<()> {
        let stored: i64 = self
            .state
            .get(STATE_KEY)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        // Clamp a fresh/old cursor up to the backfill floor so cold starts don't
        // scan all-time history (esp. into the Free-tier 90-day empty zone).
        let floor = crate::util::backfill_floor(self.backfill_days);
        let last_seen = stored.max(floor);

        let mut max_seen = last_seen;
        let mut page = 1u32;
        loop {
            let resp: Value = self
                .http
                .get(URL)
                .bearer_auth(&self.user_token)
                .query(&[("count", "100"), ("page", &page.to_string())])
                .send()
                .await?
                .json()
                .await?;

            if resp.get("ok").and_then(Value::as_bool) != Some(true) {
                let err = resp.get("error").and_then(Value::as_str).unwrap_or("?");
                anyhow::bail!("team.accessLogs error: {err}");
            }

            let logins = resp.get("logins").and_then(Value::as_array).cloned().unwrap_or_default();
            if logins.is_empty() {
                break;
            }

            let mut all_old = true;
            for entry in &logins {
                let date_first = entry.get("date_first").and_then(Value::as_i64).unwrap_or(0);
                if date_first <= last_seen {
                    continue;
                }
                all_old = false;
                if date_first > max_seen {
                    max_seen = date_first;
                }
                let ev = build_event(entry);
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }

            let paging = resp.get("paging");
            let cur_page = paging.and_then(|p| p.get("page")).and_then(Value::as_u64).unwrap_or(1);
            let total = paging.and_then(|p| p.get("pages")).and_then(Value::as_u64).unwrap_or(1);
            if all_old || cur_page >= total {
                break;
            }
            page += 1;
        }

        if max_seen > last_seen {
            self.state.set(STATE_KEY, &max_seen.to_string())?;
        }
        Ok(())
    }
}

fn build_event(entry: &Value) -> NormalizedEvent {
    let date_first = entry.get("date_first").and_then(Value::as_i64).unwrap_or(0);
    let user_id = entry.get("user_id").and_then(Value::as_str).map(String::from);
    let username = entry.get("username").and_then(Value::as_str).map(String::from);
    // team.accessLogs only records SUCCESSFUL logins (aggregated per
    // user/IP/UA with count >= 1) — failed-login detection needs the audit
    // source (`user_login_failed`, rules 100060/100061).
    let action = "user_login";

    let event_id = format!("access-{}-{}", user_id.as_deref().unwrap_or("?"), date_first);

    NormalizedEvent {
        timestamp: Utc.timestamp_opt(date_first, 0).single().unwrap_or_else(Utc::now),
        slack: SlackPayload {
            source: SourceTag::AccessLogs,
            action: action.into(),
            event_id,
            actor: Some(SlackActor {
                actor_type: "user".into(),
                id: user_id,
                name: username,
                email: None,
            }),
            entity: None,
            context: Some(SlackContext {
                ip: entry.get("ip").and_then(Value::as_str).map(String::from),
                ua: entry.get("user_agent").and_then(Value::as_str).map(String::from),
                location: entry.get("country").cloned(),
            }),
        },
        severity: Severity::Low,
        raw: entry.clone(),
    }
}

#[async_trait]
impl LogSource for AccessLogsPoller {
    fn kind(&self) -> SourceKind {
        SourceKind::AccessLogs
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
                        tracing::error!(error = %e, "access logs poll failed");
                    }
                }
                _ = shutdown.changed() => return Ok(()),
            }
        }
    }
}
