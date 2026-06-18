use crate::dedup::DedupCache;
use crate::normalize::normalize_events_payload;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use slack_connector_core::{LogSource, NormalizedEvent, SourceKind};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Slack Socket Mode source, implemented over the raw WebSocket protocol with
/// `serde_json::Value` rather than a typed client. This is deliberate: Slack's
/// typed envelope models reject Enterprise Grid org-wide installs, where
/// `authorizations[].team_id` is `null` (the strongly-typed listener fails with
/// `invalid type: null, expected a string` and silently drops every event). We
/// only strongly-type the handful of fields the normalizer/filter need; the rest
/// of the payload passes through untouched.
const CONNECTIONS_OPEN_URL: &str = "https://slack.com/api/apps.connections.open";

pub struct EventsSocketSource {
    pub app_token: String,
    pub dedup_capacity: usize,
}

impl EventsSocketSource {
    /// `bot_token` is no longer needed for Socket Mode (the app-level `xapp-`
    /// token opens the connection and the push payload carries everything), but
    /// the signature is kept stable for the supervisor.
    pub fn new(app_token: String, _bot_token: String) -> Self {
        Self { app_token, dedup_capacity: 10_000 }
    }
}

/// Open a Socket Mode connection and return the one-shot `wss://` URL.
async fn open_socket_url(http: &Client, app_token: &str) -> anyhow::Result<String> {
    let resp: Value = http
        .post(CONNECTIONS_OPEN_URL)
        .bearer_auth(app_token)
        .send()
        .await?
        .json()
        .await?;
    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp.get("error").and_then(Value::as_str).unwrap_or("?");
        anyhow::bail!("apps.connections.open failed: {err}");
    }
    resp.get("url")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("apps.connections.open: missing url"))
}

/// Dedup + normalize + forward a single `events_api` payload (the event_callback
/// envelope: `event_id`, `event_time`, `event`, …).
async fn forward_payload(payload: &Value, tx: &mpsc::Sender<NormalizedEvent>, dedup: &DedupCache) {
    let event_id = payload
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("auto-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));

    if !dedup.record(&event_id) {
        tracing::debug!(event_id, "duplicate event suppressed");
        return;
    }

    match normalize_events_payload(payload.clone()) {
        Ok(n) => {
            if let Err(e) = tx.send(n).await {
                tracing::error!(error = %e, "channel closed; dropping event");
            }
        }
        Err(e) => tracing::warn!(error = %e, "normalization failed"),
    }
}

#[async_trait]
impl LogSource for EventsSocketSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Events
    }

    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<NormalizedEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let dedup = DedupCache::new(self.dedup_capacity);
        let http = Client::builder().timeout(Duration::from_secs(30)).build()?;
        let mut backoff = Duration::from_secs(1);

        tracing::info!("starting Socket Mode listener");
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }

            // 1. Get a fresh wss URL.
            let url = match open_socket_url(&http, &self.app_token).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!(error = %e, "failed to open socket mode connection; retrying");
                    if wait_or_shutdown(&mut shutdown, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };

            // 2. Connect the WebSocket.
            let ws = match connect_async(url.as_str()).await {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::error!(error = %e, "socket mode websocket connect failed; retrying");
                    if wait_or_shutdown(&mut shutdown, backoff).await {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            tracing::info!("socket mode connected");
            backoff = Duration::from_secs(1); // reset after a successful connect
            let (mut write, mut read) = ws.split();

            // 3. Pump messages until the stream drops or shutdown fires.
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::info!("shutdown received; closing socket mode");
                        let _ = write.send(Message::Close(None)).await;
                        return Ok(());
                    }
                    maybe = read.next() => {
                        let msg = match maybe {
                            Some(Ok(m)) => m,
                            Some(Err(e)) => { tracing::warn!(error = %e, "socket mode read error; reconnecting"); break; }
                            None => { tracing::info!("socket mode stream closed; reconnecting"); break; }
                        };
                        match msg {
                            Message::Text(t) => {
                                let v: Value = match serde_json::from_str(t.as_str()) {
                                    Ok(v) => v,
                                    Err(e) => { tracing::warn!(error = %e, "failed to parse socket frame"); continue; }
                                };
                                // ACK any enveloped message immediately (Slack's 3s window),
                                // BEFORE doing any work, so it isn't redelivered.
                                if let Some(env_id) = v.get("envelope_id").and_then(Value::as_str) {
                                    let ack = json!({ "envelope_id": env_id }).to_string();
                                    if let Err(e) = write.send(Message::text(ack)).await {
                                        tracing::warn!(error = %e, "failed to ACK; reconnecting");
                                        break;
                                    }
                                }
                                match v.get("type").and_then(Value::as_str) {
                                    Some("hello") => tracing::debug!("socket mode hello"),
                                    Some("disconnect") => {
                                        let reason = v.get("reason").and_then(Value::as_str).unwrap_or("?");
                                        tracing::info!(reason, "server requested disconnect; reconnecting");
                                        break;
                                    }
                                    Some("events_api") => {
                                        if let Some(payload) = v.get("payload") {
                                            forward_payload(payload, &tx, &dedup).await;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Message::Ping(p) => {
                                if let Err(e) = write.send(Message::Pong(p)).await {
                                    tracing::warn!(error = %e, "failed to send pong; reconnecting");
                                    break;
                                }
                            }
                            Message::Close(_) => { tracing::info!("socket mode close frame; reconnecting"); break; }
                            _ => {}
                        }
                    }
                }
            }

            if wait_or_shutdown(&mut shutdown, backoff).await {
                return Ok(());
            }
        }
    }
}

/// Sleep for `dur`, or return early (`true`) if shutdown is signalled.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => true,
    }
}
