use crate::dedup::DedupCache;
use crate::normalize::normalize_events_payload;
use async_trait::async_trait;
use serde_json::Value;
use slack_connector_core::{LogSource, NormalizedEvent, SourceKind};
use slack_morphism::prelude::*;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Forwarder smuggled into slack-morphism's user-state slot.
/// Cloneable so the callback (Fn-style) can grab a copy each event.
#[derive(Clone)]
struct Forwarder {
    tx: mpsc::Sender<NormalizedEvent>,
    dedup: Arc<DedupCache>,
}

pub struct EventsSocketSource {
    pub app_token: String,
    pub bot_token: String,
    pub dedup_capacity: usize,
}

impl EventsSocketSource {
    pub fn new(app_token: String, bot_token: String) -> Self {
        Self { app_token, bot_token, dedup_capacity: 10_000 }
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
        let dedup = Arc::new(DedupCache::new(self.dedup_capacity));
        let forwarder = Forwarder { tx, dedup };

        let connector = SlackClientHyperConnector::new()
            .map_err(|e| anyhow::anyhow!("slack hyper connector init failed: {e}"))?;
        let client = Arc::new(SlackClient::new(connector));

        let callbacks = SlackSocketModeListenerCallbacks::new()
            .with_push_events(on_push_events);

        let env = Arc::new(
            SlackClientEventsListenerEnvironment::new(client.clone())
                .with_user_state(forwarder.clone()),
        );

        let listener = SlackClientSocketModeListener::new(
            &SlackClientSocketModeConfig::new(),
            env.clone(),
            callbacks,
        );

        let app_token_value: SlackApiTokenValue = self.app_token.clone().into();
        let app_token = SlackApiToken::new(app_token_value);

        tracing::info!("starting Socket Mode listener");
        listener
            .listen_for(&app_token)
            .await
            .map_err(|e| anyhow::anyhow!("listen_for failed: {e}"))?;

        // serve() runs forever; race against shutdown signal.
        tokio::select! {
            _ = listener.serve() => {
                tracing::warn!("socket mode listener returned unexpectedly");
            }
            _ = shutdown.changed() => {
                tracing::info!("shutdown received; stopping socket mode");
            }
        }
        Ok(())
    }
}

async fn on_push_events(
    event: SlackPushEventCallback,
    _client: Arc<SlackHyperClient>,
    states: SlackClientEventsUserState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Retrieve forwarder from user state.
    let states_g = states.read().await;
    let forwarder = match states_g.get_user_state::<Forwarder>() {
        Some(f) => f.clone(),
        None => {
            tracing::error!("forwarder missing from user state");
            return Ok(());
        }
    };
    drop(states_g);

    // Re-serialize push event to JSON for the normalizer.
    let envelope: Value = match serde_json::to_value(&event) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize push event");
            return Ok(());
        }
    };

    // Extract event_id for dedup; fall back to a hash-ish marker if absent.
    let event_id = envelope
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("auto-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));

    if !forwarder.dedup.record(&event_id) {
        tracing::debug!(event_id, "duplicate event suppressed");
        return Ok(());
    }

    let normalized = match normalize_events_payload(envelope) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "normalization failed");
            return Ok(());
        }
    };

    if let Err(e) = forwarder.tx.send(normalized).await {
        tracing::error!(error = %e, "channel closed; dropping event");
    }
    Ok(())
}
