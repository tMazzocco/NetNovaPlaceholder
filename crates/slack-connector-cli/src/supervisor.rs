use crate::health::{self, HealthState};
use crate::observability;
use slack_connector_core::{
    config::SinkConfig, filter::FilterRule, Config, FilterEngine, LogSource, NormalizedEvent,
    WazuhSink,
};
use slack_sources::{StateStore, Tier, TierProbe};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use wazuh_sinks::{JsonFileSink, StdoutSink};

pub async fn run_supervisor(cfg: Config) -> anyhow::Result<()> {
    observability::init_metrics(cfg.observability.prometheus_bind.as_deref())?;

    if cfg.slack.rotation.is_some() {
        tracing::warn!(
            "slack.rotation is configured but token rotation is not yet implemented; \
             using the static tokens as-is. Remove the block unless your app has \
             Token Rotation enabled (internal/custom apps use non-expiring tokens)."
        );
    }

    let sink: Arc<dyn WazuhSink> = build_sink(&cfg.sink).await?;
    let filter = Arc::new(build_filter(&cfg));
    let state = StateStore::open(&cfg.state.sqlite_path)?;

    // Optional tier probe — runs only when a bot token is available.
    let probe = if let Some(bot) = cfg.slack.token_bot.as_deref() {
        match TierProbe::run(bot, cfg.slack.token_user.as_deref()).await {
            Ok(p) => {
                p.log_summary();
                Some(p)
            }
            Err(e) => {
                tracing::warn!(error = %e, "tier probe failed; assuming all configured sources are usable");
                None
            }
        }
    } else {
        tracing::info!("no token_bot configured; skipping tier probe");
        None
    };

    // Health endpoint: stale window = 3× the longest poll interval (or 0 = disabled).
    let health = HealthState::new(health_stale_window(&cfg));
    let mut health_handle = None;
    if let Some(bind) = cfg.observability.health_bind.clone() {
        let state = health.clone();
        health_handle = Some(tokio::spawn(async move {
            if let Err(e) = health::serve(&bind, state).await {
                tracing::error!(error = %e, "health server exited");
            }
        }));
    }

    let (tx, mut rx) = mpsc::channel::<NormalizedEvent>(10_000);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let sources = build_sources(&cfg, &state, probe.as_ref());
    if sources.is_empty() {
        tracing::warn!("no sources active — connector will idle (waiting for SIGINT)");
    }
    health.mark_started(sources.len() as u64);
    let mut source_handles = Vec::new();
    for src in sources {
        let tx = tx.clone();
        let shutdown_rx = shutdown_rx.clone();
        let kind = src.kind();
        let h = tokio::spawn(async move {
            tracing::info!(?kind, "source starting");
            if let Err(e) = src.run(tx, shutdown_rx).await {
                tracing::error!(?kind, error = %e, "source exited with error");
            }
        });
        source_handles.push(h);
    }
    drop(tx);

    let sink_for_loop = sink.clone();
    let filter_for_loop = filter.clone();
    let health_for_loop = health.clone();
    let dispatcher = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let src_label = format!("{:?}", ev.slack.source).to_lowercase();
            metrics::counter!("wsc_events_received_total", "source" => src_label.clone()).increment(1);
            match filter_for_loop.evaluate(ev) {
                Some(ev) => {
                    if let Err(e) = sink_for_loop.emit(&ev).await {
                        tracing::error!(error = %e, "sink emit failed");
                        metrics::counter!("wsc_sink_errors_total").increment(1);
                    } else {
                        health_for_loop.record_emit();
                        metrics::counter!("wsc_events_emitted_total", "source" => src_label).increment(1);
                    }
                }
                None => {
                    metrics::counter!("wsc_events_filtered_total", "source" => src_label).increment(1);
                }
            }
        }
        let _ = sink_for_loop.flush().await;
    });

    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);
    for h in source_handles {
        let _ = h.await;
    }
    let _ = dispatcher.await;
    if let Some(h) = health_handle {
        h.abort();
    }
    Ok(())
}

/// Stale window for the health endpoint: 3× the longest enabled poll interval,
/// clamped to a 300s floor. Returns 0 (disabled) when only push sources (events)
/// are active, since those have no poll cadence to baseline against.
fn health_stale_window(cfg: &Config) -> u64 {
    let s = &cfg.slack.sources;
    let mut longest = 0u64;
    if s.audit.enabled {
        longest = longest.max(s.audit.poll_seconds);
    }
    if s.access_logs.enabled {
        longest = longest.max(s.access_logs.poll_seconds);
    }
    if s.web_inventory.enabled {
        longest = longest.max(s.web_inventory.poll_seconds);
    }
    if longest == 0 {
        0
    } else {
        (longest * 3).max(300)
    }
}

async fn build_sink(cfg: &SinkConfig) -> anyhow::Result<Arc<dyn WazuhSink>> {
    Ok(match cfg {
        SinkConfig::Stdout => Arc::new(StdoutSink::new()),
        SinkConfig::JsonFile(c) => Arc::new(JsonFileSink::new(&c.path, c.rotate_mb).await?),
        SinkConfig::UnixSocket(c) => {
            #[cfg(unix)]
            {
                let (dir, max_mb) = match &c.spool {
                    Some(s) => (Some(s.dir.clone()), s.max_mb),
                    None => (None, 0),
                };
                Arc::new(wazuh_sinks::UnixSocketSink::new(c.path.clone(), dir, max_mb).await?)
            }
            #[cfg(not(unix))]
            {
                let _ = c;
                anyhow::bail!("unix_socket sink not supported on this platform");
            }
        }
    })
}

fn build_filter(cfg: &Config) -> FilterEngine {
    let mut engine = FilterEngine::default();
    engine.global_drop = cfg.filters.drop.clone();
    insert_allow(&mut engine, "audit", &cfg.filters.audit.allow);
    insert_allow(&mut engine, "events", &cfg.filters.events.allow);
    insert_allow(&mut engine, "accesslogs", &cfg.filters.access_logs.allow);
    insert_allow(&mut engine, "webinventory", &cfg.filters.web_inventory.allow);
    engine.severity_map = cfg.severity_map.clone();
    engine
}

fn insert_allow(engine: &mut FilterEngine, key: &str, rules: &[FilterRule]) {
    if !rules.is_empty() {
        engine.per_source_allow.insert(key.to_string(), rules.to_vec());
    }
}

fn build_sources(cfg: &Config, state: &StateStore, probe: Option<&TierProbe>) -> Vec<Box<dyn LogSource>> {
    let mut out: Vec<Box<dyn LogSource>> = Vec::new();

    if cfg.slack.sources.events.enabled {
        if let (Some(app), Some(bot)) = (cfg.slack.token_app.clone(), cfg.slack.token_bot.clone()) {
            out.push(Box::new(slack_sources::EventsSocketSource::new(app, bot)));
        } else {
            tracing::warn!("events enabled but token_app or token_bot missing — skipping");
        }
    }

    if cfg.slack.sources.audit.enabled {
        let allowed = probe.map(|p| p.audit_logs_available).unwrap_or(true);
        match (cfg.slack.token_user.clone(), allowed) {
            (Some(tok), true) => {
                let interval = Duration::from_secs(cfg.slack.sources.audit.poll_seconds.max(15));
                out.push(Box::new(slack_sources::AuditPoller::new(tok, interval, state.clone())));
            }
            (None, _) => tracing::warn!("audit enabled but token_user (xoxp-) missing — skipping"),
            (_, false) => tracing::warn!("audit enabled but probe reports it unavailable on this tier — skipping"),
        }
    }

    if cfg.slack.sources.access_logs.enabled {
        let allowed = probe.map(|p| p.access_logs_available).unwrap_or(true);
        match (cfg.slack.token_bot.clone(), allowed) {
            (Some(tok), true) => {
                let interval = Duration::from_secs(cfg.slack.sources.access_logs.poll_seconds.max(60));
                out.push(Box::new(slack_sources::AccessLogsPoller::with_backfill(
                    tok, interval, state.clone(), cfg.slack.backfill_days,
                )));
            }
            (None, _) => tracing::warn!("access_logs enabled but token_bot missing — skipping"),
            (_, false) => match probe.map(|p| p.tier) {
                Some(Tier::Free) => tracing::warn!("access_logs unavailable on Free tier — skipping"),
                _ => tracing::warn!("access_logs unavailable on this workspace — skipping"),
            },
        }
    }

    if cfg.slack.sources.web_inventory.enabled {
        if let Some(tok) = cfg.slack.token_bot.clone() {
            let interval = Duration::from_secs(cfg.slack.sources.web_inventory.poll_seconds.max(300));
            out.push(Box::new(slack_sources::WebInventoryPoller::new(tok, interval, state.clone())));
        } else {
            tracing::warn!("web_inventory enabled but token_bot missing — skipping");
        }
    }

    out
}
