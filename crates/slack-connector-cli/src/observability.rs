use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

pub fn init_metrics(bind: Option<&str>) -> anyhow::Result<()> {
    let Some(addr) = bind else {
        tracing::info!("prometheus disabled (no observability.prometheus_bind in config)");
        return Ok(());
    };
    let sock: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prometheus_bind {addr}: {e}"))?;
    PrometheusBuilder::new()
        .with_http_listener(sock)
        .install()
        .map_err(|e| anyhow::anyhow!("prometheus install failed: {e}"))?;
    tracing::info!(%addr, "Prometheus exporter listening");

    // Pre-declare so they show up in /metrics immediately with 0 values.
    metrics::describe_counter!("wsc_events_received_total", "Events received from Slack sources");
    metrics::describe_counter!("wsc_events_filtered_total", "Events dropped by filter engine");
    metrics::describe_counter!("wsc_events_emitted_total", "Events successfully written to sink");
    metrics::describe_counter!("wsc_sink_errors_total", "Sink emit failures");
    Ok(())
}
