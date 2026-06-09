pub mod health;
pub mod observability;
pub mod supervisor;

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "wazuh-slack", version, about = "Slack → Wazuh log connector")]
pub struct Cli {
    /// Path to the YAML config file.
    #[arg(short, long, env = "WAZUH_SLACK_CONFIG", default_value = "config/wazuh-slack.yaml")]
    pub config: PathBuf,

    /// Override log level (RUST_LOG also honoured).
    #[arg(long, env = "WAZUH_SLACK_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Validate config and exit without starting the connector.
    #[arg(long)]
    pub check: bool,
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let cfg = slack_connector_core::Config::from_path(&cli.config)?;
    tracing::info!(path = %cli.config.display(), "config loaded");
    if cli.check {
        println!("config OK");
        return Ok(());
    }
    supervisor::run_supervisor(cfg).await
}
