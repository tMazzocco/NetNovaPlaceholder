use crate::event::Severity;
use crate::filter::FilterRule;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub slack: SlackConfig,
    #[serde(default)]
    pub filters: FiltersConfig,
    #[serde(default)]
    pub severity_map: HashMap<String, Severity>,
    pub sink: SinkConfig,
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackConfig {
    #[serde(default)]
    pub token_bot: Option<String>,
    #[serde(default)]
    pub token_user: Option<String>,
    #[serde(default)]
    pub token_app: Option<String>,
    #[serde(default)]
    pub org_id: Option<String>,
    /// Cold-start backfill window (days). Pollers never request history older
    /// than `now - backfill_days`. Matches the Free-tier 90-day data horizon so
    /// a fresh cursor doesn't scan into permanently-empty ranges. Default 90.
    #[serde(default = "default_backfill_days")]
    pub backfill_days: u64,
    /// Optional OAuth token-rotation settings. Only relevant for Slack apps that
    /// have "Token Rotation" enabled (tokens then expire ~12h). Parsed but NOT
    /// yet acted on — the supervisor warns if set. Internal/custom apps use
    /// non-expiring tokens and should omit this.
    #[serde(default)]
    pub rotation: Option<TokenRotationConfig>,
    #[serde(default)]
    pub sources: SourcesConfig,
}

fn default_backfill_days() -> u64 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRotationConfig {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    /// Refresh cadence in seconds (Slack tokens live ~12h; refresh well before).
    #[serde(default = "default_refresh_seconds")]
    pub refresh_seconds: u64,
}

fn default_refresh_seconds() -> u64 {
    39_600 // 11h
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesConfig {
    #[serde(default)]
    pub audit: SourceToggle,
    #[serde(default)]
    pub events: EventsSourceConfig,
    #[serde(default)]
    pub access_logs: SourceToggle,
    #[serde(default)]
    pub web_inventory: SourceToggle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceToggle {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_poll")]
    pub poll_seconds: u64,
}

impl Default for SourceToggle {
    fn default() -> Self {
        Self { enabled: false, poll_seconds: default_poll() }
    }
}

fn default_poll() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSourceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_events_mode")]
    pub mode: EventsMode,
}

impl Default for EventsSourceConfig {
    fn default() -> Self {
        Self { enabled: false, mode: EventsMode::Socket }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventsMode {
    Socket,
    Http,
}

fn default_events_mode() -> EventsMode {
    EventsMode::Socket
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiltersConfig {
    #[serde(default)]
    pub drop: Vec<FilterRule>,
    #[serde(default)]
    pub audit: PerSourceFilter,
    #[serde(default)]
    pub events: PerSourceFilter,
    #[serde(default)]
    pub access_logs: PerSourceFilter,
    #[serde(default)]
    pub web_inventory: PerSourceFilter,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerSourceFilter {
    #[serde(default)]
    pub allow: Vec<FilterRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum SinkConfig {
    Stdout,
    JsonFile(JsonFileSinkConfig),
    UnixSocket(UnixSocketSinkConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonFileSinkConfig {
    pub path: PathBuf,
    #[serde(default = "default_rotate_mb")]
    pub rotate_mb: u64,
}

fn default_rotate_mb() -> u64 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixSocketSinkConfig {
    #[serde(default = "default_socket_path")]
    pub path: PathBuf,
    #[serde(default)]
    pub spool: Option<SpoolConfig>,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/ossec/queue/sockets/queue")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolConfig {
    pub dir: PathBuf,
    #[serde(default = "default_spool_mb")]
    pub max_mb: u64,
}

fn default_spool_mb() -> u64 {
    500
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    #[serde(default = "default_state_path")]
    pub sqlite_path: PathBuf,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self { sqlite_path: default_state_path() }
    }
}

fn default_state_path() -> PathBuf {
    PathBuf::from("./state.db")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub prometheus_bind: Option<String>,
    #[serde(default)]
    pub health_bind: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self { prometheus_bind: None, health_bind: None, log_level: default_log_level() }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// Load YAML config from disk with `${VAR}` environment interpolation.
    pub fn from_path(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&raw)
    }

    pub fn from_yaml_str(raw: &str) -> anyhow::Result<Self> {
        let expanded = interpolate_env(raw)?;
        let cfg: Self = serde_yaml::from_str(&expanded)?;
        Ok(cfg)
    }
}

fn interpolate_env(input: &str) -> anyhow::Result<String> {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}").unwrap();
    let mut last = 0usize;
    let mut out = String::with_capacity(input.len());
    for cap in re.captures_iter(input) {
        let m = cap.get(0).unwrap();
        out.push_str(&input[last..m.start()]);
        let var = cap.get(1).unwrap().as_str();
        let val = std::env::var(var)
            .map_err(|_| anyhow::anyhow!("env var {} referenced in config but not set", var))?;
        out.push_str(&val);
        last = m.end();
    }
    out.push_str(&input[last..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_interpolation_works() {
        std::env::set_var("WSC_TEST_TOKEN", "xoxb-secret");
        let raw = r#"
slack:
  token_bot: "${WSC_TEST_TOKEN}"
sink:
  kind: stdout
"#;
        let cfg = Config::from_yaml_str(raw).unwrap();
        assert_eq!(cfg.slack.token_bot.as_deref(), Some("xoxb-secret"));
    }

    #[test]
    fn missing_env_is_error() {
        let raw = r#"
slack:
  token_bot: "${WSC_DOES_NOT_EXIST_XYZ}"
sink:
  kind: stdout
"#;
        assert!(Config::from_yaml_str(raw).is_err());
    }
}
