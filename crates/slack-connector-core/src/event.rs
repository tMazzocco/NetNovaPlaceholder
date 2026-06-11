use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Internal normalized event format. Wraps the raw Slack payload while
/// surfacing namespaced fields under `slack.*` for Wazuh decoders/rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    pub slack: SlackPayload,
    pub severity: Severity,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackPayload {
    pub source: SourceTag,
    pub action: String,
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<SlackActor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<SlackEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<SlackContext>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SourceTag {
    Audit,
    Events,
    AccessLogs,
    WebInventory,
}

impl SourceTag {
    pub fn location_tag(&self) -> &'static str {
        match self {
            Self::Audit => "slack-audit",
            Self::Events => "slack-events",
            Self::AccessLogs => "slack-access",
            Self::WebInventory => "slack-inventory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackActor {
    #[serde(rename = "type")]
    pub actor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackEntity {
    #[serde(rename = "type")]
    pub entity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Value>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl NormalizedEvent {
    /// Extract a dotted-path field for filter matching.
    /// Supports `slack.action`, `slack.actor.email`, `severity`, `raw.<...>`, etc.
    ///
    /// Serializes the whole event per call — when matching several rules
    /// against one event, serialize once with [`serde_json::to_value`] and use
    /// [`lookup_dotted`] instead.
    pub fn lookup(&self, path: &str) -> Option<Value> {
        let v = serde_json::to_value(self).ok()?;
        lookup_dotted(&v, path).cloned()
    }
}

pub fn lookup_dotted<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}
