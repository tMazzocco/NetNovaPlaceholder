use crate::event::{NormalizedEvent, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    pub field: String,
    #[serde(flatten)]
    pub op: MatchOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    Eq(Value),
    In(Vec<Value>),
    RegexMatch(String),
    Exists(bool),
}

impl FilterRule {
    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        let v = event.lookup(&self.field);
        match (&self.op, v) {
            (MatchOp::Exists(true), Some(_)) => true,
            (MatchOp::Exists(false), None) => true,
            (MatchOp::Exists(_), _) => false,
            (_, None) => false,
            (MatchOp::Eq(expected), Some(actual)) => &actual == expected,
            (MatchOp::In(set), Some(actual)) => set.iter().any(|s| s == &actual),
            (MatchOp::RegexMatch(re), Some(actual)) => {
                let actual_str = match actual {
                    Value::String(s) => s,
                    other => other.to_string(),
                };
                Regex::new(re)
                    .map(|r| r.is_match(&actual_str))
                    .unwrap_or(false)
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterEngine {
    pub global_drop: Vec<FilterRule>,
    pub per_source_allow: HashMap<String, Vec<FilterRule>>,
    pub severity_map: HashMap<String, Severity>,
}

impl FilterEngine {
    /// Returns `Some(event_with_severity)` if event passes, `None` if dropped.
    pub fn evaluate(&self, mut event: NormalizedEvent) -> Option<NormalizedEvent> {
        // Apply severity map first (so downstream sees the right severity).
        if let Some(sev) = self.severity_map.get(&event.slack.action) {
            event.severity = *sev;
        }

        // Global drop: any match → drop.
        if self.global_drop.iter().any(|r| r.matches(&event)) {
            return None;
        }

        // Per-source allow: if rules exist for this source, require at least one match.
        let source_key = format!("{:?}", event.slack.source).to_lowercase();
        if let Some(allow) = self.per_source_allow.get(&source_key) {
            if !allow.is_empty() && !allow.iter().any(|r| r.matches(&event)) {
                return None;
            }
        }

        Some(event)
    }
}
