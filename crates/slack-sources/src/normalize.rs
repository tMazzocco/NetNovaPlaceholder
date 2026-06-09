use chrono::{TimeZone, Utc};
use serde_json::Value;
use slack_connector_core::{
    NormalizedEvent, Severity, SlackActor, SlackContext, SlackEntity, SlackPayload, SourceTag,
};

/// Normalize a raw Slack Audit Logs entry (`audit/v1/logs` schema).
pub fn normalize_audit_payload(raw: Value) -> anyhow::Result<NormalizedEvent> {
    let id = raw
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("audit payload missing id"))?
        .to_string();
    let date = raw.get("date_create").and_then(Value::as_i64).unwrap_or(0);
    let action = raw
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let actor = raw.get("actor").map(normalize_audit_actor);
    let entity = raw.get("entity").map(normalize_audit_entity);
    let context = raw.get("context").map(normalize_audit_context);

    Ok(NormalizedEvent {
        timestamp: Utc.timestamp_opt(date, 0).single().unwrap_or_else(Utc::now),
        slack: SlackPayload {
            source: SourceTag::Audit,
            action,
            event_id: id,
            actor,
            entity,
            context,
        },
        severity: Severity::Info,
        raw,
    })
}

fn normalize_audit_actor(v: &Value) -> SlackActor {
    let actor_type = v.get("type").and_then(Value::as_str).unwrap_or("unknown").to_string();
    let user = v.get("user");
    SlackActor {
        actor_type,
        id: user.and_then(|u| u.get("id")).and_then(Value::as_str).map(String::from),
        name: user.and_then(|u| u.get("name")).and_then(Value::as_str).map(String::from),
        email: user.and_then(|u| u.get("email")).and_then(Value::as_str).map(String::from),
    }
}

fn normalize_audit_entity(v: &Value) -> SlackEntity {
    let entity_type = v.get("type").and_then(Value::as_str).unwrap_or("unknown").to_string();
    let sub = v.get(entity_type.as_str());
    SlackEntity {
        entity_type: entity_type.clone(),
        id: sub.and_then(|s| s.get("id")).and_then(Value::as_str).map(String::from),
        name: sub.and_then(|s| s.get("name")).and_then(Value::as_str).map(String::from),
    }
}

fn normalize_audit_context(v: &Value) -> SlackContext {
    SlackContext {
        ip: v.get("ip_address").and_then(Value::as_str).map(String::from),
        ua: v.get("ua").and_then(Value::as_str).map(String::from),
        location: v.get("location").cloned(),
    }
}

/// Normalize a Slack Events API callback envelope (`{type: "event_callback", event: {...}}`).
pub fn normalize_events_payload(raw: Value) -> anyhow::Result<NormalizedEvent> {
    let event_id = raw
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let event_time = raw.get("event_time").and_then(Value::as_i64).unwrap_or(0);
    let event = raw.get("event").cloned().unwrap_or(Value::Null);
    let action = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let actor_user_id = event
        .get("user")
        .and_then(Value::as_str)
        .or_else(|| event.get("user_id").and_then(Value::as_str))
        .map(String::from);

    let actor = actor_user_id.as_ref().map(|id| SlackActor {
        actor_type: "user".into(),
        id: Some(id.clone()),
        name: None,
        email: None,
    });

    let entity = event
        .get("channel")
        .and_then(Value::as_str)
        .or_else(|| event.get("channel_id").and_then(Value::as_str))
        .map(|c| SlackEntity {
            entity_type: "channel".into(),
            id: Some(c.to_string()),
            name: None,
        })
        .or_else(|| {
            event.get("file_id").and_then(Value::as_str).map(|f| SlackEntity {
                entity_type: "file".into(),
                id: Some(f.to_string()),
                name: None,
            })
        });

    Ok(NormalizedEvent {
        timestamp: Utc.timestamp_opt(event_time, 0).single().unwrap_or_else(Utc::now),
        slack: SlackPayload {
            source: SourceTag::Events,
            action,
            event_id,
            actor,
            entity,
            context: None,
        },
        severity: Severity::Info,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use slack_connector_test_fixtures as fix;

    #[test]
    fn audit_user_login_normalizes() {
        let v = fix::parse(fix::AUDIT_USER_LOGIN);
        let ev = normalize_audit_payload(v).unwrap();
        assert_eq!(ev.slack.action, "user_login");
        assert_eq!(ev.slack.actor.as_ref().unwrap().id.as_deref(), Some("U1234567890"));
        assert_eq!(ev.slack.context.as_ref().unwrap().ip.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn audit_file_downloaded_normalizes() {
        let v = fix::parse(fix::AUDIT_FILE_DOWNLOADED);
        let ev = normalize_audit_payload(v).unwrap();
        assert_eq!(ev.slack.action, "file_downloaded");
        let entity = ev.slack.entity.unwrap();
        assert_eq!(entity.entity_type, "file");
        assert_eq!(entity.id.as_deref(), Some("F0987654321"));
    }

    #[test]
    fn events_member_joined_normalizes() {
        let v = fix::parse(fix::EVENTS_MEMBER_JOINED);
        let ev = normalize_events_payload(v).unwrap();
        assert_eq!(ev.slack.action, "member_joined_channel");
        assert_eq!(ev.slack.actor.unwrap().id.as_deref(), Some("U1234567890"));
        assert_eq!(ev.slack.entity.unwrap().id.as_deref(), Some("C0CCCCCCC"));
    }

    #[test]
    fn events_file_shared_normalizes() {
        let v = fix::parse(fix::EVENTS_FILE_SHARED);
        let ev = normalize_events_payload(v).unwrap();
        assert_eq!(ev.slack.action, "file_shared");
        assert_eq!(ev.slack.entity.unwrap().id.as_deref(), Some("C0CCCCCCC"));
    }
}
