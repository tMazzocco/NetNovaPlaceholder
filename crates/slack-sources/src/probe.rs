use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// Detected workspace tier after startup probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Free,
    Paid,        // Pro / Business+
    Enterprise,  // Enterprise Grid
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TierProbe {
    pub tier: Tier,
    pub team_id: Option<String>,
    pub enterprise_id: Option<String>,
    pub user_id: Option<String>,
    pub access_logs_available: bool,
    pub audit_logs_available: bool,
}

impl TierProbe {
    /// Run the probe sequence using the provided bot token (xoxb-) and an
    /// optional user token (xoxp-) for audit-logs detection.
    pub async fn run(bot_token: &str, user_token: Option<&str>) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let mut tier = Tier::Unknown;

        // 1. auth.test
        let auth: Value = http
            .post("https://slack.com/api/auth.test")
            .bearer_auth(bot_token)
            .send()
            .await?
            .json()
            .await?;
        if auth.get("ok").and_then(Value::as_bool) != Some(true) {
            anyhow::bail!("auth.test failed: {}", auth);
        }
        let team_id = auth.get("team_id").and_then(Value::as_str).map(String::from);
        let user_id = auth.get("user_id").and_then(Value::as_str).map(String::from);
        let enterprise_id = auth.get("enterprise_id").and_then(Value::as_str).map(String::from);
        if enterprise_id.is_some() {
            tier = Tier::Enterprise;
        }

        // 2. team.accessLogs probe — distinguishes Free vs Paid (unless already Enterprise).
        let access: Value = http
            .get("https://slack.com/api/team.accessLogs")
            .bearer_auth(bot_token)
            .query(&[("count", "1")])
            .send()
            .await?
            .json()
            .await?;
        let access_logs_available = access.get("ok").and_then(Value::as_bool) == Some(true);
        if !access_logs_available {
            if let Some(err) = access.get("error").and_then(Value::as_str) {
                tracing::info!(error = err, "team.accessLogs unavailable on this tier");
                if err == "paid_only" && tier == Tier::Unknown {
                    tier = Tier::Free;
                }
            }
        } else if tier == Tier::Unknown {
            tier = Tier::Paid;
        }

        // 3. Audit logs probe (Enterprise only, requires xoxp- user token).
        let mut audit_logs_available = false;
        if let Some(utok) = user_token {
            let r = http
                .get("https://api.slack.com/audit/v1/schemas")
                .bearer_auth(utok)
                .send()
                .await;
            audit_logs_available = matches!(&r, Ok(resp) if resp.status().is_success());
            if !audit_logs_available {
                tracing::info!("audit logs API unreachable with provided user token (Enterprise Grid + auditlogs:read required)");
            }
        }

        Ok(Self {
            tier,
            team_id,
            enterprise_id,
            user_id,
            access_logs_available,
            audit_logs_available,
        })
    }

    pub fn log_summary(&self) {
        tracing::info!(
            tier = ?self.tier,
            team_id = self.team_id.as_deref().unwrap_or("?"),
            enterprise_id = self.enterprise_id.as_deref().unwrap_or("-"),
            access_logs = self.access_logs_available,
            audit_logs = self.audit_logs_available,
            "Slack tier probe complete"
        );
    }
}
