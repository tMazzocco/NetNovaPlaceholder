use serde_json::Value;

pub const AUDIT_USER_LOGIN: &str = include_str!("../fixtures/audit_user_login.json");
pub const AUDIT_FILE_DOWNLOADED: &str = include_str!("../fixtures/audit_file_downloaded.json");
pub const EVENTS_MEMBER_JOINED: &str = include_str!("../fixtures/events_member_joined.json");
pub const EVENTS_FILE_SHARED: &str = include_str!("../fixtures/events_file_shared.json");
pub const EVENTS_FILE_PUBLIC: &str = include_str!("../fixtures/events_file_public.json");
pub const EVENTS_TOKENS_REVOKED: &str = include_str!("../fixtures/events_tokens_revoked.json");

pub fn parse(s: &str) -> Value {
    serde_json::from_str(s).expect("fixture is valid JSON")
}
