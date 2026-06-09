/// Epoch-seconds floor for cold-start backfill: `now - days`.
///
/// Pollers clamp a fresh or stale cursor up to this value so a first run does
/// not scan all-time history. On Free Slack workspaces, data older than ~90
/// days is hidden/deleted, so requesting older ranges only wastes calls on
/// permanently-empty pages.
pub fn backfill_floor(days: u64) -> i64 {
    let secs = (days as i64).saturating_mul(86_400);
    chrono::Utc::now().timestamp().saturating_sub(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_is_in_the_past() {
        let now = chrono::Utc::now().timestamp();
        let f = backfill_floor(90);
        assert!(f < now);
        // ~90 days ≈ 7_776_000s; allow slack for test execution time.
        assert!((now - f - 7_776_000).abs() < 5);
    }

    #[test]
    fn zero_days_is_now() {
        let now = chrono::Utc::now().timestamp();
        assert!((backfill_floor(0) - now).abs() < 5);
    }
}
