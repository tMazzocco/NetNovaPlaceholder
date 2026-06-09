use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Arc;

/// Thin SQLite-backed cursor store. Each source (audit, access_logs, …) keeps
/// its resume-point as a string keyed by source name. Resilient to crashes —
/// cursor is advanced only after a successful sink emit upstream.
#[derive(Clone)]
pub struct StateStore {
    conn: Arc<Mutex<Connection>>,
}

impl StateStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cursors (
                source TEXT PRIMARY KEY,
                value  TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    pub fn get(&self, source: &str) -> anyhow::Result<Option<String>> {
        let g = self.conn.lock();
        let mut stmt = g.prepare_cached("SELECT value FROM cursors WHERE source = ?1")?;
        let mut rows = stmt.query(params![source])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn set(&self, source: &str, value: &str) -> anyhow::Result<()> {
        let g = self.conn.lock();
        g.execute(
            "INSERT INTO cursors(source, value, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(source) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![source, value, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let tmp = std::env::temp_dir().join(format!("wsc-state-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let s = StateStore::open(&tmp).unwrap();
        assert!(s.get("audit").unwrap().is_none());
        s.set("audit", "cursor-123").unwrap();
        assert_eq!(s.get("audit").unwrap().as_deref(), Some("cursor-123"));
        s.set("audit", "cursor-456").unwrap();
        assert_eq!(s.get("audit").unwrap().as_deref(), Some("cursor-456"));
        let _ = std::fs::remove_file(&tmp);
    }
}
