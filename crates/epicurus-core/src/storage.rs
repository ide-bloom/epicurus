//! SQLite storage (WAL mode): manifest, incidents, touch log and small
//! key/value state such as the install seed.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::catalog::Category;
use crate::incident::{Incident, IncidentSummary};
use crate::manifest::{CreatedDir, Manifest, ManifestEntry};
use crate::seed::InstallSeed;
use crate::timefmt::{parse_rfc3339, rfc3339};
use crate::{Error, Result};

const SCHEMA_VERSION: i64 = 1;

/// Database handle.
pub struct Store {
    conn: Connection,
}

/// A logged touch that did not (or not yet) become an incident, e.g. an
/// allowlisted scanner. Kept for the "touches in the last 24 hours" view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TouchLogRow {
    /// When.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub at: OffsetDateTime,
    /// PID.
    pub pid: u32,
    /// Image.
    pub image: String,
    /// Path.
    pub path: String,
    /// Decoy id.
    pub decoy_id: String,
    /// Disposition: `allowlisted`, `incident`, `own`.
    pub disposition: String,
    /// Free text (allowlist entry name, incident id).
    pub note: String,
}

/// A logged event (integrity changes, re-plants, alert failures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    /// When.
    #[serde(with = "crate::timefmt::serde_rfc3339")]
    pub at: OffsetDateTime,
    /// Kind.
    pub kind: String,
    /// Message.
    pub message: String,
}

fn ts(t: OffsetDateTime) -> String {
    rfc3339(t)
}

fn parse_ts(s: &str) -> rusqlite::Result<OffsetDateTime> {
    parse_rfc3339(s).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(0, s.to_string(), rusqlite::types::Type::Text)
    })
}

impl Store {
    /// Opens (creating if needed) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory database (tests).
    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory()?,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::Config(format!(
                "database schema {version} is newer than this build supports ({SCHEMA_VERSION})"
            )));
        }
        if version < 1 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS decoys (
                    path TEXT PRIMARY KEY COLLATE NOCASE,
                    sha256 TEXT NOT NULL, size INTEGER NOT NULL, decoy_id TEXT NOT NULL,
                    category TEXT NOT NULL, target TEXT NOT NULL, planted_at TEXT NOT NULL,
                    canary INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS created_dirs (
                    path TEXT PRIMARY KEY COLLATE NOCASE, created_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL,
                    simulated INTEGER NOT NULL, pid INTEGER NOT NULL, image TEXT NOT NULL,
                    data TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS incidents_created ON incidents(created_at);
                 CREATE TABLE IF NOT EXISTS touch_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, pid INTEGER NOT NULL,
                    image TEXT NOT NULL, path TEXT NOT NULL, decoy_id TEXT NOT NULL,
                    disposition TEXT NOT NULL, note TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS touch_log_at ON touch_log(at);
                 CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, kind TEXT NOT NULL,
                    message TEXT NOT NULL);
                 PRAGMA user_version = 1;",
            )?;
        }
        Ok(())
    }

    // ---- key/value -------------------------------------------------------

    /// Reads a value.
    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// Writes a value.
    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// The install seed, created on first use.
    pub fn install_seed(&self) -> Result<InstallSeed> {
        if let Some(hex) = self.kv_get("install_seed")?
            && let Some(seed) = InstallSeed::from_hex(&hex)
        {
            return Ok(seed);
        }
        let seed = InstallSeed::generate();
        self.kv_set("install_seed", &seed.to_hex())?;
        Ok(seed)
    }

    // ---- manifest --------------------------------------------------------

    /// Loads the full manifest.
    pub fn manifest(&self) -> Result<Manifest> {
        let mut stmt = self.conn.prepare(
            "SELECT path, sha256, size, decoy_id, category, target, planted_at, canary FROM decoys ORDER BY path",
        )?;
        let entries = stmt
            .query_map([], |r| {
                let cat: String = r.get(4)?;
                Ok(ManifestEntry {
                    path: PathBuf::from(r.get::<_, String>(0)?),
                    sha256: r.get(1)?,
                    size: r.get::<_, i64>(2)? as u64,
                    decoy_id: r.get(3)?,
                    category: Category::parse(&cat).unwrap_or(Category::Cloud),
                    target: PathBuf::from(r.get::<_, String>(5)?),
                    planted_at: parse_ts(&r.get::<_, String>(6)?)?,
                    canary: r.get::<_, i64>(7)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = self
            .conn
            .prepare("SELECT path, created_at FROM created_dirs ORDER BY path")?;
        let dirs = stmt
            .query_map([], |r| {
                Ok(CreatedDir {
                    path: PathBuf::from(r.get::<_, String>(0)?),
                    created_at: parse_ts(&r.get::<_, String>(1)?)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Manifest { entries, dirs })
    }

    /// Records planted files and created directories.
    pub fn add_to_manifest(
        &mut self,
        entries: &[ManifestEntry],
        dirs: &[CreatedDir],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for e in entries {
            tx.execute(
                "INSERT OR REPLACE INTO decoys(path, sha256, size, decoy_id, category, target, planted_at, canary)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    e.path.to_string_lossy(),
                    e.sha256,
                    e.size as i64,
                    e.decoy_id,
                    e.category.as_str(),
                    e.target.to_string_lossy(),
                    ts(e.planted_at),
                    i64::from(e.canary)
                ],
            )?;
        }
        for d in dirs {
            tx.execute(
                "INSERT OR IGNORE INTO created_dirs(path, created_at) VALUES (?1, ?2)",
                params![d.path.to_string_lossy(), ts(d.created_at)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Forgets manifest files.
    pub fn remove_from_manifest<'a>(
        &mut self,
        paths: impl IntoIterator<Item = &'a PathBuf>,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for p in paths {
            tx.execute("DELETE FROM decoys WHERE path = ?1", [p.to_string_lossy()])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Forgets created directories.
    pub fn remove_dirs<'a>(&mut self, paths: impl IntoIterator<Item = &'a PathBuf>) -> Result<()> {
        let tx = self.conn.transaction()?;
        for p in paths {
            tx.execute(
                "DELETE FROM created_dirs WHERE path = ?1",
                [p.to_string_lossy()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---- incidents -------------------------------------------------------

    /// Inserts or updates an incident.
    pub fn save_incident(&self, inc: &Incident) -> Result<()> {
        let data = serde_json::to_string(inc)?;
        self.conn.execute(
            "INSERT INTO incidents(id, created_at, updated_at, severity, score, status, simulated, pid, image, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, severity = excluded.severity,
               score = excluded.score, status = excluded.status, data = excluded.data",
            params![
                inc.id,
                ts(inc.created_at),
                ts(inc.updated_at),
                inc.severity.as_str(),
                i64::from(inc.score),
                serde_json::to_value(inc.status)?.as_str().unwrap_or("open"),
                i64::from(inc.simulated),
                i64::from(inc.process.pid),
                inc.process.image_path,
                data
            ],
        )?;
        Ok(())
    }

    /// Loads one incident.
    pub fn incident(&self, id: &str) -> Result<Option<Incident>> {
        let data: Option<String> = self
            .conn
            .query_row("SELECT data FROM incidents WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        data.map(|d| serde_json::from_str(&d).map_err(Error::from))
            .transpose()
    }

    /// Most recent incidents first.
    pub fn incidents(&self, limit: u32) -> Result<Vec<Incident>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM incidents ORDER BY created_at DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([i64::from(limit)], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|d| serde_json::from_str(d).map_err(Error::from))
            .collect()
    }

    /// Summaries, most recent first.
    pub fn incident_summaries(&self, limit: u32) -> Result<Vec<IncidentSummary>> {
        Ok(self
            .incidents(limit)?
            .iter()
            .map(Incident::summary)
            .collect())
    }

    /// Incidents awaiting a decision.
    pub fn pending_incidents(&self) -> Result<Vec<Incident>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM incidents WHERE status = 'awaiting_decision' ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|d| serde_json::from_str(d).map_err(Error::from))
            .collect()
    }

    /// Number of incidents created since `since`.
    pub fn incidents_since(&self, since: OffsetDateTime) -> Result<u32> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM incidents WHERE created_at >= ?1",
            [ts(since)],
            |r| r.get(0),
        )?;
        Ok(n as u32)
    }

    // ---- touch log and events ---------------------------------------------

    /// Appends to the touch log.
    pub fn log_touch(&self, row: &TouchLogRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO touch_log(at, pid, image, path, decoy_id, disposition, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts(row.at), i64::from(row.pid), row.image, row.path, row.decoy_id, row.disposition, row.note],
        )?;
        Ok(())
    }

    /// Touches since `since` (newest first).
    pub fn touches_since(&self, since: OffsetDateTime, limit: u32) -> Result<Vec<TouchLogRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT at, pid, image, path, decoy_id, disposition, note FROM touch_log WHERE at >= ?1 ORDER BY at DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![ts(since), i64::from(limit)], |r| {
                Ok(TouchLogRow {
                    at: parse_ts(&r.get::<_, String>(0)?)?,
                    pid: r.get::<_, i64>(1)? as u32,
                    image: r.get(2)?,
                    path: r.get(3)?,
                    decoy_id: r.get(4)?,
                    disposition: r.get(5)?,
                    note: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Appends an event.
    pub fn log_event(&self, at: OffsetDateTime, kind: &str, message: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events(at, kind, message) VALUES (?1, ?2, ?3)",
            params![ts(at), kind, message],
        )?;
        Ok(())
    }

    /// Recent events (newest first).
    pub fn events(&self, limit: u32) -> Result<Vec<EventRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT at, kind, message FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([i64::from(limit)], |r| {
                Ok(EventRow {
                    at: parse_ts(&r.get::<_, String>(0)?)?,
                    kind: r.get(1)?,
                    message: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Deletes touch log and event rows older than `before` to bound growth.
    pub fn prune(&self, before: OffsetDateTime) -> Result<()> {
        self.conn
            .execute("DELETE FROM touch_log WHERE at < ?1", [ts(before)])?;
        self.conn
            .execute("DELETE FROM events WHERE at < ?1", [ts(before)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{IncidentStatus, ProcessProfile};

    fn entry(path: &str) -> ManifestEntry {
        ManifestEntry {
            path: PathBuf::from(path),
            sha256: "ab".repeat(32),
            size: 10,
            decoy_id: "aws-credentials".into(),
            category: Category::Cloud,
            target: PathBuf::from(path),
            planted_at: OffsetDateTime::now_utc(),
            canary: false,
        }
    }

    #[test]
    fn manifest_roundtrip_is_case_insensitive() {
        let mut s = Store::open_in_memory().unwrap();
        s.add_to_manifest(
            &[entry(r"C:\U\.aws\credentials")],
            &[CreatedDir {
                path: PathBuf::from(r"C:\U\.aws"),
                created_at: OffsetDateTime::now_utc(),
            }],
        )
        .unwrap();
        // Same path, different case: replaces rather than duplicates.
        s.add_to_manifest(&[entry(r"c:\u\.AWS\credentials")], &[])
            .unwrap();
        let m = s.manifest().unwrap();
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.dirs.len(), 1);
        s.remove_from_manifest([&PathBuf::from(r"C:\U\.aws\CREDENTIALS")])
            .unwrap();
        assert!(s.manifest().unwrap().entries.is_empty());
    }

    #[test]
    fn incidents_roundtrip_and_pending() {
        let s = Store::open_in_memory().unwrap();
        let mut i = Incident::new(
            ProcessProfile {
                pid: 7,
                image_path: "x.exe".into(),
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
            "h".into(),
        );
        s.save_incident(&i).unwrap();
        i.status = IncidentStatus::AwaitingDecision;
        i.score = 95;
        s.save_incident(&i).unwrap();
        assert_eq!(s.incident(&i.id).unwrap().unwrap().score, 95);
        assert_eq!(s.pending_incidents().unwrap().len(), 1);
        assert_eq!(s.incidents(10).unwrap().len(), 1);
        assert_eq!(
            s.incidents_since(OffsetDateTime::now_utc() - time::Duration::hours(1))
                .unwrap(),
            1
        );
        assert!(s.incident("inc_0000000000000000").unwrap().is_none());
    }

    #[test]
    fn seed_is_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        let a = Store::open(&p).unwrap().install_seed().unwrap();
        let b = Store::open(&p).unwrap().install_seed().unwrap();
        assert_eq!(a, b);
        let mode: String = Store::open(&p)
            .unwrap()
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn touch_log_and_events() {
        let s = Store::open_in_memory().unwrap();
        let now = OffsetDateTime::now_utc();
        s.log_touch(&TouchLogRow {
            at: now,
            pid: 1,
            image: "i".into(),
            path: "p".into(),
            decoy_id: "d".into(),
            disposition: "allowlisted".into(),
            note: "Defender".into(),
        })
        .unwrap();
        s.log_event(now, "integrity", "deleted").unwrap();
        assert_eq!(
            s.touches_since(now - time::Duration::minutes(1), 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(s.events(10).unwrap()[0].kind, "integrity");
        s.prune(now + time::Duration::seconds(1)).unwrap();
        assert!(s.events(10).unwrap().is_empty());
    }
}
