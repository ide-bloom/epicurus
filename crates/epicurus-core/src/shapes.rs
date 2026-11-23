//! SQLite decoys in the shapes of real application databases.
//!
//! The databases are built in memory and serialized, so no temporary file is
//! ever written outside the decoy's final location.

use std::collections::BTreeMap;

use rusqlite::{Connection, MAIN_DB, params};
use time::OffsetDateTime;

use crate::Result;
use crate::catalog::SqliteShape;
use crate::generators::Entropy;

/// Chromium timestamps: microseconds since 1601-01-01 UTC.
fn chrome_time(t: OffsetDateTime) -> i64 {
    (t.unix_timestamp_nanos() / 1000) as i64 + 11_644_473_600_000_000
}

fn random_bytes(entropy: &mut dyn Entropy, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    entropy.fill(&mut v);
    v
}

/// Chromium AES-GCM blob: version tag, 12-byte nonce, ciphertext, 16-byte
/// tag. The key exists nowhere, so the blob decrypts to nothing.
fn chromium_encrypted(entropy: &mut dyn Entropy, plain_len: usize) -> Vec<u8> {
    let mut out = b"v10".to_vec();
    out.extend(random_bytes(entropy, 12 + plain_len + 16));
    out
}

/// Builds the database bytes for `shape`, with already-rendered `rows`.
pub fn build(
    shape: SqliteShape,
    rows: &[BTreeMap<String, String>],
    entropy: &mut dyn Entropy,
    created: OffsetDateTime,
) -> Result<Vec<u8>> {
    let mut conn = Connection::open_in_memory()?;
    match shape {
        SqliteShape::ChromiumLoginData => login_data(&conn, rows, entropy, created)?,
        SqliteShape::ChromiumCookies => cookies(&conn, rows, entropy, created)?,
        SqliteShape::VscodeState => vscode_state(&conn, rows)?,
    }
    let data = conn.serialize(MAIN_DB)?;
    Ok(data.to_vec())
}

fn meta(conn: &Connection, version: i64, compat: i64) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);",
    )?;
    conn.execute("INSERT INTO meta VALUES('mmap_status', '-1')", [])?;
    conn.execute(
        "INSERT INTO meta VALUES('version', ?1)",
        [version.to_string()],
    )?;
    conn.execute(
        "INSERT INTO meta VALUES('last_compatible_version', ?1)",
        [compat.to_string()],
    )?;
    Ok(())
}

fn login_data(
    conn: &Connection,
    rows: &[BTreeMap<String, String>],
    entropy: &mut dyn Entropy,
    created: OffsetDateTime,
) -> Result<()> {
    meta(conn, 43, 40)?;
    conn.execute_batch(
        "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, \
         username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, \
         signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, \
         scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, form_data BLOB, display_name VARCHAR, \
         icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, \
         possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, \
         moving_blocked_for BLOB, date_password_modified INTEGER NOT NULL DEFAULT 0, sender_email VARCHAR, \
         sender_name VARCHAR, date_received INTEGER, sharing_notification_displayed INTEGER NOT NULL DEFAULT 0, \
         keychain_identifier BLOB, sender_profile_image_url VARCHAR, \
         UNIQUE (origin_url, username_element, username_value, password_element, signon_realm));
         CREATE INDEX logins_signon ON logins (signon_realm);
         CREATE TABLE stats (origin_domain VARCHAR NOT NULL, username_value VARCHAR, dismissal_count INTEGER, \
         update_time INTEGER NOT NULL, UNIQUE(origin_domain, username_value));
         CREATE TABLE insecure_credentials (parent_id INTEGER REFERENCES logins ON UPDATE CASCADE ON DELETE CASCADE \
         DEFERRABLE INITIALLY DEFERRED, insecurity_type INTEGER NOT NULL, create_time INTEGER NOT NULL, \
         is_muted INTEGER NOT NULL DEFAULT 0, trigger_notification_from_backend INTEGER NOT NULL DEFAULT 0, \
         UNIQUE (parent_id, insecurity_type));",
    )?;
    for (i, row) in rows.iter().enumerate() {
        let origin = row.get("origin").cloned().unwrap_or_default();
        let user = row.get("username").cloned().unwrap_or_default();
        let realm = signon_realm(&origin);
        let pw_len = 12 + entropy.below(10) as usize;
        let pw = chromium_encrypted(entropy, pw_len);
        let t = chrome_time(created + time::Duration::hours(i as i64 * 37));
        conn.execute(
            "INSERT INTO logins (origin_url, action_url, username_element, username_value, password_element, \
             password_value, submit_element, signon_realm, date_created, blacklisted_by_user, scheme, password_type, \
             times_used, form_data, display_name, icon_url, federation_url, skip_zero_click, generation_upload_status, \
             possible_username_pairs, date_last_used, date_password_modified) \
             VALUES (?1, ?1, 'login', ?2, 'password', ?3, '', ?4, ?5, 0, 0, 0, ?6, x'', '', '', '', 0, 0, x'', ?7, ?5)",
            params![origin, user, pw, realm, t, (i as i64 % 7) + 1, t + 86_400_000_000],
        )?;
    }
    Ok(())
}

fn signon_realm(origin: &str) -> String {
    // "https://github.com/login" -> "https://github.com/"
    match origin.find("://") {
        Some(i) => {
            let rest = &origin[i + 3..];
            let host = rest.split('/').next().unwrap_or(rest);
            format!("{}://{}/", &origin[..i], host)
        }
        None => origin.to_string(),
    }
}

fn cookies(
    conn: &Connection,
    rows: &[BTreeMap<String, String>],
    entropy: &mut dyn Entropy,
    created: OffsetDateTime,
) -> Result<()> {
    meta(conn, 24, 24)?;
    conn.execute_batch(
        "CREATE TABLE cookies(creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL, \
         name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, \
         expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, \
         last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, \
         priority INTEGER NOT NULL, samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, \
         source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL, \
         has_cross_site_ancestor INTEGER NOT NULL);
         CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, \
         name, path, source_scheme, source_port);",
    )?;
    for (i, row) in rows.iter().enumerate() {
        let host = row.get("host").cloned().unwrap_or_default();
        let name = row.get("name").cloned().unwrap_or_default();
        let path = row.get("path").cloned().unwrap_or_else(|| "/".to_string());
        let enc_len = 32 + entropy.below(96) as usize;
        let enc = chromium_encrypted(entropy, enc_len);
        let t = chrome_time(created + time::Duration::minutes(i as i64 * 13));
        let expires = t + 400 * 86_400_000_000;
        conn.execute(
            "INSERT INTO cookies VALUES (?1, ?2, '', ?3, '', ?4, ?5, ?6, 1, 1, ?1, 1, 1, 1, 0, 2, 443, ?1, 0, 0)",
            params![t, host, name, enc, path, expires],
        )?;
    }
    Ok(())
}

fn vscode_state(conn: &Connection, rows: &[BTreeMap<String, String>]) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);
         CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB);",
    )?;
    for row in rows {
        let key = row.get("key").cloned().unwrap_or_default();
        let value = row.get("value").cloned().unwrap_or_default();
        conn.execute("INSERT INTO ItemTable VALUES (?1, ?2)", params![key, value])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Writes the bytes to a file and opens it; the TempDir keeps the file alive.
    fn reopen(bytes: &[u8]) -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("db");
        std::fs::write(&p, bytes).unwrap();
        let conn = Connection::open(&p).unwrap();
        (dir, conn)
    }

    #[test]
    fn login_data_is_a_valid_chromium_shaped_db() {
        let mut rng = rand::rng();
        let bytes = build(
            SqliteShape::ChromiumLoginData,
            &[row(&[
                ("origin", "https://github.com/login"),
                ("username", "a@b.c"),
            ])],
            &mut rng,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert!(bytes.starts_with(b"SQLite format 3\0"));
        let (_dir, db) = reopen(&bytes);
        let (realm, pw): (String, Vec<u8>) = db
            .query_row("SELECT signon_realm, password_value FROM logins", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(realm, "https://github.com/");
        assert!(pw.starts_with(b"v10"));
    }

    #[test]
    fn cookies_and_state_shapes_build() {
        let mut rng = rand::rng();
        let c = build(
            SqliteShape::ChromiumCookies,
            &[row(&[("host", ".github.com"), ("name", "user_session")])],
            &mut rng,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let n: i64 = reopen(&c)
            .1
            .query_row("SELECT count(*) FROM cookies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let s = build(
            SqliteShape::VscodeState,
            &[row(&[("key", "cursorAuth/accessToken"), ("value", "x")])],
            &mut rng,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        let v: String = reopen(&s)
            .1
            .query_row(
                "SELECT value FROM ItemTable WHERE key='cursorAuth/accessToken'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, "x");
    }
}
