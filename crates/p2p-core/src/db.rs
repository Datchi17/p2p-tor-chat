//! Vault schema and queries for application data.

use p2p_vault::rusqlite::{self, Connection, OptionalExtension, Row, params};
use serde::Serialize;

pub const CORE_V1: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    onion TEXT NOT NULL UNIQUE,
    identity_key BLOB NOT NULL UNIQUE,
    noise_static BLOB NOT NULL UNIQUE,
    client_auth_pub BLOB NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    disappear_secs INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE messages (
    id BLOB PRIMARY KEY,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    remote_id BLOB,
    outgoing INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    body TEXT NOT NULL,
    ts INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,
    status INTEGER NOT NULL,
    expire_secs INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    UNIQUE (contact_id, remote_id)
);
CREATE INDEX messages_by_contact ON messages(contact_id, ts);
CREATE INDEX messages_by_expiry ON messages(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE outbox (
    id BLOB PRIMARY KEY,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    message_id BLOB REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX outbox_by_contact ON outbox(contact_id, created_at);
CREATE TABLE seen (
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    remote_id BLOB NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (contact_id, remote_id)
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// File transfer, outbox priorities, and disappearing messages on by default (1 week).
pub const CORE_V2: &str = "
CREATE TABLE attachments (
    message_id BLOB PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 BLOB NOT NULL,
    chunk_count INTEGER NOT NULL,
    done_chunks INTEGER NOT NULL DEFAULT 0,
    state INTEGER NOT NULL
);
CREATE TABLE attachment_chunks (
    message_id BLOB NOT NULL REFERENCES attachments(message_id) ON DELETE CASCADE,
    idx INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (message_id, idx)
) WITHOUT ROWID;
ALTER TABLE outbox ADD COLUMN attachment_id BLOB REFERENCES attachments(message_id) ON DELETE CASCADE;
ALTER TABLE outbox ADD COLUMN bulk INTEGER NOT NULL DEFAULT 0;
UPDATE contacts SET disappear_secs = 604800 WHERE disappear_secs = 0;
";

/// All vault migrations, in order. Never reorder or edit released entries; only append.
pub const MIGRATIONS: &[&str] = &[CORE_V1, p2p_signal::SCHEMA, CORE_V2];

/// Disappearing-message timer for newly paired contacts: 1 week.
pub const DEFAULT_DISAPPEAR_SECS: u32 = 7 * 24 * 3600;

pub const KIND_TEXT: i64 = 0;
pub const KIND_SYSTEM: i64 = 1;
pub const KIND_FILE: i64 = 2;

pub const FILE_SENDING: i64 = 0;
pub const FILE_SENT: i64 = 1;
pub const FILE_RECEIVING: i64 = 2;
pub const FILE_RECEIVED: i64 = 3;
pub const FILE_FAILED: i64 = 4;

pub const OUT_QUEUED: i64 = 0;
pub const OUT_DELIVERED: i64 = 2;
pub const OUT_READ: i64 = 3;
pub const OUT_FAILED: i64 = 4;
pub const IN_UNREAD: i64 = 10;
pub const IN_READ: i64 = 11;

/// How long undelivered messages stay in the outbox before being marked failed.
pub const OUTBOX_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
/// How long received message IDs are remembered for de-duplication.
pub const SEEN_TTL_MS: i64 = 45 * 24 * 3600 * 1000;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn random_id() -> Vec<u8> {
    let mut id = vec![0u8; 16];
    getrandom::fill(&mut id).expect("OS RNG unavailable");
    id
}

// ------------------------------------------------------------------ meta

pub fn meta_get(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()
}

pub fn meta_set(conn: &Connection, key: &str, value: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ------------------------------------------------------------------ settings

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct Settings {
    /// Send read receipts to contacts.
    pub read_receipts: bool,
    /// Lock the screen after this many idle minutes (0 = never).
    pub auto_lock_minutes: u32,
    /// Show desktop notifications (content is never shown).
    pub notifications: bool,
    /// Tor bridge lines (one per line); empty = connect to Tor directly.
    pub bridges: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { read_receipts: false, auto_lock_minutes: 10, notifications: false, bridges: vec![] }
    }
}

pub fn settings_get(conn: &Connection) -> rusqlite::Result<Settings> {
    let raw: Option<String> =
        conn.query_row("SELECT value FROM settings WHERE key = 'app'", [], |r| r.get(0)).optional()?;
    Ok(raw.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default())
}

pub fn settings_set(conn: &Connection, s: &Settings) -> rusqlite::Result<()> {
    let json = serde_json::to_string(s).expect("settings serialize");
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('app', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [json],
    )?;
    Ok(())
}

// ------------------------------------------------------------------ contacts

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: i64,
    pub name: String,
    pub onion: String,
    pub identity_key: Vec<u8>,
    pub noise_static: [u8; 32],
    pub client_auth_pub: [u8; 32],
    pub verified: bool,
    pub disappear_secs: u32,
    pub created_at: i64,
}

fn contact_from_row(r: &Row<'_>) -> rusqlite::Result<Contact> {
    let noise: Vec<u8> = r.get(4)?;
    let auth: Vec<u8> = r.get(5)?;
    Ok(Contact {
        id: r.get(0)?,
        name: r.get(1)?,
        onion: r.get(2)?,
        identity_key: r.get(3)?,
        noise_static: noise.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_auth_pub: auth.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        verified: r.get::<_, i64>(6)? != 0,
        disappear_secs: r.get::<_, i64>(7)? as u32,
        created_at: r.get(8)?,
    })
}

const CONTACT_COLS: &str =
    "id, name, onion, identity_key, noise_static, client_auth_pub, verified, disappear_secs, created_at";

pub fn contacts(conn: &Connection) -> rusqlite::Result<Vec<Contact>> {
    let mut st = conn.prepare(&format!("SELECT {CONTACT_COLS} FROM contacts ORDER BY id"))?;
    st.query_map([], contact_from_row)?.collect()
}

pub fn contact(conn: &Connection, id: i64) -> rusqlite::Result<Option<Contact>> {
    conn.query_row(&format!("SELECT {CONTACT_COLS} FROM contacts WHERE id = ?1"), [id], contact_from_row)
        .optional()
}

pub fn contact_by_noise(conn: &Connection, noise: &[u8; 32]) -> rusqlite::Result<Option<Contact>> {
    conn.query_row(
        &format!("SELECT {CONTACT_COLS} FROM contacts WHERE noise_static = ?1"),
        [&noise[..]],
        contact_from_row,
    )
    .optional()
}

pub fn insert_contact(
    conn: &Connection,
    name: &str,
    onion: &str,
    identity_key: &[u8],
    noise_static: &[u8; 32],
    client_auth_pub: &[u8; 32],
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO contacts (name, onion, identity_key, noise_static, client_auth_pub, disappear_secs, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![name, onion, identity_key, &noise_static[..], &client_auth_pub[..], DEFAULT_DISAPPEAR_SECS, now_ms()],
    )?;
    Ok(conn.last_insert_rowid())
}

// ------------------------------------------------------------------ messages

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MessageView {
    /// Hex message ID.
    pub id: String,
    pub contact_id: i64,
    pub outgoing: bool,
    /// "text", "file" or "system".
    pub kind: &'static str,
    pub body: String,
    /// Local time the message was sent or received (ms).
    pub ts: i64,
    /// Sender's clock (ms).
    pub sent_at: i64,
    /// queued | delivered | read | failed | unread | seen
    pub status: &'static str,
    pub expires_at: Option<i64>,
    /// Set for file messages.
    pub file: Option<FileView>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FileView {
    pub name: String,
    pub size: i64,
    /// Chunks delivered (sending) or received (receiving).
    pub done: i64,
    pub total: i64,
    /// sending | sent | receiving | received | failed
    pub state: &'static str,
}

fn file_state_name(s: i64) -> &'static str {
    match s {
        FILE_SENDING => "sending",
        FILE_SENT => "sent",
        FILE_RECEIVING => "receiving",
        FILE_RECEIVED => "received",
        _ => "failed",
    }
}

pub fn status_name(s: i64) -> &'static str {
    match s {
        OUT_QUEUED => "queued",
        OUT_DELIVERED => "delivered",
        OUT_READ => "read",
        OUT_FAILED => "failed",
        IN_UNREAD => "unread",
        _ => "seen",
    }
}

const MSG_SELECT: &str = "SELECT m.id, m.contact_id, m.outgoing, m.kind, m.body, m.ts, m.sent_at, m.status, m.expires_at,
     a.name, a.size, a.done_chunks, a.chunk_count, a.state
     FROM messages m LEFT JOIN attachments a ON a.message_id = m.id";

fn message_from_row(r: &Row<'_>) -> rusqlite::Result<MessageView> {
    let kind = r.get::<_, i64>(3)?;
    let file = match r.get::<_, Option<String>>(9)? {
        Some(name) => Some(FileView {
            name,
            size: r.get(10)?,
            done: r.get(11)?,
            total: r.get(12)?,
            state: file_state_name(r.get(13)?),
        }),
        None => None,
    };
    Ok(MessageView {
        id: hex::encode(r.get::<_, Vec<u8>>(0)?),
        contact_id: r.get(1)?,
        outgoing: r.get::<_, i64>(2)? != 0,
        kind: match kind {
            KIND_SYSTEM => "system",
            KIND_FILE => "file",
            _ => "text",
        },
        body: r.get(4)?,
        ts: r.get(5)?,
        sent_at: r.get(6)?,
        status: status_name(r.get(7)?),
        expires_at: r.get(8)?,
        file,
    })
}

pub fn message(conn: &Connection, id: &[u8]) -> rusqlite::Result<Option<MessageView>> {
    conn.query_row(&format!("{MSG_SELECT} WHERE m.id = ?1"), [id], message_from_row).optional()
}

/// Messages for a contact, newest last. `before_ts` pages backwards.
pub fn messages(conn: &Connection, contact_id: i64, limit: u32, before_ts: Option<i64>) -> rusqlite::Result<Vec<MessageView>> {
    let mut st = conn.prepare(&format!(
        "{MSG_SELECT} WHERE m.contact_id = ?1 AND m.ts < ?2 ORDER BY m.ts DESC, m.rowid DESC LIMIT ?3"
    ))?;
    let mut v: Vec<MessageView> = st
        .query_map(params![contact_id, before_ts.unwrap_or(i64::MAX), limit], message_from_row)?
        .collect::<rusqlite::Result<_>>()?;
    v.reverse();
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
pub fn insert_message(
    conn: &Connection,
    id: &[u8],
    contact_id: i64,
    remote_id: Option<&[u8]>,
    outgoing: bool,
    kind: i64,
    body: &str,
    sent_at: i64,
    status: i64,
    expire_secs: u32,
) -> rusqlite::Result<()> {
    let ts = now_ms();
    // Received messages start their countdown now; sent ones when delivered (see `start_expiry`).
    let expires_at = (expire_secs > 0 && !outgoing).then(|| ts + expire_secs as i64 * 1000);
    conn.execute(
        "INSERT INTO messages (id, contact_id, remote_id, outgoing, kind, body, ts, sent_at, status, expire_secs, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![id, contact_id, remote_id, outgoing as i64, kind, body, ts, sent_at, status, expire_secs, expires_at],
    )?;
    Ok(())
}

/// Starts the disappearing countdown of a sent message (on delivery, read receipt or failure).
pub fn start_expiry(conn: &Connection, message_id: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE messages SET expires_at = ?1 + expire_secs * 1000
         WHERE id = ?2 AND outgoing = 1 AND expire_secs > 0 AND expires_at IS NULL",
        params![now_ms(), message_id],
    )?;
    Ok(())
}

// ------------------------------------------------------------------ attachments

pub fn insert_attachment(
    conn: &Connection,
    message_id: &[u8],
    name: &str,
    size: i64,
    sha256: &[u8],
    chunk_count: u32,
    state: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO attachments (message_id, name, size, sha256, chunk_count, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![message_id, name, size, sha256, chunk_count, state],
    )?;
    Ok(())
}

pub struct Attachment {
    pub message_id: Vec<u8>,
    pub size: i64,
    pub sha256: Vec<u8>,
    pub chunk_count: u32,
    pub done_chunks: u32,
    pub state: i64,
}

/// The attachment of a received file, looked up by the sender's file ID.
pub fn incoming_attachment(conn: &Connection, contact_id: i64, remote_id: &[u8]) -> rusqlite::Result<Option<Attachment>> {
    conn.query_row(
        "SELECT a.message_id, a.size, a.sha256, a.chunk_count, a.done_chunks, a.state
         FROM attachments a JOIN messages m ON m.id = a.message_id
         WHERE m.contact_id = ?1 AND m.remote_id = ?2 AND m.outgoing = 0",
        params![contact_id, remote_id],
        |r| {
            Ok(Attachment {
                message_id: r.get(0)?,
                size: r.get(1)?,
                sha256: r.get(2)?,
                chunk_count: r.get(3)?,
                done_chunks: r.get(4)?,
                state: r.get(5)?,
            })
        },
    )
    .optional()
}

/// Number of files still being received from a contact.
pub fn receiving_count(conn: &Connection, contact_id: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM attachments a JOIN messages m ON m.id = a.message_id
         WHERE m.contact_id = ?1 AND a.state = ?2",
        params![contact_id, FILE_RECEIVING],
        |r| r.get(0),
    )
}

/// Stores one received chunk. Returns false if it was already stored.
pub fn insert_chunk(conn: &Connection, message_id: &[u8], idx: u32, data: &[u8]) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO attachment_chunks (message_id, idx, data) VALUES (?1, ?2, ?3)",
        params![message_id, idx, data],
    )?;
    if n == 1 {
        conn.execute("UPDATE attachments SET done_chunks = done_chunks + 1 WHERE message_id = ?1", [message_id])?;
    }
    Ok(n == 1)
}

pub fn set_attachment_state(conn: &Connection, message_id: &[u8], state: i64) -> rusqlite::Result<()> {
    conn.execute("UPDATE attachments SET state = ?1 WHERE message_id = ?2", params![state, message_id])?;
    if state == FILE_FAILED {
        conn.execute("DELETE FROM attachment_chunks WHERE message_id = ?1", [message_id])?;
    }
    Ok(())
}

/// Calls `f` with each stored chunk of a file, in order.
pub fn for_each_chunk(conn: &Connection, message_id: &[u8], mut f: impl FnMut(&[u8])) -> rusqlite::Result<()> {
    let mut st = conn.prepare("SELECT data FROM attachment_chunks WHERE message_id = ?1 ORDER BY idx")?;
    let mut rows = st.query([message_id])?;
    while let Some(r) = rows.next()? {
        f(r.get_ref(0)?.as_blob()?);
    }
    Ok(())
}

// ------------------------------------------------------------------ outbox

#[derive(Clone)]
pub struct OutboxItem {
    pub id: Vec<u8>,
    pub content: Vec<u8>,
    /// File data, sent after everything else and only a few at a time.
    pub bulk: bool,
}

pub fn outbox_push(conn: &Connection, id: &[u8], contact_id: i64, message_id: Option<&[u8]>, content: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO outbox (id, contact_id, message_id, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, contact_id, message_id, content, now_ms()],
    )?;
    Ok(())
}

/// Queues one part of a file. `bulk` parts (file data) are sent after everything else, so
/// text messages don't wait behind a large file.
pub fn outbox_push_file_part(
    conn: &Connection,
    id: &[u8],
    contact_id: i64,
    attachment_id: &[u8],
    bulk: bool,
    content: &[u8],
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO outbox (id, contact_id, attachment_id, bulk, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, contact_id, attachment_id, bulk as i64, content, now_ms()],
    )?;
    Ok(())
}

pub fn outbox_for(conn: &Connection, contact_id: i64, limit: u32) -> rusqlite::Result<Vec<OutboxItem>> {
    let mut st =
        conn.prepare("SELECT id, content, bulk FROM outbox WHERE contact_id = ?1 ORDER BY bulk, created_at, rowid LIMIT ?2")?;
    st.query_map(params![contact_id, limit], |r| {
        Ok(OutboxItem { id: r.get(0)?, content: r.get(1)?, bulk: r.get::<_, i64>(2)? != 0 })
    })?
        .collect()
}

pub fn outbox_count(conn: &Connection, contact_id: i64) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM outbox WHERE contact_id = ?1", [contact_id], |r| r.get(0))
}

/// Removes an acknowledged outbox entry. Returns the ID of a message whose view changed
/// (for file data, only every 2 % of progress, to keep UI updates cheap).
pub fn outbox_ack(conn: &Connection, contact_id: i64, id: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
    type Row = (Option<Vec<u8>>, Option<Vec<u8>>, bool);
    let row: Option<Row> = conn
        .query_row(
            "SELECT message_id, attachment_id, bulk FROM outbox WHERE id = ?1 AND contact_id = ?2",
            params![id, contact_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)),
        )
        .optional()?;
    let Some((msg, attachment, bulk)) = row else { return Ok(None) };
    conn.execute("DELETE FROM outbox WHERE id = ?1", [id])?;
    let delivered = |m: &[u8]| -> rusqlite::Result<()> {
        conn.execute("UPDATE messages SET status = ?1 WHERE id = ?2 AND status = ?3", params![OUT_DELIVERED, m, OUT_QUEUED])?;
        start_expiry(conn, m)
    };
    if let Some(m) = &msg {
        delivered(m)?;
        return Ok(msg);
    }
    match attachment {
        Some(a) if bulk => {
            conn.execute("UPDATE attachments SET done_chunks = done_chunks + 1 WHERE message_id = ?1", [&a])?;
            let (done, total): (i64, i64) =
                conn.query_row("SELECT done_chunks, chunk_count FROM attachments WHERE message_id = ?1", [&a], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if done >= total {
                set_attachment_state(conn, &a, FILE_SENT)?;
                delivered(&a)?;
                return Ok(Some(a));
            }
            Ok((done * 50 / total != (done - 1) * 50 / total).then_some(a))
        }
        _ => Ok(None),
    }
}

/// Marks a contact's incoming messages read; returns the remote IDs that were unread.
pub fn mark_read(conn: &Connection, contact_id: i64) -> rusqlite::Result<Vec<Vec<u8>>> {
    let mut st = conn.prepare(
        "SELECT remote_id FROM messages WHERE contact_id = ?1 AND status = ?2 AND remote_id IS NOT NULL",
    )?;
    let ids: Vec<Vec<u8>> = st.query_map(params![contact_id, IN_UNREAD], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    conn.execute("UPDATE messages SET status = ?1 WHERE contact_id = ?2 AND status = ?3", params![IN_READ, contact_id, IN_UNREAD])?;
    Ok(ids)
}

pub fn unread_count(conn: &Connection, contact_id: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM messages WHERE contact_id = ?1 AND status = ?2",
        params![contact_id, IN_UNREAD],
        |r| r.get(0),
    )
}

/// Deletes expired disappearing messages and stale bookkeeping. Returns deleted message IDs
/// (hex) grouped by contact.
pub fn expire(conn: &Connection) -> rusqlite::Result<Vec<(i64, String)>> {
    let now = now_ms();
    let mut st = conn.prepare("SELECT contact_id, id FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1")?;
    let gone: Vec<(i64, String)> = st
        .query_map([now], |r| Ok((r.get::<_, i64>(0)?, hex::encode(r.get::<_, Vec<u8>>(1)?))))?
        .collect::<rusqlite::Result<_>>()?;
    conn.execute("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM seen WHERE seen_at < ?1", [now - SEEN_TTL_MS])?;
    // Undeliverable for too long: mark failed and drop from the outbox.
    let stale = "SELECT coalesce(message_id, attachment_id) FROM outbox WHERE created_at < ?3";
    conn.execute(
        &format!("UPDATE attachments SET state = ?1 WHERE state = ?2 AND message_id IN ({stale})"),
        params![FILE_FAILED, FILE_SENDING, now - OUTBOX_TTL_MS],
    )?;
    // Failed messages still disappear on their timer, counted from now.
    conn.execute(
        &format!(
            "UPDATE messages SET status = ?1, expires_at = CASE WHEN expire_secs > 0 THEN ?4 + expire_secs * 1000 END
             WHERE status = ?2 AND id IN ({stale})"
        ),
        params![OUT_FAILED, OUT_QUEUED, now - OUTBOX_TTL_MS, now],
    )?;
    conn.execute("DELETE FROM outbox WHERE created_at < ?1", [now - OUTBOX_TTL_MS])?;
    Ok(gone)
}

/// Records a received message ID; returns false if it was already seen (duplicate).
pub fn mark_seen(conn: &Connection, contact_id: i64, remote_id: &[u8]) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO seen (contact_id, remote_id, seen_at) VALUES (?1, ?2, ?3)",
        params![contact_id, remote_id, now_ms()],
    )?;
    Ok(n == 1)
}
