use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::warn;

/// Errors returned by the blind store-and-forward.
#[derive(Debug, PartialEq)]
pub enum StoreError {
    /// The requested envelope has expired and was purged.
    Expired,
    /// No envelope found for the recipient.
    NotFound,
    /// The store could not be opened, read, or written.
    Io(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Expired => write!(f, "expired"),
            StoreError::NotFound => write!(f, "not found"),
            StoreError::Io(msg) => write!(f, "store io error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io_err(e: rusqlite::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

/// Open a SQLite store at `path`, or an anonymous in-memory one when `None`.
///
/// Durability comes from SQLite: `journal_mode=WAL` plus `synchronous=FULL` means a
/// committed transaction survives a killed process or power loss. The previous
/// hand-rolled framing could not offer that without an fsync of both the file and its
/// parent directory, because a rename does not order against the write it publishes.
///
/// The schema is created here, so opening a file that is not a SQLite database fails
/// now — at startup — rather than on the first request. Callers get `Err` and can
/// refuse to start instead of serving garbage.
fn open_db(path: Option<&Path>) -> Result<Connection, StoreError> {
    let conn = match path {
        Some(path) => Connection::open(path),
        None => Connection::open_in_memory(),
    }
    .map_err(io_err)?;
    // `journal_mode` reports the mode it settled on, so it must be read rather than
    // executed. On an in-memory database this returns "memory" and changes nothing.
    let _mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(io_err)?;
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .map_err(io_err)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS prekeys (
             recipient_id TEXT PRIMARY KEY,
             value        BLOB NOT NULL,
             expiry_secs  INTEGER NOT NULL,
             expiry_nanos INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS envelopes (
             seq          INTEGER PRIMARY KEY AUTOINCREMENT,
             recipient_id TEXT NOT NULL,
             value        BLOB NOT NULL,
             expiry_secs  INTEGER NOT NULL,
             expiry_nanos INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS envelopes_fifo ON envelopes (recipient_id, seq);",
    )
    .map_err(io_err)?;
    Ok(conn)
}

/// Decompose an expiry instant into the integer pair stored on disk.
fn expiry_parts(at: SystemTime) -> (i64, i64) {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => (since.as_secs() as i64, since.subsec_nanos() as i64),
        // Before the epoch: already expired, so any past value is equivalent.
        Err(_) => (0, 0),
    }
}

/// Rebuild a `SystemTime` from the persisted integer pair.
///
/// Returns `None` for values that cannot exist: negative or >= 1s nanoseconds, or a
/// second count outside `SystemTime`'s range. `Duration::new` panics on the first and
/// `checked_add` fails on the second, so both are rejected here — a store whose bytes
/// were edited by hand fails closed instead of panicking during listener startup.
fn expiry_from_parts(secs: i64, nanos: i64) -> Option<SystemTime> {
    if !(0..1_000_000_000).contains(&nanos) || secs < 0 {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos as u32))
}

/// A blind store that holds ciphertext envelopes with TTL, optionally persisted
/// to disk.
///
/// Created with [`RelayStore::new`] (in memory, the historical behaviour) or
/// [`RelayStore::open`] (backed by a file, so entries survive a restart).
///
/// Handles can be shared: [`RelayStore::clone_handle`] returns a new handle onto
/// the SAME underlying database, so multiple listeners in one process observe one
/// durable store.
pub struct RelayStore {
    conn: Arc<Mutex<Connection>>,
}

impl Default for RelayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            conn: Arc::new(Mutex::new(open_db(None).expect("in-memory sqlite store"))),
        }
    }

    /// Open (or create) a persisted store at `path`.
    ///
    /// A fresh path starts empty and behaves exactly like [`RelayStore::new`].
    /// A file that is not a SQLite database fails closed with [`StoreError::Io`]
    /// rather than serving garbage, and never panics.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            conn: Arc::new(Mutex::new(open_db(Some(path))?)),
        })
    }

    /// Return a second handle onto the same underlying database.
    ///
    /// Mutations through either handle are visible through the other, and both
    /// persist to the same path.
    pub fn clone_handle(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
        }
    }

    /// Store an envelope for the given recipient with a TTL.
    pub fn store(
        &self,
        recipient_id: &str,
        envelope: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let (secs, nanos) = expiry_parts(SystemTime::now() + ttl);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO prekeys (recipient_id, value, expiry_secs, expiry_nanos)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(recipient_id) DO UPDATE SET
                 value        = excluded.value,
                 expiry_secs  = excluded.expiry_secs,
                 expiry_nanos = excluded.expiry_nanos",
            params![recipient_id, envelope, secs, nanos],
        )
        .map_err(io_err)?;
        Ok(())
    }

    /// Pick up the envelope for a recipient if it exists and is not expired.
    pub fn pickup(&self, recipient_id: &str) -> Result<Vec<u8>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(Vec<u8>, i64, i64)> = conn
            .query_row(
                "SELECT value, expiry_secs, expiry_nanos FROM prekeys WHERE recipient_id = ?1",
                params![recipient_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(io_err)?;
        let Some((value, secs, nanos)) = row else {
            return Err(StoreError::NotFound);
        };
        conn.execute(
            "DELETE FROM prekeys WHERE recipient_id = ?1",
            params![recipient_id],
        )
        .map_err(io_err)?;
        match expiry_from_parts(secs, nanos) {
            // An unrepresentable expiry is treated as expired: never served.
            Some(expiry) if expiry > SystemTime::now() => Ok(value),
            _ => Err(StoreError::Expired),
        }
    }

    /// Purge the stored envelope for a recipient regardless of TTL.
    pub fn purge(&self, recipient_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM prekeys WHERE recipient_id = ?1",
            params![recipient_id],
        )
        .map_err(io_err)?;
        Ok(())
    }

    /// Return the number of stored envelopes (including expired ones that haven't been cleaned yet).
    pub fn count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM prekeys", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|n| n.max(0) as usize)
        .unwrap_or_else(|e| {
            // Unreachable for a store that opened cleanly (the schema is created at
            // open), so this is a real fault worth surfacing rather than hiding.
            warn!("store: count failed: {e}");
            0
        })
    }

    /// Introspect whether a public method is exposed.
    pub fn has_method(name: &str) -> bool {
        matches!(name, "store" | "pickup" | "purge" | "count" | "open")
    }
}

/// Maximum number of live envelopes retained per recipient by [`Mailbox`].
pub const DEFAULT_MAX_ENVELOPES_PER_RECIPIENT: usize = 64;

/// Errors returned by [`Mailbox`] operations.
#[derive(Debug, PartialEq)]
pub enum MailboxError {
    /// The recipient has no queue.
    NotFound,
    /// The recipient's queue held only expired envelopes, which were discarded.
    Expired,
    /// The recipient's live queue is already at `max_depth`.
    QueueFull,
    /// The queue could not be read or written.
    Io(String),
}

/// Per-recipient FIFO queue of opaque envelopes.
///
/// [`RelayStore`] holds exactly one value per key, which is the required
/// semantics for prekey bundles (last write wins). Envelopes require the
/// opposite semantics: every envelope accepted for an offline recipient is
/// retained in arrival order until it is dequeued or expires. `Mailbox`
/// provides that queue, bounded to `max_depth` live envelopes per recipient.
///
/// Created with [`Mailbox::new`] (in memory, the historical behaviour) or
/// [`Mailbox::open`] (backed by a file, so undelivered envelopes survive a
/// restart).
pub struct Mailbox {
    max_depth: usize,
    conn: Arc<Mutex<Connection>>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT)
    }
}

impl Mailbox {
    /// Creates a mailbox retaining at most `max_depth` live envelopes per recipient.
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            conn: Arc::new(Mutex::new(open_db(None).expect("in-memory sqlite mailbox"))),
        }
    }

    /// Open (or create) a persisted mailbox at `path`.
    ///
    /// A fresh path starts empty and behaves exactly like [`Mailbox::new`]. A
    /// file that is not a SQLite database fails closed with [`StoreError::Io`]
    /// rather than serving garbage, and never panics.
    pub fn open(path: &Path, max_depth: usize) -> Result<Self, StoreError> {
        Ok(Self {
            max_depth,
            conn: Arc::new(Mutex::new(open_db(Some(path))?)),
        })
    }

    /// Return a second handle onto the same underlying database.
    ///
    /// Mutations through either handle are visible through the other, and both
    /// persist to the same path.
    pub fn clone_handle(&self) -> Self {
        Self {
            max_depth: self.max_depth,
            conn: Arc::clone(&self.conn),
        }
    }

    /// Appends `envelope` to `recipient_id`'s queue, expiring after `ttl`.
    ///
    /// Expired entries are discarded first. If `max_depth` live entries remain,
    /// returns [`MailboxError::QueueFull`] and leaves the live queue unchanged.
    pub fn enqueue(
        &self,
        recipient_id: &str,
        envelope: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), MailboxError> {
        let now = SystemTime::now();
        let (secs, nanos) = expiry_parts(now + ttl);
        // One connection behind one mutex: the read-modify-write below is serialized
        // across every handle, so concurrent senders cannot both pass the depth check.
        let conn = self.conn.lock().unwrap();
        let expired = expired_seqs(&conn, recipient_id, now).map_err(mailbox_io_err)?;
        delete_seqs(&conn, &expired).map_err(mailbox_io_err)?;
        let live = count_live(&conn, recipient_id, now).map_err(mailbox_io_err)?;
        if live >= self.max_depth {
            return Err(MailboxError::QueueFull);
        }
        conn.execute(
            "INSERT INTO envelopes (recipient_id, value, expiry_secs, expiry_nanos)
             VALUES (?1, ?2, ?3, ?4)",
            params![recipient_id, envelope, secs, nanos],
        )
        .map_err(|e| MailboxError::Io(e.to_string()))?;
        Ok(())
    }

    /// Removes and returns the oldest live envelope for `recipient_id`.
    ///
    /// Expired envelopes at the front are discarded. Returns
    /// [`MailboxError::NotFound`] when the recipient has no queue, and
    /// [`MailboxError::Expired`] when the queue held only expired envelopes.
    pub fn dequeue(&self, recipient_id: &str) -> Result<Vec<u8>, MailboxError> {
        let now = SystemTime::now();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT seq, value, expiry_secs, expiry_nanos FROM envelopes
                 WHERE recipient_id = ?1 ORDER BY seq",
            )
            .map_err(|e| MailboxError::Io(e.to_string()))?;
        let rows = stmt
            .query_map(params![recipient_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| MailboxError::Io(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MailboxError::Io(e.to_string()))?;
        drop(stmt);

        let mut discarded_expired = false;
        for (seq, value, secs, nanos) in rows {
            // An unrepresentable expiry is discarded rather than delivered.
            let live = matches!(
                expiry_from_parts(secs, nanos),
                Some(expiry) if expiry > now
            );
            delete_seqs(&conn, &[seq]).map_err(mailbox_io_err)?;
            if live {
                return Ok(value);
            }
            discarded_expired = true;
        }
        if discarded_expired {
            Err(MailboxError::Expired)
        } else {
            Err(MailboxError::NotFound)
        }
    }
}

/// Map a SQLite failure from a queue statement onto the mailbox's error type.
fn mailbox_io_err(e: rusqlite::Error) -> MailboxError {
    MailboxError::Io(e.to_string())
}

/// Sequences of `recipient_id`'s already-expired envelopes, oldest first.
fn expired_seqs(
    conn: &Connection,
    recipient_id: &str,
    now: SystemTime,
) -> Result<Vec<i64>, rusqlite::Error> {
    let mut stmt = conn
        .prepare("SELECT seq, expiry_secs, expiry_nanos FROM envelopes WHERE recipient_id = ?1")?;
    let rows = stmt
        .query_map(params![recipient_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter(|(_, secs, nanos)| {
            !matches!(expiry_from_parts(*secs, *nanos), Some(expiry) if expiry > now)
        })
        .map(|(seq, _, _)| seq)
        .collect())
}

/// Number of `recipient_id`'s envelopes that have not expired.
fn count_live(
    conn: &Connection,
    recipient_id: &str,
    now: SystemTime,
) -> Result<usize, rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT expiry_secs, expiry_nanos FROM envelopes WHERE recipient_id = ?1")?;
    let rows = stmt
        .query_map(params![recipient_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter(|(secs, nanos)| {
            matches!(expiry_from_parts(*secs, *nanos), Some(expiry) if expiry > now)
        })
        .count())
}

/// Delete envelopes by sequence number. An empty slice is a no-op.
fn delete_seqs(conn: &Connection, seqs: &[i64]) -> Result<(), rusqlite::Error> {
    for seq in seqs {
        conn.execute("DELETE FROM envelopes WHERE seq = ?1", params![seq])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drop the table out from under an open store so every statement against it
    /// fails. There is no cheaper way to make SQLite refuse a write through the
    /// public API, and the datastore is the boundary where fault injection belongs.
    fn break_table(conn: &Arc<Mutex<Connection>>, table: &str) {
        conn.lock()
            .unwrap()
            .execute_batch(&format!("DROP TABLE {table}"))
            .unwrap();
    }

    /// A failing store must REPORT the failure. The previous implementation
    /// persisted with `let _ = atomic_write(...)`, so a sender was told `ok` for an
    /// envelope that was never written and was gone on the next restart.
    #[test]
    fn mailbox_write_failure_is_reported_not_swallowed() {
        let mb = Mailbox::new(4);
        break_table(&mb.conn, "envelopes");
        let result = mb.enqueue("recipient-id", vec![0xAA], Duration::from_secs(60));
        assert!(
            matches!(result, Err(MailboxError::Io(_))),
            "an unwritable store must surface the failure, got: {result:?}"
        );
    }

    #[test]
    fn mailbox_read_failure_is_reported_not_swallowed() {
        let mb = Mailbox::new(4);
        break_table(&mb.conn, "envelopes");
        let result = mb.dequeue("recipient-id");
        assert!(
            matches!(result, Err(MailboxError::Io(_))),
            "an unreadable store must surface the failure, got: {result:?}"
        );
    }

    #[test]
    fn relay_store_write_failure_is_reported_not_swallowed() {
        let store = RelayStore::new();
        break_table(&store.conn, "prekeys");
        let result = store.store("recipient-id", vec![0xAA], Duration::from_secs(60));
        assert!(
            matches!(result, Err(StoreError::Io(_))),
            "an unwritable store must surface the failure, got: {result:?}"
        );
    }
}
