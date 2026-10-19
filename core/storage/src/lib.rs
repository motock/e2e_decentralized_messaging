//! SQLCipher-backed encrypted store: initialization and key handling.
//!
//! Scope of this module: opening (and, for a fresh path, creating) a SQLCipher-encrypted
//! SQLite database file and failing closed if the supplied key cannot decrypt an existing
//! file. Key/session/message schemas and backup export/import are separate stories.

pub mod backup;

use std::path::Path;

use rusqlite::Connection;
use zeroize::Zeroize;

/// A raw 256-bit key used to encrypt/decrypt a [`Store`]'s SQLCipher database.
///
/// The caller is responsible for deriving this key with adequate entropy/KDF before
/// constructing it; `StoreKey` itself performs no derivation, it only carries the key
/// material and zeroizes it on drop.
pub struct StoreKey([u8; 32]);

impl StoreKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Renders the key as the `x'<hex>'` literal SQLCipher's `PRAGMA key` expects for a raw
    /// (non-passphrase) key. Every output character is one of `0123456789abcdef'x`, so the
    /// result is safe to splice directly into a `PRAGMA` statement.
    fn as_sqlcipher_literal(&self) -> String {
        let mut literal = String::with_capacity(2 + self.0.len() * 2 + 1);
        literal.push_str("x'");
        for byte in self.0.iter() {
            literal.push_str(&format!("{byte:02x}"));
        }
        literal.push('\'');
        literal
    }
}

// Never print key material — only ever a fixed placeholder, even in debug builds/logs.
impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(REDACTED)")
    }
}

impl Drop for StoreKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Errors opening or initializing a [`Store`].
#[derive(Debug)]
pub enum StoreError {
    /// The supplied key could not decrypt the database at the given path. Also returned for a
    /// file that is corrupted or not a database at all — SQLCipher cannot distinguish the two
    /// cases, and per the fail-closed posture we deny access either way rather than guess.
    InvalidKey,
    /// An underlying SQLite/SQLCipher error unrelated to key verification (e.g. the path's
    /// parent directory does not exist).
    Database(rusqlite::Error),
    /// A typed value was present but could not be interpreted — a truncated row, a body whose
    /// declared length does not match, or a value written bypassing the typed API. Fail-closed:
    /// the caller gets an error rather than partial or default-constructed state.
    Corrupted { reason: &'static str },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::InvalidKey => f.write_str("store key is invalid or the store is corrupted"),
            StoreError::Database(err) => write!(f, "store database error: {err}"),
            StoreError::Corrupted { reason } => write!(f, "stored state is corrupted: {reason}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        StoreError::Database(err)
    }
}

const SCHEMA_VERSION: i64 = 1;

/// A handle to an encrypted-at-rest SQLCipher store.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens the SQLCipher database at `path`, creating it if it does not yet exist.
    ///
    /// Fails closed with [`StoreError::InvalidKey`] if `key` cannot decrypt an existing file at
    /// `path` — `PRAGMA key` itself never errors, so this performs a real read against the
    /// database to force SQLCipher to validate the key before returning a usable `Store`.
    pub fn open(path: &Path, key: &StoreKey) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(&format!("PRAGMA key = \"{}\";", key.as_sqlcipher_literal()))?;

        // Force key verification: PRAGMA key only stages the key, it doesn't validate it.
        // The first real read is what makes SQLCipher attempt to decrypt the database.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StoreError::InvalidKey)?;

        Self::initialize_schema(&conn)?;
        Ok(Self { conn })
    }

    fn initialize_schema(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                version INTEGER NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO schema_meta (id, version) VALUES (0, ?1)
             ON CONFLICT(id) DO NOTHING",
            [SCHEMA_VERSION],
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )?;
        Ok(())
    }

    /// The schema version recorded in the store, for callers/tests to confirm the store was
    /// initialized and that state persists across reopens.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        self.conn
            .query_row("SELECT version FROM schema_meta WHERE id = 0", [], |row| {
                row.get(0)
            })
            .map_err(StoreError::Database)
    }
}

/// A user-facing encrypted store keyed by a raw 32-byte key.
///
/// Wraps [`Store`] (and its zeroizing [`StoreKey`]) so callers that already hold a derived
/// 256-bit key can open the store without constructing a [`StoreKey`] themselves — the raw key
/// is wrapped in a [`StoreKey`] on open and zeroized on drop just the same. The database file
/// (`store.db`) lives inside the supplied directory.
#[derive(Debug)]
pub struct EncryptedStore(Store);

impl EncryptedStore {
    /// Opens (creating if absent) the SQLCipher database at `<dir>/store.db` with `key`.
    ///
    /// Fails closed with [`StoreError::InvalidKey`] if `key` cannot decrypt an existing file —
    /// key verification happens here, at open, not deferred to the first read.
    pub fn open(dir: &Path, key: &[u8; 32]) -> Result<Self, StoreError> {
        let db_path = dir.join("store.db");
        Store::open(&db_path, &StoreKey::new(*key)).map(Self)
    }

    /// Persists the serialized identity keypair under the `identity` key.
    ///
    /// The value is stored in a length-prefixed envelope so loaders can distinguish a genuine
    /// value from a row that was truncated or written bypassing this accessor.
    pub fn put_identity(&self, serialized: &[u8]) -> Result<(), StoreError> {
        self.put_typed(IDENTITY_KEY, serialized)
    }

    /// Loads the serialized identity keypair, or `Ok(None)` if none has been persisted.
    ///
    /// Fails closed with [`StoreError::Corrupted`] if a row exists but is not a valid envelope —
    /// for example a value written by [`Self::put_raw`].
    pub fn get_identity(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_typed(IDENTITY_KEY)
    }

    /// Writes `blob` verbatim to the row named `key`, with no envelope.
    ///
    /// Intended for tests that must inject a corrupt value beneath the typed API; production
    /// callers should use the typed accessors so values are integrity-checked on load.
    pub fn put_raw(&self, key: &str, blob: &[u8]) -> Result<(), StoreError> {
        self.0.conn.execute(
            "INSERT OR REPLACE INTO state (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, blob],
        )?;
        Ok(())
    }

    /// Persists `value` under the caller-namespaced `key`, in the same
    /// length-prefixed envelope as [`Self::put_identity`].
    ///
    /// This is the general-purpose accessor for shell state that is not the
    /// identity keypair (conversation history, safety-number verification
    /// records). Values are integrity-checked on load, so a truncated or
    /// hand-written row fails closed instead of being read as data.
    pub fn put_state(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.put_typed(key, value)
    }

    /// Loads the value persisted under `key`, or `Ok(None)` if none exists.
    ///
    /// Fails closed with [`StoreError::Corrupted`] if a row exists but is not a
    /// valid envelope.
    pub fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_typed(key)
    }

    fn put_typed(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let mut envelope = Vec::with_capacity(4 + value.len());
        envelope.extend_from_slice(&(value.len() as u32).to_be_bytes());
        envelope.extend_from_slice(value);
        self.0.conn.execute(
            "INSERT OR REPLACE INTO state (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, envelope],
        )?;
        Ok(())
    }

    fn get_typed(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let row: Option<Vec<u8>> = self
            .0
            .conn
            .query_row(
                "SELECT value FROM state WHERE key = ?1",
                rusqlite::params![key],
                |row| row.get(0),
            )
            .or_else(|err| match err {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        match row {
            None => Ok(None),
            Some(envelope) => Ok(Some(parse_envelope(&envelope)?)),
        }
    }
}

const IDENTITY_KEY: &str = "identity";

/// Unwraps a length-prefixed envelope (`u32` big-endian length, then exactly that many body
/// bytes) and returns the body. Fails closed with [`StoreError::Corrupted`] on any structural
/// mismatch — a value shorter than the prefix, or a body whose length does not match the
/// declared length.
pub fn parse_envelope(envelope: &[u8]) -> Result<Vec<u8>, StoreError> {
    if envelope.len() < 4 {
        return Err(StoreError::Corrupted {
            reason: "value shorter than length prefix",
        });
    }
    let prefix: [u8; 4] = envelope[..4].try_into().unwrap();
    let len = u32::from_be_bytes(prefix) as usize;
    let body = &envelope[4..];
    if body.len() != len {
        return Err(StoreError::Corrupted {
            reason: "declared length does not match stored body",
        });
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn key(byte: u8) -> StoreKey {
        StoreKey::new([byte; 32])
    }

    #[test]
    fn open_initializes_a_fresh_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");

        let store = Store::open(&path, &key(1)).expect("fresh store should open");

        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn reopening_with_the_correct_key_succeeds_and_state_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");

        {
            let store = Store::open(&path, &key(7)).expect("initial open should succeed");
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        } // store (and its connection) dropped here, simulating app restart

        let reopened = Store::open(&path, &key(7)).expect("reopen with correct key should succeed");
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn reopening_with_the_wrong_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");

        {
            let _store = Store::open(&path, &key(9)).expect("initial open should succeed");
        }

        let result = Store::open(&path, &key(99));

        assert!(matches!(result, Err(StoreError::InvalidKey)));
    }

    #[test]
    fn opening_a_corrupted_non_database_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-store.db");
        fs::write(&path, b"this is not a sqlite database at all").unwrap();

        let result = Store::open(&path, &key(1));

        assert!(matches!(result, Err(StoreError::InvalidKey)));
    }

    #[test]
    fn invalid_key_error_display_never_includes_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let _store = Store::open(&path, &key(42)).unwrap();
        }

        let err = Store::open(&path, &key(43)).unwrap_err();

        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains("42"));
        assert!(!rendered.contains("43"));
    }

    #[test]
    fn store_key_debug_output_is_redacted() {
        let k = key(0xAB);
        assert_eq!(format!("{k:?}"), "StoreKey(REDACTED)");
    }
}
