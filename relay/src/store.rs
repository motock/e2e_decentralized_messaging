use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Errors returned by the blind store-and-forward.
#[derive(Debug, PartialEq)]
pub enum StoreError {
    /// The requested envelope has expired and was purged.
    Expired,
    /// No envelope found for the recipient.
    NotFound,
    /// The on-disk store could not be opened, read, or written.
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

/// Magic prefix written at the head of every persisted store file.
///
/// A file that does not start with these bytes is treated as corrupt: the store
/// fails closed (starts empty) rather than serving garbage.
const STORE_MAGIC: &[u8; 4] = b"RDST";

/// On-disk format version. Bumping it invalidates older files (fail closed).
const STORE_FORMAT_VERSION: u8 = 1;

/// Load a persisted map from `path`, failing closed.
///
/// Returns an empty map when the file does not exist (a fresh path behaves
/// exactly like the in-memory constructor). A file that is unreadable, has the
/// wrong magic/version, or does not parse is treated as corrupt: the store
/// starts EMPTY rather than serving garbage, and never panics.
fn load_map(path: &Path) -> HashMap<String, (Vec<u8>, SystemTime)> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return HashMap::new(),
    };
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return HashMap::new();
    }
    decode_map(&bytes).unwrap_or_default()
}

/// Decode the persisted map format: magic || version || count || entries.
///
/// Entry = key_len(u32 BE) || key || expiry_secs(u64 BE) || expiry_nanos(u32 BE)
///         || value_len(u32 BE) || value. Returns `None` on any truncation or
///         trailing garbage so the caller can fail closed to an empty store.
fn decode_map(bytes: &[u8]) -> Option<HashMap<String, (Vec<u8>, SystemTime)>> {
    if bytes.len() < 5 || &bytes[..4] != STORE_MAGIC || bytes[4] != STORE_FORMAT_VERSION {
        return None;
    }
    let mut rest = &bytes[5..];
    let count = read_u32(&mut rest)? as usize;
    // `count` is file-controlled: a hostile count (up to u32::MAX) must not
    // drive a huge pre-allocation. Reserve nothing and let the map grow as
    // entries are actually decoded; a truncated file fails closed below.
    let mut map = HashMap::new();
    for _ in 0..count {
        let key_len = read_u32(&mut rest)? as usize;
        if rest.len() < key_len {
            return None;
        }
        let key = String::from_utf8(rest[..key_len].to_vec()).ok()?;
        rest = &rest[key_len..];
        let expiry_secs = read_u64(&mut rest)?;
        let expiry_nanos = read_u32(&mut rest)?;
        let expiry = expiry_from_parts(expiry_secs, expiry_nanos)?;
        let value_len = read_u32(&mut rest)? as usize;
        if rest.len() < value_len {
            return None;
        }
        let value = rest[..value_len].to_vec();
        rest = &rest[value_len..];
        map.insert(key, (value, expiry));
    }
    if !rest.is_empty() {
        // Trailing bytes: the file was truncated or hand-mangled — fail closed.
        return None;
    }
    Some(map)
}

fn read_u32(bytes: &mut &[u8]) -> Option<u32> {
    if bytes.len() < 4 {
        return None;
    }
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    *bytes = &bytes[4..];
    Some(value)
}

fn read_u64(bytes: &mut &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    *bytes = &bytes[8..];
    Some(u64::from_be_bytes(buf))
}

/// Build a `SystemTime` from raw persisted seconds/nanos, rejecting values that
/// cannot exist.
///
/// A hostile file can carry any u64/u32 pair. `Duration::new` panics when the
/// nanos exceed one second, and `SystemTime + Duration` panics on overflow, so
/// both are checked here and a malformed expiry fails closed (`None`) instead of
/// panicking at `open()` during listener startup.
fn expiry_from_parts(secs: u64, nanos: u32) -> Option<SystemTime> {
    if nanos >= 1_000_000_000 {
        return None;
    }
    let duration = Duration::new(secs, nanos);
    SystemTime::UNIX_EPOCH.checked_add(duration)
}

/// Encode a map into the persisted format (see [`decode_map`]).
fn encode_map(map: &HashMap<String, (Vec<u8>, SystemTime)>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(STORE_MAGIC);
    out.push(STORE_FORMAT_VERSION);
    out.extend_from_slice(&(map.len() as u32).to_be_bytes());
    // Deterministic order: sort by key so the file is reproducible.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let (value, expiry) = &map[key];
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        let since_epoch = expiry
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        out.extend_from_slice(&since_epoch.as_secs().to_be_bytes());
        out.extend_from_slice(&(since_epoch.subsec_nanos() as u32).to_be_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Atomically replace the file at `path` with `bytes`.
///
/// Writes to a sibling temp file and renames over the target so a crash mid-write
/// can never leave a half-written store behind.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
    }
    let tmp = temp_sibling(path);
    std::fs::write(&tmp, bytes).map_err(|e| StoreError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| StoreError::Io(e.to_string()))
}

/// A unique temp-file path next to `path` (same directory, `.tmp-<pid>` suffix).
fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "relay-store".to_string());
    path.with_file_name(format!(
        ".{file_name}.tmp-{}",
        std::process::id()
    ))
}

/// A blind store that holds ciphertext envelopes with TTL, optionally persisted
/// to disk.
///
/// Created with [`RelayStore::new`] (in memory, the historical behaviour) or
/// [`RelayStore::open`] (backed by a file, so entries survive a restart).
///
/// Handles can be shared: [`RelayStore::clone_handle`] returns a new handle onto
/// the SAME underlying map (and the same backing file), so multiple listeners in
/// one process observe one durable store.
pub struct RelayStore {
    inner: Arc<Mutex<HashMap<String, (Vec<u8>, SystemTime)>>>,
    /// When set, every mutation is flushed to this path so a later
    /// `RelayStore::open` on the same path sees the same state.
    path: Option<Arc<PathBuf>>,
}

impl Default for RelayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            path: None,
        }
    }

    /// Open (or create) a persisted store at `path`.
    ///
    /// A fresh path starts empty and behaves exactly like [`RelayStore::new`].
    /// A corrupt or truncated file fails closed: the store starts empty rather
    /// than serving garbage, and never panics.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let map = load_map(path);
        Ok(Self {
            inner: Arc::new(Mutex::new(map)),
            path: Some(Arc::new(path.to_path_buf())),
        })
    }

    /// Return a second handle onto the same underlying map and backing file.
    ///
    /// Mutations through either handle are visible through the other, and both
    /// persist to the same path.
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            path: self.path.clone(),
        }
    }

    /// Store an envelope for the given recipient with a TTL.
    pub fn store(
        &self,
        recipient_id: &str,
        envelope: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let expiry = SystemTime::now() + ttl;
        let mut map = self.inner.lock().unwrap();
        map.insert(recipient_id.to_string(), (envelope, expiry));
        self.persist(&map)?;
        Ok(())
    }

    /// Pick up the envelope for a recipient if it exists and is not expired.
    pub fn pickup(&self, recipient_id: &str) -> Result<Vec<u8>, StoreError> {
        let mut map = self.inner.lock().unwrap();
        match map.get(recipient_id) {
            None => Err(StoreError::NotFound),
            Some((_, expiry)) if *expiry <= SystemTime::now() => {
                // expired, remove
                map.remove(recipient_id);
                self.persist(&map)?;
                Err(StoreError::Expired)
            }
            Some((envelope, _)) => {
                let data = envelope.clone();
                map.remove(recipient_id);
                self.persist(&map)?;
                Ok(data)
            }
        }
    }

    /// Purge the stored envelope for a recipient regardless of TTL.
    pub fn purge(&self, recipient_id: &str) -> Result<(), StoreError> {
        let mut map = self.inner.lock().unwrap();
        map.remove(recipient_id);
        self.persist(&map)?;
        Ok(())
    }

    /// Return the number of stored envelopes (including expired ones that haven't been cleaned yet).
    pub fn count(&self) -> usize {
        let map = self.inner.lock().unwrap();
        map.len()
    }

    /// Flush the current map to disk when this store is persisted.
    fn persist(&self, map: &HashMap<String, (Vec<u8>, SystemTime)>) -> Result<(), StoreError> {
        match &self.path {
            None => Ok(()),
            Some(path) => atomic_write(path, &encode_map(map)),
        }
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
}

/// Opaque envelope with its expiry instant, queued FIFO per recipient.
type Queue = VecDeque<(Vec<u8>, SystemTime)>;

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
    queues: Arc<Mutex<HashMap<String, Queue>>>,
    /// When set, every mutation is flushed to this path so a later
    /// `Mailbox::open` on the same path sees the same queues.
    path: Option<Arc<PathBuf>>,
}

impl Mailbox {
    /// Creates a mailbox retaining at most `max_depth` live envelopes per recipient.
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            queues: Arc::new(Mutex::new(HashMap::new())),
            path: None,
        }
    }

    /// Open (or create) a persisted mailbox at `path`.
    ///
    /// A fresh path starts empty and behaves exactly like [`Mailbox::new`]. A
    /// corrupt or truncated file fails closed: the mailbox starts empty rather
    /// than serving garbage, and never panics.
    pub fn open(path: &Path, max_depth: usize) -> Result<Self, StoreError> {
        let queues = load_queues(path);
        Ok(Self {
            max_depth,
            queues: Arc::new(Mutex::new(queues)),
            path: Some(Arc::new(path.to_path_buf())),
        })
    }

    /// Return a second handle onto the same underlying queues and backing file.
    ///
    /// Mutations through either handle are visible through the other, and both
    /// persist to the same path.
    pub fn clone_handle(&self) -> Self {
        Self {
            max_depth: self.max_depth,
            queues: Arc::clone(&self.queues),
            path: self.path.clone(),
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
        let mut queues = self.queues.lock().unwrap();
        let queue = queues.entry(recipient_id.to_string()).or_default();
        queue.retain(|(_, expiry)| *expiry > now);
        if queue.len() >= self.max_depth {
            if queue.is_empty() {
                queues.remove(recipient_id);
            }
            return Err(MailboxError::QueueFull);
        }
        queue.push_back((envelope, now + ttl));
        self.persist(&queues);
        Ok(())
    }

    /// Removes and returns the oldest live envelope for `recipient_id`.
    ///
    /// Expired envelopes at the front are discarded. Returns
    /// [`MailboxError::NotFound`] when the recipient has no queue, and
    /// [`MailboxError::Expired`] when the queue held only expired envelopes.
    pub fn dequeue(&self, recipient_id: &str) -> Result<Vec<u8>, MailboxError> {
        let now = SystemTime::now();
        let mut queues = self.queues.lock().unwrap();
        let mut discarded_expired = false;
        let mut found: Option<Vec<u8>> = None;
        let empty_after = if let Some(queue) = queues.get_mut(recipient_id) {
            while let Some((envelope, expiry)) = queue.pop_front() {
                if expiry > now {
                    found = Some(envelope);
                    break;
                }
                discarded_expired = true;
            }
            queue.is_empty()
        } else {
            return Err(MailboxError::NotFound);
        };
        if empty_after {
            queues.remove(recipient_id);
        }
        self.persist(&queues);
        match found {
            Some(envelope) => Ok(envelope),
            None if discarded_expired => Err(MailboxError::Expired),
            None => Err(MailboxError::NotFound),
        }
    }

    /// Flush the current queues to disk when this mailbox is persisted.
    fn persist(&self, queues: &HashMap<String, Queue>) {
        if let Some(path) = &self.path {
            // Persisting is best-effort for the FIFO: a write failure must not
            // change the in-memory answer the caller already got.
            let _ = atomic_write(path, &encode_queues(queues));
        }
    }
}

/// Load persisted queues from `path`, failing closed to empty on any problem.
fn load_queues(path: &Path) -> HashMap<String, Queue> {
    match std::fs::read(path) {
        Ok(bytes) => decode_queues(&bytes).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Decode the persisted queue format (same framing as [`decode_map`], but each
/// key holds a FIFO list of `(value, expiry)` pairs).
fn decode_queues(bytes: &[u8]) -> Option<HashMap<String, Queue>> {
    if bytes.len() < 5 || &bytes[..4] != STORE_MAGIC || bytes[4] != STORE_FORMAT_VERSION {
        return None;
    }
    let mut rest = &bytes[5..];
    let count = read_u32(&mut rest)? as usize;
    // File-controlled count: never pre-allocate from it (see `decode_map`).
    let mut queues: HashMap<String, Queue> = HashMap::new();
    for _ in 0..count {
        let key_len = read_u32(&mut rest)? as usize;
        if rest.len() < key_len {
            return None;
        }
        let key = String::from_utf8(rest[..key_len].to_vec()).ok()?;
        rest = &rest[key_len..];
        let depth = read_u32(&mut rest)? as usize;
        // File-controlled depth: never pre-allocate from it (see `decode_map`).
        let mut queue = Queue::new();
        for _ in 0..depth {
            let value_len = read_u32(&mut rest)? as usize;
            if rest.len() < value_len {
                return None;
            }
            let value = rest[..value_len].to_vec();
            rest = &rest[value_len..];
            let expiry_secs = read_u64(&mut rest)?;
            let expiry_nanos = read_u32(&mut rest)?;
            let expiry = expiry_from_parts(expiry_secs, expiry_nanos)?;
            queue.push_back((value, expiry));
        }
        queues.insert(key, queue);
    }
    if !rest.is_empty() {
        return None;
    }
    Some(queues)
}

/// Encode queues into the persisted format (see [`decode_queues`]).
fn encode_queues(queues: &HashMap<String, Queue>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(STORE_MAGIC);
    out.push(STORE_FORMAT_VERSION);
    out.extend_from_slice(&(queues.len() as u32).to_be_bytes());
    let mut keys: Vec<&String> = queues.keys().collect();
    keys.sort();
    for key in keys {
        let queue = &queues[key];
        out.extend_from_slice(&(key.len() as u32).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(queue.len() as u32).to_be_bytes());
        for (value, expiry) in queue {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
            let since_epoch = expiry
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO);
            out.extend_from_slice(&since_epoch.as_secs().to_be_bytes());
            out.extend_from_slice(&(since_epoch.subsec_nanos() as u32).to_be_bytes());
        }
    }
    out
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT)
    }
}
