use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Errors returned by the blind store-and-forward.
#[derive(Debug, PartialEq)]
pub enum StoreError {
    /// The requested envelope has expired and was purged.
    Expired,
    /// No envelope found for the recipient.
    NotFound,
}

/// A blind in-memory store that holds ciphertext envelopes with TTL.
pub struct RelayStore {
    inner: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
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
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Store an envelope for the given recipient with a TTL.
    pub fn store(
        &self,
        recipient_id: &str,
        envelope: Vec<u8>,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        let expiry = Instant::now() + ttl;
        let mut map = self.inner.lock().unwrap();
        map.insert(recipient_id.to_string(), (envelope, expiry));
        Ok(())
    }

    /// Pick up the envelope for a recipient if it exists and is not expired.
    pub fn pickup(&self, recipient_id: &str) -> Result<Vec<u8>, StoreError> {
        let mut map = self.inner.lock().unwrap();
        match map.get(recipient_id) {
            None => Err(StoreError::NotFound),
            Some((_, expiry)) if Instant::now() > *expiry => {
                // expired, remove
                map.remove(recipient_id);
                Err(StoreError::Expired)
            }
            Some((envelope, _)) => {
                let data = envelope.clone();
                map.remove(recipient_id);
                Ok(data)
            }
        }
    }

    /// Purge the stored envelope for a recipient regardless of TTL.
    pub fn purge(&self, recipient_id: &str) -> Result<(), StoreError> {
        let mut map = self.inner.lock().unwrap();
        map.remove(recipient_id);
        Ok(())
    }

    /// Return the number of stored envelopes (including expired ones that haven't been cleaned yet).
    pub fn count(&self) -> usize {
        let map = self.inner.lock().unwrap();
        map.len()
    }

    /// Introspect whether a public method is exposed.
    pub fn has_method(name: &str) -> bool {
        matches!(name, "store" | "pickup" | "purge" | "count")
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
type Queue = VecDeque<(Vec<u8>, Instant)>;

/// Per-recipient FIFO queue of opaque envelopes.
///
/// [`RelayStore`] holds exactly one value per key, which is the required
/// semantics for prekey bundles (last write wins). Envelopes require the
/// opposite semantics: every envelope accepted for an offline recipient is
/// retained in arrival order until it is dequeued or expires. `Mailbox`
/// provides that queue, bounded to `max_depth` live envelopes per recipient.
pub struct Mailbox {
    max_depth: usize,
    queues: Mutex<HashMap<String, Queue>>,
}

impl Mailbox {
    /// Creates a mailbox retaining at most `max_depth` live envelopes per recipient.
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            queues: Mutex::new(HashMap::new()),
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
        let now = Instant::now();
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
        Ok(())
    }

    /// Removes and returns the oldest live envelope for `recipient_id`.
    ///
    /// Expired envelopes at the front are discarded. Returns
    /// [`MailboxError::NotFound`] when the recipient has no queue, and
    /// [`MailboxError::Expired`] when the queue held only expired envelopes.
    pub fn dequeue(&self, recipient_id: &str) -> Result<Vec<u8>, MailboxError> {
        let now = Instant::now();
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
        match found {
            Some(envelope) => Ok(envelope),
            None if discarded_expired => Err(MailboxError::Expired),
            None => Err(MailboxError::NotFound),
        }
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT)
    }
}
