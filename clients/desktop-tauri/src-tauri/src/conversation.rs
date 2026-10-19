//! Conversation history persisted in the encrypted store and rendered by [`crate::ui`].
//!
//! The store is the same [`core_storage::EncryptedStore`] the identity lives in,
//! so history survives dropping and reopening the handle (an app restart) and is
//! scoped per peer.
//!
//! # Size limit
//!
//! The shared core imposes no plaintext size limit of its own, so the shell
//! defines one here ([`MAX_MESSAGE_BYTES`]) and *rejects* anything larger with
//! [`ConversationError::TooLarge`]. Nothing is stored and nothing is truncated:
//! a silently shortened message is a message the user did not send.

use crate::ui::{ConversationState, Direction, Message};
use core_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Largest message body the shell accepts, in bytes (64 KiB).
///
/// A body of exactly this length is accepted whole; one byte more is rejected.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Prefix for the per-peer conversation record inside the encrypted store.
const HISTORY_KEY_PREFIX: &str = "conversation:";

/// Errors surfaced by [`ConversationStore`].
///
/// Messages are deliberately generic: they never carry the store path or a
/// message body, so they are safe to return over the IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationError {
    /// The body exceeded [`MAX_MESSAGE_BYTES`]; nothing was stored.
    TooLarge { len: usize, max: usize },
    /// The body was empty.
    EmptyBody,
    /// The peer identifier was empty.
    InvalidPeer,
    /// The encrypted store could not be opened or accessed.
    Store(String),
}

impl fmt::Display for ConversationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversationError::TooLarge { len, max } => {
                write!(f, "message is {len} bytes, over the {max}-byte limit")
            }
            ConversationError::EmptyBody => write!(f, "message body must not be empty"),
            ConversationError::InvalidPeer => write!(f, "peer identifier must not be empty"),
            ConversationError::Store(message) => {
                write!(f, "conversation store unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for ConversationError {}

/// One persisted history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    direction: Direction,
    body: Vec<u8>,
    unix_ts: i64,
    decrypt_failed: bool,
}

impl StoredMessage {
    fn into_message(self) -> Message {
        Message {
            direction: self.direction,
            body: self.body,
            unix_ts: self.unix_ts,
            decrypt_failed: self.decrypt_failed,
        }
    }
}

/// Per-peer conversation history backed by the encrypted store.
pub struct ConversationStore {
    store: EncryptedStore,
}

impl ConversationStore {
    /// Open (creating if absent) the encrypted store inside `dir` with `key`.
    pub fn open(dir: &Path, key: &[u8; 32]) -> Result<Self, ConversationError> {
        let store = EncryptedStore::open(dir, key)
            .map_err(|err| ConversationError::Store(err.to_string()))?;
        Ok(Self { store })
    }

    /// Append a message this client sent.
    pub fn record_sent(
        &self,
        peer: &str,
        body: &[u8],
        unix_ts: i64,
    ) -> Result<(), ConversationError> {
        self.append(
            peer,
            StoredMessage {
                direction: Direction::Sent,
                body: body.to_vec(),
                unix_ts,
                decrypt_failed: false,
            },
        )
    }

    /// Append a message received from `peer` and successfully decrypted.
    pub fn record_received(
        &self,
        peer: &str,
        body: &[u8],
        unix_ts: i64,
    ) -> Result<(), ConversationError> {
        self.append(
            peer,
            StoredMessage {
                direction: Direction::Received,
                body: body.to_vec(),
                unix_ts,
                decrypt_failed: false,
            },
        )
    }

    /// Append a visible failure entry for an envelope that could not be decrypted.
    ///
    /// The entry carries no body — there is no plaintext to show — but it is
    /// kept in the history so the UI can render "could not decrypt" instead of
    /// silently showing nothing.
    pub fn record_decrypt_failure(
        &self,
        peer: &str,
        unix_ts: i64,
    ) -> Result<(), ConversationError> {
        self.append(
            peer,
            StoredMessage {
                direction: Direction::Received,
                body: Vec::new(),
                unix_ts,
                decrypt_failed: true,
            },
        )
    }

    /// The peer's history, oldest first.
    pub fn state(&self, peer: &str) -> Result<ConversationState, ConversationError> {
        validate_peer(peer)?;

        let mut stored = self.load(peer)?;
        // Stable sort: equal timestamps keep their append order.
        stored.sort_by_key(|message| message.unix_ts);

        Ok(ConversationState {
            messages: stored
                .into_iter()
                .map(StoredMessage::into_message)
                .collect(),
        })
    }

    fn append(&self, peer: &str, message: StoredMessage) -> Result<(), ConversationError> {
        validate_peer(peer)?;
        if message.body.len() > MAX_MESSAGE_BYTES {
            return Err(ConversationError::TooLarge {
                len: message.body.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        if !message.decrypt_failed && message.body.is_empty() {
            return Err(ConversationError::EmptyBody);
        }

        let mut history = self.load(peer)?;
        history.push(message);
        self.save(peer, &history)
    }

    fn load(&self, peer: &str) -> Result<Vec<StoredMessage>, ConversationError> {
        let Some(blob) = self
            .store
            .get_state(&history_key(peer))
            .map_err(|err| ConversationError::Store(err.to_string()))?
        else {
            return Ok(Vec::new());
        };
        let history = serde_json::from_slice(&blob)
            .map_err(|err| ConversationError::Store(format!("corrupted history: {err}")))?;
        Ok(history)
    }

    fn save(&self, peer: &str, history: &[StoredMessage]) -> Result<(), ConversationError> {
        let blob = serde_json::to_vec(history)
            .map_err(|err| ConversationError::Store(format!("cannot encode history: {err}")))?;
        self.store
            .put_state(&history_key(peer), &blob)
            .map_err(|err| ConversationError::Store(err.to_string()))
    }
}

fn history_key(peer: &str) -> String {
    format!("{HISTORY_KEY_PREFIX}{peer}")
}

fn validate_peer(peer: &str) -> Result<(), ConversationError> {
    if peer.trim().is_empty() {
        return Err(ConversationError::InvalidPeer);
    }
    Ok(())
}
