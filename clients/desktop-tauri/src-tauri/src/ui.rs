//! Conversation UI rendering — sent/received message history for the desktop shell.
//!
//! This is a thin presentation layer: it renders `ConversationState` (built from
//! locally decrypted message history) into a string the Tauri frontend displays.
//! No cryptography or storage logic lives here — that's owned by `core_crypto` /
//! `core_storage`.
//!
//! # Failure visibility
//!
//! A message that could not be decrypted is represented explicitly
//! ([`Message::decrypt_failure`]) and renders a visible marker. It is never
//! dropped from the history, because a silently missing message looks exactly
//! like a message that was never sent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Which side of the conversation a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

/// A single conversation message, already decrypted to plaintext bytes.
#[derive(Debug, Clone)]
pub struct Message {
    pub direction: Direction,
    pub body: Vec<u8>,
    pub unix_ts: i64,
    /// True when the envelope arrived but could not be decrypted. The body is
    /// empty in that case; the renderer shows a visible failure marker instead
    /// of an empty line.
    pub decrypt_failed: bool,
}

impl Message {
    /// A message this client sent.
    pub fn sent(body: Vec<u8>, unix_ts: i64) -> Self {
        Self {
            direction: Direction::Sent,
            body,
            unix_ts,
            decrypt_failed: false,
        }
    }

    /// A message received from the peer and successfully decrypted.
    pub fn received(body: Vec<u8>, unix_ts: i64) -> Self {
        Self {
            direction: Direction::Received,
            body,
            unix_ts,
            decrypt_failed: false,
        }
    }

    /// A received envelope that failed to decrypt.
    ///
    /// Rendered as a visible failure rather than an empty or absent message, so
    /// the user can tell "could not read this" apart from "nothing arrived".
    pub fn decrypt_failure(unix_ts: i64) -> Self {
        Self {
            direction: Direction::Received,
            body: Vec::new(),
            unix_ts,
            decrypt_failed: true,
        }
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn human_timestamp(&self) -> String {
        DateTime::<Utc>::from_timestamp(self.unix_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("invalid timestamp ({})", self.unix_ts))
    }
}

/// The full state of a conversation as displayed by the UI.
pub struct ConversationState {
    pub messages: Vec<Message>,
}

/// Render a conversation into the string the Tauri frontend displays.
///
/// Renders an explicit empty-state marker rather than an empty or panicking
/// output when there is no history yet, and a visible marker for any message
/// that failed to decrypt.
pub fn render_conversation(state: &ConversationState) -> String {
    if state.messages.is_empty() {
        return "no messages yet".to_string();
    }

    state
        .messages
        .iter()
        .map(|message| {
            let sender = match message.direction {
                Direction::Sent => "You",
                Direction::Received => "Them",
            };
            let body = if message.decrypt_failed {
                "<message could not be decrypted>".to_string()
            } else {
                message.body_text()
            };
            format!("[{}] {}: {}", message.human_timestamp(), sender, body)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
