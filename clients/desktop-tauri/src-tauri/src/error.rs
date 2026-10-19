//! Typed error state the JS/TS UI renders for a failed core operation.

use serde::Serialize;

/// A defined, serializable error the frontend renders as UI state. Constructed only from a core
/// `Result::Err` — never from a panic — per PLAN.md Phase 5's "a core API error surfaces to the
/// UI as a defined error state, not a panic" acceptance criterion.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum ShellError {
    /// A `core_crypto` session/prekey operation failed.
    Session(String),
}

impl From<core_crypto::session::SessionError> for ShellError {
    fn from(err: core_crypto::session::SessionError) -> Self {
        ShellError::Session(err.to_string())
    }
}

/// A defined, serializable error for the conversation and verification commands.
///
/// Kept separate from [`ShellError`] so the identity commands' error contract (a single
/// `Session` kind) is unchanged, while the new commands can report *which* subsystem failed.
/// Every variant carries a generic message: no store path, no safety number, and no message body
/// ever crosses the IPC boundary inside an error.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum CommandError {
    /// A `core_crypto` session/prekey operation failed.
    Session(String),
    /// A conversation-store operation failed (including an oversized message).
    Conversation(String),
    /// A safety-number verification operation failed.
    Verification(String),
    /// The relay could not be reached or rejected the request.
    Relay(String),
}

impl From<ShellError> for CommandError {
    fn from(err: ShellError) -> Self {
        match err {
            ShellError::Session(message) => CommandError::Session(message),
        }
    }
}

impl From<core_crypto::session::SessionError> for CommandError {
    fn from(err: core_crypto::session::SessionError) -> Self {
        CommandError::Session(err.to_string())
    }
}

impl From<crate::conversation::ConversationError> for CommandError {
    fn from(err: crate::conversation::ConversationError) -> Self {
        CommandError::Conversation(err.to_string())
    }
}

impl From<crate::verify::VerificationError> for CommandError {
    fn from(err: crate::verify::VerificationError) -> Self {
        CommandError::Verification(err.to_string())
    }
}

impl From<crate::relay_client::RelayError> for CommandError {
    fn from(err: crate::relay_client::RelayError) -> Self {
        CommandError::Relay(err.to_string())
    }
}
