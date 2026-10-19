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
