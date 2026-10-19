//! Safety-number verification state, persisted in the encrypted store.
//!
//! The tests in `tests/safety_number_ui.rs` exercise a small state machine that
//! tracks whether a user has verified a safety number and warns when the
//! underlying identity key changes. `Unverified` and `Verified` are unit
//! variants (the tests compare against bare `VerificationState::Verified`), so
//! the safety number a state was created with is tracked in the persisted
//! record rather than as enum payload.
//!
//! # Why the state lives in the store
//!
//! An earlier revision kept the expected safety number in a `thread_local`
//! side channel. That made verification a per-process, per-thread fact: it
//! could not survive a restart, and two peers' expected numbers shared one
//! slot. The record below is written through [`core_storage::EncryptedStore`],
//! so a verified safety number survives an app restart and is scoped per peer.
//!
//! # Write discipline
//!
//! Reads and checks never write. Only a successful match (the user typed the
//! number the peer's current identity key derives to) persists anything. In
//! particular a detected key change is *reported*, never recorded over the
//! number the user actually verified — overwriting it would turn the next
//! check into a silent pass, which is exactly the failure this module exists
//! to prevent.

use core_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Prefix for the per-peer verification record inside the encrypted store.
const STATE_KEY_PREFIX: &str = "verification:";

/// The verification state of one peer's safety number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VerificationState {
    /// The safety number has not yet been verified.
    Unverified,
    /// The safety number matches and has been marked as verified.
    Verified,
    /// The identity key changed after a prior verification.
    KeyChangedWarning { previous: String, current: String },
}

/// Errors surfaced by [`VerificationStore`].
///
/// Messages are deliberately generic: they never carry the store path or a
/// safety number, so they are safe to return over the IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// The encrypted store could not be opened or accessed.
    Store(String),
    /// The peer identifier was empty.
    InvalidPeer,
    /// The safety number was empty.
    InvalidSafetyNumber,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::Store(message) => {
                write!(f, "verification store unavailable: {message}")
            }
            VerificationError::InvalidPeer => write!(f, "peer identifier must not be empty"),
            VerificationError::InvalidSafetyNumber => {
                write!(f, "safety number must not be empty")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// The persisted record for one peer.
///
/// * `current` — the safety number the peer's identity key derives to *now*.
/// * `verified` — the safety number the user confirmed, if any. Its presence is
///   the verified/unverified flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    current: String,
    verified: Option<String>,
}

/// Per-peer safety-number verification state backed by the encrypted store.
pub struct VerificationStore {
    store: EncryptedStore,
}

impl VerificationStore {
    /// Open (creating if absent) the encrypted store inside `dir` with `key`.
    pub fn open(dir: &Path, key: &[u8; 32]) -> Result<Self, VerificationError> {
        let store = EncryptedStore::open(dir, key)
            .map_err(|err| VerificationError::Store(err.to_string()))?;
        Ok(Self { store })
    }

    /// Record the safety number `peer`'s identity key currently derives to.
    ///
    /// A peer that was never begun is unverified. Calling `begin` again for an
    /// already-verified peer updates the *current* number (the identity key
    /// rotated) but keeps the number the user verified, so the next check
    /// reports a key change instead of silently passing.
    pub fn begin(&self, peer: &str, expected: &str) -> Result<(), VerificationError> {
        validate_peer(peer)?;
        validate_number(expected)?;

        let mut record = self.load(peer)?.unwrap_or(Record {
            current: expected.to_string(),
            verified: None,
        });
        record.current = expected.to_string();
        self.save(peer, &record)
    }

    /// Compare `input` against the peer's safety number and return the result.
    ///
    /// Only a successful match writes. A mismatch leaves the store untouched; a
    /// key change is reported as [`VerificationState::KeyChangedWarning`] and
    /// the previously verified number is preserved.
    pub fn verify(&self, peer: &str, input: &str) -> Result<VerificationState, VerificationError> {
        validate_peer(peer)?;
        validate_number(input)?;

        let Some(record) = self.load(peer)? else {
            return Ok(VerificationState::Unverified);
        };

        match record.verified {
            Some(verified) => {
                if input == verified {
                    Ok(VerificationState::Verified)
                } else {
                    Ok(VerificationState::KeyChangedWarning {
                        previous: verified,
                        current: input.to_string(),
                    })
                }
            }
            None => {
                if input == record.current {
                    let updated = Record {
                        current: record.current,
                        verified: Some(input.to_string()),
                    };
                    self.save(peer, &updated)?;
                    Ok(VerificationState::Verified)
                } else {
                    Ok(VerificationState::Unverified)
                }
            }
        }
    }

    /// The peer's persisted verification state. Never writes.
    pub fn state(&self, peer: &str) -> Result<VerificationState, VerificationError> {
        validate_peer(peer)?;

        let Some(record) = self.load(peer)? else {
            return Ok(VerificationState::Unverified);
        };

        match record.verified {
            None => Ok(VerificationState::Unverified),
            Some(verified) => {
                if record.current == verified {
                    Ok(VerificationState::Verified)
                } else {
                    Ok(VerificationState::KeyChangedWarning {
                        previous: verified,
                        current: record.current,
                    })
                }
            }
        }
    }

    fn load(&self, peer: &str) -> Result<Option<Record>, VerificationError> {
        let key = state_key(peer);
        let Some(blob) = self
            .store
            .get_state(&key)
            .map_err(|err| VerificationError::Store(err.to_string()))?
        else {
            return Ok(None);
        };
        let record = serde_json::from_slice(&blob)
            .map_err(|err| VerificationError::Store(format!("corrupted record: {err}")))?;
        Ok(Some(record))
    }

    fn save(&self, peer: &str, record: &Record) -> Result<(), VerificationError> {
        let blob = serde_json::to_vec(record)
            .map_err(|err| VerificationError::Store(format!("cannot encode record: {err}")))?;
        self.store
            .put_state(&state_key(peer), &blob)
            .map_err(|err| VerificationError::Store(err.to_string()))
    }
}

fn state_key(peer: &str) -> String {
    format!("{STATE_KEY_PREFIX}{peer}")
}

fn validate_peer(peer: &str) -> Result<(), VerificationError> {
    if peer.trim().is_empty() {
        return Err(VerificationError::InvalidPeer);
    }
    Ok(())
}

fn validate_number(number: &str) -> Result<(), VerificationError> {
    if number.trim().is_empty() {
        return Err(VerificationError::InvalidSafetyNumber);
    }
    Ok(())
}

/// The user-facing explanation of the verification flow.
pub fn describe_verification_flow_for_user() -> VerificationFlowDoc {
    VerificationFlowDoc::LayUserFriendly
}

/// A user-facing description of how safety-number verification works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationFlowDoc {
    /// Plain-language explanation suitable for a non-technical user.
    LayUserFriendly,
}

impl VerificationFlowDoc {
    /// The explanation body shown in the UI.
    pub fn body(&self) -> &str {
        match self {
            VerificationFlowDoc::LayUserFriendly => {
                "Compare the safety number shown here with the one shown on your contact's \
                 device. If both match, mark them verified. If the number ever changes, that \
                 means their identity key changed — verify again in person before trusting it."
            }
        }
    }
}
