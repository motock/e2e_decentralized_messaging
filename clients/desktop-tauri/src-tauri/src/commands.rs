//! Tauri commands invoked from the JS/TS UI (`dist/main.js`). Each one delegates directly to
//! `core_crypto` / `core_storage` — no crypto or session logic is reimplemented here — and maps
//! any core `Result::Err` into a serializable [`crate::error::ShellError`], so a malformed-input
//! failure renders as a defined UI error state instead of propagating as an opaque panic across
//! the IPC boundary.
//!
//! # Trust boundary
//!
//! These commands are the privileged side of the IPC boundary; the webview is untrusted (an XSS
//! in a rendered message body, a compromised bundled dependency, or devtools can call `invoke`
//! with arbitrary arguments). No command here therefore accepts a filesystem path from the
//! frontend: the identity location is resolved in Rust from the Tauri app handle. Any path-taking
//! helper is crate-private and re-validates its input, so it can never become an arbitrary
//! file-read/file-create primitive reachable over IPC.
//!
//! The relay endpoint is likewise *not* taken from the webview: it is read from the
//! `DESKTOP_RELAY_URL` environment variable, which is operator configuration. A webview-supplied
//! URL would let a compromised page aim the shell's relay client at an arbitrary host.
//!
//! # Conversation commands
//!
//! [`get_conversation_state`], [`send_message`] and [`receive_and_decrypt`] are the compose /
//! receive path. History is persisted through [`crate::conversation::ConversationStore`] (the
//! same encrypted store the identity lives in), so a message list survives a restart. Delivery
//! reuses the DT-2 relay client ([`crate::relay_client::RelayClient`]) and the DT-1 identity:
//! the plaintext is encrypted with the peer's ratchet session before it ever reaches the relay,
//! and a message that cannot be delivered is reported (`delivered: false`) rather than silently
//! dropped. A received envelope that cannot be decrypted is recorded as a visible failure entry,
//! never as an empty message.

use crate::conversation::ConversationStore;
use crate::error::{CommandError, ShellError};
use crate::identity_store::{
    identity_error_message, load_or_create_identity_at, load_or_create_identity_keypair_at,
    load_or_create_store_key_at, next_correlation_id,
};
use crate::relay_client::{EnvelopeKind, RelayClient, RelayError};
use crate::ui::{render_conversation, Direction};
use crate::verify::{VerificationState, VerificationStore};
use core_crypto::ratchet_session::DoubleRatchetSession;
use core_storage::EncryptedStore;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Manager;

/// Prefix for a persisted ratchet session inside the encrypted store.
const SESSION_KEY_PREFIX: &str = "session:";

/// Environment variable naming the relay the shell talks to (operator config, not webview input).
const RELAY_URL_ENV: &str = "DESKTOP_RELAY_URL";

/// Generate a fresh identity keypair and return its public key bytes.
#[tauri::command]
pub fn generate_identity() -> Result<Vec<u8>, ShellError> {
    let identity = core_crypto::identity::IdentityKeyPair::generate();
    Ok(identity.public().to_bytes())
}

/// Return the identity public key persisted in the app's data directory, minting and persisting a
/// fresh one only when none exists yet.
///
/// This is the stable-identity path the UI uses on startup. Unlike [`generate_identity`], which
/// mints a brand-new keypair on every call, this returns the *same* key across restarts, so the
/// safety numbers a user's peers have already verified keep matching.
///
/// # Storage
///
/// The **full keypair** (private key included) is persisted through the shared core storage layer:
/// [`core_storage::EncryptedStore`], the SQLCipher-encrypted store, via its `put_identity` /
/// `get_identity` accessors. Persisting only the public half would leave the client unable to sign
/// or decrypt with its own identity after a restart — a public key with no matching private key is
/// the address of a key that no longer exists, not a stable identity.
///
/// The store is encrypted with a 256-bit key held in an owner-only (0600) `store.key` file in the
/// same directory. That key is deliberately *not* plaintext config: the identity itself never
/// leaves the encrypted store, and the key file is created atomically, owner-only, and never
/// clobbered. Moving the store key into an OS keychain / secure enclave (docs/threat-model.md §4.3)
/// is the follow-up; until then the key file is the only secret on disk, and it is 0600.
///
/// # Trust boundary
///
/// Takes **no path argument**. The directory is resolved in Rust from the Tauri app handle
/// (`app_data_dir()`), so a compromised webview cannot aim the command at an arbitrary directory
/// (e.g. `~/.ssh`) to read — or, when the store is absent, *create* — files there. The path-taking
/// implementation is `identity_store::load_or_create_identity_in`, which is crate-private and re-validates its
/// input; it is deliberately not a `#[tauri::command]`.
///
/// # Failure model (fail closed)
///
/// * App-data directory missing (a fresh install) -> created, then the identity is minted. Tauri
///   does not create `app_data_dir()` on desktop, so without this the first-run path could never
///   run.
/// * No store key and no identity yet -> mint a store key and an identity, persist both, return the
///   public key.
/// * Identity present and a well-formed keypair -> return its public key. An existing identity is
///   never rewritten: rewriting it would silently rotate the user's key out from under peers who
///   already verified its safety number.
/// * Store key present but empty, truncated, or not 32 bytes -> `Err`. A corrupted key is *not* a
///   missing one, so it is never silently replaced — replacing it would make the existing identity
///   database undecryptable.
/// * Store present but undecryptable, or the stored identity is not a well-formed keypair -> `Err`.
///   A corrupted identity is *not* a missing one, so it is never silently replaced.
/// * Any I/O error -> `Err`. The response carries a generic message plus a correlation id; the
///   path and the underlying error are logged locally and never returned over IPC.
///
/// # Migration note
///
/// An identity written by an earlier build as a bare `identity.pub` file is *not* migrated: that
/// file holds no private key, so it cannot be turned into a usable identity. Such a file is left
/// untouched and a fresh keypair is minted into the encrypted store.
#[tauri::command]
pub fn load_or_create_identity(app: tauri::AppHandle) -> Result<Vec<u8>, ShellError> {
    let dir = app_data_dir(&app)?;
    load_or_create_identity_at(&dir)
}

/// Deliberately attempt PQXDH session establishment against a malformed prekey bundle. Exercises
/// the "core error surfaces as a defined UI error state, not a crash" contract end-to-end from
/// the JS/TS side.
#[tauri::command]
pub fn establish_malformed_session() -> Result<(), ShellError> {
    core_crypto::session::establish_with_malformed_prekey().map_err(ShellError::from)
}

/// One message as the frontend renders it.
#[derive(Debug, Serialize)]
pub struct MessageView {
    /// `"sent"` or `"received"`.
    pub direction: &'static str,
    /// The plaintext body (empty for a decrypt failure).
    pub body: String,
    /// Unix seconds.
    pub unix_ts: i64,
    /// True when the envelope could not be decrypted; the UI shows a visible failure.
    pub decrypt_failed: bool,
}

/// The conversation as the frontend renders it.
#[derive(Debug, Serialize)]
pub struct ConversationView {
    /// The peer this history belongs to.
    pub peer: String,
    /// The rendered history (empty state / decrypt failures included).
    pub rendered: String,
    /// Structured messages, oldest first.
    pub messages: Vec<MessageView>,
    /// Whether the last send/receive actually reached the relay.
    pub delivered: bool,
}

/// Return the persisted conversation with `peer`.
#[tauri::command]
pub fn get_conversation_state(
    app: tauri::AppHandle,
    peer: String,
) -> Result<ConversationView, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let conversation = ConversationStore::open(&dir, &key)?;
    view(&conversation, &peer, false)
}

/// Send `body` to `peer`: record it in the conversation, then deliver it over the relay when a
/// session and a relay endpoint are available.
///
/// The body is validated (non-empty, within [`crate::conversation::MAX_MESSAGE_BYTES`]) *before*
/// anything is recorded or transmitted, so an oversized message is rejected outright rather than
/// truncated. The plaintext is encrypted with the peer's ratchet session before it reaches the
/// relay; when no session exists yet the message is still shown in the conversation and
/// `delivered` is `false`, so the UI can say so instead of pretending it was sent.
#[tauri::command]
pub fn send_message(
    app: tauri::AppHandle,
    peer: String,
    body: String,
) -> Result<ConversationView, CommandError> {
    // The ratchet session holds libsignal stores that are not `Send`, so the
    // command future cannot cross the IPC boundary as an async command. The
    // work runs on the command thread's own runtime instead.
    tauri::async_runtime::block_on(send_message_inner(app, peer, body))
}

async fn send_message_inner(
    app: tauri::AppHandle,
    peer: String,
    body: String,
) -> Result<ConversationView, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let conversation = ConversationStore::open(&dir, &key)?;

    // Rejects empty / oversized bodies before anything is stored or sent.
    conversation.record_sent(&peer, body.as_bytes(), now_ts())?;

    let mut delivered = false;
    if let Some(url) = relay_url() {
        let store = open_store(&dir, &key)?;
        let identity = load_or_create_identity_keypair_at(&dir)?;
        if let Some(mut session) = load_session(&store, &identity, &peer).await? {
            let envelope = session
                .encrypt(body.as_bytes())
                .await
                .map_err(|err| CommandError::Session(err.to_string()))?;
            save_session(&store, &peer, &session).await?;

            let mut client = RelayClient::connect(&url).await?;
            client
                .send_envelope(&peer, &envelope, Some(EnvelopeKind::Direct))
                .await?;
            delivered = true;
        }
    }

    view(&conversation, &peer, delivered)
}

/// Drain the relay mailbox for `peer`, decrypting each envelope into the conversation.
///
/// A successful decrypt is recorded as a received message. A failed decrypt is recorded as a
/// visible failure entry ([`crate::ui::Message::decrypt_failure`]) — never dropped, because a
/// silently missing message is indistinguishable from one that was never sent.
#[tauri::command]
pub fn receive_and_decrypt(
    app: tauri::AppHandle,
    peer: String,
) -> Result<ConversationView, CommandError> {
    tauri::async_runtime::block_on(receive_and_decrypt_inner(app, peer))
}

async fn receive_and_decrypt_inner(
    app: tauri::AppHandle,
    peer: String,
) -> Result<ConversationView, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let conversation = ConversationStore::open(&dir, &key)?;

    let Some(url) = relay_url() else {
        return view(&conversation, &peer, false);
    };

    let store = open_store(&dir, &key)?;
    let identity = load_or_create_identity_keypair_at(&dir)?;
    let mut session = load_session(&store, &identity, &peer).await?;
    let mut client = RelayClient::connect(&url).await?;

    loop {
        match client
            .pickup_envelope(&peer, Some(EnvelopeKind::Direct))
            .await
        {
            Ok(envelope) => {
                let ts = now_ts();
                match session.as_mut() {
                    Some(active) => match active.decrypt(&envelope.bytes).await {
                        Ok(plaintext) => {
                            conversation.record_received(&peer, &plaintext, ts)?;
                            save_session(&store, &peer, active).await?;
                        }
                        Err(_) => conversation.record_decrypt_failure(&peer, ts)?,
                    },
                    // No session yet: the envelope is unreadable, which the user must see.
                    None => conversation.record_decrypt_failure(&peer, ts)?,
                }
            }
            Err(RelayError::NotFound) => break,
            Err(err) => return Err(err.into()),
        }
    }

    view(&conversation, &peer, true)
}

/// Record the safety number `peer`'s identity key currently derives to, and return the state.
#[tauri::command]
pub fn begin_verification(
    app: tauri::AppHandle,
    peer: String,
    expected: String,
) -> Result<VerificationState, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let store = VerificationStore::open(&dir, &key)?;
    store.begin(&peer, &expected)?;
    Ok(store.state(&peer)?)
}

/// Compare the number the user typed against the peer's safety number.
///
/// Only a successful match persists; a key change is reported, never recorded over the number the
/// user actually verified.
#[tauri::command]
pub fn verify_safety_number(
    app: tauri::AppHandle,
    peer: String,
    input: String,
) -> Result<VerificationState, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let store = VerificationStore::open(&dir, &key)?;
    Ok(store.verify(&peer, &input)?)
}

/// The peer's persisted verification state (survives a restart).
#[tauri::command]
pub fn get_verification_state(
    app: tauri::AppHandle,
    peer: String,
) -> Result<VerificationState, CommandError> {
    let dir = app_data_dir(&app)?;
    let key = load_or_create_store_key_at(&dir)?;
    let store = VerificationStore::open(&dir, &key)?;
    Ok(store.state(&peer)?)
}

/// Resolve the app-data directory from the Tauri app handle.
///
/// Never takes a path from the frontend: see the module-level trust-boundary note.
fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, ShellError> {
    app.path().app_data_dir().map_err(|err| {
        // `tauri::Error`'s `Display` is a fixed message with no path, so logging it is safe.
        let correlation_id = next_correlation_id();
        eprintln!("shell: correlation {correlation_id}: cannot resolve app data dir: {err}");
        ShellError::Session(identity_error_message(correlation_id))
    })
}

fn open_store(dir: &Path, key: &[u8; 32]) -> Result<EncryptedStore, CommandError> {
    EncryptedStore::open(dir, key).map_err(|err| {
        let correlation_id = next_correlation_id();
        eprintln!("shell: correlation {correlation_id}: cannot open encrypted store: {err}");
        CommandError::Session(identity_error_message(correlation_id))
    })
}

fn relay_url() -> Option<String> {
    std::env::var(RELAY_URL_ENV)
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn session_key(peer: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{peer}")
}

async fn load_session(
    store: &EncryptedStore,
    identity: &core_crypto::identity::IdentityKeyPair,
    peer: &str,
) -> Result<Option<DoubleRatchetSession>, CommandError> {
    let Some(bytes) = store
        .get_state(&session_key(peer))
        .map_err(|err| CommandError::Session(err.to_string()))?
    else {
        return Ok(None);
    };

    let session = DoubleRatchetSession::from_bytes(identity.as_libsignal(), &bytes)
        .await
        .map_err(|err| CommandError::Session(err.to_string()))?;
    Ok(Some(session))
}

async fn save_session(
    store: &EncryptedStore,
    peer: &str,
    session: &DoubleRatchetSession,
) -> Result<(), CommandError> {
    let bytes = session
        .to_bytes()
        .await
        .map_err(|err| CommandError::Session(err.to_string()))?;
    store
        .put_state(&session_key(peer), &bytes)
        .map_err(|err| CommandError::Session(err.to_string()))
}

fn view(
    conversation: &ConversationStore,
    peer: &str,
    delivered: bool,
) -> Result<ConversationView, CommandError> {
    let state = conversation.state(peer)?;
    Ok(ConversationView {
        peer: peer.to_string(),
        rendered: render_conversation(&state),
        messages: state
            .messages
            .iter()
            .map(|message| MessageView {
                direction: match message.direction {
                    Direction::Sent => "sent",
                    Direction::Received => "received",
                },
                body: String::from_utf8_lossy(&message.body).into_owned(),
                unix_ts: message.unix_ts,
                decrypt_failed: message.decrypt_failed,
            })
            .collect(),
        delivered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the actual `#[tauri::command]` entry points the JS/TS UI invokes over IPC
    // (see `dist/main.js`), not just the underlying `core_crypto` functions they delegate to —
    // a broken command signature or a broken `ShellError` mapping would otherwise compile and
    // pass CI undetected, since `commands` is a private module no external test can reach.

    #[test]
    fn generate_identity_returns_non_empty_public_key() {
        let result = generate_identity();
        let public_key_bytes = result.expect("generate_identity must succeed");
        assert!(
            !public_key_bytes.is_empty(),
            "public key bytes returned to the UI must not be empty"
        );
    }

    #[test]
    fn establish_malformed_session_surfaces_err_not_panic() {
        let result = establish_malformed_session();
        assert!(
            matches!(result, Err(ShellError::Session(_))),
            "malformed-prekey command must return Err(ShellError::Session), got: {result:?}"
        );
    }

    #[test]
    fn establish_malformed_session_error_serializes_to_the_shape_main_js_expects() {
        // `dist/main.js`'s `renderError` reads `err.kind` and `err.message` directly off the
        // rejected IPC value, so the serde tag/content field names are part of the UI contract.
        let result = establish_malformed_session();
        let err = result.expect_err("malformed-prekey command must return Err");
        let json = serde_json::to_value(&err).expect("ShellError must serialize");

        assert_eq!(json["kind"], "Session");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()),
            "serialized error must carry a non-empty message, got: {json}"
        );
    }

    /// The IPC-reachable command must take **no** filesystem path. A path parameter is an
    /// arbitrary file-read (and, when the store is absent, arbitrary file-create) primitive for
    /// anything running in the webview — an XSS in a rendered message body, a compromised bundled
    /// dependency, or devtools. This pins the signature at compile time: adding a path parameter
    /// makes the assignment below fail to compile.
    #[test]
    fn load_or_create_identity_command_takes_no_path_argument_from_the_frontend() {
        const _COMMAND: fn(tauri::AppHandle) -> Result<Vec<u8>, ShellError> =
            load_or_create_identity;
    }

    /// The conversation commands must not take a path either: the store location is resolved in
    /// Rust from the app handle.
    #[test]
    fn conversation_commands_take_no_path_argument_from_the_frontend() {
        const _GET: fn(tauri::AppHandle, String) -> Result<ConversationView, CommandError> =
            get_conversation_state;
        const _VERIFY: fn(tauri::AppHandle, String) -> Result<VerificationState, CommandError> =
            get_verification_state;
    }
}
