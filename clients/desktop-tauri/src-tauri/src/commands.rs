//! Tauri commands invoked from the JS/TS UI (`dist/main.js`). Each one delegates directly to
//! `core_crypto` — no crypto or session logic is reimplemented here — and maps any core
//! `Result::Err` into a serializable [`crate::error::ShellError`], so a malformed-input failure
//! renders as a defined UI error state instead of propagating as an opaque panic across the IPC
//! boundary.
//!
//! # Trust boundary
//!
//! These commands are the privileged side of the IPC boundary; the webview is untrusted (an XSS
//! in a rendered message body, a compromised bundled dependency, or devtools can call `invoke`
//! with arbitrary arguments). No command here therefore accepts a filesystem path from the
//! frontend: the identity location is resolved in Rust from the Tauri app handle. Any path-taking
//! helper is crate-private and re-validates its input, so it can never become an arbitrary
//! file-read/file-create primitive reachable over IPC.

use crate::error::ShellError;
use crate::identity_store::{
    identity_error_message, load_or_create_identity_at, next_correlation_id,
};
use tauri::Manager;

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
    let dir = app.path().app_data_dir().map_err(|err| {
        // `tauri::Error`'s `Display` is a fixed message with no path, so logging it is safe.
        let correlation_id = next_correlation_id();
        eprintln!("identity: correlation {correlation_id}: cannot resolve app data dir: {err}");
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    load_or_create_identity_at(&dir)
}

/// Deliberately attempt PQXDH session establishment against a malformed prekey bundle. Exercises
/// the "core error surfaces as a defined UI error state, not a crash" contract end-to-end from
/// the JS/TS side.
#[tauri::command]
pub fn establish_malformed_session() -> Result<(), ShellError> {
    core_crypto::session::establish_with_malformed_prekey().map_err(ShellError::from)
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
}
