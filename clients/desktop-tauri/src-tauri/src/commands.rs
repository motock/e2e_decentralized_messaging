//! Tauri commands invoked from the JS/TS UI (`dist/main.js`). Each one delegates directly to
//! `core_crypto` — no crypto or session logic is reimplemented here — and maps any core
//! `Result::Err` into a serializable [`crate::error::ShellError`], so a malformed-input failure
//! renders as a defined UI error state instead of propagating as an opaque panic across the IPC
//! boundary.

use crate::error::ShellError;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// File the desktop shell persists its long-term identity public key in, inside the app-data
/// directory handed to [`load_or_create_identity`].
const IDENTITY_FILE_NAME: &str = "identity.json";

/// Generate a fresh identity keypair and return its public key bytes.
#[tauri::command]
pub fn generate_identity() -> Result<Vec<u8>, ShellError> {
    let identity = core_crypto::identity::IdentityKeyPair::generate();
    Ok(identity.public().to_bytes())
}

/// Return the identity public key persisted in `dir`, minting and persisting a fresh one only when
/// none exists yet.
///
/// This is the stable-identity path the UI uses on startup. Unlike [`generate_identity`], which
/// mints a brand-new keypair on every call, this returns the *same* key across restarts, so the
/// safety numbers a user's peers have already verified keep matching. The load path opens the file
/// **read-only**: it must never truncate or rewrite an existing identity, because doing so would
/// silently rotate the user's key out from under their peers.
#[tauri::command]
pub fn load_or_create_identity(dir: String) -> Result<Vec<u8>, ShellError> {
    let path = Path::new(&dir).join(IDENTITY_FILE_NAME);

    match File::open(&path) {
        // Read-only open: an existing identity is returned verbatim and the file is left untouched.
        Ok(mut file) => {
            let mut persisted = Vec::new();
            file.read_to_end(&mut persisted).map_err(|err| {
                ShellError::Session(format!(
                    "failed to read identity at {}: {err}",
                    path.display()
                ))
            })?;
            if persisted.is_empty() {
                // Fail closed. An existing-but-empty file is a *corrupted* identity, not a missing
                // one; minting a new key here would silently rotate the user's identity, which is
                // the same state-corruption failure mode as clobbering a populated file.
                return Err(ShellError::Session(format!(
                    "identity file {} exists but is empty; refusing to overwrite it",
                    path.display()
                )));
            }
            Ok(persisted)
        }
        // Only a genuinely absent identity is created — and only then is the file written.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let identity = core_crypto::identity::IdentityKeyPair::generate();
            let public_key = identity.public().to_bytes();
            std::fs::write(&path, &public_key).map_err(|err| {
                ShellError::Session(format!(
                    "failed to persist identity at {}: {err}",
                    path.display()
                ))
            })?;
            Ok(public_key)
        }
        Err(err) => Err(ShellError::Session(format!(
            "failed to open identity at {}: {err}",
            path.display()
        ))),
    }
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
}

#[cfg(test)]
mod identity_persistence_tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Creates a fresh, empty directory under the OS temp dir that no other test shares, so the
    /// "no identity persisted yet" precondition is real rather than assumed.
    fn fresh_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "dt1-identity-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after the unix epoch")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        dir
    }

    /// Calls the command the way the JS/TS UI does, from a directory path.
    fn load_or_create(dir: &Path) -> Result<Vec<u8>, ShellError> {
        load_or_create_identity(dir.to_string_lossy().into_owned())
    }

    #[test]
    fn load_or_create_identity_returns_a_non_empty_public_key_when_none_is_persisted() {
        let dir = fresh_temp_dir();
        let public_key = load_or_create(&dir).expect("load_or_create_identity must succeed");
        assert!(
            !public_key.is_empty(),
            "public key bytes returned to the UI must not be empty"
        );
    }

    /// The bug this catches: an implementation that unconditionally does
    /// `let k = generate(); write(file, k); return k;`. Call 2's *return value* still looks fine
    /// (a non-empty public key), so a weak test passes — but the file has been clobbered with a
    /// brand-new key, so every later load returns a key the user's peers never saw. The same
    /// failure mode appears if the key is cached in memory while a fresh key is still written to
    /// disk. Both are caught here by asserting the *file bytes*, not just the return values.
    #[test]
    fn load_or_create_identity_persists_a_stable_key_and_never_clobbers_it() {
        let dir = fresh_temp_dir();
        let path = dir.join("identity.json");

        // Call 1: nothing persisted yet -> a fresh key is minted and written to disk.
        let first = load_or_create(&dir).expect("first call must succeed");
        assert!(
            !first.is_empty(),
            "first call must return a non-empty public key"
        );
        assert!(
            path.exists(),
            "first call must persist the identity to {}",
            path.display()
        );
        assert_eq!(
            std::fs::read(&path).expect("persisted identity must be readable"),
            first,
            "the persisted bytes must be exactly the public key returned to the UI"
        );

        // Call 2: the identity already exists -> it must be loaded, not regenerated, and the file
        // must be left byte-for-byte untouched (a load must never rewrite the file).
        let second = load_or_create(&dir).expect("second call must succeed");
        assert_eq!(
            second, first,
            "a second call must return the SAME identity, not a freshly generated one"
        );
        assert_eq!(
            std::fs::read(&path).expect("persisted identity must still be readable"),
            first,
            "loading an existing identity must not rewrite or truncate the file"
        );

        // Call 3: the file is gone (e.g. a fresh install) -> a brand-new key is minted and written.
        std::fs::remove_file(&path).expect("identity file must be removable");
        let third = load_or_create(&dir).expect("third call must succeed");
        assert_ne!(
            third, first,
            "after the file is deleted a genuinely new identity must be minted"
        );
        assert_eq!(
            std::fs::read(&path).expect("newly persisted identity must be readable"),
            third,
            "the newly minted identity must be persisted to disk"
        );
    }

    /// An existing-but-empty file must not be silently replaced with a freshly generated key:
    /// that is the same state-corruption failure mode as clobbering a populated file, just with a
    /// different trigger. The command fails closed and leaves the file untouched.
    #[test]
    fn load_or_create_identity_refuses_to_overwrite_an_existing_but_empty_identity_file() {
        let dir = fresh_temp_dir();
        let path = dir.join("identity.json");
        std::fs::write(&path, b"").expect("empty identity file must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "an existing-but-empty identity file must not be silently replaced, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("identity file must still be readable"),
            Vec::<u8>::new(),
            "the pre-existing file must be left untouched"
        );
    }
}
