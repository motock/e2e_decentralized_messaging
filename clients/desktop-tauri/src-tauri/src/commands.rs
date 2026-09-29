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
use core_storage::EncryptedStore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::Manager;

/// File the desktop shell keeps its 256-bit store key in, inside the app-data directory resolved
/// by [`load_or_create_identity`].
///
/// The identity itself lives in the SQLCipher database (`store.db`) that
/// [`core_storage::EncryptedStore`] opens in the same directory; this file holds only the key that
/// database is encrypted with. It is a dedicated key file, not plaintext config: the identity —
/// private key included — is never written outside the encrypted store.
const STORE_KEY_FILE_NAME: &str = "store.key";

/// Name of the SQLCipher database [`core_storage::EncryptedStore`] opens inside the app-data
/// directory. It must match the file name `EncryptedStore::open` joins onto the directory it is
/// given; it is named here only so the first-run check below can tell "no store yet" (a genuine
/// first run) from "the store's key was lost" (fail closed, never mint a replacement key).
const STORE_DB_FILE_NAME: &str = "store.db";

/// Length of the store key: 256 bits, the size [`core_storage::EncryptedStore::open`] takes.
const STORE_KEY_LEN: usize = 32;

/// Length of a serialized public identity key: a 1-byte key-type tag plus a 32-byte Curve25519
/// point (see `core_crypto::identity::PublicIdentityKey::to_bytes`).
const PUBLIC_IDENTITY_KEY_LEN: usize = 33;

/// Permissions the store key file is created with: owner read/write only (0600). The key decrypts
/// the identity database, so a world-readable key file would hand the user's private identity key
/// to any local process; the file is created owner-only rather than at the process umask default.
#[cfg(unix)]
const STORE_KEY_FILE_MODE: u32 = 0o600;

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
/// implementation is [`load_or_create_identity_in`], which is crate-private and re-validates its
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

/// Body of [`load_or_create_identity`] once the app-data directory has been resolved in Rust.
///
/// Split out of the `#[tauri::command]` so the *production* path is testable without a Tauri
/// `AppHandle`: the command does nothing with `dir` except hand it here.
///
/// `app_data_dir()` on desktop is only `dirs::data_dir().join(identifier)` — Tauri does not create
/// it (verified in the vendored tauri 2.11.5 source: `src/path/desktop.rs` has no `create_dir_all`,
/// and the only one in `src/manager/webview.rs` is for the webview `user_data_dir`, which is set
/// only on Linux/Windows). On a fresh macOS/Windows install the directory therefore does not
/// exist, and [`validate_identity_dir`]'s `canonicalize` would fail with `NotFound`, so the
/// documented first-run mint path could never execute. Creating it here (idempotent) is what makes
/// that path reachable.
fn load_or_create_identity_at(dir: &Path) -> Result<Vec<u8>, ShellError> {
    let correlation_id = next_correlation_id();
    std::fs::create_dir_all(dir).map_err(|err| {
        eprintln!(
            "identity: correlation {correlation_id}: cannot create app data dir {}: {err}",
            dir.display()
        );
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    load_or_create_identity_in(dir)
}

/// Path-taking implementation of [`load_or_create_identity`], crate-private on purpose.
///
/// This is *not* a `#[tauri::command]`: exposing it over IPC would reintroduce exactly the
/// arbitrary-path primitive the zero-arg command exists to remove. Tests call it directly to
/// exercise the persistence logic against a temp directory.
///
/// `dir` is re-validated even though the production caller passes the app-data directory resolved
/// by Tauri — defense in depth, so a future caller cannot quietly turn this into a traversal
/// primitive.
fn load_or_create_identity_in(dir: &Path) -> Result<Vec<u8>, ShellError> {
    let correlation_id = next_correlation_id();
    let dir = validate_identity_dir(dir, correlation_id)?;

    let store_key = load_or_create_store_key(&dir, correlation_id)?;
    let store = EncryptedStore::open(&dir, &store_key).map_err(|err| {
        // `StoreError`'s `Display` carries no path, so logging it is safe.
        eprintln!("identity: correlation {correlation_id}: cannot open identity store: {err}");
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    match store.get_identity().map_err(|err| {
        eprintln!("identity: correlation {correlation_id}: cannot read identity store: {err}");
        ShellError::Session(identity_error_message(correlation_id))
    })? {
        Some(serialized) => {
            let identity = core_crypto::identity::IdentityKeyPair::from_bytes(&serialized)
                .map_err(|err| {
                    eprintln!(
                        "identity: correlation {correlation_id}: stored identity is not a \
                         well-formed keypair: {err}"
                    );
                    ShellError::Session(identity_error_message(correlation_id))
                })?;
            let public_key = identity.public().to_bytes();
            validate_public_identity_key(&public_key).map_err(|reason| {
                eprintln!(
                    "identity: correlation {correlation_id}: rejecting stored identity: {reason}"
                );
                ShellError::Session(identity_error_message(correlation_id))
            })?;
            audit_identity_event(
                "identity.load",
                correlation_id,
                &format!("loaded {} bytes", serialized.len()),
            );
            Ok(public_key)
        }
        None => {
            let identity = core_crypto::identity::IdentityKeyPair::generate();
            let serialized = identity.as_libsignal().serialize();
            let public_key = identity.public().to_bytes();
            store.put_identity(&serialized).map_err(|err| {
                eprintln!("identity: correlation {correlation_id}: cannot persist identity: {err}");
                ShellError::Session(identity_error_message(correlation_id))
            })?;
            audit_identity_event(
                "identity.mint",
                correlation_id,
                &format!("minted {} bytes", serialized.len()),
            );
            Ok(public_key)
        }
    }
}

/// Reject a directory that is not an absolute, `..`-free path, and return it canonicalized.
///
/// The containment check is deliberately structural (absolute + no parent-dir components) rather
/// than "must be inside the app-data dir": the app-data dir is only known to the Tauri command,
/// and the tests exercise this helper against temp directories. The IPC-reachable command never
/// passes frontend input here at all, which is the primary control; this is the second layer.
fn validate_identity_dir(dir: &Path, correlation_id: u64) -> Result<PathBuf, ShellError> {
    let reject = |reason: &str| -> ShellError {
        eprintln!("identity: correlation {correlation_id}: rejecting identity directory: {reason}");
        ShellError::Session(identity_error_message(correlation_id))
    };

    if !dir.is_absolute() {
        return Err(reject("directory is not absolute"));
    }
    if dir
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(reject("directory contains a `..` component"));
    }

    std::fs::canonicalize(dir).map_err(|err| reject(&format!("directory is not usable: {err}")))
}

/// Read the store key, or `Ok(None)` when no key file exists yet (a genuine first run).
///
/// Fails closed: an existing key file that is empty, truncated, or not exactly [`STORE_KEY_LEN`]
/// bytes is an error, never a reason to mint a replacement key. Minting a replacement would
/// silently make the existing identity database undecryptable — i.e. it would rotate the user's
/// identity, which is the security-relevant surprise this guards against.
fn read_store_key(
    path: &Path,
    correlation_id: u64,
) -> Result<Option<[u8; STORE_KEY_LEN]>, ShellError> {
    let mut file = match File::open(path) {
        // Read-only open: an existing key is returned verbatim and the file is left untouched.
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            eprintln!(
                "identity: correlation {correlation_id}: cannot open {}: {err}",
                path.display()
            );
            return Err(ShellError::Session(identity_error_message(correlation_id)));
        }
    };

    let mut persisted = Vec::new();
    file.read_to_end(&mut persisted).map_err(|err| {
        eprintln!(
            "identity: correlation {correlation_id}: cannot read {}: {err}",
            path.display()
        );
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    let key: [u8; STORE_KEY_LEN] = persisted.as_slice().try_into().map_err(|_| {
        eprintln!(
            "identity: correlation {correlation_id}: rejecting {}: expected {STORE_KEY_LEN} \
             bytes, found {}",
            path.display(),
            persisted.len()
        );
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    Ok(Some(key))
}

/// Validate that `bytes` is a well-formed serialized public identity key.
///
/// The structural parse is delegated to `core_crypto` (libsignal's `IdentityKey::decode`, reached
/// through `derive_safety_number`) rather than reimplemented here. That is the same parse the
/// safety number a peer verifies is derived from, so a key that passes this check is exactly a key
/// that can be bound to a safety number — which is the property a substituted identity would
/// break. `PublicIdentityKey::from_bytes` is deliberately *not* used: it is documented as
/// non-validating, i.e. it is the fail-open behaviour this guards against.
fn validate_public_identity_key(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != PUBLIC_IDENTITY_KEY_LEN {
        return Err(format!(
            "expected {PUBLIC_IDENTITY_KEY_LEN} bytes, found {}",
            bytes.len()
        ));
    }

    core_crypto::derive_safety_number(bytes, bytes, bytes, bytes)
        .map(|_| ())
        .map_err(|err| format!("not a well-formed identity key: {err}"))
}

/// Load the store key from `dir`, minting and persisting a fresh one only when none exists yet.
fn load_or_create_store_key(
    dir: &Path,
    correlation_id: u64,
) -> Result<[u8; STORE_KEY_LEN], ShellError> {
    let path = dir.join(STORE_KEY_FILE_NAME);
    match read_store_key(&path, correlation_id)? {
        Some(key) => Ok(key),
        None => {
            // A missing key file is only a genuine first run when there is no store to decrypt. If
            // the store exists, its key was lost: minting a replacement would make the existing
            // identity database undecryptable, i.e. it would silently rotate the user's identity
            // and their peers would be talking to a stranger. Fail closed instead.
            if dir.join(STORE_DB_FILE_NAME).exists() {
                eprintln!(
                    "identity: correlation {correlation_id}: store key is missing but an identity \
                     store exists; refusing to mint a replacement key"
                );
                return Err(ShellError::Session(identity_error_message(correlation_id)));
            }

            let key = generate_store_key();
            persist_store_key(&path, &key, correlation_id)?;
            Ok(key)
        }
    }
}

/// Draw a fresh 256-bit store key from the OS CSPRNG.
///
/// The shell links no CSPRNG crate directly, and adding one would widen the dependency surface for
/// a single 32-byte draw. `core_crypto`'s keypair generator is the CSPRNG-backed API this crate
/// already depends on, and a fresh Curve25519 private key is exactly 32 bytes straight from the OS
/// entropy source — the same source the identity itself is drawn from.
fn generate_store_key() -> [u8; STORE_KEY_LEN] {
    let source = core_crypto::identity::IdentityKeyPair::generate();
    let mut key = [0u8; STORE_KEY_LEN];
    key.copy_from_slice(&source.as_libsignal().private_key().serialize());
    key
}

/// Persist `key` as the store key, atomically and without ever clobbering an existing file.
///
/// * The bytes are written to a sibling temp file created with `create_new(true)` (O_EXCL) and
///   mode 0600, then flushed to disk — so the final path never holds a partially written key.
/// * The temp file is moved into place with `hard_link`, which is atomic and **fails** if the
///   destination already exists. `rename` would silently replace an existing key (and
///   `std::fs::write` would follow a symlink planted at the path), either of which would make the
///   identity database undecryptable — an identity-rotation primitive; `hard_link` gives neither.
fn persist_store_key(
    path: &Path,
    key: &[u8; STORE_KEY_LEN],
    correlation_id: u64,
) -> Result<(), ShellError> {
    let fail = |err: &dyn std::fmt::Display| -> ShellError {
        eprintln!(
            "identity: correlation {correlation_id}: cannot persist {}: {err}",
            path.display()
        );
        ShellError::Session(identity_error_message(correlation_id))
    };

    let temp_path = path.with_file_name(format!("{STORE_KEY_FILE_NAME}.tmp-{correlation_id}"));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(STORE_KEY_FILE_MODE);
    }

    let mut temp = options.open(&temp_path).map_err(|err| fail(&err))?;
    temp.write_all(key).map_err(|err| fail(&err))?;
    temp.sync_all().map_err(|err| fail(&err))?;
    drop(temp);

    // Atomic, no-clobber move into place: fails rather than replacing a key that appeared (or a
    // symlink that was planted) between the read above and this write.
    std::fs::hard_link(&temp_path, path).map_err(|err| {
        let _ = std::fs::remove_file(&temp_path);
        fail(&err)
    })?;

    // The key is persisted at this point; a leftover temp file is untidy but not a failure.
    if let Err(err) = std::fs::remove_file(&temp_path) {
        eprintln!(
            "identity: correlation {correlation_id}: cannot remove temp file {}: {err}",
            temp_path.display()
        );
    }

    Ok(())
}

/// Log a security-relevant identity event.
///
/// Minting or loading the long-term identity is security-relevant: it is what the safety numbers
/// peers verify are bound to, so a rotation is exactly the event an operator needs to be able to
/// see. Only the outcome, a correlation id, and a byte count are logged — never key material, and
/// never a path in the value returned to the caller.
///
/// Interim sink: stderr. The shell has no tamper-evident audit sink yet (CLAUDE.md "Audit
/// logging" wants one the application cannot modify after the fact); wiring one is a follow-up,
/// and this is deliberately the single place that would change.
fn audit_identity_event(event: &str, correlation_id: u64, detail: &str) {
    eprintln!("audit: {event} correlation={correlation_id} {detail}");
}

/// Monotonic per-process id correlating the generic message returned over IPC with the detailed
/// local log line that explains it (CLAUDE.md: generic error to the caller, full detail logged
/// locally).
fn next_correlation_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The generic, path-free message returned over IPC for any identity failure.
fn identity_error_message(correlation_id: u64) -> String {
    format!("identity unavailable (reference {correlation_id})")
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

    /// Calls the crate-private path-taking implementation directly — the same code the zero-arg
    /// command runs once it has resolved the app-data directory from the Tauri app handle.
    fn load_or_create(dir: &Path) -> Result<Vec<u8>, ShellError> {
        load_or_create_identity_in(dir)
    }

    fn store_key_path(dir: &Path) -> PathBuf {
        dir.join(STORE_KEY_FILE_NAME)
    }

    fn store_db_path(dir: &Path) -> PathBuf {
        dir.join(STORE_DB_FILE_NAME)
    }

    /// Reads the store key the command persisted, so a test can open the store exactly the way the
    /// command does and inspect what was actually written to disk.
    fn persisted_store_key(dir: &Path) -> [u8; STORE_KEY_LEN] {
        std::fs::read(store_key_path(dir))
            .expect("the store key must have been persisted")
            .as_slice()
            .try_into()
            .expect("the persisted store key must be 32 bytes")
    }

    /// The serialized keypair actually held in the encrypted store, or `None` if none is.
    fn stored_identity(dir: &Path) -> Option<Vec<u8>> {
        EncryptedStore::open(dir, &persisted_store_key(dir))
            .expect("the store must open with the persisted key")
            .get_identity()
            .expect("the identity row must be readable")
    }

    /// The stable 32-byte recipient id of the identity currently in the store.
    fn stored_recipient_id(dir: &Path) -> [u8; 32] {
        let serialized = stored_identity(dir).expect("an identity must be persisted");
        let identity = core_crypto::identity::IdentityKeyPair::from_bytes(&serialized)
            .expect("the stored identity must be a well-formed keypair");
        core_crypto::ratchet_session::identity_hash(identity.as_libsignal())
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

    /// Test 1: loading twice returns the same identity *and* the same recipient id. The second
    /// call reopens the store from disk, so this is the restart path, not an in-memory cache.
    #[test]
    fn load_or_create_identity_returns_the_same_identity_and_recipient_id_across_restarts() {
        let dir = fresh_temp_dir();

        let first = load_or_create(&dir).expect("first call must succeed");
        let first_recipient_id = stored_recipient_id(&dir);

        let second = load_or_create(&dir).expect("second call must succeed");
        let second_recipient_id = stored_recipient_id(&dir);

        assert_eq!(
            second, first,
            "a second call must return the SAME identity, not a freshly generated one"
        );
        assert_eq!(
            second_recipient_id, first_recipient_id,
            "the recipient id derived from the identity must be stable across restarts"
        );
    }

    /// Test 3 (boundary): a first run with no existing store mints and persists exactly one
    /// identity, and a second call loads it rather than minting another.
    #[test]
    fn load_or_create_identity_mints_exactly_one_identity_on_a_first_run() {
        let dir = fresh_temp_dir();
        assert!(
            !store_db_path(&dir).exists(),
            "precondition: no identity store must exist yet"
        );
        assert!(
            !store_key_path(&dir).exists(),
            "precondition: no store key must exist yet"
        );

        let public_key = load_or_create(&dir).expect("a first run must mint an identity");

        assert!(
            store_db_path(&dir).is_file(),
            "the encrypted store must be created on a first run"
        );
        assert!(
            store_key_path(&dir).is_file(),
            "the store key must be created on a first run"
        );

        let serialized = stored_identity(&dir).expect("exactly one identity must be persisted");
        let identity = core_crypto::identity::IdentityKeyPair::from_bytes(&serialized)
            .expect("the persisted identity must be a well-formed keypair");
        assert_eq!(
            identity.public().to_bytes(),
            public_key,
            "the persisted identity must be the one returned to the UI"
        );

        // A second call must load, not mint: neither the store key nor the stored keypair changes.
        let key_before = std::fs::read(store_key_path(&dir)).expect("store key must be readable");
        let second = load_or_create(&dir).expect("a second call must succeed");
        assert_eq!(
            second, public_key,
            "a second call must not mint a second identity"
        );
        assert_eq!(
            std::fs::read(store_key_path(&dir)).expect("store key must still be readable"),
            key_before,
            "loading an existing identity must not rewrite the store key"
        );
        assert_eq!(
            stored_identity(&dir).expect("the identity must still be persisted"),
            serialized,
            "loading an existing identity must not rewrite the stored keypair"
        );
    }

    /// Regression for the blocking finding: the persisted record must be the FULL keypair, not
    /// just the public half. A public-key-only record leaves the client unable to sign or decrypt
    /// with its own identity after a restart — the address of a key that no longer exists.
    #[test]
    fn load_or_create_identity_persists_the_full_keypair_not_just_the_public_key() {
        let dir = fresh_temp_dir();
        let public_key = load_or_create(&dir).expect("first call must succeed");

        let serialized = stored_identity(&dir).expect("an identity must be persisted");
        assert!(
            serialized.len() > PUBLIC_IDENTITY_KEY_LEN,
            "a bare public key is {PUBLIC_IDENTITY_KEY_LEN} bytes; the stored record must also \
             carry the private key, got {} bytes",
            serialized.len()
        );

        // `from_bytes` requires BOTH halves (libsignal's `IdentityKeyPairStructure` has required
        // `public_key` and `private_key` fields), so a successful parse proves the private key is
        // present and usable — not merely that some bytes were stored.
        let identity = core_crypto::identity::IdentityKeyPair::from_bytes(&serialized)
            .expect("the stored record must deserialize into a usable keypair");
        assert_eq!(
            identity.public().to_bytes(),
            public_key,
            "the stored keypair's public half must be the key returned to the UI"
        );
        assert!(
            !identity.as_libsignal().private_key().serialize().is_empty(),
            "the stored keypair must carry a private key"
        );
    }

    /// Regression for the blocking finding: the identity must live in the encrypted store, never
    /// in a plaintext file. The public key must not appear verbatim anywhere in the store's bytes.
    #[test]
    fn load_or_create_identity_stores_the_identity_encrypted_not_in_a_plaintext_file() {
        let dir = fresh_temp_dir();
        let public_key = load_or_create(&dir).expect("first call must succeed");

        assert!(
            !dir.join("identity.pub").exists(),
            "the identity must not be written to a plaintext file"
        );

        let db = std::fs::read(store_db_path(&dir)).expect("the store must be readable");
        assert!(
            !db.windows(public_key.len())
                .any(|window| window == public_key.as_slice()),
            "the public identity key must not appear in plaintext inside the store file"
        );
    }

    /// A store key that exists but is empty is a corrupted key, not a missing one: replacing it
    /// would make the existing identity database undecryptable, so it fails closed.
    #[test]
    fn load_or_create_identity_in_rejects_an_empty_store_key() {
        let dir = fresh_temp_dir();
        std::fs::write(store_key_path(&dir), b"").expect("empty store key must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "an empty store key must fail closed, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(store_key_path(&dir)).expect("store key must still be readable"),
            Vec::<u8>::new(),
            "the pre-existing store key must be left untouched"
        );
        assert!(
            !store_db_path(&dir).exists(),
            "no store may be created for a rejected store key"
        );
    }

    /// A truncated store key must fail closed for the same reason, and must not be replaced.
    #[test]
    fn load_or_create_identity_in_rejects_a_truncated_store_key() {
        let dir = fresh_temp_dir();
        let truncated = vec![0x05u8; 7];
        std::fs::write(store_key_path(&dir), &truncated).expect("store key must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a truncated store key must fail closed, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(store_key_path(&dir)).expect("store key must still be readable"),
            truncated,
            "a corrupted store key must be left untouched, never silently replaced"
        );
    }

    /// Test 2: a corrupt store fails closed with a clear error and does NOT silently generate a
    /// replacement identity — silently rotating identity would mean contacts are talking to a
    /// stranger.
    #[test]
    fn load_or_create_identity_in_rejects_a_corrupt_store_without_minting_a_replacement() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");
        let key_before = std::fs::read(store_key_path(&dir)).expect("store key must be readable");

        // Corrupt the database file in place (e.g. a torn write, or a truncated file).
        std::fs::write(store_db_path(&dir), b"not a database").expect("store must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a corrupt store must fail closed, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(store_key_path(&dir)).expect("store key must still be readable"),
            key_before,
            "a corrupt store must not cause the store key to be rotated"
        );
        assert_eq!(
            std::fs::read(store_db_path(&dir)).expect("store must still be readable"),
            b"not a database",
            "a corrupt store must be left untouched, never silently replaced"
        );
    }

    /// A store whose identity row is structurally corrupt (a truncated envelope) must fail closed
    /// rather than being treated as "no identity yet".
    #[test]
    fn load_or_create_identity_in_rejects_a_malformed_identity_row() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        // `put_raw` is core_storage's documented test hook for injecting a value beneath the typed
        // API, so the corruption survives into `get_identity`.
        EncryptedStore::open(&dir, &persisted_store_key(&dir))
            .expect("store must open")
            .put_raw("identity", &[0u8; 7])
            .expect("raw write must succeed");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a malformed identity row must fail closed, got: {result:?}"
        );
    }

    /// A store whose identity row is a well-formed envelope but not a keypair must also fail
    /// closed, rather than being returned to the UI as the user's identity.
    #[test]
    fn load_or_create_identity_in_rejects_a_stored_identity_that_is_not_a_keypair() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        EncryptedStore::open(&dir, &persisted_store_key(&dir))
            .expect("store must open")
            .put_identity(&[0u8; PUBLIC_IDENTITY_KEY_LEN])
            .expect("typed write must succeed");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a stored value that is not a keypair must fail closed, got: {result:?}"
        );
    }

    /// Losing the store key must not silently rotate the identity: the store is still there, so a
    /// replacement key would make it undecryptable and the user's peers would be talking to a
    /// stranger.
    #[test]
    fn load_or_create_identity_in_refuses_to_mint_a_replacement_key_when_the_store_key_is_lost() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        std::fs::remove_file(store_key_path(&dir)).expect("store key must be removable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a lost store key must fail closed, got: {result:?}"
        );
        assert!(
            !store_key_path(&dir).exists(),
            "a lost store key must not be silently replaced"
        );
    }

    /// The IPC-reachable command must take **no** filesystem path. A path parameter is an
    /// arbitrary file-read (and, when the store is absent, arbitrary file-create) primitive for
    /// anything running in the webview — an XSS in a rendered message body, a compromised bundled
    /// dependency, or devtools. This pins the signature at compile time: adding a path parameter
    /// makes the assignment below fail to compile.
    #[test]
    fn load_or_create_identity_command_takes_no_path_argument_from_the_frontend() {
        let command: fn(tauri::AppHandle) -> Result<Vec<u8>, ShellError> = load_or_create_identity;
        let _ = command;
    }

    /// A relative directory is rejected outright rather than resolved against the process CWD,
    /// which would make the identity location depend on how the app happened to be launched.
    #[test]
    fn load_or_create_identity_in_rejects_a_relative_directory() {
        let result = load_or_create_identity_in(Path::new("relative/identity-dir"));
        assert!(
            result.is_err(),
            "a relative identity directory must be rejected, got: {result:?}"
        );
    }

    /// The traversal control: a `..` component is rejected *structurally*, even when the path
    /// resolves to a real, writable directory. Without this, `invoke("load_or_create_identity",
    /// { dir: "../.." })` would read — or create — an identity outside the app-data dir.
    #[test]
    fn load_or_create_identity_in_rejects_a_parent_dir_component_even_when_it_resolves_to_a_real_directory(
    ) {
        let dir = fresh_temp_dir();
        let traversal = dir.join("..").join(
            dir.file_name()
                .expect("temp dir must have a final component"),
        );
        assert!(
            traversal.is_dir(),
            "the traversal path must resolve to a real directory for this test to mean anything"
        );

        let result = load_or_create_identity_in(&traversal);
        assert!(
            result.is_err(),
            "a `..` traversal directory must be rejected, got: {result:?}"
        );
        assert!(
            !store_db_path(&dir).exists(),
            "a rejected directory must not have a store minted into it"
        );
        assert!(
            !store_key_path(&dir).exists(),
            "a rejected directory must not have a store key minted into it"
        );
    }

    /// A directory that does not exist is rejected rather than created: creating it would let a
    /// caller choose where the identity lands.
    #[test]
    fn load_or_create_identity_in_rejects_a_directory_that_does_not_exist() {
        let dir = fresh_temp_dir().join("does-not-exist");
        let result = load_or_create_identity_in(&dir);
        assert!(
            result.is_err(),
            "a non-existent identity directory must be rejected, got: {result:?}"
        );
        assert!(
            !dir.exists(),
            "a rejected directory must not be created as a side effect"
        );
    }

    /// A dangling symlink planted at the store key path must not be written through: the create
    /// path must fail closed instead of creating the symlink's target. `std::fs::write` would
    /// follow it, turning store-key minting into arbitrary file creation.
    #[cfg(unix)]
    #[test]
    fn load_or_create_identity_in_does_not_write_through_a_dangling_symlink() {
        let dir = fresh_temp_dir();
        let victim = dir.join("victim.txt");
        std::os::unix::fs::symlink(&victim, store_key_path(&dir))
            .expect("symlink must be creatable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a dangling symlink at the store key path must fail closed, got: {result:?}"
        );
        assert!(
            !victim.exists(),
            "the symlink target must not be created by the store key write path"
        );
    }

    /// The store key is created owner-only (0600) rather than at the process umask default: it
    /// decrypts the identity database, so a world-readable key file would hand the user's private
    /// identity key to any local process.
    #[cfg(unix)]
    #[test]
    fn load_or_create_identity_store_key_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        let mode = std::fs::metadata(store_key_path(&dir))
            .expect("store key file must exist")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the store key file must be owner-only (0600), got {:o}",
            mode & 0o777
        );
    }

    /// Minting must leave no temp file behind: a stray partially written copy of the store key in
    /// the app-data directory is both untidy and a second thing to get wrong.
    #[test]
    fn load_or_create_identity_leaves_no_temp_files_behind() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(&dir)
            .expect("temp dir must be readable")
            .map(|entry| entry.expect("dir entry must be readable").file_name())
            .collect();

        assert!(
            entries
                .iter()
                .all(|name| !name.to_string_lossy().contains(".tmp-")),
            "no temp file may be left behind, found: {entries:?}"
        );
        assert!(
            entries.contains(&std::ffi::OsString::from(STORE_KEY_FILE_NAME)),
            "the store key must be present, found: {entries:?}"
        );
        assert!(
            entries.contains(&std::ffi::OsString::from(STORE_DB_FILE_NAME)),
            "the store must be present, found: {entries:?}"
        );
    }

    /// Error responses cross the IPC boundary and are rendered by `dist/main.js`'s `renderError`,
    /// so they must not leak internal file paths (CLAUDE.md: "No sensitive data in logs or
    /// errors"). The detail goes to the local log, correlated by the reference id in the message.
    #[test]
    fn load_or_create_identity_error_message_does_not_leak_the_file_path() {
        let dir = fresh_temp_dir();
        std::fs::write(store_key_path(&dir), b"").expect("empty store key must be writable");

        let err = load_or_create(&dir).expect_err("an empty store key must fail closed");
        let ShellError::Session(message) = err;

        assert!(
            !message.contains(&dir.to_string_lossy().into_owned()),
            "the error returned over IPC must not contain the internal directory path, got: {message}"
        );
        assert!(
            !message.contains(STORE_KEY_FILE_NAME),
            "the error returned over IPC must not name the internal store key file, got: {message}"
        );
        assert!(
            !message.contains(STORE_DB_FILE_NAME),
            "the error returned over IPC must not name the internal store file, got: {message}"
        );
        assert!(
            !message.is_empty(),
            "the error must still carry a message the UI can render"
        );
    }

    /// Regression test for the fresh-install path: `app_data_dir()` is *not* created by Tauri on
    /// desktop, so on a first run the directory is missing. `load_or_create_identity_at` is the
    /// exact body the `#[tauri::command]` runs after resolving the app-data dir in Rust, so this
    /// covers the production path without needing a Tauri `AppHandle`.
    ///
    /// The path is deliberately multi-level so `create_dir_all` (rather than a single-level
    /// `create_dir`) is what is required.
    #[test]
    fn load_or_create_identity_at_creates_a_missing_app_data_directory_and_mints_into_it() {
        let root = fresh_temp_dir();
        let missing = root.join("nested").join("app-data");
        assert!(
            !missing.exists(),
            "precondition: the app-data directory must not exist yet"
        );

        let first = load_or_create_identity_at(&missing)
            .expect("a missing app-data directory must be created, not rejected");
        assert!(
            !first.is_empty(),
            "the minted public key returned to the UI must not be empty"
        );
        assert!(
            store_db_path(&missing).is_file(),
            "the store must be created inside the created directory"
        );
        assert!(
            store_key_path(&missing).is_file(),
            "the store key must be created inside the created directory"
        );

        let serialized = stored_identity(&missing).expect("an identity must be persisted");
        let identity = core_crypto::identity::IdentityKeyPair::from_bytes(&serialized)
            .expect("the persisted identity must be a well-formed keypair");
        assert_eq!(
            identity.public().to_bytes(),
            first,
            "the persisted identity must be the key returned to the UI"
        );

        // Second call against the now-existing directory must load, not re-mint.
        let second = load_or_create_identity_at(&missing)
            .expect("a second call against the created directory must succeed");
        assert_eq!(
            second, first,
            "the identity must be stable across calls once the directory exists"
        );
    }
}
