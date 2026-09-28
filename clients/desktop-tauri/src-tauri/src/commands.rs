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
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::Manager;

/// File the desktop shell persists its long-term identity public key in, inside the app-data
/// directory resolved by [`load_or_create_identity`].
///
/// The contents are the raw serialized public identity key (a 1-byte key-type tag plus a 32-byte
/// Curve25519 point), not JSON — hence the `.pub` suffix rather than `.json`.
const IDENTITY_FILE_NAME: &str = "identity.pub";

/// Length of a serialized public identity key: a 1-byte key-type tag plus a 32-byte Curve25519
/// point (see `core_crypto::identity::PublicIdentityKey::to_bytes`).
const PUBLIC_IDENTITY_KEY_LEN: usize = 33;

/// Permissions the identity file is created with: owner read/write only (0600). The public key is
/// not secret, but a world-writable identity file would be a local identity-substitution
/// primitive, so the file is created owner-only rather than at the process umask default.
#[cfg(unix)]
const IDENTITY_FILE_MODE: u32 = 0o600;

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
/// # Trust boundary
///
/// Takes **no path argument**. The directory is resolved in Rust from the Tauri app handle
/// (`app_data_dir()`), so a compromised webview cannot aim the command at an arbitrary directory
/// (e.g. `~/.ssh`) to read — or, when the file is absent, *create* — files there. The path-taking
/// implementation is [`load_or_create_identity_in`], which is crate-private and re-validates its
/// input; it is deliberately not a `#[tauri::command]`.
///
/// # Failure model (fail closed)
///
/// * App-data directory missing (a fresh install) -> created, then the file is minted. Tauri does
///   not create `app_data_dir()` on desktop, so without this the first-run path could never run.
/// * No identity file yet -> mint one, persist it, return it.
/// * Identity file present and a well-formed public identity key -> return it verbatim. The file
///   is opened **read-only** and never rewritten: rewriting it would silently rotate the user's
///   key out from under peers who already verified its safety number.
/// * Identity file present but empty, truncated, or not a well-formed key -> `Err`. A corrupted
///   identity is *not* a missing one, so it is never silently replaced.
/// * Any I/O error -> `Err`. The response carries a generic message plus a correlation id; the
///   path and the underlying error are logged locally and never returned over IPC.
///
/// # Storage-layer note (surfaced, not silently shipped)
///
/// The task title says "through the shared core storage layer", and `core_storage::EncryptedStore`
/// does expose `put_identity`/`get_identity`. It is not used here yet, deliberately: it requires a
/// 256-bit store key, and this repository has no key-management story for one (docs/threat-model.md
/// §4.3 assumes the key lives in an OS keychain / secure enclave, which the desktop shell does not
/// integrate). Persisting that key in a plaintext file beside `store.db` would add no
/// confidentiality against the local-writer adversary this command is defending against, while
/// making the identity path look encrypted. Until a keychain-backed store key exists, the identity
/// is a validated, owner-only (0600) file; moving it into `EncryptedStore` is the follow-up.
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
    let path = validate_identity_dir(dir, correlation_id)?.join(IDENTITY_FILE_NAME);

    match read_persisted_identity(&path, correlation_id)? {
        Some(public_key) => {
            audit_identity_event(
                "identity.load",
                correlation_id,
                &format!("loaded {} bytes", public_key.len()),
            );
            Ok(public_key)
        }
        None => {
            let identity = core_crypto::identity::IdentityKeyPair::generate();
            let public_key = identity.public().to_bytes();
            persist_identity(&path, &public_key, correlation_id)?;
            audit_identity_event(
                "identity.mint",
                correlation_id,
                &format!("minted {} bytes", public_key.len()),
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

/// Read and validate the persisted identity, or `Ok(None)` when no identity file exists yet.
///
/// Fails closed: an existing file that is empty, truncated, or not a well-formed public identity
/// key is an error, never a reason to mint a replacement.
fn read_persisted_identity(
    path: &Path,
    correlation_id: u64,
) -> Result<Option<Vec<u8>>, ShellError> {
    let mut file = match File::open(path) {
        // Read-only open: an existing identity is returned verbatim and the file is left untouched.
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

    validate_public_identity_key(&persisted).map_err(|reason| {
        eprintln!(
            "identity: correlation {correlation_id}: rejecting {}: {reason}",
            path.display()
        );
        ShellError::Session(identity_error_message(correlation_id))
    })?;

    Ok(Some(persisted))
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

/// Persist `public_key` as the identity, atomically and without ever clobbering an existing file.
///
/// * The bytes are written to a sibling temp file created with `create_new(true)` (O_EXCL) and
///   mode 0600, then flushed to disk — so the final path never holds a partially written identity.
/// * The temp file is moved into place with `hard_link`, which is atomic and **fails** if the
///   destination already exists. `rename` would silently replace an existing identity (and
///   `std::fs::write` would follow a symlink planted at the path), either of which is an identity
///   substitution primitive; `hard_link` gives neither.
fn persist_identity(path: &Path, public_key: &[u8], correlation_id: u64) -> Result<(), ShellError> {
    let fail = |err: &dyn std::fmt::Display| -> ShellError {
        eprintln!(
            "identity: correlation {correlation_id}: cannot persist {}: {err}",
            path.display()
        );
        ShellError::Session(identity_error_message(correlation_id))
    };

    let temp_path = path.with_file_name(format!("{IDENTITY_FILE_NAME}.tmp-{correlation_id}"));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(IDENTITY_FILE_MODE);
    }

    let mut temp = options.open(&temp_path).map_err(|err| fail(&err))?;
    temp.write_all(public_key).map_err(|err| fail(&err))?;
    temp.sync_all().map_err(|err| fail(&err))?;
    drop(temp);

    // Atomic, no-clobber move into place: fails rather than replacing an identity that appeared
    // (or a symlink that was planted) between the read above and this write.
    std::fs::hard_link(&temp_path, path).map_err(|err| {
        let _ = std::fs::remove_file(&temp_path);
        fail(&err)
    })?;

    // The identity is persisted at this point; a leftover temp file is untidy but not a failure.
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

    fn identity_path(dir: &Path) -> PathBuf {
        dir.join(IDENTITY_FILE_NAME)
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
        let path = identity_path(&dir);

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
        let path = identity_path(&dir);
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

    /// The IPC-reachable command must take **no** filesystem path. A path parameter is an
    /// arbitrary file-read (and, when the file is absent, arbitrary file-create) primitive for
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
    /// { dir: "../.." })` would read — or create — an `identity.pub` outside the app-data dir.
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
            !identity_path(&dir).exists(),
            "a rejected directory must not have an identity minted into it"
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

    /// A truncated identity file must fail closed. Returning the short blob verbatim would render
    /// an attacker-chosen value as the user's identity, breaking the safety-number binding peers
    /// already verified — the exact failure the doc comment claims to prevent.
    #[test]
    fn load_or_create_identity_in_rejects_a_truncated_identity_file() {
        let dir = fresh_temp_dir();
        let path = identity_path(&dir);
        let truncated = vec![0x05u8; 7];
        std::fs::write(&path, &truncated).expect("truncated identity file must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a truncated identity must fail closed, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("identity file must still be readable"),
            truncated,
            "a corrupted identity must be left untouched, never silently replaced"
        );
    }

    /// A blob of the right length but with an unrecognized key-type tag is not a public identity
    /// key either, and must be rejected by the same validating parse the safety number uses.
    #[test]
    fn load_or_create_identity_in_rejects_a_malformed_identity_file() {
        let dir = fresh_temp_dir();
        let path = identity_path(&dir);
        let malformed = vec![0u8; PUBLIC_IDENTITY_KEY_LEN];
        std::fs::write(&path, &malformed).expect("malformed identity file must be writable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a malformed identity must fail closed, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("identity file must still be readable"),
            malformed,
            "a corrupted identity must be left untouched, never silently replaced"
        );
    }

    /// A dangling symlink planted at the identity path must not be written through: the create
    /// path must fail closed instead of creating the symlink's target. `std::fs::write` would
    /// follow it, turning identity minting into arbitrary file creation.
    #[cfg(unix)]
    #[test]
    fn load_or_create_identity_in_does_not_write_through_a_dangling_symlink() {
        let dir = fresh_temp_dir();
        let victim = dir.join("victim.txt");
        let path = identity_path(&dir);
        std::os::unix::fs::symlink(&victim, &path).expect("symlink must be creatable");

        let result = load_or_create(&dir);
        assert!(
            result.is_err(),
            "a dangling symlink at the identity path must fail closed, got: {result:?}"
        );
        assert!(
            !victim.exists(),
            "the symlink target must not be created by the identity write path"
        );
    }

    /// The identity file is created owner-only (0600) rather than at the process umask default,
    /// so a world-writable identity file can never become a local identity-substitution primitive.
    #[cfg(unix)]
    #[test]
    fn load_or_create_identity_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        let mode = std::fs::metadata(identity_path(&dir))
            .expect("identity file must exist")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the identity file must be owner-only (0600), got {:o}",
            mode & 0o777
        );
    }

    /// Minting must leave no temp file behind: a stray partially written copy of the identity in
    /// the app-data directory is both untidy and a second thing to get wrong.
    #[test]
    fn load_or_create_identity_leaves_no_temp_files_behind() {
        let dir = fresh_temp_dir();
        load_or_create(&dir).expect("first call must succeed");

        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(&dir)
            .expect("temp dir must be readable")
            .map(|entry| entry.expect("dir entry must be readable").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(IDENTITY_FILE_NAME)],
            "only the identity file may remain in the app-data directory"
        );
    }

    /// Error responses cross the IPC boundary and are rendered by `dist/main.js`'s `renderError`,
    /// so they must not leak internal file paths (CLAUDE.md: "No sensitive data in logs or
    /// errors"). The detail goes to the local log, correlated by the reference id in the message.
    #[test]
    fn load_or_create_identity_error_message_does_not_leak_the_file_path() {
        let dir = fresh_temp_dir();
        std::fs::write(identity_path(&dir), b"").expect("empty identity file must be writable");

        let err = load_or_create(&dir).expect_err("an empty identity file must fail closed");
        let ShellError::Session(message) = err;

        assert!(
            !message.contains(&dir.to_string_lossy().into_owned()),
            "the error returned over IPC must not contain the internal directory path, got: {message}"
        );
        assert!(
            !message.contains(IDENTITY_FILE_NAME),
            "the error returned over IPC must not name the internal identity file, got: {message}"
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
    /// Before the fix this failed with `NotFound` from `validate_identity_dir`'s `canonicalize`,
    /// i.e. the documented "no identity file yet -> mint one" path was unreachable on a fresh
    /// macOS/Windows install. The path is deliberately multi-level so `create_dir_all` (rather
    /// than a single-level `create_dir`) is what is required.
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

        let path = identity_path(&missing);
        assert!(
            path.is_file(),
            "the identity must be persisted inside the created directory"
        );
        assert_eq!(
            std::fs::read(&path).expect("the persisted identity must be readable"),
            first,
            "the bytes on disk must be exactly the key returned to the UI"
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
