//! WASM-facing API surface: a thin, byte-oriented facade over `crypto` for browser clients
//! (PLAN.md Phase 8). No cryptography is implemented here — `generate_identity`/`public_bytes`
//! mirror the same names and semantics as the UniFFI binding (`core/bindings/uniffi`), so the
//! documented core API surface is identical across native and WASM targets.
//!
//! ## Prekey bundles and session establishment
//!
//! `generate_prekey_bundle` serializes a receiver's PQXDH prekey bundle to a self-delimiting
//! byte vector (see `crypto::session::bundle_to_bytes`). `establish_session_from_bundle`
//! deserializes a peer's bundle bytes, verifies the signed-prekey signature against the bundle's
//! identity key, and runs PQXDH session establishment — returning an opaque `SessionHandle`.
//! `establish_with_malformed_prekey` mirrors desktop's `establish_with_malformed_prekey` contract:
//! it deliberately tampers a bundle and asserts the failure surfaces as a structured `WasmError`,
//! never a panic across the WASM boundary.
//!
//! ## Double Ratchet encrypt/decrypt
//!
//! `create_receiver_session` constructs a receiver (Bob) session from an identity — the
//! counterpart to `establish_session_from_bundle` (which constructs a sender/Alice session).
//! `encrypt_message` encrypts plaintext on an established sender session, returning the
//! self-describing wire envelope. `decrypt_message` decrypts an envelope on a receiver session,
//! returning the plaintext. All error paths — tampered ciphertext (AEAD MAC failure),
//! mismatched session, malformed/truncated envelope — surface as a structured `WasmError`,
//! never a panic across the WASM boundary.
//!
//! ## Sender Keys group encrypt/decrypt
//!
//! `group_create` / `group_add_member` / `group_remove_member` / `group_encrypt` /
//! `group_decrypt` expose the Sender Keys group crypto from `protocol::group`. A
//! `GroupHandle` wraps a `GroupSession`; membership is managed by public identity key
//! bytes; encrypt/decrypt delegate to the core implementation. All error paths —
//! non-member decrypt, removed-member post-rotation decrypt, malformed ciphertext —
//! surface as a structured `WasmError`, never a panic.
//!
//! ## Safety-number / fingerprint derivation
//!
//! `derive_safety_number` takes two parties' serialized public identity key bytes
//! (33-byte compressed Curve25519 keys, as returned by `IdentityHandle::public_bytes`)
//! and returns the display-formatted safety number string — the real derivation from
//! `crypto::device_qr::safety_number_for_display`, not a placeholder. The derivation is
//! deterministic: the same two keys always produce the same string. Malformed or
//! wrong-length key bytes surface as a structured `WasmError` with `kind = "SafetyNumber"`,
//! never a panic.

use wasm_bindgen::prelude::*;

use crypto::device_qr;
use crypto::identity::{IdentityKeyPair, PublicIdentityKey};
use crypto::ratchet_session::{DoubleRatchetSession, SessionError};
use crypto::session;
use libsignal_protocol::IdentityKey;
use protocol::fanout::{DeviceId, FanoutError, FanoutSession};
use protocol::group::{GroupMember, GroupSession};

/// A structured, JS-visible error — the WASM analogue of desktop's `ShellError`. Every core
/// `Result::Err` that crosses the WASM boundary is mapped to this type so JS code can switch on
/// `kind` and display `message`, the same contract `clients/desktop-tauri` asserts for
/// `ShellError` serialization shape.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WasmError {
    kind: String,
    message: String,
}

#[wasm_bindgen]
impl WasmError {
    /// The error variant tag (e.g. `"MalformedBundle"`, `"Session"`). JS code switches on this.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// A human-readable detail string. JS code displays this to the user or logs it.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl WasmError {
    fn new(kind: &str, message: &str) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.to_string(),
        }
    }
}

/// Poll `fut` to completion using a no-op waker — no thread, timer, or I/O driver required.
///
/// Every async function this facade drives (`DoubleRatchetSession::new_bob` / `new_alice` /
/// `encrypt` / `decrypt`) operates over an in-memory `libsignal` store with no real I/O, so it
/// always resolves on the first poll. A full async runtime (this crate previously used `tokio`)
/// is therefore unnecessary: this hand-rolled single-poll driver has no dependency on threads,
/// timers, or an I/O reactor, so it behaves identically on native and `wasm32-unknown-unknown`.
///
/// This alone does not make session establishment work on `wasm32-unknown-unknown` — the actual
/// blocker there was `libsignal_protocol::KyberPreKeyRecord::generate` (reached via
/// `crypto::ratchet_session::DoubleRatchetSession::new_bob`) calling `std::time::SystemTime::now()`
/// internally, which panics unconditionally on that target (no OS clock, and libstd provides no
/// hook to shim one in, unlike `getrandom`). That is fixed in `core/crypto` (see
/// `crypto::now()` and `crypto::session::generate_kyber_prekey`'s explicit `timestamp`
/// parameter) — this function is a smaller, complementary simplification: removing the async
/// runtime entirely, rather than just working around what it happened to call. Neither issue was
/// caught by `cargo test` because `#[wasm_bindgen]` is a no-op off the `wasm32` target, so these
/// functions were only ever exercised as plain native Rust before this story, never through the
/// actual compiled `.wasm` binary a browser (or `vite-plugin-wasm` in Vitest) runs.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    // `Future` (needed for `.poll()` below) is already in scope via `wasm_bindgen::prelude::*`.
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable's clone/wake/wake_by_ref/drop are all no-ops that never dereference
    // the null data pointer, so this waker is sound to construct and use for a single poll.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!(
            "core_bindings_wasm::block_on: future was not ready on its first poll — this \
             facade only drives synchronous in-memory session operations, never real async I/O"
        ),
    }
}

impl From<SessionError> for WasmError {
    fn from(err: SessionError) -> Self {
        // `PreKey(_)` (prekey generation/store failure) and a rejected signed-prekey/Kyber
        // signature during establishment both name the prekey material as the culprit, so both
        // surface as kind = "PreKey" — distinct from other establishment/encrypt/decrypt
        // failures, which stay kind = "Session". See `establish_session_from_bundle`'s doc
        // comment for the contract this fulfills.
        let kind = if matches!(err, SessionError::PreKey(_)) || err.is_prekey_signature_invalid() {
            "PreKey"
        } else {
            "Session"
        };
        WasmError::new(kind, &err.to_string())
    }
}

impl From<FanoutError> for WasmError {
    fn from(err: FanoutError) -> Self {
        // `IdentityMismatch` is the security-relevant case — the bundle's identity key is not
        // the one the caller vouched for, so the device is not who it claims to be — and
        // `NoDevices` is a caller-input error; both get their own kind so JS can switch on
        // them. Everything else (establishment/encrypt failure for a named device) stays
        // kind = "Fanout".
        let kind = match err {
            FanoutError::NoDevices => "NoDevices",
            FanoutError::IdentityMismatch { .. } => "IdentityMismatch",
            _ => "Fanout",
        };
        WasmError::new(kind, &err.to_string())
    }
}

impl From<std::io::Error> for WasmError {
    fn from(err: std::io::Error) -> Self {
        // Map PermissionDenied (non-member / removed-member) to a distinct kind so JS can
        // switch on it; everything else is a generic Group error.
        let kind = if err.kind() == std::io::ErrorKind::PermissionDenied {
            "NotMember"
        } else {
            "Group"
        };
        WasmError::new(kind, &err.to_string())
    }
}

/// An opaque handle to an established PQXDH session. Wraps the real Rust session state —
/// wasm-bindgen passes struct instances by value/reference directly, no serialization step.
#[wasm_bindgen]
pub struct SessionHandle {
    inner: DoubleRatchetSession,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle").finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl SessionHandle {
    // The session handle is opaque to JS — no getter methods are exposed. The handle exists
    // so session establishment returns a concrete typed value JS can hold and pass back, not a
    // raw JsValue. Encrypt/decrypt are free functions below that take &mut SessionHandle.
}

// ---------------------------------------------------------------------------
// Receiver session creation
// ---------------------------------------------------------------------------

/// Construct a receiver (Bob) session from an identity keypair. The receiver publishes a
/// prekey bundle (via [`publish_bundle_bytes`]) and then accepts inbound messages via
/// [`decrypt_message`]. This is the counterpart to [`establish_session_from_bundle`], which
/// constructs a sender (Alice) session.
///
/// # Errors
///
/// Returns `WasmError` if prekey generation or store initialization fails. In practice this
/// never happens with a freshly generated identity, but the error path is wired so a failure
/// surfaces as a structured error, never a panic.
#[wasm_bindgen]
pub fn create_receiver_session(
    identity_handle: &IdentityHandle,
) -> Result<SessionHandle, WasmError> {
    let session = block_on(async {
        DoubleRatchetSession::new_bob(identity_handle.inner.as_libsignal())
            .await
            .map_err(WasmError::from)
    })?;

    Ok(SessionHandle { inner: session })
}

/// Serialize the prekey bundle from an established receiver (Bob) session to a self-delimiting
/// byte vector. The bundle is generated from the *same* session state that will later decrypt
/// messages — so a sender who establishes from these bytes and encrypts will produce envelopes
/// this session can decrypt. Use [`generate_prekey_bundle`] when you only need the bundle bytes
/// (the receiver session is not retained); use this when you need both the bundle and the
/// session handle for a full encrypt/decrypt round-trip.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the session is not a publisher (i.e. it was
/// constructed as a sender via [`establish_session_from_bundle`]) or if serialization fails.
/// Never panics.
#[wasm_bindgen]
pub fn publish_bundle_bytes(session: &SessionHandle) -> Result<Vec<u8>, WasmError> {
    let bundle = session.inner.publish_bundle().map_err(WasmError::from)?;
    session::bundle_to_bytes(&bundle).map_err(|e| WasmError::new("PreKey", &e.to_string()))
}

// ---------------------------------------------------------------------------
// Double Ratchet encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` on an established sender (Alice) session, returning the self-describing
/// wire envelope (sender hash + type tag + raw ciphertext). The session state is advanced
/// (ratcheted) as part of encryption.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the session is receiver-only (no remote
/// address to encrypt to) or if the Double Ratchet encryption fails. Never panics.
#[wasm_bindgen]
pub fn encrypt_message(
    session: &mut SessionHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    block_on(async {
        session
            .inner
            .encrypt(plaintext)
            .await
            .map_err(WasmError::from)
    })
}

/// Decrypt a self-describing wire envelope on a receiver (Bob) session, returning the plaintext.
/// Fails closed on any malformed envelope, identity-hash mismatch, missing session, untrusted
/// identity, or MAC/AEAD authentication failure — no plaintext is produced on error.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the envelope is malformed/truncated, the
/// sender hash does not match the bound identity, no session exists for the sender, or AEAD
/// authentication fails (tampered ciphertext). Never panics.
#[wasm_bindgen]
pub fn decrypt_message(session: &mut SessionHandle, envelope: &[u8]) -> Result<Vec<u8>, WasmError> {
    block_on(async {
        session
            .inner
            .decrypt(envelope)
            .await
            .map_err(WasmError::from)
    })
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// An opaque handle to a Curve25519 identity keypair, exactly like the existing pattern.
/// Private fields are not visible to JS; only the `#[wasm_bindgen]` methods are.
#[wasm_bindgen]
pub struct IdentityHandle {
    inner: IdentityKeyPair,
}

#[wasm_bindgen]
impl IdentityHandle {
    /// Return the public identity key bytes (33-byte compressed Curve25519 key).
    pub fn public_bytes(&self) -> Vec<u8> {
        self.inner.public().to_bytes()
    }

    /// Serialize the full keypair (public + private) to a self-delimiting byte
    /// vector, suitable for encrypted persistence across sessions.
    ///
    /// The format is libsignal's `IdentityKeyPairStructure` protobuf (see
    /// `libsignal_protocol::IdentityKeyPair::serialize`). The same bytes are
    /// deserialized by [`identity_from_bytes`].
    ///
    /// **Security:** these bytes contain the private key. Callers must only
    /// store them via an encrypted-at-rest mechanism (e.g. `StorageGate`).
    pub fn private_bytes(&self) -> Vec<u8> {
        self.inner.as_libsignal().serialize().to_vec()
    }
}

/// Generate a fresh identity keypair from the OS CSPRNG.
#[wasm_bindgen]
pub fn generate_identity() -> IdentityHandle {
    IdentityHandle {
        inner: IdentityKeyPair::generate(),
    }
}

/// Deserialize an identity keypair from the byte vector produced by
/// [`IdentityHandle::private_bytes`] (libsignal's `IdentityKeyPairStructure`
/// protobuf).  This is the inverse of `private_bytes` and is used to restore
/// a persisted identity across sessions.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Identity"` if the bytes are truncated,
/// malformed, or otherwise unparseable.  Never panics.
#[wasm_bindgen]
pub fn identity_from_bytes(bytes: &[u8]) -> Result<IdentityHandle, WasmError> {
    let keypair = IdentityKeyPair::from_bytes(bytes)
        .map_err(|e| WasmError::new("Identity", &e.to_string()))?;
    Ok(IdentityHandle { inner: keypair })
}

// ---------------------------------------------------------------------------
// Prekey bundle generation
// ---------------------------------------------------------------------------

/// Generate a PQXDH prekey bundle for the identity behind `identity_handle` and serialize it
/// to a self-delimiting byte vector (see `crypto::session::bundle_to_bytes`).
///
/// The bundle includes the identity key, a signed prekey, a Kyber KEM prekey, and a one-time
/// prekey. The byte format is an internal length-prefixed concatenation — it does NOT match
/// the `/spec` protobuf wire format (which carries transport-layer fields this struct excludes).
///
/// # Errors
///
/// Returns `WasmError` if prekey generation or serialization fails. In practice this never
/// happens with a freshly generated identity, but the error path is wired so a failure
/// surfaces as a structured error, never a panic.
#[wasm_bindgen]
pub fn generate_prekey_bundle(identity_handle: &IdentityHandle) -> Result<Vec<u8>, WasmError> {
    // Build a receiver (Bob) session — this generates signed/Kyber/one-time prekeys and
    // publishes a bundle. We then serialize that bundle to bytes.
    let bundle_bytes = block_on(async {
        let bob = DoubleRatchetSession::new_bob(identity_handle.inner.as_libsignal())
            .await
            .map_err(WasmError::from)?;
        let bundle = bob.publish_bundle().map_err(WasmError::from)?;
        session::bundle_to_bytes(&bundle).map_err(|e| WasmError::new("PreKey", &e.to_string()))
    })?;

    Ok(bundle_bytes)
}

// ---------------------------------------------------------------------------
// Session establishment from a peer's bundle bytes
// ---------------------------------------------------------------------------

/// Deserialize a peer's prekey bundle from `bundle_bytes`, verify the signed-prekey signature
/// against the bundle's identity key, and establish a PQXDH session — returning an opaque
/// `SessionHandle`.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "MalformedBundle"` if the bytes are truncated, mis-length-
/// prefixed, or structurally invalid. Returns `WasmError` with `kind = "PreKey"` if the
/// signed-prekey signature does not verify (tampered or unsigned bundle). Returns
/// `WasmError` with `kind = "Session"` if PQXDH session establishment fails. Never panics.
#[wasm_bindgen]
pub fn establish_session_from_bundle(
    identity_handle: &IdentityHandle,
    bundle_bytes: &[u8],
) -> Result<SessionHandle, WasmError> {
    // 1. Deserialize the bundle bytes — fail closed on any structural issue.
    let bundle = session::bundle_from_bytes(bundle_bytes).map_err(|_| {
        WasmError::new(
            "MalformedBundle",
            "malformed or truncated prekey bundle bytes",
        )
    })?;

    // 2. Establish the PQXDH session. `process_prekey_bundle` (called inside `new_alice`)
    //    verifies the signed-prekey and Kyber-prekey signatures against the bundle's identity
    //    key — a tampered or unsigned bundle fails closed here before any session state is
    //    written.
    let session = block_on(async {
        DoubleRatchetSession::new_alice(identity_handle.inner.as_libsignal(), &bundle)
            .await
            .map_err(WasmError::from)
    })?;

    Ok(SessionHandle { inner: session })
}

/// Extract the peer's public identity key bytes from a serialized prekey bundle, without
/// establishing a session. Callers that need the remote identity key for safety-number
/// derivation (e.g. [`derive_safety_number`]) alongside session establishment use this
/// read-only accessor over the same bundle bytes passed to [`establish_session_from_bundle`].
///
/// The returned bytes are the 33-byte serialized `IdentityKey` — the same format
/// [`IdentityHandle::public_bytes`] returns, so the result can be passed directly to
/// [`derive_safety_number`].
///
/// # Errors
///
/// Returns `WasmError` with `kind = "MalformedBundle"` if the bytes are truncated, mis-length-
/// prefixed, or structurally invalid. Never panics. Does not verify the bundle's signatures —
/// callers that need the signature-verified identity key should rely on
/// [`establish_session_from_bundle`] succeeding first.
#[wasm_bindgen]
pub fn bundle_identity_key_bytes(bundle_bytes: &[u8]) -> Result<Vec<u8>, WasmError> {
    let bundle = session::bundle_from_bytes(bundle_bytes).map_err(|_| {
        WasmError::new(
            "MalformedBundle",
            "malformed or truncated prekey bundle bytes",
        )
    })?;
    let identity_key = bundle
        .identity_key()
        .map_err(|e| WasmError::new("MalformedBundle", &e.to_string()))?;
    Ok(identity_key.serialize().to_vec())
}

// ---------------------------------------------------------------------------
// Malformed-prekey contract test (mirrors desktop's establish_with_malformed_prekey)
// ---------------------------------------------------------------------------

/// Deliberately attempt PQXDH session establishment against a bundle with a tampered
/// signed-prekey signature, and return the resulting `Err` rather than panicking.
///
/// Mirrors `core_crypto::session::establish_with_malformed_prekey` and desktop's
/// `establish_malformed_session` command — the "a malformed core input surfaces as a defined
/// error state, not a crash" contract, exercised from the WASM boundary.
#[wasm_bindgen]
pub fn establish_with_malformed_prekey() -> Result<(), WasmError> {
    crypto::session::establish_with_malformed_prekey().map_err(WasmError::from)
}

// ---------------------------------------------------------------------------
// Browser threat model (unchanged from the original API)
// ---------------------------------------------------------------------------

/// The browser's key-storage security model, as distinct from a native client's.
///
/// A native client (desktop/iOS/Android) can rely on OS-level secure storage (Keychain,
/// Keystore, or at minimum a file the OS sandboxes per-app). A browser has no equivalent: an
/// identity private key generated in WASM either lives in JS-heap memory for the tab's
/// lifetime, or is persisted via IndexedDB/WebCrypto's non-extractable-key storage — neither
/// of which is backed by a secure enclave, and both are reachable by any other code that
/// achieves script execution in the same origin (e.g. a supply-chain-compromised dependency,
/// or an XSS if the app has that class of bug). This is a real, documented reduction in the
/// threat model relative to native clients, not a WASM implementation detail to paper over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserThreatModel {
    ReducedKeyStorage,
}

impl BrowserThreatModel {
    pub fn docs(&self) -> &'static str {
        match self {
            BrowserThreatModel::ReducedKeyStorage => {
                "Browser clients have no secure enclave. Identity and session key material \
                 is stored via IndexedDB / WebCrypto non-extractable keys, which protects \
                 against casual extraction but not against a same-origin script-execution \
                 compromise (e.g. a malicious dependency or XSS). This is a reduced \
                 key-storage security model compared to native clients, which can rely on \
                 OS-level secure storage (Keychain/Keystore). Users on browser clients should \
                 be informed of this reduced guarantee, particularly for long-lived identity \
                 keys."
            }
        }
    }
}

pub fn document_browser_threat_model() -> BrowserThreatModel {
    BrowserThreatModel::ReducedKeyStorage
}

// ---------------------------------------------------------------------------
// Sender Keys group encrypt/decrypt (PLAN.md Phase 8 — follow-on story)
//
// Thin WASM facade over `protocol::group::GroupSession`. No cryptography is
// implemented here — every function delegates to the core implementation. All
// error paths surface as a structured `WasmError` (kind + message), never a
// panic across the WASM boundary.
// ---------------------------------------------------------------------------

/// An opaque handle to a Sender Keys group session. Wraps the real Rust
/// `GroupSession` state — wasm-bindgen passes struct instances by reference,
/// no serialization step. JS code creates one via [`group_create`], mutates
/// membership via [`group_add_member`]/[`group_remove_member`], and
/// encrypts/decrypts via [`group_encrypt`]/[`group_decrypt`].
#[wasm_bindgen]
pub struct GroupHandle {
    inner: GroupSession,
}

impl std::fmt::Debug for GroupHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupHandle").finish_non_exhaustive()
    }
}

/// Create a new Sender Keys group session with the given sender identity. The
/// sender's public key seeds the initial chain key (see `GroupSession::new`).
///
/// The returned `GroupHandle` has no members yet — call [`group_add_member`]
/// before [`group_encrypt`] so the ciphertext carries per-member sealed
/// wrappers that members can open.
#[wasm_bindgen]
pub fn group_create(sender: &IdentityHandle) -> GroupHandle {
    GroupHandle {
        inner: GroupSession::new(sender.inner.public()),
    }
}

/// Add a member to the group by their public identity key bytes (33-byte
/// compressed Curve25519 key, as returned by `IdentityHandle::public_bytes`).
///
/// Returns a new `GroupHandle` — `GroupSession::add_member` consumes `self`
/// and returns a new session, so the caller must use the returned handle for
/// subsequent operations.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Group"` if the member key bytes are
/// malformed (the core `seal` call during encrypt will reject them). Never
/// panics.
#[wasm_bindgen]
pub fn group_add_member(group: &GroupHandle, member_pub_bytes: &[u8]) -> GroupHandle {
    // Clone the inner session and add the member. GroupSession::add_member
    // takes `self` by value, so we clone first (GroupSession derives Clone).
    let pubkey = PublicIdentityKey::from_bytes(member_pub_bytes);
    let new_session = group.inner.clone().add_member(GroupMember(pubkey));
    GroupHandle { inner: new_session }
}

/// Remove a member from the group and rotate the sender key in the same
/// operation — so the removal is forward-secure by default (the removed member
/// cannot decrypt any message sent afterward, even with the old chain key).
///
/// Returns a new `GroupHandle` with the member removed and the chain key
/// rotated to a fresh CSPRNG value.
///
/// # Errors
///
/// Never returns `Err` — removal of a non-existent member is a no-op (the
/// core `retain` simply doesn't match). The function signature returns
/// `GroupHandle` directly (not `Result`) to match the core API's infallible
/// `remove_member`.
#[wasm_bindgen]
pub fn group_remove_member(group: &GroupHandle, member_pub_bytes: &[u8]) -> GroupHandle {
    let pubkey = PublicIdentityKey::from_bytes(member_pub_bytes);
    // remove_member internally rotates the sender key — see GroupSession::remove_member.
    let new_session = group.inner.clone().remove_member(GroupMember(pubkey));
    GroupHandle { inner: new_session }
}

/// Encrypt `plaintext` as the sender, returning the self-describing wire
/// ciphertext (nonce | payload_len | AES-GCM payload | wrapper_count |
/// per-member sealed wrappers). The session's chain key is ratcheted forward
/// on every call, so no two messages reuse the same (key, nonce) pair.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Group"` if the group exceeds the
/// 255-member wire-format limit, or if sealing the per-message key to a
/// member fails (malformed member key). Never panics.
#[wasm_bindgen]
pub fn group_encrypt(
    group: &GroupHandle,
    sender: &IdentityHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    group
        .inner
        .encrypt_as(&sender.inner, plaintext)
        .map_err(WasmError::from)
}

/// Decrypt `ciphertext` as the given member identity. Finds the wrapper
/// addressed to the member, unseals it with the member's private identity key
/// to recover the per-message key, then decrypts the AES-GCM payload.
///
/// Fails closed on any malformed ciphertext, missing wrapper (non-member),
/// or AEAD authentication failure — no plaintext is produced on error.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "NotMember"` if the caller is not a group
/// member (no wrapper addressed to them, or they hold no private key to open
/// it). Returns `WasmError` with `kind = "Group"` if the ciphertext is
/// malformed/truncated or AEAD authentication fails (tampered ciphertext).
/// Never panics.
#[wasm_bindgen]
pub fn group_decrypt(
    group: &GroupHandle,
    member: &IdentityHandle,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WasmError> {
    group
        .inner
        .decrypt_as(&member.inner, ciphertext)
        .map_err(WasmError::from)
}

// ---------------------------------------------------------------------------
// Safety-number / fingerprint derivation
// ---------------------------------------------------------------------------

/// Derive a human-readable safety number (fingerprint) from two parties'
/// serialized public identity key bytes.
///
/// Each `&[u8]` argument must be a 33-byte serialized `IdentityKey` (one key-type
/// tag byte followed by 32 key bytes), as returned by
/// [`IdentityHandle::public_bytes`]. The returned string is the display-formatted
/// safety number that both parties can compare out-of-band to detect
/// man-in-the-middle or QR-substitution attacks.
///
/// The derivation is deterministic: the same two key-pair inputs always produce
/// the same safety number string. The result is symmetric — swapping the two
/// arguments yields the same value.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "SafetyNumber"` if either key slice is
/// malformed or has the wrong length (not a decodable `IdentityKey`). Never
/// panics — all error paths surface as a structured `WasmError`.
#[wasm_bindgen]
pub fn derive_safety_number(local_key: &[u8], remote_key: &[u8]) -> Result<String, WasmError> {
    device_qr::safety_number_for_display(local_key, remote_key)
        .map_err(|e| WasmError::new("SafetyNumber", &e.to_string()))
}

// ---------------------------------------------------------------------------
// QR device-linking: encode / decode
// ---------------------------------------------------------------------------

/// Encode a device's identity public key bytes as a QR code payload string
/// (hex-encoded key bytes). The returned string is the exact data a QR code
/// scanner would read when scanning a QR code rendered from this payload.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "QrEncode"` if the bytes cannot be
/// represented as a valid QR code payload.
#[wasm_bindgen]
pub fn encode_device_qr(identity_public_key_bytes: &[u8]) -> Result<String, WasmError> {
    device_qr::encode_device_qr(identity_public_key_bytes)
        .map_err(|e| WasmError::new("QrEncode", &e.to_string()))
}

/// Decode a scanned QR code payload string back to raw identity public key
/// bytes. The payload must be the hex string returned by
/// [`encode_device_qr`].
///
/// # Errors
///
/// Returns `WasmError` with `kind = "QrDecode"` if the payload contains
/// non-hex characters, has odd length, or does not decode to exactly 33
/// bytes (the serialized identity key length). This is the fail-closed
/// boundary: any malformed or tampered payload is rejected.
#[wasm_bindgen]
pub fn decode_device_qr(qr_payload: &str) -> Result<Vec<u8>, WasmError> {
    device_qr::decode_device_qr(qr_payload).map_err(|e| WasmError::new("QrDecode", &e.to_string()))
}

// ---------------------------------------------------------------------------
// Session / group state persistence (NS-5D)
// ---------------------------------------------------------------------------

/// Serialize an established session to a self-contained byte blob that
/// [`session_from_bytes`] can restore, given the same local identity the session was created
/// with. The blob is the inverse of [`session_from_bytes`] and lets a client resume a
/// conversation across a reload without re-running PQXDH.
///
/// **Security:** the returned bytes contain **secret ratchet state** (the libsignal
/// `SessionRecord`, including chain keys, and for a receiver the prekey private material). The
/// CALLER MUST encrypt them at rest before persisting them — the web client's `StorageGate`
/// does. Never log or `Debug`-print the blob or any key material.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the session is neither a sender with an
/// outbound session nor a receiver holding prekeys, or if serialization fails. Never panics.
#[wasm_bindgen]
pub fn session_to_bytes(session: &SessionHandle) -> Result<Vec<u8>, WasmError> {
    block_on(async { session.inner.to_bytes().await.map_err(WasmError::from) })
}

/// Restore a session from the blob produced by [`session_to_bytes`], using the local identity
/// keypair the session was created with. The identity is required because the blob deliberately
/// excludes it (data minimization), so the caller must supply it from its own encrypted store.
///
/// Fails closed: any malformed, truncated, over-long, unknown-version, or wrong-identity input
/// returns `Err` and no partially restored session is ever returned.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Session"` if the bytes are empty, truncated, carry an
/// unknown version, contain trailing bytes, or were produced under a different identity. Never
/// panics.
#[wasm_bindgen]
pub fn session_from_bytes(
    identity_handle: &IdentityHandle,
    bytes: &[u8],
) -> Result<SessionHandle, WasmError> {
    let session = block_on(async {
        DoubleRatchetSession::from_bytes(identity_handle.inner.as_libsignal(), bytes)
            .await
            .map_err(WasmError::from)
    })?;

    Ok(SessionHandle { inner: session })
}

/// Serialize a Sender Keys group session to a self-contained byte blob that
/// [`group_from_bytes`] can restore. A restored group continues from the current chain-key
/// position instead of replaying keys already used.
///
/// **Security:** the returned bytes contain **secret ratchet state** (the group chain key,
/// copied verbatim). The CALLER MUST encrypt them at rest before persisting them — the web
/// client's `StorageGate` does. Never log or `Debug`-print the blob or any key material.
#[wasm_bindgen]
pub fn group_to_bytes(group: &GroupHandle) -> Vec<u8> {
    group.inner.to_bytes()
}

/// Restore a group session from the blob produced by [`group_to_bytes`].
///
/// Fails closed: every malformed, truncated, or over-long input returns `Err` and no partially
/// restored group is ever returned.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Group"` if the bytes are empty, truncated, carry an
/// unknown version, declare a segment longer than the bytes remaining, or contain trailing
/// bytes. Never panics.
#[wasm_bindgen]
pub fn group_from_bytes(bytes: &[u8]) -> Result<GroupHandle, WasmError> {
    let session = GroupSession::from_bytes(bytes).map_err(WasmError::from)?;

    Ok(GroupHandle { inner: session })
}

// ---------------------------------------------------------------------------
// Sender-side fan-out (DR-5)
// ---------------------------------------------------------------------------

/// One recipient device's public material, as supplied by the caller.
///
/// `expected_identity_key_bytes` is the device's identity key as vouched for by an
/// authenticated source — the primary-signed device list (spec/v0.md §8.3) — and NOT the
/// identity key carried inside `bundle_bytes`. [`fanout_establish`] compares the two and
/// rejects the device on a mismatch, so an attacker-substituted bundle (own identity key,
/// valid self-signatures) cannot silently redirect ciphertext.
///
/// This is a struct rather than a `(u32, Vec<u8>, Vec<u8>)` tuple because wasm-bindgen has
/// no ABI representation for tuples: `Vec<T>` requires `T: VectorIntoWasmAbi`/
/// `VectorFromWasmAbi`, implemented for primitives, `String`, `JsValue`, and
/// `#[wasm_bindgen]` structs — not tuples. JS passes an array of these objects.
#[wasm_bindgen]
pub struct FanoutDeviceInput {
    device_id: u32,
    expected_identity_key_bytes: Vec<u8>,
    bundle_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl FanoutDeviceInput {
    /// Build one recipient entry: the device id, the identity key bytes the caller vouches
    /// for from the authenticated device list, and the device's serialized prekey bundle.
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_id: u32,
        expected_identity_key_bytes: Vec<u8>,
        bundle_bytes: Vec<u8>,
    ) -> FanoutDeviceInput {
        FanoutDeviceInput {
            device_id,
            expected_identity_key_bytes,
            bundle_bytes,
        }
    }

    /// The device id this entry establishes a session for.
    #[wasm_bindgen(getter)]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// The identity key bytes the caller vouches for (from the authenticated device list).
    #[wasm_bindgen(getter)]
    pub fn expected_identity_key_bytes(&self) -> Vec<u8> {
        self.expected_identity_key_bytes.clone()
    }

    /// The device's serialized prekey bundle bytes.
    #[wasm_bindgen(getter)]
    pub fn bundle_bytes(&self) -> Vec<u8> {
        self.bundle_bytes.clone()
    }
}

impl std::fmt::Debug for FanoutDeviceInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omits the identity/bundle bytes: they are public key material, but
        // this project keeps key bytes out of logs regardless of their sensitivity.
        f.debug_struct("FanoutDeviceInput")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// One recipient's encrypted envelope, as returned by [`fanout_encrypt`].
#[wasm_bindgen]
pub struct FanoutEnvelope {
    device_id: u32,
    envelope: Vec<u8>,
}

#[wasm_bindgen]
impl FanoutEnvelope {
    /// The device this envelope is destined for.
    #[wasm_bindgen(getter)]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// The self-describing wire envelope to relay to that device.
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.envelope.clone()
    }
}

impl std::fmt::Debug for FanoutEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanoutEnvelope")
            .field("device_id", &self.device_id)
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// An opaque handle to a sender-side fan-out session. Wraps the real Rust `FanoutSession`
/// state — wasm-bindgen passes struct instances by reference, no serialization step. JS code
/// creates one via [`fanout_establish`], reads the recipient set via [`fanout_devices`],
/// removes a device via [`fanout_remove_device`], and encrypts via [`fanout_encrypt`].
///
/// The handle is stateful: [`fanout_remove_device`] mutates the session it holds, so a
/// subsequent [`fanout_devices`]/[`fanout_encrypt`] on the same handle reflects the removal.
#[wasm_bindgen]
pub struct FanoutHandle {
    inner: FanoutSession,
}

impl std::fmt::Debug for FanoutHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanoutHandle").finish_non_exhaustive()
    }
}

/// Build a sender-side fan-out session from public device material — bytes in, so the caller
/// needs no private keys.
///
/// Each entry carries `(device_id, expected_identity_key_bytes, bundle_bytes)`. The expected
/// identity key is an EXPLICIT input and is never read from the bundle being verified: PQXDH
/// only checks a bundle against the identity key carried inside it (self-consistency, not
/// authenticity), so deriving the expectation from the bundle would make the check a no-op
/// and let an attacker-substituted bundle establish cleanly. The caller supplies the
/// expectation from the primary-signed verified device set (spec/v0.md §8.3).
///
/// # Errors
///
/// Returns `WasmError` with `kind = "NoDevices"` for an empty device list, `kind =
/// "MalformedIdentityKey"` for unparseable expected-identity bytes, `kind = "MalformedBundle"`
/// for unparseable bundle bytes, `kind = "IdentityMismatch"` when a bundle's identity key is
/// not the expected one (checked before any session is built), and `kind = "Fanout"` for any
/// other establishment failure. Never panics.
#[wasm_bindgen]
pub fn fanout_establish(
    identity_handle: &IdentityHandle,
    devices: Vec<FanoutDeviceInput>,
) -> Result<FanoutHandle, WasmError> {
    if devices.is_empty() {
        return Err(WasmError::new(
            "NoDevices",
            "fan-out requires at least one recipient device",
        ));
    }

    let mut parsed = Vec::with_capacity(devices.len());
    for device in devices {
        // The expected identity comes from the caller's authenticated device list — never
        // from `bundle.identity_key()`. `establish_from_bundles` compares it against the
        // bundle's own identity key before building any session.
        let expected = IdentityKey::decode(&device.expected_identity_key_bytes).map_err(|_| {
            WasmError::new(
                "MalformedIdentityKey",
                "malformed expected identity key bytes",
            )
        })?;
        let bundle = session::bundle_from_bytes(&device.bundle_bytes).map_err(|_| {
            WasmError::new(
                "MalformedBundle",
                "malformed or truncated prekey bundle bytes",
            )
        })?;
        parsed.push((DeviceId(device.device_id), expected, bundle));
    }

    let session =
        FanoutSession::establish_from_bundles(identity_handle.inner.as_libsignal(), &parsed)
            .map_err(WasmError::from)?;

    Ok(FanoutHandle { inner: session })
}

/// The device ids currently tracked by this fan-out, ascending.
///
/// This is the observable recipient set: after [`fanout_remove_device`] the removed device is
/// absent and the survivors are still present.
#[wasm_bindgen]
pub fn fanout_devices(handle: &FanoutHandle) -> Vec<u32> {
    handle.inner.devices().map(|device| device.0).collect()
}

/// Remove a device from this fan-out, mutating the session the handle holds.
///
/// Removing a device that is not tracked is a no-op that still returns `Ok(())` — the
/// post-condition ("this device is not a recipient") holds either way. The next
/// [`fanout_encrypt`] emits nothing for the removed device.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Fanout"` if the removal fails. Never panics.
#[wasm_bindgen]
pub fn fanout_remove_device(handle: &mut FanoutHandle, device_id: u32) -> Result<(), WasmError> {
    handle
        .inner
        .remove_device(DeviceId(device_id))
        .map_err(WasmError::from)
}

/// Encrypt `plaintext` once per currently-tracked device, returning one [`FanoutEnvelope`] per
/// surviving recipient — nothing for a device that has been removed.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "Fanout"` if the Double Ratchet encrypt step fails for a
/// device. Never panics.
#[wasm_bindgen]
pub fn fanout_encrypt(
    handle: &mut FanoutHandle,
    plaintext: &[u8],
) -> Result<Vec<FanoutEnvelope>, WasmError> {
    let ciphertexts = handle
        .inner
        .encrypt_to_all(plaintext)
        .map_err(WasmError::from)?;

    Ok(ciphertexts
        .into_iter()
        .map(|ciphertext| FanoutEnvelope {
            device_id: ciphertext.device.0,
            envelope: ciphertext.envelope,
        })
        .collect())
}
