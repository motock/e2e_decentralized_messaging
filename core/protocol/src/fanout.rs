//! Per-device session fan-out for 1:1 messaging (PLAN.md Phase 6).
//!
//! A multi-device recipient (e.g. the same user on phone, laptop, and a tablet) is associated
//! with several `DeviceId`s, each carrying its own Curve25519 identity key and PQXDH prekey
//! bundle. To send a single logical 1:1 message to that user, the sender establishes and
//! maintains a **separate** Double Ratchet session per linked device and emits one
//! ciphertext per device. Each device decrypts its own ciphertext with the ratchet session
//! its own identity participates in; no device can read another device's ciphertext.
//!
//! This module is a thin coordinator over [`crypto::DoubleRatchetSession`]. It does **not**
//! reimplement any cryptography, and it does **not** share key material across devices — the
//! ratchet state for device N is the ratchet state between `sender` and `recipient_n`'s
//! identity, full stop. Removing a device simply drops its ratchet state so the next
//! `encrypt_to_all` no longer produces a ciphertext for it.
//!
//! # Lifetime
//!
//! `FanoutSession` is in-memory. Persisting fan-out state across restarts is the storage
//! story's job; the public API here matches the test surface (PLAN.md Phase 6 acceptance
//! file `core/protocol/tests/per_device_fanout.rs`).
//!
//! # Security posture
//!
//! - **Per-device session isolation.** Each device is its own PQXDH + Double Ratchet
//!   session. Compromise of one device's ratchet state does not leak another device's
//!   plaintext past the ratchet forward-secrecy guarantees of `libsignal`.
//! - **No plaintext is dropped or logged.** The fan-out only emits ciphertexts; it does
//!   not store or print the input plaintext at any point.
//! - **Removal is local.** `remove_device` drops the sender's outbound ratchet state for
//!   that device; the recipient device's own ratchet state on its own device is
//!   unaffected. Future messages from the sender simply stop targeting it. This is the
//!   behaviour PLAN.md §4 ("Multi-device") requires for device revocation.
//! - **Revocation is verifiable.** Alongside the local drop, `apply_revocation` accepts a
//!   `SignedRevocation` — a primary-signed, monotonically versioned device-list update
//!   (spec/v0.md §8) — and acts on it only after verifying the signature against the
//!   account primary's public identity key. The local shortcut and the verifiable path
//!   coexist; neither replaces the other.
//! - **No cross-device key reuse.** A device's identity is used exactly as the
//!   `DoubleRatchetSession` facade expects: as the bundle signatory on the receive side
//!   and as the addressable peer on the send side. There is no shared symmetric key
//!   between any two devices.

use std::collections::BTreeMap;

use libsignal_protocol::IdentityKeyPair;
use rand::TryRngCore;
use thiserror::Error;

use crypto::{DoubleRatchetSession, IdentityKeyPairExt};

/// Drive an async future to completion, regardless of what runtime (if any) is active
/// on the calling thread.
///
/// `DoubleRatchetSession`'s PQXDH establishment and Double Ratchet encrypt/decrypt are
/// async over the `libsignal` in-memory session store, but that store does no I/O and
/// uses no tokio-specific primitives, so every future here resolves on its very first
/// poll — it never actually suspends. The fan-out API is sync (the acceptance test in
/// `tests/per_device_fanout.rs` does not `.await`), so we need to drive these futures
/// to completion without an `.await` point of our own.
///
/// An earlier version of this helper tried to detect and special-case "is a tokio
/// runtime active on this thread, and if so which flavor" using `tokio::runtime::Handle`
/// — that approach panicked when called from inside a tokio *current-thread* runtime
/// (`Handle::block_on` cannot block the very thread already driving that runtime: "Cannot
/// start a runtime from within a runtime"). `futures_executor::block_on` sidesteps the
/// problem entirely: it is a minimal, dependency-free poll loop that never touches
/// tokio's thread-local runtime-context tracking, so it works identically whether the
/// calling thread has no runtime, a tokio current-thread runtime, or is a tokio
/// multi-thread worker thread — there is nothing to conflict with. Because the futures
/// polled here never truly suspend, this never parks the calling thread for longer than
/// the crypto operation itself takes, so it cannot starve a surrounding tokio runtime's
/// other tasks.
///
/// Safety of blocking while borrowing `&mut`: the fan-out methods *do* hold a `&mut`
/// session (or `&mut self`) across this call, but `futures_executor::block_on` runs
/// entirely on the calling thread with no concurrency of its own — the borrow is never
/// shared with or handed to another thread, so there is no reentrancy or data race.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_executor::block_on(fut)
}

/// Stable, application-defined identifier for one of a recipient user's linked devices.
///
/// `DeviceId` is opaque to this module — it is used as a key in the per-fanout device
/// table and round-tripped to the caller in `encrypt_to_all`'s output. The underlying
/// `libsignal` device id used inside each ratchet session is fixed by
/// `DoubleRatchetSession` (a single device per facade instance) and is *not* the same
/// number as this `DeviceId`; the ratchet session is the per-device keying relationship,
/// this `DeviceId` is the application-level index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u32);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device:{}", self.0)
    }
}

/// A single ciphertext targeted at one device, plus the device it is for.
///
/// The ratchet envelope bytes are opaque to callers — the recipient's
/// `DoubleRatchetSession::decrypt` consumes them. The `device` field is included so a
/// transport layer can route the envelope to the right linked device without having to
/// inspect ciphertext internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// The device this envelope is for.
    pub device: DeviceId,
    /// Opaque ratchet envelope bytes — feed them to the recipient-side
    /// `DoubleRatchetSession::decrypt` of the device that matches `device`.
    pub envelope: Vec<u8>,
}

/// Errors a `FanoutSession` can surface to its caller.
///
/// `Establishment`/`Encrypt`/`Decrypt`'s `Display` forwards the wrapped
/// `crypto::SessionError`'s detail (which in turn forwards libsignal-internal detail).
/// That's appropriate for local structured logging, but per this project's Secure by
/// Design standard, callers that relay these errors across a network trust boundary
/// (e.g. to a peer or over an API response) must not forward the `Display` text
/// verbatim — return a generic reason to the peer and log the full detail server-side.
#[derive(Debug, Error)]
pub enum FanoutError {
    /// The recipient list contained a duplicate `DeviceId`. Each device must be unique
    /// within a single fan-out; otherwise the fan-out is ambiguous.
    #[error("duplicate device id {0} in recipient list")]
    DuplicateDevice(DeviceId),
    /// Two different `DeviceId`s were given the same recipient identity key. Each device
    /// must carry its own identity; the carried `DeviceId` is the one the identity was
    /// already linked to.
    #[error("recipient identity already linked to device {0}")]
    DuplicateIdentity(DeviceId),
    /// The recipient list was empty. A fan-out with zero targets is meaningless and is
    /// rejected up front so the caller doesn't get back an empty ciphertext list that
    /// looks like a successful no-op send.
    #[error("fan-out recipient list must contain at least one device")]
    NoDevices,
    /// PQXDH session establishment (`DoubleRatchetSession::new_alice`) failed for one of
    /// the recipient devices — typically a malformed or tampered prekey bundle.
    #[error("session establishment failed for device {0}: {1}")]
    Establishment(DeviceId, crypto::SessionError),
    /// The Double Ratchet encrypt step failed for a specific device.
    #[error("encrypt failed for device {0}: {1}")]
    Encrypt(DeviceId, crypto::SessionError),
    /// The Double Ratchet decrypt step failed for a specific device — wrong recipient
    /// session, replayed envelope, or corrupted ciphertext.
    #[error("decrypt failed for device {0}: {1}")]
    Decrypt(DeviceId, crypto::SessionError),
    /// `decrypt_as` was called with an identity that does not correspond to any device
    /// currently tracked by this fan-out. The fan-out is the source of truth for which
    /// identities participate.
    #[error("no device in this fan-out matches the given identity key")]
    UnknownIdentity,
    /// `decrypt_as` was called with a `Ciphertext` whose `device` field does not match
    /// the device the given identity is linked to. `Ciphertext::device` is a routing
    /// hint for the transport layer; this catches a caller (or forged input) presenting
    /// an envelope under a mismatched device label rather than silently ignoring it.
    #[error("ciphertext claims device {claimed} but identity resolves to device {actual}")]
    DeviceMismatch { claimed: DeviceId, actual: DeviceId },
}

/// Errors the verifiable revocation path can surface to its caller.
///
/// Distinct from [`FanoutError`]: the verifiable path is an additive layer over the
/// fan-out, not a reshaping of it, so its failure modes get their own enum. Per the
/// project's Secure by Design standard, callers relaying these across a network trust
/// boundary must not forward the `Display` text verbatim — return a generic reason to
/// the peer and log the full detail locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RevocationError {
    /// The underlying `libsignal` signing call failed while producing a
    /// `SignedRevocation`. Unreachable in practice for the Curve25519 keys this
    /// workspace generates, but propagated rather than panicking.
    #[error("revocation signing failed")]
    SigningFailed,
    /// The bytes were not a parseable signed revocation — wrong length, truncated, or
    /// an unrecognized layout. Fails closed: nothing is partially applied.
    #[error("malformed signed revocation")]
    Malformed,
    /// The revocation was not signed by the account primary's identity key. A device
    /// (or any other party) cannot revoke itself or a sibling device.
    #[error("revocation not signed by the account primary")]
    NotEntitled,
    /// The offered device-list version is not strictly newer than the version already
    /// held. The device list is monotonically versioned (spec/v0.md §8.3), so an equal
    /// version is a replay and an older one is stale; both are rejected.
    #[error("stale device-list version: holding {held}, offered {offered}")]
    StaleVersion { held: u64, offered: u64 },
    /// The revocation names a device this fan-out has never linked. Rejecting it keeps
    /// the device list and the fan-out's session table consistent.
    #[error("revocation names device {0}, which is not linked in this fan-out")]
    UnknownDevice(DeviceId),
    /// The named device is already revoked. Re-revoking is a no-op at best and a
    /// version-bumping replay at worst, so it is rejected instead of silently accepted.
    #[error("device {0} is already revoked")]
    AlreadyRevoked(DeviceId),
}

/// A primary-signed, monotonically versioned device revocation (spec/v0.md §8).
///
/// This is the *verifiable* half of the revocation contract: a signed fact about the
/// account's device list that any peer can check against the account primary's public
/// identity key before acting on it, rather than a sender-side decision nobody else can
/// audit. The signature covers a domain-separated encoding of the revoked device id and
/// the device-list version, so a revocation cannot be transplanted onto another device
/// or replayed at a stale version and still verify.
///
/// The signing primitive is `libsignal`'s own Curve25519 signature
/// (`PrivateKey::calculate_signature_for_multipart_message` /
/// `PublicKey::verify_signature`) — the same audited Ed25519-over-Curve25519 primitive
/// that underlies the device-linking signatures in `crypto` — reused unmodified rather
/// than inventing a second scheme ("don't reinvent crypto").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevocation {
    device: DeviceId,
    version: u64,
    signature: Box<[u8]>,
}

/// Domain-separation prefix for revocation signatures. Distinct from the device-linking
/// prefix inside `libsignal`'s alternate-identity primitive so a signature over one
/// message type can never verify as the other.
const REVOCATION_CONTEXT: &[u8] = b"DR-2 device revocation v1";

/// Canonical bytes a revocation signature commits to: context || device id || version.
fn revocation_payload(device: DeviceId, version: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(REVOCATION_CONTEXT.len() + 12);
    payload.extend_from_slice(REVOCATION_CONTEXT);
    payload.extend_from_slice(&device.0.to_be_bytes());
    payload.extend_from_slice(&version.to_be_bytes());
    payload
}

impl SignedRevocation {
    /// Sign a revocation of `device` at device-list `version` with the account
    /// primary's identity key.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationError::SigningFailed`] if the underlying `libsignal` signing
    /// call fails (unreachable in practice for this workspace's Curve25519 keys, but
    /// propagated rather than panicking).
    pub fn sign(
        primary: &IdentityKeyPair,
        device: DeviceId,
        version: u64,
    ) -> Result<Self, RevocationError> {
        let payload = revocation_payload(device, version);
        let signature = primary
            .private_key()
            .calculate_signature_for_multipart_message(&[&payload], &mut rand::rngs::OsRng.unwrap_err())
            .map_err(|_| RevocationError::SigningFailed)?;
        Ok(Self {
            device,
            version,
            signature: signature.into(),
        })
    }

    /// The device this revocation removes from the account's device list.
    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// The device-list version this revocation carries. Must be strictly greater than
    /// the version a peer already holds for the update to be accepted.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Serialize for transport. The layout is self-delimiting: a 1-byte version tag, the
    /// 4-byte device id, the 8-byte device-list version, then the signature length and
    /// signature bytes, so `from_bytes` can reject truncated input as
    /// [`RevocationError::Malformed`] instead of mis-parsing it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + 8 + 4 + self.signature.len());
        out.push(0x01); // layout version
        out.extend_from_slice(&self.device.0.to_be_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse bytes produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`RevocationError::Malformed`] for empty, truncated, or unrecognized
    /// input. Parsing never verifies; call [`verify`](Self::verify) before acting.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RevocationError> {
        if bytes.len() < 1 + 4 + 8 + 4 {
            return Err(RevocationError::Malformed);
        }
        if bytes[0] != 0x01 {
            return Err(RevocationError::Malformed);
        }
        let device = DeviceId(u32::from_be_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4],
        ]));
        let version = u64::from_be_bytes([
            bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
        ]);
        let sig_len = u32::from_be_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]) as usize;
        let sig_start = 17;
        if bytes.len() != sig_start + sig_len || sig_len == 0 {
            return Err(RevocationError::Malformed);
        }
        Ok(Self {
            device,
            version,
            signature: bytes[sig_start..].to_vec().into_boxed_slice(),
        })
    }

    /// Verify the signature against the account primary's public identity key.
    ///
    /// Fails closed: any malformed or mismatched signature is
    /// [`RevocationError::NotEntitled`] rather than an exception, so a verification
    /// failure can never be mistaken for a verified revocation.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationError::NotEntitled`] unless `primary` produced this exact
    /// revocation.
    pub fn verify(&self, primary: &libsignal_protocol::IdentityKey) -> Result<(), RevocationError> {
        let payload = revocation_payload(self.device, self.version);
        // Fails closed: a wrong-length signature is `false`, not an exception, so a
        // verification failure can never be mistaken for a verified revocation.
        let ok = primary
            .public_key()
            .verify_signature(&payload, &self.signature);
        if ok {
            Ok(())
        } else {
            Err(RevocationError::NotEntitled)
        }
    }
}

/// Per-device session fan-out for 1:1 messaging.
///
/// A `FanoutSession` owns one outbound `DoubleRatchetSession` per linked device, all
/// keyed off the same `sender` identity. `encrypt_to_all` walks the table, encrypts the
/// plaintext once per device, and returns the resulting envelopes tagged with their
/// target `DeviceId` so the transport layer can route them. `decrypt_as` looks up the
/// matching inbound session and decrypts.
///
/// `decrypt_as` is symmetric across the fan-out: the recipient device's *own*
/// `DoubleRatchetSession` is built the same way as the sender's, so the envelope bytes
/// round-trip. Callers that already have a long-lived `DoubleRatchetSession` for a
/// device should use that directly; `decrypt_as` is here so a freshly-built fan-out
/// (e.g. a test, or a transient receiver role) can decrypt without managing stores
/// itself.
// `Debug` is intentionally not derived: `DoubleRatchetSession` wraps a
// `libsignal` in-memory store that does not implement `Debug`, and exposing the
// raw ratchet bytes in a `Debug` printout would be a confidentiality regression.
// The fan-out's identity-table and device ids *are* debug-printable via the
// public `device_ids()` iterator if callers need to introspect state.
pub struct FanoutSession {
    /// One outbound session per linked device, keyed by `DeviceId`.
    sender_sessions: BTreeMap<DeviceId, DoubleRatchetSession>,
    /// Reverse lookup: an identity key may map to at most one device in a single
    /// fan-out (each device has its own identity). Stored so `decrypt_as` can dispatch
    /// on the identity the test passes in.
    identity_to_device: BTreeMap<[u8; 32], DeviceId>,
    /// One inbound session per linked device, used by `decrypt_as`. Mirrors
    /// `sender_sessions` 1:1. Kept separate from the sender side because the ratchet
    /// store is per-party: the sender's outbound ratchet state cannot double as the
    /// recipient's inbound ratchet state.
    receiver_sessions: BTreeMap<DeviceId, DoubleRatchetSession>,
    /// Devices revoked via the *verifiable* path (`apply_revocation`), with the
    /// device-list version that revoked them. Kept separate from the local
    /// `remove_device` shortcut so the two mechanisms stay independently auditable:
    /// `remove_device` is a sender-side drop with no signature, while a device here was
    /// removed on the strength of a primary-signed, version-checked revocation.
    revoked_devices: BTreeMap<DeviceId, u64>,
    /// The highest device-list version this fan-out has accepted. Monotonically
    /// non-decreasing (spec/v0.md §8.3); starts at 0 before any revocation is applied.
    revocation_version: u64,
}

impl FanoutSession {
    /// Establish a fan-out from `sender` to one ratchet session per `(device, identity)`
    /// pair.
    ///
    /// For each entry the sender side runs PQXDH against a prekey bundle published by
    /// the device's identity, and the receiver side is built from the same identity so
    /// `decrypt_as` works against a freshly-constructed `FanoutSession` (matching the
    /// acceptance tests). In a production deployment the receiver side would normally
    /// live in a long-lived store on the recipient device and only the sender side
    /// would be held here; the test surface does not require that separation.
    ///
    /// `sender` is the same identity that initiates every per-device session — a single
    /// user sending a 1:1 message to a single multi-device recipient.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::DuplicateDevice`] if `devices` contains the same
    /// `DeviceId` twice, [`FanoutError::NoDevices`] if it is empty, and
    /// [`FanoutError::Establishment`] if PQXDH fails for any device. On any error no
    /// partial state is exposed — the returned `FanoutSession` is only constructed
    /// after every per-device session has been established.
    pub fn establish(
        sender: &IdentityKeyPair,
        devices: &[(DeviceId, &IdentityKeyPair)],
    ) -> Result<Self, FanoutError> {
        if devices.is_empty() {
            return Err(FanoutError::NoDevices);
        }

        let mut sender_sessions: BTreeMap<DeviceId, DoubleRatchetSession> = BTreeMap::new();
        let mut receiver_sessions: BTreeMap<DeviceId, DoubleRatchetSession> = BTreeMap::new();
        let mut identity_to_device: BTreeMap<[u8; 32], DeviceId> = BTreeMap::new();

        for (device_id, recipient_identity) in devices {
            if sender_sessions.contains_key(device_id) {
                return Err(FanoutError::DuplicateDevice(*device_id));
            }

            // Build the device-side session first so we can pull a freshly-published
            // PQXDH prekey bundle off it. That bundle is what the sender consumes via
            // PQXDH (`new_alice`); a tampered or stale bundle would surface as
            // `Establishment` here.
            let receiver = block_on(DoubleRatchetSession::new_bob(recipient_identity))
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;
            let bundle = receiver
                .publish_bundle()
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;

            let outbound = block_on(DoubleRatchetSession::new_alice(sender, &bundle))
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;

            // Sanity check: ratchet envelopes are self-describing only by sender
            // identity hash, so a single sender establishing sessions against
            // *distinct* recipient identities is exactly the property the test relies
            // on. Record the identity→device reverse lookup for `decrypt_as`.
            let identity_hash = recipient_identity.identity_hash();
            if let Some(existing) = identity_to_device.get(&identity_hash) {
                // Same identity re-used for two different device ids — reject so the
                // fan-out is unambiguous. This is a distinct failure from a duplicate
                // `DeviceId` (the device ids differ; it's the identity that collided),
                // so it gets its own variant that names the device the identity was
                // already linked to.
                return Err(FanoutError::DuplicateIdentity(*existing));
            }
            identity_to_device.insert(identity_hash, *device_id);

            sender_sessions.insert(*device_id, outbound);
            receiver_sessions.insert(*device_id, receiver);
        }

        Ok(Self {
            sender_sessions,
            identity_to_device,
            receiver_sessions,
            revoked_devices: BTreeMap::new(),
            revocation_version: 0,
        })
    }

    /// Encrypt `plaintext` once per currently-tracked device and return the resulting
    /// envelopes, each tagged with the `DeviceId` it is destined for.
    ///
    /// The plaintext is the same byte slice for every device; per-device confidentiality
    /// comes from each device having its own ratchet session, not from any per-device
    /// transformation of the input. Devices that have been removed via
    /// [`remove_device`](Self::remove_device) are skipped, so the returned vector's
    /// length equals the number of currently-linked devices.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::Encrypt`] on the first ratchet failure. The fan-out is
    /// not transactional across devices: a failure on device N leaves devices 0..N with
    /// their ratchets advanced (the Double Ratchet always advances on encrypt) and
    /// devices N+1.. untouched. This matches the per-device session isolation property —
    /// a failure on one device must not poison another's ratchet state.
    pub fn encrypt_to_all(&mut self, plaintext: &[u8]) -> Result<Vec<Ciphertext>, FanoutError> {
        let mut out = Vec::with_capacity(self.sender_sessions.len());
        // Snapshot the device ids so we don't borrow `self.sender_sessions` mutably
        // while iterating it.
        let device_ids: Vec<DeviceId> = self.sender_sessions.keys().copied().collect();
        for device_id in device_ids {
            let session = self
                .sender_sessions
                .get_mut(&device_id)
                .expect("device id came from sender_sessions.keys()");
            let envelope = block_on(session.encrypt(plaintext))
                .map_err(|e| FanoutError::Encrypt(device_id, e))?;
            out.push(Ciphertext {
                device: device_id,
                envelope,
            });
        }
        Ok(out)
    }

    /// Decrypt a ciphertext as the device identified by `device_identity`.
    ///
    /// `ciphertext` is expected to be one of the envelopes returned by
    /// [`encrypt_to_all`](Self::encrypt_to_all) for the device that matches
    /// `device_identity`. The fan-out's per-device receiver session is used; if a
    /// caller has a long-lived receiver session for the same device they should
    /// decrypt with that instead — `decrypt_as` is provided so a freshly-constructed
    /// `FanoutSession` (as in the acceptance test) is symmetric and self-contained.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::UnknownIdentity`] if `device_identity` does not match
    /// any device tracked by this fan-out, [`FanoutError::DeviceMismatch`] if
    /// `ciphertext.device` does not match the device `device_identity` resolves to, and
    /// [`FanoutError::Decrypt`] on a ratchet failure (wrong session, tampered
    /// ciphertext, replay).
    pub fn decrypt_as(
        &mut self,
        device_identity: &IdentityKeyPair,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, FanoutError> {
        let device_id = *self
            .identity_to_device
            .get(&device_identity.identity_hash())
            .ok_or(FanoutError::UnknownIdentity)?;
        if ciphertext.device != device_id {
            return Err(FanoutError::DeviceMismatch {
                claimed: ciphertext.device,
                actual: device_id,
            });
        }
        let session = self
            .receiver_sessions
            .get_mut(&device_id)
            .expect("identity_to_device maps only to inserted device ids");
        block_on(session.decrypt(&ciphertext.envelope))
            .map_err(|e| FanoutError::Decrypt(device_id, e))
    }

    /// Drop the per-device ratchet state for `device_id` so future
    /// [`encrypt_to_all`](Self::encrypt_to_all) calls no longer emit a ciphertext for
    /// it.
    ///
    /// This is the revocation primitive: the next message goes only to the still-linked
    /// devices. Removing a device is idempotent — calling it twice is not an error.
    ///
    /// # Errors
    ///
    /// Never errors today; the `Result` return is kept for forward compatibility with
    /// future persistence-backed implementations that may need to surface store I/O
    /// failures during removal.
    pub fn remove_device(&mut self, device_id: DeviceId) -> Result<(), FanoutError> {
        // NOTE: this drops the map entries, releasing the heap allocations backing the
        // ratchet state — it does NOT zeroize the underlying key material. libsignal's
        // `InMemSignalProtocolStore` (which `DoubleRatchetSession` wraps) has no
        // `Zeroize`/`Drop` impl, so ratchet chain/root keys are left in freed heap
        // memory until some later allocation happens to overwrite them. Forward secrecy
        // after removal comes from the ratchet no longer being advanced/used for this
        // device, not from memory scrubbing. If scrubbing-on-drop is required (e.g. for
        // core-dump/cold-boot exposure hardening), that is a separate upstream change to
        // libsignal's store, not something this module can provide on its own.
        self.sender_sessions.remove(&device_id);
        self.receiver_sessions.remove(&device_id);
        // Drop the identity→device reverse mapping only if it points at the removed
        // device — a different device with a colliding hash is impossible by
        // construction (we rejected collisions in `establish`), so a stale entry here
        // would only mean the device was added under a different identity, which the
        // public API does not support.
        self.identity_to_device.retain(|_, d| *d != device_id);
        Ok(())
    }

    /// Apply a *verifiable* device revocation: verify the primary's signature, check the
    /// device-list version is strictly newer, then revoke the named device.
    ///
    /// This is the additive counterpart to [`remove_device`](Self::remove_device).
    /// `remove_device` is the local sender-side shortcut — no signature, no version, no
    /// effect on any other party's view of the device list. `apply_revocation` is the
    /// path spec/v0.md §8 requires for a revocation a peer *observes*: the update is
    /// acted on only after the signature verifies against the account primary's public
    /// identity key and the version advances monotonically. Both paths end in the same
    /// state — the device's ratchet state is dropped and the next
    /// [`encrypt_to_all`](Self::encrypt_to_all) no longer targets it — and both coexist.
    ///
    /// The checks run in a fixed order and all of them fail closed, before any state
    /// changes: signature ([`RevocationError::NotEntitled`]), version
    /// ([`RevocationError::StaleVersion`]), device linked
    /// ([`RevocationError::UnknownDevice`]), device not already revoked
    /// ([`RevocationError::AlreadyRevoked`]). A rejected update leaves the version and
    /// the revoked set untouched.
    ///
    /// # Errors
    ///
    /// See above; on any error nothing is applied.
    pub fn apply_revocation(
        &mut self,
        revocation: &SignedRevocation,
        primary: &libsignal_protocol::IdentityKey,
    ) -> Result<(), RevocationError> {
        // 1. Entitlement: only the account primary may revoke. This check is first so a
        //    forged update is rejected before any of its contents are considered.
        revocation.verify(primary)?;

        // 2. Monotonic version (§8.3): an equal version is a replay, an older one is
        //    stale; both must be rejected without advancing the held version.
        let offered = revocation.version();
        let held = self.revocation_version;
        if offered <= held {
            return Err(RevocationError::StaleVersion { held, offered });
        }

        // 3. Re-revoking an already-revoked device is rejected rather than silently
        //    accepted: the only legitimate way to name a revoked device again is a
        //    *newer* device-list update that re-links it under a fresh identity key
        //    (§8.4), which arrives as a new device, not a re-revocation. This check
        //    precedes the linked-device check because a revoked device has already had
        //    its session state dropped — it is no longer linked, but it is still *known*
        //    to the device list, and "already revoked" is the accurate rejection.
        let device = revocation.device();
        if self.revoked_devices.contains_key(&device) {
            return Err(RevocationError::AlreadyRevoked(device));
        }

        // 4. The named device must actually be linked in this fan-out. Revoking a device
        //    the fan-out never knew about would desynchronize the signed device list
        //    from the session table.
        if !self.sender_sessions.contains_key(&device) {
            return Err(RevocationError::UnknownDevice(device));
        }

        // All checks passed: apply. The ratchet-state drop is exactly what
        // `remove_device` does — the verifiable path adds the signature and version
        // checks, it does not change what revocation means locally.
        self.sender_sessions.remove(&device);
        self.receiver_sessions.remove(&device);
        self.identity_to_device.retain(|_, d| *d != device);
        self.revoked_devices.insert(device, offered);
        self.revocation_version = offered;
        Ok(())
    }

    /// The highest device-list version this fan-out has accepted (0 before any
    /// revocation). Monotonically non-decreasing; rejected updates never advance it.
    pub fn revocation_version(&self) -> u64 {
        self.revocation_version
    }

    /// Whether `device` has been revoked via the verifiable path. A device dropped only
    /// through the local [`remove_device`](Self::remove_device) shortcut is *removed*,
    /// not revoked — it is no longer linked, so it cannot be revoked either.
    pub fn is_revoked(&self, device: DeviceId) -> bool {
        self.revoked_devices.contains_key(&device)
    }
}

#[cfg(test)]
mod tests {
    //! Negative and boundary coverage for the fan-out's input-validation paths. The
    //! acceptance tests in `tests/per_device_fanout.rs` cover the multi-device happy path
    //! and device removal; this module covers the empty/duplicate/unknown-identity error
    //! paths and the single-device boundary that the project's testing standards require
    //! ("always write both positive and negative tests"; boundary conditions include
    //! zero, one, and empty collections).

    use super::{Ciphertext, DeviceId, FanoutError, FanoutSession};
    use crypto::generate_identity_key_pair;

    #[test]
    fn establish_rejects_an_empty_device_list() {
        let sender = generate_identity_key_pair();
        let result = FanoutSession::establish(&sender, &[]);
        let Err(e) = result else {
            panic!("empty recipient list must be rejected with NoDevices, got Ok");
        };
        assert!(
            matches!(e, FanoutError::NoDevices),
            "empty recipient list must be rejected with NoDevices, got: {e:?}"
        );
    }

    #[test]
    fn establish_rejects_a_duplicate_device_id() {
        let sender = generate_identity_key_pair();
        let a = generate_identity_key_pair();
        let b = generate_identity_key_pair();
        // Two distinct identities under the *same* DeviceId — the device id collides.
        let devices = [(DeviceId(1), &a), (DeviceId(1), &b)];
        let result = FanoutSession::establish(&sender, &devices);
        let Err(e) = result else {
            panic!("duplicate DeviceId must be rejected, got Ok");
        };
        assert!(
            matches!(e, FanoutError::DuplicateDevice(DeviceId(1))),
            "duplicate DeviceId must be rejected with DuplicateDevice(1), got: {e:?}"
        );
    }

    #[test]
    fn establish_rejects_the_same_identity_under_two_device_ids() {
        let sender = generate_identity_key_pair();
        let shared = generate_identity_key_pair();
        // Same identity, two different DeviceIds — the identity collides, not the id.
        let devices = [(DeviceId(1), &shared), (DeviceId(2), &shared)];
        let result = FanoutSession::establish(&sender, &devices);
        let Err(e) = result else {
            panic!("reused identity must be rejected, got Ok");
        };
        assert!(
            matches!(e, FanoutError::DuplicateIdentity(DeviceId(1))),
            "reused identity must be rejected with DuplicateIdentity(1), got: {e:?}"
        );
    }

    #[test]
    fn decrypt_as_rejects_an_identity_not_in_the_fanout() {
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();
        let stranger = generate_identity_key_pair();

        let mut fanout =
            FanoutSession::establish(&sender, &[(DeviceId(1), &recipient)]).expect("establish");
        let ciphertexts = fanout.encrypt_to_all(b"hi").expect("encrypt");
        assert_eq!(ciphertexts.len(), 1);

        // An identity the fan-out never linked must be refused, not decrypted.
        let result = fanout.decrypt_as(&stranger, &ciphertexts[0]);
        assert!(
            matches!(result, Err(FanoutError::UnknownIdentity)),
            "unknown identity must be rejected with UnknownIdentity, got: {result:?}"
        );
    }

    #[test]
    fn single_device_round_trips() {
        // The "one" boundary: a fan-out with a single linked device must still produce
        // exactly one ciphertext that the device can decrypt.
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();

        let mut fanout =
            FanoutSession::establish(&sender, &[(DeviceId(7), &recipient)]).expect("establish");
        let ciphertexts = fanout.encrypt_to_all(b"only you").expect("encrypt");
        assert_eq!(ciphertexts.len(), 1, "one ciphertext for one device");
        assert_eq!(ciphertexts[0].device, DeviceId(7));

        let opened = fanout
            .decrypt_as(&recipient, &ciphertexts[0])
            .expect("decrypt");
        assert_eq!(opened, b"only you");
    }

    #[test]
    fn a_device_cannot_decrypt_another_devices_ciphertext() {
        let sender = generate_identity_key_pair();
        let recipient_a = generate_identity_key_pair();
        let recipient_b = generate_identity_key_pair();

        let mut fanout = FanoutSession::establish(
            &sender,
            &[(DeviceId(1), &recipient_a), (DeviceId(2), &recipient_b)],
        )
        .expect("establish");
        let ciphertexts = fanout.encrypt_to_all(b"secret").expect("encrypt");

        // Device B's identity against device A's envelope: neither the device-mismatch
        // check nor the ratchet session should let this through.
        let mismatched = Ciphertext {
            device: DeviceId(2),
            envelope: ciphertexts[0].envelope.clone(),
        };
        let result = fanout.decrypt_as(&recipient_b, &mismatched);
        assert!(
            matches!(result, Err(FanoutError::Decrypt(DeviceId(2), _))),
            "device B must not be able to decrypt device A's ciphertext, got: {result:?}"
        );
    }

    #[test]
    fn decrypt_as_rejects_a_ciphertext_with_a_mismatched_device_label() {
        let sender = generate_identity_key_pair();
        let recipient_a = generate_identity_key_pair();
        let recipient_b = generate_identity_key_pair();

        let mut fanout = FanoutSession::establish(
            &sender,
            &[(DeviceId(1), &recipient_a), (DeviceId(2), &recipient_b)],
        )
        .expect("establish");
        let ciphertexts = fanout.encrypt_to_all(b"secret").expect("encrypt");

        // Device A's own envelope, but forged to claim it targets device 2 — the
        // `device` field must be validated against the identity, not trusted blindly.
        let forged = Ciphertext {
            device: DeviceId(2),
            envelope: ciphertexts[0].envelope.clone(),
        };
        let result = fanout.decrypt_as(&recipient_a, &forged);
        assert!(
            matches!(
                result,
                Err(FanoutError::DeviceMismatch {
                    claimed: DeviceId(2),
                    actual: DeviceId(1),
                })
            ),
            "mismatched device label must be rejected with DeviceMismatch, got: {result:?}"
        );
    }

    #[test]
    fn decrypting_after_the_device_was_removed_is_unknown_identity() {
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();

        let mut fanout =
            FanoutSession::establish(&sender, &[(DeviceId(1), &recipient)]).expect("establish");
        let ciphertexts = fanout.encrypt_to_all(b"before removal").expect("encrypt");

        fanout.remove_device(DeviceId(1)).expect("remove device 1");

        let result = fanout.decrypt_as(&recipient, &ciphertexts[0]);
        assert!(
            matches!(result, Err(FanoutError::UnknownIdentity)),
            "decrypting after the device was removed must fail with UnknownIdentity, got: {result:?}"
        );
    }

    #[test]
    fn fanout_works_from_inside_a_current_thread_runtime() {
        // Reproduces the bug this test guards against: the fan-out API is sync and
        // internally calls the module's `block_on` helper. Calling it from the very
        // thread already driving a current-thread tokio runtime must not panic
        // ("Cannot start a runtime from within a runtime") — it must offload to a
        // scoped worker thread instead (see `block_on`'s case 3).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime for test");
        rt.block_on(async {
            let sender = generate_identity_key_pair();
            let recipient = generate_identity_key_pair();
            let mut fanout = FanoutSession::establish(&sender, &[(DeviceId(1), &recipient)])
                .expect("establish must succeed from inside a current-thread runtime");
            let ciphertexts = fanout
                .encrypt_to_all(b"from a current-thread runtime")
                .expect("encrypt must succeed from inside a current-thread runtime");
            let opened = fanout
                .decrypt_as(&recipient, &ciphertexts[0])
                .expect("decrypt must succeed from inside a current-thread runtime");
            assert_eq!(opened, b"from a current-thread runtime");
        });
    }
}
