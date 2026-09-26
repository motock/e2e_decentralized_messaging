//! High-level Double Ratchet session facade (PLAN.md Phase 1 "Crypto core").
//!
//! A single async session type that wraps the done low-level building blocks —
//! `InMemSignalProtocolStore`, [`crate::session`]'s prekey-bundle builder / PQXDH
//! establishment, [`crate::prekey`]'s signed / Kyber / one-time prekey generation, and
//! [`crate::double_ratchet`]'s encrypt / decrypt — so a caller can establish a 1:1 Signal
//! (PQXDH + Double Ratchet) session from a peer's prekey bundle and exchange messages without
//! touching libsignal stores, addresses, or record types directly.
//!
//! No crypto is reimplemented here. This module is a thin, named facade over the audited
//! `libsignal` ratchet; every primitive (X3DH/PQXDH, the Double Ratchet, XEdDSA signatures) is
//! delegated to `libsignal` via the wrappers in [`crate::session`] and [`crate::double_ratchet`].
//!
//! # Wire format
//!
//! `libsignal`'s serialized `SignalMessage` / `PreKeySignalMessage` do not carry their own type
//! tag (see [`crate::double_ratchet`] for why), and a receiver must know which parser to use.
//! [`DoubleRatchetSession::encrypt`] therefore prefixes the raw ciphertext with a self-describing
//! envelope so [`DoubleRatchetSession::decrypt`] can reconstruct both the sender's address and
//! the ciphertext shape without out-of-band context:
//!
//! ```text
//!   [ sender identity_hash : 32 bytes ]
//!   [ message-type tag     :  1 byte  ]   // 1 = PreKey, 2 = Ciphertext
//!   [ raw libsignal ciphertext          ]
//! ```
//!
//! `identity_hash` is SHA-256 of the sender's serialized public identity key — the same stable
//! 32-byte peer id the transport layer addresses peers by.

use std::fmt;

use libsignal_protocol::{
    DeviceId, IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::double_ratchet::{self, DoubleRatchetError, MessageType, SerializedCiphertext};
use crate::prekey::{generate_one_time_pre_keys, generate_signed_pre_key};
use crate::session::{build_prekey_bundle, establish_outbound_session, generate_kyber_prekey};

/// Registration id both parties use in this facade. Addressing is derived from the identity
/// key (see [`identity_hash`]), not the registration id, so a shared constant keeps the bundle
/// well-formed without coupling two parties' ids.
const REGISTRATION_ID: u32 = 1;
/// Device id both parties use for their 1:1 address. Each party's `local_address` is derived
/// from its own identity hash plus this device id, which matches the address its peer derives
/// from its bundle's identity key + device id.
const DEVICE_ID: u8 = 1;
const SIGNED_PREKEY_ID: u32 = 1;
const KYBER_PREKEY_ID: u32 = 1;
const ONE_TIME_PREKEY_ID: u32 = 1;

/// Wire-format type tags. Kept as plain constants (not a pub enum) because they are an
/// internal encoding detail of [`DoubleRatchetSession`], not part of its public surface.
const TYPE_TAG_PREKEY: u8 = 1;
const TYPE_TAG_CIPHERTEXT: u8 = 2;
/// Total length of the envelope prefix the receiver must strip before the raw ciphertext.
const ENVELOPE_PREFIX_LEN: usize = 32 + 1;

/// Version tag of the [`DoubleRatchetSession::to_bytes`] / [`DoubleRatchetSession::from_bytes`]
/// session-state blob. Bump only for an incompatible layout change.
const SERIALIZATION_VERSION: u8 = 1;
/// Role tag for a sender (Alice) session blob — the only role this build serializes.
const ROLE_SENDER: u8 = 1;
/// Role tag for a receiver (Bob) session blob. Reserved for the receiver story; restoring one
/// is rejected as [`SessionError::UnsupportedRole`] here.
const ROLE_RECEIVER: u8 = 2;

/// A high-level 1:1 Signal (PQXDH + Double Ratchet) session.
///
/// A **receiver** (Bob) is constructed via [`DoubleRatchetSession::new_bob`], which generates and
/// saves his signed / Kyber / one-time prekeys; [`DoubleRatchetSession::publish_bundle`] then
/// publishes the PQXDH bundle a sender consumes. A **sender** (Alice) is constructed via
/// [`DoubleRatchetSession::new_alice`] from Bob's bundle, which establishes the outbound session;
/// she then calls [`DoubleRatchetSession::encrypt`]. Either side calls
/// [`DoubleRatchetSession::decrypt`] on an inbound envelope.
pub struct DoubleRatchetSession {
    identity: IdentityKeyPair,
    local_address: ProtocolAddress,
    /// SHA-256 of `identity.identity_key()` — prepended to outbound envelopes so the receiver
    /// can reconstruct the sender's address, and used to build our own address.
    local_hash: [u8; 32],
    store: InMemSignalProtocolStore,
    /// Present on a sender (Alice) after establishment — the address [`encrypt`](Self::encrypt)
    /// targets. `None` on a receiver-only session constructed via [`new_bob`](Self::new_bob).
    remote_address: Option<ProtocolAddress>,
    /// Prekey records a receiver (Bob) published, kept so [`publish_bundle`](Self::publish_bundle)
    /// can re-reference them. `None` on a sender.
    signed_prekey: Option<SignedPreKeyRecord>,
    kyber_prekey: Option<KyberPreKeyRecord>,
    one_time_prekey: Option<PreKeyRecord>,
}

/// Errors from high-level session construction, encryption, or decryption.
///
/// Each variant wraps the underlying typed error from the building block that failed, so callers
/// can distinguish establishment failures (bad signature, untrusted identity) from encrypt/decrypt
/// failures (no session, bad MAC) without depending on `libsignal_protocol`. Every variant is
/// fail-closed: on any error no plaintext is produced and the session state is untouched.
#[derive(Debug)]
pub enum SessionError {
    /// A serialized session blob was structurally invalid: wrong version, a truncated or
    /// over-long length prefix, trailing bytes, a remote name that does not match its
    /// identity hash, or a local identity that does not match the one the session was
    /// created with. Fail-closed: no partially restored session is ever returned.
    MalformedState,
    /// A serialized session blob declared a role this build cannot restore (e.g. a receiver
    /// blob passed to the sender-only restore path). Fail-closed.
    UnsupportedRole,
    /// A prekey-generation or in-memory store failure during [`new_bob`](Self::new_bob) /
    /// [`new_alice`](Self::new_alice).
    PreKey(SignalProtocolError),
    /// PQXDH session establishment (`process_prekey_bundle`) failed — tampered prekey
    /// signature, untrusted identity after TOFU, or a malformed bundle.
    Establishment(SignalProtocolError),
    /// Encryption via the Double Ratchet failed.
    Encrypt(DoubleRatchetError),
    /// Decryption via the Double Ratchet failed.
    Decrypt(DoubleRatchetError),
    /// A `libsignal` store read/write failed (e.g. the identity-store lookup performed during
    /// [`decrypt`](DoubleRatchetSession::decrypt) to verify the sender's bound identity).
    Store(SignalProtocolError),
    /// An inbound envelope was too short to carry the sender-hash + type prefix, or carried an
    /// unknown type tag.
    MalformedEnvelope,
    /// The envelope's self-declared `sender_hash` does not match the identity key the message
    /// actually carries (PreKey) or that is already bound to the sender's address (Ciphertext).
    /// A first-contact PreKey message with a mismatched hash is rejected *before* libsignal's
    /// TOFU binds anything, so an attacker cannot bind their identity key to a victim's address
    /// name (impersonation) or preempt the real victim's later first message (DoS). Fail-closed:
    /// no plaintext is produced.
    IdentityHashMismatch,
    /// Internal prekey generation yielded no one-time prekey. Unreachable in practice
    /// (`generate_one_time_pre_keys(1, 1)` always yields one) but propagated rather than
    /// panicking, per the fail-securely posture.
    NoOneTimePreKey,
    /// [`publish_bundle`](DoubleRatchetSession::publish_bundle) was called on a sender-only
    /// session (constructed via [`new_alice`](DoubleRatchetSession::new_alice)), which holds no
    /// prekeys to publish.
    NotPublisher,
    /// [`encrypt`](DoubleRatchetSession::encrypt) was called on a receiver-only session
    /// (constructed via [`new_bob`](DoubleRatchetSession::new_bob)), which has no remote address
    /// to encrypt to.
    NotSender,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedState => write!(f, "malformed serialized session state"),
            Self::UnsupportedRole => write!(f, "serialized session role not supported"),
            Self::PreKey(e) => write!(f, "session prekey error: {e}"),
            Self::Establishment(e) => write!(f, "session establishment failed: {e}"),
            Self::Encrypt(e) => write!(f, "session encrypt failed: {e}"),
            Self::Decrypt(e) => write!(f, "session decrypt failed: {e}"),
            Self::Store(e) => write!(f, "session store error: {e}"),
            Self::MalformedEnvelope => write!(f, "malformed session envelope"),
            Self::IdentityHashMismatch => {
                write!(
                    f,
                    "envelope sender hash does not match the bound identity key"
                )
            }
            Self::NoOneTimePreKey => write!(f, "no one-time prekey generated"),
            Self::NotPublisher => write!(f, "session is not a prekey publisher"),
            Self::NotSender => write!(f, "session has no remote address to encrypt to"),
        }
    }
}

impl std::error::Error for SessionError {}

impl SessionError {
    /// True if this error is specifically a rejected signed-prekey or Kyber-prekey signature
    /// during PQXDH establishment (`process_prekey_bundle`'s `SignatureValidationFailed`).
    /// Bindings (e.g. the WASM facade) use this to surface a distinct "the bundle's signature
    /// didn't verify" error kind, separate from other establishment failures, without needing
    /// `libsignal_protocol` as a direct dependency themselves.
    pub fn is_prekey_signature_invalid(&self) -> bool {
        matches!(
            self,
            SessionError::Establishment(SignalProtocolError::SignatureValidationFailed)
        )
    }
}

/// SHA-256 of `identity`'s serialized public identity key — a stable, 32-byte peer identifier.
///
/// This is the transport-level peer id (the key the DHT / delivery layer addresses peers by) and
/// the basis of each party's libsignal `ProtocolAddress` name in this facade. Hashing the
/// *public* key means it is computable by anyone who has seen the identity key, not just the
/// key owner, so a sender can derive the receiver's address straight from its prekey bundle.
pub fn identity_hash(identity: &IdentityKeyPair) -> [u8; 32] {
    hash_of_identity_key(identity.identity_key())
}

fn hash_of_identity_key(key: &IdentityKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.serialize());
    hasher.finalize().into()
}

fn device() -> DeviceId {
    DeviceId::new(DEVICE_ID).expect("DEVICE_ID is a valid device id (1..=127)")
}

fn now_ts() -> Timestamp {
    Timestamp::from_epoch_millis(
        crate::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    )
}

/// Lower-case hex of a 32-byte hash, used as the `ProtocolAddress` name. No `hex` dependency —
/// the name only needs to be a stable, collision-free string derived from the hash.
fn hex_name(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in hash {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

fn address_for_hash(hash: &[u8; 32]) -> ProtocolAddress {
    ProtocolAddress::new(hex_name(hash), device())
}

/// Read one big-endian `u32`-length-prefixed segment from `bytes` at `*pos`, advancing `*pos`
/// past it and returning the segment slice.
///
/// Checks the declared length against the bytes remaining BEFORE slicing or allocating, so a
/// hostile blob declaring a 4 GiB segment returns [`SessionError::MalformedState`] instead of
/// panicking or allocating. Any shortfall (missing length prefix, or a segment longer than the
/// remaining bytes) is also [`SessionError::MalformedState`].
fn read_segment<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], SessionError> {
    let remaining = bytes.len().saturating_sub(*pos);
    if remaining < 4 {
        return Err(SessionError::MalformedState);
    }
    let len = u32::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
    ]) as usize;
    *pos += 4;

    // `*pos <= bytes.len()` holds here, so the subtraction cannot underflow. `len` is checked
    // against the remaining bytes before `*pos + len` is formed, so that addition cannot
    // overflow either (even on 32-bit wasm32 targets).
    let remaining = bytes.len() - *pos;
    if len > remaining {
        return Err(SessionError::MalformedState);
    }
    let segment = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(segment)
}

fn type_tag(mt: MessageType) -> u8 {
    match mt {
        MessageType::PreKey => TYPE_TAG_PREKEY,
        MessageType::Ciphertext => TYPE_TAG_CIPHERTEXT,
    }
}

fn message_type_from_tag(tag: u8) -> Option<MessageType> {
    match tag {
        TYPE_TAG_PREKEY => Some(MessageType::PreKey),
        TYPE_TAG_CIPHERTEXT => Some(MessageType::Ciphertext),
        _ => None,
    }
}

impl DoubleRatchetSession {
    /// Serialize this sender (Alice) session to a self-contained byte blob that
    /// [`from_bytes`](Self::from_bytes) can restore.
    ///
    /// # Security
    ///
    /// The returned bytes contain **secret ratchet state** (the libsignal `SessionRecord`,
    /// including chain keys). The CALLER MUST encrypt them at rest before persisting them —
    /// the web client's `StorageGate` does. Never log or `Debug`-print the blob or any key
    /// material. The local identity keypair is deliberately NOT included (data
    /// minimization); the caller supplies it to [`from_bytes`](Self::from_bytes).
    ///
    /// # Format (v1, all integers big-endian)
    ///
    /// ```text
    ///   [ version : 1 byte  ]   // 1
    ///   [ role    : 1 byte  ]   // 1 = sender/Alice
    ///   [ remote entry: four u32-length-prefixed segments ]
    /// ```
    ///
    /// A remote entry is, in order: the remote address name (UTF-8), the remote device id
    /// (exactly 4 bytes), the remote `IdentityKey` (libsignal `serialize`), and that remote's
    /// libsignal `SessionRecord` (`serialize`).
    ///
    /// Returns [`SessionError::UnsupportedRole`] on a receiver-only session
    /// (`remote_address == None`), which holds no outbound session to serialize.
    pub async fn to_bytes(&self) -> Result<Vec<u8>, SessionError> {
        let remote = self
            .remote_address
            .as_ref()
            .ok_or(SessionError::UnsupportedRole)?;

        let record = self
            .store
            .session_store
            .load_session(remote)
            .await
            .map_err(SessionError::Store)?
            .ok_or(SessionError::MalformedState)?;

        let remote_identity = self
            .store
            .identity_store
            .get_identity(remote)
            .await
            .map_err(SessionError::Store)?
            .ok_or(SessionError::MalformedState)?;

        // The serialized record is secret ratchet state; keep the temporary copy in a
        // `Zeroizing` buffer so it is wiped when this function returns.
        let record_bytes = Zeroizing::new(record.serialize().map_err(SessionError::Store)?);

        let mut out = Vec::new();
        out.push(SERIALIZATION_VERSION);
        out.push(ROLE_SENDER);
        let push_segment = |buf: &mut Vec<u8>, segment: &[u8]| {
            buf.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            buf.extend_from_slice(segment);
        };
        push_segment(&mut out, remote.name().as_bytes());
        push_segment(&mut out, &u32::from(remote.device_id()).to_be_bytes());
        push_segment(&mut out, &remote_identity.serialize());
        push_segment(&mut out, record_bytes.as_slice());
        Ok(out)
    }

    /// Restore a sender (Alice) session from the blob produced by
    /// [`to_bytes`](Self::to_bytes), using the local `identity` the session was created with.
    ///
    /// Parses strictly and fails closed: every structural error (bad version, unknown role,
    /// truncated or over-long length prefix, trailing bytes, a remote name that does not match
    /// its identity hash, or an `identity` that is not the one the session was created with)
    /// returns `Err` and no partially restored session is ever returned.
    pub async fn from_bytes(
        identity: &IdentityKeyPair,
        bytes: &[u8],
    ) -> Result<Self, SessionError> {
        let mut pos = 0usize;

        let version = *bytes.first().ok_or(SessionError::MalformedState)?;
        pos += 1;
        if version != SERIALIZATION_VERSION {
            return Err(SessionError::MalformedState);
        }

        let role = *bytes.get(pos).ok_or(SessionError::MalformedState)?;
        pos += 1;
        match role {
            ROLE_SENDER => {}
            ROLE_RECEIVER => return Err(SessionError::UnsupportedRole),
            _ => return Err(SessionError::MalformedState),
        }

        let name_bytes = read_segment(bytes, &mut pos)?;
        let name = std::str::from_utf8(name_bytes).map_err(|_| SessionError::MalformedState)?;

        let device_bytes = read_segment(bytes, &mut pos)?;
        let device_raw: [u8; 4] = device_bytes
            .try_into()
            .map_err(|_| SessionError::MalformedState)?;
        let device_id = DeviceId::new(
            u8::try_from(u32::from_be_bytes(device_raw))
                .map_err(|_| SessionError::MalformedState)?,
        )
        .map_err(|_| SessionError::MalformedState)?;

        let identity_bytes = read_segment(bytes, &mut pos)?;
        let remote_identity =
            IdentityKey::try_from(identity_bytes).map_err(|_| SessionError::MalformedState)?;

        let record_bytes = read_segment(bytes, &mut pos)?;
        let record =
            SessionRecord::deserialize(record_bytes).map_err(|_| SessionError::MalformedState)?;

        // Reject trailing bytes after the last segment.
        if pos != bytes.len() {
            return Err(SessionError::MalformedState);
        }

        // The remote address name must be the hash of the remote identity key, so a blob
        // cannot bind an identity key to a name it does not hash to.
        if name != hex_name(&hash_of_identity_key(&remote_identity)) {
            return Err(SessionError::MalformedState);
        }

        // The supplied identity must be the one the session was created with, otherwise the
        // restored session would silently operate under the wrong identity.
        let record_local_identity = record
            .local_identity_key_bytes()
            .map_err(|_| SessionError::MalformedState)?;
        if record_local_identity.as_slice() != identity.public_key().serialize().as_ref() {
            return Err(SessionError::MalformedState);
        }

        let remote_address = ProtocolAddress::new(name.to_string(), device_id);

        let mut store = InMemSignalProtocolStore::new(*identity, REGISTRATION_ID)
            .map_err(SessionError::PreKey)?;
        store
            .session_store
            .store_session(&remote_address, &record)
            .await
            .map_err(SessionError::Store)?;
        store
            .identity_store
            .save_identity(&remote_address, &remote_identity)
            .await
            .map_err(SessionError::Store)?;

        let local_hash = identity_hash(identity);
        let local_address = address_for_hash(&local_hash);

        Ok(Self {
            identity: *identity,
            local_address,
            local_hash,
            store,
            remote_address: Some(remote_address),
            signed_prekey: None,
            kyber_prekey: None,
            one_time_prekey: None,
        })
    }
    /// Construct a receiver (Bob): generate and save signed, Kyber, and one-time prekeys into a
    /// fresh in-memory libsignal store, ready for [`publish_bundle`](Self::publish_bundle) and
    /// inbound [`decrypt`](Self::decrypt).
    pub async fn new_bob(identity: &IdentityKeyPair) -> Result<Self, SessionError> {
        let mut store = InMemSignalProtocolStore::new(*identity, REGISTRATION_ID)
            .map_err(SessionError::PreKey)?;

        let now = now_ts();
        let signed_prekey = generate_signed_pre_key(identity, SIGNED_PREKEY_ID, now);
        let kyber_prekey = generate_kyber_prekey(
            KyberPreKeyId::from(KYBER_PREKEY_ID),
            identity.private_key(),
            now,
        )
        .map_err(SessionError::PreKey)?;
        let otpks = generate_one_time_pre_keys(ONE_TIME_PREKEY_ID, 1);
        let one_time_prekey = otpks
            .into_iter()
            .next()
            .ok_or(SessionError::NoOneTimePreKey)?;

        // Save the prekeys Bob will need to decrypt Alice's first (PreKey) message. The records
        // are also kept as struct fields so publish_bundle can re-reference them without cloning.
        store
            .save_signed_pre_key(SignedPreKeyId::from(SIGNED_PREKEY_ID), &signed_prekey)
            .await
            .map_err(SessionError::PreKey)?;
        store
            .save_kyber_pre_key(KyberPreKeyId::from(KYBER_PREKEY_ID), &kyber_prekey)
            .await
            .map_err(SessionError::PreKey)?;
        store
            .save_pre_key(PreKeyId::from(ONE_TIME_PREKEY_ID), &one_time_prekey)
            .await
            .map_err(SessionError::PreKey)?;

        let local_hash = identity_hash(identity);
        let local_address = address_for_hash(&local_hash);
        Ok(Self {
            identity: *identity,
            local_address,
            local_hash,
            store,
            remote_address: None,
            signed_prekey: Some(signed_prekey),
            kyber_prekey: Some(kyber_prekey),
            one_time_prekey: Some(one_time_prekey),
        })
    }

    /// Build the PQXDH prekey bundle a sender consumes to establish a session with this
    /// receiver. Only valid on a session constructed via [`new_bob`](Self::new_bob).
    pub fn publish_bundle(&self) -> Result<PreKeyBundle, SessionError> {
        let signed_prekey = self
            .signed_prekey
            .as_ref()
            .ok_or(SessionError::NotPublisher)?;
        let kyber_prekey = self
            .kyber_prekey
            .as_ref()
            .ok_or(SessionError::NotPublisher)?;
        let one_time_prekey = self.one_time_prekey.as_ref();

        build_prekey_bundle(
            REGISTRATION_ID,
            device(),
            &self.identity,
            signed_prekey,
            kyber_prekey,
            one_time_prekey,
        )
        .map_err(SessionError::PreKey)
    }

    /// Construct a sender (Alice) from a peer's prekey bundle: derive the peer's address from
    /// the bundle's identity key + device id, then run PQXDH session establishment against a
    /// fresh in-memory store. After this, [`encrypt`](Self::encrypt) targets the peer.
    pub async fn new_alice(
        identity: &IdentityKeyPair,
        bundle: &PreKeyBundle,
    ) -> Result<Self, SessionError> {
        let mut rng = OsRng.unwrap_err();
        let mut store = InMemSignalProtocolStore::new(*identity, REGISTRATION_ID)
            .map_err(SessionError::PreKey)?;

        // Derive the peer's address straight from the bundle so it matches the address the peer
        // uses as its own local_address (same identity key → same hash → same name; same device
        // id, since publish_bundle tags the bundle with our shared DEVICE_ID).
        let remote_identity = *bundle.identity_key().map_err(SessionError::Establishment)?;
        let remote_device = bundle.device_id().map_err(SessionError::Establishment)?;
        let remote_hash = hash_of_identity_key(&remote_identity);
        let remote_address = ProtocolAddress::new(hex_name(&remote_hash), remote_device);

        let local_hash = identity_hash(identity);
        let local_address = address_for_hash(&local_hash);

        establish_outbound_session(
            &local_address,
            &remote_address,
            bundle,
            &mut store.session_store,
            &mut store.identity_store,
            &mut rng,
        )
        .await
        .map_err(SessionError::Establishment)?;

        Ok(Self {
            identity: *identity,
            local_address,
            local_hash,
            store,
            remote_address: Some(remote_address),
            signed_prekey: None,
            kyber_prekey: None,
            one_time_prekey: None,
        })
    }

    /// Encrypt `plaintext` for the peer this session was established against, returning the
    /// self-describing wire envelope (sender hash + type tag + raw ciphertext).
    pub async fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let remote_address = self
            .remote_address
            .as_ref()
            .ok_or(SessionError::NotSender)?;

        let ciphertext = double_ratchet::encrypt_message(
            plaintext,
            remote_address,
            &self.local_address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
        )
        .await
        .map_err(SessionError::Encrypt)?;

        let serialized =
            SerializedCiphertext::try_from(&ciphertext).map_err(SessionError::Encrypt)?;

        let mut envelope = Vec::with_capacity(ENVELOPE_PREFIX_LEN + serialized.as_bytes().len());
        envelope.extend_from_slice(&self.local_hash);
        envelope.push(type_tag(serialized.message_type()));
        envelope.extend_from_slice(serialized.as_bytes());
        Ok(envelope)
    }

    /// Decrypt a self-describing wire envelope, returning the plaintext. Fails closed on any
    /// malformed envelope, identity-hash mismatch, missing session, untrusted identity, or
    /// MAC/replay failure — no plaintext is produced on error.
    ///
    /// Before handing control to `libsignal`'s TOFU, the facade enforces its structural
    /// invariant — *the sender address name IS the hash of the sender's identity key* — so a
    /// first-contact PreKey message cannot bind an attacker's identity key to a victim's address
    /// name. For a PreKey envelope the sender's signed identity key is read straight from the
    /// `PreKeySignalMessage` header and required to hash to the declared `sender_hash`; for a
    /// Ciphertext envelope the identity already bound to the sender's address must hash to it.
    /// A mismatch is rejected before `libsignal` binds anything, which closes both the
    /// first-contact impersonation and the address-preemption (DoS) consequences.
    pub async fn decrypt(&mut self, envelope: &[u8]) -> Result<Vec<u8>, SessionError> {
        if envelope.len() < ENVELOPE_PREFIX_LEN {
            return Err(SessionError::MalformedEnvelope);
        }
        let sender_hash: [u8; 32] = envelope[..32]
            .try_into()
            .map_err(|_| SessionError::MalformedEnvelope)?;
        let message_type =
            message_type_from_tag(envelope[32]).ok_or(SessionError::MalformedEnvelope)?;
        let raw = &envelope[ENVELOPE_PREFIX_LEN..];

        let sender_address = address_for_hash(&sender_hash);

        // Enforce "sender address name == hash(sender identity key)" BEFORE libsignal's TOFU,
        // per the Secure-by-Design fail-closed posture. The check is structural to this facade's
        // wire format; the caller never sees the sender address until decrypt returns.
        match message_type {
            MessageType::PreKey => {
                // The PreKeySignalMessage carries the sender's signed identity key in its
                // (unencrypted, signed) header. Parse it and require its hash to match the
                // declared sender_hash before libsignal binds anything via TOFU — otherwise an
                // attacker could declare a victim's hash while embedding their own identity key,
                // getting bound to the victim's address name on first contact.
                let prekey = PreKeySignalMessage::try_from(raw)
                    .map_err(|_| SessionError::MalformedEnvelope)?;
                if hash_of_identity_key(prekey.identity_key()) != sender_hash {
                    return Err(SessionError::IdentityHashMismatch);
                }
            }
            MessageType::Ciphertext => {
                // An established-session message: the identity for this address must already be
                // bound and must hash to the declared sender_hash. The session MAC is the
                // primary forgery gate; this check enforces the address-name invariant and
                // refuses a Ciphertext envelope whose declared hash does not match the bound
                // identity.
                let stored = self
                    .store
                    .identity_store
                    .get_identity(&sender_address)
                    .await
                    .map_err(SessionError::Store)?;
                match stored {
                    Some(key) if hash_of_identity_key(&key) == sender_hash => {}
                    _ => return Err(SessionError::IdentityHashMismatch),
                }
            }
        }

        let ciphertext = SerializedCiphertext::new(message_type, raw.to_vec());

        double_ratchet::decrypt_message(
            ciphertext,
            &sender_address,
            &self.local_address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
        )
        .await
        .map_err(SessionError::Decrypt)
    }
}

/// Extension methods on libsignal's [`IdentityKeyPair`] for the high-level session / transport
/// surface: the public identity key and its stable 32-byte hash.
///
/// Provided as a trait so downstream crates (e.g. the transport delivery story) can call
/// `b_id.public_identity()` / `b_id.identity_hash()` on an owned `IdentityKeyPair` without
/// importing `libsignal_protocol` or the free function in this module.
pub trait IdentityKeyPairExt {
    /// The public identity key half of this keypair.
    fn public_identity(&self) -> IdentityKey;
    /// SHA-256 of the serialized public identity key — the stable 32-byte peer id. See
    /// [`identity_hash`].
    fn identity_hash(&self) -> [u8; 32];
}

impl IdentityKeyPairExt for IdentityKeyPair {
    fn public_identity(&self) -> IdentityKey {
        *self.identity_key()
    }

    fn identity_hash(&self) -> [u8; 32] {
        identity_hash(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_hash_is_stable_and_32_bytes() {
        let id = crate::generate_identity_key_pair();
        let h = identity_hash(&id);
        assert_eq!(h.len(), 32);
        // Same key → same hash.
        assert_eq!(hash_of_identity_key(id.identity_key()), h);
    }

    #[test]
    fn identity_hash_differs_for_different_identity_keys() {
        let a = crate::generate_identity_key_pair();
        let b = crate::generate_identity_key_pair();
        assert_ne!(identity_hash(&a), identity_hash(&b));
    }

    #[test]
    fn extension_trait_exposes_public_identity_and_hash() {
        let id = crate::generate_identity_key_pair();
        assert_eq!(id.public_identity(), *id.identity_key());
        assert_eq!(id.identity_hash(), identity_hash(&id));
    }

    #[test]
    fn message_type_tag_round_trips() {
        assert_eq!(
            message_type_from_tag(type_tag(MessageType::PreKey)),
            Some(MessageType::PreKey)
        );
        assert_eq!(
            message_type_from_tag(type_tag(MessageType::Ciphertext)),
            Some(MessageType::Ciphertext)
        );
        // Unknown tag → None (decrypt maps this to MalformedEnvelope).
        assert_eq!(message_type_from_tag(0), None);
        assert_eq!(message_type_from_tag(9), None);
    }
}
