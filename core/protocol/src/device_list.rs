//! The primary-signed device list wire type (spec/v0.md §8.3).
//!
//! A multi-device account publishes one *signed device list*: the set of devices that
//! belong to the account, each with its own identity key and PQXDH prekey bundle, plus
//! the account binding and a monotonically increasing version. The primary device signs
//! the canonical encoding of that set, so any peer can check the list against the
//! account primary's public identity key before fanning a message out to it
//! ([`crate::fanout`]).
//!
//! # Encoding
//!
//! [`SignedDeviceList::canonical_bytes`] is the byte string the primary signs. It is
//! domain-separated by the ASCII prefix `e2e:device-list:v1` and uses fixed-width
//! big-endian integers throughout, so the encoding is unambiguous and independent of
//! the host's endianness or pointer width:
//!
//! ```text
//! "e2e:device-list:v1"          (18 bytes)
//! u64_be(version)
//! u32_be(account.len())  account
//! u32_be(entries.len())
//! per entry:
//!     u32_be(device_id)
//!     u32_be(identity_key.len())  identity_key
//!     u32_be(prekey_bundle.len()) prekey_bundle
//! ```
//!
//! The signature is deliberately **not** part of `canonical_bytes` — it is what signs
//! them. [`SignedDeviceList::to_bytes`] appends `u32_be(sig.len())` and the signature to
//! produce the on-the-wire blob that [`SignedDeviceList::from_bytes`] parses.
//!
//! # Structural validity
//!
//! Parsing is not the same as validity. [`SignedDeviceList::from_bytes`] parses the
//! framing and then enforces the structural invariants a verifier relies on:
//!
//! - the account binding is exactly 33 bytes (a serialized libsignal `IdentityKey`:
//!   one `0x05` type byte plus 32 key bytes);
//! - `version >= 1`, so a list can never be confused with "no list yet";
//! - between 1 and 256 entries;
//! - exactly one entry with `device_id == 0` — the primary is itself a fan-out
//!   recipient — and no duplicate device ids;
//! - every identity key is exactly 33 bytes and every prekey bundle is 1..=8192 bytes;
//! - the whole blob is at most 65536 bytes and carries no trailing bytes.
//!
//! `from_bytes` never panics: every read is bounds-checked and every length is
//! validated before it is used, so hostile input yields an error rather than a crash.

use thiserror::Error;

/// Domain-separation prefix for the canonical device-list encoding.
const MAGIC: &[u8] = b"e2e:device-list:v1";

/// Length of a serialized libsignal `IdentityKey` (1 type byte + 32 key bytes).
const IDENTITY_KEY_LEN: usize = 33;

/// Largest accepted prekey bundle, in bytes.
const MAX_BUNDLE_LEN: usize = 8192;

/// Largest accepted number of entries in a device list.
const MAX_ENTRIES: usize = 256;

/// Largest accepted on-the-wire blob, in bytes.
const MAX_BLOB_LEN: usize = 65536;

/// One device in a [`SignedDeviceList`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListEntry {
    /// The device id. `0` is reserved for the account's primary device; linked devices
    /// use ids `>= 1`.
    pub device_id: u32,
    /// The device's serialized public identity key (33 bytes).
    pub identity_key: Vec<u8>,
    /// The device's serialized PQXDH prekey bundle (1..=8192 bytes).
    pub prekey_bundle: Vec<u8>,
}

/// A primary-signed, monotonically versioned device list (spec/v0.md §8.3).
///
/// The signature covers [`canonical_bytes`](Self::canonical_bytes) and is verified
/// against the account primary's public identity key. The account binding is inside the
/// record and inside the signed material, so a verifier can attribute the list to its
/// account from the record alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDeviceList {
    /// The account this list belongs to: the serialized public identity key of the
    /// primary that signed it (33 bytes).
    pub account: Vec<u8>,
    /// Monotonically increasing device-list version. Must be `>= 1`.
    pub version: u64,
    /// The account's devices, including the primary (`device_id == 0`) exactly once.
    pub entries: Vec<DeviceListEntry>,
    /// The primary's signature over [`canonical_bytes`](Self::canonical_bytes).
    pub primary_signature: Vec<u8>,
}

/// Errors [`SignedDeviceList::from_bytes`] can surface to its caller.
///
/// Per the project's Secure by Design standard, callers relaying these across a network
/// trust boundary must not forward the `Display` text verbatim — return a generic reason
/// to the peer and log the full detail locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeviceListError {
    /// The blob ended before the framing did. Every read is bounds-checked, so a
    /// truncated blob is an error rather than a panic.
    #[error("truncated signed device list")]
    Truncated,
    /// The blob exceeded [`MAX_BLOB_LEN`]. Rejected before any parsing so an oversized
    /// input cannot drive allocation or work.
    #[error("signed device list exceeds the maximum size")]
    Oversized,
    /// The blob did not start with the `e2e:device-list:v1` domain-separation prefix.
    #[error("signed device list has an unrecognized domain prefix")]
    BadMagic,
    /// The account binding was not a 33-byte serialized identity key.
    #[error("account binding must be a 33-byte serialized identity key")]
    BadAccountLength,
    /// The version was `0`. Device-list versions start at 1 so that "no list yet" is
    /// never representable as a valid list.
    #[error("device-list version must be at least 1")]
    BadVersion,
    /// No entry carried `device_id == 0`. The primary is itself a fan-out recipient, so
    /// a list without it is not a device list.
    #[error("device list has no primary device (device id 0)")]
    MissingPrimary,
    /// Two entries carried the same `device_id`. A device list is a set; a duplicate
    /// makes the fan-out ambiguous.
    #[error("device list contains a duplicate device id")]
    DuplicateDeviceId,
    /// The list carried more than [`MAX_ENTRIES`] entries.
    #[error("device list has too many entries")]
    TooManyEntries,
    /// An entry's identity key was not exactly 33 bytes.
    #[error("device identity key must be 33 bytes")]
    BadIdentityKeyLength,
    /// An entry's prekey bundle was empty or larger than [`MAX_BUNDLE_LEN`].
    #[error("device prekey bundle length is out of range")]
    BadBundleLength,
    /// Bytes remained after the signature. Trailing data means the blob is not the
    /// canonical encoding of the record it claims to be.
    #[error("trailing bytes after signed device list")]
    TrailingBytes,
    /// The list's account binding was not the expected account primary's identity key.
    /// Checked before the signature so an attacker-signed list is attributed to the
    /// wrong account rather than accepted on the strength of its own key.
    #[error("device list is not bound to the expected account")]
    WrongAccount,
    /// The primary signature did not verify over the canonical bytes. The list was
    /// tampered with, or was not signed by the account it names.
    #[error("device list signature is invalid")]
    BadSignature,
}

impl SignedDeviceList {
    /// The byte string the primary signs.
    ///
    /// Deterministic and side-effect free: repeated calls on the same value return the
    /// same bytes, and the record is never mutated (entries are not sorted or drained).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MAGIC.len()
                + 8
                + 4
                + self.account.len()
                + 4
                + self
                    .entries
                    .iter()
                    .map(|e| 12 + e.identity_key.len() + e.prekey_bundle.len())
                    .sum::<usize>(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.account.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.device_id.to_be_bytes());
            out.extend_from_slice(&(entry.identity_key.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.identity_key);
            out.extend_from_slice(&(entry.prekey_bundle.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.prekey_bundle);
        }
        out
    }

    /// The on-the-wire blob: [`canonical_bytes`](Self::canonical_bytes) followed by
    /// `u32_be(signature.len())` and the signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes();
        out.extend_from_slice(&(self.primary_signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.primary_signature);
        out
    }

    /// Parse and structurally validate a blob produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceListError::Oversized`] if the blob is larger than 65536 bytes,
    /// [`DeviceListError::Truncated`] if it ends mid-field,
    /// [`DeviceListError::BadMagic`] if the domain prefix is wrong,
    /// [`DeviceListError::TrailingBytes`] if bytes remain after the signature, and the
    /// remaining variants for structural violations. Never panics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceListError> {
        if bytes.len() > MAX_BLOB_LEN {
            return Err(DeviceListError::Oversized);
        }

        let mut reader = Reader::new(bytes);

        if reader.take(MAGIC.len())? != MAGIC {
            return Err(DeviceListError::BadMagic);
        }
        let version = reader.u64()?;

        let account_len = reader.u32()? as usize;
        let account = reader.take(account_len)?.to_vec();

        let entry_count = reader.u32()? as usize;
        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let device_id = reader.u32()?;
            let key_len = reader.u32()? as usize;
            let identity_key = reader.take(key_len)?.to_vec();
            let bundle_len = reader.u32()? as usize;
            let prekey_bundle = reader.take(bundle_len)?.to_vec();
            entries.push(DeviceListEntry {
                device_id,
                identity_key,
                prekey_bundle,
            });
        }

        let sig_len = reader.u32()? as usize;
        let primary_signature = reader.take(sig_len)?.to_vec();

        if reader.cursor != bytes.len() {
            return Err(DeviceListError::TrailingBytes);
        }

        let list = Self {
            account,
            version,
            entries,
            primary_signature,
        };
        list.validate()?;
        Ok(list)
    }

    /// Enforce the structural invariants a verifier relies on.
    fn validate(&self) -> Result<(), DeviceListError> {
        if self.account.len() != IDENTITY_KEY_LEN {
            return Err(DeviceListError::BadAccountLength);
        }
        if self.version < 1 {
            return Err(DeviceListError::BadVersion);
        }
        if self.entries.is_empty() {
            return Err(DeviceListError::MissingPrimary);
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(DeviceListError::TooManyEntries);
        }

        // Duplicates are checked across *all* ids before the primary count, so two
        // primaries report `DuplicateDeviceId` rather than a misleading `MissingPrimary`.
        let mut seen: Vec<u32> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            if seen.contains(&entry.device_id) {
                return Err(DeviceListError::DuplicateDeviceId);
            }
            seen.push(entry.device_id);
        }

        if self.entries.iter().filter(|e| e.device_id == 0).count() != 1 {
            return Err(DeviceListError::MissingPrimary);
        }

        for entry in &self.entries {
            if entry.identity_key.len() != IDENTITY_KEY_LEN {
                return Err(DeviceListError::BadIdentityKeyLength);
            }
            if entry.prekey_bundle.is_empty() || entry.prekey_bundle.len() > MAX_BUNDLE_LEN {
                return Err(DeviceListError::BadBundleLength);
            }
        }

        Ok(())
    }
}

impl SignedDeviceList {
    /// Sign a device list at `version` with the account primary's identity key.
    ///
    /// The account binding is set to `primary`'s *public* identity key — the 33-byte
    /// serialized form (one `0x05` type byte plus 32 key bytes), never the 32-byte
    /// private key — so a verifier can attribute the list to its account from the
    /// record alone.
    ///
    /// `version` and `entries` are stored exactly as supplied and the signature is
    /// computed over [`canonical_bytes`](Self::canonical_bytes) of those stored values.
    /// Nothing is sorted, deduplicated or reordered: `verify` recomputes the canonical
    /// bytes over the stored order, so canonicalizing over a different copy would make
    /// a freshly signed list fail its own signature check.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceListError::BadSignature`] if the underlying `libsignal` signing
    /// call fails (unreachable in practice for this workspace's Curve25519 keys, but
    /// propagated rather than panicking).
    pub fn sign(
        primary: &libsignal_protocol::IdentityKeyPair,
        version: u64,
        entries: Vec<DeviceListEntry>,
    ) -> Result<Self, DeviceListError> {
        // `TryRngCore::unwrap_err` turns the fallible `OsRng` into an infallible one;
        // the same primitive `fanout::SignedRevocation::sign` uses.
        use rand::TryRngCore;

        let list = Self {
            account: primary.public_key().serialize().into_vec(),
            version,
            entries,
            // Filled in below, once the canonical bytes exist.
            primary_signature: Vec::new(),
        };
        let canonical = list.canonical_bytes();
        let signature = primary
            .private_key()
            .calculate_signature_for_multipart_message(
                &[&canonical],
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .map_err(|_| DeviceListError::BadSignature)?;
        Ok(Self {
            primary_signature: signature.into_vec(),
            ..list
        })
    }

    /// Verify this list against the account primary's public identity key.
    ///
    /// Checks run in this order, and the order is load-bearing:
    ///
    /// 1. **Account binding.** `self.account` must be byte-identical to
    ///    `expected_account.serialize()`. This is the cheapest decisive check and it
    ///    subsumes the 33-byte account-length invariant, so a hand-built record with
    ///    garbage account bytes is [`DeviceListError::WrongAccount`] rather than a
    ///    length error — and, because the comparison is over bytes, it never decodes
    ///    attacker-supplied key material and so never panics.
    /// 2. **Structural validity.** The MD-1 invariants are re-run over `self.entries`,
    ///    so a hand-built struct cannot bypass them by skipping `from_bytes`.
    /// 3. **Signature.** Verified over [`canonical_bytes`](Self::canonical_bytes) using
    ///    `expected_account` — after step 1 it is byte-identical to `self.account`, so
    ///    the verifying key is always the caller's, never one the record names.
    ///
    /// Checking the signature before the account binding would accept an
    /// attacker-signed list on the strength of the attacker's own key; checking it
    /// before the structural pass would report [`DeviceListError::BadSignature`] for a
    /// list whose real defect is a duplicate device id.
    ///
    /// # Errors
    ///
    /// - [`DeviceListError::WrongAccount`] if the list is bound to another account.
    /// - Any structural error [`SignedDeviceList::from_bytes`] can return (e.g.
    ///   [`DeviceListError::DuplicateDeviceId`]) if the entries are invalid.
    /// - [`DeviceListError::BadSignature`] if the signature does not verify.
    pub fn verify(
        &self,
        expected_account: &libsignal_protocol::IdentityKey,
    ) -> Result<(), DeviceListError> {
        if self.account != expected_account.serialize().into_vec() {
            return Err(DeviceListError::WrongAccount);
        }
        self.validate()?;
        let canonical = self.canonical_bytes();
        // Fails closed: a wrong-length signature is `false`, not an exception.
        if expected_account
            .public_key()
            .verify_signature(&canonical, &self.primary_signature)
        {
            Ok(())
        } else {
            Err(DeviceListError::BadSignature)
        }
    }

    /// Whether this list supersedes the version the caller already holds.
    ///
    /// `true` iff nothing is held yet, or this list's version is *strictly* greater.
    /// Strictly greater matters: a replayed same-version list must not be accepted.
    ///
    /// Side-effect free — the held version is caller state, so this takes `&self` and
    /// mutates nothing. A caller that stored `self.version` even when this returned
    /// `false` would regress its high-water mark and then accept a replay.
    pub fn is_newer_than(&self, held_version: Option<u64>) -> bool {
        held_version.is_none_or(|held| self.version > held)
    }
}

/// A bounds-checked cursor over an untrusted byte slice.
///
/// Every read goes through [`Reader::take`], which uses `checked_add` and `get` so a
/// short or hostile input yields [`DeviceListError::Truncated`] instead of a panic.
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DeviceListError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(DeviceListError::Truncated)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(DeviceListError::Truncated)?;
        self.cursor = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, DeviceListError> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DeviceListError::Truncated)?;
        Ok(u32::from_be_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, DeviceListError> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DeviceListError::Truncated)?;
        Ok(u64::from_be_bytes(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 33-byte serialized libsignal identity key (0x05 type byte + 32 key bytes).
    fn key(seed: u8) -> Vec<u8> {
        let mut k = vec![0x05u8];
        k.extend_from_slice(&[seed; 32]);
        k
    }

    fn entry(device_id: u32, seed: u8, bundle_len: usize) -> DeviceListEntry {
        DeviceListEntry {
            device_id,
            identity_key: key(seed),
            prekey_bundle: vec![seed; bundle_len],
        }
    }

    fn valid_list() -> SignedDeviceList {
        SignedDeviceList {
            account: key(0xAA),
            version: 2,
            entries: vec![entry(0, 0x01, 5), entry(1, 0x02, 3)],
            primary_signature: vec![0x77; 64],
        }
    }

    #[test]
    fn round_trip_two_entries() {
        let list = valid_list();
        let bytes = list.to_bytes();
        let parsed = SignedDeviceList::from_bytes(&bytes).expect("valid blob must parse");
        assert_eq!(parsed, list);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].device_id, 0);
        assert_eq!(parsed.entries[1].device_id, 1);
    }

    #[test]
    fn canonical_bytes_stable_across_calls() {
        let list = valid_list();
        let first = list.canonical_bytes();
        let second = list.canonical_bytes();
        assert_eq!(first, second);
        assert_eq!(first.len(), 165);
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.version, 2);
    }

    #[test]
    fn every_prefix_is_truncated_without_panic() {
        let bytes = valid_list().to_bytes();
        assert_eq!(bytes.len(), 233);
        for len in 0..bytes.len() {
            let prefix = &bytes[..len];
            assert_eq!(
                SignedDeviceList::from_bytes(prefix),
                Err(DeviceListError::Truncated),
                "prefix of length {len} must be Truncated"
            );
        }
        assert!(SignedDeviceList::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn oversized_blob_rejected() {
        let blob = vec![0u8; 65537];
        assert_eq!(
            SignedDeviceList::from_bytes(&blob),
            Err(DeviceListError::Oversized)
        );
    }

    #[test]
    fn missing_primary_rejected() {
        let mut list = valid_list();
        list.entries = vec![entry(1, 0x01, 5), entry(2, 0x02, 3)];
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::MissingPrimary)
        );
    }

    #[test]
    fn duplicate_primary_rejected() {
        let mut list = valid_list();
        list.entries = vec![entry(0, 0x01, 5), entry(0, 0x02, 3)];
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::DuplicateDeviceId)
        );
    }

    #[test]
    fn duplicate_linked_device_rejected() {
        let mut list = valid_list();
        list.entries = vec![entry(0, 0x01, 5), entry(1, 0x02, 3), entry(1, 0x03, 4)];
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::DuplicateDeviceId)
        );
    }

    #[test]
    fn bad_identity_key_length_rejected() {
        let mut list = valid_list();
        list.entries[1].identity_key = vec![0x05; 32];
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::BadIdentityKeyLength)
        );
    }

    #[test]
    fn empty_bundle_rejected() {
        let mut list = valid_list();
        list.entries[1].prekey_bundle = Vec::new();
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::BadBundleLength)
        );
    }

    #[test]
    fn bad_version_rejected() {
        let mut list = valid_list();
        list.version = 0;
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::BadVersion)
        );
    }

    #[test]
    fn bad_account_length_rejected() {
        let mut list = valid_list();
        list.account = vec![0x05; 32];
        let bytes = list.to_bytes();
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::BadAccountLength)
        );
    }

    #[test]
    fn trailing_byte_rejected() {
        let mut bytes = valid_list().to_bytes();
        bytes.push(0x00);
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::TrailingBytes)
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = valid_list().to_bytes();
        bytes[0] ^= 0xFF;
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::BadMagic)
        );
    }

    #[test]
    fn too_many_entries_rejected() {
        let mut entries = vec![entry(0, 0x01, 1)];
        for id in 1..=256u32 {
            entries.push(entry(id, 0x02, 1));
        }
        let list = SignedDeviceList {
            account: key(0xAA),
            version: 1,
            entries,
            primary_signature: vec![0x77; 64],
        };
        let bytes = list.to_bytes();
        assert!(bytes.len() < 65536);
        assert_eq!(
            SignedDeviceList::from_bytes(&bytes),
            Err(DeviceListError::TooManyEntries)
        );
    }
}

/// Signing, verification and version-check coverage for [`SignedDeviceList`]
/// (spec/v0.md §8.3).
///
/// Kept in its own module so the MD-1 wire-format tests above stay untouched: this
/// module covers the *trust* half of the contract — who signed a list, whether a
/// hand-built struct can bypass structural validation, and whether a replayed version
/// is rejected.
#[cfg(test)]
mod device_list_signing_tests {
    use super::*;
    use crypto::generate_identity_key_pair;
    use libsignal_protocol::{IdentityKey, IdentityKeyPair};

    /// The account binding a verifier expects: the keypair's public identity key.
    /// Mirrors `crypto::IdentityKeyPairExt::public_identity`.
    fn account(pair: &IdentityKeyPair) -> IdentityKey {
        *pair.identity_key()
    }

    /// A 33-byte serialized libsignal identity key (0x05 type byte + 32 key bytes).
    fn key(seed: u8) -> Vec<u8> {
        let mut k = vec![0x05u8];
        k.extend_from_slice(&[seed; 32]);
        k
    }

    fn entry(device_id: u32, seed: u8) -> DeviceListEntry {
        DeviceListEntry {
            device_id,
            identity_key: key(seed),
            prekey_bundle: vec![seed; 4],
        }
    }

    /// A structurally valid two-device list (primary + one linked device).
    fn entries() -> Vec<DeviceListEntry> {
        vec![entry(0, 0x01), entry(1, 0x02)]
    }

    #[test]
    fn sign_then_verify_with_matching_account_succeeds() {
        let primary = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");

        // The account binding is the *public* key (33 bytes, leading 0x05), never the
        // 32-byte private key.
        assert_eq!(list.account, primary.public_key().serialize().into_vec());
        assert_eq!(list.account.len(), 33);
        assert_eq!(list.version, 4);
        assert_eq!(list.entries, entries());
        assert!(!list.primary_signature.is_empty());

        assert_eq!(list.verify(&account(&primary)), Ok(()));
    }

    #[test]
    fn is_newer_than_none_and_older_versions_true() {
        let primary = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");

        assert!(
            list.is_newer_than(None),
            "no held version means any list is newer"
        );
        assert!(list.is_newer_than(Some(3)), "version 4 is newer than 3");
        assert!(list.is_newer_than(Some(1)), "version 4 is newer than 1");
    }

    #[test]
    fn is_newer_than_same_and_newer_versions_false() {
        let primary = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");

        // Strictly greater: a replayed same-version list must be rejected.
        assert!(
            !list.is_newer_than(Some(4)),
            "version 4 is not newer than 4"
        );
        assert!(
            !list.is_newer_than(Some(5)),
            "version 4 is not newer than 5"
        );
        assert!(
            !list.is_newer_than(Some(9)),
            "version 4 is not newer than 9"
        );
    }

    #[test]
    fn tampered_bundle_byte_fails_signature() {
        let primary = generate_identity_key_pair();
        // A distinctive payload so the flipped byte is provably inside an entry's
        // opaque bundle, not a length prefix or an id field.
        let bundle = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44];
        let list = SignedDeviceList::sign(
            &primary,
            4,
            vec![
                entry(0, 0x01),
                DeviceListEntry {
                    device_id: 1,
                    identity_key: key(0x02),
                    prekey_bundle: bundle.clone(),
                },
            ],
        )
        .expect("signing must succeed");

        let mut bytes = list.to_bytes();
        let pos = bytes
            .windows(bundle.len())
            .position(|w| w == bundle.as_slice())
            .expect("the bundle payload must appear verbatim in the blob");
        bytes[pos + 3] ^= 0xFF;

        let tampered =
            SignedDeviceList::from_bytes(&bytes).expect("a flipped payload byte still parses");
        assert_ne!(
            tampered.entries[1].prekey_bundle, bundle,
            "the tamper must land inside the bundle payload"
        );
        assert_eq!(
            tampered.verify(&account(&primary)),
            Err(DeviceListError::BadSignature)
        );
    }

    #[test]
    fn verify_with_a_different_account_is_wrong_account() {
        let primary = generate_identity_key_pair();
        let other = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");

        assert_eq!(
            list.verify(&account(&other)),
            Err(DeviceListError::WrongAccount)
        );
    }

    #[test]
    fn list_signed_by_attacker_key_is_wrong_account() {
        let primary = generate_identity_key_pair();
        let attacker = generate_identity_key_pair();
        // The attacker signs a perfectly valid list with its own key.
        let forged = SignedDeviceList::sign(&attacker, 4, entries()).expect("signing must succeed");

        // Verified against the real primary it must be rejected on the account binding,
        // not accepted because the signature happens to be valid under the attacker key.
        assert_eq!(
            forged.verify(&account(&primary)),
            Err(DeviceListError::WrongAccount)
        );
    }

    #[test]
    fn hand_built_duplicate_ids_fail_structural_validation() {
        let primary = generate_identity_key_pair();
        // Correct account, garbage signature: the structural check must fire first so a
        // hand-built struct cannot bypass the MD-1 invariants.
        let list = SignedDeviceList {
            account: primary.public_key().serialize().into_vec(),
            version: 4,
            entries: vec![entry(0, 0x01), entry(7, 0x02), entry(7, 0x03)],
            primary_signature: vec![0x00; 64],
        };

        assert_eq!(
            list.verify(&account(&primary)),
            Err(DeviceListError::DuplicateDeviceId)
        );
    }

    #[test]
    fn hand_built_garbage_account_is_wrong_account_without_panic() {
        let primary = generate_identity_key_pair();
        // Five bytes is not a decodable identity key. A verifier that decoded the
        // attacker-supplied bytes would panic here; comparing bytes first does not.
        let list = SignedDeviceList {
            account: vec![0u8; 5],
            version: 4,
            entries: entries(),
            primary_signature: vec![0x00; 64],
        };

        assert_eq!(
            list.verify(&account(&primary)),
            Err(DeviceListError::WrongAccount)
        );
    }

    /// The signature must cover the stored entry order: signing must not canonicalize
    /// over a sorted/deduplicated copy while storing the unsorted `Vec`.
    #[test]
    fn signature_covers_stored_entry_order() {
        let primary = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");
        assert_eq!(
            list.entries,
            entries(),
            "sign must store the entries unchanged"
        );

        let mut reordered = list.clone();
        reordered.entries.reverse();
        assert_eq!(
            reordered.verify(&account(&primary)),
            Err(DeviceListError::BadSignature)
        );
    }

    /// `is_newer_than` must not mutate: the caller owns the held version.
    #[test]
    fn is_newer_than_does_not_mutate_the_list() {
        let primary = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 4, entries()).expect("signing must succeed");
        let before = list.clone();

        assert!(!list.is_newer_than(Some(5)));
        assert_eq!(list, before, "is_newer_than must be side-effect free");
        assert_eq!(list.version, 4);
    }

    /// `sign` must reject nothing it is given — but a caller-supplied list that is
    /// structurally invalid must still fail `verify`, never panic.
    #[test]
    fn verify_never_panics_on_hostile_input() {
        let primary = generate_identity_key_pair();
        let hostile = [
            SignedDeviceList {
                account: Vec::new(),
                version: 0,
                entries: Vec::new(),
                primary_signature: Vec::new(),
            },
            SignedDeviceList {
                account: vec![0xFF; 33],
                version: u64::MAX,
                entries: vec![entry(0, 0x01)],
                primary_signature: vec![0xFF; 1],
            },
            SignedDeviceList {
                account: primary.public_key().serialize().into_vec(),
                version: 1,
                entries: vec![entry(1, 0x01)],
                primary_signature: vec![0xFF; 64],
            },
        ];
        for list in &hostile {
            assert!(
                list.verify(&account(&primary)).is_err(),
                "hostile list must be rejected, not accepted"
            );
        }
    }

    /// `IdentityKeyPair` is only used to prove the signature type is the libsignal one.
    #[test]
    fn sign_accepts_a_libsignal_identity_key_pair() {
        let primary: IdentityKeyPair = generate_identity_key_pair();
        let list = SignedDeviceList::sign(&primary, 1, entries()).expect("signing must succeed");
        assert_eq!(list.verify(&account(&primary)), Ok(()));
    }
}
