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
