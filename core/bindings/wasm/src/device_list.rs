//! WASM-facing signed device list: primary sign and verify (spec/v0.md §8.3).
//!
//! The browser client holds the primary's private identity bytes and the packed device
//! entries; it signs a versioned list and later verifies a list it received from the
//! relay. Both directions are byte-oriented so no `libsignal` type crosses the WASM
//! boundary, and every error path surfaces as a structured [`WasmError`], never a panic.
//!
//! ## Packed entry layout
//!
//! `entries` is a bare concatenation of records with no count prefix — the buffer is
//! parsed until exhaustion, and a partial trailing record is an error rather than a
//! silently dropped device:
//!
//! ```text
//! u32_le(device_id) | u32_le(identity_key_len) | identity_key
//!                   | u32_le(prekey_bundle_len) | prekey_bundle
//! ```
//!
//! `verify_device_list` returns the same layout prefixed with `u64_le(version)`.

use wasm_bindgen::prelude::*;

use crypto::identity::IdentityKeyPair;
use protocol::device_list::{DeviceListEntry, SignedDeviceList};
use protocol::fanout::{DeviceId, SignedRevocation};

use crate::WasmError;

/// The `WasmError::kind` every failure from this module carries.
const KIND: &str = "DeviceList";

/// Length of a serialized (type-tagged) Curve25519 public identity key.
const IDENTITY_KEY_LEN: usize = 33;

/// Map a core [`DeviceListError`](protocol::device_list::DeviceListError) to a JS-visible
/// error whose message names the variant, so the client can switch on it without parsing
/// prose. The `Display` text is deliberately not forwarded verbatim (Secure by Design).
fn device_list_error(error: &protocol::device_list::DeviceListError) -> WasmError {
    WasmError::new(KIND, &format!("{error:?}"))
}

/// Map a core [`RevocationError`](protocol::fanout::RevocationError) to a JS-visible error
/// whose message names the variant, so the client can switch on it without parsing prose.
/// The `Display` text is deliberately not forwarded verbatim (Secure by Design).
fn revocation_error(error: &protocol::fanout::RevocationError) -> WasmError {
    WasmError::new(KIND, &format!("{error:?}"))
}

/// Read a little-endian `u32` at `*pos`, advancing it. Bounds-checked: a short buffer is
/// an error, never a panic.
fn read_u32_le(buf: &[u8], pos: &mut usize) -> Result<u32, WasmError> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| WasmError::new(KIND, "Truncated"))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| WasmError::new(KIND, "Truncated"))?;
    let raw: [u8; 4] = slice
        .try_into()
        .map_err(|_| WasmError::new(KIND, "Truncated"))?;
    *pos = end;
    Ok(u32::from_le_bytes(raw))
}

/// Borrow `len` bytes at `*pos`, advancing it. Bounds-checked via `checked_add` + `get`,
/// so neither an overflowing length nor a short buffer can panic.
fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], WasmError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| WasmError::new(KIND, "Truncated"))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| WasmError::new(KIND, "Truncated"))?;
    *pos = end;
    Ok(slice)
}

/// Parse the packed entry buffer until exhaustion. A partial trailing record is
/// [`DeviceListError::Truncated`](protocol::device_list::DeviceListError::Truncated).
fn parse_entries(packed: &[u8]) -> Result<Vec<DeviceListEntry>, WasmError> {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    while pos < packed.len() {
        let device_id = read_u32_le(packed, &mut pos)?;
        let key_len = read_u32_le(packed, &mut pos)? as usize;
        let identity_key = read_bytes(packed, &mut pos, key_len)?.to_vec();
        let bundle_len = read_u32_le(packed, &mut pos)? as usize;
        let prekey_bundle = read_bytes(packed, &mut pos, bundle_len)?.to_vec();
        entries.push(DeviceListEntry {
            device_id,
            identity_key,
            prekey_bundle,
        });
    }
    Ok(entries)
}

/// Append one entry in the packed layout.
fn write_entry(out: &mut Vec<u8>, entry: &DeviceListEntry) {
    out.extend_from_slice(&entry.device_id.to_le_bytes());
    out.extend_from_slice(&(entry.identity_key.len() as u32).to_le_bytes());
    out.extend_from_slice(&entry.identity_key);
    out.extend_from_slice(&(entry.prekey_bundle.len() as u32).to_le_bytes());
    out.extend_from_slice(&entry.prekey_bundle);
}

/// Sign a device list at `version` with the account primary's identity key.
///
/// `primary_private_bytes` is the libsignal `IdentityKeyPairStructure` protobuf produced by
/// `IdentityHandle::private_bytes` — the same form [`identity_from_bytes`](crate::identity_from_bytes)
/// accepts. `entries` is the packed entry buffer described in the module docs.
///
/// Returns the on-the-wire blob produced by `SignedDeviceList::to_bytes`.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "DeviceList"` if the private bytes are malformed, if
/// `entries` ends mid-record (`Truncated`), or if signing fails (`BadSignature`). Never
/// panics.
#[wasm_bindgen]
pub fn sign_device_list(
    primary_private_bytes: &[u8],
    version: u64,
    entries: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let keypair = IdentityKeyPair::from_bytes(primary_private_bytes)
        .map_err(|e| WasmError::new(KIND, &e.to_string()))?;
    let entries = parse_entries(entries)?;
    let list = SignedDeviceList::sign(keypair.as_libsignal(), version, entries)
        .map_err(|e| device_list_error(&e))?;
    Ok(list.to_bytes())
}

/// Verify a signed device list against the expected account primary's identity key.
///
/// `expected_account` must be the 33-byte serialized public identity key of the account
/// primary. On success returns `u64_le(version)` followed by the packed entry buffer
/// described in the module docs.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "DeviceList"` whose message names the
/// `DeviceListError` variant — `BadAccountLength` if `expected_account` is not 33 bytes,
/// `WrongAccount` if the list is bound to a different account, `BadSignature` if the
/// signature does not verify, and the structural variants for a malformed blob. Never
/// panics.
#[wasm_bindgen]
pub fn verify_device_list(bytes: &[u8], expected_account: &[u8]) -> Result<Vec<u8>, WasmError> {
    if expected_account.len() != IDENTITY_KEY_LEN {
        return Err(WasmError::new(KIND, "BadAccountLength"));
    }

    let list = SignedDeviceList::from_bytes(bytes).map_err(|e| device_list_error(&e))?;

    // Decode the caller's bytes into the account's public identity key. The target type is
    // inferred from `verify`'s parameter, so this crate still does not name (or depend on)
    // a `libsignal-protocol` type directly. The length check above makes this infallible in
    // practice; the error path is mapped rather than unwrapped.
    let expected = expected_account
        .try_into()
        .map_err(|_| WasmError::new(KIND, "BadAccountLength"))?;

    list.verify(&expected).map_err(|e| device_list_error(&e))?;

    let mut out = Vec::with_capacity(8 + list.entries.len() * 12);
    out.extend_from_slice(&list.version.to_le_bytes());
    for entry in &list.entries {
        write_entry(&mut out, entry);
    }
    Ok(out)
}

/// Derive the account's human-shareable link key from its 33-byte serialized public
/// identity key.
///
/// Returns `"link:"` followed by the lowercase hex SHA-256 digest of the key — the same
/// string the protocol helper produces, so the client can show it without reimplementing
/// the derivation in JavaScript.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "DeviceList"` and message `BadIdentityKeyLength` if
/// `identity_key` is not exactly 33 bytes. Never panics.
#[wasm_bindgen]
pub fn derive_link_key(identity_key: &[u8]) -> Result<String, WasmError> {
    protocol::device_list::derive_link_key(identity_key).map_err(|e| device_list_error(&e))
}

/// Sign a revocation of `device_id` at device-list `version` with the account primary's
/// identity key.
///
/// `primary_private_bytes` is the libsignal `IdentityKeyPairStructure` protobuf produced
/// by `IdentityHandle::private_bytes` — the same form [`identity_from_bytes`](crate::identity_from_bytes)
/// accepts. Returns the on-the-wire blob produced by `SignedRevocation::to_bytes`.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "DeviceList"` if the private bytes are malformed or if
/// signing fails (`SigningFailed`). Never panics.
#[wasm_bindgen]
pub fn sign_revocation(
    primary_private_bytes: &[u8],
    device_id: u32,
    version: u64,
) -> Result<Vec<u8>, WasmError> {
    let keypair = IdentityKeyPair::from_bytes(primary_private_bytes)
        .map_err(|e| WasmError::new(KIND, &e.to_string()))?;
    let revocation = SignedRevocation::sign(keypair.as_libsignal(), DeviceId(device_id), version)
        .map_err(|e| revocation_error(&e))?;
    Ok(revocation.to_bytes())
}

/// Verify a signed revocation against the account primary's public identity key.
///
/// `primary_public_key` must be the 33-byte serialized public identity key of the account
/// primary. On success returns the revoked device id.
///
/// # Errors
///
/// Returns `WasmError` with `kind = "DeviceList"` whose message names the
/// `RevocationError` variant — `Malformed` for a truncated or unrecognized blob,
/// `NotEntitled` if the signature does not verify against the given key, and
/// `BadIdentityKeyLength` if `primary_public_key` is not 33 bytes. Never panics.
#[wasm_bindgen]
pub fn verify_revocation(bytes: &[u8], primary_public_key: &[u8]) -> Result<u32, WasmError> {
    if primary_public_key.len() != IDENTITY_KEY_LEN {
        return Err(WasmError::new(KIND, "BadIdentityKeyLength"));
    }

    let revocation = SignedRevocation::from_bytes(bytes).map_err(|e| revocation_error(&e))?;

    // Decode the caller's bytes into the primary's public identity key. The target type is
    // inferred from `verify`'s parameter, so this crate still does not name (or depend on)
    // a `libsignal-protocol` type directly. The length check above makes this infallible in
    // practice; the error path is mapped rather than unwrapped.
    let primary = primary_public_key
        .try_into()
        .map_err(|_| WasmError::new(KIND, "BadIdentityKeyLength"))?;

    revocation
        .verify(&primary)
        .map_err(|e| revocation_error(&e))?;
    Ok(revocation.device().0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::identity::IdentityKeyPair;

    /// The 33-byte serialized public identity key of `keypair`.
    fn public_bytes(keypair: &IdentityKeyPair) -> Vec<u8> {
        keypair.public().to_bytes()
    }

    /// The libsignal `IdentityKeyPairStructure` protobuf bytes for `keypair` — the same
    /// form `IdentityHandle::private_bytes` returns and `identity_from_bytes` accepts.
    fn private_bytes(keypair: &IdentityKeyPair) -> Vec<u8> {
        keypair.as_libsignal().serialize().to_vec()
    }

    /// One packed entry: `u32_le(device_id) | u32_le(key_len) | key | u32_le(bundle_len) | bundle`.
    fn pack_entry(device_id: u32, identity_key: &[u8], prekey_bundle: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&device_id.to_le_bytes());
        out.extend_from_slice(&(identity_key.len() as u32).to_le_bytes());
        out.extend_from_slice(identity_key);
        out.extend_from_slice(&(prekey_bundle.len() as u32).to_le_bytes());
        out.extend_from_slice(prekey_bundle);
        out
    }

    #[test]
    fn sign_then_verify_round_trips_two_entries() {
        let primary = IdentityKeyPair::generate();
        let linked = IdentityKeyPair::generate();

        let mut packed = pack_entry(0, &public_bytes(&primary), &[0xA0; 10]);
        packed.extend_from_slice(&pack_entry(1, &public_bytes(&linked), &[0xB1; 7]));

        let blob = sign_device_list(&private_bytes(&primary), 5, &packed)
            .expect("signing a well-formed two-entry list must succeed");
        let out = verify_device_list(&blob, &public_bytes(&primary))
            .expect("a freshly signed list must verify against its own account");

        let mut expected = 5u64.to_le_bytes().to_vec();
        expected.extend_from_slice(&packed);
        assert_eq!(
            out, expected,
            "verify must return version + the packed entries"
        );
    }

    #[test]
    fn verify_rejects_wrong_account() {
        let primary = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();

        let packed = pack_entry(0, &public_bytes(&primary), &[0xA0; 10]);
        let blob = sign_device_list(&private_bytes(&primary), 1, &packed)
            .expect("signing a well-formed list must succeed");

        assert!(
            verify_device_list(&blob, &public_bytes(&other)).is_err(),
            "a list signed by one account must not verify against another account"
        );
    }

    #[test]
    fn sign_rejects_truncated_entries() {
        let primary = IdentityKeyPair::generate();

        // device_id=7, key_len=33, 33 key bytes, bundle_len=10, but only 4 bundle bytes:
        // 49 bytes present where 55 are required.
        let mut packed = Vec::new();
        packed.extend_from_slice(&7u32.to_le_bytes());
        packed.extend_from_slice(&33u32.to_le_bytes());
        packed.extend_from_slice(&[0x05; 33]);
        packed.extend_from_slice(&10u32.to_le_bytes());
        packed.extend_from_slice(&[0xEE; 4]);
        assert_eq!(packed.len(), 49);

        assert!(
            sign_device_list(&private_bytes(&primary), 1, &packed).is_err(),
            "a partial trailing record must be rejected, not silently dropped"
        );
    }

    #[test]
    fn verify_rejects_flipped_byte() {
        let primary = IdentityKeyPair::generate();
        let linked = IdentityKeyPair::generate();

        let mut packed = pack_entry(0, &public_bytes(&primary), &[0xA0; 10]);
        packed.extend_from_slice(&pack_entry(1, &public_bytes(&linked), &[0xB1; 3]));

        let mut blob = sign_device_list(&private_bytes(&primary), 5, &packed)
            .expect("signing a well-formed list must succeed");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        assert!(
            verify_device_list(&blob, &public_bytes(&primary)).is_err(),
            "a single flipped signature byte must fail verification"
        );
    }

    /// The link key is a pure function of the 33-byte identity key. The expected value is
    /// the same recorded vector the protocol test asserts, so a change to the derivation
    /// breaks both sides and the TypeScript test that shares it.
    #[test]
    fn derive_link_key_matches_the_recorded_vector() {
        const EXPECTED: &str =
            "link:ce041765675ad4d93378e20bd3a7d0d97ddcf3385fb6341581b21d4bc9e3e69e";
        let key = [0x01u8; 33];
        assert_eq!(
            derive_link_key(&key).expect("a 33-byte identity key must derive a link key"),
            EXPECTED
        );
        // Deterministic: a second call returns the identical string.
        assert_eq!(
            derive_link_key(&key).expect("a 33-byte identity key must derive a link key"),
            derive_link_key(&key).expect("a 33-byte identity key must derive a link key")
        );
    }

    /// A 32-byte slice is not a serialized identity key, so it must be rejected rather
    /// than hashed into a plausible-looking link key.
    #[test]
    fn derive_link_key_rejects_a_32_byte_identity_key() {
        assert!(
            derive_link_key(&[0x01u8; 32]).is_err(),
            "a 32-byte identity key must be rejected"
        );
    }

    /// Signing a revocation and verifying it against the signing primary's public key
    /// returns the revoked device id — the round trip the client relies on.
    #[test]
    fn sign_then_verify_revocation_returns_the_device_id() {
        let primary = IdentityKeyPair::generate();
        let blob = sign_revocation(&private_bytes(&primary), 7, 3)
            .expect("signing a revocation with a valid keypair must succeed");
        let device = verify_revocation(&blob, &public_bytes(&primary))
            .expect("a freshly signed revocation must verify against its own primary");
        assert_eq!(device, 7, "verify must return the revoked device id");
    }

    /// A revocation signed by one account must not verify against another account's
    /// public key: entitlement is checked against the key the record names.
    #[test]
    fn verify_revocation_rejects_wrong_public_key() {
        let primary = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let blob = sign_revocation(&private_bytes(&primary), 1, 2)
            .expect("signing a revocation must succeed");
        assert!(
            verify_revocation(&blob, &public_bytes(&other)).is_err(),
            "a revocation must not verify against a different account's primary"
        );
    }

    /// A truncated revocation blob is a parse error, never a panic or a partial accept.
    #[test]
    fn verify_revocation_rejects_truncated_bytes() {
        let primary = IdentityKeyPair::generate();
        let blob = sign_revocation(&private_bytes(&primary), 1, 2)
            .expect("signing a revocation must succeed");
        let truncated = &blob[..blob.len() - 1];
        assert!(
            verify_revocation(truncated, &public_bytes(&primary)).is_err(),
            "a truncated revocation must be rejected"
        );
    }

    /// A public key that is not 33 bytes cannot be a serialized identity key.
    #[test]
    fn verify_revocation_rejects_a_short_public_key() {
        let primary = IdentityKeyPair::generate();
        let blob = sign_revocation(&private_bytes(&primary), 1, 2)
            .expect("signing a revocation must succeed");
        assert!(
            verify_revocation(&blob, &[0x05u8; 32]).is_err(),
            "a 32-byte public key must be rejected"
        );
    }
}
