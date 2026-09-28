//! Device revocation — the *verifiable* path (spec/v0.md §8, PLAN.md Phase 6).
//!
//! The local half of the revocation contract — `FanoutSession::remove_device` drops a device's
//! ratchet state so the next `encrypt_to_all` no longer targets it — is pinned by
//! `tests/per_device_fanout.rs` and must keep working exactly as it does today. This file covers
//! the half §8.3 adds: revocation is a **signed, monotonically versioned** fact that a peer
//! *verifies* before acting on it, instead of a local sender-side shortcut.
//!
//! # Public API this file grades (must exist in `protocol::fanout`)
//!
//! ```text
//! pub struct SignedRevocation;
//! impl SignedRevocation {
//!     pub fn sign(primary: &IdentityKeyPair, device: DeviceId, version: u64)
//!         -> Result<Self, RevocationError>;
//!     pub fn device(&self) -> DeviceId;
//!     pub fn version(&self) -> u64;
//!     pub fn to_bytes(&self) -> Vec<u8>;
//!     pub fn from_bytes(bytes: &[u8]) -> Result<Self, RevocationError>;
//!     pub fn verify(&self, primary: &IdentityKey) -> Result<(), RevocationError>;
//! }
//!
//! pub enum RevocationError {   // derives Debug + Display (thiserror)
//!     SigningFailed,
//!     Malformed,
//!     NotEntitled,
//!     StaleVersion { held: u64, offered: u64 },
//!     UnknownDevice(DeviceId),
//!     AlreadyRevoked(DeviceId),
//! }
//!
//! impl FanoutSession {
//!     pub fn apply_revocation(&mut self, revocation: &SignedRevocation, primary: &IdentityKey)
//!         -> Result<(), RevocationError>;
//!     /// Highest revocation version observed; 0 until the first revocation is applied.
//!     pub fn revocation_version(&self) -> u64;
//!     /// True only for a device this session has applied a revocation for.
//!     pub fn is_revoked(&self, device: DeviceId) -> bool;
//! }
//! ```
//!
//! A rejected `apply_revocation` must leave the session unchanged: no device becomes revoked and
//! `revocation_version` does not advance.
//!
//! `IdentityKey` is `libsignal_protocol::IdentityKey`; a keypair's public half comes from
//! `crypto::IdentityKeyPairExt::public_identity`. `remove_device` and every existing
//! `FanoutError` variant keep their current signatures and meanings — this is an additive path,
//! not a replacement.

use crypto::{generate_identity_key_pair, IdentityKeyPair, IdentityKeyPairExt};
use protocol::fanout::{DeviceId, FanoutSession, RevocationError, SignedRevocation};

/// Establish a fan-out to `n` freshly generated recipient devices, numbered 1..=n.
fn fanout_with_devices(n: u32) -> (FanoutSession, Vec<IdentityKeyPair>) {
    let sender = generate_identity_key_pair();
    let devices: Vec<IdentityKeyPair> = (0..n).map(|_| generate_identity_key_pair()).collect();
    let refs: Vec<(DeviceId, &IdentityKeyPair)> = devices
        .iter()
        .enumerate()
        .map(|(i, kp)| (DeviceId(i as u32 + 1), kp))
        .collect();
    let fanout = FanoutSession::establish(&sender, &refs).expect("establish");
    (fanout, devices)
}

#[test]
fn primary_signed_revocation_verifies_and_stops_delivery() {
    let (mut fanout, devices) = fanout_with_devices(3);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();

    let before = fanout
        .encrypt_to_all(b"before revocation")
        .expect("encrypt");
    assert_eq!(before.len(), 3);
    let for_device_2 = before
        .iter()
        .find(|c| c.device == DeviceId(2))
        .expect("ciphertext for device 2")
        .clone();

    let revocation = SignedRevocation::sign(&primary, DeviceId(2), 1).expect("sign revocation");
    assert_eq!(revocation.device(), DeviceId(2));
    assert_eq!(revocation.version(), 1);
    revocation
        .verify(&primary_pub)
        .expect("a primary-signed revocation must verify against the account primary");

    fanout
        .apply_revocation(&revocation, &primary_pub)
        .expect("apply verified revocation");

    assert!(fanout.is_revoked(DeviceId(2)), "device 2 must be revoked");
    assert!(
        !fanout.is_revoked(DeviceId(1)),
        "device 1 must not be revoked"
    );
    assert_eq!(fanout.revocation_version(), 1);

    // §8.2.5: the revoked device is excluded from fan-out.
    let after = fanout.encrypt_to_all(b"after revocation").expect("encrypt");
    assert_eq!(after.len(), 2, "revoked device must be excluded: {after:?}");
    assert!(
        after.iter().all(|c| c.device != DeviceId(2)),
        "no envelope may be addressed to the revoked device"
    );

    // §8.2.3: traffic from the revoked device observed after revocation is rejected, not
    // decrypted and surfaced to the application layer.
    assert!(
        fanout.decrypt_as(&devices[1], &for_device_2).is_err(),
        "the revoked device's traffic must be rejected"
    );

    // The still-linked devices keep working.
    let ct1 = after
        .iter()
        .find(|c| c.device == DeviceId(1))
        .expect("ct 1");
    let ct3 = after
        .iter()
        .find(|c| c.device == DeviceId(3))
        .expect("ct 3");
    assert_eq!(
        fanout
            .decrypt_as(&devices[0], ct1)
            .expect("device 1 decrypts"),
        b"after revocation"
    );
    assert_eq!(
        fanout
            .decrypt_as(&devices[2], ct3)
            .expect("device 3 decrypts"),
        b"after revocation"
    );
}

#[test]
fn revocation_signed_by_a_non_primary_is_rejected() {
    let (mut fanout, _devices) = fanout_with_devices(2);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();
    let rogue = generate_identity_key_pair();

    let forged = SignedRevocation::sign(&rogue, DeviceId(1), 1).expect("sign");

    assert!(
        matches!(
            forged.verify(&primary_pub),
            Err(RevocationError::NotEntitled)
        ),
        "a revocation not signed by the account primary must not verify"
    );
    assert!(matches!(
        fanout.apply_revocation(&forged, &primary_pub),
        Err(RevocationError::NotEntitled)
    ));

    assert!(
        !fanout.is_revoked(DeviceId(1)),
        "a rejected revocation must not take effect"
    );
    assert!(
        !fanout.is_revoked(DeviceId(99)),
        "an unlinked device is not 'revoked'"
    );
    assert_eq!(
        fanout.revocation_version(),
        0,
        "a rejected revocation must not advance the version"
    );
    assert_eq!(
        fanout.encrypt_to_all(b"still all").expect("encrypt").len(),
        2
    );
}

#[test]
fn tampered_revocation_bytes_never_verify() {
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();
    let revocation = SignedRevocation::sign(&primary, DeviceId(2), 7).expect("sign");

    let mut bytes = revocation.to_bytes();
    assert!(
        !bytes.is_empty(),
        "a signed revocation must serialize to bytes"
    );
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;

    match SignedRevocation::from_bytes(&bytes) {
        Ok(tampered) => assert!(
            tampered.verify(&primary_pub).is_err(),
            "a tampered revocation must not verify"
        ),
        Err(e) => assert!(
            matches!(e, RevocationError::Malformed),
            "tampered bytes must be rejected as Malformed, got {e}"
        ),
    }
}

#[test]
fn malformed_revocation_bytes_are_rejected() {
    assert!(
        matches!(
            SignedRevocation::from_bytes(&[]),
            Err(RevocationError::Malformed)
        ),
        "empty input is not a revocation"
    );
    assert!(
        matches!(
            SignedRevocation::from_bytes(&[0u8; 3]),
            Err(RevocationError::Malformed)
        ),
        "a 3-byte blob is not a revocation"
    );

    let primary = generate_identity_key_pair();
    let valid = SignedRevocation::sign(&primary, DeviceId(1), 1)
        .expect("sign")
        .to_bytes();
    let truncated = &valid[..valid.len() / 2];
    assert!(
        matches!(
            SignedRevocation::from_bytes(truncated),
            Err(RevocationError::Malformed)
        ),
        "a truncated revocation must be rejected"
    );
}

#[test]
fn signed_revocation_round_trips_through_bytes() {
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();
    let original = SignedRevocation::sign(&primary, DeviceId(4), 9).expect("sign");

    let restored = SignedRevocation::from_bytes(&original.to_bytes()).expect("round trip");
    assert_eq!(restored.device(), DeviceId(4));
    assert_eq!(restored.version(), 9);
    restored
        .verify(&primary_pub)
        .expect("restored revocation still verifies");
}

#[test]
fn stale_revocation_versions_are_rejected() {
    let (mut fanout, _devices) = fanout_with_devices(3);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();

    let first = SignedRevocation::sign(&primary, DeviceId(1), 5).expect("sign");
    fanout
        .apply_revocation(&first, &primary_pub)
        .expect("first revocation at version 5");
    assert_eq!(fanout.revocation_version(), 5);

    // §8.3: the device list is *monotonically* versioned — an equal version is stale.
    let equal = SignedRevocation::sign(&primary, DeviceId(2), 5).expect("sign");
    match fanout.apply_revocation(&equal, &primary_pub) {
        Err(RevocationError::StaleVersion { held, offered }) => {
            assert_eq!(held, 5);
            assert_eq!(offered, 5);
        }
        other => panic!("an equal version must be rejected as StaleVersion, got {other:?}"),
    }

    let older = SignedRevocation::sign(&primary, DeviceId(2), 4).expect("sign");
    assert!(matches!(
        fanout.apply_revocation(&older, &primary_pub),
        Err(RevocationError::StaleVersion {
            held: 5,
            offered: 4
        })
    ));
    assert!(
        !fanout.is_revoked(DeviceId(2)),
        "a stale update must not revoke anything"
    );

    // A strictly newer version is accepted.
    let newer = SignedRevocation::sign(&primary, DeviceId(2), 6).expect("sign");
    fanout
        .apply_revocation(&newer, &primary_pub)
        .expect("newer version accepted");
    assert!(fanout.is_revoked(DeviceId(2)));
    assert_eq!(fanout.revocation_version(), 6);
}

#[test]
fn revoking_a_device_that_was_never_linked_is_rejected() {
    let (mut fanout, _devices) = fanout_with_devices(2);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();

    let unknown = SignedRevocation::sign(&primary, DeviceId(99), 1).expect("sign");
    assert!(matches!(
        fanout.apply_revocation(&unknown, &primary_pub),
        Err(RevocationError::UnknownDevice(DeviceId(99)))
    ));
    assert!(!fanout.is_revoked(DeviceId(99)));
    assert_eq!(
        fanout.revocation_version(),
        0,
        "a rejected update must not advance the version"
    );
}

#[test]
fn revoking_an_already_revoked_device_is_rejected() {
    let (mut fanout, _devices) = fanout_with_devices(2);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();

    let first = SignedRevocation::sign(&primary, DeviceId(1), 1).expect("sign");
    fanout
        .apply_revocation(&first, &primary_pub)
        .expect("first revocation");
    assert!(fanout.is_revoked(DeviceId(1)));

    let again = SignedRevocation::sign(&primary, DeviceId(1), 2).expect("sign");
    assert!(matches!(
        fanout.apply_revocation(&again, &primary_pub),
        Err(RevocationError::AlreadyRevoked(DeviceId(1)))
    ));
    assert_eq!(
        fanout.revocation_version(),
        1,
        "a rejected re-revocation must not advance the version"
    );
}

#[test]
fn local_remove_device_still_works_alongside_verifiable_revocation() {
    let (mut fanout, _devices) = fanout_with_devices(3);
    let primary = generate_identity_key_pair();
    let primary_pub = primary.public_identity();

    // The pre-existing local shortcut is unchanged: it drops the device's ratchet state and
    // returns Ok without needing any signature.
    fanout
        .remove_device(DeviceId(1))
        .expect("local remove_device still returns Ok");
    let after_local = fanout.encrypt_to_all(b"local removal").expect("encrypt");
    assert_eq!(after_local.len(), 2);
    assert!(after_local.iter().all(|c| c.device != DeviceId(1)));

    // The verifiable path is additive: it revokes a *different* device and coexists.
    let revocation = SignedRevocation::sign(&primary, DeviceId(2), 1).expect("sign");
    fanout
        .apply_revocation(&revocation, &primary_pub)
        .expect("apply");
    let after_both = fanout.encrypt_to_all(b"both").expect("encrypt");
    assert_eq!(after_both.len(), 1);
    assert_eq!(after_both[0].device, DeviceId(3));
}
