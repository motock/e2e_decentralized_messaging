//! WASM stateful fan-out handle tests (DR-5).
//!
//! TDD tests for the new stateful fan-out bindings:
//!  - `fanout_establish` — builds a sender-side fan-out session from public device material
//!    `(device_id, expected_identity_key_bytes, bundle_bytes)` tuples
//!  - `fanout_devices` — reads the current recipient set (observable state)
//!  - `fanout_remove_device` — removes a device from the held session (stateful mutation)
//!  - `fanout_encrypt` — per-device envelopes for the surviving recipients
//!
//! These assert an EFFECT, not merely "did not throw": after a removal the device set and the
//! encrypt output must both reflect the removal. A stateless no-op would pass a
//! "did not throw" test while leaving the revoked device in the recipient set.
//!
//! Security case: the expected identity for each device is an EXPLICIT input, never derived
//! from the bundle being verified. A well-formed bundle whose identity key is not the expected
//! one must be rejected before any session is built.

use core_bindings_wasm::{
    fanout_devices, fanout_encrypt, fanout_establish, fanout_remove_device, generate_identity,
    generate_prekey_bundle, FanoutDeviceInput,
};

/// Build a `FanoutDeviceInput` for a fresh device: the device id, the identity key bytes the
/// caller vouches for, and the device's serialized prekey bundle.
fn device(id: u32) -> FanoutDeviceInput {
    let identity = generate_identity();
    let expected = identity.public_bytes();
    let bundle = generate_prekey_bundle(&identity).expect("bundle generation must succeed");
    FanoutDeviceInput::new(id, expected, bundle)
}

// ---------------------------------------------------------------------------
// Positive path: establish lists the recipients, and the set is observable
// ---------------------------------------------------------------------------

#[test]
fn establish_lists_devices() {
    let sender = generate_identity();
    let devices = vec![device(1), device(2), device(3)];

    let handle = fanout_establish(&sender, devices).expect("fan-out establishment must succeed");

    assert_eq!(
        fanout_devices(&handle),
        vec![1, 2, 3],
        "the established fan-out must list every recipient device"
    );
}

// ---------------------------------------------------------------------------
// Stateful removal: the handle itself must change, not a clone/local copy
// ---------------------------------------------------------------------------

#[test]
fn remove_drops_device_keeps_survivors() {
    let sender = generate_identity();
    let devices = vec![device(1), device(2), device(3)];
    let mut handle =
        fanout_establish(&sender, devices).expect("fan-out establishment must succeed");

    fanout_remove_device(&mut handle, 2).expect("removing a member device must succeed");

    assert_eq!(
        fanout_devices(&handle),
        vec![1, 3],
        "after removal the handle must no longer list device 2, and must keep 1 and 3"
    );

    let envelopes = fanout_encrypt(&mut handle, b"hi").expect("fan-out encrypt must succeed");
    let recipients: Vec<u32> = envelopes.iter().map(|e| e.device_id()).collect();
    assert_eq!(
        recipients,
        vec![1, 3],
        "encrypt must emit material only for the surviving recipients"
    );
    assert!(
        !recipients.contains(&2),
        "the removed device must receive no envelope"
    );
    for envelope in &envelopes {
        assert!(
            !envelope.envelope().is_empty(),
            "envelope for device {} must not be empty",
            envelope.device_id()
        );
    }
}

// ---------------------------------------------------------------------------
// Security: the expected identity is an explicit input, not read from the bundle
// ---------------------------------------------------------------------------

#[test]
fn mismatched_expected_identity_rejected() {
    let sender = generate_identity();
    let genuine = generate_identity();
    let genuine_identity_bytes = genuine.public_bytes();
    let genuine_bundle =
        generate_prekey_bundle(&genuine).expect("bundle generation must succeed");

    // The genuine bundle for device 7, with the genuine expected identity: accepted.
    let ok = fanout_establish(
        &sender,
        vec![FanoutDeviceInput::new(
            7,
            genuine_identity_bytes.clone(),
            genuine_bundle.clone(),
        )],
    );
    assert!(
        ok.is_ok(),
        "the genuine bundle for device 7 must establish, got: {ok:?}"
    );

    // The SAME well-formed bundle, but the caller's expected identity is a different key.
    // The bundle is internally self-consistent (its signature verifies against the identity
    // key it carries), so only the explicit expected-identity comparison can catch this.
    let other = generate_identity();
    let other_identity_bytes = other.public_bytes();
    assert_ne!(
        other_identity_bytes, genuine_identity_bytes,
        "test setup: the two identities must differ"
    );

    let mismatch = fanout_establish(
        &sender,
        vec![FanoutDeviceInput::new(7, other_identity_bytes, genuine_bundle)],
    );
    assert!(
        mismatch.is_err(),
        "a bundle whose identity key is not the expected identity must be rejected, got: {mismatch:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative paths: structured errors, never a panic
// ---------------------------------------------------------------------------

#[test]
fn empty_device_list_is_error() {
    let sender = generate_identity();
    let result = fanout_establish(&sender, vec![]);
    assert!(
        result.is_err(),
        "an empty device list must surface as Err, got: {result:?}"
    );
}

#[test]
fn malformed_bundle_is_error() {
    let sender = generate_identity();
    let expected = generate_identity().public_bytes();
    let result = fanout_establish(&sender, vec![FanoutDeviceInput::new(1, expected, vec![0u8; 3])]);
    assert!(
        result.is_err(),
        "a malformed bundle must surface as Err, got: {result:?}"
    );
}
