//! Sender-only fan-out construction from public prekey bundles.
//!
//! A web client holds only the PUBLIC prekey bundle of each linked device, so it can never
//! call `FanoutSession::establish`, which needs every recipient's full identity keypair
//! (it builds the receiver side internally). These tests pin the sender-only constructor
//! `establish_from_bundles` and the `devices()` accessor that lets a caller observe that a
//! removed device is gone — the effect device revocation could never previously observe.
//!
//! Every session here is built from bundles round-tripped through the wire byte format
//! (`bundle_to_bytes` -> `bundle_from_bytes`), i.e. from public material only.
//!
//! The bundle type is `libsignal_protocol::PreKeyBundle`: the type `publish_bundle()`
//! returns, `bundle_from_bytes` parses, and `DoubleRatchetSession::new_alice` consumes.

use crypto::session::{bundle_from_bytes, bundle_to_bytes};
use crypto::{generate_identity_key_pair, DoubleRatchetSession, IdentityKeyPair};
use libsignal_protocol::PreKeyBundle;
use protocol::fanout::{DeviceId, FanoutError, FanoutSession};

/// Publish `identity`'s prekey bundle and round-trip it through the wire format, so the
/// test only ever hands the constructor public bytes — exactly what a web client has.
fn public_bundle(identity: &IdentityKeyPair) -> PreKeyBundle {
    let bundle = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(async {
            let receiver = DoubleRatchetSession::new_bob(identity)
                .await
                .expect("new_bob");
            receiver.publish_bundle().expect("publish_bundle")
        });
    let bytes = bundle_to_bytes(&bundle).expect("bundle_to_bytes");
    bundle_from_bytes(&bytes).expect("bundle_from_bytes")
}

/// The same public bundle material, but with the signed-prekey signature zeroed — the
/// tampering `new_alice` must reject rather than accept.
fn tampered_bundle(identity: &IdentityKeyPair) -> PreKeyBundle {
    let bundle = public_bundle(identity);
    let one_time = bundle
        .pre_key_id()
        .unwrap()
        .zip(bundle.pre_key_public().unwrap());
    PreKeyBundle::new(
        bundle.registration_id().unwrap(),
        bundle.device_id().unwrap(),
        one_time,
        bundle.signed_pre_key_id().unwrap(),
        bundle.signed_pre_key_public().unwrap(),
        vec![0u8; 64],
        bundle.kyber_pre_key_id().unwrap(),
        bundle.kyber_pre_key_public().unwrap().clone(),
        bundle.kyber_pre_key_signature().unwrap().to_vec(),
        *bundle.identity_key().unwrap(),
    )
    .expect("PreKeyBundle::new")
}

#[test]
fn builds_from_public_bundles_and_removal_is_observable() {
    let sender = generate_identity_key_pair();
    let device_one = generate_identity_key_pair();
    let device_two = generate_identity_key_pair();

    let mut fanout = FanoutSession::establish_from_bundles(
        &sender,
        &[
            (DeviceId(1), public_bundle(&device_one)),
            (DeviceId(2), public_bundle(&device_two)),
        ],
    )
    .expect("establish_from_bundles");

    let mut before = fanout.devices();
    before.sort();
    assert_eq!(
        before,
        vec![DeviceId(1), DeviceId(2)],
        "both linked devices must be recipients"
    );

    fanout.remove_device(DeviceId(1)).expect("remove device 1");

    let after = fanout.devices();
    assert!(
        !after.contains(&DeviceId(1)),
        "removed device must be absent from devices(): {after:?}"
    );
    assert!(
        after.contains(&DeviceId(2)),
        "surviving device must still be a recipient: {after:?}"
    );
    assert_eq!(after.len(), 1, "exactly one recipient remains: {after:?}");

    let ciphertexts = fanout.encrypt_to_all(b"after removal").expect("encrypt");
    assert_eq!(
        ciphertexts.len(),
        1,
        "exactly one ciphertext, for the survivor: {ciphertexts:?}"
    );
    assert_eq!(ciphertexts[0].device, DeviceId(2));
    assert!(
        !ciphertexts[0].envelope.is_empty(),
        "the survivor's envelope must carry ratchet bytes"
    );
}

#[test]
fn single_device_boundary() {
    let sender = generate_identity_key_pair();
    let only = generate_identity_key_pair();

    let mut fanout =
        FanoutSession::establish_from_bundles(&sender, &[(DeviceId(7), public_bundle(&only))])
            .expect("establish_from_bundles");

    assert_eq!(fanout.devices(), vec![DeviceId(7)]);

    let ciphertexts = fanout.encrypt_to_all(b"only you").expect("encrypt");
    assert_eq!(ciphertexts.len(), 1, "one ciphertext for one device");
    assert_eq!(ciphertexts[0].device, DeviceId(7));
}

#[test]
fn removing_the_last_device_leaves_no_recipients() {
    let sender = generate_identity_key_pair();
    let only = generate_identity_key_pair();

    let mut fanout =
        FanoutSession::establish_from_bundles(&sender, &[(DeviceId(3), public_bundle(&only))])
            .expect("establish_from_bundles");
    fanout.remove_device(DeviceId(3)).expect("remove device 3");

    assert!(
        fanout.devices().is_empty(),
        "no recipients remain: {:?}",
        fanout.devices()
    );
    assert!(
        fanout
            .encrypt_to_all(b"nobody")
            .expect("encrypt")
            .is_empty(),
        "no ciphertexts are produced once every device is removed"
    );
}

#[test]
fn empty_bundle_list_is_rejected() {
    let sender = generate_identity_key_pair();

    let result = FanoutSession::establish_from_bundles(&sender, &[]);
    let Err(e) = result else {
        panic!("empty recipient list must be rejected with NoDevices, got Ok");
    };
    assert!(
        matches!(e, FanoutError::NoDevices),
        "empty recipient list must be rejected with NoDevices, got: {e:?}"
    );
}

#[test]
fn duplicate_device_id_is_rejected() {
    let sender = generate_identity_key_pair();
    let a = generate_identity_key_pair();
    let b = generate_identity_key_pair();

    let result = FanoutSession::establish_from_bundles(
        &sender,
        &[
            (DeviceId(1), public_bundle(&a)),
            (DeviceId(1), public_bundle(&b)),
        ],
    );
    let Err(e) = result else {
        panic!("duplicate DeviceId must be rejected, got Ok");
    };
    assert!(
        matches!(e, FanoutError::DuplicateDevice(DeviceId(1))),
        "duplicate DeviceId must be rejected with DuplicateDevice(1), got: {e:?}"
    );
}

#[test]
fn sender_only_session_cannot_decrypt() {
    // A sender-only session holds no inbound ratchet state, so `decrypt_as` must return
    // `UnknownIdentity` rather than panicking on a missing receiver session.
    let sender = generate_identity_key_pair();
    let recipient = generate_identity_key_pair();

    let mut fanout =
        FanoutSession::establish_from_bundles(&sender, &[(DeviceId(1), public_bundle(&recipient))])
            .expect("establish_from_bundles");
    let ciphertexts = fanout.encrypt_to_all(b"hi").expect("encrypt");
    assert_eq!(ciphertexts.len(), 1);

    let result = fanout.decrypt_as(&recipient, &ciphertexts[0]);
    assert!(
        matches!(result, Err(FanoutError::UnknownIdentity)),
        "a sender-only session must refuse to decrypt with UnknownIdentity, got: {result:?}"
    );
}

#[test]
fn tampered_bundle_is_rejected_as_an_establishment_failure() {
    let sender = generate_identity_key_pair();
    let recipient = generate_identity_key_pair();

    let result = FanoutSession::establish_from_bundles(
        &sender,
        &[(DeviceId(1), tampered_bundle(&recipient))],
    );
    let Err(e) = result else {
        panic!("a tampered bundle must be rejected, got Ok");
    };
    assert!(
        matches!(e, FanoutError::Establishment(DeviceId(1), _)),
        "a tampered bundle must surface as Establishment(1, _), got: {e:?}"
    );
}

#[test]
fn establish_from_identity_keypairs_still_works() {
    // The sender-only constructor is additive: `establish` keeps its
    // `&[(DeviceId, &IdentityKeyPair)]` signature, and `devices()` reports its recipients too.
    let sender = generate_identity_key_pair();
    let recipient = generate_identity_key_pair();

    let fanout = FanoutSession::establish(&sender, &[(DeviceId(5), &recipient)])
        .expect("establish must still accept identity keypairs");
    assert_eq!(fanout.devices(), vec![DeviceId(5)]);
}
