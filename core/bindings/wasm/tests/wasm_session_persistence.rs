//! WASM session/group persistence tests (NS-5D).
//!
//! TDD tests for the four new WASM-facing serialize/restore functions:
//!  - `session_to_bytes`   — serialize an established `SessionHandle` to a secret blob
//!  - `session_from_bytes` — restore a `SessionHandle` from that blob plus the local identity
//!  - `group_to_bytes`     — serialize a `GroupHandle` to a secret blob
//!  - `group_from_bytes`   — restore a `GroupHandle` from that blob
//!
//! Positive cases prove a restored session/group continues the conversation (the next message
//! still decrypts). Negative/boundary cases prove the restore boundary fails closed: empty,
//! truncated, unknown-version, and wrong-identity inputs all return `Err` and never a partially
//! restored handle.
//!
//! These tests run natively (the same `#[test]` harness the CI `test` job uses) — the
//! `wasm-bindgen` attribute is a no-op outside `wasm32-unknown-unknown`, so the functions
//! are callable as ordinary Rust functions here.

use core_bindings_wasm::{
    create_receiver_session, decrypt_message, encrypt_message, establish_session_from_bundle,
    generate_identity, generate_prekey_bundle, group_add_member, group_create, group_decrypt,
    group_encrypt, group_from_bytes, group_to_bytes, publish_bundle_bytes, session_from_bytes,
    session_to_bytes, IdentityHandle, SessionHandle,
};

/// Build a sender (Alice) session and its matching receiver (Bob) session, plus the identities
/// that own them. The receiver session publishes the bundle, so the same session that produced
/// the bundle is the one that decrypts.
fn established_pair() -> (IdentityHandle, SessionHandle, IdentityHandle, SessionHandle) {
    let bob_identity = generate_identity();
    let bob_session = create_receiver_session(&bob_identity).expect("receiver session must build");
    let bundle_bytes = publish_bundle_bytes(&bob_session).expect("bundle publication must succeed");
    let alice_identity = generate_identity();
    let alice_session = establish_session_from_bundle(&alice_identity, &bundle_bytes)
        .expect("sender session must establish");
    (alice_identity, alice_session, bob_identity, bob_session)
}

/// Build a sender session whose bundle came from a throwaway receiver session — used where the
/// test only needs a valid sender blob, not a live conversation partner.
fn sender_session_with_blob() -> (IdentityHandle, SessionHandle) {
    let bob_identity = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&bob_identity).expect("bundle generation must work");
    let alice_identity = generate_identity();
    let alice_session = establish_session_from_bundle(&alice_identity, &bundle_bytes)
        .expect("sender session must establish");
    (alice_identity, alice_session)
}

// ---------------------------------------------------------------------------
// Positive path: sender session round-trip
// ---------------------------------------------------------------------------

#[test]
fn sender_session_round_trip_decrypts_next_message() {
    let (alice_identity, mut alice_session, _bob_identity, mut bob_session) = established_pair();

    let first = encrypt_message(&mut alice_session, b"first").expect("first encrypt must succeed");
    let first_plaintext =
        decrypt_message(&mut bob_session, &first).expect("first decrypt must succeed");
    assert_eq!(first_plaintext.as_slice(), b"first");

    let blob = session_to_bytes(&alice_session).expect("sender serialization must succeed");
    let mut restored =
        session_from_bytes(&alice_identity, &blob).expect("sender restore must succeed");

    let second =
        encrypt_message(&mut restored, b"second").expect("restored sender must still encrypt");
    let second_plaintext =
        decrypt_message(&mut bob_session, &second).expect("receiver must decrypt restored sender");
    assert_eq!(second_plaintext.as_slice(), b"second");
}

// ---------------------------------------------------------------------------
// Positive path: receiver session round-trip after decrypting a message
// ---------------------------------------------------------------------------

#[test]
fn receiver_session_round_trip_after_decrypting_a_message() {
    let (_alice_identity, mut alice_session, bob_identity, mut bob_session) = established_pair();

    let first = encrypt_message(&mut alice_session, b"first").expect("first encrypt must succeed");
    let first_plaintext =
        decrypt_message(&mut bob_session, &first).expect("first decrypt must succeed");
    assert_eq!(first_plaintext.as_slice(), b"first");

    let blob = session_to_bytes(&bob_session).expect("receiver serialization must succeed");
    let mut restored =
        session_from_bytes(&bob_identity, &blob).expect("receiver restore must succeed");

    let second = encrypt_message(&mut alice_session, b"second").expect("second encrypt must work");
    let second_plaintext =
        decrypt_message(&mut restored, &second).expect("restored receiver must decrypt");
    assert_eq!(second_plaintext.as_slice(), b"second");
}

// ---------------------------------------------------------------------------
// Positive path: group round-trip
// ---------------------------------------------------------------------------

#[test]
fn group_round_trip_encrypts_message_member_decrypts() {
    let sender = generate_identity();
    let member = generate_identity();
    let group = group_add_member(&group_create(&sender), &member.public_bytes());

    let blob = group_to_bytes(&group);
    let restored = group_from_bytes(&blob).expect("group restore must succeed");

    let ciphertext =
        group_encrypt(&restored, &sender, b"group hello").expect("restored group must encrypt");
    let plaintext =
        group_decrypt(&restored, &member, &ciphertext).expect("member must decrypt restored group");
    assert_eq!(plaintext.as_slice(), b"group hello");
}

#[test]
fn group_round_trip_next_message_differs_from_previous() {
    let sender = generate_identity();
    let member = generate_identity();
    let group = group_add_member(&group_create(&sender), &member.public_bytes());
    let restored = group_from_bytes(&group_to_bytes(&group)).expect("group restore must succeed");

    let first = group_encrypt(&restored, &sender, b"same").expect("first encrypt must succeed");
    let second = group_encrypt(&restored, &sender, b"same").expect("second encrypt must succeed");

    assert_ne!(
        first, second,
        "the ratcheted group must not reuse a (key, nonce) pair across messages"
    );
}

// ---------------------------------------------------------------------------
// Negative / boundary: session restore fails closed
// ---------------------------------------------------------------------------

#[test]
fn session_from_bytes_rejects_empty_bytes() {
    let (alice_identity, _alice_session) = sender_session_with_blob();

    let err = session_from_bytes(&alice_identity, &[]).expect_err("empty bytes must be rejected");

    assert_eq!(err.kind(), "Session");
}

#[test]
fn session_from_bytes_rejects_truncated_bytes() {
    let (alice_identity, alice_session) = sender_session_with_blob();
    let blob = session_to_bytes(&alice_session).expect("serialization must succeed");

    let err = session_from_bytes(&alice_identity, &blob[..blob.len() - 1])
        .expect_err("truncated bytes must be rejected");

    assert_eq!(err.kind(), "Session");
}

#[test]
fn session_from_bytes_rejects_unknown_version() {
    let (alice_identity, alice_session) = sender_session_with_blob();
    let mut blob = session_to_bytes(&alice_session).expect("serialization must succeed");
    blob[0] = 0xFF;

    let err = session_from_bytes(&alice_identity, &blob)
        .expect_err("an unknown version byte must be rejected");

    assert_eq!(err.kind(), "Session");
}

#[test]
fn session_from_bytes_rejects_different_identity() {
    let (_alice_identity, alice_session) = sender_session_with_blob();
    let blob = session_to_bytes(&alice_session).expect("serialization must succeed");
    let other_identity = generate_identity();

    let err = session_from_bytes(&other_identity, &blob)
        .expect_err("a blob restored under the wrong identity must be rejected");

    assert_eq!(err.kind(), "Session");
}

#[test]
fn receiver_blob_restored_with_different_identity_is_rejected() {
    let (_alice_identity, mut alice_session, _bob_identity, mut bob_session) = established_pair();
    let first = encrypt_message(&mut alice_session, b"first").expect("first encrypt must succeed");
    decrypt_message(&mut bob_session, &first).expect("first decrypt must succeed");
    let blob = session_to_bytes(&bob_session).expect("receiver serialization must succeed");
    let other_identity = generate_identity();

    let err = session_from_bytes(&other_identity, &blob)
        .expect_err("a receiver blob restored under the wrong identity must be rejected");

    assert_eq!(err.kind(), "Session");
}

#[test]
fn failed_restore_leaves_identity_usable_for_a_later_restore() {
    let (_alice_identity, mut alice_session, bob_identity, mut bob_session) = established_pair();
    let first = encrypt_message(&mut alice_session, b"first").expect("first encrypt must succeed");
    decrypt_message(&mut bob_session, &first).expect("first decrypt must succeed");
    let blob = session_to_bytes(&bob_session).expect("receiver serialization must succeed");

    let failed = session_from_bytes(&bob_identity, &blob[..blob.len() - 1]);
    assert!(failed.is_err(), "the truncated restore must fail");

    let mut restored = session_from_bytes(&bob_identity, &blob)
        .expect("the same identity must still restore the intact blob");
    let second = encrypt_message(&mut alice_session, b"second").expect("second encrypt must work");
    let plaintext =
        decrypt_message(&mut restored, &second).expect("restored receiver must decrypt");
    assert_eq!(plaintext.as_slice(), b"second");
}

// ---------------------------------------------------------------------------
// Negative / boundary: group restore fails closed
// ---------------------------------------------------------------------------

#[test]
fn group_from_bytes_rejects_empty_bytes() {
    let err = group_from_bytes(&[]).expect_err("empty group bytes must be rejected");

    assert_eq!(err.kind(), "Group");
}

#[test]
fn group_from_bytes_rejects_truncated_bytes() {
    let sender = generate_identity();
    let member = generate_identity();
    let group = group_add_member(&group_create(&sender), &member.public_bytes());
    let blob = group_to_bytes(&group);

    let err = group_from_bytes(&blob[..blob.len() - 1])
        .expect_err("truncated group bytes must be rejected");

    assert_eq!(err.kind(), "Group");
}
