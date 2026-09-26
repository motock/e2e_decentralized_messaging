//! Serialization / restore of a sender (Alice) `DoubleRatchetSession`.
//!
//! Covers the NS-5A acceptance criteria: a sender session can be serialized with
//! [`DoubleRatchetSession::to_bytes`] and restored with
//! [`DoubleRatchetSession::from_bytes`] such that the restored session keeps ratcheting
//! with the same peer, and every malformed / hostile blob fails closed with `Err`.
//!
//! The blob format is versioned and role-tagged:
//!
//! ```text
//!   [ version : 1 byte  ]   // 1
//!   [ role    : 1 byte  ]   // 1 = sender/Alice, 2 = receiver/Bob
//!   [ remote entry: four u32-length-prefixed segments ]
//! ```
//!
//! The local identity keypair is deliberately NOT stored — the caller supplies it on
//! restore (data minimization).

use crypto::{generate_identity_key_pair, DoubleRatchetSession, IdentityKeyPair};

/// True if `needle` occurs anywhere in `haystack`. Used to assert that secret material
/// (the local private key, a sent plaintext) is absent from the serialized blob.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Build a Bob receiver, publish his bundle, and establish an Alice sender against it.
/// Returns `(alice, bob, alice_identity)`.
async fn established_alice_and_bob() -> (DoubleRatchetSession, DoubleRatchetSession, IdentityKeyPair)
{
    let a_id = generate_identity_key_pair();
    let b_id = generate_identity_key_pair();

    let bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    let alice = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .expect("alice session");

    (alice, bob, a_id)
}

/// A valid sender blob produced from a freshly established Alice session.
async fn valid_alice_blob() -> Vec<u8> {
    let (alice, _bob, _a_id) = established_alice_and_bob().await;
    alice.to_bytes().await.expect("to_bytes on a sender")
}

// ---------------------------------------------------------------------------
// Positive: round-trip and ratchet continuation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restored_alice_encrypts_next_message_bob_decrypts() {
    let (mut alice, mut bob, a_id) = established_alice_and_bob().await;

    // Alice sends one message and Bob decrypts it, advancing both ratchets.
    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    let recovered_first = bob.decrypt(&first).await.expect("bob decrypts m1");
    assert_eq!(recovered_first.as_slice(), b"m1");

    let bytes = alice.to_bytes().await.expect("alice to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&a_id, &bytes)
        .await
        .expect("restore alice");

    // The restored Alice encrypts the NEXT message; the same Bob decrypts it.
    let next = restored.encrypt(b"m2").await.expect("restored encrypts m2");
    let recovered_next = bob.decrypt(&next).await.expect("bob decrypts m2");
    assert_eq!(recovered_next.as_slice(), b"m2");
}

#[tokio::test]
async fn restored_alice_ratchets_across_three_messages() {
    let (mut alice, mut bob, a_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");

    let bytes = alice.to_bytes().await.expect("alice to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&a_id, &bytes)
        .await
        .expect("restore alice");

    let second = restored.encrypt(b"m2").await.expect("restored encrypts m2");
    let recovered_second = bob.decrypt(&second).await.expect("bob decrypts m2");
    assert_eq!(recovered_second.as_slice(), b"m2");

    let third = restored.encrypt(b"m3").await.expect("restored encrypts m3");
    let recovered_third = bob.decrypt(&third).await.expect("bob decrypts m3");
    assert_eq!(recovered_third.as_slice(), b"m3");

    let fourth = restored.encrypt(b"m4").await.expect("restored encrypts m4");
    let recovered_fourth = bob.decrypt(&fourth).await.expect("bob decrypts m4");
    assert_eq!(recovered_fourth.as_slice(), b"m4");
}

#[tokio::test]
async fn serialized_bytes_start_with_version_and_role() {
    let bytes = valid_alice_blob().await;
    assert_eq!(bytes[0], 1, "first byte is the format version");
    assert_eq!(bytes[1], 1, "second byte is the sender role tag");
}

#[tokio::test]
async fn two_to_bytes_calls_on_unchanged_state_are_identical() {
    let (alice, _bob, _a_id) = established_alice_and_bob().await;

    let first = alice.to_bytes().await.expect("first to_bytes");
    let second = alice.to_bytes().await.expect("second to_bytes");

    assert_eq!(
        first, second,
        "to_bytes must be deterministic and read-only"
    );
}

// ---------------------------------------------------------------------------
// Negative / boundary: malformed and hostile blobs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_input_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[]).await;
    assert!(result.is_err(), "empty input must be rejected");
}

#[tokio::test]
async fn one_byte_input_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[1u8]).await;
    assert!(result.is_err(), "a 1-byte input must be rejected");
}

#[tokio::test]
async fn header_only_two_bytes_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[1u8, 1u8]).await;
    assert!(
        result.is_err(),
        "a header-only blob with no remote entry must be rejected"
    );
}

#[tokio::test]
async fn unknown_version_zero_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[0u8, 1u8]).await;
    assert!(result.is_err(), "version 0 must be rejected");
}

#[tokio::test]
async fn unknown_version_two_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[2u8, 1u8]).await;
    assert!(result.is_err(), "version 2 must be rejected");
}

#[tokio::test]
async fn unknown_role_zero_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[1u8, 0u8]).await;
    assert!(result.is_err(), "role 0 must be rejected");
}

#[tokio::test]
async fn unknown_role_three_is_rejected() {
    let a_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&a_id, &[1u8, 3u8]).await;
    assert!(result.is_err(), "role 3 must be rejected");
}

#[tokio::test]
async fn truncated_by_one_byte_is_rejected() {
    let a_id = generate_identity_key_pair();
    let mut bytes = valid_alice_blob().await;
    bytes.pop();

    let result = DoubleRatchetSession::from_bytes(&a_id, &bytes).await;
    assert!(
        result.is_err(),
        "a blob truncated by one byte must be rejected"
    );
}

#[tokio::test]
async fn truncated_in_first_length_prefix_is_rejected() {
    let a_id = generate_identity_key_pair();
    let bytes = valid_alice_blob().await;
    // Header (2 bytes) + only 2 bytes of the first 4-byte length prefix.
    let truncated = &bytes[..4];

    let result = DoubleRatchetSession::from_bytes(&a_id, truncated).await;
    assert!(
        result.is_err(),
        "a blob truncated inside the first length prefix must be rejected"
    );
}

#[tokio::test]
async fn trailing_extra_byte_is_rejected() {
    let a_id = generate_identity_key_pair();
    let mut bytes = valid_alice_blob().await;
    bytes.push(0u8);

    let result = DoubleRatchetSession::from_bytes(&a_id, &bytes).await;
    assert!(
        result.is_err(),
        "trailing bytes after the last segment must be rejected"
    );
}

#[tokio::test]
async fn huge_declared_length_is_rejected_quickly() {
    let a_id = generate_identity_key_pair();
    // version 1, role 1, then a first segment declaring length u32::MAX with only a few
    // bytes remaining. Must return Err without allocating 4 GiB or panicking.
    let hostile = [0x01u8, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02];

    let result = DoubleRatchetSession::from_bytes(&a_id, &hostile).await;
    assert!(
        result.is_err(),
        "a u32::MAX length prefix must be rejected, not allocated"
    );
}

#[tokio::test]
async fn tampered_remote_name_is_rejected() {
    let a_id = generate_identity_key_pair();
    let mut bytes = valid_alice_blob().await;
    // The remote address name is the first segment after the 2-byte header: its 4-byte
    // length prefix occupies bytes 2..6, so byte 6 is the first name byte. Flip it so the
    // name no longer matches hex(hash(remote identity key)).
    bytes[6] ^= 0xff;

    let result = DoubleRatchetSession::from_bytes(&a_id, &bytes).await;
    assert!(
        result.is_err(),
        "a remote name that does not match the identity hash must be rejected"
    );
}

#[tokio::test]
async fn restore_with_different_identity_is_rejected() {
    let bytes = valid_alice_blob().await;
    let other_identity = generate_identity_key_pair();

    let result = DoubleRatchetSession::from_bytes(&other_identity, &bytes).await;
    assert!(
        result.is_err(),
        "restoring under an identity other than the session's own must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Negative: secret material must not leak into the blob
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blob_does_not_contain_local_private_key() {
    let (alice, _bob, a_id) = established_alice_and_bob().await;
    let bytes = alice.to_bytes().await.expect("alice to_bytes");

    let private_key_bytes = a_id.private_key().serialize();
    assert!(
        !contains_subslice(&bytes, &private_key_bytes),
        "the serialized blob must not contain the local identity private key"
    );
}

#[tokio::test]
async fn blob_does_not_contain_sent_plaintext() {
    let (mut alice, mut bob, _a_id) = established_alice_and_bob().await;
    let marker = b"UNIQUE-PLAINTEXT-MARKER-9f3a1c";

    let ciphertext = alice.encrypt(marker).await.expect("alice encrypts marker");
    bob.decrypt(&ciphertext).await.expect("bob decrypts marker");

    let bytes = alice.to_bytes().await.expect("alice to_bytes");
    assert!(
        !contains_subslice(&bytes, marker),
        "the serialized blob must not contain a previously sent plaintext"
    );
}
