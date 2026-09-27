//! Serialization / restore of a receiver (Bob) `DoubleRatchetSession`.
//!
//! Covers the NS-5B acceptance criteria: a receiver session that has decrypted one or more
//! inbound messages can be serialized with [`DoubleRatchetSession::to_bytes`] and restored with
//! [`DoubleRatchetSession::from_bytes`] such that the restored session keeps ratcheting with
//! every peer it has heard from, and every malformed / hostile blob fails closed with `Err`.
//!
//! The receiver body of the versioned, role-tagged blob is:
//!
//! ```text
//!   [ version : 1 byte  ]   // 1
//!   [ role    : 1 byte  ]   // 2 = receiver/Bob
//!   [ signed prekey record   : u32-length-prefixed ]
//!   [ kyber prekey record    : u32-length-prefixed ]
//!   [ one-time prekey record : u32-length-prefixed, empty once consumed ]
//!   [ remote count           : 4 bytes big-endian ]
//!   [ remote entry * count   : four u32-length-prefixed segments each ]
//! ```
//!
//! A remote entry is, in order: the remote address name (UTF-8), the remote device id (exactly
//! 4 bytes), the remote `IdentityKey` (libsignal `serialize`), and that remote's libsignal
//! `SessionRecord` (`serialize`). The local identity keypair is deliberately NOT stored — the
//! caller supplies it on restore (data minimization).

use crypto::{generate_identity_key_pair, DoubleRatchetSession, IdentityKeyPair};

/// True if `needle` occurs anywhere in `haystack`. Used to assert that secret material (the
/// local identity private key) is absent from the serialized blob.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Build a Bob receiver, publish his bundle, and establish an Alice sender against it.
/// Returns `(alice, bob, alice_identity, bob_identity)`.
async fn established_alice_and_bob() -> (
    DoubleRatchetSession,
    DoubleRatchetSession,
    IdentityKeyPair,
    IdentityKeyPair,
) {
    let a_id = generate_identity_key_pair();
    let b_id = generate_identity_key_pair();

    let bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    let alice = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .expect("alice session");

    (alice, bob, a_id, b_id)
}

/// A valid receiver blob produced after Bob has decrypted Alice's first (PreKey) message, plus
/// Bob's identity keypair. At this point Bob's one-time prekey has been consumed.
async fn bob_blob_after_first_message() -> (Vec<u8>, IdentityKeyPair) {
    let (mut alice, mut bob, _a_id, b_id) = established_alice_and_bob().await;
    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");
    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    (bytes, b_id)
}

/// Advance `pos` past one `u32`-length-prefixed segment of `blob`.
fn skip_segment(blob: &[u8], pos: &mut usize) {
    let len = u32::from_be_bytes(
        blob[*pos..*pos + 4]
            .try_into()
            .expect("4-byte length prefix"),
    ) as usize;
    *pos += 4 + len;
}

/// Byte offset of the 4-byte remote count in a receiver blob.
fn remote_count_offset(blob: &[u8]) -> usize {
    let mut pos = 2;
    skip_segment(blob, &mut pos); // signed prekey record
    skip_segment(blob, &mut pos); // kyber prekey record
    skip_segment(blob, &mut pos); // one-time prekey record (possibly empty)
    pos
}

/// The remote count declared by a receiver blob.
fn remote_count(blob: &[u8]) -> u32 {
    let pos = remote_count_offset(blob);
    u32::from_be_bytes(blob[pos..pos + 4].try_into().expect("remote count"))
}

/// A copy of `blob` whose declared remote count is replaced with `count`.
fn with_remote_count(blob: &[u8], count: u32) -> Vec<u8> {
    let pos = remote_count_offset(blob);
    let mut out = blob.to_vec();
    out[pos..pos + 4].copy_from_slice(&count.to_be_bytes());
    out
}

/// Byte offset of the first byte of the first remote entry's name segment.
fn first_remote_name_offset(blob: &[u8]) -> usize {
    remote_count_offset(blob) + 4 + 4
}

// ---------------------------------------------------------------------------
// Positive: round-trip and ratchet continuation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restored_bob_decrypts_alices_second_message() {
    let (mut alice, mut bob, _a_id, b_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    let recovered_first = bob.decrypt(&first).await.expect("bob decrypts m1");
    assert_eq!(recovered_first.as_slice(), b"m1");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&b_id, &bytes)
        .await
        .expect("restore bob");

    // Alice's second message is a normal ciphertext on the established session; the restored
    // Bob must decrypt it.
    let second = alice.encrypt(b"m2").await.expect("alice encrypts m2");
    let recovered_second = restored
        .decrypt(&second)
        .await
        .expect("restored bob decrypts m2");
    assert_eq!(recovered_second.as_slice(), b"m2");
}

#[tokio::test]
async fn two_senders_continue_after_one_restore() {
    let (mut alice, mut bob, _a_id, b_id) = established_alice_and_bob().await;

    let a1 = alice.encrypt(b"a1").await.expect("alice encrypts a1");
    bob.decrypt(&a1).await.expect("bob decrypts a1");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&b_id, &bytes)
        .await
        .expect("restore bob");

    // A second sender establishes against the restored Bob's bundle (which no longer carries
    // the consumed one-time prekey) and sends a first message.
    let bundle = restored
        .publish_bundle()
        .expect("restored bob publishes bundle");
    let c_id = generate_identity_key_pair();
    let mut carol = DoubleRatchetSession::new_alice(&c_id, &bundle)
        .await
        .expect("carol session");
    let c1 = carol.encrypt(b"c1").await.expect("carol encrypts c1");
    let recovered_c1 = restored
        .decrypt(&c1)
        .await
        .expect("restored bob decrypts c1");
    assert_eq!(recovered_c1.as_slice(), b"c1");

    // Alice's next message still decrypts on the same restored Bob.
    let a2 = alice.encrypt(b"a2").await.expect("alice encrypts a2");
    let recovered_a2 = restored
        .decrypt(&a2)
        .await
        .expect("restored bob decrypts a2");
    assert_eq!(recovered_a2.as_slice(), b"a2");
}

#[tokio::test]
async fn restored_bob_publishes_bundle_without_consumed_one_time_key() {
    let (mut alice, mut bob, _a_id, b_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&b_id, &bytes)
        .await
        .expect("restore bob");

    // The restored Bob can still publish a bundle; because the one-time prekey was consumed,
    // the bundle omits it, so a brand-new sender's first message must not reference it.
    let bundle = restored
        .publish_bundle()
        .expect("restored bob publishes bundle");
    let c_id = generate_identity_key_pair();
    let mut carol = DoubleRatchetSession::new_alice(&c_id, &bundle)
        .await
        .expect("carol session");
    let c1 = carol.encrypt(b"c1").await.expect("carol encrypts c1");
    let recovered = restored
        .decrypt(&c1)
        .await
        .expect("restored bob decrypts c1");
    assert_eq!(recovered.as_slice(), b"c1");
}

#[tokio::test]
async fn bob_serialized_before_any_message_restores_and_decrypts_first_message() {
    let b_id = generate_identity_key_pair();
    let bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&b_id, &bytes)
        .await
        .expect("restore bob");

    let bundle = restored
        .publish_bundle()
        .expect("restored bob publishes bundle");
    let a_id = generate_identity_key_pair();
    let mut alice = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .expect("alice session");
    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    let recovered = restored
        .decrypt(&first)
        .await
        .expect("restored bob decrypts m1");
    assert_eq!(recovered.as_slice(), b"m1");
}

#[tokio::test]
async fn two_to_bytes_calls_on_unchanged_receiver_state_are_identical() {
    let b_id = generate_identity_key_pair();
    let bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");

    let first = bob.to_bytes().await.expect("first to_bytes");
    let second = bob.to_bytes().await.expect("second to_bytes");

    assert_eq!(
        first, second,
        "to_bytes must be deterministic and read-only"
    );
}

#[tokio::test]
async fn repeated_messages_from_one_sender_record_one_remote() {
    let (mut alice, mut bob, _a_id, _b_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");
    let second = alice.encrypt(b"m2").await.expect("alice encrypts m2");
    bob.decrypt(&second).await.expect("bob decrypts m2");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    assert_eq!(
        remote_count(&bytes),
        1,
        "the same sender must be recorded exactly once"
    );
}

// ---------------------------------------------------------------------------
// Negative / boundary: malformed and hostile blobs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replaying_an_already_decrypted_message_after_restore_is_rejected() {
    let (mut alice, mut bob, _a_id, b_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let mut restored = DoubleRatchetSession::from_bytes(&b_id, &bytes)
        .await
        .expect("restore bob");

    let replayed = restored.decrypt(&first).await;
    assert!(
        replayed.is_err(),
        "a message already decrypted must be rejected after a restore"
    );
}

#[tokio::test]
async fn restore_with_a_different_identity_is_rejected() {
    let (bytes, _b_id) = bob_blob_after_first_message().await;
    let other = generate_identity_key_pair();

    let result = DoubleRatchetSession::from_bytes(&other, &bytes).await;
    assert!(
        result.is_err(),
        "restoring with an identity other than the session's own must be rejected"
    );
}

#[tokio::test]
async fn failed_decrypt_leaves_serialized_state_unchanged() {
    let (mut alice, mut bob, _a_id, _b_id) = established_alice_and_bob().await;

    let first = alice.encrypt(b"m1").await.expect("alice encrypts m1");
    bob.decrypt(&first).await.expect("bob decrypts m1");

    let before = bob.to_bytes().await.expect("bob to_bytes before");

    let garbage = [0u8; 64];
    let failed = bob.decrypt(&garbage).await;
    assert!(failed.is_err(), "a garbage envelope must be rejected");

    let after = bob.to_bytes().await.expect("bob to_bytes after");
    assert_eq!(
        before, after,
        "a failed decrypt must not change the serialized state"
    );
}

#[tokio::test]
async fn empty_input_is_rejected() {
    let b_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&b_id, &[]).await;
    assert!(result.is_err(), "empty input must be rejected");
}

#[tokio::test]
async fn header_only_receiver_blob_is_rejected() {
    let b_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&b_id, &[1u8, 2u8]).await;
    assert!(
        result.is_err(),
        "a receiver header with no body must be rejected"
    );
}

#[tokio::test]
async fn unknown_role_zero_is_rejected() {
    let b_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&b_id, &[1u8, 0u8]).await;
    assert!(result.is_err(), "role 0 must be rejected");
}

#[tokio::test]
async fn unknown_role_three_is_rejected() {
    let b_id = generate_identity_key_pair();
    let result = DoubleRatchetSession::from_bytes(&b_id, &[1u8, 3u8]).await;
    assert!(result.is_err(), "role 3 must be rejected");
}

#[tokio::test]
async fn receiver_blob_truncated_by_one_byte_is_rejected() {
    let (mut bytes, b_id) = bob_blob_after_first_message().await;
    bytes.pop();

    let result = DoubleRatchetSession::from_bytes(&b_id, &bytes).await;
    assert!(
        result.is_err(),
        "a receiver blob truncated by one byte must be rejected"
    );
}

#[tokio::test]
async fn receiver_blob_with_trailing_extra_byte_is_rejected() {
    let (mut bytes, b_id) = bob_blob_after_first_message().await;
    bytes.push(0u8);

    let result = DoubleRatchetSession::from_bytes(&b_id, &bytes).await;
    assert!(
        result.is_err(),
        "trailing bytes after the last segment must be rejected"
    );
}

#[tokio::test]
async fn huge_remote_count_is_rejected_without_allocating() {
    let (bytes, b_id) = bob_blob_after_first_message().await;
    let hostile = with_remote_count(&bytes, u32::MAX);

    let result = DoubleRatchetSession::from_bytes(&b_id, &hostile).await;
    assert!(
        result.is_err(),
        "a 0xFFFFFFFF remote count must be rejected, not allocated"
    );
}

#[tokio::test]
async fn remote_name_not_matching_its_identity_hash_is_rejected() {
    let (bytes, b_id) = bob_blob_after_first_message().await;
    let mut tampered = bytes.clone();
    let offset = first_remote_name_offset(&bytes);
    tampered[offset] ^= 0xff;

    let result = DoubleRatchetSession::from_bytes(&b_id, &tampered).await;
    assert!(
        result.is_err(),
        "a remote name that does not hash to its identity key must be rejected"
    );
}

#[tokio::test]
async fn blob_does_not_contain_bobs_identity_private_key() {
    let b_id = generate_identity_key_pair();
    let bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");

    let bytes = bob.to_bytes().await.expect("bob to_bytes");
    let private_key = b_id.private_key().serialize();

    assert!(
        !contains_subslice(&bytes, private_key.as_ref()),
        "the blob must not contain the local identity private key"
    );
}

#[tokio::test]
async fn sender_role_blob_still_restores() {
    let (alice, _bob, a_id, _b_id) = established_alice_and_bob().await;

    let bytes = alice.to_bytes().await.expect("alice to_bytes");
    let restored = DoubleRatchetSession::from_bytes(&a_id, &bytes).await;

    assert!(
        restored.is_ok(),
        "a sender-role blob must still restore through the same from_bytes"
    );
}
