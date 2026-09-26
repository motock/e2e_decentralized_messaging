//! `GroupSession` persistence: serialize/restore round-trip and hostile-blob rejection.
//!
//! Anchors the NS-5C requirement that a group session's ratchet state can be serialized and
//! restored so a restarted client continues the same chain, and that every malformed or
//! truncated blob fails closed with `ErrorKind::InvalidData` instead of yielding a partially
//! restored session.

use crypto::identity::{IdentityKeyPair, PublicIdentityKey};
use protocol::group::{GroupMember, GroupSession, NonMember};
use std::io::ErrorKind;

/// A deterministic 33-byte member identity (1-byte Curve25519 type tag + 32-byte point).
///
/// Used where a test only needs distinct, well-formed-length member keys (round-trip fidelity,
/// the 255-member boundary) rather than keys that can actually open a sealed wrapper.
fn member_identity(seed: u8) -> PublicIdentityKey {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x05;
    for (i, b) in bytes[1..].iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    PublicIdentityKey::from_bytes(&bytes)
}

/// A group session holding `count` deterministic members.
fn group_with_members(count: u8) -> GroupSession {
    let sender = IdentityKeyPair::generate();
    let mut group = GroupSession::new(sender.public());
    for seed in 0..count {
        group = group.add_member(GroupMember(member_identity(seed)));
    }
    group
}

/// A v1 blob: version byte, 32-byte chain key, big-endian member count, then the member body.
fn blob(version: u8, chain_key: [u8; 32], count: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(version);
    out.extend_from_slice(&chain_key);
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// One member segment: big-endian declared length followed by that many payload bytes.
fn member_segment(len: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `count` well-formed 33-byte member segments.
fn repeated_member_segments(count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..count {
        body.extend_from_slice(&member_segment(33, &[0x33; 33]));
    }
    body
}

/// Every parse failure must be `InvalidData` — never a panic, never a partial session.
fn assert_rejected(bytes: &[u8]) {
    let err = GroupSession::from_bytes(bytes).expect_err("hostile blob must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn two_member_group_round_trips_and_restored_group_message_decrypts() {
    let sender = IdentityKeyPair::generate();
    let member_a = IdentityKeyPair::generate();
    let member_b = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public())
        .add_member(GroupMember(member_a.public()))
        .add_member(GroupMember(member_b.public()));
    let original = group.to_bytes();

    let restored = GroupSession::from_bytes(&original).expect("restore");
    assert_eq!(restored.to_bytes(), original, "round-trip must be lossless");

    let ciphertext = restored
        .encrypt_as(&sender, b"after restore")
        .expect("encrypt");
    assert_eq!(
        restored
            .decrypt_as(&member_a, &ciphertext)
            .expect("member a decrypts"),
        b"after restore"
    );
}

#[test]
fn restored_group_continues_the_chain_without_reusing_a_nonce() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

    let first = group.encrypt_as(&sender, b"one").expect("encrypt one");
    let restored = GroupSession::from_bytes(&group.to_bytes()).expect("restore");
    let second = restored.encrypt_as(&sender, b"two").expect("encrypt two");

    assert_ne!(
        first[..12],
        second[..12],
        "a restored session must not reuse the pre-restore message's nonce"
    );
    assert_eq!(
        restored.decrypt_as(&member, &second).expect("decrypt two"),
        b"two"
    );
    assert_eq!(
        restored.decrypt_as(&member, &first).expect("decrypt one"),
        b"one"
    );
}

#[test]
fn restored_group_after_remove_member_still_excludes_the_removed_member() {
    let sender = IdentityKeyPair::generate();
    let kept = IdentityKeyPair::generate();
    let removed = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public())
        .add_member(GroupMember(kept.public()))
        .add_member(GroupMember(removed.public()))
        .remove_member(GroupMember(removed.public()));

    let restored = GroupSession::from_bytes(&group.to_bytes()).expect("restore");
    let ciphertext = restored
        .encrypt_as(&sender, b"after removal")
        .expect("encrypt");

    assert!(
        restored.decrypt_as(&removed, &ciphertext).is_err(),
        "a member removed before serialization must not decrypt after restore"
    );
}

#[test]
fn non_member_cannot_decrypt_after_restore() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();
    let outsider = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

    let restored = GroupSession::from_bytes(&group.to_bytes()).expect("restore");
    let ciphertext = restored
        .encrypt_as(&sender, b"members only")
        .expect("encrypt");

    assert!(
        restored
            .decrypt_as(NonMember(outsider.public()), &ciphertext)
            .is_err(),
        "a non-member must not decrypt a message from a restored group"
    );
}

#[test]
fn empty_member_group_round_trips() {
    let group = group_with_members(0);

    let restored = GroupSession::from_bytes(&group.to_bytes()).expect("restore");

    assert_eq!(restored.to_bytes(), group.to_bytes());
}

#[test]
fn group_with_255_members_round_trips() {
    let group = group_with_members(255);

    let restored = GroupSession::from_bytes(&group.to_bytes()).expect("restore");

    assert_eq!(restored.to_bytes(), group.to_bytes());
}

#[test]
fn empty_input_is_rejected() {
    assert_rejected(&[]);
}

#[test]
fn version_only_input_is_rejected() {
    assert_rejected(&[1u8]);
}

#[test]
fn unknown_version_zero_is_rejected() {
    assert_rejected(&blob(0, [0x22; 32], 0, &[]));
}

#[test]
fn unknown_version_two_is_rejected() {
    assert_rejected(&blob(2, [0x22; 32], 0, &[]));
}

#[test]
fn truncated_inside_chain_key_is_rejected() {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&[0x22; 20]);

    assert_rejected(&bytes);
}

#[test]
fn truncated_mid_member_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 1, &member_segment(33, &[0x33; 20])));
}

#[test]
fn truncated_by_one_byte_is_rejected() {
    let group = group_with_members(1);
    let mut bytes = group.to_bytes();
    bytes.pop();

    assert_rejected(&bytes);
}

#[test]
fn trailing_extra_byte_is_rejected() {
    let group = group_with_members(1);
    let mut bytes = group.to_bytes();
    bytes.push(0);

    assert_rejected(&bytes);
}

#[test]
fn member_count_256_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 256, &repeated_member_segments(256)));
}

#[test]
fn member_count_0xffff_with_short_body_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 0xFFFF, &[0u8; 10]));
}

#[test]
fn member_key_length_zero_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 1, &member_segment(0, &[])));
}

#[test]
fn member_key_length_32_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 1, &member_segment(32, &[0x33; 32])));
}

#[test]
fn member_key_length_34_is_rejected() {
    assert_rejected(&blob(1, [0x22; 32], 1, &member_segment(34, &[0x33; 34])));
}

#[test]
fn debug_output_does_not_contain_the_serialized_blob() {
    let group = group_with_members(2);
    let bytes = group.to_bytes();

    assert!(!format!("{:?}", group).contains(&format!("{:?}", bytes)));
}
