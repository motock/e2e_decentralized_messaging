//! The group session's initial chain key must not be derivable from public information.
//!
//! `GroupSession::new` used to derive the initial chain key from the sender's *public* identity
//! key, so anyone who knew that public key could reconstruct the chain key, rederive the
//! per-message key and decrypt. That made the property named by the in-file test
//! `an_attacker_who_only_reads_wire_bytes_cannot_decrypt_without_a_private_key` false.
//!
//! These tests grade that property through the public API only: an attacker who knows the
//! sender's public key (and nothing secret) must not be able to decrypt, while real members
//! still can, and the two per-message-key derivation sites (`encrypt_as` and
//! `try_decrypt_with_sender_key`) must stay in agreement.

use crypto::identity::IdentityKeyPair;
use protocol::group::{GroupMember, GroupSession, NonMember};

/// The core property: knowing only the sender's *public* identity key must not let an attacker
/// recover the plaintext. The attacker reconstructs a session from the public key alone and
/// tries the explicit-key decryption path with whatever chain key that yields.
#[test]
fn an_attacker_who_knows_only_the_senders_public_key_cannot_decrypt() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();

    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));
    let ciphertext = group
        .encrypt_as(&sender, b"group secret")
        .expect("encrypt");

    // The attacker holds no private key and no secret: only the sender's public identity key,
    // which is public knowledge. Reconstructing the session from it must NOT reproduce the
    // chain key that produced `ciphertext`.
    let attacker_session = GroupSession::new(sender.public());
    let attacker_chain_key = attacker_session.sender_key_copy_for(&sender);
    let result = attacker_session.try_decrypt_with_sender_key(&attacker_chain_key, &ciphertext);

    assert!(
        result.is_err(),
        "an attacker who knows only the sender's public key must not decrypt, got: {result:?}"
    );
}

/// The initial chain key must not be a deterministic function of the sender's public key.
#[test]
fn two_sessions_for_the_same_sender_do_not_share_a_chain_key() {
    let sender = IdentityKeyPair::generate();
    let a = GroupSession::new(sender.public());
    let b = GroupSession::new(sender.public());

    assert_ne!(
        a.sender_key_copy_for(&sender),
        b.sender_key_copy_for(&sender),
        "the initial chain key must not be a deterministic function of the sender's public key"
    );
}

/// Anchors BOTH per-message-key derivation sites: the key `encrypt_as` derives from the live
/// chain key must be exactly the key `try_decrypt_with_sender_key` re-derives from that same
/// chain key, and a stale key must still fail.
#[test]
fn encrypt_as_and_try_decrypt_with_sender_key_derive_the_same_message_key() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

    // Capture the chain key that will encrypt this message, before encrypt_as ratchets it.
    let chain_key = group.sender_key_copy_for(&sender);
    let ciphertext = group.encrypt_as(&sender, b"anchored").expect("encrypt");

    let recovered = group
        .try_decrypt_with_sender_key(&chain_key, &ciphertext)
        .expect("the chain key that encrypted the message must decrypt it");
    assert_eq!(recovered, b"anchored");

    // A chain key that did not encrypt this message must not decrypt it.
    let stale = [0u8; 32];
    assert!(
        group.try_decrypt_with_sender_key(&stale, &ciphertext).is_err(),
        "a chain key that did not encrypt the message must not decrypt it"
    );
}

/// Happy path: real members still decrypt after the chain key stops being public.
#[test]
fn members_still_decrypt() {
    let sender = IdentityKeyPair::generate();
    let a = IdentityKeyPair::generate();
    let b = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public())
        .add_member(GroupMember(a.public()))
        .add_member(GroupMember(b.public()));

    let ciphertext = group.encrypt_as(&sender, b"hello group").expect("encrypt");
    assert_eq!(group.decrypt_as(&a, &ciphertext).expect("a"), b"hello group");
    assert_eq!(group.decrypt_as(&b, &ciphertext).expect("b"), b"hello group");
}

/// Negative: a non-member still cannot decrypt.
#[test]
fn a_non_member_still_cannot_decrypt() {
    let sender = IdentityKeyPair::generate();
    let member = IdentityKeyPair::generate();
    let outsider = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

    let ciphertext = group.encrypt_as(&sender, b"members only").expect("encrypt");
    assert!(group.decrypt_as(&NonMember(outsider.public()), &ciphertext).is_err());
}

/// Boundary: an empty group encrypts, but nobody can decrypt.
#[test]
fn an_empty_group_encrypts_but_nobody_can_decrypt() {
    let sender = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public());

    let ciphertext = group.encrypt_as(&sender, b"no members").expect("encrypt");
    let outsider = IdentityKeyPair::generate();
    assert!(group.decrypt_as(&NonMember(outsider.public()), &ciphertext).is_err());
}

/// Boundary: a group with exactly one member still round-trips.
#[test]
fn a_single_member_group_round_trips() {
    let sender = IdentityKeyPair::generate();
    let only = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public()).add_member(GroupMember(only.public()));

    let ciphertext = group.encrypt_as(&sender, b"solo").expect("encrypt");
    assert_eq!(
        group.decrypt_as(&only, &ciphertext).expect("only member"),
        b"solo"
    );
}

/// Malformed input: a truncated ciphertext must be rejected with an error, never panic.
#[test]
fn a_truncated_ciphertext_is_rejected_not_panicked() {
    let sender = IdentityKeyPair::generate();
    let group = GroupSession::new(sender.public());
    let chain_key = group.sender_key_copy_for(&sender);

    for len in [0usize, 1, 11, 12, 16, 17] {
        let truncated = vec![0u8; len];
        let err = group
            .try_decrypt_with_sender_key(&chain_key, &truncated)
            .expect_err(&format!(
                "a {len}-byte ciphertext must be rejected, not accepted or panicked on"
            ));
        // Malformed input is a data error, not a panic and not a silent success.
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "a {len}-byte ciphertext must be reported as InvalidData, got {err:?}"
        );
    }
}
