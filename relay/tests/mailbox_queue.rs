//! FIFO mailbox queueing for offline recipients (`relay::store::Mailbox`).
//!
//! The single-slot `RelayStore` silently overwrites a pending envelope when a
//! second message arrives for an offline recipient. `Mailbox` is the bounded,
//! per-recipient FIFO counterpart: arrival order is preserved, the depth cap is
//! enforced without evicting older envelopes, and expired entries are dropped.
//!
//! Envelope bytes are opaque here: the tests only ever compare them for equality.

use relay::store::{Mailbox, MailboxError, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT};
use std::time::Duration;

/// TTL that is still live for the whole test (no sleeps, no timing races).
const LIVE: Duration = Duration::from_secs(60);
/// TTL that is already elapsed by the time the entry is inspected.
const DEAD: Duration = Duration::from_millis(0);

fn env(tag: u8) -> Vec<u8> {
    vec![tag; 16]
}

// ---------------------------------------------------------------- positive ---

#[test]
fn two_envelopes_for_one_recipient_dequeue_in_arrival_order() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), LIVE).expect("first enqueue");
    mb.enqueue("alice", env(2), LIVE).expect("second enqueue");

    assert_eq!(mb.dequeue("alice").expect("first dequeue"), env(1));
    assert_eq!(mb.dequeue("alice").expect("second dequeue"), env(2));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn dequeue_removes_exactly_one_envelope_per_call() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), LIVE).unwrap();
    mb.enqueue("alice", env(2), LIVE).unwrap();

    assert_eq!(mb.dequeue("alice").unwrap(), env(1));
    // One call removed one envelope: the second is still queued.
    assert_eq!(mb.dequeue("alice").unwrap(), env(2));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn recipients_have_independent_queues() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), LIVE).unwrap();
    mb.enqueue("bob", env(2), LIVE).unwrap();

    assert_eq!(mb.dequeue("bob").unwrap(), env(2));
    assert_eq!(mb.dequeue("alice").unwrap(), env(1));
    assert_eq!(mb.dequeue("bob"), Err(MailboxError::NotFound));
}

#[test]
fn envelope_enqueued_after_a_dequeue_is_returned() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), LIVE).unwrap();
    assert_eq!(mb.dequeue("alice").unwrap(), env(1));

    mb.enqueue("alice", env(2), LIVE).unwrap();
    assert_eq!(mb.dequeue("alice").unwrap(), env(2));
}

// ------------------------------------------------------- negative/boundary ---

#[test]
fn dequeue_with_nothing_ever_stored_is_not_found() {
    let mb = Mailbox::new(8);
    assert_eq!(mb.dequeue("nobody"), Err(MailboxError::NotFound));
}

#[test]
fn queue_accepts_up_to_max_depth_then_rejects_without_dropping() {
    let mb = Mailbox::new(3);
    // max_depth - 1 = 2 entries: accepted.
    mb.enqueue("alice", env(1), LIVE).expect("depth 1 of 3");
    mb.enqueue("alice", env(2), LIVE).expect("depth 2 of 3");
    // At max_depth: still accepted.
    mb.enqueue("alice", env(3), LIVE).expect("depth 3 of 3");
    // One past max_depth: rejected, and nothing was evicted to make room.
    assert_eq!(
        mb.enqueue("alice", env(4), LIVE),
        Err(MailboxError::QueueFull)
    );

    for tag in 1..=3u8 {
        assert_eq!(
            mb.dequeue("alice").unwrap(),
            env(tag),
            "queued envelope {tag} must survive"
        );
    }
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn zero_depth_rejects_every_enqueue() {
    let mb = Mailbox::new(0);
    assert_eq!(
        mb.enqueue("alice", env(1), LIVE),
        Err(MailboxError::QueueFull)
    );
    assert_eq!(
        mb.enqueue("alice", env(2), LIVE),
        Err(MailboxError::QueueFull)
    );
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn depth_one_accepts_one_then_rejects() {
    let mb = Mailbox::new(1);
    mb.enqueue("alice", env(1), LIVE).expect("first fits");
    assert_eq!(
        mb.enqueue("alice", env(2), LIVE),
        Err(MailboxError::QueueFull)
    );
    assert_eq!(mb.dequeue("alice").unwrap(), env(1));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn expired_front_entry_is_skipped_and_live_entry_behind_it_returned() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), DEAD).unwrap();
    mb.enqueue("alice", env(2), LIVE).unwrap();

    assert_eq!(mb.dequeue("alice").unwrap(), env(2));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn queue_of_only_expired_entries_reports_expired_once_then_not_found() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), DEAD).unwrap();
    mb.enqueue("alice", env(2), DEAD).unwrap();

    assert_eq!(mb.dequeue("alice"), Err(MailboxError::Expired));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn expired_entries_do_not_count_toward_the_depth_cap() {
    let mb = Mailbox::new(2);
    mb.enqueue("alice", env(1), DEAD).unwrap();
    mb.enqueue("alice", env(2), DEAD).unwrap();

    // The queue is "full" only with expired entries, so a live one still fits.
    mb.enqueue("alice", env(3), LIVE)
        .expect("expired entries must be dropped first");
    assert_eq!(mb.dequeue("alice").unwrap(), env(3));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn default_max_depth_is_64_and_default_matches_it() {
    assert_eq!(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT, 64);

    let mb = Mailbox::default();
    for tag in 0..64u8 {
        mb.enqueue("alice", env(tag), LIVE)
            .expect("within default depth");
    }
    assert_eq!(
        mb.enqueue("alice", env(99), LIVE),
        Err(MailboxError::QueueFull)
    );
}

#[test]
fn mailbox_error_is_debug_and_partial_eq() {
    assert_eq!(MailboxError::NotFound, MailboxError::NotFound);
    assert_ne!(MailboxError::NotFound, MailboxError::Expired);
    assert_ne!(MailboxError::Expired, MailboxError::QueueFull);
    assert!(format!("{:?}", MailboxError::QueueFull).contains("QueueFull"));
}

// ------------------------------------------------------------- structural ---

#[test]
fn mailbox_is_defined_below_relay_store_with_a_doc_comment() {
    let src = include_str!("../src/store.rs");
    let store_at = src
        .find("pub struct RelayStore")
        .expect("RelayStore must remain in store.rs");
    let mailbox_at = src
        .find("pub struct Mailbox ")
        .expect("Mailbox must be added to store.rs");
    assert!(
        mailbox_at > store_at,
        "Mailbox must be defined below the existing RelayStore"
    );

    // Walk back over attribute/blank lines to find the doc comment block.
    let mut preceding = src[..mailbox_at].lines().rev().skip_while(|l| {
        let t = l.trim_start();
        t.starts_with("#[") || t.is_empty()
    });
    assert!(
        preceding.next().unwrap_or("").trim_start().starts_with("///"),
        "Mailbox must carry a doc comment explaining why it exists next to RelayStore"
    );

    assert!(src.contains("pub enum MailboxError"), "MailboxError must be public in store.rs");
    assert!(
        src.contains("pub const DEFAULT_MAX_ENVELOPES_PER_RECIPIENT"),
        "DEFAULT_MAX_ENVELOPES_PER_RECIPIENT must be a public const"
    );
    assert!(
        src.contains("VecDeque<(Vec<u8>, Instant)>"),
        "Mailbox storage must be a per-recipient VecDeque of (envelope, expiry)"
    );
}

#[test]
fn mailbox_exposes_only_new_enqueue_and_dequeue() {
    let src = include_str!("../src/store.rs");
    let start = src.find("impl Mailbox {").expect("impl Mailbox block must exist");
    let rest = &src[start..];
    let end = rest.find("\n}").expect("impl Mailbox must be closed");
    let mut names: Vec<&str> = rest[..end]
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub fn "))
        .map(|sig| sig.split(['(', '<']).next().unwrap_or("").trim())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["dequeue", "enqueue", "new"],
        "Mailbox must expose exactly new/enqueue/dequeue and no other public API"
    );
}

#[test]
fn relay_store_and_store_error_are_unchanged() {
    let src = include_str!("../src/store.rs");
    for needle in [
        "pub enum StoreError",
        "pub struct RelayStore",
        "pub fn store(",
        "pub fn pickup(",
        "pub fn purge(",
        "pub fn count(",
        "pub fn has_method(",
    ] {
        assert!(src.contains(needle), "store.rs must keep `{needle}` (prekey bundles depend on it)");
    }
}
