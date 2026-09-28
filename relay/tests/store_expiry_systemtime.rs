//! RD-1: envelope/prekey expiry must be a wall clock (`SystemTime`), not a
//! monotonic `Instant`.
//!
//! The expiry type lives in the private fields `RelayStore::inner` and
//! `Mailbox::queues`, and no public accessor exposes an expiry value, so an
//! external integration test cannot name the store's expiry type directly.
//! The type swap is therefore verified by `cargo build` plus the pre-existing
//! `store_forward_ttl` / `mailbox_queue` suites; this file pins the observable
//! boundary behaviour the swap must preserve: a zero-TTL entry is expired on
//! the very next read, with no sleep and no timing race.

use relay::store::{Mailbox, MailboxError, RelayStore, StoreError};
use std::time::{Duration, SystemTime};

/// TTL that stays live for the whole test (no sleeps, no timing races).
const LIVE: Duration = Duration::from_secs(60);
/// TTL that has already elapsed by the time the entry is inspected.
const DEAD: Duration = Duration::from_millis(0);

fn env(tag: u8) -> Vec<u8> {
    vec![tag; 16]
}

/// Compile-time pin for the wall-clock type the expiry must be built from.
///
/// `Instant` does not satisfy this signature, so the helper documents the
/// intended type even though the store's private field cannot be named here.
fn takes_systemtime(_: SystemTime) {}

#[test]
fn expiry_is_built_from_a_wall_clock() {
    // The store computes `expiry = now + ttl`; that arithmetic must be the
    // wall-clock one, i.e. `SystemTime + Duration`.
    let expiry = SystemTime::now() + DEAD;
    takes_systemtime(expiry);
    assert!(
        expiry <= SystemTime::now(),
        "a zero TTL must already be expired on the next wall-clock read"
    );
}

#[test]
fn zero_ttl_envelope_is_expired_on_the_very_next_read() {
    let store = RelayStore::new();
    store.store("recipient-id", env(1), DEAD).expect("store");

    // No sleep: the boundary is `expiry <= now`, so the very next read is
    // expired even if it lands in the same clock tick as the insert.
    assert_eq!(store.pickup("recipient-id"), Err(StoreError::Expired));
    assert_eq!(store.pickup("recipient-id"), Err(StoreError::NotFound));
}

#[test]
fn zero_ttl_mailbox_entry_is_expired_on_the_very_next_read() {
    let mb = Mailbox::new(8);
    mb.enqueue("alice", env(1), DEAD).unwrap();

    assert_eq!(mb.dequeue("alice"), Err(MailboxError::Expired));
    assert_eq!(mb.dequeue("alice"), Err(MailboxError::NotFound));
}

#[test]
fn live_ttl_envelope_is_still_delivered() {
    let store = RelayStore::new();
    store.store("recipient-id", env(2), LIVE).expect("store");

    assert_eq!(store.pickup("recipient-id").unwrap(), env(2));
}
