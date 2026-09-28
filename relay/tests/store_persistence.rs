//! RD-2: the relay's store-and-forward state must survive a restart.
//!
//! `Mailbox` (envelope FIFO) and `RelayStore` (prekey bundles) are today
//! constructible only in memory, so a restart silently drops every undelivered
//! envelope and every published prekey. This suite pins the durability contract
//! of the persistence constructors that close that gap:
//!
//! - `RelayStore::open(path)` / `Mailbox::open(path, max_depth)` open (or
//!   create) an on-disk store at `path` and return a `Result`.
//! - A "restart" is modelled by dropping the store and reopening the same path.
//! - Durability must not weaken the TTL mitigation: an entry whose TTL elapsed
//!   while the relay was down must NOT be resurrected.
//! - A corrupt/truncated store fails closed: it starts empty or refuses to
//!   start, but never panics and never serves garbage.
//! - The store stays blind: persistence adds no payload accessor.
//!
//! The rate limiter and PoW challenges are deliberately NOT persisted (a fresh
//! limiter per listener is pinned by `ws_bridge.rs`); nothing here asserts on
//! them.

use relay::store::{Mailbox, MailboxError, RelayStore, StoreError};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A unique, not-yet-existing store path under the system temp dir.
fn temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("relay-rd2-{}-{tag}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("relay-store.db")
}

fn open_store(path: &Path) -> RelayStore {
    RelayStore::open(path).expect("RelayStore::open must succeed on a fresh path")
}

fn open_mailbox(path: &Path, max_depth: usize) -> Mailbox {
    Mailbox::open(path, max_depth).expect("Mailbox::open must succeed on a fresh path")
}

// ── durability: the acceptance test that is missing today ────────────────────

#[test]
fn envelope_survives_a_restart() {
    let path = temp_path("envelope-restart");
    let envelope = vec![0xAAu8; 256];
    {
        let mb = open_mailbox(&path, 8);
        mb.enqueue("recipient-id", envelope.clone(), Duration::from_secs(60))
            .expect("enqueue");
    } // the relay "restarts": the in-memory handle is dropped

    let mb = open_mailbox(&path, 8);
    assert_eq!(
        mb.dequeue("recipient-id").expect("envelope must survive the restart"),
        envelope,
        "an undelivered envelope must still be delivered after a restart"
    );
}

#[test]
fn prekey_survives_a_restart() {
    let path = temp_path("prekey-restart");
    let bundle = vec![0xBBu8; 128];
    {
        let store = open_store(&path);
        store
            .store("recipient-id", bundle.clone(), Duration::from_secs(60))
            .expect("store");
    }

    let store = open_store(&path);
    assert_eq!(
        store.pickup("recipient-id").expect("prekey must survive the restart"),
        bundle,
        "a published prekey bundle must still be found after a restart"
    );
}

// ── security requirement: durability must not weaken the TTL mitigation ──────

#[test]
fn expired_entries_are_not_resurrected_by_a_restart() {
    // An envelope whose TTL elapses while the relay is down.
    let path = temp_path("envelope-expired");
    {
        let mb = open_mailbox(&path, 8);
        mb.enqueue("recipient-id", vec![0xCC; 64], Duration::from_millis(50))
            .expect("enqueue");
    }
    std::thread::sleep(Duration::from_millis(250)); // relay is down past the TTL
    let mb = open_mailbox(&path, 8);
    let result = mb.dequeue("recipient-id");
    assert!(
        matches!(result, Err(MailboxError::Expired) | Err(MailboxError::NotFound)),
        "an envelope whose TTL elapsed while the relay was down must not be delivered, got: {result:?}"
    );

    // A zero-TTL entry is already expired at the moment it is written.
    let path = temp_path("zero-ttl-envelope");
    {
        let mb = open_mailbox(&path, 8);
        mb.enqueue("recipient-id", vec![0xDD; 16], Duration::from_millis(0))
            .expect("enqueue");
    }
    let mb = open_mailbox(&path, 8);
    let result = mb.dequeue("recipient-id");
    assert!(
        matches!(result, Err(MailboxError::Expired) | Err(MailboxError::NotFound)),
        "a zero-TTL envelope must not be resurrected by a restart, got: {result:?}"
    );

    let path = temp_path("zero-ttl-prekey");
    {
        let store = open_store(&path);
        store
            .store("recipient-id", vec![0xEE; 32], Duration::from_millis(0))
            .expect("store");
    }
    let store = open_store(&path);
    let result = store.pickup("recipient-id");
    assert!(
        matches!(result, Err(StoreError::Expired) | Err(StoreError::NotFound)),
        "a zero-TTL prekey must not be resurrected by a restart, got: {result:?}"
    );
}

// ── boundary: queue semantics must hold across a restart ─────────────────────

#[test]
fn fifo_order_and_depth_cap_hold_across_a_restart() {
    let path = temp_path("fifo-cap");
    {
        let mb = open_mailbox(&path, 2);
        mb.enqueue("recipient-id", vec![1], Duration::from_secs(60))
            .expect("enqueue first");
        mb.enqueue("recipient-id", vec![2], Duration::from_secs(60))
            .expect("enqueue second");
    }

    let mb = open_mailbox(&path, 2);
    assert_eq!(
        mb.enqueue("recipient-id", vec![3], Duration::from_secs(60)),
        Err(MailboxError::QueueFull),
        "the per-recipient depth cap must still hold after a restart"
    );
    assert_eq!(mb.dequeue("recipient-id").expect("first"), vec![1]);
    assert_eq!(mb.dequeue("recipient-id").expect("second"), vec![2]);
    assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
}

// ── negative: corrupt / truncated / empty store files ────────────────────────

#[test]
fn corrupt_or_empty_store_fails_closed_without_panicking() {
    for (tag, bytes) in [("corrupt", &b"this is not a relay store"[..]), ("empty", &b""[..])] {
        let path = temp_path(tag);
        std::fs::write(&path, bytes).expect("write file");

        // Either refuse to start, or start empty — never panic, never serve garbage.
        if let Ok(store) = RelayStore::open(&path) {
            assert_eq!(store.count(), 0, "a {tag} store must not serve garbage");
            assert_eq!(store.pickup("recipient-id"), Err(StoreError::NotFound));
        }
        if let Ok(mb) = Mailbox::open(&path, 8) {
            assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
        }
    }
}

// ── boundary: a fresh path behaves exactly as today ──────────────────────────

#[test]
fn fresh_store_with_no_file_behaves_as_today() {
    let store_path = temp_path("fresh-store");
    assert!(!store_path.exists(), "the test path must not exist yet");
    let store = open_store(&store_path);
    assert_eq!(store.count(), 0);
    assert_eq!(store.pickup("recipient-id"), Err(StoreError::NotFound));
    store
        .store("recipient-id", vec![7], Duration::from_secs(60))
        .expect("store");
    assert_eq!(store.pickup("recipient-id").expect("pickup"), vec![7]);

    let mailbox_path = temp_path("fresh-mailbox");
    assert!(!mailbox_path.exists(), "the test path must not exist yet");
    let mb = open_mailbox(&mailbox_path, 4);
    assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
    mb.enqueue("recipient-id", vec![9], Duration::from_secs(60))
        .expect("enqueue");
    assert_eq!(mb.dequeue("recipient-id").expect("dequeue"), vec![9]);
}

// ── negative: state must be keyed by path, not process-global ────────────────

#[test]
fn stores_at_different_paths_are_isolated() {
    let mb_a = open_mailbox(&temp_path("isolation-mb-a"), 8);
    mb_a.enqueue("recipient-id", vec![0x11], Duration::from_secs(60))
        .expect("enqueue");
    let mb_b = open_mailbox(&temp_path("isolation-mb-b"), 8);
    assert_eq!(
        mb_b.dequeue("recipient-id"),
        Err(MailboxError::NotFound),
        "a store at one path must not see another path's envelopes"
    );
    assert_eq!(mb_a.dequeue("recipient-id").expect("still there"), vec![0x11]);

    let pk_a = open_store(&temp_path("isolation-pk-a"));
    pk_a.store("recipient-id", vec![0x22], Duration::from_secs(60))
        .expect("store");
    let pk_b = open_store(&temp_path("isolation-pk-b"));
    assert_eq!(
        pk_b.pickup("recipient-id"),
        Err(StoreError::NotFound),
        "a store at one path must not see another path's prekeys"
    );
    assert_eq!(pk_a.pickup("recipient-id").expect("still there"), vec![0x22]);
}

// ── blindness: persistence adds no payload accessor ──────────────────────────

#[test]
fn persistence_constructor_is_registered_and_the_store_stays_blind() {
    assert!(
        RelayStore::has_method("open"),
        "RelayStore::open is public, so has_method must report it"
    );
    for forbidden in ["decrypt", "read_plaintext", "parse"] {
        assert!(
            !RelayStore::has_method(forbidden),
            "RelayStore must not expose `{forbidden}` — the relay stays blind to payloads"
        );
    }
}

// ── hostile: valid magic, out-of-range expiry/count must fail closed ─────────

/// Hand-build a persisted file with valid magic/version and a hostile body.
fn hostile_file(tag: &str, count: u32, body: &[u8]) -> PathBuf {
    let path = temp_path(tag);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RDST");
    bytes.push(1); // STORE_FORMAT_VERSION
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(body);
    std::fs::write(&path, bytes).expect("write hostile file");
    path
}

#[test]
fn valid_magic_with_hostile_expiry_fails_closed_without_panicking() {
    // A file with valid magic/version but an expiry that cannot exist as a
    // SystemTime must fail closed at open(), not panic during listener startup.
    for (tag, secs, nanos) in [
        ("secs-overflow", u64::MAX, 0u32),
        ("nanos-overflow", 1, 2_000_000_000), // nanos >= 1s: Duration::new would panic
        ("both", u64::MAX, u32::MAX),
    ] {
        let mut body = Vec::new();
        body.extend_from_slice(&("recipient-id".len() as u32).to_be_bytes());
        body.extend_from_slice(b"recipient-id");
        body.extend_from_slice(&secs.to_be_bytes());
        body.extend_from_slice(&nanos.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes()); // value_len
        body.push(0x11);

        let path = hostile_file(&format!("expiry-{tag}"), 1, &body);
        if let Ok(store) = RelayStore::open(&path) {
            assert_eq!(
                store.count(),
                0,
                "{tag}: an out-of-range expiry must fail closed, not serve garbage"
            );
            assert_eq!(store.pickup("recipient-id"), Err(StoreError::NotFound));
        }
        if let Ok(mb) = Mailbox::open(&path, 8) {
            assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
        }
    }
}

#[test]
fn valid_magic_with_hostile_count_and_depth_fails_closed_without_aborting() {
    // count = u32::MAX with no entries: trusting it for pre-allocation would
    // attempt ~4 billion buckets and abort the process.
    let path = hostile_file("count-u32-max", u32::MAX, &[]);
    if let Ok(store) = RelayStore::open(&path) {
        assert_eq!(store.count(), 0, "a hostile count must not serve garbage");
        assert_eq!(store.pickup("recipient-id"), Err(StoreError::NotFound));
    }
    if let Ok(mb) = Mailbox::open(&path, 8) {
        assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
    }

    // depth = u32::MAX with no entries: same allocation-abort vector for the FIFO.
    let mut body = Vec::new();
    body.extend_from_slice(&("recipient-id".len() as u32).to_be_bytes());
    body.extend_from_slice(b"recipient-id");
    body.extend_from_slice(&u32::MAX.to_be_bytes()); // depth
    let path = hostile_file("depth-u32-max", 1, &body);
    if let Ok(mb) = Mailbox::open(&path, 8) {
        assert_eq!(mb.dequeue("recipient-id"), Err(MailboxError::NotFound));
    }
}
