//! Opaque discovery-blob storage for the relay.
//!
//! A *discovery blob* is an end-to-end-encrypted, client-produced payload that a
//! peer publishes under its own `recipient_id` so that other peers can fetch it
//! later (multi-device discovery). The relay is deliberately **blind**: it never
//! parses, decodes, or verifies the blob — it only enforces a size cap and a TTL.
//!
//! Storage is keyed by [`discovery_key`] in a dedicated namespace so discovery
//! blobs can never collide with prekey bundles or mailbox envelopes.

use std::time::Duration;

use crate::store::{RelayStore, StoreError};

/// Maximum accepted size of a discovery blob, in bytes.
///
/// The cap is inclusive: a blob of exactly this many bytes is accepted, one byte
/// more is rejected. Enforced here (defence in depth) and again in the
/// `publish_discovery` WS arm so the peer gets the specific `DiscoveryTooLarge`
/// reason.
pub const MAX_DISCOVERY_BLOB_BYTES: usize = 65536;

/// TTL granted to a stored discovery blob (7 days).
pub const DISCOVERY_TTL: Duration = Duration::from_secs(7 * 86400);

/// Store key for a recipient's discovery blob.
///
/// The `discovery:` prefix keeps this namespace disjoint from `prekey:` bundles
/// and from mailbox envelopes, which share the same underlying table.
pub fn discovery_key(recipient_id: &str) -> String {
    format!("discovery:{recipient_id}")
}

/// Store `blob` for `recipient_id`, replacing any previous blob (last write wins).
///
/// Rejects an oversize blob **without writing**: the existing entry, if any, is
/// left untouched. The blob is treated as opaque bytes — it is never parsed.
pub fn store_blob(store: &RelayStore, recipient_id: &str, blob: Vec<u8>) -> Result<(), StoreError> {
    if blob.len() > MAX_DISCOVERY_BLOB_BYTES {
        // Reject BEFORE touching the store: an oversize publish must not evict or
        // truncate the blob already published under this handle.
        return Err(StoreError::Io(format!(
            "discovery blob too large: {} bytes (max {MAX_DISCOVERY_BLOB_BYTES})",
            blob.len()
        )));
    }
    store.store(&discovery_key(recipient_id), blob, DISCOVERY_TTL)
}

/// Load the discovery blob for `recipient_id` without consuming it.
///
/// Delegates to [`RelayStore::peek`], so repeated lookups return the same bytes
/// and expiry is decided by the store, not by this module.
pub fn load_blob(store: &RelayStore, recipient_id: &str) -> Result<Vec<u8>, StoreError> {
    store.peek(&discovery_key(recipient_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T1: a stored blob round-trips, and reading it twice returns the same bytes
    /// (peek is non-consuming).
    #[test]
    fn round_trip_is_non_consuming() {
        let store = RelayStore::new();
        assert!(store_blob(&store, "alice", vec![1, 2, 3]).is_ok());

        let first = load_blob(&store, "alice").expect("first load must succeed");
        assert_eq!(first, vec![1, 2, 3]);

        let second = load_blob(&store, "alice").expect("second load must succeed");
        assert_eq!(second, vec![1, 2, 3], "peek must not consume the blob");
    }

    /// T2: publishing twice replaces the blob (last write wins, no append, no
    /// duplicate error).
    #[test]
    fn second_publish_wins() {
        let store = RelayStore::new();
        assert!(store_blob(&store, "dave", vec![1, 1]).is_ok());
        assert!(
            store_blob(&store, "dave", vec![2, 2, 2]).is_ok(),
            "re-publishing must not be an error"
        );

        let loaded = load_blob(&store, "dave").expect("load must succeed");
        assert_eq!(loaded, vec![2, 2, 2]);
        assert_eq!(loaded.len(), 3, "blobs must not be appended");
    }

    /// T3: the size cap is inclusive at exactly `MAX_DISCOVERY_BLOB_BYTES`, and an
    /// oversize publish is rejected without disturbing the stored blob.
    #[test]
    fn size_boundary_is_inclusive_and_rejection_preserves_state() {
        let store = RelayStore::new();
        assert!(store_blob(&store, "bob", Vec::new()).is_ok());

        assert!(
            store_blob(&store, "bob", vec![7u8; MAX_DISCOVERY_BLOB_BYTES]).is_ok(),
            "exactly MAX_DISCOVERY_BLOB_BYTES must be accepted"
        );
        let at_cap = load_blob(&store, "bob").expect("load must succeed");
        assert_eq!(at_cap.len(), MAX_DISCOVERY_BLOB_BYTES);

        let oversize = store_blob(&store, "bob", vec![9u8; MAX_DISCOVERY_BLOB_BYTES + 1]);
        assert!(oversize.is_err(), "one byte over the cap must be rejected");

        let after = load_blob(&store, "bob").expect("previous blob must survive");
        assert_eq!(after.len(), MAX_DISCOVERY_BLOB_BYTES);
        assert_eq!(after[0], 7, "the rejected blob must not be stored");
    }

    /// T4: an unknown handle is `NotFound` — not an empty blob.
    #[test]
    fn unknown_handle_is_not_found() {
        let store = RelayStore::new();
        match load_blob(&store, "nobody") {
            Err(StoreError::NotFound) => {}
            other => panic!("expected StoreError::NotFound, got {other:?}"),
        }
    }

    /// T5: the blob is opaque — arbitrary non-UTF-8 bytes survive verbatim.
    #[test]
    fn blob_is_opaque() {
        let store = RelayStore::new();
        assert!(store_blob(&store, "erin", vec![0xFF, 0xFE, 0x00]).is_ok());
        assert_eq!(
            load_blob(&store, "erin").expect("load must succeed"),
            vec![0xFF, 0xFE, 0x00]
        );
    }

    /// T6: constants and key format are pinned.
    #[test]
    fn constants_and_key_format() {
        assert_eq!(MAX_DISCOVERY_BLOB_BYTES, 65536);
        assert_eq!(DISCOVERY_TTL, Duration::from_secs(604800));
        assert_eq!(discovery_key("alice"), "discovery:alice");
    }
}
