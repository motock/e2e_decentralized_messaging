//! DT-4: conversation history persisted in the encrypted store, rendered via `ui`.
//!
//! Public interface these tests pin (`clients_desktop_tauri::conversation`):
//! - `ConversationStore::open(dir: &Path, key: &[u8; 32]) -> Result<ConversationStore, ConversationError>`
//!   (backed by `core_storage::EncryptedStore`, so history survives dropping and reopening it)
//! - `record_sent(&self, peer: &str, body: &[u8], unix_ts: i64) -> Result<(), ConversationError>`
//! - `record_received(&self, peer: &str, body: &[u8], unix_ts: i64) -> Result<(), ConversationError>`
//! - `record_decrypt_failure(&self, peer: &str, unix_ts: i64) -> Result<(), ConversationError>`
//! - `state(&self, peer: &str) -> Result<ui::ConversationState, ConversationError>` (oldest first)
//! - `pub const MAX_MESSAGE_BYTES: usize`; a body longer than it -> `ConversationError::TooLarge`
//!   and nothing is stored; an empty body -> `ConversationError::EmptyBody`.
//! - `ui::Message::decrypt_failure(unix_ts)`; `render_conversation` shows a visible marker
//!   containing the word "decrypt" for it.

use clients_desktop_tauri::conversation::{ConversationError, ConversationStore, MAX_MESSAGE_BYTES};
use clients_desktop_tauri::ui::{render_conversation, ConversationState, Message};

const KEY: [u8; 32] = [7u8; 32];

fn open(dir: &tempfile::TempDir) -> ConversationStore {
    ConversationStore::open(dir.path(), &KEY).expect("open store")
}

#[test]
fn sent_message_appears_in_the_conversation() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.record_sent("bob", b"hello bob", 1_700_000_000).unwrap();

    let rendered = render_conversation(&store.state("bob").unwrap());

    assert!(rendered.contains("hello bob"), "got: {rendered:?}");
    assert!(rendered.contains("You"), "sent side must be labelled, got: {rendered:?}");
}

#[test]
fn received_message_renders_as_a_message() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.record_received("bob", b"hi alice", 1_700_000_001).unwrap();

    let rendered = render_conversation(&store.state("bob").unwrap());

    assert!(rendered.contains("hi alice"), "got: {rendered:?}");
    assert!(rendered.contains("Them"), "received side must be labelled, got: {rendered:?}");
}

#[test]
fn messages_are_returned_oldest_first() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.record_sent("bob", b"first", 1_700_000_000).unwrap();
    store.record_received("bob", b"second", 1_700_000_005).unwrap();

    let rendered = render_conversation(&store.state("bob").unwrap());

    assert!(rendered.find("first").unwrap() < rendered.find("second").unwrap());
}

#[test]
fn history_survives_reopening_the_store() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).record_sent("bob", b"persisted", 1_700_000_000).unwrap();

    let rendered = render_conversation(&open(&dir).state("bob").unwrap());

    assert!(rendered.contains("persisted"), "got: {rendered:?}");
}

#[test]
fn conversations_with_different_peers_are_separate() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.record_sent("bob", b"for bob", 1_700_000_000).unwrap();

    let rendered = render_conversation(&store.state("carol").unwrap());

    assert!(!rendered.contains("for bob"), "got: {rendered:?}");
}

#[test]
fn unknown_peer_renders_the_empty_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = open(&dir).state("nobody").unwrap();

    assert!(state.messages.is_empty());
    assert!(render_conversation(&state).contains("no messages"));
}

#[test]
fn decrypt_failure_renders_a_visible_marker() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.record_decrypt_failure("bob", 1_700_000_000).unwrap();

    let rendered = render_conversation(&store.state("bob").unwrap());

    assert!(rendered.to_lowercase().contains("decrypt"), "got: {rendered:?}");
}

#[test]
fn decrypt_failure_message_renders_a_visible_marker_without_a_store() {
    let state = ConversationState { messages: vec![Message::decrypt_failure(1_700_000_000)] };

    assert!(render_conversation(&state).to_lowercase().contains("decrypt"));
}

#[test]
fn message_at_the_size_limit_is_accepted_whole() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let body = vec![b'a'; MAX_MESSAGE_BYTES];
    store.record_sent("bob", &body, 1_700_000_000).unwrap();

    let state = store.state("bob").unwrap();

    assert_eq!(state.messages.len(), 1);
    assert_eq!(state.messages[0].body, body, "body must not be truncated");
}

#[test]
fn message_one_byte_over_the_limit_is_rejected_and_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let result = store.record_sent("bob", &vec![b'a'; MAX_MESSAGE_BYTES + 1], 1_700_000_000);

    assert!(matches!(result, Err(ConversationError::TooLarge { .. })), "got: {result:?}");
    assert!(store.state("bob").unwrap().messages.is_empty());
}

#[test]
fn oversized_received_message_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let result = open(&dir).record_received("bob", &vec![b'a'; MAX_MESSAGE_BYTES + 1], 1_700_000_000);

    assert!(matches!(result, Err(ConversationError::TooLarge { .. })), "got: {result:?}");
}

#[test]
fn empty_message_body_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let result = open(&dir).record_sent("bob", b"", 1_700_000_000);

    assert!(matches!(result, Err(ConversationError::EmptyBody)), "got: {result:?}");
}

#[test]
fn reopening_with_the_wrong_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).record_sent("bob", b"secret", 1_700_000_000).unwrap();

    let result = ConversationStore::open(dir.path(), &[9u8; 32]);

    assert!(result.is_err(), "wrong key must not open the history");
}
