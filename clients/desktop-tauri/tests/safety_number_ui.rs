//! Safety-number verification UI — mark verified; warn on key change.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Matching safety numbers can be marked verified
//!  - Negative: a changed identity key after verification surfaces a clear warning, not a silent pass-through
//!
//! DT-4 (pre-authorized edit): the expected number used to ride in a thread-local set by
//! `VerificationState::new`. It now lives in the encrypted store, so the three original tests
//! construct state through `VerificationStore` (`open(dir, &key)`, `begin(peer, expected)`,
//! `verify(peer, input)`, `state(peer)`), with the same assertions as before. The tests that
//! follow the original three are new: persistence across restart and no cross-state leakage.

use clients_desktop_tauri::verify::{VerificationState, VerificationStore};

const KEY: [u8; 32] = [3u8; 32];

fn open(dir: &tempfile::TempDir) -> VerificationStore {
    VerificationStore::open(dir.path(), &KEY).expect("open verification store")
}

#[test]
fn matching_safety_numbers_can_be_marked_verified() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let safety_number = "12345 67890 12345 67890 12345";
    store.begin("bob", safety_number).unwrap();

    let result = store.verify("bob", safety_number).unwrap();
    assert_eq!(result, VerificationState::Verified);
}

#[test]
fn changed_identity_key_after_verification_surfaces_warning_not_silent_pass() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let original_number = "11111 22222 33333 44444 55555";
    store.begin("bob", original_number).unwrap();
    let state = store.verify("bob", original_number).unwrap();
    assert_eq!(state, VerificationState::Verified);

    // Identity key rotates (e.g., reinstall), safety number now differs.
    let new_number = "99999 88888 77777 66666 55555";
    let state = store.verify("bob", new_number).unwrap();

    assert!(
        matches!(state, VerificationState::KeyChangedWarning { .. }),
        "changed identity key must surface VerificationState::KeyChangedWarning, got: {state:?}"
    );
}

#[test]
fn mismatched_user_input_does_not_mark_verified() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.begin("bob", "12345 67890 12345 67890 12345").unwrap();

    let result = store.verify("bob", "00000 00000 00000 00000 00000").unwrap();
    assert_eq!(result, VerificationState::Unverified);
}

#[test]
fn verified_state_survives_an_app_restart() {
    let dir = tempfile::tempdir().unwrap();
    let number = "12345 67890 12345 67890 12345";
    let store = open(&dir);
    store.begin("bob", number).unwrap();
    store.verify("bob", number).unwrap();
    drop(store);

    assert_eq!(open(&dir).state("bob").unwrap(), VerificationState::Verified);
}

#[test]
fn key_change_is_still_detected_after_an_app_restart() {
    let dir = tempfile::tempdir().unwrap();
    let number = "12345 67890 12345 67890 12345";
    let store = open(&dir);
    store.begin("bob", number).unwrap();
    store.verify("bob", number).unwrap();
    drop(store);

    let state = open(&dir).verify("bob", "99999 88888 77777 66666 55555").unwrap();

    assert!(matches!(state, VerificationState::KeyChangedWarning { .. }), "got: {state:?}");
}

#[test]
fn unverified_peer_stays_unverified_after_an_app_restart() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).begin("bob", "12345 67890 12345 67890 12345").unwrap();

    assert_eq!(open(&dir).state("bob").unwrap(), VerificationState::Unverified);
}

#[test]
fn unknown_peer_is_unverified() {
    let dir = tempfile::tempdir().unwrap();

    assert_eq!(open(&dir).state("stranger").unwrap(), VerificationState::Unverified);
}

#[test]
fn expected_numbers_of_different_peers_do_not_leak_into_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    store.begin("bob", "11111 11111 11111 11111 11111").unwrap();
    store.begin("carol", "22222 22222 22222 22222 22222").unwrap();

    let result = store.verify("bob", "22222 22222 22222 22222 22222").unwrap();

    assert_eq!(result, VerificationState::Unverified);
}

#[test]
fn verifying_a_peer_that_was_never_begun_does_not_verify() {
    let dir = tempfile::tempdir().unwrap();

    let result = open(&dir).verify("stranger", "12345 67890 12345 67890 12345").unwrap();

    assert_eq!(result, VerificationState::Unverified);
}
