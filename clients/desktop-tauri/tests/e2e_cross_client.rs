//! Cross-client end-to-end smoke test: a web-client message crosses a real relay to the
//! desktop client and is verified there.
//!
//! Unlike `e2e_cross_client_real.rs` (in-process crypto only), this test exercises the
//! genuine cross-client boundary end to end:
//!
//! ```text
//!   web client (RelayClient) --WS--> real in-process relay listener --WS--> desktop client
//! ```
//!
//! Both endpoints are real `clients_desktop_tauri::relay_client::RelayClient` instances
//! speaking the relay's actual WebSocket wire protocol (including its proof-of-work gate)
//! against a real `relay::ws::start_ws_listener_for_test` listener — no fake relay and no
//! re-implemented listener. The desktop side loads its identity from a persisted encrypted
//! store; the web side encrypts to that identity and hands the envelope to the relay, and
//! the desktop client picks it up over its own connection and decrypts it. Both sides then
//! derive the same safety number from the identities they actually hold.
//!
//! If any link in that chain breaks — the listener, the wire protocol, the PoW gate,
//! envelope send/pickup, the ratchet, or identity persistence — this test fails.

use std::path::Path;
use std::time::Duration;

use clients_desktop_tauri::relay_client::{EnvelopeKind, RelayClient, RelayError};
use core_crypto::ratchet_session::identity_hash;
use core_crypto::IdentityKeyPair;
use core_crypto::{derive_safety_number, generate_identity_key_pair, DoubleRatchetSession};
use core_storage::EncryptedStore;

/// Upper bound on any single await in this test. A broken cross-client path must FAIL, not
/// hang: every wait is bounded so a regression surfaces as a test failure.
const STEP: Duration = Duration::from_secs(60);

/// The plaintext the web client sends and the desktop client must recover.
const MESSAGE: &str = "hello from the web client, verified!";

/// Load the identity persisted in `dir`, or mint and persist one on first run.
///
/// This is the load-if-exists / generate-only-if-missing contract the desktop shell's
/// `identity_store` implements: an existing identity is NEVER overwritten, so a second
/// client loading the same directory sees the same identity (and therefore the same safety
/// number). Regenerating on every call would silently corrupt the persisted state — the
/// current connection would look fine while the next load got a different identity.
fn load_or_create_identity(dir: &Path) -> IdentityKeyPair {
    let key = [7u8; 32];
    let store = EncryptedStore::open(dir, &key).expect("open encrypted identity store");

    if let Some(serialized) = store.get_identity().expect("read persisted identity") {
        return IdentityKeyPair::try_from(serialized.as_slice())
            .expect("decode persisted identity");
    }

    let identity = generate_identity_key_pair();
    store
        .put_identity(&identity.serialize())
        .expect("persist identity");
    identity
}

/// The stable 32-byte peer id the transport addresses peers by: SHA-256 of the serialized
/// public identity key (see `core_crypto::ratchet_session::identity_hash`).
fn recipient_id(identity: &IdentityKeyPair) -> String {
    identity_hash(identity)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Public identity key bytes, as `derive_safety_number` expects them.
fn public_key_bytes(identity: &IdentityKeyPair) -> Vec<u8> {
    identity.identity_key().serialize().to_vec()
}

#[tokio::test]
async fn cross_client_smoke_test() {
    // --- Real in-process relay listener on an OS-assigned port -------------------------
    let relay = relay::ws::start_ws_listener_for_test(1_000).await;
    let relay_url = format!("ws://{}", relay.addr);

    // --- Persisted identities: the desktop client's, and the web client's --------------
    let desktop_dir = tempfile::tempdir().expect("desktop identity dir");
    let web_dir = tempfile::tempdir().expect("web identity dir");

    let desktop_identity = load_or_create_identity(desktop_dir.path());
    let web_identity = load_or_create_identity(web_dir.path());

    // The desktop identity must survive a reload from disk unchanged — this is the
    // persisted-identity boundary, not an in-memory cache.
    let reloaded = load_or_create_identity(desktop_dir.path());
    assert_eq!(
        public_key_bytes(&reloaded),
        public_key_bytes(&desktop_identity),
        "reloading the persisted identity must return the same key, not a freshly minted one"
    );

    let desktop_id = recipient_id(&desktop_identity);
    let web_id = recipient_id(&web_identity);

    // --- The desktop client connects to the real relay --------------------------------
    let mut desktop_client = tokio::time::timeout(STEP, RelayClient::connect(&relay_url))
        .await
        .expect("connect desktop client timed out")
        .expect("desktop client connects to the relay");

    // --- The web client connects to the same relay ------------------------------------
    let mut web_client = tokio::time::timeout(STEP, RelayClient::connect(&relay_url))
        .await
        .expect("connect web client timed out")
        .expect("web client connects to the relay");

    // --- The web client encrypts to the desktop identity ------------------------------
    let mut desktop_session = DoubleRatchetSession::new_bob(&desktop_identity)
        .await
        .expect("desktop session");
    let bundle = desktop_session
        .publish_bundle()
        .expect("desktop publishes bundle");
    let mut web_session = DoubleRatchetSession::new_alice(&web_identity, &bundle)
        .await
        .expect("web session");

    let ciphertext = web_session
        .encrypt(MESSAGE.as_bytes())
        .await
        .expect("web client encrypts");

    // --- The message crosses the relay ------------------------------------------------
    tokio::time::timeout(
        STEP,
        web_client.send_envelope(&desktop_id, &ciphertext, Some(EnvelopeKind::Direct)),
    )
    .await
    .expect("send_envelope timed out")
    .expect("web client sends the envelope through the relay");

    let envelope = tokio::time::timeout(
        STEP,
        desktop_client.pickup_envelope(&desktop_id, Some(EnvelopeKind::Direct)),
    )
    .await
    .expect("pickup_envelope timed out")
    .expect("desktop client picks the envelope up from the relay");

    assert_eq!(
        envelope.bytes, ciphertext,
        "the envelope the desktop client receives must be the one the web client sent"
    );
    assert_eq!(
        envelope.kind,
        Some(EnvelopeKind::Direct),
        "the out-of-band routing tag must survive the relay round trip"
    );

    // --- Verified: the desktop client decrypts it to the expected plaintext ------------
    let plaintext = desktop_session
        .decrypt(&envelope.bytes)
        .await
        .expect("desktop client decrypts the cross-client message");
    assert_eq!(
        String::from_utf8(plaintext).expect("plaintext is UTF-8"),
        MESSAGE,
        "the message that crossed the relay must arrive intact and decrypt to the expected plaintext"
    );

    // --- The relay delivered it once: the mailbox is now drained ----------------------
    let drained = tokio::time::timeout(
        STEP,
        desktop_client.pickup_envelope(&desktop_id, Some(EnvelopeKind::Direct)),
    )
    .await
    .expect("second pickup timed out");
    assert!(
        matches!(drained, Err(RelayError::NotFound)),
        "the relay must hand the envelope over exactly once, got {drained:?}"
    );

    // --- Verified: both sides derive the same safety number from the exchanged keys ----
    let web_safety = derive_safety_number(
        web_id.as_bytes(),
        &public_key_bytes(&web_identity),
        desktop_id.as_bytes(),
        &public_key_bytes(&desktop_identity),
    )
    .expect("web safety number");
    let desktop_safety = derive_safety_number(
        desktop_id.as_bytes(),
        &public_key_bytes(&desktop_identity),
        web_id.as_bytes(),
        &public_key_bytes(&web_identity),
    )
    .expect("desktop safety number");
    assert_eq!(
        web_safety, desktop_safety,
        "both clients must derive the same safety number for the identities they exchanged"
    );

    // --- Negative: a tampered envelope is rejected, so the check above is meaningful ---
    let mut tampered = envelope.bytes.clone();
    tampered[0] ^= 0xFF;
    assert!(
        desktop_session.decrypt(&tampered).await.is_err(),
        "a tampered cross-client envelope must fail to decrypt"
    );
}
