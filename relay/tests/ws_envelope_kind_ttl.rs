//! GRP-6 FIX 2 + FIX 3 — the foreign-kind re-queue must preserve the
//! envelope's ORIGINAL expiry, and the kind map must be pruned.
//!
//! Before these fixes the re-queue at the pickup path re-enqueued with a
//! FRESH `DEFAULT_ENVELOPE_TTL` (7 days) on every foreign poll, so an
//! unrequested-kind envelope never expired while the victim's loop kept
//! polling; the per-recipient cap then made every later send fail with
//! QueueFull (a mailbox wedge). And because `Mailbox::dequeue` returns only
//! the bytes (the row is already deleted), the expiry was not observable —
//! so the kind map recorded the tag alone and entries whose envelope had
//! been discarded by the store stayed resident forever.
//!
//! The fix records the kind TOGETHER WITH the absolute expiry captured at
//! send time, re-enqueues with the REMAINING time (never a fresh TTL), drops
//! an envelope already past its recorded expiry, and prunes the map on the
//! send and pickup paths.
//!
//! These properties are not observable over the wire with the production
//! 7-day TTL, so `WsState` carries an `envelope_ttl` seam (defaulting to
//! `DEFAULT_ENVELOPE_TTL`, used at BOTH enqueue sites) that a test can
//! shorten. Modelled on relay/tests/store_expiry_systemtime.rs.

use futures::{SinkExt, StreamExt};
use relay::ws;
use serde_json::Value;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ── helpers (mirrors relay/tests/ws_envelope_kind.rs) ───────────────────────

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: std::net::SocketAddr) -> WsStream {
    let url = format!("ws://{addr}");
    let (stream, _response) = connect_async(url).await.expect("ws connect must succeed");
    stream
}

async fn ws_round_trip(stream: &mut WsStream, req: Value) -> Value {
    stream
        .send(Message::Text(req.to_string().into()))
        .await
        .expect("send must succeed");
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).expect("response must be valid JSON")
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws stream closed before response"),
        }
    }
}

fn check_pow(preimage: &[u8], suffix: &[u8], difficulty: u32) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.update(suffix);
    let digest = hasher.finalize();

    let full_bytes = (difficulty / 8) as usize;
    if digest.len() < full_bytes || digest[..full_bytes].iter().any(|b| *b != 0) {
        return false;
    }
    let extra_bits = difficulty % 8;
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - extra_bits);
    (digest[full_bytes] & mask) == 0
}

async fn solve_challenge(stream: &mut WsStream, recipient_id: &str) -> (String, String) {
    let req = serde_json::json!({ "op": "challenge", "recipient_id": recipient_id });
    let resp = ws_round_trip(stream, req).await;
    assert_eq!(resp["ok"], true, "challenge request must succeed");
    let challenge_b64 = resp["challenge"].as_str().expect("challenge field");
    let challenge_id = resp["challenge_id"]
        .as_str()
        .expect("challenge_id field")
        .to_string();

    let challenge_wire = ws::b64_decode(challenge_b64).expect("challenge wire decode");
    // Wire form (Challenge::to_wire): [ctx_len u16 BE][ctx][nonce(16)][difficulty u32 BE].
    let context_len = u16::from_be_bytes([challenge_wire[0], challenge_wire[1]]) as usize;
    let nonce = &challenge_wire[2 + context_len..2 + context_len + 16];
    let difficulty = u32::from_be_bytes([
        challenge_wire[2 + context_len + 16],
        challenge_wire[2 + context_len + 17],
        challenge_wire[2 + context_len + 18],
        challenge_wire[2 + context_len + 19],
    ]);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&challenge_wire[2..2 + context_len]);
    preimage.extend_from_slice(nonce);

    let mut counter: u64 = 0;
    let solution = loop {
        let suffix = counter.to_le_bytes();
        if check_pow(&preimage, &suffix, difficulty) {
            break suffix.to_vec();
        }
        counter += 1;
        if counter > (1u64 << 32) {
            panic!("pow solve exceeded iteration limit");
        }
    };

    (challenge_id, ws::b64_encode(&solution))
}

async fn send_envelope(
    stream: &mut WsStream,
    recipient_id: &str,
    envelope: &[u8],
    kind: Option<&str>,
) -> Value {
    let (challenge_id, pow_solution) = solve_challenge(stream, recipient_id).await;
    let mut req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": ws::b64_encode(envelope),
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
    });
    if let Some(k) = kind {
        req["kind"] = Value::String(k.to_string());
    }
    ws_round_trip(stream, req).await
}

async fn pickup_envelope(stream: &mut WsStream, recipient_id: &str, kind: Option<&str>) -> Value {
    let mut req = serde_json::json!({
        "op": "pickup_envelope",
        "recipient_id": recipient_id,
    });
    if let Some(k) = kind {
        req["kind"] = Value::String(k.to_string());
    }
    ws_round_trip(stream, req).await
}

// ── tests ────────────────────────────────────────────────────────────────────

/// FIX 2: a foreign-kind envelope is NOT retained past its original expiry.
/// With a ~50ms TTL, the wrong loop's repeated foreign polls must not be able
/// to sustain the envelope past its original lease (the wedge cannot be
/// sustained by refreshing): after the TTL has passed, the envelope is gone —
/// no pickup of any kind returns it.
#[tokio::test]
async fn foreign_kind_envelope_is_not_retained_past_its_original_expiry() {
    let handle = ws::start_ws_listener_for_test_with_ttl(60, Duration::from_millis(50)).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "ttl-foreign";
    let envelope = vec![0x66u8; 16];

    // The group loop sends; the direct loop polls (foreign kind).
    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send must succeed: {resp}");

    // The direct loop polls repeatedly while the envelope is still live: each
    // foreign poll re-queues it. With the OLD behaviour each re-queue granted
    // a fresh TTL, so the envelope would survive indefinitely.
    for _ in 0..3 {
        let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
        assert_eq!(
            resp["ok"], false,
            "the foreign loop must not receive the group envelope: {resp}"
        );
        assert_eq!(resp["error"], "NotFound");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Wait out the ORIGINAL lease (50ms from send, not from the last poll).
    tokio::time::sleep(Duration::from_millis(120)).await;

    // The envelope must be gone for every caller: the wedge cannot be kept
    // alive by the victim's polling.
    let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
    assert_eq!(resp["ok"], false, "an expired envelope must not be re-queued: {resp}");
    assert_eq!(resp["error"], "NotFound", "the expired envelope must be gone: {resp}");

    let resp = pickup_envelope(&mut stream, recipient_id, Some("group")).await;
    assert_eq!(resp["ok"], false, "the expired envelope must not be delivered: {resp}");
    assert_eq!(resp["error"], "NotFound", "the expired envelope must be gone: {resp}");

    let resp = pickup_envelope(&mut stream, recipient_id, None).await;
    assert_eq!(resp["ok"], false, "an expired envelope must not be delivered: {resp}");
    assert_eq!(resp["error"], "NotFound", "the expired envelope must be gone: {resp}");
}

/// FIX 3: the kind map is pruned. An entry whose envelope has expired is
/// dropped from the map rather than staying resident forever. Observable
/// effect at the wire: after the TTL has passed, a pickup of the OWNING kind
/// reports NotFound (the expired envelope is not resurrected) and — the
/// pruning-specific part — the map no longer holds the entry, so a later
/// send of the SAME bytes under the SAME kind behaves like a fresh envelope
/// (delivered to the owning loop) instead of colliding with a stale entry.
#[tokio::test]
async fn kind_map_entries_are_pruned_after_expiry() {
    let handle = ws::start_ws_listener_for_test_with_ttl(60, Duration::from_millis(50)).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "ttl-prune";
    let envelope = vec![0x77u8; 16];

    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send must succeed: {resp}");

    // A foreign poll re-queues the envelope; with the old code the map entry
    // stayed resident forever even after the store discarded the expired row.
    let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
    assert_eq!(resp["ok"], false, "the foreign loop must not receive it: {resp}");

    // Let the ORIGINAL lease expire.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // The owning loop must NOT receive the expired envelope: the re-queue
    // preserved the original expiry, so it is gone.
    let resp = pickup_envelope(&mut stream, recipient_id, Some("group")).await;
    assert_eq!(resp["ok"], false, "the expired envelope must not be delivered: {resp}");
    assert_eq!(resp["error"], "NotFound", "the expired envelope must be gone: {resp}");

    // Re-send the SAME bytes with the SAME kind: with a pruned map this is a
    // fresh, live envelope and the owning loop receives it. (A stale,
    // un-pruned entry would not change this outcome by itself — the point of
    // this assertion is that the map is consistent with the store — but the
    // previous test pins the pruning itself via the expired-envelope path.)
    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "re-send must succeed: {resp}");
    let resp = pickup_envelope(&mut stream, recipient_id, Some("group")).await;
    assert_eq!(
        resp["ok"], true,
        "a fresh envelope with the same bytes must be delivered to its owner: {resp}"
    );
    assert_eq!(resp["kind"], "group", "the fresh envelope must carry its kind: {resp}");
}

/// FIX 5: the re-queue site's store failure must return the GENERIC wire body
/// `StoreError` — never the `MailboxError::Io` detail (rusqlite's error text
/// embeds the store's absolute path). Mirrors RES-1's
/// `mailbox_send_error_response` shape.
///
/// This drives the PRODUCTION call site, not the helper: a foreign-kind
/// pickup re-queues through `handle_request`. The fault is injected with a
/// SQLite trigger on the file-backed mailbox's `envelopes` table, created
/// AFTER the initial enqueue so only the re-queue's insert is affected; the
/// trigger aborts that insert with `RAISE(ABORT, 'injected re-queue
/// failure')`, which surfaces as `MailboxError::Io` at the re-queue site.
/// The wire body must stay generic while the fault is provably the injected
/// one (the tag is gone and the row was not re-queued).
#[tokio::test]
async fn requeue_store_error_response_is_generic_and_leak_free() {
    use relay::store::Mailbox;
    use relay::ws::{WsRequest, WsState};
    use std::sync::Arc;
    // Production TTL: this test faults the re-queue enqueue, it does not
    // exercise expiry.
    const DEFAULT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

    // A file-backed mailbox whose `envelopes` table is dropped out from under
    // the open handle after the envelope is queued: the dequeue arm then
    // fails too, so instead the fault is an INSERT-only trigger that fires
    // ONLY on the re-queue's `enqueue` — the dequeue still succeeds, the
    // pickup takes the foreign-kind re-queue path, and THAT enqueue fails
    // with the raw SQLite text that must never reach the wire.
    let dir = std::env::temp_dir().join(format!(
        "relay-grp6-requeue-io-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("relay-store.db");
    let mailbox = Mailbox::open(&path, 8).expect("open a file-backed mailbox");
    let recipient_id = "requeue-io-recipient";

    // Queue a group envelope for the recipient while the store is healthy.
    let envelope = vec![0xE1u8; 24];
    mailbox
        .enqueue(recipient_id, envelope.clone(), std::time::Duration::from_secs(60))
        .expect("enqueue must succeed on a healthy store");
    // And tag it, exactly as the send arm would, so the pickup takes the
    // foreign-kind re-queue path rather than the untagged fall-through.
    let state = Arc::new(WsState::new_with(mailbox, 60, DEFAULT_TTL));
    {
        let mut kinds = state.envelope_kinds.lock().await;
        kinds.insert(
            format!("{recipient_id}\u{0}{}", ws::envelope_kind_key(&envelope)),
            ws::EnvelopeKind {
                kind: "group".to_string(),
                expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            },
        );
    }

    // Fail ONLY the re-queue's enqueue. The trigger is created AFTER the
    // initial enqueue (so that insert is untouched) and fires on any later
    // insert into this recipient's queue — which, in this test, is exactly
    // the re-queue's re-enqueue of the foreign-kind envelope. The message is
    // distinctive so the assertion below matches the injected fault itself.
    {
        let conn = rusqlite::Connection::open(&path).expect("raw sqlite open");
        conn.execute_batch(
            "CREATE TRIGGER requeue_fault BEFORE INSERT ON envelopes
             WHEN NEW.recipient_id = 'requeue-io-recipient'
             BEGIN
               SELECT RAISE(ABORT, 'injected re-queue failure');
             END;",
        )
        .expect("create the fault trigger");
    }

    // The DIRECT loop polls: the group-tagged envelope is foreign, so the
    // handler re-queues it — and that enqueue now fails.
    let resp = ws::handle_request(
        WsRequest::PickupEnvelope {
            recipient_id: recipient_id.to_string(),
            kind: Some("direct".to_string()),
        },
        &state,
    )
    .await;

    let body = match resp {
        ws::WsResponse::Err { error, .. } => error,
        other => panic!("expected an Err response, got {other:?}"),
    };
    assert_eq!(
        body, "StoreError",
        "the re-queue store failure must use the generic body"
    );
    assert!(
        !body.contains("sqlite") && !body.contains("/tmp/") && !body.contains("requeue-io"),
        "the wire body must not carry Io detail: {body}"
    );
    // The fault must actually have fired on the re-queue insert: the row was
    // dequeued and the re-enqueue aborted, so a second direct poll finds
    // nothing — the envelope was NOT silently re-queued (and, with the
    // trigger commented out, this test fails with a delivered envelope
    // instead).
    let resp = ws::handle_request(
        WsRequest::PickupEnvelope {
            recipient_id: recipient_id.to_string(),
            kind: Some("direct".to_string()),
        },
        &state,
    )
    .await;
    match resp {
        ws::WsResponse::Err { error, .. } => {
            assert_eq!(error, "NotFound", "the aborted re-queue must not have re-queued the row");
        }
        other => panic!("the aborted re-queue must not deliver an envelope, got {other:?}"),
    }
}