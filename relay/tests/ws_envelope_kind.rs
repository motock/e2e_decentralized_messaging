//! Relay-side tests for the out-of-band envelope `kind` discriminator.
//!
//! The kind travels as a SIBLING FIELD on the relay's `send_envelope` /
//! `pickup_envelope` ops — never inside the ciphertext bytes. These tests pin
//! that contract at the wire level:
//!
//! - `send_envelope` accepts a `kind` field and stores it alongside the payload.
//! - `pickup_envelope` accepts a `kind` field and only returns envelopes whose
//!   kind matches, so a foreign-kind envelope is NOT destroyed by the wrong
//!   loop — the owning loop still receives it afterwards.
//! - The envelope bytes are passed through byte-for-byte: the kind is not part
//!   of the ciphertext.
//! - A missing kind falls through (is still delivered), it is not skipped.

use futures::{SinkExt, StreamExt};
use relay::ws;
use serde_json::Value;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ── helpers (mirrors relay/tests/ws_bridge.rs) ───────────────────────────────

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

/// Send an envelope with an optional out-of-band `kind` sibling field.
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

/// Pick up an envelope, optionally filtering by `kind`.
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

fn envelope_bytes(resp: &Value) -> Vec<u8> {
    ws::b64_decode(resp["envelope"].as_str().expect("envelope field")).expect("envelope decode")
}

// ── tests ────────────────────────────────────────────────────────────────────

/// The kind is a sibling field on the op: `pickup_envelope` returns the kind
/// that was supplied to `send_envelope`.
#[tokio::test]
async fn send_envelope_carries_kind_and_pickup_returns_it() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "kind-roundtrip";
    let envelope = vec![0x11u8, 0x22, 0x33, 0x44];

    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send_envelope with kind must succeed: {resp}");

    let resp = pickup_envelope(&mut stream, recipient_id, Some("group")).await;
    assert_eq!(
        resp["ok"], true,
        "pickup_envelope with the matching kind must succeed: {resp}"
    );
    assert_eq!(
        resp["kind"], "group",
        "the kind must come back as a sibling field of the pickup response"
    );
    assert_eq!(envelope_bytes(&resp), envelope, "envelope bytes must round-trip unchanged");
}

/// A foreign-kind envelope is NOT destroyed by the wrong loop: a pickup with a
/// non-matching kind reports NotFound and leaves the envelope queued, so the
/// owning loop still receives it afterwards.
#[tokio::test]
async fn pickup_with_foreign_kind_does_not_destroy_the_envelope() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "kind-foreign";
    let envelope = vec![0xAAu8; 32];

    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send_envelope must succeed: {resp}");

    // The direct loop polls with its own kind and must not receive (or destroy)
    // the group envelope.
    let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
    assert_eq!(
        resp["ok"], false,
        "a foreign-kind pickup must not hand the envelope to the wrong loop: {resp}"
    );
    assert_eq!(
        resp["error"], "NotFound",
        "a foreign-kind pickup must report NotFound, not an error that discards it: {resp}"
    );

    // The owning (group) loop still receives it afterwards.
    let resp = pickup_envelope(&mut stream, recipient_id, Some("group")).await;
    assert_eq!(
        resp["ok"], true,
        "the owning loop must still receive the envelope afterwards: {resp}"
    );
    assert_eq!(
        envelope_bytes(&resp),
        envelope,
        "the envelope must survive the foreign pickup unchanged"
    );
}

/// The kind is NOT part of the ciphertext: the bytes handed back are exactly the
/// bytes that were sent, with no wrapper or tag prepended/appended.
#[tokio::test]
async fn envelope_bytes_are_not_wrapped_by_the_kind() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "kind-bytes";
    let envelope: Vec<u8> = (0u8..64).collect();

    let resp = send_envelope(&mut stream, recipient_id, &envelope, Some("direct")).await;
    assert_eq!(resp["ok"], true, "send_envelope must succeed: {resp}");

    let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
    assert_eq!(resp["ok"], true, "pickup_envelope must succeed: {resp}");
    assert_eq!(
        envelope_bytes(&resp),
        envelope,
        "the ciphertext must be byte-for-byte unchanged — the kind is not inside it"
    );
}

/// Missing kind must fall through, not skip: an envelope sent without a kind is
/// still delivered, and a pickup without a kind still returns it.
#[tokio::test]
async fn missing_kind_falls_through_and_is_still_delivered() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "kind-missing";
    let envelope = vec![0x5Au8; 16];

    let resp = send_envelope(&mut stream, recipient_id, &envelope, None).await;
    assert_eq!(
        resp["ok"], true,
        "send_envelope without a kind must still succeed: {resp}"
    );

    let resp = pickup_envelope(&mut stream, recipient_id, None).await;
    assert_eq!(
        resp["ok"], true,
        "pickup_envelope without a kind must still return the envelope: {resp}"
    );
    assert_eq!(
        envelope_bytes(&resp),
        envelope,
        "a kind-less envelope must not be skipped"
    );
}

/// A kind-less envelope must also fall through to a kind-filtered pickup: the
/// receiving loop then falls through to its own decrypt rather than skipping.
#[tokio::test]
async fn missing_kind_falls_through_to_a_kind_filtered_pickup() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "kind-missing-filtered";
    let envelope = vec![0x77u8; 8];

    let resp = send_envelope(&mut stream, recipient_id, &envelope, None).await;
    assert_eq!(resp["ok"], true, "send_envelope must succeed: {resp}");

    let resp = pickup_envelope(&mut stream, recipient_id, Some("direct")).await;
    assert_eq!(
        resp["ok"], true,
        "an untagged envelope must fall through to the polling loop, not be skipped: {resp}"
    );
    assert_eq!(envelope_bytes(&resp), envelope, "the untagged envelope must be delivered intact");
}

/// Cross-recipient collision regression (GRP-6 rework): sender-keys fan-out
/// sends ONE ciphertext to every group member, so every member's mailbox row
/// holds the SAME envelope bytes. The kind tag must therefore be keyed by
/// (recipient_id, envelope bytes), not by the bytes alone — otherwise the
/// first member's delivery removes the tag every other member's row still
/// needs, those rows go untagged, and `tag.is_none()` hands the group
/// envelope to ANY polling loop (a direct loop cannot decrypt it, and the
/// relay has already destructively dequeued it — the message is lost).
///
/// Two recipients, identical envelope bytes, kind "group": A's group poll
/// delivers and removes only A's tag; B's DIRECT poll must NOT receive the
/// envelope, and B's GROUP poll must.
#[tokio::test]
async fn same_envelope_for_two_recipients_keeps_each_recipients_tag() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_a = "kind-fanout-a";
    let recipient_b = "kind-fanout-b";
    // Identical bytes to both recipients — the sender-keys fan-out shape.
    let envelope = vec![0xC1u8; 48];

    let resp = send_envelope(&mut stream, recipient_a, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send to A must succeed: {resp}");
    let resp = send_envelope(&mut stream, recipient_b, &envelope, Some("group")).await;
    assert_eq!(resp["ok"], true, "send to B must succeed: {resp}");

    // A's group loop picks up its copy. Pre-fix this removed the single
    // content-keyed tag that B's row also pointed at.
    let resp = pickup_envelope(&mut stream, recipient_a, Some("group")).await;
    assert_eq!(resp["ok"], true, "A's group poll must deliver: {resp}");
    assert_eq!(envelope_bytes(&resp), envelope, "A must receive the envelope intact");

    // B's DIRECT poll must not receive (or destroy) the group envelope.
    let resp = pickup_envelope(&mut stream, recipient_b, Some("direct")).await;
    assert_eq!(
        resp["ok"], false,
        "B's direct poll must not consume the group envelope after A's delivery: {resp}"
    );
    assert_eq!(
        resp["error"], "NotFound",
        "B's direct poll must report NotFound, not an error that discards it: {resp}"
    );

    // B's GROUP poll must still deliver it.
    let resp = pickup_envelope(&mut stream, recipient_b, Some("group")).await;
    assert_eq!(
        resp["ok"], true,
        "B's group poll must still deliver after A's copy was taken: {resp}"
    );
    assert_eq!(envelope_bytes(&resp), envelope, "B must receive the envelope intact");
}
