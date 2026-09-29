//! GRP-6 FIX 4 — the out-of-band `kind` tag is ALLOW-LISTED.
//!
//! `kind` is non-content routing metadata, but an unbounded, unvalidated
//! string would let a client grow the relay's kind map with arbitrary values.
//! Only `"direct"`, `"group"`, or an absent field is accepted; anything else
//! is rejected at send_envelope with the distinct wire body `InvalidKind`,
//! BEFORE the rate-limit and PoW gates (no challenge consumed, no PoW CPU
//! burned, no state changed), and the envelope is NOT queued.
//!
//! A rejected send must leave the mailbox untouched: a following unfiltered
//! pickup still reports NotFound.

use futures::{SinkExt, StreamExt};
use relay::ws;
use serde_json::Value;
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

// ── tests ────────────────────────────────────────────────────────────────────

/// The two known kinds (and an absent kind) are accepted.
#[tokio::test]
async fn allow_listed_kinds_are_accepted() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    for kind in ["direct", "group"] {
        let recipient_id = format!("allow-ok-{kind}");
        let envelope = vec![0x21u8; 16];
        let resp = send_envelope(&mut stream, &recipient_id, &envelope, Some(kind)).await;
        assert_eq!(
            resp["ok"], true,
            "send_envelope with kind \"{kind}\" must be accepted: {resp}"
        );
    }

    // An absent kind is still accepted (untagged envelopes fall through).
    let envelope = vec![0x22u8; 16];
    let resp = send_envelope(&mut stream, "allow-ok-absent", &envelope, None).await;
    assert_eq!(resp["ok"], true, "send_envelope without a kind must be accepted: {resp}");
}

/// Anything outside the allow-list is rejected with the distinct `InvalidKind`
/// body and the envelope is NOT queued.
#[tokio::test]
async fn unlisted_kinds_are_rejected_with_invalid_kind() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    for bogus in ["bogus", "DIRECT", "", "group "] {
        let recipient_id = "allow-reject";
        let envelope = vec![0x33u8; 16];
        let resp = send_envelope(&mut stream, recipient_id, &envelope, Some(bogus)).await;
        assert_eq!(
            resp["ok"], false,
            "send_envelope with kind \"{bogus}\" must be rejected: {resp}"
        );
        assert_eq!(
            resp["error"], "InvalidKind",
            "the rejection must carry the distinct InvalidKind body: {resp}"
        );
    }

    // The mailbox is unchanged: nothing was queued by any rejected send.
    let resp = pickup_envelope(&mut stream, "allow-reject", None).await;
    assert_eq!(
        resp["ok"], false,
        "the mailbox must be untouched after rejected sends: {resp}"
    );
    assert_eq!(resp["error"], "NotFound", "no envelope may have been queued: {resp}");
}

/// An invalid kind fails fast: it must not consume a PoW challenge. A send
/// that reuses the challenge the INVALID send already consumed still works
/// (the invalid kind was rejected before the PoW gate ever saw it).
#[tokio::test]
async fn invalid_kind_is_rejected_before_the_pow_gate() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "allow-fastfail";
    let (challenge_id, pow_solution) = solve_challenge(&mut stream, recipient_id).await;

    // First: an invalid kind with a VALID solution must be rejected with
    // InvalidKind — and must NOT burn the solution.
    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": ws::b64_encode(&[0x44u8; 8]),
        "kind": "bogus",
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "an invalid kind must be rejected: {resp}");
    assert_eq!(resp["error"], "InvalidKind", "the body must be InvalidKind: {resp}");

    // The same challenge/solution is still spendable on a VALID kind: the
    // InvalidKind check ran before the PoW gate and consumed nothing.
    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": ws::b64_encode(&[0x45u8; 8]),
        "kind": "direct",
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(
        resp["ok"], true,
        "the invalid-kind rejection must not have consumed the PoW solution: {resp}"
    );
}