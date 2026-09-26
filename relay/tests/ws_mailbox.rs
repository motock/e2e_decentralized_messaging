//! WebSocket relay bridge: mailbox (FIFO envelope queue) integration tests.
//!
//! The WS `send_envelope` op must queue envelopes FIFO per recipient so that an
//! offline recipient's messages are retained in arrival order, and `pickup_envelope`
//! must return and remove the OLDEST envelope, one per call, until the queue is
//! drained (`NotFound`).
//!
//! These tests exercise the public WS wire protocol only — they connect to the
//! listener, solve the PoW challenge, and assert on the JSON responses.
//!
//! ## Required positive/boundary cases
//!
//! - Two envelopes sent to one offline recipient are returned in send order, and a
//!   third pickup reports `NotFound` (the queue is drained, not overwritten).
//! - Two different recipients do not observe each other's envelopes.
//! - Picking up for a recipient that never received anything reports `NotFound`.

use futures::{SinkExt, StreamExt};
use relay::ws;
use serde_json::Value;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ── helpers (mirrors relay/tests/ws_bridge.rs; test files cannot import each other) ──

/// Connect to the WS listener and return the stream.
async fn ws_connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}");
    let (stream, _response) = connect_async(url).await.expect("ws connect must succeed");
    stream
}

/// Send a JSON request and return the JSON response.
async fn ws_round_trip(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    req: Value,
) -> Value {
    stream
        .send(Message::Text(req.to_string().into()))
        .await
        .expect("send must succeed");
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).expect("response must be valid JSON")
            }
            Some(Ok(_)) => continue, // skip non-text frames
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws stream closed before response"),
        }
    }
}

/// Request a PoW challenge, solve it, and return `(challenge_id, pow_solution)`.
async fn solve_challenge(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    recipient_id: &str,
) -> (String, String) {
    let req = serde_json::json!({
        "op": "challenge",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(stream, req).await;
    assert_eq!(resp["ok"], true, "challenge request must succeed");
    let challenge_b64 = resp["challenge"].as_str().expect("challenge field");
    let challenge_id = resp["challenge_id"]
        .as_str()
        .expect("challenge_id field")
        .to_string();

    // Wire format: context_len(2 BE) || context || nonce(16) || difficulty(4 BE)
    let challenge_wire = ws::b64_decode(challenge_b64).expect("challenge wire decode");
    let context_len = u16::from_be_bytes([challenge_wire[0], challenge_wire[1]]) as usize;
    let nonce = &challenge_wire[2 + context_len..2 + context_len + 16];
    let difficulty = u32::from_be_bytes([
        challenge_wire[2 + context_len + 16],
        challenge_wire[2 + context_len + 16 + 1],
        challenge_wire[2 + context_len + 16 + 2],
        challenge_wire[2 + context_len + 16 + 3],
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

/// Check if a PoW solution meets the difficulty (mirrors pow::meets_difficulty).
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

/// Solve PoW and send one envelope; asserts the send succeeded.
async fn send_envelope(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    recipient_id: &str,
    envelope: &[u8],
) {
    let (challenge_id, pow_solution) = solve_challenge(stream, recipient_id).await;
    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": ws::b64_encode(envelope),
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
    });
    let resp = ws_round_trip(stream, req).await;
    assert_eq!(resp["ok"], true, "send_envelope must succeed: {resp}");
}

/// Pick up one envelope and return the raw response JSON.
async fn pickup_envelope(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    recipient_id: &str,
) -> Value {
    let req = serde_json::json!({
        "op": "pickup_envelope",
        "recipient_id": recipient_id,
    });
    ws_round_trip(stream, req).await
}

/// Assert a pickup response carries the expected envelope bytes.
fn assert_pickup_ok(resp: &Value, expected: &[u8], context: &str) {
    assert_eq!(resp["ok"], true, "{context}: pickup must succeed: {resp}");
    let fetched_b64 = resp["envelope"].as_str().expect("envelope field");
    let fetched = ws::b64_decode(fetched_b64).expect("envelope must be valid base64");
    assert_eq!(fetched, expected, "{context}: envelope payload mismatch");
}

/// Assert a pickup response reports the expected error string.
fn assert_pickup_err(resp: &Value, expected_error: &str, context: &str) {
    assert_eq!(resp["ok"], false, "{context}: pickup must fail: {resp}");
    assert_eq!(
        resp["error"].as_str().unwrap_or(""),
        expected_error,
        "{context}: unexpected error, got: {resp}"
    );
}

// ── positive tests ───────────────────────────────────────────────────────────

/// Two envelopes sent to one offline recipient come back in send order, then the
/// queue is empty — the second send must not overwrite the first.
#[tokio::test]
async fn fifo_order_and_drain() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "mailbox-fifo-recipient";
    let first = vec![0xAAu8; 32];
    let second = vec![0xBBu8; 32];

    send_envelope(&mut stream, recipient_id, &first).await;
    send_envelope(&mut stream, recipient_id, &second).await;

    let resp = pickup_envelope(&mut stream, recipient_id).await;
    assert_pickup_ok(&resp, &first, "first pickup");

    let resp = pickup_envelope(&mut stream, recipient_id).await;
    assert_pickup_ok(&resp, &second, "second pickup");

    let resp = pickup_envelope(&mut stream, recipient_id).await;
    assert_pickup_err(&resp, "NotFound", "third pickup (drained)");
}

/// Envelopes queued for one recipient are not visible to another recipient.
#[tokio::test]
async fn recipients_are_isolated() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let r1 = "mailbox-isolation-r1";
    let r2 = "mailbox-isolation-r2";
    let r1_envelope = vec![0x11u8; 32];
    let r2_envelope = vec![0x22u8; 32];

    send_envelope(&mut stream, r1, &r1_envelope).await;
    send_envelope(&mut stream, r2, &r2_envelope).await;

    let resp = pickup_envelope(&mut stream, r1).await;
    assert_pickup_ok(&resp, &r1_envelope, "r1 pickup");

    let resp = pickup_envelope(&mut stream, r2).await;
    assert_pickup_ok(&resp, &r2_envelope, "r2 pickup");

    // Both queues are now drained.
    let resp = pickup_envelope(&mut stream, r1).await;
    assert_pickup_err(&resp, "NotFound", "r1 drained");
    let resp = pickup_envelope(&mut stream, r2).await;
    assert_pickup_err(&resp, "NotFound", "r2 drained");
}

// ── negative / boundary tests ────────────────────────────────────────────────

/// Picking up for a recipient that never received anything reports NotFound.
///
/// This is a regression guard: it holds both before and after the mailbox change.
#[tokio::test]
async fn pickup_never_received_is_not_found() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let resp = pickup_envelope(&mut stream, "mailbox-never-received").await;
    assert_pickup_err(&resp, "NotFound", "fresh recipient");
}
