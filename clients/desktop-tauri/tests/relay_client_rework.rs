//! DT-2 rework regression tests (additive; `tests/relay_client.rs` is untouched).
//!
//! DEFECT 1 — a timed-out request desyncs the connection: once a round trip
//! exceeds its bound, the client must be poisoned — socket closed, and every
//! later op returns `ConnectionClosed` immediately — so the previous op's late
//! reply can never be consumed as the next op's response.
//!
//! DEFECT 2 — unbounded relay-controlled PoW work: a challenge whose
//! difficulty exceeds the client's cap (28) must be rejected with `Protocol`
//! before any hashing, and the solve must run off the async executor.

use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clients_desktop_tauri::relay_client::{parse_challenge_wire, RelayClient, RelayError};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

type WsStream = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// The client's round-trip bound in these tests.
const CLIENT_BOUND: Duration = Duration::from_millis(300);
/// Outer bound so a broken client fails the test instead of hanging it.
const STEP: Duration = Duration::from_secs(10);

/// Read the next text frame, or `None` when the stream ends.
async fn next_text(ws: &mut WsStream) -> Option<String> {
    match ws.next().await {
        Some(Ok(Message::Text(text))) => Some(text.to_string()),
        _ => None,
    }
}

/// Build a challenge wire frame:
/// `ctx_len(2 BE) || ctx || nonce(16) || difficulty(4 BE)`.
fn challenge_wire(difficulty: u32) -> Vec<u8> {
    let mut wire = vec![0u8, 1, b'x'];
    wire.extend_from_slice(&[7u8; 16]);
    wire.extend_from_slice(&difficulty.to_be_bytes());
    wire
}

/// Scripted relay for the desync test: accepts ONE connection, withholds
/// request 1's reply indefinitely (so op 1 times out at the client's bound),
/// then — the moment request 2 arrives — sends the STALE reply to request 1.
///
/// Timing-independent by construction: the stale frame is guaranteed to be in
/// flight when op 2 reads. Pre-fix, op 2 consumes it as its own response and
/// returns `Ok(Envelope { bytes: "late-1" })` — the desync under test.
/// Post-fix, the client is poisoned: op 2 is `Err(ConnectionClosed)` and
/// request 2 never reaches the wire, so the relay's second branch never runs.
async fn late_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();

        // Request 1: never answered within the client's bound.
        let _req1 = next_text(&mut ws).await;

        // Request 2 arrives only if the client is NOT poisoned. Answer it
        // with the STALE reply to request 1 — exactly what a relay that
        // answers late produces on the wire.
        if let Some(req2) = next_text(&mut ws).await {
            let req: serde_json::Value = serde_json::from_str(&req2).unwrap();
            assert_eq!(req["op"], "pickup_envelope", "unexpected second op: {req}");
            let stale = serde_json::json!({ "ok": true, "envelope": B64.encode(b"late-1") });
            let _ = ws.send(Message::Text(stale.to_string().into())).await;
            // Keep the socket open a moment so the frame is deliverable.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    addr
}

/// DEFECT 1: after op 1 times out, op 2 on the same client must be
/// `ConnectionClosed` — never the late reply to op 1.
#[tokio::test]
async fn should_poison_the_client_after_a_timed_out_request() {
    let addr = late_relay().await;
    let mut client = RelayClient::connect_with_timeout(&format!("ws://{addr}"), CLIENT_BOUND)
        .await
        .expect("connect to scripted relay");

    // Op 1: the relay holds its reply past the bound -> fail closed.
    let op1 = tokio::time::timeout(STEP, client.pickup_envelope("r", None))
        .await
        .expect("op 1 must not hang");
    assert!(
        matches!(op1, Err(RelayError::ConnectionClosed)),
        "op 1: got {op1:?}"
    );

    // Op 2 on the SAME client: the relay now sends the stale reply to op 1.
    // The client must be poisoned — Err(ConnectionClosed), never the stale
    // reply, and never a hang waiting for a reply that will never come.
    let op2 = tokio::time::timeout(STEP, client.pickup_envelope("r", None))
        .await
        .expect("op 2 must not hang");
    assert!(
        matches!(op2, Err(RelayError::ConnectionClosed)),
        "op 2 must be poisoned after op 1 timed out; got {op2:?} (a stale reply to op 1)"
    );
}

/// Scripted relay that answers each `challenge` op with the next difficulty
/// from `difficulties` (it never solves anything itself).
async fn difficulty_relay(difficulties: Vec<u32>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let mut issued = 0usize;
        while let Some(text) = next_text(&mut ws).await {
            let req: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(req["op"], "challenge", "unexpected op: {req}");
            let difficulty = difficulties[issued];
            issued += 1;
            let resp = serde_json::json!({
                "ok": true,
                "challenge_id": format!("chal-{issued}"),
                "challenge": B64.encode(challenge_wire(difficulty)),
            });
            ws.send(Message::Text(resp.to_string().into()))
                .await
                .unwrap();
        }
    });
    addr
}

/// DEFECT 2(a): a challenge above the cap must be rejected with `Protocol`
/// promptly — before any hashing — for difficulty 29 and for 256.
#[tokio::test]
async fn should_reject_challenges_above_max_pow_difficulty_promptly() {
    let addr = difficulty_relay(vec![29, 256]).await;
    let mut client = RelayClient::connect(&format!("ws://{addr}")).await.unwrap();

    let op1 = tokio::time::timeout(STEP, client.send_envelope("r", b"x", None))
        .await
        .expect("difficulty 29 must be rejected promptly, not solved");
    assert!(
        matches!(op1, Err(RelayError::Protocol(_))),
        "difficulty 29: got {op1:?}"
    );

    // The rejection leaves the connection usable: op 2 is issued the next
    // challenge (difficulty 256) and is rejected the same way.
    let op2 = tokio::time::timeout(STEP, client.send_envelope("r", b"x", None))
        .await
        .expect("difficulty 256 must be rejected promptly, not solved");
    assert!(
        matches!(op2, Err(RelayError::Protocol(_))),
        "difficulty 256: got {op2:?}"
    );
}

/// DEFECT 2(b): the parser accepts the 28-bit cap and rejects one bit past it
/// (and the old accept-anything ceiling of 256) — asserted on
/// `parse_challenge_wire` directly, so no solving happens here.
#[test]
fn should_accept_difficulty_28_at_the_parser_boundary_and_reject_above_it() {
    let (preimage, difficulty) = parse_challenge_wire(&challenge_wire(28))
        .expect("difficulty 28 is the documented cap and must parse");
    assert_eq!(difficulty, 28);
    assert_eq!(
        preimage,
        vec![b'x', 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]
    );

    for above_cap in [29u32, 256] {
        let err = parse_challenge_wire(&challenge_wire(above_cap))
            .expect_err("difficulty above the cap must be rejected before any hashing");
        assert!(
            matches!(err, RelayError::Protocol(_)),
            "difficulty {above_cap}: got {err:?}"
        );
    }
}
