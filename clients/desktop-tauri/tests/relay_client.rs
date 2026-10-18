//! DT-2: native WebSocket relay client (`clients_desktop_tauri::relay_client`).
//!
//! Public interface these tests pin (all methods are `async`):
//! - `RelayClient::connect(url: &str) -> Result<RelayClient, RelayError>`
//! - `publish_prekey(&mut self, recipient_id: &str, bundle: &[u8]) -> Result<(), RelayError>`
//! - `lookup_prekey(&mut self, recipient_id: &str) -> Result<Vec<u8>, RelayError>`
//! - `send_envelope(&mut self, recipient_id: &str, envelope: &[u8], kind: Option<EnvelopeKind>) -> Result<(), RelayError>`
//! - `pickup_envelope(&mut self, recipient_id: &str, kind: Option<EnvelopeKind>) -> Result<Envelope, RelayError>`
//! - `Envelope { pub bytes: Vec<u8>, pub kind: Option<EnvelopeKind> }`
//! - `EnvelopeKind::{Direct, Group}` (wire strings "direct" / "group")
//! - `RelayError::{NotFound, Expired, QueueFull, PowFailed(String), Unreachable(String), ConnectionClosed, ..}`
//!   (relay `{"ok":false,"error":"PowFailed: ..."}` -> `PowFailed`; connect failure -> `Unreachable`;
//!   stream ended / closed mid-request -> `ConnectionClosed`.)
//! The client fetches and solves the relay's PoW challenge itself (`challenge` op) before
//! `publish_prekey` / `send_envelope`.

use std::net::SocketAddr;
use std::time::Duration;

use clients_desktop_tauri::relay_client::{Envelope, EnvelopeKind, RelayClient, RelayError};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const STEP: Duration = Duration::from_secs(120);

async fn connect(addr: SocketAddr) -> RelayClient {
    RelayClient::connect(&format!("ws://{addr}")).await.expect("connect to relay")
}

/// Scripted relay: answers `challenge` with a difficulty-0 challenge, and every other op with
/// `reply` (or closes the socket when `reply` is None).
async fn fake_relay(reply: Option<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let req: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let resp = match (req["op"].as_str().unwrap(), reply) {
                        ("challenge", Some(_)) => {
                            // wire: ctx_len(2 BE) || ctx || nonce(16) || difficulty(4 BE)
                            let mut wire = vec![0u8, 1, b'x'];
                            wire.extend_from_slice(&[7u8; 16]);
                            wire.extend_from_slice(&0u32.to_be_bytes());
                            let b64 = relay::ws::b64_encode(&wire);
                            serde_json::json!({"ok":true,"challenge_id":"07070707070707070707070707070707","challenge":b64})
                        }
                        (_, Some(err)) => serde_json::json!({"ok":false,"error":err}),
                        (_, None) => return,
                    };
                    ws.send(Message::Text(resp.to_string().into())).await.unwrap();
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn should_publish_look_up_send_and_pick_up_against_real_relay() {
    let relay = relay::ws::start_ws_listener_for_test(60).await;
    let mut client = connect(relay.addr).await;

    tokio::time::timeout(STEP, client.publish_prekey("alice", b"prekey-bundle")).await.unwrap().unwrap();
    let bundle = client.lookup_prekey("alice").await.unwrap();
    assert_eq!(bundle, b"prekey-bundle");

    tokio::time::timeout(STEP, client.send_envelope("alice", b"ciphertext", None)).await.unwrap().unwrap();
    let got = client.pickup_envelope("alice", None).await.unwrap();
    assert_eq!(got, Envelope { bytes: b"ciphertext".to_vec(), kind: None });
}

#[tokio::test]
async fn should_round_trip_the_kind_tag_as_a_sibling_field() {
    let relay = relay::ws::start_ws_listener_for_test(60).await;
    let mut client = connect(relay.addr).await;

    tokio::time::timeout(STEP, client.send_envelope("bob", b"grp", Some(EnvelopeKind::Group))).await.unwrap().unwrap();
    let got = client.pickup_envelope("bob", Some(EnvelopeKind::Group)).await.unwrap();

    assert_eq!(got.bytes, b"grp");
    assert_eq!(got.kind, Some(EnvelopeKind::Group));
}

#[tokio::test]
async fn should_report_not_found_for_unknown_prekey() {
    let relay = relay::ws::start_ws_listener_for_test(60).await;
    let mut client = connect(relay.addr).await;

    let err = client.lookup_prekey("nobody").await.unwrap_err();

    assert!(matches!(err, RelayError::NotFound), "got {err:?}");
}

#[tokio::test]
async fn should_report_not_found_for_empty_mailbox_without_hanging() {
    let relay = relay::ws::start_ws_listener_for_test(60).await;
    let mut client = connect(relay.addr).await;

    let result = tokio::time::timeout(Duration::from_secs(10), client.pickup_envelope("empty", None))
        .await
        .expect("pickup from an empty mailbox must not hang");

    assert!(matches!(result, Err(RelayError::NotFound)), "got {result:?}");
}

#[tokio::test]
async fn should_not_deliver_an_expired_envelope() {
    let relay = relay::ws::start_ws_listener_for_test_with_ttl(60, Duration::from_millis(50)).await;
    let mut client = connect(relay.addr).await;
    tokio::time::timeout(STEP, client.send_envelope("carol", b"stale", None)).await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let result = client.pickup_envelope("carol", None).await;

    assert!(matches!(result, Err(RelayError::Expired) | Err(RelayError::NotFound)), "got {result:?}");
}

#[tokio::test]
async fn should_map_a_pow_rejection_to_pow_failed() {
    let addr = fake_relay(Some("PowFailed: bad solution")).await;
    let mut client = connect(addr).await;

    let err = client.send_envelope("dave", b"x", None).await.unwrap_err();

    assert!(matches!(err, RelayError::PowFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn should_map_queue_full() {
    let addr = fake_relay(Some("QueueFull")).await;
    let mut client = connect(addr).await;

    let err = client.send_envelope("erin", b"x", None).await.unwrap_err();

    assert!(matches!(err, RelayError::QueueFull), "got {err:?}");
}

#[tokio::test]
async fn should_map_expired_on_pickup() {
    let addr = fake_relay(Some("Expired")).await;
    let mut client = connect(addr).await;

    let err = client.pickup_envelope("frank", None).await.unwrap_err();

    assert!(matches!(err, RelayError::Expired), "got {err:?}");
}

#[tokio::test]
async fn should_surface_unreachable_relay_on_connect() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);

    let result = RelayClient::connect(&format!("ws://{addr}")).await;

    assert!(matches!(result, Err(RelayError::Unreachable(_))));
}

#[tokio::test]
async fn should_not_silently_swallow_a_send_when_the_relay_drops_mid_session() {
    let addr = fake_relay(None).await;
    let mut client = connect(addr).await;

    let result = tokio::time::timeout(Duration::from_secs(10), client.send_envelope("gina", b"x", None))
        .await
        .expect("send must fail, not hang");

    assert!(matches!(result, Err(RelayError::ConnectionClosed)), "got {result:?}");
}
