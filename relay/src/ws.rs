//! WebSocket bridge for browser clients.
//!
//! Browsers cannot open raw TCP/QUIC sockets or run the Kademlia DHT / Circuit Relay v2
//! libp2p stack the native clients use (`core/transport/src/{dht.rs, online.rs}`). This
//! module adds a **parallel** WebSocket listener to the self-hostable relay that shares
//! its existing proof-of-work / rate-limit gates (`pow`, `ratelimit`) and uses
//! `store::Mailbox` for store-and-forward envelope handling (`store::RelayStore` for
//! prekey bundles, which are last-write-wins by design).
//!
//! ## Design decision (solution-architect sign-off)
//!
//! The WS listener is a **parallel ingress path**, not a replacement for the libp2p
//! transport. Both paths share the same `pow::verify` and `ratelimit::RateLimiter`
//! gates — the WS path does **not** create a second, weaker ingress. A browser client
//! must solve the same PoW challenge and is subject to the same per-identity rate limit
//! before any store/pickup operation is accepted. Envelopes are queued in
//! `store::Mailbox` (FIFO per recipient); prekey bundles stay in `store::RelayStore`.
//!
//! ## Wire protocol
//!
//! All messages are JSON text frames. Each request is a JSON object with a `op` field:
//!
//! - `{"op":"publish_prekey","recipient_id":"...","bundle":"<base64>","challenge_id":"<hex>","pow_solution":"<base64>"}`
//!   → `{"ok":true}` or `{"ok":false,"error":"..."}`
//! - `{"op":"lookup_prekey","recipient_id":"..."}`
//!   → `{"ok":true,"bundle":"<base64>"}` or `{"ok":false,"error":"NotFound"}`
//! - `{"op":"send_envelope","recipient_id":"...","envelope":"<base64>","challenge_id":"<hex>","pow_solution":"<base64>"}`
//!   → `{"ok":true}` or `{"ok":false,"error":"..."}`. Envelopes are queued FIFO per
//!   recipient, up to a per-recipient cap; when the cap is reached the send is rejected
//!   with `{"ok":false,"error":"QueueFull"}` and queued envelopes are never dropped to
//!   make room.
//! - `{"op":"pickup_envelope","recipient_id":"..."}`
//!   → `{"ok":true,"envelope":"<base64>"}` or `{"ok":false,"error":"NotFound|Expired"}`.
//!   Returns and removes the OLDEST queued envelope, one per call; `NotFound` when the
//!   queue is empty, and `Expired` once when only expired envelopes remained (they are
//!   discarded, so the next call reports `NotFound`).
//!
//! The PoW challenge is issued out-of-band: the relay exposes a `challenge` op that
//! returns the challenge wire bytes (see `pow::Challenge::to_wire`). The browser solves
//! it and includes the solution as `pow_solution` (base64 of solution bytes) along
//! with the `challenge_id` (hex of the challenge nonce) in publish/send requests.
//!
//! ## Security
//!
//! - **Fail closed**: any parse error, PoW failure, or rate-limit violation returns an
//!   error response and does NOT perform the requested operation.
//! - **Same gates**: PoW and rate-limit checks are identical to the libp2p path.
//! - **Blind relay**: the relay never decrypts or inspects envelope/prekey contents —
//!   they are opaque base64 blobs at this layer.
//! - **Data minimization**: no envelope or bundle contents are logged.
//! - **Audit logging**: PoW failures and rate-limit violations are logged at WARN level
//!   with the operation and a truncated recipient_id (first 8 chars), never the payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

use crate::pow::{self, Challenge, PowError};
use crate::ratelimit::{RateLimitError, RateLimiter};
use crate::store::{
    Mailbox, MailboxError, RelayStore, StoreError, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT,
};

/// Default TTL for stored prekey bundles (24h).
const DEFAULT_PREKEY_TTL: Duration = Duration::from_secs(86400);
/// Default TTL for stored Sealed Sender envelopes (7 days).
const DEFAULT_ENVELOPE_TTL: Duration = Duration::from_secs(7 * 86400);
/// PoW difficulty for browser-facing requests (20 bits — same as the libp2p path).
const POW_DIFFICULTY: u32 = 20;
/// PoW context string (binds solutions to this relay's WS path).
const POW_CONTEXT: &[u8] = b"ws-relay-v1";

/// Shared state for the WS listener: the store, rate limiter, and active PoW challenges.
struct WsState {
    store: Mailbox,
    /// Prekey bundles are stored separately from envelopes so lookup_prekey doesn't
    /// collide with pickup_envelope. We use a second RelayStore keyed by a prefix.
    prekeys: RelayStore,
    rate_limiter: Mutex<RateLimiter>,
    /// Currently active PoW challenges, keyed by a challenge ID (the nonce hex).
    challenges: Mutex<std::collections::HashMap<String, Challenge>>,
}

impl WsState {
    fn new(rate_limit_per_minute: u32) -> Self {
        Self {
            store: Mailbox::new(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT),
            prekeys: RelayStore::new(),
            rate_limiter: Mutex::new(RateLimiter::per_identity(rate_limit_per_minute)),
            challenges: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

/// Request frame: all operations share this envelope.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum WsRequest {
    #[serde(rename = "challenge")]
    Challenge { recipient_id: String },
    #[serde(rename = "publish_prekey")]
    PublishPrekey {
        recipient_id: String,
        bundle: String,       // base64
        challenge_id: String, // hex of challenge nonce
        pow_solution: String, // base64 of solution bytes
    },
    #[serde(rename = "lookup_prekey")]
    LookupPrekey { recipient_id: String },
    #[serde(rename = "send_envelope")]
    SendEnvelope {
        recipient_id: String,
        envelope: String,     // base64
        challenge_id: String, // hex of challenge nonce
        pow_solution: String, // base64 of solution bytes
    },
    #[serde(rename = "pickup_envelope")]
    PickupEnvelope { recipient_id: String },
}

/// Response frame: success or error.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WsResponse {
    Ok {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        bundle: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        envelope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge: Option<String>, // base64 of Challenge::to_wire()
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge_id: Option<String>,
    },
    Err {
        ok: bool,
        error: String,
    },
}

impl WsResponse {
    fn ok_simple() -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: None,
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_bundle(bundle: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: Some(bundle),
            envelope: None,
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_envelope(envelope: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: Some(envelope),
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_challenge(challenge_id: String, challenge: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: None,
            challenge: Some(challenge),
            challenge_id: Some(challenge_id),
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        WsResponse::Err {
            ok: false,
            error: msg.into(),
        }
    }
}

/// Decode a base64 string into bytes. Uses standard base64 (with padding).
///
/// **Security**: invalid characters are rejected (not silently skipped). This
/// prevents malformed or malicious input from decoding to unexpected bytes that
/// could bypass downstream validation.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let lookup = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    // Strip whitespace (newlines, spaces, carriage returns) which is valid per RFC 2045.
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Reject invalid characters upfront — do NOT silently skip them.
    for &b in &bytes {
        if b != b'=' && lookup(b).is_none() {
            return Err(format!("invalid base64 character: 0x{b:02X}"));
        }
    }
    // Validate padding: '=' only allowed at the end, and at most 2.
    let non_pad_len = bytes.iter().take_while(|&&b| b != b'=').count();
    let pad_count = bytes.len() - non_pad_len;
    if pad_count > 2 {
        return Err("invalid base64: more than 2 padding characters".to_string());
    }
    // Length must be a multiple of 4 (with padding).
    if !bytes.len().is_multiple_of(4) {
        return Err(format!(
            "invalid base64 length: {} (must be multiple of 4)",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut iter = bytes.iter().peekable();
    while iter.peek().is_some() {
        let mut vals: [Option<u8>; 4] = [None; 4];
        for slot in vals.iter_mut() {
            *slot = iter
                .next()
                .and_then(|&c| if c == b'=' { None } else { lookup(c) });
        }
        let n = vals.iter().filter(|v| v.is_some()).count();
        if n == 0 {
            break;
        }
        let v0 = vals[0].unwrap_or(0);
        let v1 = vals[1].unwrap_or(0);
        let v2 = vals[2].unwrap_or(0);
        let v3 = vals[3].unwrap_or(0);
        out.push((v0 << 2) | (v1 >> 4));
        if vals[2].is_some() {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if vals[3].is_some() {
            out.push((v2 << 6) | v3);
        }
        if n < 4 {
            break;
        }
    }
    Ok(out)
}

/// Encode bytes to a base64 string (standard, with padding).
pub fn b64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 << 4) & 0x30 | b1 >> 4) as usize] as char);
        if i + 1 < data.len() {
            out.push(ALPHABET[((b1 << 2) & 0x3C | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Truncate a recipient_id for logging (data minimization — never log full identifiers).
fn truncate_id(id: &str) -> String {
    if id.len() <= 8 {
        id.to_string()
    } else {
        format!("{}…", &id[..8])
    }
}

/// Map a [`MailboxError`] from `enqueue` to a WS error response.
///
/// A full queue is a distinct, non-retryable condition for the sender, so it gets
/// its own error string rather than being folded into the generic `StoreError` form.
fn mailbox_send_error_response(e: MailboxError) -> WsResponse {
    match e {
        MailboxError::QueueFull => WsResponse::err("QueueFull"),
        // NotFound/Expired are unreachable from enqueue; kept for exhaustiveness.
        other => WsResponse::err(format!("StoreError: {other:?}")),
    }
}

/// Handle a single WS request against the shared state.
///
/// This is the security-critical path: PoW and rate-limit gates are enforced here
/// before any store/pickup operation. Failures return an error response and do NOT
/// perform the requested operation (fail closed / deny by default).
async fn handle_request(req: WsRequest, state: &Arc<WsState>) -> WsResponse {
    // Rate-limit identity: use the recipient_id as the identity key. This is the
    // same per-identity model as the libp2p path.
    let now = Duration::from_secs(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    match req {
        WsRequest::Challenge { recipient_id } => {
            // Issue a PoW challenge. This op itself is rate-limited to prevent
            // challenge-flooding DoS.
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) = rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on challenge request"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }

            let challenge = Challenge::new(POW_CONTEXT, POW_DIFFICULTY);
            let challenge_id = hex::encode(challenge.nonce());
            let wire = challenge.to_wire();
            state
                .challenges
                .lock()
                .await
                .insert(challenge_id.clone(), challenge);
            WsResponse::ok_challenge(challenge_id, b64_encode(&wire))
        }

        WsRequest::PublishPrekey {
            recipient_id,
            bundle,
            challenge_id,
            pow_solution,
        } => {
            // 1. Rate limit
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) = rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on publish_prekey"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            // 2. PoW verification
            if let Err(e) = verify_pow(&challenge_id, &pow_solution, state).await {
                warn!(
                    recipient = %truncate_id(&recipient_id),
                    "ws: pow failed on publish_prekey: {e}"
                );
                return WsResponse::err(format!("PowFailed: {e}"));
            }
            // 3. Store the prekey bundle
            let bundle_bytes = match b64_decode(&bundle) {
                Ok(b) => b,
                Err(e) => return WsResponse::err(format!("InvalidBase64: {e}")),
            };
            let prekey_key = format!("prekey:{recipient_id}");
            if let Err(e) = state
                .prekeys
                .store(&prekey_key, bundle_bytes, DEFAULT_PREKEY_TTL)
            {
                return WsResponse::err(format!("StoreError: {e:?}"));
            }
            info!(recipient = %truncate_id(&recipient_id), "ws: prekey published");
            WsResponse::ok_simple()
        }

        WsRequest::LookupPrekey { recipient_id } => {
            // Lookup is a read — rate-limited but no PoW required (reading a public
            // prekey bundle is not a resource-intensive operation).
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) = rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on lookup_prekey"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            let prekey_key = format!("prekey:{recipient_id}");
            match state.prekeys.pickup(&prekey_key) {
                Ok(bundle_bytes) => WsResponse::ok_bundle(b64_encode(&bundle_bytes)),
                Err(StoreError::NotFound) => WsResponse::err("NotFound"),
                Err(StoreError::Expired) => WsResponse::err("Expired"),
            }
        }

        WsRequest::SendEnvelope {
            recipient_id,
            envelope,
            challenge_id,
            pow_solution,
        } => {
            // 1. Rate limit
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) = rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on send_envelope"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            // 2. PoW verification
            if let Err(e) = verify_pow(&challenge_id, &pow_solution, state).await {
                warn!(
                    recipient = %truncate_id(&recipient_id),
                    "ws: pow failed on send_envelope: {e}"
                );
                return WsResponse::err(format!("PowFailed: {e}"));
            }
            // 3. Queue the envelope (blind — relay never inspects contents)
            let envelope_bytes = match b64_decode(&envelope) {
                Ok(b) => b,
                Err(e) => return WsResponse::err(format!("InvalidBase64: {e}")),
            };
            if let Err(e) = state
                .store
                .enqueue(&recipient_id, envelope_bytes, DEFAULT_ENVELOPE_TTL)
            {
                if matches!(&e, MailboxError::QueueFull) {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: envelope queue full on send_envelope"
                    );
                }
                return mailbox_send_error_response(e);
            }
            info!(recipient = %truncate_id(&recipient_id), "ws: envelope stored");
            WsResponse::ok_simple()
        }

        WsRequest::PickupEnvelope { recipient_id } => {
            // Pickup is a read — rate-limited but no PoW required.
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) = rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on pickup_envelope"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            match state.store.dequeue(&recipient_id) {
                Ok(envelope_bytes) => WsResponse::ok_envelope(b64_encode(&envelope_bytes)),
                Err(MailboxError::NotFound) => WsResponse::err("NotFound"),
                Err(MailboxError::Expired) => WsResponse::err("Expired"),
                Err(e) => WsResponse::err(format!("StoreError: {e:?}")),
            }
        }
    }
}

/// Verify a PoW solution submitted by the client.
///
/// The client must first request a challenge (which returns challenge_id + wire bytes),
/// solve it, and include the solution as `pow_solution` (base64 of solution bytes)
/// along with the `challenge_id` (hex of the challenge nonce) in the request.
///
/// The challenge is single-use: it is removed from the active set on lookup, preventing
/// replay. The solution bytes are base64-decoded (not passed through UTF-8 string
/// conversion) to avoid corruption of binary solution values.
async fn verify_pow(
    challenge_id: &str,
    pow_solution: &str,
    state: &Arc<WsState>,
) -> Result<(), String> {
    let solution = b64_decode(pow_solution).map_err(|e| format!("solution base64 decode: {e}"))?;

    let challenge = {
        let mut challenges = state.challenges.lock().await;
        challenges
            .remove(challenge_id)
            .ok_or_else(|| "challenge not found or already used".to_string())?
    };

    pow::verify(&challenge, &solution).map_err(|e: PowError| match e {
        PowError::Invalid { difficulty } => {
            format!("invalid solution ({difficulty} bits)")
        }
        PowError::MalformedChallenge { reason } => format!("malformed challenge: {reason}"),
    })
}

/// Handle a single WebSocket connection.
async fn handle_connection(stream: WebSocketStream<TcpStream>, state: Arc<WsState>) {
    let mut ws = stream;
    while let Some(msg_result) = ws.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let req: WsRequest = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("ws: malformed request: {e}");
                        let resp = WsResponse::err(format!("MalformedRequest: {e}"));
                        let _ = ws
                            .send(Message::Text(serde_json::to_string(&resp).unwrap().into()))
                            .await;
                        continue;
                    }
                };
                let resp = handle_request(req, &state).await;
                let resp_json = serde_json::to_string(&resp)
                    .unwrap_or_else(|_| r#"{"ok":false,"error":"InternalError"}"#.to_string());
                if ws.send(Message::Text(resp_json.into())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Binary(_)) => {
                warn!("ws: binary frame rejected (text-only protocol)");
                let resp = WsResponse::err("BinaryFramesNotAllowed");
                let _ = ws
                    .send(Message::Text(serde_json::to_string(&resp).unwrap().into()))
                    .await;
            }
            Ok(Message::Close(_)) => {
                info!("ws: connection closed");
                break;
            }
            Ok(_) => {} // Ping/Pong handled by tungstenite
            Err(e) => {
                warn!("ws: connection error: {e}");
                break;
            }
        }
    }
}

/// Run the WebSocket listener on the given address.
///
/// This is the main entry point for the WS bridge. It spawns a task per connection,
/// each sharing the same `Arc<WsState>` (store, rate limiter, challenges).
pub async fn run_ws_listener(
    addr: SocketAddr,
    rate_limit_per_minute: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener, rate_limit_per_minute).await
}

/// Run the WS accept loop on an already-bound [`TcpListener`].
///
/// This is split out from [`run_ws_listener`] so the relay binary can bind the
/// listener eagerly (surfacing a port-in-use error as a clear startup failure)
/// and then hand it off to a spawned task.
pub async fn serve_listener(
    listener: TcpListener,
    rate_limit_per_minute: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(WsState::new(rate_limit_per_minute));

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            info!(peer = %peer_addr, "ws: connection accepted");
            let ws_stream = match tokio_tungstenite::accept_async(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_addr, "ws: handshake failed: {e}");
                    return;
                }
            };
            handle_connection(ws_stream, state).await;
        });
    }
}

/// A handle to a running WS listener, for testing. Dropping it stops the listener
/// and aborts the accept loop.
pub struct WsListenerHandle {
    pub addr: SocketAddr,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for WsListenerHandle {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

/// Start a WS listener on a random localhost port, returning the bound address.
/// For testing only — the production path uses `run_ws_listener`.
pub async fn start_ws_listener_for_test(rate_limit_per_minute: u32) -> WsListenerHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(WsState::new(rate_limit_per_minute));

    let join = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let ws_stream = match tokio_tungstenite::accept_async(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(peer = %peer_addr, "ws: handshake failed: {e}");
                                return;
                            }
                        };
                        handle_connection(ws_stream, state).await;
                    });
                }
                Err(e) => {
                    warn!("ws: accept error: {e}");
                    break;
                }
            }
        }
    });

    WsListenerHandle {
        addr,
        join: Some(join),
    }
}

// ── Browser-side client ──────────────────────────────────────────────────────
//
// `WsRelayClient` is the browser-facing client that talks to the WS listener.
// It is a reference implementation: the WASM binding layer (`core/bindings/wasm`)
// can wrap the same logic. The key security property is **fail closed**: if the
// relay connection is unavailable at send time, the client returns an `Err`
// rather than silently dropping the message.

/// Errors returned by [`WsRelayClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsClientError {
    /// The relay connection could not be established or was lost. The client
    /// **fails closed** — the caller must handle this and never silently drop
    /// the message.
    ConnectionUnavailable,
    /// The relay returned an error response.
    Relay(String),
    /// A PoW challenge could not be solved (e.g. difficulty too high).
    PowFailed(String),
    /// Base64 decode failure on a relay response.
    Decode(String),
    /// The requested prekey bundle or envelope was not found.
    NotFound,
}

impl std::fmt::Display for WsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsClientError::ConnectionUnavailable => {
                write!(
                    f,
                    "relay connection unavailable — message not sent (fail closed)"
                )
            }
            WsClientError::Relay(msg) => write!(f, "relay error: {msg}"),
            WsClientError::PowFailed(msg) => write!(f, "PoW solve failed: {msg}"),
            WsClientError::Decode(msg) => write!(f, "decode error: {msg}"),
            WsClientError::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for WsClientError {}

/// A client for the WebSocket relay bridge.
///
/// This is the browser-side counterpart to `run_ws_listener`. It connects to
/// the relay, requests PoW challenges, solves them, and performs
/// publish/lookup/send/pickup operations. **Fail closed**: if the connection
/// is unavailable at send time, operations return `Err(ConnectionUnavailable)`
/// rather than silently dropping the message.
pub struct WsRelayClient {
    stream: Option<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
}

impl WsRelayClient {
    /// Connect to a relay at the given WebSocket URL.
    ///
    /// Returns `Err(ConnectionUnavailable)` if the connection fails — the
    /// caller must handle this and never silently drop the message.
    pub async fn connect(addr: SocketAddr) -> Result<Self, WsClientError> {
        let url = format!("ws://{addr}");
        match tokio_tungstenite::connect_async(url).await {
            Ok((stream, _)) => Ok(Self {
                stream: Some(stream),
            }),
            Err(_) => Err(WsClientError::ConnectionUnavailable),
        }
    }

    /// Ensure the stream is available; return a mutable reference or fail closed.
    fn stream_mut(
        &mut self,
    ) -> Result<
        &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        WsClientError,
    > {
        self.stream
            .as_mut()
            .ok_or(WsClientError::ConnectionUnavailable)
    }

    /// Send a JSON request and return the JSON response.
    async fn round_trip(
        &mut self,
        req: serde_json::Value,
    ) -> Result<serde_json::Value, WsClientError> {
        let stream = self.stream_mut()?;
        stream
            .send(Message::Text(req.to_string().into()))
            .await
            .map_err(|_| WsClientError::ConnectionUnavailable)?;
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => {
                    return serde_json::from_str(&text)
                        .map_err(|e| WsClientError::Relay(format!("invalid JSON response: {e}")));
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) => return Err(WsClientError::ConnectionUnavailable),
                None => {
                    // Stream closed — mark it as unavailable and fail closed.
                    self.stream = None;
                    return Err(WsClientError::ConnectionUnavailable);
                }
            }
        }
    }

    /// Request a PoW challenge, solve it, and return `(challenge_id, pow_solution)`.
    pub async fn solve_challenge(
        &mut self,
        recipient_id: &str,
    ) -> Result<(String, String), WsClientError> {
        let req = serde_json::json!({
            "op": "challenge",
            "recipient_id": recipient_id,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] != true {
            return Err(WsClientError::Relay(
                resp["error"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_string(),
            ));
        }
        let challenge_b64 = resp["challenge"]
            .as_str()
            .ok_or_else(|| WsClientError::Relay("missing challenge field".into()))?;
        let challenge_id = resp["challenge_id"]
            .as_str()
            .ok_or_else(|| WsClientError::Relay("missing challenge_id field".into()))?
            .to_string();

        let challenge_wire = b64_decode(challenge_b64)
            .map_err(|e| WsClientError::Decode(format!("challenge wire: {e}")))?;

        // Wire format: context_len(2 BE) || context || nonce(16) || difficulty(4 BE)
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

        // Brute-force the solution
        let mut counter: u64 = 0;
        let solution = loop {
            let suffix = counter.to_le_bytes();
            if check_pow_difficulty(&preimage, &suffix, difficulty) {
                break suffix.to_vec();
            }
            counter += 1;
            if counter > (1u64 << 32) {
                return Err(WsClientError::PowFailed("exceeded iteration limit".into()));
            }
        };

        Ok((challenge_id, b64_encode(&solution)))
    }

    /// Publish a prekey bundle for the given recipient.
    pub async fn publish_prekey(
        &mut self,
        recipient_id: &str,
        bundle: &[u8],
    ) -> Result<(), WsClientError> {
        let (challenge_id, pow_solution) = self.solve_challenge(recipient_id).await?;
        let req = serde_json::json!({
            "op": "publish_prekey",
            "recipient_id": recipient_id,
            "bundle": b64_encode(bundle),
            "challenge_id": challenge_id,
            "pow_solution": pow_solution,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            Ok(())
        } else {
            Err(WsClientError::Relay(
                resp["error"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_string(),
            ))
        }
    }

    /// Look up a prekey bundle for the given recipient.
    pub async fn lookup_prekey(&mut self, recipient_id: &str) -> Result<Vec<u8>, WsClientError> {
        let req = serde_json::json!({
            "op": "lookup_prekey",
            "recipient_id": recipient_id,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            let bundle_b64 = resp["bundle"]
                .as_str()
                .ok_or_else(|| WsClientError::Relay("missing bundle field".into()))?;
            b64_decode(bundle_b64).map_err(WsClientError::Decode)
        } else {
            let err = resp["error"].as_str().unwrap_or("unknown error");
            if err == "NotFound" || err == "Expired" {
                Err(WsClientError::NotFound)
            } else {
                Err(WsClientError::Relay(err.to_string()))
            }
        }
    }

    /// Send a Sealed Sender envelope to the given recipient.
    pub async fn send_envelope(
        &mut self,
        recipient_id: &str,
        envelope: &[u8],
    ) -> Result<(), WsClientError> {
        let (challenge_id, pow_solution) = self.solve_challenge(recipient_id).await?;
        let req = serde_json::json!({
            "op": "send_envelope",
            "recipient_id": recipient_id,
            "envelope": b64_encode(envelope),
            "challenge_id": challenge_id,
            "pow_solution": pow_solution,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            Ok(())
        } else {
            Err(WsClientError::Relay(
                resp["error"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_string(),
            ))
        }
    }

    /// Pick up a Sealed Sender envelope for the given recipient.
    pub async fn pickup_envelope(&mut self, recipient_id: &str) -> Result<Vec<u8>, WsClientError> {
        let req = serde_json::json!({
            "op": "pickup_envelope",
            "recipient_id": recipient_id,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            let envelope_b64 = resp["envelope"]
                .as_str()
                .ok_or_else(|| WsClientError::Relay("missing envelope field".into()))?;
            b64_decode(envelope_b64).map_err(WsClientError::Decode)
        } else {
            let err = resp["error"].as_str().unwrap_or("unknown error");
            if err == "NotFound" || err == "Expired" {
                Err(WsClientError::NotFound)
            } else {
                Err(WsClientError::Relay(err.to_string()))
            }
        }
    }

    /// Close the connection explicitly.
    pub async fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.close(None).await;
        }
    }
}

/// Check if a PoW solution meets the difficulty (mirrors pow::meets_difficulty).
fn check_pow_difficulty(preimage: &[u8], suffix: &[u8], difficulty: u32) -> bool {
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

// Simple hex encoding (avoid pulling in another dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip() {
        let data = vec![0u8, 1, 2, 3, 255, 254, 253];
        let encoded = b64_encode(&data);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn b64_empty() {
        let encoded = b64_encode(&[]);
        assert_eq!(encoded, "");
        let decoded = b64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncate_id_short_unchanged() {
        assert_eq!(truncate_id("short"), "short");
    }

    #[test]
    fn truncate_id_long_truncated() {
        assert_eq!(truncate_id("very-long-recipient-id"), "very-lon…");
    }

    #[test]
    fn b64_rejects_invalid_chars() {
        // Invalid characters must be rejected, not silently skipped.
        let result = b64_decode("AB!D");
        assert!(result.is_err(), "invalid base64 char must be rejected");
    }

    #[test]
    fn b64_rejects_bad_padding() {
        // More than 2 padding chars is invalid.
        let result = b64_decode("AB===");
        assert!(result.is_err(), "excess padding must be rejected");
    }

    #[test]
    fn b64_rejects_bad_length() {
        // Length not a multiple of 4 is invalid.
        let result = b64_decode("ABC");
        assert!(result.is_err(), "bad length must be rejected");
    }

    #[test]
    fn mailbox_send_error_response_maps_queue_full_distinctly() {
        // A full queue must surface as its own error string, not the generic
        // StoreError form, so the sender can distinguish "backlog full" from a
        // storage failure.
        match mailbox_send_error_response(MailboxError::QueueFull) {
            WsResponse::Err { ok, error } => {
                assert!(!ok, "QueueFull must be an error response");
                assert_eq!(
                    error, "QueueFull",
                    "QueueFull must map to the distinct QueueFull error string"
                );
            }
            other => panic!("expected an error response, got: {other:?}"),
        }
    }

    #[test]
    fn mailbox_send_error_response_folds_other_variants_into_store_error() {
        match mailbox_send_error_response(MailboxError::NotFound) {
            WsResponse::Err { ok, error } => {
                assert!(!ok, "non-QueueFull must be an error response");
                assert!(
                    error.starts_with("StoreError: "),
                    "non-QueueFull variants keep the StoreError form, got: {error}"
                );
            }
            other => panic!("expected an error response, got: {other:?}"),
        }
    }
}
