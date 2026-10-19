//! DT-2: native Rust WebSocket client for the relay's WS wire protocol.
//!
//! Mirrors the browser client (`clients/web/src/relay_transport.ts`) and the
//! reference implementation in `relay::ws::WsRelayClient`, behind the narrow
//! seam the desktop call sites use — the same shape as the web client's
//! `GroupTransport` interface (`clients/web/src/GroupConversation.tsx`), so a
//! future consolidation onto `core_transport` stays possible without
//! rewriting call sites.
//!
//! Wire protocol (see `relay/src/ws.rs` module docs): JSON text frames, ops
//! `challenge` / `publish_prekey` / `lookup_prekey` / `send_envelope` /
//! `pickup_envelope`. Payloads (`bundle`, `envelope`, `challenge`,
//! `pow_solution`) are standard base64 WITH padding. Protected ops
//! (`publish_prekey`, `send_envelope`) carry `challenge_id` (hex of the
//! challenge nonce) plus `pow_solution` (base64 of the solution suffix); the
//! relay's challenges are SINGLE-USE (removed from its active set on lookup),
//! so this client fetches a fresh challenge per protected op and never caches
//! one across calls.
//!
//! The relay stays blind: only ciphertext and the protocol's existing
//! non-content routing fields (`recipient_id`, the allow-listed `kind` tag as
//! a sibling JSON field — never inside the ciphertext) go on the wire.
//!
//! Error semantics (fail closed): a send that cannot be completed returns
//! `Err` — the message is never silently dropped. Every response read is
//! bounded by a timeout, so a relay that stalls or drops mid-session surfaces
//! as [`RelayError::ConnectionClosed`] instead of hanging the caller.

use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// Bound on a single request/response round trip. A relay that accepts the
/// request but never answers must surface as an error, not a hang.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the PoW difficulty this client will accept from a relay.
///
/// The difficulty is relay-controlled, and the solve is up to `2^difficulty`
/// SHA-256 evaluations — so an unbounded cap would let a hostile or
/// misconfigured relay pin the client for unbounded work. 28 bits is far
/// above the relay's real setting of 20 (`relay/src/ws.rs POW_DIFFICULTY`)
/// while capping the worst case at ~2^28 hashes (~seconds, off the async
/// executor). A challenge above the cap is rejected with
/// [`RelayError::Protocol`] before any hashing happens.
const MAX_POW_DIFFICULTY: u32 = 28;

/// The relay's WS PoW difficulty is 20 bits (relay/src/ws.rs `POW_DIFFICULTY`);
/// a 32-bit counter space is ample headroom, matching the reference client's
/// iteration cap.
const POW_ITERATION_LIMIT: u64 = 1u64 << 32;

/// Errors returned by [`RelayClient`]. Distinct variants for the relay's
/// documented error cases so callers can branch on them without string
/// matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The requested prekey bundle or envelope does not exist (relay wire
    /// error `"NotFound"`).
    NotFound,
    /// The stored item outlived its lease and was pruned (relay wire error
    /// `"Expired"`).
    Expired,
    /// The recipient's mailbox queue is at its per-recipient cap (relay wire
    /// error `"QueueFull"`). The connection stays usable; a later send after
    /// the queue drains works.
    QueueFull,
    /// The relay rejected the proof-of-work solution (`"PowFailed: ..."`) or
    /// no valid solution could be found for the issued challenge.
    PowFailed(String),
    /// The relay could not be reached at connect time.
    Unreachable(String),
    /// The connection was lost mid-session (stream ended, protocol error, or
    /// a response never arrived within the round-trip bound). The in-flight
    /// op failed — it never reports `Ok` across a dropped socket.
    ConnectionClosed,
    /// The relay answered with an error this client does not model, or a
    /// response frame did not match the protocol.
    Protocol(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::NotFound => write!(f, "not found"),
            RelayError::Expired => write!(f, "expired"),
            RelayError::QueueFull => write!(f, "recipient mailbox queue is full"),
            RelayError::PowFailed(msg) => write!(f, "PoW rejected: {msg}"),
            RelayError::Unreachable(msg) => write!(f, "relay unreachable: {msg}"),
            RelayError::ConnectionClosed => {
                write!(f, "relay connection closed mid-session — op not completed")
            }
            RelayError::Protocol(msg) => write!(f, "relay protocol error: {msg}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Map a relay wire error string onto a typed variant. Unknown strings keep
/// their text in [`RelayError::Protocol`] rather than being collapsed, so no
/// relay error case is silently swallowed.
fn map_wire_error(error: &str) -> RelayError {
    if error == "NotFound" {
        RelayError::NotFound
    } else if error == "Expired" {
        RelayError::Expired
    } else if error == "QueueFull" {
        RelayError::QueueFull
    } else if let Some(rest) = error.strip_prefix("PowFailed:") {
        RelayError::PowFailed(rest.trim().to_string())
    } else {
        RelayError::Protocol(error.to_string())
    }
}

/// The out-of-band envelope-kind routing tag. NON-CONTENT metadata: it
/// travels as a sibling JSON field of `send_envelope` / `pickup_envelope` —
/// never inside the ciphertext — and the relay stores and echoes it verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// 1:1 session envelope.
    Direct,
    /// Group sender-key envelope.
    Group,
}

impl EnvelopeKind {
    fn as_str(self) -> &'static str {
        match self {
            EnvelopeKind::Direct => "direct",
            EnvelopeKind::Group => "group",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "direct" => Some(EnvelopeKind::Direct),
            "group" => Some(EnvelopeKind::Group),
            _ => None,
        }
    }
}

/// An envelope delivered by [`RelayClient::pickup_envelope`]: the ciphertext
/// bytes plus the out-of-band kind tag the sender attached (absent when the
/// sender sent none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The envelope ciphertext exactly as the sender queued it.
    pub bytes: Vec<u8>,
    /// The out-of-band routing tag, echoed verbatim by the relay.
    pub kind: Option<EnvelopeKind>,
}

/// A native WebSocket client for the relay's WS wire protocol.
///
/// One client owns one connection. Operations are sequential request/response
/// round trips; each protected op fetches and solves a fresh PoW challenge.
pub struct RelayClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Bound on a single request/response round trip on this connection.
    response_timeout: Duration,
    /// Set once a round trip has failed in a way that desynchronizes the
    /// request/response pairing (a response that never arrived within the
    /// bound, a send failure, or a transport error). The late reply to the
    /// abandoned request may still arrive and would otherwise be consumed as
    /// the NEXT op's response — so once poisoned, every later op fails with
    /// [`RelayError::ConnectionClosed`] immediately, without touching the
    /// socket. The connection must be re-established.
    poisoned: bool,
}

impl RelayClient {
    /// Connect to a relay at the given WebSocket URL (e.g. `ws://127.0.0.1:8080`).
    ///
    /// Fails closed: an unreachable relay is [`RelayError::Unreachable`], never
    /// a silently-degraded client.
    pub async fn connect(url: &str) -> Result<Self, RelayError> {
        Self::connect_with_timeout(url, RESPONSE_TIMEOUT).await
    }

    /// [`RelayClient::connect`] with an explicit per-round-trip response bound
    /// (the default is [`RESPONSE_TIMEOUT`]). Exposed so tests can exercise
    /// the timeout path without waiting ten seconds.
    pub async fn connect_with_timeout(
        url: &str,
        response_timeout: Duration,
    ) -> Result<Self, RelayError> {
        // DT-3: refuse a plain ws:// relay on a non-loopback host up front,
        // before any dial. Plain ws:// exposes recipient IDs and timing to the
        // network; a remote relay must use wss:// unless the user opted in with
        // `--allow-insecure-ws`, which is resolved into a `RelayConfig` and
        // dialed through [`RelayClient::connect_config`] instead.
        crate::relay_config::validate_relay_url(url, false)
            .map_err(|e| RelayError::Unreachable(e.to_string()))?;
        Self::dial(url, response_timeout).await
    }

    /// Connect using an address that has already been validated, typically the
    /// one held in [`crate::relay_config::RelayConfigState`].
    ///
    /// The policy decision — including an explicit `--allow-insecure-ws` opt-in
    /// — was made when the config was resolved, and a `RelayConfig` can only be
    /// produced by that validation, so re-applying the default-deny rule here
    /// would make the opt-in unreachable.
    pub async fn connect_config(
        config: &crate::relay_config::RelayConfig,
    ) -> Result<Self, RelayError> {
        Self::connect_config_with_timeout(config, RESPONSE_TIMEOUT).await
    }

    /// [`RelayClient::connect_config`] with an explicit round-trip bound.
    pub async fn connect_config_with_timeout(
        config: &crate::relay_config::RelayConfig,
        response_timeout: Duration,
    ) -> Result<Self, RelayError> {
        Self::dial(config.url(), response_timeout).await
    }

    async fn dial(url: &str, response_timeout: Duration) -> Result<Self, RelayError> {
        match connect_async(url).await {
            Ok((ws, _response)) => Ok(Self {
                ws,
                response_timeout,
                poisoned: false,
            }),
            Err(e) => Err(RelayError::Unreachable(e.to_string())),
        }
    }

    /// Publish a prekey bundle for `recipient_id` (last-write-wins on the
    /// relay). PoW-protected: fetches a fresh challenge per call.
    pub async fn publish_prekey(
        &mut self,
        recipient_id: &str,
        bundle: &[u8],
    ) -> Result<(), RelayError> {
        let (challenge_id, pow_solution) = self.solve_challenge(recipient_id).await?;
        let req = json!({
            "op": "publish_prekey",
            "recipient_id": recipient_id,
            "bundle": B64.encode(bundle),
            "challenge_id": challenge_id,
            "pow_solution": pow_solution,
        });
        let resp = self.round_trip(req).await?;
        expect_ok(resp)
    }

    /// Look up the published prekey bundle for `recipient_id`. A read — no
    /// PoW, mirroring the relay's own gating.
    pub async fn lookup_prekey(&mut self, recipient_id: &str) -> Result<Vec<u8>, RelayError> {
        let req = json!({
            "op": "lookup_prekey",
            "recipient_id": recipient_id,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            let bundle_b64 = resp["bundle"]
                .as_str()
                .ok_or_else(|| RelayError::Protocol("ok lookup_prekey missing bundle".into()))?;
            B64.decode(bundle_b64)
                .map_err(|e| RelayError::Protocol(format!("bundle base64: {e}")))
        } else {
            Err(map_wire_error(wire_error(&resp)?))
        }
    }

    /// Queue `envelope` (ciphertext) for `recipient_id`. PoW-protected.
    ///
    /// `kind` is the optional out-of-band routing tag, sent as a sibling JSON
    /// field — never inside the ciphertext — and allow-listed by the relay to
    /// `"direct"` / `"group"`.
    pub async fn send_envelope(
        &mut self,
        recipient_id: &str,
        envelope: &[u8],
        kind: Option<EnvelopeKind>,
    ) -> Result<(), RelayError> {
        let (challenge_id, pow_solution) = self.solve_challenge(recipient_id).await?;
        let mut req = json!({
            "op": "send_envelope",
            "recipient_id": recipient_id,
            "envelope": B64.encode(envelope),
            "challenge_id": challenge_id,
            "pow_solution": pow_solution,
        });
        // Sibling field, omitted entirely when absent — the relay stores an
        // absent kind as absent and echoes it back as absent.
        if let Some(kind) = kind {
            req["kind"] = json!(kind.as_str());
        }
        let resp = self.round_trip(req).await?;
        expect_ok(resp)
    }

    /// Take the oldest queued envelope for `recipient_id`, optionally filtered
    /// by kind. No PoW (a read, like `lookup_prekey`).
    ///
    /// An empty (or foreign-kind-only) mailbox is [`RelayError::NotFound`] —
    /// returned immediately, never awaited forever: every response read is
    /// bounded.
    pub async fn pickup_envelope(
        &mut self,
        recipient_id: &str,
        kind: Option<EnvelopeKind>,
    ) -> Result<Envelope, RelayError> {
        let mut req = json!({
            "op": "pickup_envelope",
            "recipient_id": recipient_id,
        });
        if let Some(kind) = kind {
            req["kind"] = json!(kind.as_str());
        }
        let resp = self.round_trip(req).await?;
        if resp["ok"] == true {
            let envelope_b64 = resp["envelope"].as_str().ok_or_else(|| {
                RelayError::Protocol("ok pickup_envelope missing envelope".into())
            })?;
            let bytes = B64
                .decode(envelope_b64)
                .map_err(|e| RelayError::Protocol(format!("envelope base64: {e}")))?;
            // The relay echoes the tag verbatim; absent stays absent. A value
            // outside the allow-list cannot be stored by the relay, so seeing
            // one here is a protocol violation, not a routable tag.
            let kind = match resp["kind"].as_str() {
                None => None,
                Some(s) => Some(EnvelopeKind::from_wire(s).ok_or_else(|| {
                    RelayError::Protocol(format!("unknown envelope kind on wire: {s}"))
                })?),
            };
            Ok(Envelope { bytes, kind })
        } else {
            Err(map_wire_error(wire_error(&resp)?))
        }
    }

    /// Request a fresh PoW challenge, solve it, and return
    /// `(challenge_id, pow_solution)`.
    ///
    /// A challenge is fetched per protected op — the relay's challenges are
    /// single-use (removed from its active set on lookup), so caching one
    /// across calls would make the next op fail with "challenge not found or
    /// already used". A rejected solution leaves no client-side state behind:
    /// the challenge is simply discarded and the next call fetches a fresh one.
    async fn solve_challenge(
        &mut self,
        recipient_id: &str,
    ) -> Result<(String, String), RelayError> {
        let req = json!({
            "op": "challenge",
            "recipient_id": recipient_id,
        });
        let resp = self.round_trip(req).await?;
        if resp["ok"] != true {
            return Err(map_wire_error(wire_error(&resp)?));
        }
        let challenge_b64 = resp["challenge"].as_str().ok_or_else(|| {
            RelayError::Protocol("ok challenge response missing challenge".into())
        })?;
        let challenge_id = resp["challenge_id"]
            .as_str()
            .ok_or_else(|| {
                RelayError::Protocol("ok challenge response missing challenge_id".into())
            })?
            .to_string();
        let wire = B64
            .decode(challenge_b64)
            .map_err(|e| RelayError::Protocol(format!("challenge base64: {e}")))?;
        let (preimage, difficulty) = parse_challenge_wire(&wire)?;
        // The solve is a CPU-bound loop of up to 2^difficulty SHA-256
        // evaluations: run it on the blocking thread pool so a legitimate
        // (but heavy) challenge can never pin a tokio async worker.
        let solution = tokio::task::spawn_blocking(move || solve_pow(&preimage, difficulty))
            .await
            .map_err(|e| RelayError::PowFailed(format!("pow worker failed: {e}")))??;
        Ok((challenge_id, B64.encode(solution)))
    }

    /// Send one request frame and await exactly one response frame, bounded by
    /// this client's round-trip bound.
    ///
    /// The bound is what keeps a stalled or half-dead relay from hanging a
    /// pickup forever: a timeout, a stream end, and a transport error all map
    /// to [`RelayError::ConnectionClosed`] — the op did not complete, so it
    /// must not report `Ok`.
    ///
    /// Any of those failures also POISONS the connection: the abandoned
    /// request's reply may still arrive later, and reading it as the next
    /// op's response would silently pair one op's answer with another op's
    /// request (e.g. a late `{"ok":true}` taken as the reply to a
    /// `send_envelope` that never went through). After poisoning, the socket
    /// is closed and every later op returns [`RelayError::ConnectionClosed`]
    /// immediately, without touching the socket — the caller must reconnect.
    async fn round_trip(&mut self, req: Value) -> Result<Value, RelayError> {
        if self.poisoned {
            return Err(RelayError::ConnectionClosed);
        }
        let text = serde_json::to_string(&req)
            .map_err(|e| RelayError::Protocol(format!("request serialization: {e}")))?;
        // A send failure means the socket is already gone: the op cannot
        // complete, so it fails closed rather than reporting Ok.
        if self.ws.send(Message::Text(text.into())).await.is_err() {
            self.poison().await;
            return Err(RelayError::ConnectionClosed);
        }
        match timeout(self.response_timeout, self.ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str(&text)
                .map_err(|e| RelayError::Protocol(format!("response frame: {e}"))),
            Ok(Some(Ok(_))) => {
                // Binary frames are rejected by the relay; ping/pong are
                // handled by tungstenite. Anything else here is a violation.
                Err(RelayError::Protocol("non-text response frame".into()))
            }
            Ok(Some(Err(_))) | Ok(None) => {
                // The transport is gone (or broke mid-frame): nothing further
                // can be paired reliably on this socket.
                self.poison().await;
                Err(RelayError::ConnectionClosed)
            }
            Err(_elapsed) => {
                // The response never arrived within the bound — but it may
                // still arrive later. That stale frame must never be read as
                // a later op's response, so the connection is poisoned.
                self.poison().await;
                Err(RelayError::ConnectionClosed)
            }
        }
    }

    /// Poison the connection: stop using the socket for good. Best-effort
    /// close handshake (the socket may already be unusable — that is fine);
    /// the poisoned flag is what actually guarantees later ops never touch
    /// it again.
    async fn poison(&mut self) {
        self.poisoned = true;
        let _ = self.ws.close(None).await;
    }
}

/// Extract the `error` string from an error-shaped response frame.
fn wire_error(resp: &Value) -> Result<&str, RelayError> {
    resp["error"]
        .as_str()
        .ok_or_else(|| RelayError::Protocol("error response missing error field".into()))
}

/// Require `{"ok":true}` from an op that returns no payload.
fn expect_ok(resp: Value) -> Result<(), RelayError> {
    if resp["ok"] == true {
        Ok(())
    } else {
        Err(map_wire_error(wire_error(&resp)?))
    }
}

/// Parse the challenge wire format:
/// `context_len(2 BE) || context || nonce(16) || difficulty(4 BE)`.
///
/// Returns the PoW preimage prefix (`context || nonce`) and the difficulty in
/// bits. Every length is bounds-checked — a malformed challenge is a
/// [`RelayError::Protocol`], never a panic.
pub fn parse_challenge_wire(wire: &[u8]) -> Result<(Vec<u8>, u32), RelayError> {
    if wire.len() < 2 {
        return Err(RelayError::Protocol("challenge wire too short".into()));
    }
    let context_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    let nonce_start = 2usize
        .checked_add(context_len)
        .ok_or_else(|| RelayError::Protocol("challenge context length overflow".into()))?;
    let difficulty_start = nonce_start
        .checked_add(16)
        .ok_or_else(|| RelayError::Protocol("challenge length overflow".into()))?;
    let end = difficulty_start
        .checked_add(4)
        .ok_or_else(|| RelayError::Protocol("challenge length overflow".into()))?;
    if wire.len() < end {
        return Err(RelayError::Protocol(format!(
            "challenge wire truncated: {} bytes, need {}",
            wire.len(),
            end
        )));
    }
    let mut preimage = Vec::with_capacity(2 + context_len + 16);
    preimage.extend_from_slice(&wire[2..nonce_start]);
    preimage.extend_from_slice(&wire[nonce_start..difficulty_start]);
    let difficulty = u32::from_be_bytes([
        wire[difficulty_start],
        wire[difficulty_start + 1],
        wire[difficulty_start + 2],
        wire[difficulty_start + 3],
    ]);
    // Difficulty 0 is trivially satisfied (zero leading zero-bits required —
    // the relay's own meets_difficulty accepts it immediately); the scripted
    // test relay issues exactly that. Anything above [`MAX_POW_DIFFICULTY`]
    // is rejected HERE, before any hashing: the difficulty is relay-controlled
    // and the solve cost is exponential in it, so an unbounded cap would let
    // a hostile relay pin the client for unbounded work.
    if difficulty > MAX_POW_DIFFICULTY {
        return Err(RelayError::Protocol(format!(
            "challenge difficulty {difficulty} exceeds the client cap of {MAX_POW_DIFFICULTY}"
        )));
    }
    Ok((preimage, difficulty))
}

/// Solve the PoW: find the little-endian u64 suffix `s` minimizing work such
/// that SHA-256(`preimage || s`) has `difficulty` leading zero bits.
///
/// Mirrors `relay::pow::solve` (suffix = counter as LE bytes) and
/// `relay::pow::meets_difficulty` (whole-byte zeros, then a partial-bit mask),
/// so a solution this client produces verifies against the relay's checker.
fn solve_pow(preimage: &[u8], difficulty: u32) -> Result<Vec<u8>, RelayError> {
    let full_bytes = (difficulty / 8) as usize;
    let extra_bits = difficulty % 8;
    let mask: u8 = if extra_bits == 0 {
        0
    } else {
        0xFFu8 << (8 - extra_bits)
    };

    let mut counter: u64 = 0;
    loop {
        let suffix = counter.to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        hasher.update(suffix);
        let digest = hasher.finalize();

        let leading_zero = digest[..full_bytes].iter().all(|&b| b == 0)
            && (extra_bits == 0 || (digest[full_bytes] & mask) == 0);
        if leading_zero {
            return Ok(suffix.to_vec());
        }
        counter += 1;
        if counter >= POW_ITERATION_LIMIT {
            return Err(RelayError::PowFailed(
                "no solution found within iteration limit".into(),
            ));
        }
    }
}
