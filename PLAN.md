# Plan: Portable, Decentralized, E2E-Encrypted Messenger (Signal Protocol)

## 1. Goal & Constraints

Build an **open-source**, **decentralized**, **end-to-end encrypted** messaging app that uses the
**Signal Protocol** as its cryptographic core, with **portability** as a first-class design goal.

This plan is grounded in the landscape review in `e2e_decentralized_chat_summary.md`. That review's
conclusion was that no existing decentralized option (Matrix/Megolm, Briar, Jami, XMPP/OMEMO) gives you
the *actual* Signal Protocol — they use Signal-*derived* schemes with smaller audit footprints. The
strategy here is therefore: **use the real, audited Signal Protocol crypto (`libsignal`) on top of a
decentralized transport we control**, rather than adopting a federated protocol's weaker crypto.

### Locked decisions
| Decision | Choice | Rationale |
|---|---|---|
| Topology | **Hybrid P2P + blind relays** | DHT peer discovery + swappable store-and-forward relays for offline delivery. No server owns identity; relays can't read content. |
| Platforms | **All platforms, shared Rust core** | `libsignal` is Rust. One audited crypto core, thin native UI per platform. Maximum code reuse + one place to audit. |
| Group crypto | **Signal Sender Keys** | Signal's own group mechanism over the Double Ratchet; ships in `libsignal`; most faithful to "use Signal Protocol". |

### Non-goals (v1)
- Phone-number-based identity (we use self-sovereign keys instead — a deliberate decentralization win).
- Voice/video calls (chat-first; calls are a later epic).
- Large public broadcast channels (Sender Keys fan-out is sized for private groups, not 10k-member rooms).

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  UI layer (per platform — thin)                              │
│  iOS/SwiftUI · Android/Compose · Desktop/Tauri · Web/React    │
└───────────────▲───────────────────────────────▲──────────────┘
                │ UniFFI bindings                │ WASM
┌───────────────┴───────────────────────────────┴──────────────┐
│  SHARED RUST CORE (the one audited place)                     │
│                                                               │
│  ┌──────────────┐ ┌───────────────┐ ┌──────────────────────┐ │
│  │ Crypto       │ │ Protocol/     │ │ Storage              │ │
│  │ (libsignal)  │ │ Session mgmt  │ │ (SQLCipher)          │ │
│  │ X3DH/PQXDH   │ │ wire format   │ │ keys, sessions, msgs │ │
│  │ Double Ratchet│ │ (protobuf)    │ │ encrypted at rest    │ │
│  │ Sender Keys  │ └───────────────┘ └──────────────────────┘ │
│  │ Sealed Sender│ ┌─────────────────────────────────────────┐│
│  └──────────────┘ │ Transport (libp2p)                      ││
│                   │ Noise · QUIC/TCP · Kademlia DHT ·        ││
│                   │ Circuit Relay v2 · GossipSub            ││
│                   └─────────────────────────────────────────┘│
└───────────────────────────────────────────────────────────────┘
                │                              │
        ┌───────▼────────┐            ┌────────▼────────┐
        │ Peer (direct)  │            │ Blind relay     │
        │ when online    │            │ store-&-forward │
        └────────────────┘            └─────────────────┘
```

### Layer responsibilities
- **Crypto** — `libsignal` used as-is. X3DH (or **PQXDH**, post-quantum, if available in the pinned
  version) for async session setup; Double Ratchet for 1:1 forward secrecy; Sender Keys for groups;
  **Sealed Sender** so relays can't see who sent a message. We do **not** roll our own crypto.
- **Protocol** — session lifecycle, prekey management, message envelopes. Wire format is **Protocol
  Buffers** with an explicit, versioned, published spec so third-party clients can interoperate.
- **Storage** — encrypted local store via SQLCipher (`rusqlite`). Holds identity/session/prekey state
  and message history. Backed by an encrypted, portable export/import format.
- **Transport** — `libp2p`: Noise transport encryption (defense-in-depth *under* the E2E layer),
  QUIC/TCP, **Kademlia DHT** for peer + prekey-bundle discovery, **Circuit Relay v2** for NAT traversal
  and store-and-forward.

---

## 3. Identity & Discovery (decentralized, no phone number)

- **Identity = a device-generated Ed25519/Curve25519 keypair.** The private key never leaves the device
  unencrypted. The public identity key's fingerprint is the user's address.
- **Discovery:** users find each other by an out-of-band invite (QR / link) or a self-chosen handle
  mapped through the DHT to the current prekey bundle. No central directory.
- **Prekey bundles** (signed prekeys + one-time prekeys) are published to the DHT/relays so a sender can
  start an X3DH/PQXDH session while the recipient is **offline**. Replenished automatically.
- **Verification:** TOFU (trust-on-first-use) plus **safety-number / fingerprint comparison** for manual
  out-of-band verification — same model as Signal.
- **Abuse/spam control** (needed because there's no phone-number cost): client-side **proof-of-work** on
  first contact + relay-side rate limiting. Tracked as its own story; flagged as an open risk (§7).

---

## 4. Multi-Device & Sync

The hard part of "decentralized Signal." Approach:
- Each device has **its own identity key**. An account is a set of **linked device keys signed by a
  primary device**. Linking is done by secure QR pairing with safety-number confirmation.
- Sessions and Sender Keys are **per-device** (sender fan-out per recipient device, as Signal does).
- **History sync** between a user's own devices is an explicit later epic (it's genuinely hard without a
  server); v1 ships per-device history + encrypted backup export/import for migration.
- **Revocation/unlinking** is the inverse of linking and is specified (semantics only) in
  `spec/v0.md` §8: unlinking a device revokes its `DeviceAddress`, drops its prekey bundle from
  the account's `DiscoveryRecord`, tears down its sessions, and rejects its Sealed Sender
  certificates, propagated as a signed, monotonically versioned device list. The wire shapes are
  Phase 6 work; revoking the *primary* device is an open item (`spec/v0.md` §7).

---

## 5. Portability Strategy (the explicit requirement)

Portability is treated on four axes:

1. **Code portability** — one Rust core, compiled everywhere:
   - iOS/Android via **UniFFI** (auto-generated Swift/Kotlin bindings).
   - Web via **WASM**.
   - Desktop via **Tauri** (the Tauri backend *is* the same Rust core — no second implementation).
   - UI is thin and native per platform for best UX; crypto/protocol/transport is never reimplemented.
2. **Identity portability** — self-sovereign keys, not bound to a phone number or any server. Users can
   switch relays freely; identity travels with the key.
3. **Data portability** — a documented, encrypted backup/export format. No lock-in; import on any client.
4. **Protocol portability / interoperability** — a published, versioned protobuf wire spec in `/spec`,
   so independent clients can implement the protocol and interoperate.

> **Web caveat:** browsers lack a secure enclave; key material in WASM/IndexedDB is weaker than on
> mobile/desktop. The web client ships with a documented, reduced threat model and a clear in-app warning.

---

## 6. Proposed Repository Layout (monorepo)

```
/core            Rust workspace
  /crypto        libsignal integration, identity, session, sender keys
  /protocol      envelopes, prekey mgmt, protobuf-generated types
  /transport     libp2p: DHT discovery, relay client, delivery
  /storage       SQLCipher store, backup export/import
  /bindings
    /uniffi      iOS/Android FFI
    /wasm        web build
/clients
  /ios           SwiftUI
  /android       Jetpack Compose
  /desktop       Tauri (reuses /core)
  /web           React + WASM
/relay           Standalone relay node binary (self-hostable)
/spec            Versioned protocol + wire-format specification
/docs            Architecture, threat model, operator guide
```

### 6.5 Current state vs target state

The tree above is the **target layout**. Not every box is built today, and this document
deliberately describes the finished design; read it as the destination, not a status report.
What exists and is tested right now (see the per-crate tests and `docs/threat-model.md`):

- **Built:** the Rust core (`core/crypto`, `core/protocol`, `core/storage`, `core/transport`,
  including Sealed Sender and padding), the standalone relay (`relay/`), the UniFFI and WASM
  bindings, the web client (`clients/web`), and the desktop client (`clients/desktop-tauri`).
- **Scaffolded only:** `clients/desktop`, `clients/ios`, and `clients/android` are placeholder
  directories with a README each — no implementation yet (Phase 8).
- **Not started:** multi-device history sync (a later epic, per §4) and the Phase 9 hardening
  items (external audit, fuzzing, Tor/mixnet transport).

Everything else in this plan — DHT discovery, relay store-and-forward, group Sender Keys,
backup export/import — is implemented and covered by the suites; where a capability is still
future work, this plan says so explicitly (§4, §7, §10) rather than in the present tense.

---

## 7. Phased Roadmap

Each phase is a set of stories driven through the pipeline (see §9) under strict TDD. Phases are ordered
so the **crypto core is correct and tested before any networking**, and one client is end-to-end before
fanning out to all platforms.

| Phase | Deliverable | Key tests |
|---|---|---|
| **0 — Foundations** | Monorepo, CI matrix, threat model doc, protocol spec v0 draft, pin `libsignal`/`libp2p` versions, AGPL licensing decision (§7 risk). | CI green on empty workspace; spec lint. |
| **1 — Crypto core** | Identity generation, X3DH/PQXDH session setup, Double Ratchet 1:1 encrypt/decrypt. | Unit tests against **published Signal test vectors**; negative tests (tampered ciphertext, replay, out-of-order). |
| **2 — Storage** | Encrypted SQLCipher store for keys/sessions/messages; backup export/import. | Round-trip + corruption/negative tests; fail-closed on bad key. |
| **3 — Transport (online)** | libp2p stack, DHT prekey publication/lookup, direct delivery between two online peers. | Two-node integration tests; DHT lookup contract tests. |
| **4 — Relays & offline** | Self-hostable relay binary, blind store-and-forward with durable SQLite store, **Sealed Sender**. | Relay state persists across restarts; envelopes survive restarts and are retained only until their TTL expires, enforced by wall‑clock expiry. |
| **5 — First client (desktop/Tauri)** | One platform end-to-end on the shared core — fastest iteration loop. | E2E smoke: two clients exchange verified messages. |
| **6 — Multi-device** | Device linking (QR + safety number), per-device sessions, device revocation/unlinking (semantics fixed in `spec/v0.md` §8). | Linking flow tests; per-device fan-out; revocation propagation (a revoked device's messages are rejected once the signed device-list update is observed). |
| **7 — Groups** | Sender Keys group sessions, membership changes. | Group encrypt/decrypt, member add/remove key rotation, negative (removed member can't read new msgs). |
| **8 — All platforms** | UniFFI iOS+Android, WASM web. | Per-binding contract tests against core API. |
| **9 — Hardening** | External security audit, fuzzing, metadata analysis, safety-number UX, backup/restore polish, optional Tor/mixnet transport. | Fuzz wire parser; metadata leakage review; audit findings closed. |

Recommended first vertical slice to de-risk: **Phases 1 → 5 for 1:1 messaging on desktop**, then expand.

---

## 8. Security Posture (per `CLAUDE.md` "Secure by Design")

- **Fail closed:** any crypto/verification error denies — never silently sends plaintext or accepts an
  unverified key.
- **Defense in depth:** Noise transport encryption *under* the E2E Signal layer; relays are blind
  (Sealed Sender); local store encrypted at rest.
- **Data minimization:** relays store only ciphertext envelopes with short TTLs and no sender identity.
- **No security by obscurity:** the protocol spec is public; security rests on the crypto, not hidden paths.
- **Audit logging** (relay/node side): connection/abuse events with identifiers and outcomes only — never
  payloads or content.
- **Post-quantum:** prefer PQXDH where the pinned `libsignal` supports it.
- **Don't reinvent crypto:** `libsignal` is used unmodified; any deviation requires security-engineer sign-off.

---

## 9. Process / Workflow (per `CLAUDE.md`)

This repo mandates driving work through the pipeline before coding. Before implementation begins:
1. Decompose this plan into **epics → stories with acceptance criteria** (via the `product-analyst`
   agent), one epic roughly per phase above.
2. Register them with `mcp__pipeline__save_plan` / `ingest_plan`.
3. Implement each story **test-first (TDD)**, branch `agent/{STORY-ID}`, run the full suite, route through
   `review_story` (security-engineer review is mandatory for all crypto/transport stories), then commit.

Testing emphasis specific to this project:
- **Crypto:** validate against official Signal **test vectors**; property tests for ratchet ordering.
- **Wire format:** **contract tests** treating the protobuf spec as source of truth (both producer and
  consumer sides), per the API-contract-testing standard.
- **Fuzzing:** the message/envelope parser is an untrusted boundary — fuzz it.

---

## 10. Key Risks & Open Questions

| Risk | Impact | Mitigation / decision needed |
|---|---|---|
| **`libsignal` is AGPLv3** | Affects licensing of the whole app and any forks. | **Decided (Phase 0):** project adopts AGPLv3 project-wide. See `LICENSE` and `CONTRIBUTING.md` for the decision, the network-use obligation on the relay, and the flagged App Store distribution risk for the iOS client. |
| **Spam/abuse without phone-number identity** | Open relays invite spam. | Proof-of-work on first contact + relay rate limiting (own story). |
| **Web key storage weakness** | Lower security on web than mobile/desktop. | Documented reduced threat model + in-app warning; consider passkey/WebAuthn-bound storage. |
| **Multi-device history sync** | Hard without a server. | v1 = per-device history + encrypted backup migration; full sync is a later epic. |
| **Offline prekey exhaustion** | New sessions fail if one-time prekeys run out. | Auto-replenish + signed-prekey fallback. |
| **Group scaling (Sender Keys)** | Fan-out cost grows with members×devices. | Size v1 for private groups; revisit MLS if large-group need emerges. |
| **Metadata via DHT participation** | DHT activity can leak presence/social graph. | Sealed Sender, padding, optional Tor transport in Phase 9. |

---

*Derived from `e2e_decentralized_chat_summary.md` and governed by `CLAUDE.md`. Last updated: 2026-06-22.*
