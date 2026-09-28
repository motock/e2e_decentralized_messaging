# Threat Model

Status: draft, pending security-engineer sign-off.
Scope: the architecture described in `PLAN.md` — Signal Protocol crypto core (`libsignal`)
over a hybrid P2P + blind-relay transport (`libp2p`, Kademlia DHT, Circuit Relay v2).

This document defines the adversaries we design against, the trust boundaries between
components, and — per component — what is and is not trusted, and what metadata leaks.
It does not re-derive the security properties of the Signal Protocol itself (X3DH/PQXDH,
Double Ratchet, Sender Keys); those are taken as given from upstream `libsignal` and are
out of scope for re-analysis here, except where our integration could weaken them.

---

## 1. Assets

What we are protecting, in priority order:

1. **Message plaintext** — content of 1:1 and group messages.
2. **Long-term identity private keys** — the device's Curve25519 identity keypair (used for
   X3DH/PQXDH key agreement and, via XEdDSA, for signing); compromise is equivalent to full
   impersonation.
3. **Session state** — Double Ratchet chain keys, Sender Keys; compromise breaks forward
   secrecy for affected messages.
4. **Social graph / contact metadata** — who talks to whom, and when.
5. **Presence / liveness** — whether a user is currently online and reachable.
6. **Local message history** — stored ciphertext-derived plaintext at rest on a device.

---

## 2. Adversaries

| Adversary | Capability | Goal |
|---|---|---|
| **Network observer** | Can see all traffic on the wire (ISP, Wi-Fi operator, nation-state passive intercept). Cannot break Noise or TLS-grade crypto, cannot compromise endpoints. | Learn who is communicating with whom, when, and how much; deanonymize users; build a social graph. |
| **Malicious/compromised relay operator** | Runs (or has compromised) a store-and-forward relay node. Sees everything that transits the relay: connection metadata, envelope timing/size, source/destination routing info. Does not have any party's private keys. | Read message content; learn the social graph; selectively drop, delay, duplicate, or reorder messages; deny service. |
| **Malicious DHT peer** | Participates in the Kademlia DHT as one or more node identities (including Sybil nodes). Can answer or poison lookups it is queried for, observe queries routed through it. | Map social graph via query patterns; serve stale/forged prekey bundles to enable impersonation or session-establishment attacks; censor discovery of a target. |
| **Attacker with a lost/stolen device** | Has physical possession of an unlocked or partially-locked device, or extracts its storage. Does not have the user's separate devices or their keys. | Read local message history and session/identity key material; impersonate the user from that device going forward. |
| **Malicious or compromised contact** | A legitimate, verified conversation partner whose account or device has been compromised, or who is acting in bad faith. | Read messages sent to them (unavoidable — they are an intended recipient); attempt to pivot compromise to others (e.g., poison group Sender Key state). |
| **Global passive adversary** | Network observer at internet-backbone scale, correlating timing/volume across many vantage points simultaneously. | De-anonymize via traffic analysis even without reading any single hop's metadata in isolation. |
| **Handle-squatter / discovery-layer impersonator** | Publishes a prekey bundle to the DHT under a handle before the legitimate owner does, or races a republish. Does not have the legitimate owner's identity key. | Get a victim's contacts to establish a session with the attacker's identity instead of the real owner (a TOFU gap at the *discovery* layer, distinct from message-content TOFU). |
| **Compromised primary device (device-linking abuse)** | Has compromised a user's *primary* device specifically (not just any device, see lost/stolen below), and so holds its device-linking signing authority. | Sign and link a rogue device into the account; that rogue device then has standing as a "legitimate" linked device until detected and revoked. Revocation semantics are in `spec/v0.md` §8, but a compromised primary can sign a device list that keeps the rogue device in — see §5.3 and `spec/v0.md` §8.5. |

Out of scope for v1 (acknowledged, not designed against): an adversary who can compel or
backdoor the `libsignal` library itself, and a fully active global adversary capable of
real-time traffic confirmation attacks across the entire relay/DHT network (mitigations for
the latter — padding, mixnet/Tor transport — are tracked as Phase 9 hardening per `PLAN.md` §7
and §10, not v1).

---

## 3. Trust Boundaries

```
┌──────────────┐        ┌───────────────┐        ┌──────────────┐
│  Device A    │  Noise  │  DHT / Relay  │  Noise │   Device B   │
│ (full trust) │◄──────►│ (zero trust)   │◄──────►│ (full trust) │
└──────────────┘        └───────────────┘        └──────────────┘
       │                                                  │
       │            Signal Protocol E2E layer             │
       └──────────────────────────────────────────────────┘
                 (only boundary plaintext crosses)
```

- **Device boundary**: the only place plaintext exists is in memory on the sender's and
  recipient's own devices, and on disk inside the encrypted SQLCipher store. Crossing this
  boundary in any other direction (to a relay, a DHT peer, or another of the user's devices
  without an established session) must never carry plaintext.
- **Network boundary**: every hop outside a device — relay, DHT peer, or transit network —
  is **zero-trust** for content. Noise transport encryption is defense-in-depth on this
  boundary (keeps casual network observers from seeing wire-level metadata they wouldn't
  otherwise need), but the design must hold even if every relay and DHT peer is hostile.
- **Multi-device boundary**: a user's own additional devices are a *separate* trust domain
  from each other until explicitly linked (QR pairing + safety-number confirmation per
  `PLAN.md` §4). An unlinked device has no implicit trust just because it shares an account
  in the future history-sync sense. Unlinking a device revokes it (`spec/v0.md` §8); the
  revoked device's messages are rejected once the signed device-list update is observed.

---

## 4. Per-Layer Trust and Metadata Exposure

### 4.1 Crypto layer (`libsignal`: X3DH/PQXDH, Double Ratchet, Sender Keys, Sealed Sender)

- **Trusted to**: provide confidentiality, integrity, and forward secrecy for message content
  between sessions that have been correctly established and verified; detect tampering or
  replay of ciphertext.
- **Not trusted to**: protect against a compromised endpoint (a device that already has the
  plaintext or the session keys), or against a user skipping safety-number verification.
- **Sealed Sender caveat**: Sealed Sender hides the cryptographic sender field from whoever
  handles the envelope, but it provides no sender *authentication* to that handler and does
  not hide the sender's network identity (source IP / libp2p peer ID at the time it pushes the
  envelope). It is a confidentiality control on one field, not a network-anonymity guarantee —
  see §4.5 and §5.1.
- **Metadata that still leaks at this layer**: message size (padding is a Phase 9 item, not
  v1) and approximate timing of encrypt/decrypt operations to anyone who already has
  ciphertext — i.e., this layer protects *content*, not *traffic shape*.

### 4.2 Protocol layer (session lifecycle, prekey management, envelope format)

- **Trusted to**: correctly bind ciphertext to a specific sender/session and reject malformed
  or out-of-order envelopes safely (fail closed, never fall back to plaintext).
- **Not trusted to**: hide the *existence* of an envelope from anything that handles it in
  transit — envelope headers needed for routing (recipient routing hint, timestamp, size) are
  visible to relays and DHT peers by necessity, even under Sealed Sender (which hides the
  *sender*, not the *recipient* or the *existence* of a message).
- **Metadata exposure**: recipient identity/routing hint, approximate envelope size, delivery
  timestamp are visible to the relay that stores/forwards it. Sender identity is hidden from
  the relay by Sealed Sender, but **not** from the recipient (by design — the recipient must
  decrypt and authenticate the sender).

### 4.3 Storage layer (SQLCipher, local keys/sessions/messages)

- **Trusted to**: keep identity keys, session state, and message history encrypted at rest
  such that the storage file alone (without the passphrase/key) is unreadable.
- **Not trusted to**: protect against an adversary with the device unlocked, with the
  passphrase, or with access to key material held in OS keychain/secure-enclave equivalents
  if those are themselves compromised. This is the layer directly implicated by the
  **lost/stolen device** adversary (§5.3).
- **Metadata exposure**: none to remote parties; locally, file existence/size on disk reveals
  that the app is in use and approximate history volume to anyone with filesystem access who
  lacks the decryption key.

### 4.4 Transport layer (`libp2p`: Noise, QUIC/TCP, Kademlia DHT, Circuit Relay v2, GossipSub)

- **Trusted to**: provide point-to-point confidentiality/integrity against passive network
  observers between any two libp2p endpoints (Noise), and to route/discover peers.
- **Not trusted to**: hide *who is talking to whom* from a relay or DHT peer that is itself
  one of the endpoints in a Noise session — Noise protects the channel, not the participants'
  identities from each other. It is also not trusted to provide anonymity against a global
  passive adversary correlating connection timing across many vantage points (§2, out of
  scope for v1).
- **Metadata exposure**: this is the layer with the largest metadata surface — see §5.1 and
  §5.2 for relay- and DHT-specific detail.

### 4.5 Relay layer (self-hostable store-and-forward node)

- **Trusted to**: store and forward opaque ciphertext envelopes for offline delivery, within
  a bounded TTL, without being able to decrypt them.
- **Explicitly not trusted with**: message content (protected by the E2E layer above it,
  independent of relay behavior) or, ideally, the cryptographic sender field (Sealed Sender).
  A relay is assumed **actively malicious** in this model, not merely curious — see §5.1.
- **Metadata exposure**: recipient routing hint, envelope size/count, connection timing and
  source IP of whoever connects to push/pull envelopes, retention of undelivered envelopes
  for up to the TTL window. Sealed Sender does **not** remove the source IP/peer ID a relay
  observes when a sender pushes an envelope — a relay can still correlate "who connected,
  when, with what envelope size" even though it cannot read the sealed sender-identity field
  inside the envelope. This also means Sealed Sender alone does not stop an abusive sender
  from flooding a relay; abuse control is the separate proof-of-work/rate-limiting item in
  `PLAN.md` §3 and §10.

### 4.55 Web client layer (browser/WASM: reduced threat model)

- **Trusted to**: keep identity keys, session state, and message history encrypted at rest in
  the browser profile's IndexedDB (AES-256-GCM via WebCrypto, fail-closed on a bad key or
  corrupt data), and to derive safety numbers from the real identity keys.
- **Not trusted to**: provide enclave-grade key protection — browsers have no secure enclave,
  so key material in WASM/IndexedDB is weaker than on mobile/desktop. This is the documented
  **reduced threat model** for web (`PLAN.md` §5): the client ships with a clear in-app
  warning about it, shown before first use (`threatModelWarning()` in `clients/web/src/api.ts`).
- **Metadata exposure**: none beyond the transport layers above while messages are in flight;
  locally, the same filesystem/profile risks as §4.3 apply, plus the browser profile itself —
  clearing site data or opening another profile loses identity and history (backup
  export/import is the only recovery path).
- **Status note**: this layer is implemented and covered by the web test suite; the
  *reduced* rating is about the platform's key-storage strength, not about missing features.

### 4.6 DHT layer (Kademlia peer/prekey-bundle discovery)

- **Trusted to**: eventually resolve a lookup for a peer's current address or prekey bundle,
  assuming a quorum of honest nodes along the lookup path.
- **Explicitly not trusted with**: returning a *correct* result without independent
  verification — prekey bundles fetched via the DHT must be authenticated (signed by the
  owning identity key) before use, precisely because DHT peers are untrusted. A query
  response is a hint, not a fact, until cryptographically verified.
- **Metadata exposure**: the identity/handle being looked up is visible to every DHT node on
  the lookup path; query frequency and pattern from a given network vantage point can reveal
  who is trying to reach whom, even without reading any message content. See §5.2.

---

## 5. Adversary Scenarios (acceptance-criteria coverage)

### 5.1 Compromised relay

**Scenario**: a relay operator is malicious from the start, or a legitimate relay is
compromised by an attacker who gains full read/write access to its storage and logic.

- **Cannot do**: decrypt message content (Signal Protocol E2E), determine the sender's
  identity for a Sealed-Sender envelope, forge a valid envelope that the recipient's session
  state will accept (integrity-protected).
- **Can do**: see recipient routing hints, envelope sizes and arrival/pickup timestamps for
  everything it handles; correlate connection source IPs with recipient hints over time to
  build a partial social/usage graph for users who route through it; drop, delay, duplicate,
  or reorder envelopes (availability/integrity-of-delivery attack, not confidentiality); 
  refuse service entirely (DoS against users who depend on that relay).
- **Mitigation already in design**: relays are swappable (§ Locked decisions in `PLAN.md`) —
  a single malicious relay cannot prevent delivery if the client retries via another relay or
  direct P2P. Sealed Sender bounds what a compromised relay learns about the sender. Short
  TTLs bound how long a compromised relay can retain undelivered envelopes.
- **Residual risk / open item**: a relay that is the *only* one a recipient is reachable
  through can still mount a targeted denial-of-service or timing-correlation attack; relay
  diversity is a deployment-level mitigation, not a protocol guarantee, and should be called
  out to operators/users.

### 5.2 Malicious DHT peer

**Scenario**: an attacker controls one or more nodes in the Kademlia DHT, potentially via a
Sybil attack (many node identities) to increase the probability of being on a target's lookup
path.

- **Cannot do**: forge a prekey bundle that passes signature verification against the
  claimed identity key, or silently swap in their own key without that mismatch being
  detectable by a client that checks the signature (this is why prekey bundles **must** be
  signed and verified client-side, not trusted as DHT responses).
- **Can do**: refuse to answer a lookup (censorship of discovery for a specific target, an
  availability attack); return a stale prekey bundle if the legitimate one is past its
  replenishment and the DHT peer is the sole intermediary that hasn't synced the latest
  record (degrades to old-but-still-valid behavior, not key substitution, *if* the client
  verifies signatures); observe the identity/handle being queried, which leaks intent to
  contact that party to anyone running enough Sybil nodes to land on the query path.
- **Mitigation already in design**: signed prekey bundles (the DHT is explicitly "not trusted
  with" returning correct data unverified, §4.6); a sender can fall back to an out-of-band
  invite (QR/link) rather than depending solely on DHT-mediated discovery.
- **Residual risk / open item**: Sybil-driven query-pattern surveillance of the DHT is a
  metadata leak the current design does not fully close; tracked under "Metadata via DHT
  participation" in `PLAN.md` §10 (Sealed Sender, padding, optional Tor transport are Phase 9
  mitigations, not v1).

### 5.3 Lost or stolen device

**Scenario**: an attacker gains physical possession of a device that is locked, partially
locked (e.g., screen lock bypassed but disk not separately encrypted), or fully unlocked.

- **If the device is locked and disk encryption (SQLCipher store + OS-level full-disk
  encryption) is intact and the attacker lacks the unlock credential**: message history,
  session state, and identity keys remain confidential. This is the floor the storage layer
  (§4.3) must guarantee.
- **If the device is unlocked, or the attacker has the unlock credential**: the attacker has
  full access to local message history and can impersonate the user *from that device* going
  forward (send messages, respond in existing sessions) until the compromise is detected and
  the device is unlinked/revoked.
- **Mitigation already in design**: per-device identity keys (§ Multi-Device in `PLAN.md` §4)
  mean a stolen device does not expose the user's *other* devices' keys or sessions —
  blast radius is limited to that one device's sessions and local history. Forward secrecy
  (Double Ratchet) limits exposure of *past* messages even if a current chain key is
  recovered, but does not protect messages already decrypted and stored in local history.
- **Revocation semantics now specified**: the unlink/revoke flow this bullet used to flag as
  unspecified is defined in `spec/v0.md` §8 — unlinking a device revokes its `DeviceAddress`,
  removes its `PreKeyBundle` from the account's `DiscoveryRecord`, tears down existing sessions,
  and rejects its Sealed Sender certificates, propagated as a signed, monotonically versioned
  device list. The wire shapes remain Phase 6 (`PLAN.md` Phase 6) work.
- **Residual risk / open item**: revocation is *eventually consistent*, not instantaneous — a
  peer that has not yet observed the device-list update still accepts the stolen device's
  messages, and the revoked device itself cannot be reached (`spec/v0.md` §8.3, §8.5). Revoking
  the *primary* device is not covered by `spec/v0.md` §8 and is an open item (`spec/v0.md` §7);
  it is the "compromised primary device" adversary in §2 above. Remote wipe is out of scope for a
  server-less design and is documented as a known limitation (`spec/v0.md` §8.5), not silently
  gapped.

### 5.4 Network observer

**Scenario**: a passive adversary observes all traffic on the path between a device and the
relays/DHT/peers it talks to (ISP, Wi-Fi operator, or nation-state passive collection), without
compromising any endpoint.

- **Cannot do**: read message content (E2E encryption) or read Noise-protected transport
  payloads between libp2p endpoints.
- **Can do**: see that a device is communicating, with which IP addresses/relays, at what
  times, how often, and with what approximate volume — i.e., full traffic-analysis metadata
  even though content and most identifiers are encrypted in transit. A sufficiently
  well-positioned observer (e.g., one watching both ends of a conversation) can perform timing
  correlation to link sender and recipient activity even without decrypting Sealed Sender.
- **Mitigation already in design**: Noise transport encryption prevents trivial content/SNI-
  style inspection; Sealed Sender prevents the relay itself (a privileged observer) from
  reading sender identity, which also raises the bar for a network-only observer who would
  otherwise piggyback on relay-visible plaintext metadata.
- **Residual risk / open item**: no traffic padding or cover traffic in v1, so message timing
  and size remain a side channel; optional Tor/mixnet transport is explicitly deferred to
  Phase 9 (`PLAN.md` §7, §10). Until then, a network observer's traffic-analysis capability
  should be stated plainly to users in-app, not implied away by "it's encrypted."

---

## 6. Summary: What Leaks Where

| Layer | Sees content? | Sees sender identity? | Sees recipient identity? | Sees timing/volume? |
|---|---|---|---|---|
| Crypto/Protocol (E2E) | No | No (Sealed Sender) | Necessarily, to route | N/A (this is the layer being measured against) |
| Relay (malicious) | No | No (Sealed Sender) | Yes (routing hint) | Yes |
| DHT peer (malicious) | No | N/A (no message transits the DHT) | Yes (the identity being looked up) | Yes (query timing) |
| Network observer | No | No (Noise + Sealed Sender) | No (Noise), but can correlate via timing | Yes |
| Lost/stolen device (unlocked) | Yes (local history) | Yes (it's the user's own device) | Yes | Yes (local history) |

No layer below the device boundary ever sees message plaintext. The dominant residual risk
across this entire design is **traffic-analysis metadata** (who/when/how-much, not what) —
this is consistent with the "Metadata via DHT participation" risk already flagged in
`PLAN.md` §10 and is the primary motivation for the Phase 9 hardening items (Sealed Sender
already in v1; padding and optional Tor/mixnet transport deferred).

---

## 7. Sign-off

This document requires review and sign-off by the security-engineer persona before the
Phase 0 "Foundations" deliverable is considered complete, per the acceptance criteria for
this story and `CLAUDE.md`'s mandatory security review for changes touching crypto,
identity, transport, or key storage design.

- [ ] Security-engineer review completed
