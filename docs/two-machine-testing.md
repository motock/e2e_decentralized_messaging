# Two-machine operator guide: exchange a verified encrypted message

This guide walks two people — each on their own machine — through setting up
the web client, self-hosting a relay, finding each other's recipient ID,
sending a first encrypted message, and verifying the safety number out of
band. If you don't have two physical machines, you can approximate the setup
with two browser profiles or two incognito windows on the same machine (see
[Same-machine approximation](#same-machine-approximation) below).

> **What you need:** two machines (or two browser profiles), the ability to
> run `cargo` and `npm` on at least one of them, and a way to share a short
> string out of band (e.g. read it over the phone).

---

## 1. Build and serve the web client

The web client is a Vite + React app that consumes the shared Rust core via
WASM bindings. Prerequisites (on the machine that will serve the client):

- **Rust** with the `wasm32-unknown-unknown` target:
  `rustup target add wasm32-unknown-unknown`
- **wasm-pack** (installed via npm or Cargo — the build scripts invoke it
  automatically).
- **Node.js** and npm.

### Install dependencies

```sh
cd clients/web
npm install
```

### Option A — dev server (simplest, good for testing)

The dev server regenerates the WASM bindings automatically (via a
`prepare-wasm` pre-step), so you don't need to build them by hand:

```sh
npm run dev -- --host 0.0.0.0 --port 5173
```

`--host 0.0.0.0` makes the server reachable from other machines on your LAN
(not just `localhost`). Vite prints the local network URL — note it; you'll
open it in the browser on each machine.

### Option B — production build + preview

```sh
npm run build
npx vite preview --host 0.0.0.0 --port 4173
```

`npm run build` produces a static bundle in `clients/web/dist/`. `vite preview`
serves it. As with the dev server, `--host 0.0.0.0` exposes it on the LAN.

### Open the client on each machine

On **each** of the two machines, open a browser to the URL Vite printed
(e.g. `http://192.168.1.50:5173`). The app loads, generates a fresh identity
on first visit, and publishes a prekey bundle to the relay (see step 2).

> **Browser key storage:** each browser profile generates its own identity
> and stores it in IndexedDB. Two incognito windows on the same machine are
> independent identities, just like two separate machines. See
> [Same-machine approximation](#same-machine-approximation).

---

## 2. Self-host the relay with `--ws-listen`

The web client talks to a relay over WebSocket. The relay is a standalone
Rust binary in `relay/`. By default it runs only the libp2p Circuit Relay v2
listener; the WebSocket bridge — which browsers need — is **opt-in** and must
be explicitly enabled with `--ws-listen`.

### Build and run the relay

On the machine that will host the relay (this can be one of the two
messaging machines or a third machine on the same LAN):

```sh
cargo run -p relay -- --listen /ip4/0.0.0.0/tcp/4001 --ws-listen 0.0.0.0:8000
```

This starts:

- The libp2p relay on TCP port 4001 (not used by the web client, but
  required by the binary).
- The WebSocket bridge on `0.0.0.0:8000` — the address browsers connect to.

You should see log lines like:

```
relay node started …
ws relay listener started addr=0.0.0.0:8000
```

### Point the web client at your relay

The web client resolves the relay WebSocket URL at runtime via
`getRelayWsUrl()` (in `clients/web/src/relay_transport.ts`), with this
priority (highest first):

1. **`localStorage["relayWsUrl"]`** — runtime override, set in the browser
   console:
   ```js
   localStorage.setItem('relayWsUrl', 'ws://192.168.1.50:8000');
   ```
2. **`VITE_RELAY_WS_URL`** — build-time Vite env var:
   ```sh
   VITE_RELAY_WS_URL=ws://192.168.1.50:8000 npm run build
   ```
3. **`ws://localhost:8000`** — last-resort development fallback.

For two-machine testing, the simplest approach is to open the browser
console on each machine and set the `localStorage` override to the relay's
**LAN IP** address:

```js
localStorage.setItem('relayWsUrl', 'ws://<relay-LAN-IP>:8000');
```

Then reload the page. The app will connect to your relay on the next
operation.

### LAN IP vs public hostname

Use the relay's **LAN IP** (e.g. `192.168.1.50`) when both machines are on
the same network. If the machines are on different networks, you'll need a
publicly reachable hostname or IP, and you must consider TLS (below).

### ⚠️ Known limitation: browsers on a non-localhost origin may require `wss://` (TLS)

Modern browsers block **insecure** WebSocket connections (`ws://`) from
pages served over HTTPS, and some block `ws://` connections from
non-`localhost` origins even over HTTP depending on browser settings and
mixed-content policies.

**What works today (verified):**

- The web client served over **HTTP** from a LAN IP, connecting to the relay
  over **`ws://`** on the same LAN. This is the configuration this guide
  describes.

**What does NOT work without additional setup:**

- Serving the web client over **HTTPS** while connecting to the relay over
  `ws://` — the browser will block this as mixed content.
- Connecting to a relay on a **public hostname** over `ws://` from a browser
  that enforces secure-context WebSocket restrictions.

To use the client over HTTPS or across the public internet, you need
**`wss://`** (TLS) on the relay. This requires terminating TLS in front of
the relay (e.g. with a reverse proxy like nginx or Caddy) and pointing the
client at `wss://your-relay.example`. **TLS termination is not provided by
the relay binary or this epic** — it is left to the operator. Until you set
that up, use the HTTP + `ws://` LAN configuration described above.

---

## 3. Find and share your recipient ID

When the app loads, it generates (or loads) your identity and displays your
**recipient ID** in the left-hand navigation rail, under the "You" label. It
looks like a base64 string, e.g.:

```
A3fK9x…(44 characters total)…==
```

The recipient ID is base64 of your 33-byte compressed Curve25519 public
identity key. It is stable across page reloads (the identity is persisted in
encrypted IndexedDB) — the same browser profile always has the same
recipient ID.

### Share it

Click the **Copy** button next to your recipient ID to copy it to the
clipboard. Share it with the other person through any channel (chat, email,
read it over the phone). They will paste it into their client in step 4.

Each person should share their own recipient ID with the other.

---

## 4. Enter a peer's recipient ID and send a first message

1. On your machine, make sure you're on the **Direct** view (click "Direct"
   in the left nav if needed).
2. Paste the other person's recipient ID into the **Recipient ID** input
   field at the top of the conversation panel.
3. Type a message in the text field at the bottom and click **Send**.

What happens behind the scenes:

- The client looks up the peer's prekey bundle on the relay
  (`lookup_prekey`).
- It establishes a Signal Protocol session from that bundle
  (`establish_session_from_bundle`), which verifies the bundle's
  signatures.
- It encrypts the message (`encrypt_message`) and sends the encrypted
  envelope to the relay addressed to the peer's recipient ID
  (`send_envelope`).
- The status line shows "Sent" on success, or an error (e.g. "Peer not
   found" if the peer hasn't published a prekey to this relay yet).

### Receiving a message

The client polls the relay for inbound envelopes every 5 seconds
(`pickup_envelope`). When an envelope arrives, it decrypts it with the
receiver-side session and displays the plaintext. If decryption fails
(tampered or corrupted ciphertext), no plaintext is shown and a visible
warning is displayed instead — the client fails closed.

The relay queues envelopes FIFO per recipient, so messages sent while the
peer is offline are retained in send order rather than overwriting each
other. Each `pickup_envelope` returns and removes the OLDEST queued
envelope, one per call: it reports `NotFound` when the queue is empty and
`Expired` once when only expired envelopes remained (those are discarded,
so the next call reports `NotFound`). A client should therefore keep
polling until it gets `NotFound` to drain a backlog. Each recipient's queue
has a per-recipient cap; once it is reached, further sends are rejected with
`QueueFull` and already-queued envelopes are never dropped to make room.

> **First message timing:** the peer must have already loaded the app
> (publishing their prekey bundle to the relay) before you can send them a
> message. If you see "Peer not found", ask them to open the app and confirm
> their recipient ID is displayed, then try again.

---

## 5. Compare and mark the safety number verified

After you've sent (or received) a first message and a session is
established, the **safety number** appears in the "Verify this conversation"
panel on the right side of the Direct view.

### What the safety number is

The safety number is derived from **both** your local identity key and the
peer's remote identity key (via the WASM `derive_safety_number` binding). It
is a fingerprint that uniquely identifies this conversation's two
participants. Both sides derive the same safety number for the same pair of
identity keys.

### Verify out of band

1. Read your safety number to the other person over a separate channel
   (phone call, in person, etc.).
2. Have them read theirs back. **They should be identical.**
3. If they match, click **Mark as Verified**.
4. The other person does the same on their machine.

### TOFU (Trust On First Use) behavior

The verified state is persisted per conversation (in encrypted IndexedDB)
and survives page reloads. When you mark a conversation verified, the
remote identity key at the time of verification is stored alongside the
verified flag.

On subsequent loads, if the remote identity key has **changed** since you
last verified:

- The verified flag is **automatically cleared**.
- A visible warning is shown: *"Remote identity key changed; safety number
  invalidated."*

This means you must re-verify if the peer's identity changes. The system
never silently carries a verification forward onto a different key.

You can also click **Unverify** at any time to manually clear the verified
state.

---

## 6. Link another device — and revoke it

The **Devices** panel lets you link a second device (or browser profile) to
your identity by scanning a QR code or exchanging a linking code, confirming
the safety number out of band as in step 5. Once the link completes, every
linked device is listed under **Linked devices**.

### Revoking a linked device

If a device is lost, stolen, or retired, revoke it so it can no longer
receive your messages:

1. In the **Linked devices** section, find the device you want to remove.
2. Click **Revoke device &lt;id&gt;** next to it. Nothing is removed yet —
   the client asks for confirmation first.
3. Click **Confirm revoke** to proceed, or **Keep device** to back out.
4. On success the status line reports the device as revoked, it disappears
   from **Linked devices**, and it is excluded from message fan-out from
   that point on.

Guardrails:

- **Last remaining device:** revoking your only linked device is refused
  unless you explicitly confirm the action — the client never locks you out
  silently.
- **Unknown device:** revoking a device id that is not linked fails closed
  with a clear error and changes nothing.
- **Honest status:** a failed revocation is never reported as success — the
  status line shows the error and the device list is unchanged.

---

## 7. Reduced threat model caveat

The web client operates under a **reduced threat model** compared to the
mobile and desktop clients. Browsers lack a secure enclave, and key
material (identity keys, session state, storage encryption keys) lives in
WASM/IndexedDB — which is weaker than native key storage. This is a known,
documented trade-off, not an oversight.

See **[PLAN.md §5](../PLAN.md)** (the "Web caveat" callout) and
**[docs/threat-model.md](threat-model.md)** for the full discussion. The web
client is suitable for testing and for threat models where browser-based
key storage is acceptable; it is not equivalent to the native clients'
security posture.

---

## Same-machine approximation

If you don't have two physical machines, you can use two **incognito
windows** or two **browser profiles** on the same machine. Each incognito
window / profile has its own IndexedDB and `localStorage`, so it generates
an independent identity and recipient ID — exactly like two separate
machines.

Steps:

1. Start the relay with `--ws-listen 0.0.0.0:8000` (or
   `127.0.0.1:8000` — `localhost` is fine here since everything is on one
   machine).
2. Start the web client dev server: `npm run dev` (the default
   `ws://localhost:8000` relay fallback will work without any
   `localStorage` override).
3. Open **two incognito windows** to `http://localhost:5173`.
4. Each window shows its own recipient ID. Follow steps 3–5 above, sharing
   recipient IDs between the two windows.

> **Note:** because the relay fallback is `ws://localhost:8000`, you don't
> need to set `localStorage["relayWsUrl"]` when everything is on localhost.
> If you used `--host 0.0.0.0` for the dev server but are connecting from
> `localhost`, the default still works.

---

## Quick reference: end-to-end checklist

| Step | Action |
|------|--------|
| 1 | `cd clients/web && npm install && npm run dev -- --host 0.0.0.0` |
| 2 | `cargo run -p relay -- --listen /ip4/0.0.0.0/tcp/4001 --ws-listen 0.0.0.0:8000` |
| 3 | On each machine: open the client URL, set `localStorage.setItem('relayWsUrl', 'ws://<relay-ip>:8000')` if not on localhost, reload |
| 4 | Copy your recipient ID from the left rail; share it with the other person |
| 5 | Paste their recipient ID into the Direct view, type a message, click Send |
| 6 | Read the safety number out of band; if both sides match, click "Mark as Verified" |