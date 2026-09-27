# Web client

## Build prerequisites

The web client consumes the shared Rust core via WASM bindings (`core/bindings/wasm`). Building and running the client requires:

* **Rust** with the `wasm32-unknown-unknown` target installed (e.g., `rustup target add wasm32-unknown-unknown`).
* **wasm-pack** (installed via npm or Cargo). The build scripts invoke `wasm-pack build --target bundler` to generate ES‑module bindings.

These prerequisites are only needed for local development and CI builds; the published NPM package does not contain the generated WASM artifacts.

## Setup

```sh
npm install
```

## Build the WASM bindings

`npm run dev`, `npm run build`, and `npm test` all invoke this automatically via a
`prepare-wasm` pre-step, so you normally don't need to run it by hand:

```sh
npm run prepare-wasm
```

This runs `wasm-pack build --target bundler` against `core/bindings/wasm` and writes
the generated ES-module bindings to `pkg/` (gitignored, regenerated on demand).

## Run the dev server

```sh
npm run dev
```

## Run the test suite

```sh
npm test
```

Runs the Vitest suite (`vitest run`) after regenerating the WASM bindings.

## Build for production

```sh
npm run build
```

This writes a self-contained static bundle to `dist/` (`index.html` + JS + CSS +
the `.wasm` binary + fonts). The production build targets ES2022 (Chrome 94+,
Firefox 93+, Safari 15.4+) — a lower target makes `vite-plugin-top-level-await`
try to downlevel the wasm-bindgen glue's destructuring, which esbuild cannot do.

## Run a prebuilt artifact (no build from source)

CI builds `dist/` on every push and pull request and uploads it as a workflow
artifact named `web-client-dist` (downloadable from the Actions run page).
Version tags (`v*`)
also attach a `web-client-dist.zip` to the corresponding GitHub Release, so you
can run the client without installing Rust, wasm-pack, or Node:

1. Download `web-client-dist.zip` from the release and unzip it.
2. Serve the folder over HTTP — any static server works, e.g.:
   ```sh
   npx serve web-client-dist
   # or: python3 -m http.server -d web-client-dist 8000
   ```
3. Open the printed URL and point the client at your relay. The left rail has a
   **Relay URL** field — enter your relay's `ws://` or `wss://` address and click
   **Apply**. (You can also set it from the console:
   `localStorage.setItem('relayWsUrl', 'ws://my-relay.example:8000')`.)

**The artifact must be served over HTTP.** Opening `index.html` via `file://`
will not work — browsers block WASM instantiation and `fetch()` from `file:`
URLs. No relay URL is baked into the prebuilt artifact, so the same zip works
against any relay; see "Configuring the relay endpoint" below for the full
resolution order.

## Security Headers for Production Hosting

When deploying the static bundle to a web server or CDN, add the following security headers (the exact syntax depends on your host):

- **X‑Content-Type‑Options: nosniff** – prevents MIME‑type sniffing.
- **Referrer‑Policy: no-referrer** – removes referrer information from requests.
- **X‑Frame‑Options: DENY** (or `SAMEORIGIN` if you need framing in the same origin) – protects against click‑jacking.
- **Strict‑Transport‑Security: max-age=31536000; includeSubDomains** – forces HTTPS.
- **Content‑Security‑Policy** – already set via a meta tag, but you can also enforce it as an HTTP header for stricter control.

These headers complement the CSP meta tag and provide additional protection when the client is served from a production environment.

## Limitations

- Identity and messages are stored locally in the browser profile's IndexedDB; they are **not shared across different profiles, devices, or browsers**.
- The web client does **not automatically sync** between multiple devices. Clearing site data (or using a new profile/device) removes the identity and all local message history.
- If you need to preserve your identity when switching browsers/devices, export a backup via the **Backup** tab in the left rail.
  - Export: downloads an encrypted file that contains all stored keys and messages.
  - Import: uploads the file and restores the data atomically.
  - This is the only supported recovery path for lost local storage.
- For more context on the reduced threat model and how it affects multi-device usage, see [PLAN.md §5](../PLAN.md) (the same link-rather-than-restate convention used in `docs/two-machine-testing.md`).

React app consuming the shared Rust core via WASM bindings (`core/bindings/wasm`).
See PLAN.md §5 for the documented reduced threat model on web (no secure enclave).

## Session persistence

The web client persists its cryptographic state in the browser's encrypted
IndexedDB store, so it survives a page reload:

- The identity key is loaded from storage (or generated and persisted on first
  run).
- The receiver session is restored at startup and re-saved after every
  successful decrypt.
- Per-peer sender sessions are saved before each send and restored lazily when
  a peer is next messaged.
- Message history is stored alongside the session state.

Limits that remain: clearing site data or opening the app in another browser or
on another device starts fresh, and a message can still be lost if the tab dies
between the relay handing it over and the save. A failed session save shows a
warning rather than silently continuing.

## Encrypted storage API

Two IndexedDB-backed encrypted storage modules are exported from `src/index.ts`:

### `StorageGate`

Parity with `core/storage` — identity/session/prekey state and message history,
encrypted at rest with AES-256-GCM via WebCrypto, fail-closed on a bad key or
corrupt data.

```ts
import { StorageGate } from '@e2e-decentralized-messaging/web-client';

const gate = new StorageGate({
  indexedDB: window.indexedDB,
  keyBytes: rawKey, // 32-byte AES-256 key
});
await gate.open(); // throws if IndexedDB unavailable or key is wrong length
await gate.put('identity', 'self', { name: 'Alice' });
const val = await gate.get('identity', 'self'); // null if missing, throws on tamper
```

Store names: `'identity' | 'session' | 'prekey' | 'messages'`. The CryptoKey is
imported as non-extractable so raw key material cannot be exfiltrated from JS.

### Safety-number verification (`SafetyNumberVerification`)

The `SafetyNumberVerification` component displays the safety number for a
conversation by calling the WASM `derive_safety_number` binding (real
derivation from the local and remote identity keys — not a placeholder).

**Persistence.** The verified/unverified state is persisted per
`conversationId` via `StorageGate` (encrypted IndexedDB, store `'identity'`,
key `safety-number:<conversationId>`). The stored record includes the remote
identity key (base64) that was present at the time of verification, so it
survives a page reload.

**TOFU (Trust On First Use) handling.** On load, if the current remote
identity key differs from the key stored alongside the last `verified: true`
record, the verified flag is **cleared** and a visible warning
(`role="alert"`) is surfaced — the verified state is never silently carried
forward onto a changed key. The user must explicitly re-verify against the
new safety number.

### `BrowserStorage`

A simpler key/value store that derives its AES-256-GCM key from a password via
PBKDF2 (SHA-256, 100k iterations). Same fail-closed guarantees.

```ts
import { BrowserStorage } from '@e2e-decentralized-messaging/web-client';

const storage = new BrowserStorage('user-password');
await storage.open();
await storage.setItem('identity', { name: 'Alice' });
const val = await storage.getItem('identity'); // null if missing, throws on tamper
await storage.deleteItem('identity');
```

## Configuring the relay endpoint

The web client connects to the relay over WebSocket. The relay URL is **not
hardcoded** — it is resolved at runtime by `getRelayWsUrl()` (in
`src/relay_transport.ts`), with the following priority (highest first):

1. **In-app Relay URL field** — the left rail shows a **Relay URL** input and
   the connection status (Connecting / Connected / Can't reach relay). Enter a
   `ws://` or `wss://` URL and click **Apply** to switch relays at runtime; the
   publish retries with backoff and auto-recovers when the relay becomes
   reachable. Clearing the field resets to the default below. This is the
   recommended way to change the relay. It writes `localStorage["relayWsUrl"]`
   under the hood, so it is exactly the override described next.

2. **`localStorage["relayWsUrl"]`** — runtime override. Set this in the browser
   console or app code to point at a specific relay, e.g.:
   ```js
   localStorage.setItem('relayWsUrl', 'ws://my-relay.example:8000');
   ```
   This takes effect immediately for new connections (no reload needed if the
   transport is re-created).

3. **`VITE_RELAY_WS_URL`** — build-time Vite env var. Set it in `.env` (or
   `.env.production`) before building:
   ```sh
   VITE_RELAY_WS_URL=ws://relay.example.com:8000 npm run build
   ```
   The value is baked into the bundle at build time.

4. **`ws://localhost:8000`** — last-resort development fallback, used only when
   none of the above are set. This is intentionally a dev default, not a
   production assumption.

Both `RelayTransport` (the real wire-protocol client used by `Conversation.tsx`)
and the legacy `websocket_transport.ts` resolve the relay URL through this same
function, so the override applies uniformly.
