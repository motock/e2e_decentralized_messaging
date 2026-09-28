# e2e-decentralized-messaging

An open-source, decentralized, end-to-end encrypted messenger built on the real
[Signal Protocol](https://signal.org/docs/) (`libsignal`) — X3DH/PQXDH session setup, the Double
Ratchet, and Sender Keys for groups — over a peer-to-peer transport (`libp2p`) with blind
store-and-forward relays for offline delivery. That paragraph is the **target architecture**;
what is built and tested today is the Rust core, the relay, the WASM/UniFFI bindings, and the
web and desktop clients — the iOS, Android, and scaffolded desktop clients are not implemented
yet (see `PLAN.md` §6.5 for the current-state vs target-state breakdown). See `PLAN.md` for the
full design rationale and `docs/threat-model.md` for the adversary model.

```
┌─────────────────────────────────────────────────────────────┐
│  UI layer (per platform — thin)                              │
│  iOS/SwiftUI · Android/Compose · Desktop/Tauri · Web/React    │
└───────────────▲───────────────────────────────▲──────────────┘
                │ UniFFI bindings                │ WASM
┌───────────────┴───────────────────────────────┴──────────────┐
│  SHARED RUST CORE (the one audited place)                     │
│  Crypto (libsignal) · Protocol/session mgmt · Storage          │
│  (SQLCipher) · Transport (libp2p: Noise, QUIC/TCP, Kademlia    │
│  DHT, Circuit Relay v2, GossipSub)                             │
└───────────────────────────────────────────────────────────────┘
                │                              │
        ┌───────▼────────┐            ┌────────▼────────┐
        │ Peer (direct)  │            │ Blind relay     │
        │ when online    │            │ store-&-forward │
        └────────────────┘            └─────────────────┘
```

No server ever sees plaintext or owns identity; relays are cryptographically blind to content.

## Repository layout

| Path | What it is |
|---|---|
| `core/crypto` | `libsignal`-backed identity keys, sessions, sealed sender |
| `core/protocol` | Session/group (Sender Keys) management and wire format |
| `core/transport` | `libp2p`-based P2P transport: DHT discovery, relay, padding |
| `core/storage` | SQLCipher-backed encrypted-at-rest local store |
| `core/bindings/uniffi` | UniFFI bindings exposing the core to iOS/Android |
| `core/bindings/wasm` | WASM bindings exposing the core to the web client |
| `relay` | Blind store-and-forward relay service |
| `clients/desktop-tauri` | Desktop app (Tauri) — the shipping desktop client |
| `clients/web` | React/TypeScript web client (WASM bridge) |
| `clients/desktop`, `clients/ios`, `clients/android` | Scaffolded, not yet implemented |
| `docs/` | Threat model, dependency pinning rationale, security audit tracker |
| `spec/` | Versioned wire-format specification (protobuf) |

## Local development setup

### Prerequisites
- Rust (stable toolchain) — `rustup toolchain install stable`
- `protoc` (Protocol Buffers compiler) — required to build the `spqr` (Sparse Post-Quantum
  Ratchet) dependency pulled in transitively by `libsignal`.
  - macOS: `brew install protobuf`
  - Debian/Ubuntu: `apt-get install protobuf-compiler`
  - Windows: see the [protobuf releases page](https://github.com/protocolbuffers/protobuf/releases)
- Node.js 22+ and npm — only needed for `clients/web`

### 1. Clone and build the Rust workspace

```sh
git clone <repo-url>
cd e2e_decentralized_messaging
cargo build --workspace --all-targets --locked
```

### 2. Set up the web client (optional, only if working on `clients/web`)

```sh
cd clients/web
npm install
```

### 3. Configure environment variables

No environment variables are required for local development at this stage of the project.

### 4. Run the app

- **Desktop**: `cd clients/desktop-tauri && cargo tauri dev` (requires the
  [Tauri CLI](https://tauri.app/start/prerequisites/))
- **Web / iOS / Android**: not yet implemented — see the per-client `README.md` in each
  `clients/*` directory for status.

## Running tests

This is a multi-project repository: a Cargo workspace plus an independent Node/TypeScript
project (`clients/web`). Run both suites when your change could affect either side of a shared
contract (e.g. the WASM binding surface).

### Rust workspace

```sh
# Build everything, including test binaries
cargo build --workspace --all-targets --locked

# Run all tests
cargo test --workspace --locked

# Formatting (checked in CI; excludes tests/ — see note below)
cargo fmt --all -- --check

# Lints (checked in CI; excludes tests/ — see note below)
cargo clippy --workspace --lib --bins --examples --all-features --locked -- -D warnings

# WASM target build (checked in CI)
cargo build -p wasm-bindings --target wasm32-unknown-unknown --locked
```

> **Note on `tests/*.rs` files:** integration test files under each crate's `tests/` directory
> (plus `docs/audit/findings.rs`) are treated as read-only acceptance fixtures by this project's
> agent pipeline — they encode the acceptance criteria a story must satisfy and must not be
> edited without explicit sign-off. `cargo fmt` and `cargo clippy` are scoped in CI to exclude
> them for that reason; run the full unscoped commands locally if you need to check them, but
> do not auto-fix or reformat them.

### Web client (`clients/web`)

```sh
cd clients/web
npm install
npm test
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request:

| Job | What it checks |
|---|---|
| `test` (ubuntu/macos/windows) | `cargo build --workspace --all-targets --locked` + `cargo test --workspace --locked` |
| `lint` | `cargo fmt --check` and `cargo clippy -D warnings` (both scoped to exclude acceptance-fixture `tests/` files) |
| `wasm32 target build` | `cargo build -p wasm-bindings --target wasm32-unknown-unknown --locked` |
| `web-client` | `npm ci && npm test` in `clients/web` |

All jobs must pass before merging.

## Further reading

- [`PLAN.md`](PLAN.md) — full architecture and phased build plan
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries, trust boundaries, metadata leakage
- [`docs/dependency-versions.md`](docs/dependency-versions.md) — why specific dependency versions/revs are pinned
- [`docs/audit/`](docs/audit) — security audit findings tracker
- [`spec/`](spec) — versioned wire-format specification
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution guidelines
- [`CLAUDE.md`](CLAUDE.md) — engineering standards and AI-agent workflow for this repo
