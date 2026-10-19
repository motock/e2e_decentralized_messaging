# Desktop Tauri Client

## Prerequisites

* **Rust stable** — 1.82 or newer (the MSRV of the Tauri 2.x line this
  workspace pins, currently 2.11). Install via [rustup](https://rustup.rs/).
* **Tauri CLI** – install once per machine:
  ```sh
  cargo install tauri-cli --version "^2" --locked
  ```
* **Linux system dependencies** (only needed when building on Ubuntu):
  ```sh
  sudo apt-get update
  sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
    libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev patchelf
  ```
  (Windows and macOS do not require these packages.)

## Running the Desktop Client

```sh
# From the repository root
cd clients/desktop-tauri
cargo tauri dev
```

This starts the Tauri development server and launches the desktop window.

## Building the Desktop App

```sh
cd clients/desktop-tauri
cargo tauri build
```

The bundled binaries are placed under `target/release/bundle/` in the
workspace root (e.g. `target/release/bundle/macos/desktop-tauri.app` on macOS,
`target/release/bundle/deb/` on Linux, `target/release/bundle/nsis/` on Windows).

## Relay Configuration

The desktop client reads the relay URL from the following sources (in order of precedence):

1. **CLI flag** `--relay-url`.
2. **Environment variable** `E2E_RELAY_WS_URL`.
3. **JSON config file** specified with `--relay-config`.

See `src-tauri/src/relay_config.rs` for the exact parsing logic.

Plain `ws://` relays are only accepted on loopback hosts (`localhost`,
`127.0.0.0/8`, `[::1]`). To point the client at a plain `ws://` relay on a
non-loopback host — e.g. a relay on another machine on your LAN — pass the
explicit opt-in flag `--allow-insecure-ws`; without it the URL is rejected
with a validation error.

## Running Tests

```sh
cargo test -p clients-desktop-tauri --locked
```

The tests exercise the core logic and the Tauri integration.
