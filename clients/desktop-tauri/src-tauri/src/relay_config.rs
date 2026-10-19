//! DT-3: relay address configuration, URL validation and CSP derivation.
//!
//! The desktop shell has no browser `localStorage`/`import.meta.env` to read a
//! relay address from (unlike `clients/web/src/relay_transport.ts`), so the
//! address is resolved from explicit sources with a documented precedence that
//! mirrors how the relay itself is configured (`relay/src/main.rs`: CLI flag
//! first, then environment, then a file):
//!
//! 1. CLI (`--relay-url`) — highest precedence.
//! 2. Environment (`E2E_RELAY_WS_URL`).
//! 3. Config file (JSON `{"relay_url": "..."}`).
//!
//! The first source that is present wins and is the *only* one validated/read:
//! a set-but-invalid CLI value is an error, never a silent fall-through to the
//! environment. An empty/whitespace-only value counts as unset.
//!
//! Secure by default: with no source configured this fails closed with
//! [`RelayConfigError::NotConfigured`] — it never defaults to any host,
//! including `127.0.0.1`. Plain `ws://` is accepted only for loopback hosts
//! (`127.0.0.0/8`, `localhost`, `[::1]`) unless the user explicitly opts in to
//! an insecure remote relay, because plain `ws://` exposes recipient IDs and
//! timing to the network (envelope contents stay ciphertext either way).
//!
//! Host checks go through the `url` crate's parsed [`Host`], never string
//! prefix/substring matching: `ws://127.evil.com`, `ws://localhost.evil.com`
//! and `ws://127.0.0.1@evil.com` (userinfo trick — the real host is
//! `evil.com`) are all correctly treated as remote.

use std::fmt;
use std::path::{Path, PathBuf};

use url::{Host, Url};

/// Environment variable consulted when no CLI value is supplied.
pub const RELAY_URL_ENV: &str = "E2E_RELAY_WS_URL";

/// The sources a relay address may come from, in precedence order.
///
/// `Default` means "nothing configured, insecure ws NOT allowed" — the
/// secure-by-default starting point.
#[derive(Debug, Clone, Default)]
pub struct RelaySources {
    /// CLI value (`--relay-url`). Highest precedence.
    pub cli: Option<String>,
    /// Environment value ([`RELAY_URL_ENV`]).
    pub env: Option<String>,
    /// Path to a JSON config file containing `{"relay_url": "..."}`.
    pub config_file: Option<PathBuf>,
    /// Explicit opt-in to a plain `ws://` relay on a non-loopback host.
    pub allow_insecure_ws: bool,
}

/// A validated relay address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    url: String,
    origin: String,
}

impl RelayConfig {
    /// The address exactly as configured.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `scheme://host[:port]` with no path — the only origin a policy needs to
    /// allow to reach this relay.
    pub fn origin(&self) -> String {
        self.origin.clone()
    }
}

/// Why a relay address could not be resolved or accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConfigError {
    /// No source supplied a relay address. Fails closed: there is no default.
    NotConfigured,
    /// The address is unparsable, host-less, or not a `ws`/`wss` URL.
    InvalidUrl(String),
    /// A plain `ws://` URL points at a non-loopback host and the user has not
    /// opted in to an insecure remote relay.
    InsecureRemote(String),
    /// The config file is missing, unreadable, not JSON, or has no
    /// non-empty `relay_url` string.
    InvalidConfigFile(String),
}

impl fmt::Display for RelayConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayConfigError::NotConfigured => write!(
                f,
                "no relay address configured: pass --relay-url, set {RELAY_URL_ENV}, \
                 or provide a config file with a \"relay_url\" entry"
            ),
            RelayConfigError::InvalidUrl(msg) => {
                write!(f, "invalid relay URL: {msg}")
            }
            RelayConfigError::InsecureRemote(msg) => write!(
                f,
                "refusing insecure ws:// relay {msg}: plain ws:// exposes recipient IDs \
                 and timing to the network; use wss:// or explicitly opt in to an \
                 insecure remote relay"
            ),
            RelayConfigError::InvalidConfigFile(msg) => {
                write!(f, "invalid relay config file: {msg}")
            }
        }
    }
}

impl std::error::Error for RelayConfigError {}

/// Resolve the relay address from `sources`, honouring the documented
/// precedence (CLI > env > config file).
///
/// The first present source wins and is the only one validated/read. With no
/// source at all this returns [`RelayConfigError::NotConfigured`] — it never
/// falls back to a default host.
pub fn resolve_relay_config(sources: &RelaySources) -> Result<RelayConfig, RelayConfigError> {
    let raw = if let Some(cli) = non_empty(sources.cli.as_deref()) {
        cli.to_string()
    } else if let Some(env) = non_empty(sources.env.as_deref()) {
        env.to_string()
    } else if let Some(path) = sources.config_file.as_deref() {
        read_config_file(path)?
    } else {
        return Err(RelayConfigError::NotConfigured);
    };

    validate_relay_url(&raw, sources.allow_insecure_ws)
}

/// Validate a relay URL.
///
/// `wss://` is always accepted. `ws://` is accepted only for loopback hosts
/// (`127.0.0.0/8`, `localhost`, `[::1]`) unless `allow_insecure_ws` is set.
/// Every other scheme, an unparsable URL, or a URL without a host is
/// [`RelayConfigError::InvalidUrl`] regardless of the opt-in.
pub fn validate_relay_url(url: &str, allow_insecure_ws: bool) -> Result<RelayConfig, RelayConfigError> {
    let parsed = Url::parse(url).map_err(|e| RelayConfigError::InvalidUrl(format!("{url:?}: {e}")))?;

    let scheme = parsed.scheme();
    if scheme != "ws" && scheme != "wss" {
        return Err(RelayConfigError::InvalidUrl(format!(
            "{url:?}: scheme must be ws:// or wss://, got {scheme}://"
        )));
    }

    let host = parsed
        .host()
        .ok_or_else(|| RelayConfigError::InvalidUrl(format!("{url:?}: missing host")))?;

    if scheme == "ws" && !allow_insecure_ws && !is_loopback(&host) {
        return Err(RelayConfigError::InsecureRemote(url.to_string()));
    }

    let host_str = parsed
        .host_str()
        .ok_or_else(|| RelayConfigError::InvalidUrl(format!("{url:?}: missing host")))?;
    let origin = match parsed.port() {
        Some(port) => format!("{scheme}://{host_str}:{port}"),
        None => format!("{scheme}://{host_str}"),
    };

    Ok(RelayConfig {
        url: url.to_string(),
        origin,
    })
}

/// The Content-Security-Policy the shell should apply.
///
/// The DT-2 relay client dials the WebSocket from Rust (`tokio-tungstenite`),
/// so the CSP does not govern that connection and the shipped policy stays
/// locked down. When a relay is configured its exact origin is added to
/// `connect-src` (never a bare `ws:`/`wss:` scheme, a wildcard, or a general
/// `http(s):` source) so a future frontend-initiated socket to that one relay
/// would be permitted and nothing else.
pub fn content_security_policy(relay: Option<&RelayConfig>) -> String {
    let mut connect = String::from("'self' ipc: http://ipc.localhost");
    if let Some(cfg) = relay {
        connect.push(' ');
        connect.push_str(&cfg.origin());
    }
    format!("default-src 'self'; script-src 'self'; style-src 'self'; connect-src {connect}")
}

/// A value counts as present only if it has non-whitespace content; an empty
/// environment variable is treated as unset and falls through to the next
/// source.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

fn read_config_file(path: &Path) -> Result<String, RelayConfigError> {
    let body = std::fs::read_to_string(path).map_err(|e| {
        RelayConfigError::InvalidConfigFile(format!("{}: {e}", path.display()))
    })?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        RelayConfigError::InvalidConfigFile(format!("{}: not valid JSON: {e}", path.display()))
    })?;
    let url = json
        .get("relay_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            RelayConfigError::InvalidConfigFile(format!(
                "{}: missing non-empty \"relay_url\" string",
                path.display()
            ))
        })?;
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_env_falls_through_to_the_config_file() {
        let dir = std::env::temp_dir().join(format!("dt3-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"relay_url":"wss://file.example.com"}"#).unwrap();

        let sources = RelaySources {
            cli: None,
            env: Some(String::new()),
            config_file: Some(path),
            allow_insecure_ws: false,
        };
        assert_eq!(
            resolve_relay_config(&sources).unwrap().url(),
            "wss://file.example.com"
        );
    }

    #[test]
    fn userinfo_loopback_is_not_the_host() {
        assert!(matches!(
            validate_relay_url("ws://127.0.0.1@evil.example.com", false),
            Err(RelayConfigError::InsecureRemote(_))
        ));
    }

    #[test]
    fn lookalike_hostname_is_not_loopback() {
        assert!(matches!(
            validate_relay_url("ws://127.evil.com", false),
            Err(RelayConfigError::InsecureRemote(_))
        ));
    }

    #[test]
    fn origin_drops_the_path() {
        let cfg = validate_relay_url("wss://relay.example.com:8443/ws/v1", false).unwrap();
        assert_eq!(cfg.origin(), "wss://relay.example.com:8443");
    }
}
