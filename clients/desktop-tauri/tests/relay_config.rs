//! DT-3: relay address configuration, TLS policy and CSP narrowing.
//!
//! Public interface these tests pin (`clients_desktop_tauri::relay_config`):
//! - `RelaySources { cli: Option<String>, env: Option<String>, config_file: Option<PathBuf>,
//!   allow_insecure_ws: bool }` (derives `Default`: nothing configured, insecure ws NOT allowed)
//! - `resolve_relay_config(&RelaySources) -> Result<RelayConfig, RelayConfigError>`
//!   precedence: cli > env > config file (JSON `{"relay_url": "..."}`); the first source that is
//!   present wins and is the only one validated/read. No source -> `NotConfigured` (no default host).
//! - `validate_relay_url(url: &str, allow_insecure_ws: bool) -> Result<RelayConfig, RelayConfigError>`
//!   wss:// always ok; ws:// only for loopback (127.0.0.0/8 literal, `localhost`, `[::1]`) unless
//!   `allow_insecure_ws`; any other scheme / unparsable / host-less url -> `InvalidUrl`.
//! - `RelayConfig::url() -> &str` (as given), `RelayConfig::origin() -> String`
//!   (`scheme://host[:port]`, no path).
//! - `RelayConfigError::{NotConfigured, InvalidUrl(String), InsecureRemote(String),
//!   InvalidConfigFile(String)}` implementing `Display` (NotConfigured's text mentions "relay").
//! - `content_security_policy(Option<&RelayConfig>) -> String`
//! Also: `RelayClient::connect` must refuse a plain ws:// remote host (returns Err, no dial).

use std::path::PathBuf;
use std::time::Duration;

use clients_desktop_tauri::relay_client::RelayClient;
use clients_desktop_tauri::relay_config::{
    content_security_policy, resolve_relay_config, sources_from_args_and_env, validate_relay_url,
    RelayConfigError, RelayConfigState, RelaySources, RELAY_URL_ENV,
};

fn config_file(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dt3-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, body).unwrap();
    path
}

fn sources(cli: Option<&str>, env: Option<&str>, file: Option<PathBuf>) -> RelaySources {
    RelaySources {
        cli: cli.map(String::from),
        env: env.map(String::from),
        config_file: file,
        ..Default::default()
    }
}

#[test]
fn should_fail_closed_when_nothing_is_configured() {
    let err = resolve_relay_config(&RelaySources::default()).unwrap_err();
    assert!(matches!(err, RelayConfigError::NotConfigured));
    assert!(err.to_string().to_lowercase().contains("relay"));
}

#[test]
fn should_prefer_cli_over_env_and_file() {
    let file = config_file("prec1", r#"{"relay_url":"wss://file.example.com"}"#);
    let cfg = resolve_relay_config(&sources(
        Some("wss://cli.example.com"),
        Some("wss://env.example.com"),
        Some(file),
    ))
    .unwrap();
    assert_eq!(cfg.url(), "wss://cli.example.com");
}

#[test]
fn should_prefer_env_over_file() {
    let file = config_file("prec2", r#"{"relay_url":"wss://file.example.com"}"#);
    let cfg =
        resolve_relay_config(&sources(None, Some("wss://env.example.com"), Some(file))).unwrap();
    assert_eq!(cfg.url(), "wss://env.example.com");
}

#[test]
fn should_read_the_config_file_when_it_is_the_only_source() {
    let file = config_file("only", r#"{"relay_url":"wss://file.example.com"}"#);
    let cfg = resolve_relay_config(&sources(None, None, Some(file))).unwrap();
    assert_eq!(cfg.url(), "wss://file.example.com");
}

#[test]
fn should_not_fall_through_to_a_lower_source_when_the_higher_one_is_invalid() {
    let err = resolve_relay_config(&sources(
        Some("http://cli.example.com"),
        Some("wss://env.example.com"),
        None,
    ))
    .unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidUrl(_)));
}

#[test]
fn should_reject_a_malformed_config_file() {
    let file = config_file("bad", "not json");
    let err = resolve_relay_config(&sources(None, None, Some(file))).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidConfigFile(_)));
}

#[test]
fn should_reject_a_config_file_without_relay_url() {
    let file = config_file("nokey", "{}");
    let err = resolve_relay_config(&sources(None, None, Some(file))).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidConfigFile(_)));
}

#[test]
fn should_reject_a_missing_config_file() {
    let missing = std::env::temp_dir().join("dt3-definitely-missing/config.json");
    let err = resolve_relay_config(&sources(None, None, Some(missing))).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidConfigFile(_)));
}

#[test]
fn should_accept_wss_url() {
    assert!(validate_relay_url("wss://relay.example.com", false).is_ok());
}

#[test]
fn should_reject_plain_ws_to_a_remote_host_by_default() {
    let err = validate_relay_url("ws://relay.example.com", false).unwrap_err();
    assert!(matches!(err, RelayConfigError::InsecureRemote(_)));
}

#[test]
fn should_allow_plain_ws_to_a_remote_host_with_explicit_opt_in() {
    assert!(validate_relay_url("ws://relay.example.com", true).is_ok());
}

#[test]
fn should_allow_plain_ws_to_ipv4_loopback() {
    assert!(validate_relay_url("ws://127.0.0.1:8000", false).is_ok());
}

#[test]
fn should_allow_plain_ws_to_localhost() {
    assert!(validate_relay_url("ws://localhost:8000", false).is_ok());
}

#[test]
fn should_allow_plain_ws_to_ipv6_loopback() {
    assert!(validate_relay_url("ws://[::1]:8000", false).is_ok());
}

#[test]
fn should_not_treat_a_lookalike_hostname_as_loopback() {
    let err = validate_relay_url("ws://127.0.0.1.evil.example.com", false).unwrap_err();
    assert!(matches!(err, RelayConfigError::InsecureRemote(_)));
}

#[test]
fn should_not_treat_userinfo_loopback_as_the_host() {
    let err = validate_relay_url("ws://127.0.0.1@evil.example.com", false).unwrap_err();
    assert!(matches!(err, RelayConfigError::InsecureRemote(_)));
}

#[test]
fn should_reject_non_websocket_schemes() {
    let err = validate_relay_url("https://relay.example.com", true).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidUrl(_)));
}

#[test]
fn should_reject_an_empty_url() {
    let err = validate_relay_url("", true).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidUrl(_)));
}

#[test]
fn should_reject_a_url_without_a_host() {
    let err = validate_relay_url("wss://", true).unwrap_err();
    assert!(matches!(err, RelayConfigError::InvalidUrl(_)));
}

#[test]
fn should_report_the_origin_without_path() {
    let cfg = validate_relay_url("wss://relay.example.com:8443/ws/v1", false).unwrap();
    assert_eq!(cfg.origin(), "wss://relay.example.com:8443");
}

#[test]
fn should_allow_only_the_configured_relay_origin_in_connect_src() {
    let cfg = validate_relay_url("wss://relay.example.com:8443/ws", false).unwrap();
    let csp = content_security_policy(Some(&cfg));
    let connect = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("connect-src"))
        .unwrap();
    let sources: Vec<&str> = connect.split_whitespace().skip(1).collect();
    assert!(sources.contains(&"wss://relay.example.com:8443"));
    assert!(sources.contains(&"'self'"));
}

#[test]
fn should_not_open_general_outbound_origins_when_a_relay_is_configured() {
    let cfg = validate_relay_url("wss://relay.example.com", false).unwrap();
    let csp = content_security_policy(Some(&cfg));
    let connect = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("connect-src"))
        .unwrap();
    let sources: Vec<&str> = connect.split_whitespace().skip(1).collect();
    for banned in ["*", "ws:", "wss:", "http:", "https:", "data:"] {
        assert!(
            !sources.contains(&banned),
            "connect-src must not contain {banned}"
        );
    }
}

#[test]
fn should_not_allow_any_websocket_origin_when_no_relay_is_configured() {
    let csp = content_security_policy(None);
    assert!(!csp.contains("ws:") && !csp.contains("wss:") && !csp.contains('*'));
}

#[test]
fn should_keep_default_src_locked_down_with_a_relay_configured() {
    let cfg = validate_relay_url("wss://relay.example.com", false).unwrap();
    assert!(content_security_policy(Some(&cfg)).contains("default-src 'self'"));
}

#[test]
fn should_ship_a_tauri_conf_csp_with_no_hardcoded_relay_or_wildcard() {
    let conf =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&conf).unwrap();
    let csp = json["app"]["security"]["csp"].as_str().unwrap();
    assert!(!csp.contains("ws:") && !csp.contains("wss:") && !csp.contains('*'));
}

#[test]
fn should_grant_no_wildcard_capability_permissions() {
    let caps = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capabilities/default.json"
    ))
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&caps).unwrap();
    let wildcard = json["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p.as_str())
        .any(|p| p == "*" || p.ends_with(":allow-all"));
    assert!(!wildcard);
}

#[test]
fn should_enable_a_rustls_tls_feature_on_tokio_tungstenite_and_not_native_tls() {
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let deps = manifest.split("[dev-dependencies]").next().unwrap();
    let line = deps
        .lines()
        .find(|l| l.trim_start().starts_with("tokio-tungstenite"))
        .unwrap();
    assert!(line.contains("rustls-tls-webpki-roots"), "got: {line}");
    assert!(!line.contains("native-tls"));
}

#[tokio::test]
async fn should_refuse_to_dial_a_plain_ws_remote_host() {
    // 192.0.2.1 is TEST-NET-1 (blackhole): an unvalidated dial would hang past the bound.
    let attempt = tokio::time::timeout(
        Duration::from_secs(3),
        RelayClient::connect("ws://192.0.2.1:9"),
    )
    .await;
    assert!(attempt
        .expect("connect must reject up front, not dial")
        .is_err());
}

// ---------------------------------------------------------------------------
// Process-level wiring: the shell must actually read the documented sources.
// ---------------------------------------------------------------------------

fn no_env(_: &str) -> Option<String> {
    None
}

fn env_with(url: &'static str) -> impl Fn(&str) -> Option<String> {
    move |name| (name == RELAY_URL_ENV).then(|| url.to_string())
}

#[test]
fn should_read_the_relay_url_from_a_space_separated_argument() {
    let sources = sources_from_args_and_env(["--relay-url", "wss://cli.example.com"], no_env);
    assert_eq!(sources.cli.as_deref(), Some("wss://cli.example.com"));
}

#[test]
fn should_read_the_relay_url_from_an_equals_form_argument() {
    let sources = sources_from_args_and_env(["--relay-url=wss://cli.example.com"], no_env);
    assert_eq!(sources.cli.as_deref(), Some("wss://cli.example.com"));
}

#[test]
fn should_read_the_relay_url_from_the_environment_when_no_flag_is_present() {
    let sources = sources_from_args_and_env(
        std::iter::empty::<&str>(),
        env_with("wss://env.example.com"),
    );
    assert_eq!(sources.env.as_deref(), Some("wss://env.example.com"));
}

#[test]
fn should_prefer_the_cli_url_over_the_environment_in_the_resolved_config() {
    let sources = sources_from_args_and_env(
        ["--relay-url", "wss://cli.example.com"],
        env_with("wss://env.example.com"),
    );
    assert_eq!(
        resolve_relay_config(&sources).unwrap().url(),
        "wss://cli.example.com"
    );
}

#[test]
fn should_read_the_config_file_path_from_its_flag() {
    let sources = sources_from_args_and_env(["--relay-config", "/etc/e2e/relay.json"], no_env);
    assert_eq!(
        sources.config_file,
        Some(PathBuf::from("/etc/e2e/relay.json"))
    );
}

#[test]
fn should_enable_insecure_ws_only_when_the_flag_is_present() {
    let without = sources_from_args_and_env(std::iter::empty::<&str>(), no_env);
    let with = sources_from_args_and_env(["--allow-insecure-ws"], no_env);
    assert!(!without.allow_insecure_ws);
    assert!(with.allow_insecure_ws);
}

#[test]
fn should_ignore_unknown_arguments() {
    let sources = sources_from_args_and_env(
        [
            "--unrelated",
            "value",
            "--relay-url",
            "wss://cli.example.com",
        ],
        no_env,
    );
    assert_eq!(sources.cli.as_deref(), Some("wss://cli.example.com"));
}

#[test]
fn should_treat_an_empty_cli_value_as_unset_and_fall_through_to_the_environment() {
    let sources = sources_from_args_and_env(["--relay-url", ""], env_with("wss://env.example.com"));
    assert_eq!(
        resolve_relay_config(&sources).unwrap().url(),
        "wss://env.example.com"
    );
}

#[test]
fn should_hold_the_resolved_address_in_startup_state() {
    let state = RelayConfigState::resolve(sources_from_args_and_env(
        ["--relay-url", "wss://relay.example.com:8443"],
        no_env,
    ));
    assert_eq!(
        state.require().unwrap().origin(),
        "wss://relay.example.com:8443"
    );
    assert!(state.error().is_none());
}

#[test]
fn should_fail_closed_through_startup_state_when_nothing_is_configured() {
    let state = RelayConfigState::resolve(RelaySources::default());
    assert!(state.config().is_none());
    let error = state.require().unwrap_err();
    assert!(matches!(error, RelayConfigError::NotConfigured));
    assert!(error.to_string().to_lowercase().contains("relay"));
}

#[test]
fn should_keep_a_resolution_failure_in_startup_state() {
    let state = RelayConfigState::resolve(sources_from_args_and_env(
        ["--relay-url", "http://not-a-websocket.example.com"],
        no_env,
    ));
    assert!(state.config().is_none());
    assert!(matches!(
        state.require(),
        Err(RelayConfigError::InvalidUrl(_))
    ));
}
