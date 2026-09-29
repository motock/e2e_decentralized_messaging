//! RD-3: operator-configurable relay store location.
//!
//! Graded through the operator-facing surface — the `relay` binary and its
//! `--store-path <PATH>` flag — so the suite stays agnostic to *how* the path is
//! threaded from the entry point into the WS listener's store (a new
//! `RelayOptions` field, a builder, or a separate entry point are all fine).
//!
//! Requirements pinned here:
//!  1. With no path configured the relay keeps today's in-memory behaviour and
//!     writes no on-disk state (the default must not silently change).
//!  2. With `--store-path` configured the relay creates the store there, and a
//!     restart on the same path reads back what a previous run left behind.
//!  3. An unopenable path (missing parent, or a file that is not a store) fails
//!     closed with a clear error naming the path — never a silent in-memory
//!     fallback. The corrupt-file case also proves the relay really opens the
//!     configured path instead of ignoring it.
//!  4. A relative path resolves predictably, against the process working
//!     directory.
//!  5. `.gitignore` anticipates the state path and the operator guide documents
//!     the flag.
//!
//! RED until the implementation lands: `--store-path` does not exist yet, so the
//! relay ignores it and every assertion below fails.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use relay::store::{Mailbox, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT};

const BIN: &str = env!("CARGO_BIN_EXE_relay");

/// Kills the relay on drop, so a failing assertion never leaves a stray process.
struct RelayProc(Child);

impl Drop for RelayProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("relay-store-path-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Reserve an ephemeral localhost port (bind + drop; a small TOCTOU race, as
/// elsewhere in this suite).
fn ephemeral_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn relay_args(ws_port: u16, store_path: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--listen".into(),
        "/ip4/127.0.0.1/tcp/0".into(),
        "--ws-listen".into(),
        format!("127.0.0.1:{ws_port}"),
    ];
    if let Some(path) = store_path {
        args.push("--store-path".into());
        args.push(path.into());
    }
    args
}

fn spawn_relay(args: &[String], cwd: Option<&Path>) -> RelayProc {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    RelayProc(cmd.spawn().expect("spawn the relay binary"))
}

/// Wait until the relay's WS listener accepts a TCP connection.
fn wait_for_ws(port: u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..200 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("relay WS listener never came up on {addr}");
}

fn wait_for_path(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("store path {} was never created", path.display());
}

fn wait_for_exit(proc: &mut RelayProc, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = proc.0.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Only safe once the process has exited (the pipe is drained to EOF).
fn stderr_of(proc: &mut RelayProc) -> String {
    let mut out = String::new();
    if let Some(mut err) = proc.0.stderr.take() {
        let _ = err.read_to_string(&mut out);
    }
    out
}

// ── 1. default stays in-memory ───────────────────────────────────────────────

#[test]
fn no_store_path_keeps_the_relay_in_memory() {
    let dir = temp_dir("default");
    let port = ephemeral_port();
    let proc = spawn_relay(&relay_args(port, None), Some(&dir));
    wait_for_ws(port);

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    drop(proc);

    assert!(
        entries.is_empty(),
        "without --store-path the relay must keep today's in-memory behaviour and write no \
         on-disk state; found {entries:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── 2. configured path: created, and read back across a restart ──────────────

#[test]
fn configured_store_path_is_created_and_read_back_across_a_restart() {
    let dir = temp_dir("configured");
    let store = dir.join("relay-store");
    let store_arg = store.to_str().unwrap();
    assert!(!store.exists(), "precondition: the store does not exist yet");

    let port = ephemeral_port();
    let proc = spawn_relay(&relay_args(port, Some(store_arg)), None);
    wait_for_ws(port);
    wait_for_path(&store);
    drop(proc);

    assert!(
        store.is_file(),
        "the relay must create the store at the configured --store-path"
    );

    // A previous run left an undelivered envelope behind.
    {
        let mb = Mailbox::open(&store, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT)
            .expect("the relay must leave a readable store at the configured path");
        mb.enqueue("alice", b"persisted".to_vec(), Duration::from_secs(3600))
            .unwrap();
    }

    // Restart on the same path: the relay must reuse the store, not clobber it.
    let port2 = ephemeral_port();
    let proc = spawn_relay(&relay_args(port2, Some(store_arg)), None);
    wait_for_ws(port2);
    drop(proc);

    let mb = Mailbox::open(&store, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT).unwrap();
    assert_eq!(
        mb.dequeue("alice").unwrap(),
        b"persisted",
        "a restart on the configured store path must read back what was already there"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── 3. negative: fail closed, never a silent in-memory fallback ──────────────

#[test]
fn store_path_with_a_missing_parent_fails_closed_with_a_clear_error() {
    let dir = temp_dir("missing-parent");
    let store = dir.join("no-such-dir").join("relay-store");
    let port = ephemeral_port();

    let mut proc = spawn_relay(&relay_args(port, Some(store.to_str().unwrap())), None);
    let status = wait_for_exit(&mut proc, Duration::from_secs(20));
    if status.is_none() {
        panic!("the relay must fail closed on an unopenable store path, not hang");
    }
    let stderr = stderr_of(&mut proc);
    let status = status.unwrap();

    assert!(
        !status.success(),
        "an unopenable store path must exit non-zero rather than fall back to memory; \
         stderr: {stderr}"
    );
    assert!(
        stderr.contains("relay-store"),
        "the failure must be a clear error naming the store path it could not open; \
         stderr: {stderr}"
    );
    assert!(
        !store.exists(),
        "no store may be created at an unopenable path"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn store_path_that_is_not_a_store_fails_closed() {
    let dir = temp_dir("corrupt");
    let store = dir.join("relay-store");
    std::fs::write(&store, b"this is not a sqlite database").unwrap();
    let port = ephemeral_port();

    let mut proc = spawn_relay(&relay_args(port, Some(store.to_str().unwrap())), None);
    let status = wait_for_exit(&mut proc, Duration::from_secs(20));
    if status.is_none() {
        panic!("the relay must fail closed on a corrupt store file, not hang");
    }
    let stderr = stderr_of(&mut proc);
    let status = status.unwrap();

    assert!(
        !status.success(),
        "the relay must actually open the configured store path and fail closed on a file that \
         is not a store; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "the failure must come from opening the configured store, not from the flag being \
         unrecognised; stderr: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── 4. relative paths resolve against the working directory ──────────────────

#[test]
fn relative_store_path_resolves_against_the_working_directory() {
    let dir = temp_dir("relative");
    let rel = "relay-store-relative";
    let port = ephemeral_port();

    let proc = spawn_relay(&relay_args(port, Some(rel)), Some(&dir));
    wait_for_ws(port);
    wait_for_path(&dir.join(rel));
    drop(proc);

    assert!(
        dir.join(rel).is_file(),
        "a relative --store-path must resolve against the process working directory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── 5. CLI surface, .gitignore and operator docs ─────────────────────────────

#[test]
fn relay_binary_documents_the_store_path_flag() {
    let out = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("run `relay --help`");
    assert!(out.status.success(), "`relay --help` must succeed");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--store-path"),
        "`relay --help` must document the new --store-path flag; got:\n{help}"
    );
}

#[test]
fn gitignore_and_operator_docs_anticipate_the_state_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();

    let gitignore = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    assert!(
        gitignore.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("relay") && (line.contains("state") || line.contains("store"))
        }),
        ".gitignore must anticipate the relay state path; got:\n{gitignore}"
    );

    let docs = std::fs::read_to_string(root.join("docs/two-machine-testing.md")).unwrap();
    assert!(
        docs.contains("--store-path"),
        "docs/two-machine-testing.md must document the new --store-path flag"
    );
}
