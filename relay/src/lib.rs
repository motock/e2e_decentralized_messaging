//! Circuit Relay v2 server behaviour and swarm builder.
//!
//! The relay node provides a rendezvous point for NAT-traversal-resistant peers.
//! It implements the libp2p Circuit Relay v2 server protocol: peers that cannot
//! accept inbound connections make a **reservation** at the relay; other peers then
//! open a proxied **circuit** through the relay to reach them.
//!
//! Defence-in-depth note: the relay is deliberately blind — it forwards encrypted
//! streams between peers without being able to read or modify the Signal Protocol
//! E2E content.

use crate::store::{Mailbox, RelayStore, StoreError, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT};
use libp2p::{
    futures::StreamExt, identity::Keypair, noise, ping, relay, swarm::SwarmEvent, tcp, yamux,
    Multiaddr, Swarm, SwarmBuilder,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub mod pow;
pub mod ratelimit;
pub mod store;
pub mod ws;

/// Combined network behaviour for the relay node: Circuit Relay v2 server + ping liveness.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct RelayBehaviour {
    pub relay: relay::Behaviour,
    pub ping: ping::Behaviour,
}

/// Builds a [`Swarm`] configured as a Circuit Relay v2 **server**.
///
/// Transport: TCP + Noise XX + Yamux (same stack as `core/transport`).
/// Behaviour: [`relay::Behaviour`] in server mode, plus [`ping::Behaviour`] for liveness.
pub fn build_relay_swarm(
    keypair: Keypair,
) -> Result<Swarm<RelayBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            Ok(RelayBehaviour {
                relay: relay::Behaviour::new(peer_id, relay::Config::default()),
                ping: ping::Behaviour::default(),
            })
        })?
        .build();
    Ok(swarm)
}

/// Resolve a configured store path ONCE, at startup.
///
/// A relative path is anchored to the process working directory so a later
/// working-directory change cannot silently split the store across two
/// locations. An existing path is canonicalized; a not-yet-existing store file
/// (first run) is anchored to the current directory instead.
fn resolve_store_path(path: &Path) -> Result<PathBuf, StoreError> {
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(path))
                    .map_err(|e| StoreError::Io(e.to_string()))
            }
        }
        Err(e) => Err(StoreError::Io(format!(
            "cannot resolve store path {}: {e}",
            path.display()
        ))),
    }
}

/// Options for [`run_relay`].
pub struct RelayOptions {
    /// Multiaddr for the libp2p (Circuit Relay v2) listener.
    pub listen: Multiaddr,
    /// If `Some`, start the WebSocket bridge on this address.
    ///
    /// The WS bridge is **opt-in** (secure-by-default): it is only started when
    /// the operator explicitly passes `--ws-listen` on the command line. This
    /// follows the repo's CLAUDE.md requirement that new endpoints ship
    /// locked-down by default.
    pub ws_listen: Option<SocketAddr>,
    /// Per-identity rate limit (requests/minute) for the WS bridge. Ignored when
    /// `ws_listen` is `None`.
    pub ws_rate_limit_per_minute: u32,
}

/// Run the relay node: the libp2p swarm event loop and, optionally, the WS
/// bridge concurrently.
///
/// The WS bridge (if enabled) is spawned on its own tokio task so it never
/// blocks the swarm event loop and vice-versa. This function runs until the
/// swarm event loop ends (which, in normal operation, is never).
///
/// Returns an error if the libp2p listener cannot bind or if the WS listener
/// cannot bind (e.g. port already in use) — the latter surfaces as a clear
/// startup error rather than a silent hang.
pub async fn run_relay(
    options: RelayOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_relay_with_store(options, None).await
}

/// Run the relay node with an explicit durable-store location for the WS bridge.
///
/// This is RD-3's operator-facing entry point: `store_path: Some(path)` opts in
/// to on-disk durability (the store is opened — or created — at `path` before
/// the listener serves, and an unopenable path fails the process closed rather
/// than silently falling back to memory); `None` keeps the historical in-memory
/// behaviour. A relative path is resolved against the process working directory
/// at startup.
///
/// The store is opened synchronously here (not inside the spawned listener
/// task) so a bad path is a hard startup failure with a non-zero exit, never a
/// silent in-memory fallback.
pub async fn run_relay_with_store(
    options: RelayOptions,
    store_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Open the store eagerly, before anything is spawned, so a bad path fails
    // closed with a clear error. The opened handles are then handed to the
    // listener, which shares them across every accepted connection.
    // Ordering matters: the store is opened BEFORE the WS port is bound, so an
    // unopenable path never exposes a listening socket and the store file
    // always exists by the time any client can connect to the bridge.
    let ws = match options.ws_listen {
        Some(ws_addr) => {
            let (mailbox, prekeys) = match store_path.as_deref() {
                None => (
                    Mailbox::new(DEFAULT_MAX_ENVELOPES_PER_RECIPIENT),
                    RelayStore::new(),
                ),
                Some(path) => {
                    let resolved = resolve_store_path(path)?;
                    info!("ws: opening durable store at the configured --store-path");
                    (
                        Mailbox::open(&resolved, DEFAULT_MAX_ENVELOPES_PER_RECIPIENT)?,
                        RelayStore::open(&resolved)?,
                    )
                }
            };
            let listener = tokio::net::TcpListener::bind(ws_addr).await?;
            let bound_addr = listener.local_addr()?;
            Some((listener, bound_addr, mailbox, prekeys))
        }
        None => None,
    };

    run_relay_with_stores(options, ws).await
}

/// Like [`run_relay_with_store`], but with the WS-bridge stores already opened.
///
/// `ws` is `Some((listener, bound_addr, mailbox, prekeys))` when the WS bridge
/// is enabled; the listener task is spawned with those shared handles.
async fn run_relay_with_stores(
    options: RelayOptions,
    ws: Option<(tokio::net::TcpListener, SocketAddr, Mailbox, RelayStore)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let keypair = Keypair::generate_ed25519();
    let local_peer_id = keypair.public().to_peer_id();

    let mut swarm = build_relay_swarm(keypair)?;
    swarm.listen_on(options.listen.clone())?;

    info!(peer_id = %local_peer_id, listen = %options.listen, "relay node started");

    // Start the WS bridge on a concurrent task if an address was provided.
    // Binding (and, with a configured store path, the store open) happened
    // synchronously in the entry point above, before the first `accept` await,
    // so a port-in-use or unopenable-store error is returned here (not
    // swallowed).
    if let Some((listener, bound_addr, mailbox, prekeys)) = ws {
        let rate_limit = options.ws_rate_limit_per_minute;
        info!(addr = %bound_addr, "ws relay listener started");
        tokio::spawn(async move {
            if let Err(e) =
                ws::serve_listener_with_stores(listener, rate_limit, mailbox, prekeys).await
            {
                warn!("ws relay listener ended with error: {e}");
            }
        });
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "listening on {}", address);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
                relay::Event::ReservationReqAccepted {
                    src_peer_id,
                    renewed,
                } => {
                    info!(peer = %src_peer_id, renewed, "circuit reservation accepted");
                }
                relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                    info!(peer = %src_peer_id, "circuit reservation denied");
                }
                relay::Event::ReservationTimedOut { src_peer_id } => {
                    info!(peer = %src_peer_id, "circuit reservation timed out");
                }
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                } => {
                    info!(src = %src_peer_id, dst = %dst_peer_id, "circuit accepted");
                }
                relay::Event::CircuitReqDenied {
                    src_peer_id,
                    dst_peer_id,
                    ..
                } => {
                    info!(src = %src_peer_id, dst = %dst_peer_id, "circuit request denied (no reservation)");
                }
                other => {
                    info!("relay event: {:?}", other);
                }
            },
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!(peer = %peer_id, "connection established");
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(err) = cause {
                    warn!(peer = %peer_id, err = %err, "connection closed with error");
                } else {
                    info!(peer = %peer_id, "connection closed");
                }
            }
            _ => {}
        }
    }
}
