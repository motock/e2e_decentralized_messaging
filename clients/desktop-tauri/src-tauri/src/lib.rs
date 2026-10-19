//! Tauri desktop shell backend — a thin UI layer over the shared Rust core (PLAN.md Phase 5).
//!
//! The shell links directly against `core_crypto`/`core_protocol`/`core_transport` as path
//! dependencies (see `Cargo.toml`); no core logic is reimplemented in Rust, TypeScript, or
//! JavaScript here.

pub mod backup;
mod commands;
mod error;
mod identity_store;
pub mod relay_client;
pub mod relay_config;
pub mod ui;
pub mod verify;

pub use verify::{
    describe_verification_flow_for_user, verify_safety_number, VerificationFlowDoc,
    VerificationState,
};

/// Build and run the Tauri application.
///
/// The relay address is resolved once here, from the process arguments and
/// environment (see [`relay_config::sources_from_args_and_env`]), and held in
/// managed state so every command that dials the relay can read the same
/// validated address. An unconfigured shell still launches — no relay is a
/// valid secure default — and the failure is reported when the relay is used.
pub fn run() {
    let relay = relay_config::RelayConfigState::from_process();
    match relay.require() {
        Ok(config) => eprintln!("relay: configured {}", config.origin()),
        Err(error) => eprintln!("relay: unavailable: {error}"),
    }

    tauri::Builder::default()
        .manage(relay)
        .invoke_handler(tauri::generate_handler![
            commands::generate_identity,
            commands::load_or_create_identity,
            commands::establish_malformed_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the desktop shell");
}
