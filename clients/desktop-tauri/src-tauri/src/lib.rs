//! Tauri desktop shell backend — a thin UI layer over the shared Rust core (PLAN.md Phase 5).
//!
//! The shell links directly against `core_crypto`/`core_protocol`/`core_transport` as path
//! dependencies (see `Cargo.toml`); no core logic is reimplemented in Rust, TypeScript, or
//! JavaScript here.

pub mod backup;
mod commands;
mod error;
pub mod ui;
pub mod verify;

pub use verify::{
    describe_verification_flow_for_user, verify_safety_number, VerificationFlowDoc,
    VerificationState,
};

/// Build and run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::generate_identity,
            commands::load_or_create_identity,
            commands::establish_malformed_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the desktop shell");
}
