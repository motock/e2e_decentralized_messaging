//! Tauri desktop shell backend — a thin UI layer over the shared Rust core (PLAN.md Phase 5).
//!
//! The shell links directly against `core_crypto`/`core_protocol`/`core_transport` as path
//! dependencies (see `Cargo.toml`); no core logic is reimplemented in Rust, TypeScript, or
//! JavaScript here.

pub mod backup;
mod commands;
pub mod conversation;
mod error;
mod identity_store;
pub mod relay_client;
pub mod ui;
pub mod verify;

pub use verify::{
    describe_verification_flow_for_user, VerificationError, VerificationFlowDoc, VerificationState,
    VerificationStore,
};

/// Build and run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::generate_identity,
            commands::load_or_create_identity,
            commands::establish_malformed_session,
            commands::get_conversation_state,
            commands::send_message,
            commands::receive_and_decrypt,
            commands::begin_verification,
            commands::verify_safety_number,
            commands::get_verification_state,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the desktop shell");
}
