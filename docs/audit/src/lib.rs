//! External security audit findings tracker (PLAN.md Phase 9 "External security audit
//! coordination and findings closure").
//!
//! Every finding a security review raises against this codebase is tracked here through to
//! resolution. The acceptance criteria this module exists to satisfy: no finding may sit
//! untriaged, no critical/high-severity finding may ship in an `Open` or `Untriaged` state, and
//! any finding the team deliberately decides not to fix (`WontFix`) must carry a documented risk
//! acceptance rather than a silent shrug. A finding closed out by a later change records that
//! change in [`Finding::resolution`] (e.g. `"resolved-by-GRP-1"`) so the ledger names *what*
//! closed it rather than only that it is closed.
//!
//! The findings below are drawn from this project's own internal security reviews (the
//! code-reviewer and security-engineer passes already run against the sender-keys group
//! encrypt/decrypt and member-removal stories), recorded here as the seed of what an external
//! audit would also be expected to re-verify. As a real external audit runs, its findings should
//! be appended to [`load_findings`] with the same discipline: every finding triaged, every
//! critical/high fixed or explicitly risk-accepted before release.

/// How severe a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Where a finding stands in its resolution lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Reported but not yet reviewed by the team. The default for a brand-new finding — never a
    /// valid terminal state for release.
    Untriaged,
    /// Reviewed and confirmed as a real issue, not yet fixed.
    Open,
    /// Reviewed and a fix is planned/in progress, but not yet landed.
    Triaged,
    /// A fix has landed and been verified.
    Fixed,
    /// The finding is closed out, and [`Finding::resolution`] names the change that closed it
    /// (e.g. a later story that fixed the true root cause). Distinct from [`Status::Fixed`] so
    /// the ledger records *what* closed it, not only that it is closed.
    Resolved,
    /// The team has decided not to fix this, with an explicit, documented reason
    /// (`Finding::risk_acceptance`).
    WontFix,
}

/// A single audit finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Short, stable identifier (e.g. `"AUDIT-001"`), referenced in commit messages / PRs that
    /// address it.
    pub id: String,
    pub severity: Severity,
    pub status: Status,
    /// One-line description of the finding.
    pub description: String,
    /// Required non-empty justification when `status` is [`Status::WontFix`]; empty for every
    /// other status (there is nothing to justify about a finding still being worked or already
    /// fixed).
    pub risk_acceptance: String,
    /// How the finding was closed out, when a later change is what closed it: `None` for findings
    /// whose status already records their outcome, `Some("...")` to name the change that resolved
    /// it (e.g. `Some("resolved-by-GRP-1")`).
    pub resolution: Option<String>,
}

/// The tracked set of external (and internally-surfaced) security audit findings for this
/// codebase, as of the current release.
pub fn load_findings() -> Vec<Finding> {
    vec![
        Finding {
            id: "AUDIT-001".to_string(),
            severity: Severity::Critical,
            status: Status::Fixed,
            description: "GroupSession::encrypt_as embedded the raw sender-key chain key in \
                plaintext inside every member's wire-format wrapper, so any passive observer of \
                the ciphertext bytes — not just group members — could read a wrapper's chain key \
                directly, rederive the AES key, and decrypt without holding any private key. \
                (This fix stopped the raw chain key appearing on the wire, but was later found \
                incomplete: the per-message key was still a deterministic function of the \
                sender's public key. See GRP-1-standin.)"
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-002".to_string(),
            severity: Severity::Critical,
            status: Status::Fixed,
            description: "GroupSession::encrypt_as derived the per-message AES-256-GCM key and \
                nonce from a chain key that never advanced, so every message from one \
                GroupSession reused the identical (key, nonce) pair — a catastrophic AES-GCM \
                break (plaintext XOR recovery and GHASH-subkey-recovery-enabled forgery)."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-003".to_string(),
            severity: Severity::High,
            status: Status::Fixed,
            description: "The initial UniFFI binding's encrypt_message implementation hard-coded \
                an all-zero AES-256-GCM nonce and reimplemented raw symmetric encryption instead \
                of delegating to the already-audited PublicIdentityKey::seal primitive, \
                reintroducing the same nonce-reuse class of defect found in AUDIT-002 at the FFI \
                boundary."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-004".to_string(),
            severity: Severity::High,
            status: Status::Fixed,
            description: "GroupSession::remove_member and rotate_sender_key were exposed as two \
                separate calls, so a caller could remove a member from the wrapper roster \
                without rotating the chain key, silently leaving the removed member able to \
                ratchet their captured chain key forward and decrypt every subsequent message."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-005".to_string(),
            severity: Severity::Medium,
            status: Status::WontFix,
            description: "GroupSession::sender_key_copy_for and try_decrypt_with_sender_key are \
                pub (not #[cfg(test)]-gated), exposing the raw chain key through the crate's \
                public API surface rather than confining it to test code."
                .to_string(),
            risk_acceptance: "Both methods are marked #[doc(hidden)] to keep them out of the \
                advertised API surface. They cannot be made #[cfg(test)]-only because the \
                read-only acceptance oracle (core/protocol/tests/member_removal_rotation.rs) \
                calls them directly as an external integration test, which only sees a crate's \
                pub items. Neither method grants a capability beyond what any holder of a \
                &GroupSession already has by construction (the chain key), so the exposure is \
                judged low-impact; revisit if a future refactor removes the test-oracle \
                constraint."
                .to_string(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-006".to_string(),
            severity: Severity::Low,
            status: Status::Triaged,
            description: "GroupSession::encrypt_as's wire format serializes wrapper_count as a \
                single byte, silently truncating (wrapping to 0) for groups larger than 255 \
                members instead of raising a validation error."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "AUDIT-007".to_string(),
            severity: Severity::Info,
            status: Status::Triaged,
            description: "The pipeline's Claude-backed code review was passing the --max-tokens \
                CLI flag, which the installed claude CLI version no longer supports, causing \
                every Claude-backed review to silently return an inconclusive verdict rather \
                than a real review. Not a vulnerability in the product itself, but a gap in the \
                review-gate infrastructure that could have let unreviewed changes reach main."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: None,
        },
        Finding {
            id: "GRP-1-standin".to_string(),
            severity: Severity::Critical,
            status: Status::Resolved,
            description: "AUDIT-001's fix was incomplete. GroupSession::new seeded the chain key \
                from the sender's PUBLIC identity key alone (HKDF::new(None, \
                &sender_pub.to_bytes()).expand(b\"chain\")), and encrypt_as derived the \
                per-message AES-256-GCM key and nonce from that chain while never using its \
                `_sender: &IdentityKeyPair` argument. The payload key was therefore a \
                deterministic function of public data, so any passive observer who knew the \
                sender's public key — which is the recipient ID and is also carried in the \
                ciphertext's own wrapper roster — could rederive the key and decrypt. Sealing \
                the per-message key to each member's identity key did not close this, because \
                the sealed value was itself publicly derivable. GRP-1 fixed the root cause by \
                deriving the chain key from a secret rather than the sender's public key."
                .to_string(),
            risk_acceptance: String::new(),
            resolution: Some("resolved-by-GRP-1".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_findings_returns_a_nonempty_set() {
        assert!(!load_findings().is_empty());
    }

    #[test]
    fn every_wontfix_finding_in_the_seed_data_has_a_risk_acceptance() {
        for f in load_findings() {
            if matches!(f.status, Status::WontFix) {
                assert!(
                    !f.risk_acceptance.is_empty(),
                    "{} is WontFix with no risk_acceptance",
                    f.id
                );
            }
        }
    }

    #[test]
    fn no_critical_or_high_finding_in_the_seed_data_is_open_or_untriaged() {
        for f in load_findings() {
            if matches!(f.severity, Severity::Critical | Severity::High) {
                assert!(
                    !matches!(f.status, Status::Open | Status::Untriaged),
                    "{} is {:?}/{:?} — critical/high findings must not ship open",
                    f.id,
                    f.severity,
                    f.status
                );
            }
        }
    }
}
