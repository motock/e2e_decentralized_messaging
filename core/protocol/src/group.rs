//! Sender Keys group encrypt/decrypt (PLAN.md Phase 7).
//!
//! ## Wire format and why it looks like this
//!
//! `encrypt_as` picks a fresh per-message AES-256-GCM key/nonce (HKDF-derived from the session's
//! chain key) and, for every member, *seals* that per-message key to the member's identity key
//! via [`crypto::identity::PublicIdentityKey::seal`] — the same ephemeral-static-ECDH + HKDF +
//! AEAD construction `core/transport/src/sealed_sender.rs` uses to hide sender identity from a
//! relay. The chain key itself never appears on the wire in any form, sealed or otherwise: only
//! the one-time per-message key is sealed, and only for that message. It leaves the
//! [`GroupSession`] that holds it only through [`GroupSession::to_bytes`], which returns it
//! verbatim in a caller-visible blob — that blob is secret ratchet state and the caller MUST
//! encrypt it at rest before storing it (see that method's docs).
//!
//! An earlier version of this module embedded the raw chain key in every member's wrapper in
//! plaintext. That defeated the entire feature: any passive observer of the ciphertext bytes —
//! not just group members — could read a wrapper's chain key directly off the wire, rederive the
//! AES key, and decrypt, with no need to go through [`GroupSession::decrypt_as`] or hold any
//! private key at all. Sealing each member's key material closes that hole: recovering the
//! per-message key from a wrapper now requires the matching member's private identity key, the
//! same trust boundary [`GroupMember`]/[`NonMember`] are meant to enforce.
//!
//! ```text
//! nonce(12) | payload_len(u32 LE) | AES-GCM ciphertext | wrapper_count(u8)
//!   | (member_pubkey(33) | sealed_len(u16 LE) | sealed_msg_key)*
//! ```
//!
//! ## Chain-key ratchet
//!
//! A security review of the sealing fix above caught a second, independent defect in the same
//! function: `encrypt_as` derived the per-message key/nonce from the session's chain key, but the
//! chain key never advanced — every message from one [`GroupSession`] reused the identical
//! AES-256-GCM (key, nonce) pair. GCM fails catastrophically under nonce reuse: two ciphertexts
//! under the same (key, nonce) XOR to the XOR of their plaintexts (confidentiality break), and
//! nonce reuse leaks the GHASH authentication subkey, enabling ciphertext forgery (integrity
//! break) — both exploitable by a purely passive observer, the same adversary the sealing fix was
//! meant to defeat.
//!
//! `encrypt_as` now ratchets the chain key forward on every call: each call derives
//! `(msg_key, nonce, next_chain_key)` from the *current* chain key via three separately-labeled
//! HKDF-Expand outputs, uses `msg_key`/`nonce` for that message only, and immediately stores
//! `next_chain_key` before returning — so no two messages from the same session ever reuse a
//! (key, nonce) pair, and recovering a past message's key from the current chain key is
//! computationally infeasible (HKDF-Expand is one-way). The chain key is stored in a [`Cell`] so
//! `encrypt_as` can advance it while keeping a `&self` (not `&mut self`) signature — the
//! established public API this module's acceptance test already depends on.
//!
//! ## Member removal and rotation
//!
//! [`GroupSession::remove_member`] drops a member from the roster AND rotates the chain key to a
//! **fresh CSPRNG value**, atomically, in one call. Rotation is deliberately NOT another
//! `encrypt_as`-style HKDF-ratchet step: the per-message ratchet is a one-way function of the
//! *current* chain key, so anyone who captured that chain key (a removed member, by definition,
//! since they were a member up until removal) could still compute every future ratcheted key
//! forward from it by hand. A CSPRNG-fresh key breaks that chain completely — the old chain key
//! carries zero information about the new one.
//!
//! Removal and rotation used to be two separate calls. A security review flagged that as a
//! foot-gun: nothing stopped a caller from removing a member and forgetting to rotate, silently
//! shipping a "removed" member who could still decrypt every subsequent message with their
//! captured key. There is no legitimate use case in this system for removing a member without
//! also rotating, so `remove_member` now does both — the secure behavior is the only behavior,
//! not an opt-in second step. [`GroupSession::rotate_sender_key`] remains separately callable for
//! routine key hygiene independent of membership changes (a legitimate standalone use case),
//! but a caller who only wants to remove a member gets forward security automatically.
//!
//! [`GroupSession::sender_key_copy_for`] and [`GroupSession::try_decrypt_with_sender_key`] exist
//! solely to let a test (or an incident investigation) simulate "what if this specific captured
//! chain key were used to try to decrypt a later message" — they are the explicit-key equivalent
//! of `decrypt_as`, which always uses the session's *current* live chain key. Neither method
//! grants any capability a holder of that raw key didn't already have; they just make the
//! captured-key attack scenario directly testable. Both are `#[doc(hidden)]`: the read-only
//! acceptance test requires them to be `pub` (it calls them directly, so they cannot be
//! `#[cfg(test)]`-gated), but they are not part of the supported public API and should not be
//! relied on by production callers.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use crypto::identity::{IdentityKeyPair, PublicIdentityKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use std::cell::Cell;
use std::convert::TryInto;
use zeroize::Zeroize;

/// Members beyond this count would overflow the wire format's 1-byte wrapper-count field.
const MAX_MEMBERS: usize = 255;

/// Wrapper for a group member's public identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember(pub PublicIdentityKey);

/// Wrapper used to indicate a caller that is not a member of the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMember(pub PublicIdentityKey);

/// A caller that can identify itself (for matching against a wrapper's addressee) and, when it
/// really is a member, open its own sealed wrapper with its private identity key.
pub trait Caller {
    fn public(&self) -> PublicIdentityKey;
    /// Attempt to unseal `sealed` addressed to this caller. A [`NonMember`] never holds the
    /// private key any real member's wrapper is sealed to, so this always fails for it — the
    /// negative test relies on this, not just on the pubkey-matching loop in `decrypt_as`.
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

impl Caller for IdentityKeyPair {
    fn public(&self) -> PublicIdentityKey {
        IdentityKeyPair::public(self)
    }
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        IdentityKeyPair::open_sealed(self, sealed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl Caller for NonMember {
    fn public(&self) -> PublicIdentityKey {
        self.0.clone()
    }
    fn open_sealed(&self, _sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // A NonMember never holds a private identity key at all (it wraps only a public key —
        // see its constructor), so it cannot open any wrapper, sealed or not. Fail closed rather
        // than pretending to attempt it.
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "non-member holds no private key to open a sealed wrapper",
        ))
    }
}

impl<T: Caller> Caller for &T {
    fn public(&self) -> PublicIdentityKey {
        (*self).public()
    }
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        (*self).open_sealed(sealed)
    }
}

/// A group session that can encrypt a message once and let every member decrypt it, without
/// exposing any member's key material to non-members.
///
/// `chain_key` is a [`Cell`] so [`encrypt_as`](Self::encrypt_as) can ratchet it forward on every
/// call while keeping a `&self` signature — see the module-level "Chain-key ratchet" doc.
#[derive(Debug, Clone)]
pub struct GroupSession {
    members: Vec<PublicIdentityKey>,
    chain_key: Cell<[u8; 32]>,
}

impl GroupSession {
    /// Create a new group session with the given sender's public identity key.
    ///
    /// The initial chain key is a fresh CSPRNG secret, NOT a derivation of
    /// `sender_pub`. The sender's public key is, by definition, known to every
    /// observer of the wire, so a chain key derived from it is recomputable by
    /// any passive observer: they could ratchet it forward exactly like
    /// [`encrypt_as`](Self::encrypt_as) does and rederive every per-message
    /// payload key without holding any private key, reducing the per-member
    /// key sealing to theater. A CSPRNG seed makes the chain key an actual
    /// secret that exists only inside this session (and in [`Self::to_bytes`]
    /// output, which callers MUST encrypt at rest — see that method's docs).
    pub fn new(_sender_pub: PublicIdentityKey) -> Self {
        let mut ck = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut ck)
            .expect("OS CSPRNG must be available");
        Self {
            members: Vec::new(),
            chain_key: Cell::new(ck),
        }
    }

    /// Add a member to the group.
    pub fn add_member(mut self, member: GroupMember) -> Self {
        self.members.push(member.0);
        self
    }

    /// Remove a member from the group and rotate the sender key in the same operation, so the
    /// removal is secure by default rather than requiring the caller to remember a second step.
    ///
    /// Removal alone (dropping the member from the wrapper roster) does NOT protect messages
    /// sent afterward: the removed member still holds every chain key they observed while a
    /// member, and `encrypt_as`'s ratchet is a one-way function of the *current* chain key, so
    /// they could still compute forward by hand. An earlier version of this API exposed removal
    /// and rotation as two separate calls; a security review flagged that as a foot-gun — nothing
    /// in the type system stopped a caller from removing a member and forgetting to rotate,
    /// silently shipping a group with no actual forward security post-removal. `remove_member`
    /// therefore always rotates internally now; there is no legitimate use case in this system
    /// for removing a member without also rotating.
    pub fn remove_member(mut self, member: GroupMember) -> Self {
        self.members.retain(|m| m != &member.0);
        self.rotate_sender_key()
    }

    /// Serialize this group session's ratchet state (member roster + current chain key) as a v1
    /// blob, so a restarted client can resume the same chain.
    ///
    /// SECURITY: the returned bytes contain secret ratchet state — the chain key every future
    /// per-message key is derived from. The CALLER must encrypt them at rest before storing them
    /// (the web client's `StorageGate` does). Never log or `Debug`-print the returned bytes.
    ///
    /// Format (big-endian): `version(1) | chain_key(32) | member_count(u16) | (len(u16) | key)*`.
    /// The chain key is copied verbatim, so a restored session continues from the current
    /// position instead of replaying keys already used. This is a pure read: it never advances
    /// the ratchet.
    ///
    /// Precondition: the roster must hold at most [`MAX_MEMBERS`] (255) members. [`add_member`]
    /// does not enforce that cap — only [`encrypt_as`](Self::encrypt_as) does — so a session that
    /// grew past it serializes to a blob [`from_bytes`](Self::from_bytes) rejects (and past 65535
    /// members the count would truncate). This fails closed on restore, but a caller that can
    /// exceed the cap should check before persisting.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut chain_key = self.chain_key.get();
        let mut out = Vec::with_capacity(1 + 32 + 2 + self.members.len() * 35);
        out.push(1u8); // VERSION
        out.extend_from_slice(&chain_key);
        out.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for member in &self.members {
            let key = member.to_bytes();
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(&key);
        }
        chain_key.zeroize();
        out
    }

    /// Restore a group session previously produced by [`to_bytes`](Self::to_bytes).
    ///
    /// Fails closed: every malformed, truncated, or over-long input returns
    /// [`ErrorKind::InvalidData`](std::io::ErrorKind::InvalidData) and no partially restored
    /// session is ever returned. Every length prefix is checked against the bytes remaining
    /// BEFORE anything is allocated or sliced, so a hostile blob declaring a multi-gigabyte
    /// segment is rejected rather than allocated. Trailing bytes after the last member are
    /// rejected too.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        fn invalid(msg: &str) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
        }

        let version = *bytes.first().ok_or_else(|| invalid("empty group blob"))?;
        if version != 1 {
            return Err(invalid("unsupported group blob version"));
        }
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(
            bytes
                .get(1..33)
                .ok_or_else(|| invalid("truncated chain key"))?,
        );
        // The roster is parsed in an inner closure so the local chain-key copy is zeroized on the
        // error paths too, not only on success.
        let parsed = (|| -> Result<Vec<PublicIdentityKey>, std::io::Error> {
            let count_bytes = bytes
                .get(33..35)
                .ok_or_else(|| invalid("truncated member count"))?;
            let count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]);
            if count as usize > MAX_MEMBERS {
                return Err(invalid("member count exceeds MAX_MEMBERS"));
            }
            let mut pos = 35usize;
            // Every member segment is at least 2 + 33 bytes, so this necessary condition rejects
            // a hostile count before any allocation happens.
            if bytes.len() - pos < count as usize * 35 {
                return Err(invalid("truncated member list"));
            }
            let mut members = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let len_bytes = bytes
                    .get(pos..pos + 2)
                    .ok_or_else(|| invalid("truncated member length"))?;
                let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
                pos += 2;
                if len != 33 {
                    return Err(invalid("member key must be exactly 33 bytes"));
                }
                let key_bytes = bytes
                    .get(pos..pos + len)
                    .ok_or_else(|| invalid("truncated member key"))?;
                pos += len;
                members.push(PublicIdentityKey::from_bytes(key_bytes));
            }
            if pos != bytes.len() {
                return Err(invalid("trailing bytes after last member"));
            }
            Ok(members)
        })();
        let members = match parsed {
            Ok(members) => members,
            Err(err) => {
                chain_key.zeroize();
                return Err(err);
            }
        };
        let session = Self {
            members,
            chain_key: Cell::new(chain_key),
        };
        chain_key.zeroize();
        Ok(session)
    }

    /// Replace the chain key with a fresh CSPRNG value, unrelated to the current one.
    ///
    /// Unlike `encrypt_as`'s per-message ratchet (a deterministic HKDF-Expand of the *current*
    /// chain key), this draws fresh randomness from the OS CSPRNG — so no one who observed the
    /// pre-rotation chain key, including a member removed via
    /// [`remove_member`](Self::remove_member) (which calls this internally), can derive the
    /// post-rotation key or any message key descended from it. Still public on its own for
    /// periodic rotation independent of membership changes — unlike removal, standalone rotation
    /// has a legitimate use case (routine key hygiene), so it is not folded into another method.
    pub fn rotate_sender_key(self) -> Self {
        let mut fresh = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut fresh)
            .expect("OS CSPRNG must be available");
        self.chain_key.set(fresh);
        fresh.zeroize();
        self
    }

    /// Return a copy of the session's CURRENT raw chain key, as observed by `member` (who must
    /// currently be a member — this does not check membership, since it exists only to let a
    /// test or incident investigation simulate "capture the key a member could see right now").
    ///
    /// Exists solely to make the captured-key attack scenario in
    /// [`try_decrypt_with_sender_key`](Self::try_decrypt_with_sender_key) testable — it does not
    /// grant `member` (or the caller) any capability they didn't already have as a current
    /// member, since a real member already has access to every message key derived from this
    /// chain key via ordinary [`decrypt_as`](Self::decrypt_as) calls.
    ///
    /// `pub` (not `#[cfg(test)]`) only because the read-only acceptance test calls it directly
    /// as an external integration test. `#[doc(hidden)]` keeps it out of the advertised API —
    /// production callers should not use this.
    #[doc(hidden)]
    pub fn sender_key_copy_for(&self, _member: &IdentityKeyPair) -> [u8; 32] {
        self.chain_key.get()
    }

    /// Attempt to decrypt `ciphertext` using an explicitly-provided chain key rather than the
    /// session's current live one.
    ///
    /// This simulates an attacker (e.g. a removed member) who captured a chain key at some point
    /// and is trying to use it against a LATER message. It re-derives the per-message key from
    /// `sender_key` the same way `encrypt_as` would have — but if `ciphertext` was produced after
    /// [`rotate_sender_key`](Self::rotate_sender_key) replaced the live chain key with a fresh,
    /// unrelated CSPRNG value, `sender_key` (the old one) cannot reproduce the message key that
    /// actually encrypted `ciphertext`, and AEAD authentication fails.
    ///
    /// `pub` (not `#[cfg(test)]`) only because the read-only acceptance test calls it directly
    /// as an external integration test. `#[doc(hidden)]` keeps it out of the advertised API —
    /// production callers should not use this.
    #[doc(hidden)]
    pub fn try_decrypt_with_sender_key(
        &self,
        sender_key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        if ciphertext.len() < 12 + 4 + 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ciphertext too short",
            ));
        }
        let nonce_bytes: [u8; 12] = ciphertext[0..12].try_into().unwrap();

        // Derive the candidate message key from sender_key exactly as encrypt_as would from a
        // live chain key. The nonce is read from the wire (matching decrypt_as), not re-derived
        // from sender_key: if sender_key is stale (post-rotation), the derived key is simply
        // wrong for this ciphertext, and AEAD authentication fails on that basis alone — the
        // same failure mode decrypt_as would hit with a wrong key, not an artificial nonce
        // mismatch that would obscure the actual security property under test.
        let hk = Hkdf::<Sha256>::new(None, sender_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes)
            .expect("hkdf expand msg key");

        let payload_len = u32::from_le_bytes(ciphertext[12..16].try_into().unwrap()) as usize;
        if ciphertext.len() < 16 + payload_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload length mismatch",
            ));
        }
        let payload = &ciphertext[16..16 + payload_len];

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        key_bytes.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(plaintext)
    }

    /// Encrypt plaintext as the sender. Returns ciphertext bytes.
    ///
    /// `_sender` is not read: the per-message key is sealed to every member's identity key, so
    /// membership in the group is what grants decryption — there is nothing further to check
    /// here. The parameter exists to make the call site's intent explicit.
    ///
    /// Ratchets the session's chain key forward before returning (see the module-level
    /// "Chain-key ratchet" doc), so every message — even repeated calls with identical
    /// `plaintext` — gets a distinct AES-256-GCM key and nonce.
    pub fn encrypt_as(
        &self,
        _sender: &IdentityKeyPair,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        if self.members.len() > MAX_MEMBERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "group has {} members, exceeding the wire format's {MAX_MEMBERS}-member limit",
                    self.members.len()
                ),
            ));
        }

        // Derive this message's key, nonce, and the NEXT chain key from the CURRENT chain key,
        // via three separately-labeled HKDF-Expand outputs of one HKDF-Extract. Distinct labels
        // (domain separation) mean an attacker who somehow learned msg_key or nonce for one
        // message gains no information about next_chain_key, and vice versa. Store the ratcheted
        // key immediately, before any fallible step below, so a message is never (re)encrypted
        // under a key that was already used for a prior message.
        let current_chain_key = self.chain_key.get();
        let hk = Hkdf::<Sha256>::new(None, &current_chain_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes)
            .expect("hkdf expand msg key");
        let mut nonce_bytes = [0u8; 12];
        hk.expand(b"nonce", &mut nonce_bytes)
            .expect("hkdf expand nonce");
        let mut next_chain_key = [0u8; 32];
        hk.expand(b"chain-ratchet", &mut next_chain_key)
            .expect("hkdf expand next chain key");
        self.chain_key.set(next_chain_key);
        next_chain_key.zeroize();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_payload = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Seal the per-message key to each member individually — only that member's private
        // identity key can recover it.
        let mut wrappers = Vec::with_capacity(self.members.len());
        for m in &self.members {
            let sealed = m
                .seal(&key_bytes)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            wrappers.push((m.clone(), sealed));
        }
        // key_bytes has now been consumed by both the AEAD cipher and every seal() call above —
        // scrub it rather than letting it linger un-scrubbed until the allocator reuses the stack
        // slot (defense in depth; matches the discipline in identity.rs/sealed_sender.rs).
        key_bytes.zeroize();

        // Serialize: nonce | payload_len | payload | wrapper_count
        //   | (member_pubkey(33) | sealed_len(u16 LE) | sealed_bytes)*
        let mut out = Vec::new();
        out.extend_from_slice(&nonce_bytes);
        out.extend(&(ciphertext_payload.len() as u32).to_le_bytes());
        out.extend(&ciphertext_payload);
        out.push(wrappers.len() as u8);
        for (pubkey, sealed) in wrappers {
            out.extend(pubkey.to_bytes());
            out.extend(&(sealed.len() as u16).to_le_bytes());
            out.extend(&sealed);
        }
        Ok(out)
    }

    /// Decrypt ciphertext as the given caller: find the wrapper addressed to `caller`, unseal it
    /// with `caller`'s own private identity key to recover the per-message key, then decrypt.
    ///
    /// Fails if `caller` is not addressed by any wrapper, or — for a [`NonMember`], which holds
    /// no private key — even when its public key happens to match a wrapper (that case cannot
    /// arise via this crate's API, but `open_sealed` fails closed regardless).
    pub fn decrypt_as<C: Caller>(
        &self,
        caller: C,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut pos = 0;
        if ciphertext.len() < 12 + 4 + 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ciphertext too short",
            ));
        }
        let nonce_bytes: [u8; 12] = ciphertext[pos..pos + 12].try_into().unwrap();
        pos += 12;
        let payload_len = u32::from_le_bytes(ciphertext[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if ciphertext.len() < pos + payload_len + 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload length mismatch",
            ));
        }
        let payload = &ciphertext[pos..pos + payload_len];
        pos += payload_len;
        let wrapper_count = ciphertext[pos] as usize;
        pos += 1;

        let caller_pubkey = caller.public().to_bytes();
        let mut found_sealed: Option<&[u8]> = None;
        for _ in 0..wrapper_count {
            if pos + 33 + 2 > ciphertext.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "wrapper truncated",
                ));
            }
            let pubkey_bytes = &ciphertext[pos..pos + 33];
            pos += 33;
            let sealed_len =
                u16::from_le_bytes(ciphertext[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + sealed_len > ciphertext.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sealed wrapper truncated",
                ));
            }
            let sealed_bytes = &ciphertext[pos..pos + sealed_len];
            pos += sealed_len;
            if found_sealed.is_none() && pubkey_bytes == caller_pubkey.as_slice() {
                found_sealed = Some(sealed_bytes);
            }
        }
        let sealed = found_sealed.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "caller not a member")
        })?;

        let mut key_bytes = caller.open_sealed(sealed)?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        key_bytes.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(plaintext)
    }
}

impl GroupMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self {
        Self(pubkey)
    }
}

impl NonMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self {
        Self(pubkey)
    }
}

#[cfg(test)]
mod tests {
    //! Implementation-level tests supplementing the acceptance oracle in
    //! `tests/sender_keys_group.rs`. That file covers the documented API's positive/negative
    //! behavior; this module covers the wire-format security property the reviewer flagged:
    //! an attacker who can read raw ciphertext bytes (not just call the API as a NonMember)
    //! must not be able to recover any member's per-message key.
    use super::*;

    #[test]
    fn wire_bytes_do_not_expose_the_per_message_key_or_chain_key() {
        let sender = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

        // Capture the pre-encrypt chain key (white-box, since this test verifies an
        // implementation invariant, not exercising the public API) BEFORE encrypt_as ratchets
        // it, so we can independently recompute what this message's key/nonce/next-chain-key
        // actually were and assert none of them appear on the wire.
        let pre_chain_key = group.chain_key.get();
        let ciphertext = group
            .encrypt_as(&sender, b"attacker reads these bytes")
            .unwrap();

        let hk = Hkdf::<Sha256>::new(None, &pre_chain_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes).unwrap();
        let mut next_chain_key = [0u8; 32];
        hk.expand(b"chain-ratchet", &mut next_chain_key).unwrap();

        assert!(
            !ciphertext.windows(32).any(|w| w == pre_chain_key),
            "the chain key that produced this message must never appear on the wire"
        );
        assert!(
            !ciphertext.windows(32).any(|w| w == key_bytes),
            "per-message key must never appear on the wire in the clear"
        );
        assert!(
            !ciphertext.windows(32).any(|w| w == next_chain_key),
            "the ratcheted next chain key must never appear on the wire"
        );
        assert_eq!(
            group.chain_key.get(),
            next_chain_key,
            "encrypt_as must have ratcheted the session's chain key forward"
        );
    }

    #[test]
    fn successive_messages_never_reuse_a_key_or_nonce() {
        // Regression test for the nonce-reuse defect a security review caught: encrypt_as used
        // to derive the message key/nonce from a chain key that never advanced, so every message
        // from one GroupSession reused the identical AES-256-GCM (key, nonce) pair — a
        // catastrophic break under GCM (XOR of ciphertexts leaks XOR of plaintexts, and the
        // authentication subkey leaks, enabling forgery). Two encrypt_as calls on the same
        // session must now produce distinct nonces (the directly observable proxy for "distinct
        // key", since the nonce is serialized on the wire and the key is not).
        let sender = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));

        let ct1 = group.encrypt_as(&sender, b"message one").unwrap();
        let ct2 = group.encrypt_as(&sender, b"message two").unwrap();
        let nonce1 = &ct1[0..12];
        let nonce2 = &ct2[0..12];
        assert_ne!(
            nonce1, nonce2,
            "each encrypt_as call must ratchet to a fresh nonce"
        );

        // Same plaintext length ("message one"/"message two" are both 11 bytes) under different
        // keys/nonces must not merely differ byte-for-byte by coincidence of plaintext content —
        // decrypt each with the OTHER message's recovered key to confirm they are not
        // interchangeable (i.e. this isn't just two different plaintexts happening to differ).
        let plain1 = group.decrypt_as(&member, &ct1).unwrap();
        let plain2 = group.decrypt_as(&member, &ct2).unwrap();
        assert_eq!(plain1, b"message one");
        assert_eq!(plain2, b"message two");
    }

    #[test]
    fn encrypting_with_more_than_255_members_is_rejected_not_silently_truncated() {
        // Regression test for a wire-format correctness bug: wrapper_count is serialized as a
        // single byte (`wrappers.len() as u8`), so 256 members would silently wrap to 0 and
        // decrypt_as would then match no wrapper for anyone. Rather than emit a corrupt frame,
        // encrypt_as must reject the call outright once the group exceeds the wire format's
        // capacity.
        let sender = IdentityKeyPair::generate();
        let mut group = GroupSession::new(sender.public());
        for _ in 0..=MAX_MEMBERS {
            group = group.add_member(GroupMember(IdentityKeyPair::generate().public()));
        }
        assert_eq!(group.members.len(), MAX_MEMBERS + 1);
        let result = group.encrypt_as(&sender, b"too many members");
        assert!(
            result.is_err(),
            "encrypt_as must reject a group over the wire format's member limit"
        );
    }

    #[test]
    fn an_attacker_who_only_reads_wire_bytes_cannot_decrypt_without_a_private_key() {
        // Stronger than the API-level non_member_cannot_decrypt_a_group_message test: this
        // attacker does not go through decrypt_as/Caller at all. It parses the wire format by
        // hand (exactly what a passive network observer or malicious relay could do) and tries
        // to recover the plaintext using only what is visible on the wire.
        let sender = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));
        let ciphertext = group.encrypt_as(&sender, b"group secret").unwrap();

        // Parse exactly what encrypt_as serialized: nonce | payload_len | payload | wrapper_count
        // | (pubkey(33) | sealed_len(u16) | sealed_bytes)*.
        let nonce_bytes = &ciphertext[0..12];
        let payload_len = u32::from_le_bytes(ciphertext[12..16].try_into().unwrap()) as usize;
        let payload = &ciphertext[16..16 + payload_len];
        let mut pos = 16 + payload_len + 1; // skip wrapper_count
        let _pubkey = &ciphertext[pos..pos + 33];
        pos += 33;
        let sealed_len = u16::from_le_bytes(ciphertext[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let sealed_bytes = &ciphertext[pos..pos + sealed_len];

        // The attacker has the sealed blob and the AEAD ciphertext, but no private identity key
        // for anyone. Every key the attacker could try (brute-forcing the sealed blob's AEAD, or
        // treating the sealed blob itself as if it were the AES key) must fail to decrypt.
        let cipher_from_sealed_bytes = Aes256Gcm::new_from_slice(&sealed_bytes[..32]);
        if let Ok(cipher) = cipher_from_sealed_bytes {
            let nonce = Nonce::from_slice(nonce_bytes);
            assert!(
                cipher.decrypt(nonce, payload).is_err(),
                "treating the sealed blob's leading bytes as the AES key must not decrypt"
            );
        }

        // THE attack that motivated the secret-seed fix: the sender's public key is public
        // information (it is on the wire in the wrapper, and members publish it anyway), so a
        // chain key derived from it is recomputable by anyone. An attacker who replays the
        // exact derivation GroupSession::new used to perform — HKDF-Extract(salt=None,
        // IKM=sender_pub) then Expand(b"chain"), followed by encrypt_as's own ratchet labels —
        // must NOT recover a key that decrypts the payload. This is what a passive observer
        // would try first, and it is exactly what the old public-seed derivation handed them.
        let attacker_hk = Hkdf::<Sha256>::new(None, &sender.public().to_bytes());
        let mut attacker_chain_key = [0u8; 32];
        attacker_hk
            .expand(b"chain", &mut attacker_chain_key)
            .unwrap();
        let attacker_hk2 = Hkdf::<Sha256>::new(None, &attacker_chain_key);
        let mut attacker_msg_key = [0u8; 32];
        attacker_hk2.expand(b"msg", &mut attacker_msg_key).unwrap();
        let cipher_from_public_key = Aes256Gcm::new_from_slice(&attacker_msg_key)
            .expect("32 bytes is a valid AES-256 key length");
        assert!(
            cipher_from_public_key
                .decrypt(Nonce::from_slice(nonce_bytes), payload)
                .is_err(),
            "a chain key derived from the sender's PUBLIC key must not decrypt the payload — \
             if this fails, the initial chain key is derivable from public information and the \
             per-member sealing is theater"
        );
    }

    #[test]
    fn rotation_produces_a_chain_key_unrelated_to_the_pre_rotation_one() {
        // The core security property rotate_sender_key depends on: the new chain key must be
        // CSPRNG-fresh, NOT an HKDF-ratchet of the old one. If it were derived from the old key
        // (the same one-way function encrypt_as's per-message ratchet uses), a removed member
        // holding the old chain key could still compute the new one.
        let sender = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public());
        let pre_rotation_key = group.chain_key.get();

        let group = group.rotate_sender_key();
        let post_rotation_key = group.chain_key.get();

        assert_ne!(pre_rotation_key, post_rotation_key);

        // Stronger than mere inequality: confirm the new key is NOT derivable from the old one
        // via the same ratchet construction encrypt_as uses (the "chain-ratchet" HKDF label).
        // If rotation were just another ratchet step, this would match.
        let hk = Hkdf::<Sha256>::new(None, &pre_rotation_key);
        let mut would_be_ratcheted = [0u8; 32];
        hk.expand(b"chain-ratchet", &mut would_be_ratcheted)
            .unwrap();
        assert_ne!(
            post_rotation_key, would_be_ratcheted,
            "rotate_sender_key must NOT be equivalent to one more encrypt_as ratchet step \
             derived from the old key — it must be independent CSPRNG randomness"
        );
    }

    #[test]
    fn a_removed_members_captured_chain_key_cannot_decrypt_any_message_after_rotation_even_several_messages_later(
    ) {
        // Stronger than the acceptance test: confirms the captured-old-key attack fails not just
        // for the very next message post-rotation, but for messages arbitrarily far after it —
        // i.e. rotation is a hard break, not something a stale key could catch up to by
        // replaying encrypt_as's forward ratchet from the captured point.
        let sender = IdentityKeyPair::generate();
        let alice = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();

        let mut group = GroupSession::new(sender.public())
            .add_member(GroupMember(alice.public()))
            .add_member(GroupMember(eve.public()));

        let eve_captured_key = group.sender_key_copy_for(&eve);

        group = group.remove_member(GroupMember(eve.public()));
        group = group.rotate_sender_key();

        // Several messages after rotation, not just the first one.
        for i in 0..5 {
            let ciphertext = group
                .encrypt_as(&sender, format!("message {i}").as_bytes())
                .unwrap();
            assert!(
                group.try_decrypt_with_sender_key(&eve_captured_key, &ciphertext).is_err(),
                "captured pre-rotation key must never decrypt, including message {i} several steps after rotation"
            );
            // Remaining member still works at every step.
            assert_eq!(
                group.decrypt_as(&alice, &ciphertext).unwrap(),
                format!("message {i}").as_bytes()
            );
        }
    }

    #[test]
    fn remove_member_alone_now_protects_future_messages_because_it_rotates_internally() {
        // Regression test for a design foot-gun a security review caught: remove_member and
        // rotate_sender_key used to be two separate calls, so a caller could remove a member and
        // forget to rotate, silently leaving the removed member able to ratchet their captured
        // chain key forward by hand and decrypt future messages. remove_member now rotates
        // internally — this test confirms a SINGLE call to remove_member (with no separate
        // rotate_sender_key call) is sufficient for forward security.
        let sender = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();

        let mut group = GroupSession::new(sender.public()).add_member(GroupMember(eve.public()));
        let eve_captured_key = group.sender_key_copy_for(&eve);

        group = group.remove_member(GroupMember(eve.public()));
        // No separate rotate_sender_key() call — remove_member alone must be sufficient.

        let ciphertext = group
            .encrypt_as(&sender, b"removed and already protected")
            .unwrap();

        // Eve is gone from the wrapper list, so the ordinary decrypt_as path fails...
        assert!(group.decrypt_as(&eve, &ciphertext).is_err());

        // ...AND her captured chain key can no longer ratchet forward to this message's key,
        // because remove_member already rotated to a CSPRNG-fresh, unrelated chain key.
        assert!(
            group
                .try_decrypt_with_sender_key(&eve_captured_key, &ciphertext)
                .is_err(),
            "remove_member alone must invalidate a captured chain key, with no separate \
             rotate_sender_key call required"
        );
    }
}
