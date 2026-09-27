/**
 * Persistent identity management for the web client.
 *
 * On app startup: load the persisted identity from `StorageGate` (encrypted
 * IndexedDB) if present, else generate a new one and persist it.  This
 * ensures the user's identity — and therefore their recipient ID (the
 * address a peer types in to reach them) — survives a page reload and does
 * not silently change between sessions.
 *
 * After loading/generating the identity, call `publishPrekeyForIdentity` to
 * generate a PQXDH prekey bundle and publish it to the relay via the
 * transport's `publishPrekey` op, keyed by the recipient ID.
 *
 * ## Recipient ID encoding
 *
 * The recipient ID is **base64** of `IdentityHandle.public_bytes()` — the
 * 33-byte compressed Curve25519 public identity key.  This is a stable,
 * self-describing identifier: the same identity always produces the same
 * recipient ID, and a peer can use it to look up this user's prekey bundle
 * on the relay.  Base64 is chosen over hex for brevity (44 chars vs 66) and
 * over raw bytes because it is URL-safe and typeable.  We use standard
 * base64 (not URL-safe) for consistency with the relay wire protocol, which
 * base64-encodes all binary payloads.
 */

import {
    generate_identity,
    identity_from_bytes,
    create_receiver_session,
    publish_bundle_bytes,
    type SessionHandle,
    type IdentityHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import type { StorageGate } from './storage';
import {
    persistSessionRecord,
    restoreSessionRecord,
    RECEIVER_RECORD_ID,
} from './session_persistence';

/** The IndexedDB store and record id used for the identity keypair. */
const IDENTITY_STORE = 'identity' as const;
const IDENTITY_RECORD_ID = 'self';

/** Minimum length for a valid serialized identity keypair (private bytes). */
const MIN_PRIVATE_BYTES_LEN = 32;

/* ------------------------------------------------------------------ */
/* Recipient ID                                                        */
/* ------------------------------------------------------------------ */

/**
 * Convert a Uint8Array to a standard base64 string (no URL-safe variant).
 * Works in both browser and Node (test harness).
 */
function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    if (typeof btoa === 'function') return btoa(bin);
    // Node fallback
    return Buffer.from(bytes).toString('base64');
}

/**
 * Derive the recipient ID from the identity's public bytes.
 *
 * The recipient ID is **base64(`IdentityHandle.public_bytes()`)** — the
 * 33-byte compressed Curve25519 public identity key, base64-encoded.  This
 * is what a peer types in to address this user; it is stable across
 * sessions because the identity is persisted.
 *
 * @param publicBytes 33-byte compressed Curve25519 public identity key
 * @returns base64-encoded recipient ID string
 */
export function recipientIdFromPublicBytes(publicBytes: Uint8Array): string {
    return bytesToBase64(publicBytes);
}

/* ------------------------------------------------------------------ */
/* PersistedIdentity                                                   */
/* ------------------------------------------------------------------ */

/**
 * An identity that has been loaded or generated and is ready for use.
 * Carries the WASM `IdentityHandle` (for prekey generation, session
 * establishment, etc.) plus the derived recipient ID.
 */
export interface PersistedIdentity {
    /** The WASM identity handle — call `public_bytes()` / `private_bytes()` on it. */
    readonly handle: IdentityHandleLike;
    /** The 33-byte public identity key bytes. */
    readonly publicBytes: Uint8Array;
    /** The base64 recipient ID derived from the public bytes. */
    readonly recipientId: string;
}

/** Structural type matching the WASM `IdentityHandle` we need. */
export interface IdentityHandleLike {
    public_bytes(): Uint8Array;
    private_bytes(): Uint8Array;
}

/** The shape of the persisted record in IndexedDB. */
interface IdentityRecord {
    /** Serialized full keypair (public + private), as from `private_bytes()`. */
    privateBytes: number[];
    /** The public identity key bytes, as from `public_bytes()`. */
    publicBytes: number[];
}

/* ------------------------------------------------------------------ */
/* Load or generate                                                    */
/* ------------------------------------------------------------------ */

/**
 * Load the persisted identity from `StorageGate`, or generate and persist a
 * new one if none exists.
 *
 * **Fail-closed contract:** if the stored key is corrupt (wrong length,
 * unparseable), this throws — it does NOT silently fall back to generating
 * a new identity, which would silently change the user's address between
 * sessions.
 *
 * @param gate An opened `StorageGate` instance.
 * @returns The loaded or freshly generated identity.
 */
export async function loadOrGenerateIdentity(gate: StorageGate): Promise<PersistedIdentity> {
    const record = (await gate.get(IDENTITY_STORE, IDENTITY_RECORD_ID)) as
        | IdentityRecord
        | null;

    if (record) {
        // Fail closed on corrupt data — never silently regenerate.
        return identityFromRecord(record);
    }

    // No persisted identity — generate and persist a new one.
    const handle = generate_identity();
    const publicBytes = handle.public_bytes();
    const privateBytes = handle.private_bytes();

    const newRecord: IdentityRecord = {
        privateBytes: Array.from(privateBytes),
        publicBytes: Array.from(publicBytes),
    };
    await gate.put(IDENTITY_STORE, IDENTITY_RECORD_ID, newRecord);

    return {
        handle,
        publicBytes,
        recipientId: recipientIdFromPublicBytes(publicBytes),
    };
}

/**
 * Reconstruct an identity from a persisted record.
 *
 * Throws on corrupt data (wrong-length bytes, unparseable keypair) — the
 * fail-closed contract.  Does NOT fall back to generating a new identity.
 */
function identityFromRecord(record: IdentityRecord): PersistedIdentity {
    if (
        !record ||
        !Array.isArray(record.privateBytes) ||
        !Array.isArray(record.publicBytes)
    ) {
        throw new Error('corrupt identity record: missing or invalid fields');
    }

    const privateBytes = new Uint8Array(record.privateBytes);
    const publicBytes = new Uint8Array(record.publicBytes);

    if (privateBytes.length < MIN_PRIVATE_BYTES_LEN) {
        throw new Error(
            `corrupt identity: private bytes too short (${privateBytes.length} < ${MIN_PRIVATE_BYTES_LEN})`,
        );
    }
    if (publicBytes.length !== 33) {
        throw new Error(
            `corrupt identity: public bytes wrong length (${publicBytes.length}, expected 33)`,
        );
    }

    // Deserialize the full keypair from its serialized form.  This throws
    // on malformed bytes — the fail-closed contract.
    const handle = identity_from_bytes(privateBytes);

    // Verify the deserialized identity's public bytes match what we stored.
    // If they don't, the record is corrupt or tampered — fail closed.
    const deserializedPub = handle.public_bytes();
    if (!bytesEqual(deserializedPub, publicBytes)) {
        throw new Error('corrupt identity: deserialized public bytes do not match stored record');
    }

    return {
        handle,
        publicBytes: deserializedPub,
        recipientId: recipientIdFromPublicBytes(deserializedPub),
    };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Prekey publishing                                                   */
/* ------------------------------------------------------------------ */

/** Minimal interface for the relay transport (mockable in tests). */
export interface PrekeyTransport {
    publishPrekey(recipientId: string, bundle: Uint8Array): Promise<void>;
}

/**
 * Create a receiver (Bob) session for the given identity, publish its prekey
 * bundle to the relay, and return the session handle.
 *
 * This is the critical wiring point: the session that publishes the bundle
 * MUST be the same session that later decrypts messages encrypted to that
 * bundle. `generate_prekey_bundle` creates a session internally and drops it
 * (only bytes come back), so we cannot use it here — we use
 * `create_receiver_session` + `publish_bundle_bytes` instead, which produce
 * the bundle from a retained session handle we can hand to the receive loop.
 *
 * ## Session persistence (optional `gate`)
 *
 * When a `StorageGate` is supplied, the receiver session is restored from the
 * encrypted store (store `'session'`, record `RECEIVER_RECORD_ID`) instead of
 * being recreated on every load, so a peer that already fetched this client's
 * prekey bundle keeps decrypting after a reload. The session is re-persisted
 * *before* the bundle is published, so the stored state always matches the
 * bundle a peer can fetch.
 *
 * Both persistence steps fail soft, because a client that cannot reach its
 * store must still become reachable on the relay:
 * - a restore that returns nothing or throws falls back to a fresh session
 *   (a throw logs a static warning; a `null` return is simply "nothing saved");
 * - a save that fails is non-fatal and logs a static warning.
 *
 * Warnings are static strings only — session bytes, keys, and peer ids are
 * never logged.
 *
 * If the relay is unreachable, `publishPrekey` rejects and the error
 * propagates — the caller must surface a visible error state, not swallow it.
 *
 * @param identity The loaded/generated identity.
 * @param transport The relay transport (or a mock).
 * @param gate Optional encrypted store used to persist/restore the receiver
 *             session. When omitted, no storage is touched and the function
 *             behaves exactly as before.
 * @returns The receiver session handle — pass this to `<Conversation receiverSession={...} />`
 *          so the receive loop decrypts with the same session whose bundle was published.
 */
export async function publishPrekeyForIdentity(
    identity: PersistedIdentity,
    transport: PrekeyTransport,
    gate?: StorageGate,
): Promise<InstanceType<typeof SessionHandle>> {
    let session: ReturnType<typeof create_receiver_session> | null = null;

    if (gate) {
        try {
            const restored = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity.handle);
            session = restored ? restored.session : null;
        } catch {
            console.warn('receiver session restore failed; creating a new session');
            session = null;
        }
    }

    if (!session) {
        session = create_receiver_session(
            identity.handle as unknown as InstanceType<typeof IdentityHandle>,
        );
    }

    if (gate) {
        try {
            await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);
        } catch {
            console.warn('receiver session could not be saved; continuing in memory');
        }
    }

    const bundle = publish_bundle_bytes(session);
    await transport.publishPrekey(identity.recipientId, bundle);
    return session;
}