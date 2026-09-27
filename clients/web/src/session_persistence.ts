/**
 * Session persistence for the web client (NS-6A).
 *
 * A Double-Ratchet session is *secret ratchet state*: whoever holds the
 * serialized bytes can decrypt the conversation.  This module is therefore the
 * only place that turns a `SessionHandle` into bytes and back, and it writes
 * them **only** through `StorageGate` (AES-256-GCM at rest, store `'session'`).
 * Nothing here logs, prints, or transmits a blob, a key, or a peer id.
 *
 * ## Record format
 *
 * Stored under store `'session'` with `id = recordId`:
 *
 * ```json
 * { "v": 1, "blob": [ ...session_to_bytes(session) ], "remoteIdentityKey": [ ...33 bytes ] }
 * ```
 *
 * `remoteIdentityKey` is present only for sender sessions, where the peer's
 * identity key is needed to re-establish the session's trust context.
 *
 * ## Fail-closed contract
 *
 * `restoreSessionRecord` validates the record *strictly* before handing any
 * bytes to WASM and throws `SessionRecordError` (a static message — never the
 * record contents) for anything malformed.  Errors raised by WASM itself
 * (wrong identity, garbage blob) are **not** wrapped: they propagate unchanged
 * so callers can distinguish "corrupt record" from "not this identity's
 * session".  A `null` return means nothing was ever saved under that id.
 */

import {
    session_to_bytes,
    session_from_bytes,
    type SessionHandle,
    type IdentityHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import type { StorageGate } from './storage';
import type { IdentityHandleLike } from './identity';

/** The IndexedDB store holding serialized session state. */
const SESSION_STORE = 'session' as const;

/** Record id of the single receiver session whose prekey bundle this client publishes. */
export const RECEIVER_RECORD_ID = 'receiver';

/** Version tag of the persisted record format. */
const RECORD_VERSION = 1;

/** Largest serialized session accepted on restore (1 MiB). */
const MAX_BLOB_LENGTH = 1048576;

/** Length of a compressed Curve25519 identity public key. */
const IDENTITY_KEY_LENGTH = 33;

/**
 * Thrown when a stored session record is structurally invalid.
 *
 * The message is deliberately static: a record's contents (blob bytes, keys)
 * must never reach an error message, a log, or a crash report.
 */
export class SessionRecordError extends Error {
    constructor() {
        super('invalid session record');
        this.name = 'SessionRecordError';
    }
}

/**
 * Record id for the session this client uses to talk to `peerId`.
 *
 * One record per peer, so a sender session survives a reload without being
 * confused with any other peer's session.
 */
export function senderRecordId(peerId: string): string {
    return `sender:${peerId}`;
}

/** The shape of the persisted record in IndexedDB. */
interface SessionRecord {
    v: number;
    blob: number[];
    remoteIdentityKey?: number[];
}

/** True for a value that is a valid byte (integer in 0..255). */
function isByte(entry: unknown): entry is number {
    return Number.isInteger(entry) && (entry as number) >= 0 && (entry as number) <= 255;
}

/**
 * Serialize `session` and write it to `gate` under `recordId`.
 *
 * Any error from the gate propagates unchanged — the caller decides what a
 * failed save means (at startup a failed receiver save is non-fatal; before a
 * send it is not).
 *
 * @param gate An opened `StorageGate` instance.
 * @param recordId `RECEIVER_RECORD_ID` or `senderRecordId(peerId)`.
 * @param session The session whose current ratchet state must be saved.
 * @param remoteIdentityKey The peer's 33-byte identity key, for sender sessions.
 */
export async function persistSessionRecord(
    gate: StorageGate,
    recordId: string,
    session: SessionHandle,
    remoteIdentityKey?: Uint8Array,
): Promise<void> {
    const record: SessionRecord = {
        v: RECORD_VERSION,
        blob: Array.from(session_to_bytes(session)),
    };
    if (remoteIdentityKey !== undefined) {
        record.remoteIdentityKey = Array.from(remoteIdentityKey);
    }

    await gate.put(SESSION_STORE, recordId, record);
}

/**
 * Load and validate the session stored under `recordId`, then restore it with
 * `identity` (the local keypair the session was created with — the blob
 * deliberately excludes it).
 *
 * @returns `null` when nothing was saved under `recordId`; otherwise the
 *          restored session and the stored remote identity key (or `null`).
 * @throws SessionRecordError if the stored record is structurally invalid.
 * @throws Whatever WASM throws if the blob is not a session for `identity`.
 */
export async function restoreSessionRecord(
    gate: StorageGate,
    recordId: string,
    identity: IdentityHandleLike,
): Promise<{ session: SessionHandle; remoteIdentityKey: Uint8Array | null } | null> {
    const record = await gate.get(SESSION_STORE, recordId);
    if (record == null) return null;

    if (typeof record !== 'object' || record === null || Array.isArray(record)) {
        throw new SessionRecordError();
    }

    const { v, blob, remoteIdentityKey } = record as {
        v?: unknown;
        blob?: unknown;
        remoteIdentityKey?: unknown;
    };

    if (v !== RECORD_VERSION) throw new SessionRecordError();
    if (!Array.isArray(blob)) throw new SessionRecordError();
    if (blob.length === 0) throw new SessionRecordError();
    if (blob.length > MAX_BLOB_LENGTH) throw new SessionRecordError();
    if (!blob.every(isByte)) throw new SessionRecordError();

    const key = remoteIdentityKey as number[] | undefined;
    if (key !== undefined) {
        if (!Array.isArray(key) || key.length !== IDENTITY_KEY_LENGTH) throw new SessionRecordError();
        if (!key.every(isByte)) throw new SessionRecordError();
    }

    // `session_from_bytes` needs the WASM `IdentityHandle`; `PersistedIdentity.handle`
    // is one, so pass it through with the same double cast identity.ts uses at its
    // `create_receiver_session` call.  We cast to the instance type directly rather
    // than `InstanceType<typeof IdentityHandle>`: the latter trips TS2344 ("private
    // constructor") repo-wide, and this story must not add typecheck errors.
    const session = session_from_bytes(
        identity as unknown as IdentityHandle,
        new Uint8Array(blob),
    );

    return {
        session,
        remoteIdentityKey: key ? new Uint8Array(key) : null,
    };
}
