/**
 * DL-2: persistence for the account's OWN signed device list.
 *
 * The account primary signs a versioned list of its devices (spec/v0.md §8.3)
 * and publishes it as an opaque discovery blob. The relay keeps that blob for a
 * 7-day TTL (`relay/src/discovery.rs`), so a client that only ever held the
 * list in memory loses it on reload: after expiry it would re-seed version 1
 * containing nothing but device 0, silently dropping every linked device from
 * the published list.
 *
 * This module is the durable half of that story. It stores the exact signed
 * bytes and the version they were signed at under its OWN record
 * (`identity` / `own-device-list`) and restores them on the next start, so the
 * client can re-publish the list it already had instead of seeding a fresh v1.
 *
 * It is deliberately separate from the linking handshake's
 * `identity` / `account-device-list` record (MD-16), which describes THIS
 * device's link to an account (`{accountHandle, deviceId, signedListBytesBase64}`).
 * That record is written by the handshake and is never touched here: a linked
 * device does not own the account's list, and overwriting its link record with
 * an own-list record would destroy the device id the receive path depends on.
 *
 * Security properties:
 *  - **Never returns unverified bytes.** Every read goes through
 *    `verify_device_list` against the account's own public identity key; a
 *    record that is missing, malformed, tampered with, or signed by anyone else
 *    yields `null` rather than the stored bytes.
 *  - **Monotonic.** {@link restoreOwnDeviceList} hands the persisted version to
 *    the relay lookup as the §8.4 baseline, so a relay blob is only accepted
 *    when it is strictly newer. An older list is never re-published over a
 *    newer one.
 *  - **No sensitive data in logs or errors.** Identity keys, list bytes and
 *    prekey bundles are never logged, and thrown messages name only the
 *    structural failure.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import {
    lookupDeviceList,
    splitVerified,
    toConversationDeviceList,
    type DiscoveryTransport,
} from './discovery';
import type { DeviceListEntry } from './Conversation';
import type { StorageGate } from './storage';

/** Store the account's own signed list is persisted in. */
export const OWN_LIST_STORE = 'identity' as const;

/**
 * Record id for the account's own signed list.
 *
 * Distinct from the linking handshake's `account-device-list` record on
 * purpose — see the module docblock.
 */
export const OWN_LIST_RECORD_ID = 'own-device-list';

/**
 * Upper bound on a persisted record's base64 payload (the 64 KiB protocol cap
 * encoded as standard base64). Checked before decoding so a corrupted or
 * hostile local record cannot force a large allocation.
 */
const MAX_SIGNED_LIST_BASE64_LENGTH = 4 * Math.ceil((64 * 1024) / 3);

/** A verified signed device list: its version, its exact bytes, its devices. */
export interface OwnDeviceList {
    /** The version the bytes were signed at. */
    version: number;
    /** The exact signed bytes the relay holds (re-published verbatim). */
    bytes: Uint8Array;
    /** The devices the signed bytes actually list. */
    devices: DeviceListEntry[];
}

/** The persisted record shape. */
interface OwnListRecord {
    version: number;
    signedListBytesBase64: string;
}

/**
 * The signed-device-list binding this module uses (MD-3).
 *
 * Declared locally rather than added to `wasm-bindings.d.ts`, mirroring
 * discovery.ts: that file is the ambient fallback for the unbuilt-WASM case.
 */
interface DeviceListVerifyBindings {
    /** `u64_le(version) || packed entries`. */
    verify_device_list(bytes: Uint8Array, expectedAccount: Uint8Array): Uint8Array;
}

const deviceListWasm = wasm as unknown as DeviceListVerifyBindings;

/** Standard base64 (not URL-safe), matching the relay wire protocol. */
function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    if (typeof btoa === 'function') return btoa(binary);
    return Buffer.from(binary, 'binary').toString('base64');
}

/** Inverse of {@link bytesToBase64}. Throws on input that is not base64. */
function base64ToBytes(b64: string): Uint8Array {
    let binary: string;
    if (typeof atob === 'function') {
        binary = atob(b64);
    } else {
        binary = Buffer.from(b64, 'base64').toString('binary');
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

/**
 * Verify `signedBytes` against the account's public identity key and return the
 * version, bytes and devices they actually encode.
 *
 * Synchronous: the caller (App's `handleOwnListPublished`) must be able to throw
 * back into the linking hook so it keeps its pending send and fails closed.
 * WASM is already initialised by the time any list is published.
 *
 * @throws if the bytes are malformed, signed by another key, or carry a
 *   version/entry layout that cannot be parsed. Unverified bytes are never
 *   returned.
 */
export function verifyOwnDeviceList(
    signedBytes: Uint8Array,
    expectedAccount: Uint8Array,
): OwnDeviceList {
    const verified = deviceListWasm.verify_device_list(signedBytes, expectedAccount);
    const { version, packedEntries } = splitVerified(verified);
    const { devices } = toConversationDeviceList(version, packedEntries);
    return { version, bytes: signedBytes, devices };
}

/**
 * Structurally validate a persisted own-list record.
 *
 * Anything else — no record, a record from an older/foreign writer, or a
 * corrupted one — yields `null`. Never throws, and never echoes the record.
 */
function parseOwnListRecord(raw: unknown): OwnListRecord | null {
    if (typeof raw !== 'object' || raw === null) return null;
    const { version, signedListBytesBase64 } = raw as Record<string, unknown>;
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return null;
    if (typeof signedListBytesBase64 !== 'string' || signedListBytesBase64.length === 0) return null;
    if (signedListBytesBase64.length > MAX_SIGNED_LIST_BASE64_LENGTH) return null;
    return { version, signedListBytesBase64 };
}

/**
 * Persist the account's own signed list.
 *
 * Stores the version alongside the exact signed bytes so a later read can
 * reject a record whose two halves disagree. Callers treat a failure as
 * best-effort: losing the record costs a re-seed, never correctness.
 */
export async function saveOwnDeviceList(
    gate: StorageGate,
    list: { version: number; bytes: Uint8Array },
): Promise<void> {
    if (!Number.isSafeInteger(list.version) || list.version < 1) {
        throw new Error('own device list: version is out of range');
    }
    if (list.bytes.length === 0) {
        throw new Error('own device list: signed bytes are empty');
    }
    const record: OwnListRecord = {
        version: list.version,
        signedListBytesBase64: bytesToBase64(list.bytes),
    };
    await gate.put(OWN_LIST_STORE, OWN_LIST_RECORD_ID, record);
}

/**
 * Load, verify and convert the persisted own signed list.
 *
 * Returns `null` when there is no record, when the record is malformed, when
 * the bytes fail verification against `expectedAccount`, or when the stored
 * version disagrees with the version the signed bytes carry. A `null` result
 * means "nothing trustworthy is persisted" — never "here are unverified bytes".
 *
 * @param expectedAccount - The account primary's 33-byte public identity key.
 */
export async function loadOwnDeviceList(
    gate: StorageGate,
    expectedAccount: Uint8Array,
): Promise<OwnDeviceList | null> {
    let raw: unknown;
    try {
        raw = await gate.get(OWN_LIST_STORE, OWN_LIST_RECORD_ID);
    } catch {
        // An unreadable record is not fatal: the caller falls back to the relay
        // or a seed. Nothing about the record is logged.
        return null;
    }
    const record = parseOwnListRecord(raw);
    if (record === null) return null;
    try {
        await ensureWasmInit();
        const list = verifyOwnDeviceList(base64ToBytes(record.signedListBytesBase64), expectedAccount);
        // The two halves of the record must agree; a mismatch means the record
        // was written by something that did not sign these bytes.
        if (list.version !== record.version) return null;
        return list;
    } catch {
        // Tampered, foreign-signed or unparseable: ignore it entirely.
        return null;
    }
}

/** What {@link restoreOwnDeviceList} decided the caller should hold. */
export interface OwnListRestore {
    /** The verified list to hold. */
    list: OwnDeviceList;
    /**
     * True when the caller must re-publish `list.bytes` verbatim to refresh the
     * relay's 7-day TTL. Always the exact bytes of `list` — never a re-sign.
     */
    republish: boolean;
}

/**
 * Wrap a discovery transport so the raw blob the last lookup saw is observable.
 *
 * `lookupDeviceList` verifies and converts a blob but does not hand back the
 * signed bytes, and the caller must keep the exact bytes it holds (MD-18
 * re-signs from them, and the TTL refresh re-publishes them verbatim).
 */
function recordingTransport(inner: DiscoveryTransport): {
    transport: DiscoveryTransport;
    lastBlob: () => Uint8Array | null;
} {
    let blob: Uint8Array | null = null;
    return {
        transport: {
            publishDiscovery: (handle, bytes) => inner.publishDiscovery(handle, bytes),
            lookupDiscovery: async (handle) => {
                blob = await inner.lookupDiscovery(handle);
                return blob;
            },
        },
        lastBlob: () => blob,
    };
}

/**
 * Decide what the account's own list should be on startup, restoring the
 * persisted list when the relay's copy is gone.
 *
 * Outcomes:
 *  - the relay holds a verified list strictly newer than everything held or
 *    persisted -> hold it and re-publish those exact bytes (TTL refresh);
 *  - the relay holds nothing newer (absent, expired, or older) and a valid
 *    persisted list exists -> hold the persisted list and re-publish its exact
 *    bytes. Version 1 is NEVER seeded here;
 *  - neither -> `null`, and the caller seeds version 1 as before.
 *
 * The persisted version is handed to the relay lookup as the §8.4 baseline, so
 * a returned relay list is always strictly newer than the persisted one and an
 * older list can never be re-published over a newer blob.
 *
 * @throws if the relay's blob fails verification. The caller fails closed.
 */
export async function restoreOwnDeviceList(opts: {
    /** The encrypted store, or `undefined` when it is not open yet. */
    gate: StorageGate | undefined;
    transport: DiscoveryTransport;
    /** The account handle the list is published under. */
    handle: string;
    /** The account primary's 33-byte public identity key. */
    expectedAccount: Uint8Array;
    /** The version already held in memory, if any. */
    heldVersion: number | null;
}): Promise<OwnListRestore | null> {
    const persisted = opts.gate
        ? await loadOwnDeviceList(opts.gate, opts.expectedAccount)
        : null;
    // §8.4 baseline for OUR OWN list only — never another account's version.
    // Take the max of the in-memory and persisted versions: if a persist ever
    // failed (the store is newer than memory), the lower memory version must
    // not let a relay blob between the two be adopted and downgrade the store.
    const baseline = Math.max(opts.heldVersion ?? 0, persisted?.version ?? 0) || null;

    const recorder = recordingTransport(opts.transport);
    const verified = await lookupDeviceList(
        recorder.transport,
        opts.handle,
        opts.expectedAccount,
        baseline,
    );
    if (verified) {
        const bytes = recorder.lastBlob();
        if (bytes) {
            // Re-verify the exact bytes that will be held and re-published, so
            // the held list is always the one the signature vouches for.
            return {
                list: verifyOwnDeviceList(bytes, opts.expectedAccount),
                // Only a client that already had a persisted list refreshes the
                // TTL: it is the one that has been away long enough for the
                // blob to be near expiry. A first run adopts the relay's list
                // without writing, so a plain page load never publishes.
                republish: persisted !== null,
            };
        }
    }
    if (persisted) return { list: persisted, republish: true };
    return null;
}
