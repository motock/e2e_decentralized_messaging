/** @vitest-environment jsdom */
//
// TDD tests for the web session-persistence module (NS-6A).
//
// A serialized Double-Ratchet session is secret ratchet state, so it may only
// ever be written through `StorageGate` (AES-256-GCM at rest). These tests use
// the REAL wasm bindings (built via `npm run prepare-wasm`) and a REAL
// `StorageGate` over `fake-indexeddb`; only the external boundaries are mocked
// (IndexedDB itself and the storage key), matching the convention in
// tests/app_identity.test.tsx and tests/wasm_session_persistence.test.ts.
//
// Positive cases prove a persisted session continues the conversation after a
// restore. Negative/boundary cases prove the restore boundary fails closed:
// malformed records are rejected with `SessionRecordError` before any WASM call,
// while WASM-level failures (wrong identity, garbage blob) propagate unchanged.

import { describe, test, expect, beforeAll, beforeEach, vi } from 'vitest';
import fakeIndexedDB from 'fake-indexeddb';

// StorageGate takes the IDBFactory explicitly, but install the global too so
// nothing in the import graph reaches for an undefined `indexedDB`.
(globalThis as any).indexedDB = fakeIndexedDB;

// Provide a stable 32-byte key so StorageGate can encrypt/decrypt.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

import { StorageGate } from '../src/storage';
import { ensureWasmInit } from '../src/wasm_init';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    establish_session_from_bundle,
    encrypt_message,
    decrypt_message,
    bundle_identity_key_bytes,
    session_to_bytes,
} from '../../../core/bindings/wasm/pkg/index.js';
import {
    SessionRecordError,
    RECEIVER_RECORD_ID,
    senderRecordId,
    persistSessionRecord,
    restoreSessionRecord,
} from '../src/session_persistence';

const KEY_BYTES = new Uint8Array(32);

/** The error a gate's `put` rejects with, to prove it propagates unchanged. */
const PUT_FAILURE = new Error('disk full');

beforeAll(async () => {
    await ensureWasmInit();
});

beforeEach(() => {
    // Wipe fake IndexedDB between tests so record ids reused across tests
    // (RECEIVER_RECORD_ID) never leak state into the next case.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }
});

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** An opened real StorageGate over fake-indexeddb. */
async function newGate(): Promise<StorageGate> {
    const gate = new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
    await gate.open();
    return gate;
}

function encode(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

function decode(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}

/** A receiver session plus the prekey bundle a sender must use to reach it. */
function receiverWithBundle() {
    const identity = generate_identity();
    const session = create_receiver_session(identity);
    const bundle = publish_bundle_bytes(session);
    return { identity, session, bundle };
}

/** A sender session established from `bundle`, plus the identity that owns it. */
function senderFor(bundle: Uint8Array) {
    const identity = generate_identity();
    const session = establish_session_from_bundle(identity, bundle);
    return { identity, session };
}

/** A real, valid serialized receiver session blob, as a plain number array. */
function validReceiverBlob(): number[] {
    return Array.from(session_to_bytes(receiverWithBundle().session));
}

/** Capture a promise's rejection reason, or null if it resolved. */
async function captureError(promise: Promise<unknown>): Promise<unknown> {
    try {
        await promise;
        return null;
    } catch (error) {
        return error;
    }
}

/** Capture either a promise's resolved value or its rejection reason. */
async function captureOutcome(promise: Promise<unknown>): Promise<{ returned: unknown; error: unknown }> {
    try {
        return { returned: await promise, error: null };
    } catch (error) {
        return { returned: undefined, error };
    }
}

/** Store `record` under the receiver id, then return the restore error (or null). */
async function restoreErrorFor(record: unknown): Promise<unknown> {
    const gate = await newGate();
    const identity = generate_identity();
    await gate.put('session', RECEIVER_RECORD_ID, record);
    return captureError(restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity));
}

/** A gate whose `put` always rejects with PUT_FAILURE. */
function gateWithFailingPut(): StorageGate {
    return {
        put: () => Promise.reject(PUT_FAILURE),
        get: () => Promise.resolve(null),
    } as unknown as StorageGate;
}

/* ------------------------------------------------------------------ */
/* Positive path                                                       */
/* ------------------------------------------------------------------ */

describe('session persistence round-trip', () => {
    test('a persisted receiver session restores and decrypts a message from a sender built on its original bundle', async () => {
        const gate = await newGate();
        const { identity, session, bundle } = receiverWithBundle();

        await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);
        const restored = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity);

        const sender = senderFor(bundle);
        const envelope = encrypt_message(sender.session, encode('hello receiver'));

        expect(decode(decrypt_message(restored!.session, envelope))).toBe('hello receiver');
    });

    test('a persisted sender session restores with its remote identity key and encrypts a message the receiver decrypts', async () => {
        const gate = await newGate();
        const receiver = receiverWithBundle();
        const sender = senderFor(receiver.bundle);
        const remoteIdentityKey = bundle_identity_key_bytes(receiver.bundle);

        await persistSessionRecord(gate, senderRecordId('bob'), sender.session, remoteIdentityKey);
        const restored = await restoreSessionRecord(gate, senderRecordId('bob'), sender.identity);

        expect(Array.from(restored!.remoteIdentityKey!)).toEqual(Array.from(remoteIdentityKey));

        const envelope = encrypt_message(restored!.session, encode('next message'));
        expect(decode(decrypt_message(receiver.session, envelope))).toBe('next message');
    });

    test('restoring a record id nothing was saved under returns null', async () => {
        const gate = await newGate();
        const identity = generate_identity();

        expect(await restoreSessionRecord(gate, senderRecordId('nobody'), identity)).toBeNull();
    });

    test('two sender record ids hold independent sessions', async () => {
        const gate = await newGate();
        const first = receiverWithBundle();
        const second = receiverWithBundle();
        const firstSender = senderFor(first.bundle);
        const secondSender = senderFor(second.bundle);

        await persistSessionRecord(gate, senderRecordId('a'), firstSender.session);
        await persistSessionRecord(gate, senderRecordId('b'), secondSender.session);
        const restoredFirst = await restoreSessionRecord(gate, senderRecordId('a'), firstSender.identity);
        const restoredSecond = await restoreSessionRecord(gate, senderRecordId('b'), secondSender.identity);

        const toFirst = encrypt_message(restoredFirst!.session, encode('to first'));
        const toSecond = encrypt_message(restoredSecond!.session, encode('to second'));

        expect(decode(decrypt_message(first.session, toFirst))).toBe('to first');
        expect(decode(decrypt_message(second.session, toSecond))).toBe('to second');
    });

    test('persisting twice under one id keeps the latest session state', async () => {
        const gate = await newGate();
        const { identity, session, bundle } = receiverWithBundle();
        const sender = senderFor(bundle);

        await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);
        expect(decode(decrypt_message(session, encrypt_message(sender.session, encode('m1'))))).toBe('m1');

        await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);
        const restored = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity);

        expect(decode(decrypt_message(restored!.session, encrypt_message(sender.session, encode('m2'))))).toBe('m2');
    });

    test('a restored session can be persisted again and continue the conversation', async () => {
        const gate = await newGate();
        const { identity, session, bundle } = receiverWithBundle();
        const sender = senderFor(bundle);

        await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);
        const first = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity);
        expect(decode(decrypt_message(first!.session, encrypt_message(sender.session, encode('m1'))))).toBe('m1');

        await persistSessionRecord(gate, RECEIVER_RECORD_ID, first!.session);
        const second = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity);

        expect(decode(decrypt_message(second!.session, encrypt_message(sender.session, encode('m2'))))).toBe('m2');
    });

    test("senderRecordId('x') is 'sender:x'", () => {
        expect(senderRecordId('x')).toBe('sender:x');
    });
});

/* ------------------------------------------------------------------ */
/* Negative / boundary: malformed records fail closed                  */
/* ------------------------------------------------------------------ */

describe('restoreSessionRecord rejects malformed records with SessionRecordError', () => {
    test('rejects a record whose version is not 1', async () => {
        expect(await restoreErrorFor({ v: 2, blob: 'x' })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a record with no version field', async () => {
        expect(await restoreErrorFor({ blob: [1, 2, 3] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a record whose blob is not an array', async () => {
        expect(await restoreErrorFor({ v: 1, blob: 'not-an-array' })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a record with an empty blob', async () => {
        expect(await restoreErrorFor({ v: 1, blob: [] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a blob containing a byte above 255', async () => {
        expect(await restoreErrorFor({ v: 1, blob: [0, 256] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a blob containing a negative byte', async () => {
        expect(await restoreErrorFor({ v: 1, blob: [-1] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a blob containing a non-integer byte', async () => {
        expect(await restoreErrorFor({ v: 1, blob: [0, 255, 1.5] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a blob containing a string entry', async () => {
        expect(await restoreErrorFor({ v: 1, blob: ['2'] })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a blob longer than the maximum record size', async () => {
        expect(await restoreErrorFor({ v: 1, blob: Array(1048577).fill(0) })).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a remote identity key of 32 bytes', async () => {
        const record = { v: 1, blob: validReceiverBlob(), remoteIdentityKey: Array(32).fill(0) };
        expect(await restoreErrorFor(record)).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a remote identity key of 34 bytes', async () => {
        const record = { v: 1, blob: validReceiverBlob(), remoteIdentityKey: Array(34).fill(0) };
        expect(await restoreErrorFor(record)).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a record that is a plain string', async () => {
        expect(await restoreErrorFor('hello')).toBeInstanceOf(SessionRecordError);
    });

    test('rejects a record that is an array', async () => {
        expect(await restoreErrorFor([1, 2, 3])).toBeInstanceOf(SessionRecordError);
    });
});

/* ------------------------------------------------------------------ */
/* Negative / boundary: WASM-level failures propagate unchanged        */
/* ------------------------------------------------------------------ */

describe('restoreSessionRecord propagates WASM failures unchanged', () => {
    test('restoring a valid record under a different identity rejects with a WASM Session error and no session', async () => {
        const gate = await newGate();
        const { session } = receiverWithBundle();
        await persistSessionRecord(gate, RECEIVER_RECORD_ID, session);

        const outcome = await captureOutcome(
            restoreSessionRecord(gate, RECEIVER_RECORD_ID, generate_identity()),
        );

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).not.toBeInstanceOf(SessionRecordError);
        expect((outcome.error as { kind: string }).kind).toBe('Session');
    });

    test('a valid-shaped but garbage blob rejects with a WASM error, not a SessionRecordError', async () => {
        const error = await restoreErrorFor({ v: 1, blob: [1, 2, 3, 4, 5] });

        expect(error).not.toBeInstanceOf(SessionRecordError);
        expect((error as { kind: string }).kind).toBe('Session');
    });

    test('a blob of exactly the maximum record size is not rejected by the length check', async () => {
        const error = await restoreErrorFor({ v: 1, blob: Array(1048576).fill(0) });

        expect(error).not.toBeInstanceOf(SessionRecordError);
    });
});

/* ------------------------------------------------------------------ */
/* Negative / boundary: persist propagates gate failures               */
/* ------------------------------------------------------------------ */

describe('persistSessionRecord', () => {
    test('rejects with the gate error when the gate put rejects', async () => {
        const session = create_receiver_session(generate_identity());

        expect(await captureError(persistSessionRecord(gateWithFailingPut(), RECEIVER_RECORD_ID, session))).toBe(PUT_FAILURE);
    });
});
