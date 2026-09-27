// @vitest-environment jsdom
//
// NS-6B: `publishPrekeyForIdentity` must restore the persisted receiver session
// at startup instead of creating a new one on every load, so the prekey bundle
// a peer already fetched keeps decrypting after a reload.
//
// Behavioral only: the REAL WASM module is used (via `ensureWasmInit()`), and a
// REAL `StorageGate` over `fake-indexeddb`. Only external boundaries are mocked
// — the relay transport (a recording stub), `../src/storage_key` (a fixed
// 32-byte key) and IndexedDB itself. The code under test is never mocked.

import '@testing-library/jest-dom';
import fakeIndexedDB from 'fake-indexeddb';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';

// StorageGate reads `globalThis.indexedDB`-style factories via its options, but
// the module also touches the global in some paths; install it as the reference
// suite does.
(globalThis as any).indexedDB = fakeIndexedDB;

// A stable 32-byte key so StorageGate can encrypt/decrypt at rest.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

import { StorageGate } from '../src/storage';
import {
    publishPrekeyForIdentity,
    type PersistedIdentity,
    type IdentityHandleLike,
} from '../src/identity';
import { RECEIVER_RECORD_ID, restoreSessionRecord } from '../src/session_persistence';
import { ensureWasmInit } from '../src/wasm_init';
import {
    generate_identity,
    establish_session_from_bundle,
    encrypt_message,
    decrypt_message,
} from '../../../core/bindings/wasm/pkg/index.js';

const KEY_BYTES = new Uint8Array(32);

/** Static warning texts — asserted verbatim so no bytes/keys can leak into logs. */
const RESTORE_FAILED_WARN = 'receiver session restore failed; creating a new session';
const SAVE_FAILED_WARN = 'receiver session could not be saved; continuing in memory';

/** The IndexedDB store holding serialized session state (see session_persistence.ts). */
const SESSION_STORE = 'session';

/** A fresh, opened StorageGate over the shared fake IndexedDB. */
async function newGate(): Promise<StorageGate> {
    const gate = new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
    await gate.open();
    return gate;
}

/** Wrap a real WASM identity handle in the PersistedIdentity shape. */
function toIdentity(handle: IdentityHandleLike, recipientId: string): PersistedIdentity {
    return { handle, publicBytes: handle.public_bytes(), recipientId };
}

/** A relay transport stub that records every publishPrekey call. */
function recordingTransport() {
    return { publishPrekey: vi.fn().mockResolvedValue(undefined) };
}

/** The bundle bytes handed to the transport on its first publish. */
function firstBundle(transport: { publishPrekey: ReturnType<typeof vi.fn> }): Uint8Array {
    return transport.publishPrekey.mock.calls[0][1] as Uint8Array;
}

beforeEach(async () => {
    await ensureWasmInit();
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('publishPrekeyForIdentity receiver session persistence', () => {
    test('creates a session, saves a receiver record, and publishes a bundle', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        const transport = recordingTransport();

        await publishPrekeyForIdentity(identity, transport, gate);

        expect(transport.publishPrekey).toHaveBeenCalledTimes(1);
        const [recipientId, bundle] = transport.publishPrekey.mock.calls[0];
        expect(recipientId).toBe('alice');
        expect(bundle.length).toBeGreaterThan(0);

        const record = (await gate.get(SESSION_STORE, RECEIVER_RECORD_ID)) as {
            v: number;
            blob: number[];
        };
        expect(record.v).toBe(1);
        expect(Array.isArray(record.blob)).toBe(true);
    });

    test('a second call with the same gate and identity publishes a byte-identical bundle', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        const first = recordingTransport();
        const second = recordingTransport();

        await publishPrekeyForIdentity(identity, first, gate);
        await publishPrekeyForIdentity(identity, second, gate);

        expect(Array.from(firstBundle(second))).toEqual(Array.from(firstBundle(first)));
    });

    test('a message encrypted by a sender from the first bundle decrypts with the session returned by the second call', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        const first = recordingTransport();
        const second = recordingTransport();

        await publishPrekeyForIdentity(identity, first, gate);
        const restoredSession = await publishPrekeyForIdentity(identity, second, gate);

        const sender = generate_identity();
        const senderSession = establish_session_from_bundle(sender, firstBundle(first));
        const envelope = encrypt_message(senderSession, new TextEncoder().encode('hello after reload'));

        const plaintext = decrypt_message(restoredSession, envelope);
        expect(new TextDecoder().decode(plaintext)).toBe('hello after reload');
    });

    test('called with two arguments (no gate) it publishes and writes nothing', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        const transport = recordingTransport();

        const session = await publishPrekeyForIdentity(identity, transport);

        expect(session).toBeTruthy();
        expect(transport.publishPrekey).toHaveBeenCalledTimes(1);
        expect(await restoreSessionRecord(gate, RECEIVER_RECORD_ID, identity.handle)).toBeNull();
    });

    test('a corrupt saved record yields a fresh session, still publishes, warns once, and is replaced by a valid record', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        await gate.put(SESSION_STORE, RECEIVER_RECORD_ID, { v: 2 });
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const transport = recordingTransport();

        await publishPrekeyForIdentity(identity, transport, gate);

        expect(transport.publishPrekey).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledWith(RESTORE_FAILED_WARN);
        const record = (await gate.get(SESSION_STORE, RECEIVER_RECORD_ID)) as { v: number };
        expect(record.v).toBe(1);
    });

    test('after a corrupt record is replaced, the next call publishes a byte-identical bundle without warning again', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        await gate.put(SESSION_STORE, RECEIVER_RECORD_ID, { v: 2 });
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const first = recordingTransport();
        const second = recordingTransport();

        await publishPrekeyForIdentity(identity, first, gate);
        await publishPrekeyForIdentity(identity, second, gate);

        expect(warn).toHaveBeenCalledTimes(1);
        expect(Array.from(firstBundle(second))).toEqual(Array.from(firstBundle(first)));
    });

    test('a record saved for a different identity falls back to a fresh session and is replaced', async () => {
        const gate = await newGate();
        const bob = toIdentity(generate_identity(), 'bob');
        await publishPrekeyForIdentity(bob, recordingTransport(), gate);

        const alice = toIdentity(generate_identity(), 'alice');
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const transport = recordingTransport();

        const session = await publishPrekeyForIdentity(alice, transport, gate);

        expect(session).toBeTruthy();
        expect(transport.publishPrekey).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledWith(RESTORE_FAILED_WARN);
        expect(await restoreSessionRecord(gate, RECEIVER_RECORD_ID, alice.handle)).not.toBeNull();
    });

    test('a gate whose put rejects still returns a session and still publishes, warning that it continues in memory', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        vi.spyOn(gate, 'put').mockRejectedValue(new Error('quota'));
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const transport = recordingTransport();

        const session = await publishPrekeyForIdentity(identity, transport, gate);

        expect(session).toBeTruthy();
        expect(transport.publishPrekey).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn).toHaveBeenCalledWith(SAVE_FAILED_WARN);
    });

    test('a transport whose publishPrekey rejects still rejects even when a gate is supplied', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        const transport = { publishPrekey: vi.fn().mockRejectedValue(new Error('relay down')) };

        await expect(publishPrekeyForIdentity(identity, transport, gate)).rejects.toThrow('relay down');
    });

    test('the restore-failure warning is exactly the static string, with no bytes or keys', async () => {
        const gate = await newGate();
        const identity = toIdentity(generate_identity(), 'alice');
        await gate.put(SESSION_STORE, RECEIVER_RECORD_ID, { v: 2 });
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

        await publishPrekeyForIdentity(identity, recordingTransport(), gate);

        expect(warn.mock.calls).toEqual([[RESTORE_FAILED_WARN]]);
    });
});
