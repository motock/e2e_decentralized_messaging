/** @vitest-environment jsdom */
//
// TDD tests for NS-6C: the Conversation receive loop must persist the receiver
// session after every successful decrypt, so a reload can continue the
// conversation instead of losing the ratchet state.
//
// Real WASM crypto and a REAL StorageGate over fake-indexeddb (store 'session')
// are used; only the external boundaries are mocked: the relay transport
// (`pickupEnvelope`), the storage key, and IndexedDB itself. `../src/storage` is
// wrapped by a subclass that delegates to the real StorageGate, so a single test
// can force the 'session' store's `put` to fail.
//
// Only the polling interval is faked: fake-indexeddb and React need real
// setTimeout/setImmediate to make progress, so faking every timer would hang.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';

// Conversation.tsx reads `globalThis.indexedDB` directly, so install
// fake-indexeddb on the global before any render.
(globalThis as any).indexedDB = fakeIndexedDB;

// Provide a stable 32-byte key so StorageGate can encrypt/decrypt.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

// Wraps the real StorageGate so one test can force a failed save of the receiver
// session record. Delegates to the real implementation in every other case.
let failSessionPut = false;

vi.mock('../src/storage', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../src/storage')>();
    class WrappedStorageGate extends actual.StorageGate {
        async put(store: any, id: string, value: unknown): Promise<void> {
            if (failSessionPut && store === 'session') {
                throw new Error('session store unavailable');
            }
            return super.put(store, id, value);
        }
    }
    return { ...actual, StorageGate: WrappedStorageGate };
});

import { Conversation } from '../src/Conversation';
import { ensureWasmInit } from '../src/wasm_init';
import { StorageGate } from '../src/storage';
import { RECEIVER_RECORD_ID, restoreSessionRecord } from '../src/session_persistence';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    establish_session_from_bundle,
    encrypt_message,
    IdentityHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

const KEY_BYTES = new Uint8Array(32);

const PERSISTENCE_WARNING =
    'Session state could not be saved. Messages received after a reload may fail to decrypt.';
const DECRYPTION_WARNING =
    'A received message could not be verified and was discarded. ' +
    'This may indicate a tampered or corrupted message.';

/** Envelopes handed out by the mocked transport, one per poll. */
let envelopeQueue: Uint8Array[] = [];

/** A transport whose pickupEnvelope drains `envelopeQueue` (NotFound when empty). */
function makeTransport() {
    return {
        lookupPrekey: vi.fn(),
        sendEnvelope: vi.fn(),
        pickupEnvelope: vi.fn(async () => {
            const next = envelopeQueue.shift();
            if (!next) throw new Error('NotFound');
            return next;
        }),
    };
}

/** Minimal PersistedIdentity-shaped wrapper around a real wasm IdentityHandle. */
function toIdentity(handle: InstanceType<typeof IdentityHandle>) {
    return {
        handle,
        publicBytes: handle.public_bytes(),
        recipientId: 'test-recipient',
    };
}

/** A real receiver (Bob) and a real sender (Alice) session built on Bob's bundle. */
function setupRoundTrip() {
    const bobIdentity = generate_identity();
    const bobSession = create_receiver_session(bobIdentity);
    const bobBundle = publish_bundle_bytes(bobSession);

    const aliceIdentity = generate_identity();
    const aliceSession = establish_session_from_bundle(aliceIdentity, bobBundle);

    const bob = toIdentity(bobIdentity);

    function encryptToBob(plaintext: string): Uint8Array {
        return encrypt_message(aliceSession, new TextEncoder().encode(plaintext));
    }

    return { bob, bobIdentity, bobSession, encryptToBob };
}

/** Read the raw (encrypted) record StorageGate wrote for the receiver session. */
function readRawSessionRecord(): Promise<{ id: string; ciphertext: string } | undefined> {
    return new Promise((resolve, reject) => {
        const request = fakeIndexedDB.open('messaging');
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const db = request.result;
            const tx = db.transaction(['session'], 'readonly');
            const getRequest = tx.objectStore('session').get(RECEIVER_RECORD_ID);
            getRequest.onsuccess = () => resolve(getRequest.result);
            getRequest.onerror = () => reject(getRequest.error);
        };
    });
}

/** Number of message rows currently rendered. */
function messageCount(): number {
    return document.querySelectorAll('.msg-row').length;
}

/** Let the mount-time poll and its storage I/O finish. */
async function settle(): Promise<void> {
    await act(async () => {
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setTimeout(resolve, 5));
        }
    });
}

/** Fire the polling interval once and let the resulting poll finish. */
async function advanceToNextPoll(): Promise<void> {
    await act(async () => {
        vi.advanceTimersByTime(5000);
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setTimeout(resolve, 5));
        }
    });
}

beforeAll(async () => {
    await ensureWasmInit();
});

beforeEach(() => {
    failSessionPut = false;
    envelopeQueue = [];
    // Wipe fake IndexedDB between tests so the reused receiver record id never
    // leaks state into the next case.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
});

afterEach(() => {
    vi.useRealTimers();
});

describe('Conversation receive loop persists the receiver session', () => {
    test('a successfully decrypted message is saved as the receiver session record', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('hello receiver')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        expect(screen.getByText('hello receiver')).toBeInTheDocument();
        expect(await readRawSessionRecord()).toBeDefined();
    });

    test('a restored receiver session decrypts a second message after a reload', async () => {
        const { bob, bobIdentity, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('first message')];

        const first = render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByText('first message')).toBeInTheDocument();
        first.unmount();

        const gate = new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
        await gate.open();
        const restored = await restoreSessionRecord(gate, RECEIVER_RECORD_ID, bobIdentity);
        expect(restored).not.toBeNull();

        // Mount with an empty mailbox and let the history load settle first, so the
        // second message is appended after (not overwritten by) the reloaded history.
        envelopeQueue = [];
        render(
            <Conversation
                identity={bob}
                transport={makeTransport()}
                receiverSession={restored!.session}
            />,
        );
        await settle();
        expect(screen.getByText('first message')).toBeInTheDocument();

        envelopeQueue = [encryptToBob('second message')];
        await advanceToNextPoll();

        expect(screen.getByText('second message')).toBeInTheDocument();
    });

    test('the stored receiver record changes after a second message', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('message one')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByText('message one')).toBeInTheDocument();
        const afterFirst = await readRawSessionRecord();

        envelopeQueue = [encryptToBob('message two')];
        await advanceToNextPoll();
        expect(screen.getByText('message two')).toBeInTheDocument();
        const afterSecond = await readRawSessionRecord();

        expect(afterSecond!.ciphertext).not.toBe(afterFirst!.ciphertext);
    });

    test('a garbage envelope leaves the stored receiver record byte-identical and adds no message', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('valid message')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByText('valid message')).toBeInTheDocument();
        const before = await readRawSessionRecord();

        envelopeQueue = [new Uint8Array([0xde, 0xad, 0xbe, 0xef])];
        await advanceToNextPoll();

        const after = await readRawSessionRecord();
        expect(after!.ciphertext).toBe(before!.ciphertext);
        expect(messageCount()).toBe(1);
    });

    test('a failed session save still displays the decrypted message and warns', async () => {
        failSessionPut = true;
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('still delivered')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        expect(screen.getByText('still delivered')).toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent(PERSISTENCE_WARNING);
    });

    test('the persistence warning clears after a later successful save', async () => {
        failSessionPut = true;
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('first delivery')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByRole('alert')).toHaveTextContent(PERSISTENCE_WARNING);

        failSessionPut = false;
        envelopeQueue = [encryptToBob('second delivery')];
        await advanceToNextPoll();

        expect(screen.getByText('second delivery')).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('a garbage envelope does not clear an existing persistence warning', async () => {
        failSessionPut = true;
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        envelopeQueue = [encryptToBob('delivered once')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByRole('alert')).toHaveTextContent(PERSISTENCE_WARNING);

        failSessionPut = false;
        envelopeQueue = [new Uint8Array([0xde, 0xad, 0xbe, 0xef])];
        await advanceToNextPoll();

        const alerts = screen.getAllByRole('alert').map(el => el.textContent);
        expect(alerts).toContain(PERSISTENCE_WARNING);
        expect(messageCount()).toBe(1);
    });

    test('the stored receiver record never contains the decrypted plaintext', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        const plaintext = 'top secret plaintext';
        envelopeQueue = [encryptToBob(plaintext)];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();
        expect(screen.getByText(plaintext)).toBeInTheDocument();

        const raw = await readRawSessionRecord();
        expect(JSON.stringify(raw)).not.toContain(plaintext);
    });

    test('a garbage envelope shows the existing decryption-failure alert', async () => {
        const { bob, bobSession } = setupRoundTrip();
        envelopeQueue = [new Uint8Array([0xde, 0xad, 0xbe, 0xef])];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        expect(screen.getByRole('alert')).toHaveTextContent(DECRYPTION_WARNING);
        expect(messageCount()).toBe(0);
    });
});
