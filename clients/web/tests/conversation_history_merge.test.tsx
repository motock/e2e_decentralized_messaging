/** @vitest-environment jsdom */
//
// TDD tests for NS-6H: the mount-time history load must not discard a message
// that arrives while the load is in flight.
//
// The load effect reads the stored history and then replaces the whole message
// array, so an envelope picked up during the read is dropped from both the UI
// and state (and is unrecoverable: the relay removed the envelope on pickup and
// `seenEnvelopesRef` already deduped it). These tests hold the history read open
// by hand, deliver an envelope while it is pending, and then resolve the read.
//
// Real WASM crypto and a REAL StorageGate over fake-indexeddb are used; only the
// external boundaries are mocked: the relay transport (`pickupEnvelope`), the
// storage key, and IndexedDB itself. `../src/storage` is wrapped by a subclass
// that delegates to the real StorageGate but lets a test (a) hold the
// `get('messages', 'history')` read open and (b) observe every write to the
// 'messages' store.
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

/**
 * When true, a `get('messages', 'history')` returns `historyRead.promise`
 * instead of reading the store, so a test can keep the mount-time history load
 * in flight and resolve it by hand.
 */
let holdHistoryRead = false;
let historyRead: { promise: Promise<unknown>; resolve: (value: unknown) => void } | null = null;
/** Every value written to the 'messages' store, in order. */
let historyWrites: unknown[] = [];

vi.mock('../src/storage', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../src/storage')>();
    class WrappedStorageGate extends actual.StorageGate {
        async get(store: any, id: string): Promise<unknown> {
            if (holdHistoryRead && store === 'messages') {
                return historyRead!.promise;
            }
            return super.get(store, id);
        }
        async put(store: any, id: string, value: unknown): Promise<void> {
            if (store === 'messages') historyWrites.push(value);
            return super.put(store, id, value);
        }
    }
    return { ...actual, StorageGate: WrappedStorageGate };
});

import { Conversation } from '../src/Conversation';
import { ensureWasmInit } from '../src/wasm_init';
import { StorageGate } from '../src/storage';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    establish_session_from_bundle,
    encrypt_message,
    IdentityHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

const KEY_BYTES = new Uint8Array(32);

/**
 * The id Conversation.tsx generates for a received message is
 * `Math.random().toString(36).substr(2, 9)`. `(265/432).toString(36)` is exactly
 * "0.m3", so mocking Math.random to 265/432 makes that id 'm3' — which lets a
 * test deliver a message whose id overlaps the stored history.
 */
const RANDOM_FOR_M3 = 265 / 432;

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

    return { bob, bobSession, encryptToBob };
}

/** A hand-resolved promise, used to hold the history read open. */
function makeDeferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>(r => {
        resolve = r;
    });
    return { promise, resolve };
}

/** A stored-history entry. Body mirrors the id so rendered order is readable. */
function storedMessage(id: string) {
    return { id, body: id, timestamp: 1, sentByMe: false };
}

/**
 * Seed the stored message history through the real StorageGate, then forget the
 * seeding write so assertions only see writes made by the component.
 */
async function seedHistory(history: unknown): Promise<void> {
    const gate = new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
    await gate.open();
    await gate.put('messages', 'history', history);
    historyWrites = [];
}

/** The rendered message bodies, in render order. */
function renderedBodies(): string[] {
    return Array.from(document.querySelectorAll('.msg-row')).map(row => {
        const bubble = row.querySelector('.msg-bubble')!;
        const time = row.querySelector('.msg-time')!;
        return bubble.textContent!.replace(time.textContent!, '').trim();
    });
}

/** The ids of the most recent write to the 'messages' store. */
function lastStoredIds(): string[] {
    const last = historyWrites[historyWrites.length - 1] as Array<{ id: string }> | undefined;
    return (last ?? []).map(m => m.id);
}

/** Let the mount-time poll and its storage I/O finish. */
async function settle(): Promise<void> {
    await act(async () => {
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setTimeout(resolve, 5));
        }
    });
}

/** Resolve the held history read and let the resulting render/persist settle. */
async function resolveHistoryRead(value: unknown): Promise<void> {
    await act(async () => {
        historyRead!.resolve(value);
    });
    await settle();
}

beforeAll(async () => {
    await ensureWasmInit();
});

beforeEach(() => {
    holdHistoryRead = false;
    historyRead = null;
    historyWrites = [];
    envelopeQueue = [];
    // Wipe fake IndexedDB between tests so stored history never leaks across cases.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    // Deterministic received-message id: 'm3' (see RANDOM_FOR_M3).
    vi.spyOn(Math, 'random').mockReturnValue(RANDOM_FOR_M3);
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('Conversation history load merges with messages received during the load', () => {
    test('a message received while the load is in flight survives the load and is persisted', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        await seedHistory([storedMessage('m1'), storedMessage('m2')]);

        historyRead = makeDeferred<unknown>();
        holdHistoryRead = true;
        envelopeQueue = [encryptToBob('m3')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        // The envelope was picked up and rendered while the load is still pending.
        expect(renderedBodies()).toEqual(['m3']);

        await resolveHistoryRead([storedMessage('m1'), storedMessage('m2')]);

        expect(renderedBodies()).toEqual(['m1', 'm2', 'm3']);
        expect(lastStoredIds()).toEqual(['m1', 'm2', 'm3']);
    });

    test('a message received during the load is not duplicated when the load returns overlapping history', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        await seedHistory([storedMessage('m1'), storedMessage('m2'), storedMessage('m3')]);

        historyRead = makeDeferred<unknown>();
        holdHistoryRead = true;
        // The generated id for this envelope is 'm3' (Math.random is mocked).
        envelopeQueue = [encryptToBob('m3')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        expect(renderedBodies()).toEqual(['m3']);

        await resolveHistoryRead([
            storedMessage('m1'),
            storedMessage('m2'),
            storedMessage('m3'),
        ]);

        expect(renderedBodies()).toEqual(['m1', 'm2', 'm3']);
        expect(document.querySelectorAll('.msg-row').length).toBe(3);
    });

    test('a stored non-empty history is still rendered on mount after the load', async () => {
        const { bob, bobSession } = setupRoundTrip();
        await seedHistory([storedMessage('m1'), storedMessage('m2')]);

        historyRead = makeDeferred<unknown>();
        holdHistoryRead = true;
        envelopeQueue = [];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        await resolveHistoryRead([storedMessage('m1'), storedMessage('m2')]);

        expect(renderedBodies()).toEqual(['m1', 'm2']);
    });

    test('an empty stored history renders nothing and does not crash', async () => {
        const { bob, bobSession } = setupRoundTrip();
        await seedHistory([]);

        historyRead = makeDeferred<unknown>();
        holdHistoryRead = true;
        envelopeQueue = [];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        await resolveHistoryRead([]);

        expect(renderedBodies()).toEqual([]);
        expect(screen.getByText('No messages yet.')).toBeInTheDocument();
    });

    test('with no stored history, a message received during the load is rendered and persisted', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        // No seed: the store has never been written, so the read returns null.
        historyRead = makeDeferred<unknown>();
        holdHistoryRead = true;
        envelopeQueue = [encryptToBob('m3')];

        render(
            <Conversation identity={bob} transport={makeTransport()} receiverSession={bobSession} />,
        );
        await settle();

        expect(renderedBodies()).toEqual(['m3']);

        await resolveHistoryRead(null);

        expect(renderedBodies()).toEqual(['m3']);
        expect(lastStoredIds()).toEqual(['m3']);
    });
});
