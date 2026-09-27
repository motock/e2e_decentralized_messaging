// @vitest-environment jsdom
//
// NS-6B2: App must hand the StorageGate it already opens for identity loading
// to useRelayConnection, so the receiver session is restored from (and
// re-persisted to) the encrypted store instead of being recreated on every
// load.
//
// Behavioral only: the REAL WASM module and a REAL StorageGate over
// fake-indexeddb are used. Only external boundaries are mocked — the relay
// transport, the storage key, and IndexedDB itself.

import '@testing-library/jest-dom';
import { render, screen, waitFor } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';
import { describe, test, expect, vi, beforeEach } from 'vitest';

// App.tsx reads `globalThis.indexedDB` directly, so fake-indexeddb must be
// installed on the global before any render.
(globalThis as any).indexedDB = fakeIndexedDB;

// ── Relay transport mock ────────────────────────────────────────────────────
//
// publishPrekey is a spy we can assert on. A holder object keeps a stable
// reference for the hoisted mock factory; the vi.fn instances are (re)created
// in beforeEach.
type RelaySpy = ReturnType<typeof vi.fn<(...args: unknown[]) => unknown>>;

const mockHolder: { publishPrekey: RelaySpy; connect: RelaySpy } = {
    publishPrekey: vi.fn<(...args: unknown[]) => unknown>(),
    connect: vi.fn<(...args: unknown[]) => unknown>(),
};

vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: (...args: unknown[]) => mockHolder.publishPrekey(...args),
            connect: (...args: unknown[]) => mockHolder.connect(...args),
            // The receive loop polls pickupEnvelope on mount. A NotFound
            // rejection is treated as an empty poll (no error banner).
            pickupEnvelope: () => Promise.reject(new Error('NotFound')),
        };
    }),
}));

// ── Storage key mock ───────────────────────────────────────────────────────
// A stable 32-byte key so StorageGate can encrypt/decrypt.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

import { ensureWasmInit } from '../src/wasm_init';
import { StorageGate } from '../src/storage';
import App from '../src/App';
import {
    generate_identity,
    create_receiver_session,
    session_to_bytes,
} from '../../../core/bindings/wasm/pkg/index.js';

const KEY_BYTES = new Uint8Array(32);
const SESSION_STORE = 'session';
const RECEIVER_RECORD_ID = 'receiver';

function newGate(): StorageGate {
    return new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
}

/** The recipient ID App currently renders (base64 of the identity public key). */
function renderedRecipientId(): string {
    const code = screen.getByTitle('Copy your recipient ID').querySelector('code');
    return code?.textContent ?? '';
}

/** The (recipientId, bundle) pair recorded for the nth publishPrekey call. */
function publishedCall(index: number): { recipientId: string; bundle: Uint8Array } {
    const [recipientId, bundle] = mockHolder.publishPrekey.mock.calls[index];
    return { recipientId: recipientId as string, bundle: bundle as Uint8Array };
}

/**
 * Write a receiver session record that belongs to a *different* identity, so
 * restoring it with App's own identity must fail closed.
 */
async function writeForeignReceiverRecord(): Promise<void> {
    const gate = newGate();
    await gate.open();
    const otherIdentity = generate_identity();
    const otherSession = create_receiver_session(otherIdentity);
    await gate.put(SESSION_STORE, RECEIVER_RECORD_ID, {
        v: 1,
        blob: Array.from(session_to_bytes(otherSession)),
    });
}

/** Write a structurally invalid receiver session record (unknown version). */
async function writeCorruptReceiverRecord(): Promise<void> {
    const gate = newGate();
    await gate.open();
    await gate.put(SESSION_STORE, RECEIVER_RECORD_ID, { v: 2 });
}

beforeEach(async () => {
    mockHolder.publishPrekey = vi.fn().mockResolvedValue(undefined);
    mockHolder.connect = vi.fn().mockResolvedValue(undefined);

    // Wipe fake IndexedDB between tests.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }

    await ensureWasmInit();
});

describe('App session persistence wiring', () => {
    test('republishes a byte-identical bundle after a remount, restoring the persisted receiver session', async () => {
        const first = render(<App />);
        await waitFor(() => {
            expect(mockHolder.publishPrekey).toHaveBeenCalledTimes(1);
        });
        const firstPublish = publishedCall(0);
        first.unmount();

        render(<App />);
        await waitFor(() => {
            expect(mockHolder.publishPrekey).toHaveBeenCalledTimes(2);
        });
        const secondPublish = publishedCall(1);

        expect(secondPublish.recipientId).toBe(firstPublish.recipientId);
        expect(Array.from(secondPublish.bundle)).toEqual(Array.from(firstPublish.bundle));
    });

    test('starts and publishes a fresh session when the stored receiver record belongs to another identity', async () => {
        await writeForeignReceiverRecord();

        render(<App />);

        await waitFor(() => {
            expect(mockHolder.publishPrekey).toHaveBeenCalled();
        });
        const { recipientId, bundle } = publishedCall(0);

        expect(recipientId).toHaveLength(44);
        expect(bundle.length).toBeGreaterThan(0);
        await waitFor(() => {
            expect(renderedRecipientId()).toBe(recipientId);
        });
    });

    test('starts and publishes a fresh session when the stored receiver record is corrupt', async () => {
        await writeCorruptReceiverRecord();

        render(<App />);

        await waitFor(() => {
            expect(mockHolder.publishPrekey).toHaveBeenCalled();
        });
        const { recipientId, bundle } = publishedCall(0);

        expect(recipientId).toHaveLength(44);
        expect(bundle.length).toBeGreaterThan(0);
        await waitFor(() => {
            expect(renderedRecipientId()).toBe(recipientId);
        });
    });

    test('shows the unreachable state when the relay rejects publishPrekey', async () => {
        mockHolder.publishPrekey = vi.fn().mockRejectedValue(new Error('relay unreachable'));

        render(<App />);

        await waitFor(() => {
            expect(screen.getByText(/can't reach relay/i)).toBeInTheDocument();
        }, { timeout: 3000 });
    });
});
