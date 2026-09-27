/** @vitest-environment jsdom */
//
// TDD tests for NS-6D: `Conversation.send()` must
//
//   1. lazily RESTORE the sender session saved for the peer before falling back
//      to establishing a brand-new one, and
//   2. PERSIST the advanced ratchet state BEFORE handing the envelope to the
//      transport (a skipped ratchet step is safe; a reused message key is not).
//
// Real WASM crypto and a REAL StorageGate over fake-indexeddb (store 'session')
// are used; only the external boundaries are mocked: the relay transport, the
// storage key, and IndexedDB itself. `../src/storage` is wrapped by a subclass
// that delegates to the real StorageGate so one test can force the 'session'
// store's `put` to fail.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeAll, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';

// Conversation.tsx reads `globalThis.indexedDB` directly, so install
// fake-indexeddb on the global before any render.
(globalThis as any).indexedDB = fakeIndexedDB;

// Provide a stable 32-byte key so StorageGate can encrypt/decrypt.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

// Wraps the real StorageGate so one test can force a failed save of a session
// record. Delegates to the real implementation in every other case.
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
import {
    senderRecordId,
    restoreSessionRecord,
    persistSessionRecord,
} from '../src/session_persistence';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    bundle_identity_key_bytes,
    establish_session_from_bundle,
    decrypt_message,
    IdentityHandle,
    SessionHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

const KEY_BYTES = new Uint8Array(32);

// `InstanceType<typeof IdentityHandle>` trips TS2344 ("private constructor")
// repo-wide, so derive the handle types from the factory functions instead.
type WasmIdentity = ReturnType<typeof generate_identity>;
type WasmSession = ReturnType<typeof create_receiver_session>;

const RESTORE_FAILED =
    'Saved session for this peer could not be restored; establishing a new one';
const SAVE_FAILED = 'Could not save session state; message not sent';
const PEER_NOT_FOUND = 'Peer not found';

/** A real receiver-side session (the "peer") and the bundle it published. */
interface Receiver {
    identity: WasmIdentity;
    session: WasmSession;
    bundle: Uint8Array;
    identityKey: Uint8Array;
}

function makeReceiver(): Receiver {
    const identity = generate_identity();
    const session = create_receiver_session(identity);
    const bundle = publish_bundle_bytes(session);
    return { identity, session, bundle, identityKey: bundle_identity_key_bytes(bundle) };
}

/** Minimal PersistedIdentity-shaped wrapper around a real wasm IdentityHandle. */
function toIdentity(handle: WasmIdentity) {
    return { handle, publicBytes: handle.public_bytes(), recipientId: 'alice-recipient' };
}

interface SentEnvelope {
    recipientId: string;
    envelope: Uint8Array;
}

/** A transport that serves `bundles` by recipient id and records what was sent. */
function makeTransport(
    bundles: Record<string, Uint8Array>,
    sent: SentEnvelope[],
    onSend?: () => Promise<void>,
) {
    return {
        lookupPrekey: vi.fn(async (recipientId: string) => {
            const bundle = bundles[recipientId];
            if (!bundle) throw new Error('NotFound');
            return bundle;
        }),
        sendEnvelope: vi.fn(async (recipientId: string, envelope: Uint8Array) => {
            if (onSend) await onSend();
            sent.push({ recipientId, envelope });
        }),
        pickupEnvelope: vi.fn(async () => {
            throw new Error('NotFound');
        }),
    };
}

/**
 * A transport whose `lookupPrekey` stays pending until `release()` is called, so
 * a test can observe the status shown while the prekey lookup is in flight.
 */
function makeDeferredTransport(bundle: Uint8Array, sent: SentEnvelope[]) {
    let release!: () => void;
    const pending = new Promise<Uint8Array>((resolve) => {
        release = () => resolve(bundle);
    });
    return {
        lookupPrekey: vi.fn(() => pending),
        sendEnvelope: vi.fn(async (recipientId: string, envelope: Uint8Array) => {
            sent.push({ recipientId, envelope });
        }),
        pickupEnvelope: vi.fn(async () => {
            throw new Error('NotFound');
        }),
        release,
    };
}

/** A transport whose prekey lookup always fails (peer unreachable). */
function makeUnreachableTransport() {
    return {
        lookupPrekey: vi.fn(async () => {
            throw new Error('NotFound');
        }),
        sendEnvelope: vi.fn(async () => {}),
        pickupEnvelope: vi.fn(async () => {
            throw new Error('NotFound');
        }),
    };
}

/** Type a peer id and a message, then press Send. */
function typeAndSend(peerId: string, body: string): void {
    fireEvent.change(screen.getByLabelText('Recipient ID'), { target: { value: peerId } });
    fireEvent.change(screen.getByPlaceholderText('Type a message'), { target: { value: body } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
}

async function waitForText(text: string): Promise<void> {
    await waitFor(() => expect(screen.getByText(text)).toBeInTheDocument());
}

/** Let mount-time storage I/O (history load) finish. */
async function settle(): Promise<void> {
    await act(async () => {
        for (let i = 0; i < 10; i++) {
            await new Promise((resolve) => setTimeout(resolve, 5));
        }
    });
}

async function openGate(): Promise<StorageGate> {
    const gate = new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
    await gate.open();
    return gate;
}

/** Read the raw (encrypted) record StorageGate wrote for `id`. */
function readRawSessionRecord(
    id: string,
): Promise<{ id: string; ciphertext: string } | undefined> {
    return new Promise((resolve, reject) => {
        const request = fakeIndexedDB.open('messaging');
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const db = request.result;
            const tx = db.transaction(['session'], 'readonly');
            const getRequest = tx.objectStore('session').get(id);
            getRequest.onsuccess = () => resolve(getRequest.result);
            getRequest.onerror = () => reject(getRequest.error);
        };
    });
}

function decryptWith(session: WasmSession, envelope: Uint8Array): string {
    return new TextDecoder().decode(decrypt_message(session, envelope));
}

/** The non-null identity keys `spy` reported for `peerId`, as plain arrays. */
function reportedIdentityKeys(
    spy: { mock: { calls: unknown[][] } },
    peerId: string,
): number[][] {
    return spy.mock.calls
        .filter((call) => call[0] === peerId && call[1] != null)
        .map((call) => Array.from(call[1] as Uint8Array));
}

/** What the store held at the moment `sendEnvelope` was called. */
let restoredAtSendTime: { remoteIdentityKey: Uint8Array | null } | null = null;

beforeAll(async () => {
    await ensureWasmInit();
});

beforeEach(() => {
    failSessionPut = false;
    restoredAtSendTime = null;
    // Wipe fake IndexedDB between tests so a reused record id never leaks state
    // into the next case.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }
});

describe('Conversation send persists and restores the sender session', () => {
    test('the first send saves a sender session record for the peer', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        render(
            <Conversation identity={alice} transport={makeTransport({ bob: bob.bundle }, sent)} />,
        );
        await settle();

        typeAndSend('bob', 'hello bob');
        await waitForText('hello bob');

        const gate = await openGate();
        const restored = await restoreSessionRecord(gate, senderRecordId('bob'), alice.handle);
        expect(restored).not.toBeNull();
        expect(Array.from(restored!.remoteIdentityKey!)).toEqual(Array.from(bob.identityKey));
    });

    test('the session is saved before the envelope is handed to the transport', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle }, sent, async () => {
            const gate = await openGate();
            restoredAtSendTime = await restoreSessionRecord(
                gate,
                senderRecordId('bob'),
                alice.handle,
            );
        });
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        typeAndSend('bob', 'hello bob');
        await waitForText('hello bob');

        expect(restoredAtSendTime).not.toBeNull();
        expect(Array.from(restoredAtSendTime!.remoteIdentityKey!)).toEqual(
            Array.from(bob.identityKey),
        );
    });

    test('a restored sender session continues the ratchet after a reload without a new prekey lookup', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle }, sent);

        const first = render(<Conversation identity={alice} transport={transport} />);
        await settle();
        typeAndSend('bob', 'message one');
        await waitForText('message one');
        first.unmount();

        render(<Conversation identity={alice} transport={transport} />);
        await settle();
        typeAndSend('bob', 'message two');
        await waitForText('message two');

        expect(transport.lookupPrekey).toHaveBeenCalledTimes(1);
        expect(decryptWith(bob.session, sent[0].envelope)).toBe('message one');
        expect(decryptWith(bob.session, sent[1].envelope)).toBe('message two');
    });

    test('a restored sender session reports the peer identity key to the caller', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle }, sent);

        const first = render(<Conversation identity={alice} transport={transport} />);
        await settle();
        typeAndSend('bob', 'message one');
        await waitForText('message one');
        first.unmount();

        const onRemoteIdentityKeyChange = vi.fn();
        render(
            <Conversation
                identity={alice}
                transport={transport}
                onRemoteIdentityKeyChange={onRemoteIdentityKeyChange}
            />,
        );
        await settle();
        typeAndSend('bob', 'message two');
        await waitForText('message two');

        expect(reportedIdentityKeys(onRemoteIdentityKeyChange, 'bob')).toEqual([
            Array.from(bob.identityKey),
        ]);
    });

    test('two peers keep independent saved sender sessions', async () => {
        const bob = makeReceiver();
        const carol = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle, carol: carol.bundle }, sent);
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        typeAndSend('bob', 'hi bob');
        await waitForText('hi bob');
        typeAndSend('carol', 'hi carol');
        await waitForText('hi carol');

        const gate = await openGate();
        const bobRecord = await restoreSessionRecord(gate, senderRecordId('bob'), alice.handle);
        const carolRecord = await restoreSessionRecord(gate, senderRecordId('carol'), alice.handle);
        expect(Array.from(bobRecord!.remoteIdentityKey!)).toEqual(Array.from(bob.identityKey));
        expect(Array.from(carolRecord!.remoteIdentityKey!)).toEqual(Array.from(carol.identityKey));
        expect(decryptWith(bob.session, sent[0].envelope)).toBe('hi bob');
        expect(decryptWith(carol.session, sent[1].envelope)).toBe('hi carol');
    });

    test('a failed session save blocks the send and reports it', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle }, sent);
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        failSessionPut = true;
        typeAndSend('bob', 'hello bob');
        await waitForText(SAVE_FAILED);

        expect(transport.sendEnvelope).not.toHaveBeenCalled();
        expect(screen.queryByText('hello bob')).not.toBeInTheDocument();
    });

    test('a corrupt saved record falls back to establishing a new session', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const gate = await openGate();
        await gate.put('session', senderRecordId('bob'), { v: 2 });

        const transport = makeDeferredTransport(bob.bundle, sent);
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        typeAndSend('bob', 'hello bob');
        await waitForText(RESTORE_FAILED);
        expect(transport.lookupPrekey).toHaveBeenCalledTimes(1);

        transport.release();
        await waitForText('hello bob');
        expect(decryptWith(bob.session, sent[0].envelope)).toBe('hello bob');
    });

    test('a saved record without a remote identity key falls back to establishing a new session', async () => {
        const bob = makeReceiver();
        const aliceHandle = generate_identity();
        const alice = toIdentity(aliceHandle);
        const sent: SentEnvelope[] = [];
        const gate = await openGate();
        const staleSession = establish_session_from_bundle(aliceHandle, bob.bundle);
        await persistSessionRecord(gate, senderRecordId('bob'), staleSession);

        const transport = makeDeferredTransport(bob.bundle, sent);
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        typeAndSend('bob', 'hello bob');
        await waitForText(RESTORE_FAILED);
        expect(transport.lookupPrekey).toHaveBeenCalledTimes(1);

        transport.release();
        await waitForText('hello bob');
        expect(decryptWith(bob.session, sent[0].envelope)).toBe('hello bob');
    });

    test('a saved session for another peer is never used when sending to a different peer', async () => {
        const bob = makeReceiver();
        const carol = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        const transport = makeTransport({ bob: bob.bundle, carol: carol.bundle }, sent);
        render(<Conversation identity={alice} transport={transport} />);
        await settle();

        typeAndSend('bob', 'hi bob');
        await waitForText('hi bob');
        typeAndSend('carol', 'hi carol');
        await waitForText('hi carol');

        expect(transport.lookupPrekey).toHaveBeenCalledTimes(2);
        expect(decryptWith(carol.session, sent[1].envelope)).toBe('hi carol');
    });

    test('the stored session record contains no plaintext', async () => {
        const bob = makeReceiver();
        const alice = toIdentity(generate_identity());
        const sent: SentEnvelope[] = [];
        render(
            <Conversation identity={alice} transport={makeTransport({ bob: bob.bundle }, sent)} />,
        );
        await settle();

        typeAndSend('bob', 'topsecret payload');
        await waitForText('topsecret payload');

        const raw = await readRawSessionRecord(senderRecordId('bob'));
        expect(raw).toBeDefined();
        expect(JSON.stringify(raw)).not.toContain('topsecret');
        expect(JSON.stringify(window.localStorage)).not.toContain('topsecret');
        expect(JSON.stringify(window.sessionStorage)).not.toContain('topsecret');
    });

    test('an unreachable peer with no saved session still reports Peer not found', async () => {
        const alice = toIdentity(generate_identity());
        render(<Conversation identity={alice} transport={makeUnreachableTransport()} />);
        await settle();

        typeAndSend('bob', 'hello bob');
        await waitForText(PEER_NOT_FOUND);

        expect(screen.queryByText('hello bob')).not.toBeInTheDocument();
    });
});
