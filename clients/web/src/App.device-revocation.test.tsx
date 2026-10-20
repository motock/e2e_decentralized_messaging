// @vitest-environment jsdom
//
// MF-2: the revoke control is offered ONLY on the primary device (id 0).
//
// CONTRACT pinned here:
//   * The current device id comes from the persisted account-device link record
//     (MD-16: store `identity`, id `account-device-list`) — NOT from the first
//     entry of the signed list.
//   * No record, `deviceId: 0`, and a malformed record all resolve to device 0
//     (the primary), so the revoke control is rendered. A malformed id such as
//     `"2"` must NOT be coerced to numeric 2.
//   * A persisted `deviceId: 2` leaves `onRevokeDevice` undefined, so the real
//     DeviceLinking renders no revoke control and App never calls revokeDevice —
//     before the read resolves, after it resolves, after a rerender, and after a
//     remount.
//
// Only the WASM module, the relay transport, the storage key, StorageGate,
// `revokeDevice` and Conversation are mocked. The real DeviceLinking renders the
// linked-devices section, so the assertion is on the actual accessible name.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';

// ── Hoisted shared state (referenced from the vi.mock factories) ────────────
const h = vi.hoisted(() => {
    const BUNDLE = new Uint8Array([9, 9, 9]);
    const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

    function makeKeypair() {
        const priv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) priv[i] = Math.floor(Math.random() * 256);
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return { priv, pub };
    }

    /** The store/id MD-16 persists the account-device link record under. */
    const LINK_KEY = 'identity/account-device-list';

    const storage = {
        /** Records keyed by `${store}/${id}`. */
        records: new Map<string, unknown>(),
        /** How many times the account-device link record has been read. */
        linkReads: 0,
        /** When set, the link read awaits this promise instead of resolving. */
        deferred: null as null | { promise: Promise<unknown>; resolve: (v: unknown) => void },
        /** When true, the link read rejects (unreadable record). */
        linkThrows: false,
    };

    /** Props App passed to Conversation, in render order. */
    const conversationProps: any[] = [];

    const relay = {
        /** The blob served for the account's OWN handle. */
        ownBlob: null as Uint8Array | null,
        published: [] as { handle: string; blob: Uint8Array }[],
    };

    return { BUNDLE, keypairs, makeKeypair, LINK_KEY, storage, conversationProps, relay };
});

// ── WASM mock (external boundary: the compiled bindings) ────────────────────
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        const kp = h.makeKeypair();
        h.keypairs.push(kp);
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        const match = h.keypairs.find((kp) => kp.priv.every((b, i) => b === bytes[i]));
        const kp = match ?? h.makeKeypair();
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => h.BUNDLE.slice(),
    generate_prekey_bundle: () => h.BUNDLE.slice(),
    derive_safety_number: () => '00000 00000',
    sign_device_list: (_priv: Uint8Array, version: number, packed: Uint8Array) => {
        const out = new Uint8Array(1 + packed.length);
        out[0] = version;
        out.set(packed, 1);
        return out;
    },
    verify_device_list: (bytes: Uint8Array) => {
        const out = new Uint8Array(8 + bytes.length - 1);
        new DataView(out.buffer).setBigUint64(0, BigInt(bytes[0]), true);
        out.set(bytes.slice(1), 8);
        return out;
    },
    fanout_establish: () => ({}),
    fanout_remove_device: () => {},
    FanoutDeviceInput: class {
        constructor(
            public device_id: number,
            public expected_identity_key_bytes: Uint8Array,
            public bundle_bytes: Uint8Array,
        ) {}
    },
    FanoutHandle: class {},
}));

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

// ── StorageGate mock (external boundary: the encrypted store) ───────────────
// Only open/get/put are used by App and the identity loader. The link record
// read is the one under test, so it is observable and can be deferred.
vi.mock('../src/storage', async (importOriginal) => {
    const actual = await importOriginal<any>();
    return {
        ...actual,
        StorageGate: class {
            constructor(_opts: unknown) {}
            async open(): Promise<void> {}
            async put(store: string, id: string, value: unknown): Promise<void> {
                h.storage.records.set(`${store}/${id}`, value);
            }
            async get(store: string, id: string): Promise<unknown | null> {
                const key = `${store}/${id}`;
                if (key === h.LINK_KEY) {
                    h.storage.linkReads += 1;
                    if (h.storage.linkThrows) throw new Error('unreadable record');
                    if (h.storage.deferred) return h.storage.deferred.promise;
                }
                return h.storage.records.get(key) ?? null;
            }
        },
    };
});

// ── revokeDevice mock (external boundary: the revocation implementation) ────
vi.mock('../src/revocation', async (importOriginal) => {
    const actual = await importOriginal<any>();
    return { ...actual, revokeDevice: vi.fn() };
});

// ── Transport mock ──────────────────────────────────────────────────────────
vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: async () => {},
            connect: async () => {},
            close: () => {},
            pickupEnvelope: () => Promise.reject(new Error('NotFound')),
            publishDiscovery: async (handle: string, blob: Uint8Array) => {
                h.relay.published.push({ handle, blob });
            },
            lookupDiscovery: async () => h.relay.ownBlob,
        };
    }),
}));

// Conversation is stubbed to null so the direct view stays cheap; its props are
// recorded because App passes the resolved link's `deviceId` to it, which is a
// deterministic signal that the persisted id has been read.
vi.mock('../src/Conversation', async () => {
    const actual = await vi.importActual<any>('../src/Conversation');
    return {
        ...actual,
        Conversation: (props: any) => {
            h.conversationProps.push(props);
            return null;
        },
    };
});

import App from '../src/App';
import { revokeDevice } from '../src/revocation';

// ── Fixtures ────────────────────────────────────────────────────────────────
function pack(entries: { deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }[]) {
    let size = 0;
    for (const e of entries) size += 12 + e.identityKey.length + e.bundleBytes.length;
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const e of entries) {
        view.setUint32(pos, e.deviceId, true);
        pos += 4;
        view.setUint32(pos, e.identityKey.length, true);
        pos += 4;
        out.set(e.identityKey, pos);
        pos += e.identityKey.length;
        view.setUint32(pos, e.bundleBytes.length, true);
        pos += 4;
        out.set(e.bundleBytes, pos);
        pos += e.bundleBytes.length;
    }
    return out;
}

function signedBlob(version: number, entries: Parameters<typeof pack>[0]): Uint8Array {
    const packed = pack(entries);
    const out = new Uint8Array(1 + packed.length);
    out[0] = version;
    out.set(packed, 1);
    return out;
}

const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: h.BUNDLE };
const dev2 = { deviceId: 2, identityKey: new Uint8Array(33).fill(3), bundleBytes: h.BUNDLE };

/** The MD-16 record shape, as persisted by the linking handshake. */
function linkRecord(deviceId: unknown) {
    return {
        accountHandle: 'acct-handle',
        deviceId,
        signedListBytesBase64: 'AAAA',
    };
}

function deferLinkRead() {
    let resolve!: (v: unknown) => void;
    const promise = new Promise<unknown>((r) => {
        resolve = r;
    });
    h.storage.deferred = { promise, resolve };
    return { promise, resolve };
}

const revokeControls = () => screen.queryAllByRole('button', { name: /revoke/i });
const lastConversation = () => h.conversationProps[h.conversationProps.length - 1];

/** Render App, wait for the identity, and open the Link view. */
async function openLinkView() {
    const view = render(<App />);
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Link' }));
    // The linked-devices section is fed from the account's own signed list
    // (devices 0 and 2), so this is the deterministic "list held" signal.
    await waitFor(() => expect(screen.getByText('Device 2')).toBeInTheDocument());
    return view;
}

beforeEach(() => {
    h.keypairs.length = 0;
    h.conversationProps.length = 0;
    h.storage.records.clear();
    h.storage.linkReads = 0;
    h.storage.deferred = null;
    h.storage.linkThrows = false;
    h.relay.published.length = 0;
    h.relay.ownBlob = signedBlob(1, [dev0, dev2]);
    vi.mocked(revokeDevice).mockClear();
});

afterEach(() => {
    cleanup();
});

describe('MF-2: revoke control is offered only on the primary device', () => {
    test('renders the revoke control when no link record is persisted (device 0)', async () => {
        await openLinkView();

        await waitFor(() => expect(revokeControls()).toHaveLength(2));
        expect(revokeControls()[0]).toHaveAccessibleName(/revoke/i);
    });

    test('renders the revoke control when the persisted device id is 0', async () => {
        h.storage.records.set(h.LINK_KEY, linkRecord(0));

        await openLinkView();

        await waitFor(() => expect(revokeControls()).toHaveLength(2));
    });

    test('renders the revoke control for a malformed device id ("2" is not coerced to 2)', async () => {
        // A careless `Number(raw.deviceId)` would resolve this to device 2 and
        // wrongly suppress the control on the primary.
        h.storage.records.set(h.LINK_KEY, linkRecord('2'));

        await openLinkView();

        await waitFor(() => expect(revokeControls()).toHaveLength(2));
    });

    test('renders the revoke control when the link record is unreadable', async () => {
        h.storage.linkThrows = true;

        await openLinkView();

        await waitFor(() => expect(revokeControls()).toHaveLength(2));
    });

    test('a linked device (id 2) never gets the revoke control, before or after the read', async () => {
        const deferred = deferLinkRead();

        // ── Pending: the persisted id is not known yet ──────────────────────
        const { rerender, unmount } = await openLinkView();
        expect(h.storage.linkReads).toBe(1);
        expect(revokeControls()).toHaveLength(0);

        // ── Loaded: the record resolves to device 2 ─────────────────────────
        // Persist it too, so the rerender/remount below read the same record.
        h.storage.records.set(h.LINK_KEY, linkRecord(2));
        await act(async () => {
            deferred.resolve(linkRecord(2));
        });
        h.storage.deferred = null;
        expect(revokeControls()).toHaveLength(0);

        // Prove the id really resolved to 2 (not silently reset to 0): App
        // hands the resolved id to Conversation.
        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        await waitFor(() => expect(lastConversation()?.deviceId).toBe(2));

        fireEvent.click(screen.getByRole('button', { name: 'Link' }));
        await waitFor(() => expect(screen.getByText('Device 2')).toBeInTheDocument());
        expect(revokeControls()).toHaveLength(0);
        expect(revokeDevice).not.toHaveBeenCalled();

        // ── Rerendered: same persisted record ───────────────────────────────
        rerender(<App />);
        expect(revokeControls()).toHaveLength(0);
        expect(revokeDevice).not.toHaveBeenCalled();

        // ── Remounted: the persisted record still says device 2 ─────────────
        unmount();
        await openLinkView();
        await waitFor(() => expect(h.storage.linkReads).toBeGreaterThanOrEqual(1));
        expect(revokeControls()).toHaveLength(0);
        expect(revokeDevice).not.toHaveBeenCalled();
    });
});
