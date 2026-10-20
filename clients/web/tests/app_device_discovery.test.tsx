// @vitest-environment jsdom
//
// MD-17: App loads its OWN device list and its PEERS' device lists from the
// signed-discovery layer (discovery.ts, MD-9) instead of relying on a prop.
//
// CONTRACT pinned here:
//   * With identity + receiverSession available, App looks up its own list. When
//     the relay holds none it seeds version 1 containing device 0 (this device),
//     signs it with the identity's private bytes and publishes it.
//   * The raw signed bytes and the held version are kept, and handed to
//     DeviceLinking as `currentListBytes` / `heldListVersion` so its primary
//     scan path can enforce §8.4 freshness.
//   * A peer's list (reported via onRemoteIdentityKeyChange) is applied only
//     when strictly newer; a verification failure leaves the held list
//     untouched and never throws out of render.
//   * `heldListVersion` is never undefined/null while a list is held.
//
// Only the WASM module, the relay transport, the storage key, Conversation and
// DeviceLinking are mocked; the real discovery orchestration runs.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';

(globalThis as any).indexedDB = fakeIndexedDB;

// ── Shared test state (referenced only from deferred closures) ──────────────
const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];
const BUNDLE = new Uint8Array([9, 9, 9]);

/** The fake relay's discovery store, keyed by handle. */
const relay = {
    byHandle: new Map<string, Uint8Array>(),
    defaultBlob: null as Uint8Array | null,
    published: [] as { handle: string; blob: Uint8Array }[],
    /** When set, verification for this expected account throws. */
    throwFor: null as Uint8Array | null,
};

const convProps: any[] = [];
const linkProps: any[] = [];

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((v, i) => v === b[i]);
}

function makeKeypair() {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = Math.floor(Math.random() * 256);
    const pub = new Uint8Array(33);
    pub[0] = 5;
    for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
    return { priv, pub };
}

// ── WASM mock ───────────────────────────────────────────────────────────────
// Test blobs are `[versionByte, ...packedEntries]`; verify_device_list turns
// them into the real `u64_le(version) || packed` shape discovery.ts expects.
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        const kp = makeKeypair();
        keypairs.push(kp);
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        const match = keypairs.find((kp) => kp.priv.every((b, i) => b === bytes[i]));
        const kp = match ?? makeKeypair();
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => BUNDLE.slice(),
    generate_prekey_bundle: () => BUNDLE.slice(),
    derive_safety_number: () => '00000 00000',
    sign_device_list: (_priv: Uint8Array, version: number, packed: Uint8Array) => {
        const out = new Uint8Array(1 + packed.length);
        out[0] = version;
        out.set(packed, 1);
        return out;
    },
    verify_device_list: (bytes: Uint8Array, expected: Uint8Array) => {
        if (relay.throwFor && bytesEqual(expected, relay.throwFor)) {
            throw new Error('device list: signature verification failed');
        }
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
                relay.published.push({ handle, blob });
                relay.byHandle.set(handle, blob);
            },
            lookupDiscovery: async (handle: string) =>
                relay.byHandle.get(handle) ?? relay.defaultBlob,
        };
    }),
}));

// ── Component stubs that record the props App actually passes ───────────────
vi.mock('../src/Conversation', async () => {
    const actual = await vi.importActual<any>('../src/Conversation');
    return {
        ...actual,
        Conversation: (props: any) => {
            convProps.push(props);
            return null;
        },
    };
});
vi.mock('../src/DeviceLinking', () => ({
    DeviceLinking: (props: any) => {
        linkProps.push(props);
        return null;
    },
}));

import App from '../src/App';

// ── Helpers ─────────────────────────────────────────────────────────────────
function pack(entries: { deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }[]) {
    let size = 0;
    for (const e of entries) size += 12 + e.identityKey.length + e.bundleBytes.length;
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const e of entries) {
        view.setUint32(pos, e.deviceId, true); pos += 4;
        view.setUint32(pos, e.identityKey.length, true); pos += 4;
        out.set(e.identityKey, pos); pos += e.identityKey.length;
        view.setUint32(pos, e.bundleBytes.length, true); pos += 4;
        out.set(e.bundleBytes, pos); pos += e.bundleBytes.length;
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

function decodePacked(packed: Uint8Array) {
    const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
    const entries: { deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }[] = [];
    let pos = 0;
    while (pos < packed.length) {
        const deviceId = view.getUint32(pos, true); pos += 4;
        const idLen = view.getUint32(pos, true); pos += 4;
        const identityKey = packed.slice(pos, pos + idLen); pos += idLen;
        const bLen = view.getUint32(pos, true); pos += 4;
        const bundleBytes = packed.slice(pos, pos + bLen); pos += bLen;
        entries.push({ deviceId, identityKey, bundleBytes });
    }
    return entries;
}

const lastConv = () => convProps[convProps.length - 1];
const lastLink = () => linkProps[linkProps.length - 1];

async function renderApp() {
    const utils = render(<App />);
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    return utils;
}

beforeEach(async () => {
    keypairs.length = 0;
    convProps.length = 0;
    linkProps.length = 0;
    relay.byHandle.clear();
    relay.published.length = 0;
    relay.defaultBlob = null;
    relay.throwFor = null;
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();
});

describe('App device discovery (MD-17)', () => {
    test('a version-2 list from discovery reaches Conversation', async () => {
        const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: BUNDLE };
        const dev1 = { deviceId: 1, identityKey: new Uint8Array(33).fill(2), bundleBytes: BUNDLE };
        relay.defaultBlob = signedBlob(2, [dev0, dev1]);

        await renderApp();

        await waitFor(() => expect(lastConv()?.deviceList?.version).toBe(2));
        expect(lastConv().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0, 1]);
        // Nothing was published: the account already had a list.
        expect(relay.published).toHaveLength(0);
    });

    test('an empty account list publishes version 1 containing device 0', async () => {
        await renderApp();

        await waitFor(() => expect(relay.published).toHaveLength(1));
        const { handle, blob } = relay.published[0];
        expect(handle).toBe(keypairs[0].pub && lastConv().identity.recipientId);
        expect(blob[0]).toBe(1);

        const entries = decodePacked(blob.slice(1));
        expect(entries).toHaveLength(1);
        expect(entries[0].deviceId).toBe(0);
        expect(entries[0].identityKey).toEqual(keypairs[0].pub);
        expect(entries[0].bundleBytes).toEqual(BUNDLE);

        await waitFor(() => expect(lastConv()?.deviceList?.version).toBe(1));
        expect(lastConv().deviceList.devices[0].deviceId).toBe(0);
    });

    test('DeviceLinking receives the held raw bytes and version', async () => {
        await renderApp();
        await waitFor(() => expect(relay.published).toHaveLength(1));

        fireEvent.click(screen.getByRole('button', { name: 'Link' }));

        await waitFor(() => expect(lastLink()).toBeTruthy());
        expect(lastLink().currentListBytes).toEqual(relay.published[0].blob);
        expect(lastLink().heldListVersion).toBe(1);
    });

    test('an older peer list does not replace the held one', async () => {
        const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: BUNDLE };
        const dev1 = { deviceId: 1, identityKey: new Uint8Array(33).fill(2), bundleBytes: BUNDLE };
        relay.defaultBlob = signedBlob(2, [dev0, dev1]);

        await renderApp();
        await waitFor(() => expect(lastConv()?.deviceList?.version).toBe(2));

        // The peer reports its real identity key; the relay serves a STALE
        // version-1 list for it. Monotonicity (§8.4) must reject it.
        const peerKey = new Uint8Array(33).fill(7);
        relay.byHandle.set('peer-handle', signedBlob(1, [dev0]));

        act(() => {
            lastConv().onRemoteIdentityKeyChange('peer-handle', peerKey);
        });

        // Give the async lookup a chance to settle, then assert nothing moved.
        await act(async () => {
            await Promise.resolve();
        });
        expect(lastConv().deviceList.version).toBe(2);
        expect(lastConv().deviceList.devices).toHaveLength(2);
    });

    test('a failed verification leaves the previous list untouched and does not throw', async () => {
        const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: BUNDLE };
        const dev1 = { deviceId: 1, identityKey: new Uint8Array(33).fill(2), bundleBytes: BUNDLE };
        relay.defaultBlob = signedBlob(2, [dev0, dev1]);

        await renderApp();
        await waitFor(() => expect(lastConv()?.deviceList?.version).toBe(2));

        const peerKey = new Uint8Array(33).fill(7);
        relay.throwFor = peerKey;
        relay.byHandle.set('peer-handle', signedBlob(9, [dev0]));

        // Must not throw out of render/act.
        act(() => {
            lastConv().onRemoteIdentityKeyChange('peer-handle', peerKey);
        });
        await act(async () => {
            await Promise.resolve();
        });

        expect(lastConv().deviceList.version).toBe(2);
        expect(lastConv().deviceList.devices).toHaveLength(2);
    });

    test('heldListVersion is never undefined while a list is held', async () => {
        await renderApp();
        await waitFor(() => expect(relay.published).toHaveLength(1));

        fireEvent.click(screen.getByRole('button', { name: 'Link' }));
        await waitFor(() => expect(lastLink()).toBeTruthy());

        expect(lastLink().heldListVersion).not.toBeUndefined();
        expect(lastLink().heldListVersion).not.toBeNull();
        expect(typeof lastLink().heldListVersion).toBe('number');
        expect(lastLink().heldListVersion).toBe(lastConv().deviceList.version);
    });
});
