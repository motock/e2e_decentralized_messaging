// @vitest-environment jsdom
//
// MD-18: revoking a device from the account's OWN signed list re-signs and
// re-publishes it at version+1, and App holds the new bytes.
//
// CONTRACT pinned here:
//   * `handleRevokeDevice` on a held own list calls `revokeDevice`, then holds
//     the returned list AND the returned raw bytes together — the linked-devices
//     section (fed from the own list) drops the revoked device.
//   * The relay receives exactly one new blob for the account handle, which
//     verifies to version+1 without the revoked device and still with device 0.
//   * A publish failure leaves the held list (and its bytes) unchanged: the
//     revoked device is still listed and no partial list is held.
//
// Only the WASM module, the relay transport, the storage key, Conversation and
// DeviceLinking are mocked; the real revocation + discovery orchestration runs.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';

(globalThis as any).indexedDB = fakeIndexedDB;

// ── Shared test state (referenced only from deferred closures) ──────────────
const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];
const BUNDLE = new Uint8Array([9, 9, 9]);

const relay = {
    /** The blob served for the account's OWN handle. */
    ownBlob: null as Uint8Array | null,
    published: [] as { handle: string; blob: Uint8Array }[],
    /** Handles looked up, in call order — the first is the account's own. */
    lookups: [] as string[],
    /** When true, publishing a discovery blob throws (relay unavailable). */
    failPublish: false,
};

const linkProps: any[] = [];

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
// them into the real `u64_le(version) || packed` shape the modules expect.
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
                if (relay.failPublish) throw new Error('relay unavailable');
                relay.published.push({ handle, blob });
            },
            lookupDiscovery: async (handle: string) => {
                relay.lookups.push(handle);
                return relay.ownBlob;
            },
        };
    }),
}));

// ── Component stubs that record the props App actually passes ───────────────
vi.mock('../src/Conversation', async () => {
    const actual = await vi.importActual<any>('../src/Conversation');
    return { ...actual, Conversation: () => null };
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

/** Decode a published blob back to its version and device ids. */
function decodeBlob(blob: Uint8Array): { version: number; deviceIds: number[] } {
    const version = blob[0];
    const packed = blob.subarray(1);
    const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
    const deviceIds: number[] = [];
    let pos = 0;
    while (pos < packed.length) {
        deviceIds.push(view.getUint32(pos, true));
        pos += 4;
        const idLen = view.getUint32(pos, true);
        pos += 4 + idLen;
        const bundleLen = view.getUint32(pos, true);
        pos += 4 + bundleLen;
    }
    return { version, deviceIds };
}

const lastLink = () => linkProps[linkProps.length - 1];

const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: BUNDLE };
const dev2 = { deviceId: 2, identityKey: new Uint8Array(33).fill(3), bundleBytes: BUNDLE };

/** Render App and wait until the own list (version 1, devices 0 and 2) is held. */
async function renderWithOwnList() {
    relay.ownBlob = signedBlob(1, [dev0, dev2]);
    render(<App />);
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    // The linked-devices section (and its revoke controls) lives on the Link view.
    fireEvent.click(screen.getByRole('button', { name: 'Link' }));
    await waitFor(() => expect(lastLink()?.deviceList?.version).toBe(1));
    expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0, 2]);
}

beforeEach(() => {
    keypairs.length = 0;
    linkProps.length = 0;
    relay.ownBlob = null;
    relay.published.length = 0;
    relay.failPublish = false;
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();
});

describe('App device revocation publishes a signed version+1 list (MD-18)', () => {
    test('revoking device 2 publishes version 2 without device 2 and with device 0', async () => {
        await renderWithOwnList();
        // The account handle App looked its own list up under — the same handle
        // the new list must be published under.
        const accountHandle = relay.lookups[0];
        expect(accountHandle).toBeTruthy();

        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });

        // App holds the new list: device 2 gone, device 0 kept, version bumped.
        await waitFor(() => expect(lastLink()?.deviceList?.version).toBe(2));
        expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0]);

        // Exactly one new blob was published, for this account, at version 2.
        expect(relay.published).toHaveLength(1);
        expect(relay.published[0].handle).toBe(accountHandle);
        expect(decodeBlob(relay.published[0].blob)).toEqual({ version: 2, deviceIds: [0] });
        // The held raw bytes are the published ones, so a later re-sign starts
        // from what the relay actually holds.
        expect(lastLink().currentListBytes).toEqual(relay.published[0].blob);
    });

    test('a publish failure leaves the held list unchanged', async () => {
        await renderWithOwnList();
        relay.failPublish = true;

        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });

        // Nothing was published and the revoked device is still listed.
        expect(relay.published).toHaveLength(0);
        expect(lastLink().deviceList.version).toBe(1);
        expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0, 2]);
    });

    test('the primary device (0) cannot be revoked and nothing is published', async () => {
        await renderWithOwnList();

        await act(async () => {
            await lastLink().onRevokeDevice(0);
        });

        expect(relay.published).toHaveLength(0);
        expect(lastLink().deviceList.version).toBe(1);
        expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0, 2]);
    });
});
