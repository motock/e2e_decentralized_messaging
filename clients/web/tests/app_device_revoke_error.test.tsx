// @vitest-environment jsdom
//
// MF-1: a failed device revocation must be SURFACED, not swallowed.
//
// CONTRACT pinned here:
//   * A rejected revoke (the held list does not verify) leaves the held list
//     untouched, publishes nothing, and renders a role="alert" message.
//   * The message is generic: it must not leak keys, list bytes, or the
//     underlying relay/verification error text.
//   * A later successful revoke clears the alert.
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
    /** When true, verifying the held list throws (unverifiable/tampered list). */
    failVerify: false,
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
        if (relay.failVerify) throw new Error('signature verification failed');
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
    relay.lookups.length = 0;
    relay.failPublish = false;
    relay.failVerify = false;
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();
});

describe('App surfaces a failed device revocation (MF-1)', () => {
    test('a rejected revoke leaves the held list untouched, publishes nothing and renders an alert', async () => {
        await renderWithOwnList();
        // The held list no longer verifies (tampered / foreign list).
        relay.failVerify = true;

        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });

        // Fail closed: the revoked device is still listed at the held version.
        expect(lastLink().deviceList.version).toBe(1);
        expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0, 2]);
        // Nothing was published.
        expect(relay.published).toHaveLength(0);
        // The failure is surfaced.
        expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    test('the alert message is generic and leaks no verification or relay detail', async () => {
        await renderWithOwnList();
        relay.failVerify = true;

        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });

        const alert = screen.getByRole('alert');
        expect(alert).toHaveTextContent(
            'Device revocation failed; the device is still trusted by peers',
        );
        // The underlying thrown message ("signature verification failed") must
        // never reach the UI.
        expect(alert.textContent ?? '').not.toMatch(/signature|verification failed/i);
    });

    test('a successful revoke clears a prior error', async () => {
        await renderWithOwnList();
        relay.failPublish = true;

        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });
        expect(screen.getByRole('alert')).toBeInTheDocument();
        // The failed publish left the list untouched, so device 2 is still there.
        expect(lastLink().deviceList.version).toBe(1);

        // The relay recovers; the retried revoke succeeds.
        relay.failPublish = false;
        await act(async () => {
            await lastLink().onRevokeDevice(2);
        });

        await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
        expect(lastLink().deviceList.version).toBe(2);
        expect(lastLink().deviceList.devices.map((d: any) => d.deviceId)).toEqual([0]);
        expect(relay.published).toHaveLength(1);
    });
});
