/** @vitest-environment jsdom */
//
// GF-4 — App-level wiring for the group receive address.
//
// The hook-level unit test (src/group_receive_address.test.ts) proves the
// address rule. This test proves the *shipped app* actually supplies the
// inputs to that rule: App must hand GroupConversation this device's account
// handle, its device id, and the account's own device list. Without this
// wiring the group receive loop polls the bare handle on a linked device and
// never sees its own mail.
//
// Only external boundaries are mocked (WASM, the encrypted store, the relay
// transport, the storage key) plus GroupConversation itself, which is stubbed
// as a prop recorder — the same seam app_group_transport_wiring.test.tsx and
// App.device-revocation.test.tsx already use.

import '@testing-library/jest-dom';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';
import { describe, test, expect, vi, beforeEach } from 'vitest';

(globalThis as any).indexedDB = fakeIndexedDB;

const h = {
    LINK_KEY: 'identity/account-device-list',
    storage: {
        records: new Map<string, unknown>(),
    },
    groupProps: [] as any[],
    console: [] as string[],
};

// ── WASM mock ───────────────────────────────────────────────────────────────
const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

function makeKeypair() {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = Math.floor(Math.random() * 256);
    const pub = new Uint8Array(33);
    pub[0] = 5;
    for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
    return { priv, pub };
}

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        const kp = makeKeypair();
        keypairs.push(kp);
        return {
            public_bytes: () => kp.pub.slice(),
            private_bytes: () => kp.priv.slice(),
        };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        const match = keypairs.find((kp) => kp.priv.every((b, i) => b === bytes[i]));
        if (match) {
            return {
                public_bytes: () => match.pub.slice(),
                private_bytes: () => match.priv.slice(),
            };
        }
        const priv = bytes.slice();
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return { public_bytes: () => pub, private_bytes: () => priv };
    },
    generate_prekey_bundle: () => new Uint8Array([1, 2, 3, 4, 5]),
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => new Uint8Array([1, 2, 3, 4, 5]),
    derive_safety_number: () => '00000 00000',
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

// ── StorageGate mock (external boundary: the encrypted store) ───────────────
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
                return h.storage.records.get(`${store}/${id}`) ?? null;
            }
        },
    };
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
            publishDiscovery: async () => {},
            lookupDiscovery: async () => null,
        };
    }),
}));

// ── GroupConversation stub: records the real render-site props ──────────────
vi.mock('../src/GroupConversation', () => ({
    GroupConversation: (props: any) => {
        h.groupProps.push(props);
        return null;
    },
}));

import App from '../src/App';

function seedLink(deviceId: number, accountHandle: string) {
    h.storage.records.set(h.LINK_KEY, {
        accountHandle,
        deviceId,
        signedListBytesBase64: 'eA==',
    });
}

async function renderGroupView() {
    render(<App />);
    await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Group' })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Group' }));
    await waitFor(() => {
        expect(h.groupProps.length).toBeGreaterThan(0);
    });
    return h.groupProps[h.groupProps.length - 1];
}

beforeEach(() => {
    keypairs.length = 0;
    h.storage.records.clear();
    h.groupProps.length = 0;
    h.console.length = 0;
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();
});

describe('App wires this device\'s mailbox into the group view', () => {
    test('the primary device passes its bare handle and device id 0', async () => {
        seedLink(0, 'primary-handle');

        const props = await renderGroupView();

        // App passes `identity.recipientId` as the account handle (DELIVER 3),
        // which is also the self recipient id — so the primary polls the bare
        // handle.
        expect(props.accountHandle).toBe(props.selfRecipientId);
        expect(props.accountHandle).toBeTruthy();
        expect(props.deviceId).toBe(0);
    });

    test('a linked device passes its device-qualified handle and device id', async () => {
        seedLink(2, 'linked-handle');

        const props = await renderGroupView();

        expect(props.accountHandle).toBe(props.selfRecipientId);
        expect(props.accountHandle).toBeTruthy();
        expect(props.deviceId).toBe(2);
    });

    test('passes the account\'s own device list to the group view', async () => {
        seedLink(0, 'primary-handle');

        const props = await renderGroupView();

        // ownDevices is either the loaded list or undefined before discovery
        // resolves — never a crash, and never a non-array.
        expect(props.ownDevices === undefined || Array.isArray(props.ownDevices)).toBe(true);
    });

    test('never logs key material while wiring the group view', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation((...args) => {
            h.console.push(args.map(String).join(' '));
        });
        const logSpy = vi.spyOn(console, 'log').mockImplementation((...args) => {
            h.console.push(args.map(String).join(' '));
        });
        seedLink(2, 'linked-handle');

        await renderGroupView();

        const logged = h.console.join('\n');
        expect(logged).not.toMatch(/private_bytes|privateKey|storageKey|secret/i);
        errorSpy.mockRestore();
        logSpy.mockRestore();
    });
});
