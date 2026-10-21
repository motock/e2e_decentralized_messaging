// @vitest-environment jsdom
//
// DL-1: App must actually wire the device-linking handshake.
//
// The screen fails closed ("Device linking is not configured for this device")
// when any of `transport`, `identityHandle`, `storageGate`, `accountHandle` or
// `primaryBundleBytes` is missing. Before this story App passed none of them, so
// the whole linking path was unreachable from the shipped app even though the
// component-level tests passed (they render DeviceLinking directly with the full
// prop set). These assertions pin the real render-site prop set.
//
// Only external boundaries are mocked (WASM, relay transport, storage key,
// Conversation, DeviceLinking); the real App, identity and relay-connection
// orchestration run.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

const linkProps: any[] = [];
const persistedLink = vi.hoisted(() => ({ value: null as unknown }));
const BUNDLE = new Uint8Array([9, 9, 9]);

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => ({
        public_bytes: () => new Uint8Array(33).fill(5),
        private_bytes: () => new Uint8Array(32).fill(1),
    }),
    identity_from_bytes: () => ({
        public_bytes: () => new Uint8Array(33).fill(5),
        private_bytes: () => new Uint8Array(32).fill(1),
    }),
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
    FanoutDeviceInput: class {},
    FanoutHandle: class {},
}));

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'not-a-real-password',
}));
vi.mock('../src/storage', () => ({
    StorageGate: class {
        async open() {}
        async get(store: string, id: string) {
            if (store === 'identity' && id === 'account-device-list') {
                return persistedLink.value;
            }
            return null;
        }
        async put() {}
        async deleteItem() {}
    },
}));

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
            lookupPrekey: async () => new Uint8Array([1]),
        };
    }),
}));

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

const lastLink = () => linkProps[linkProps.length - 1];

async function openLinkView(): Promise<void> {
    render(<App />);
    await waitFor(() =>
        expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Link' }));
    await waitFor(() => expect(lastLink()).toBeTruthy());
}

beforeEach(() => {
    linkProps.length = 0;
    persistedLink.value = null;
});

describe('DL-1: App wires the real linking handshake', () => {
    test('passes the scan-path props for the primary device', async () => {
        await openLinkView();

        // The receiver session is published once the relay connection succeeds;
        // publish_bundle_bytes (mocked) yields the device-0 bundle.
        await waitFor(() => expect(lastLink().primaryBundleBytes).toEqual(BUNDLE));

        expect(lastLink().transport).toBeDefined();
        expect(lastLink().identityHandle).toBeDefined();
        expect(lastLink().storageGate).toBeDefined();
        expect(lastLink().accountHandle).toBeTruthy();
        expect(typeof lastLink().onOwnListPublished).toBe('function');
    });

    test('withholds the signing props from a linked device', async () => {
        persistedLink.value = {
            accountHandle: 'account-handle',
            deviceId: 2,
            signedListBytesBase64: 'AAAA',
        };
        await openLinkView();

        // currentDeviceId resolves to the persisted id; the primary-only signing
        // props must be absent so a linked device cannot publish a list peers
        // would reject.
        await waitFor(() => expect(lastLink().primaryBundleBytes).toBeUndefined());
        expect(lastLink().onOwnListPublished).toBeUndefined();
        // The display-path props remain available so the screen is not broken.
        expect(lastLink().transport).toBeDefined();
        expect(lastLink().identityHandle).toBeDefined();
    });
});
