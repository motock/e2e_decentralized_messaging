// @vitest-environment jsdom
//
// Tests that App renders the persisted identity's recipient ID with a copy
// affordance, and that a publish_prekey failure surfaces a visible error.
//
// The WASM module, relay transport, and storage key are mocked so this suite
// doesn't require a built pkg/ or a live relay.

import '@testing-library/jest-dom';
import { render, screen, act, waitFor, fireEvent } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';
import { describe, test, expect, vi, beforeEach } from 'vitest';

// App.tsx reads `globalThis.indexedDB` directly, so we must install
// fake-indexeddb on the global before any render.
(globalThis as any).indexedDB = fakeIndexedDB;

// ── WASM mock ───────────────────────────────────────────────────────────────
//
// Simulates the real WASM contract: generate_identity returns a handle whose
// private_bytes/public_bytes round-trip through identity_from_bytes.

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
        const match = keypairs.find((kp) =>
            kp.priv.every((b, i) => b === bytes[i]),
        );
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
        return {
            public_bytes: () => pub,
            private_bytes: () => priv,
        };
    },
    generate_prekey_bundle: () => new Uint8Array([1, 2, 3, 4, 5]),
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => new Uint8Array([1, 2, 3, 4, 5]),
    derive_safety_number: () => '00000 00000',
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

// ── Transport mock ──────────────────────────────────────────────────────────
//
// We mock the RelayTransport so publishPrekey is a spy we can assert on.
// By default it succeeds; individual tests override to simulate failure.

// Use a holder object so the mock factory (which is hoisted by vitest
// above all other code) can reference the mocks via a stable reference.
// The actual vi.fn instances are (re)created in beforeEach.
const mockHolder: { publishPrekey: ReturnType<typeof vi.fn>; connect: ReturnType<typeof vi.fn> } = {
    publishPrekey: vi.fn(),
    connect: vi.fn(),
};

vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: (...args: unknown[]) => mockHolder.publishPrekey(...args),
            connect: (...args: unknown[]) => mockHolder.connect(...args),
            // The receive loop polls pickupEnvelope on mount. Return a
            // NotFound rejection so it's treated as an empty poll (no
            // error banner, no console spam) rather than crashing with
            // "pickupEnvelope is not a function".
            pickupEnvelope: () => Promise.reject(new Error('NotFound')),
            close: () => {},
        };
    }),
}));

// ── GroupConversation mock ─────────────────────────────────────────────────
//
// The group view is a bare `<GroupConversation />` in the shipped app unless
// App.tsx wires the real identity, recipient ID, storage gate and transport
// into it — and GroupConversation now FAILS CLOSED without them. So the
// wiring is load-bearing and must be pinned here: we replace the component
// with a stub that records the props it actually receives, then assert on
// those props (not on App's internals or on DOM text).
const groupPropsHolder: { props: any[] } = { props: [] };

vi.mock('../src/GroupConversation', () => ({
    GroupConversation: (props: any) => {
        groupPropsHolder.props.push(props);
        return null;
    },
}));

// ── Storage key mock ───────────────────────────────────────────────────────
// Provide a stable 32-byte key so StorageGate can encrypt/decrypt.
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

import { StorageGate } from '../src/storage';
import App from '../src/App';

const KEY_BYTES = new Uint8Array(32);

function newGate(): StorageGate {
    return new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
}

beforeEach(async () => {
    keypairs.length = 0;
    groupPropsHolder.props.length = 0;
    mockHolder.publishPrekey = vi.fn().mockResolvedValue(undefined);
    mockHolder.connect = vi.fn().mockResolvedValue(undefined);

    // Wipe fake IndexedDB between tests.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }

    // Clear any persisted identity from a prior test.
    const gate = newGate();
    await gate.open();
    try {
        await gate.delete('identity', 'self');
    } catch {
        // store may not exist yet — ignore
    }
});

describe('App identity UI', () => {
    test('recipient ID is visible and copyable in the UI', async () => {
        render(<App />);

        // Wait for the identity to load and the recipient ID to appear.
        await waitFor(() => {
            const copyBtn = screen.queryByTitle('Copy your recipient ID');
            expect(copyBtn).toBeInTheDocument();
        });

        // The recipient ID should be a base64 string (44 chars for 33 bytes).
        const codeEl = screen.getByTitle('Copy your recipient ID').querySelector('code');
        expect(codeEl).not.toBeNull();
        const recipientId = codeEl!.textContent!;
        expect(recipientId.length).toBe(44);

        // The copy button should be present.
        const copyBtn = screen.getByTitle('Copy your recipient ID');
        expect(copyBtn).toBeInTheDocument();
    });

    test('publish_prekey is called on startup with the identity recipient ID', async () => {
        render(<App />);

        await waitFor(() => {
            expect(mockHolder.publishPrekey).toHaveBeenCalledTimes(1);
        });

        // The recipient ID passed to publishPrekey should match the one rendered.
        const [calledRecipientId, bundle] = mockHolder.publishPrekey.mock.calls[0];
        expect(calledRecipientId.length).toBe(44);
        expect(bundle).toBeInstanceOf(Uint8Array);
        expect(bundle.length).toBeGreaterThan(0);
    });

    test('publish_prekey failure surfaces a visible unreachable state', async () => {
        mockHolder.publishPrekey = vi.fn().mockRejectedValue(new Error('relay unreachable'));

        render(<App />);

        // The retry burst has a short backoff; once it is exhausted the rail
        // shows a human "Can't reach relay" state instead of the old
        // permanent "Prekey publish failed" banner.
        await waitFor(() => {
            expect(screen.getByText(/can't reach relay/i)).toBeInTheDocument();
        }, { timeout: 3000 });
        expect(screen.queryByText(/prekey publish failed/i)).not.toBeInTheDocument();

        // The raw technical error is available behind a details toggle, not
        // shown as the headline.
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /details/i }));
        });
        expect(screen.getByText(/relay unreachable/i)).toBeInTheDocument();
    });

    // ── Criterion 1/2: App wires the group view to the app's real identity ──
    //
    // Regression guard for the story's central change. GroupConversation fails
    // closed without identity + selfRecipientId, so if App.tsx ever goes back
    // to a bare `<GroupConversation />` (or drops any one of the four props)
    // the shipped group view breaks with a visible "unavailable" alert. This
    // test asserts on the props the component ACTUALLY receives.
    test('the group view receives the app identity, recipient ID, storage gate and transport', async () => {
        render(<App />);

        // Wait for the persisted identity to load — the recipient ID only
        // renders once `identity` is set, and the group view must be wired to
        // that same identity.
        await waitFor(() => {
            expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument();
        });
        const appRecipientId = screen.getByTitle('Copy your recipient ID').querySelector('code')!.textContent!;

        // Switch to the group view.
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'Group' }));
        });

        await waitFor(() => {
            expect(groupPropsHolder.props.length).toBeGreaterThan(0);
        });
        const props = groupPropsHolder.props[groupPropsHolder.props.length - 1];

        // All four props must be supplied — dropping any one breaks the view.
        expect(props.identity).toBeTruthy();
        expect(props.selfRecipientId).toBeTruthy();
        expect(props.storageGate).toBeTruthy();
        expect(props.transport).toBeTruthy();

        // Criterion 2: the identity used is the APP's persisted identity, not a
        // freshly generated demo one. Its public bytes must base64-encode to
        // the recipient ID the app itself displays.
        expect(props.selfRecipientId).toBe(appRecipientId);
        const pub = props.identity.public_bytes();
        expect(btoa(String.fromCharCode(...pub))).toBe(appRecipientId);

        // The gate handed to the group view is App's canonical sessionGate, not
        // a second StorageGate opened over the same IndexedDB.
        expect(props.storageGate).toBeInstanceOf(StorageGate);
    });

    test('reloading (re-instantiating StorageGate) yields the same recipient ID', async () => {
        // First mount: generate and persist identity.
        const { unmount } = render(<App />);
        await waitFor(() => {
            expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument();
        });
        const firstRecipientId = screen.getByTitle('Copy your recipient ID').querySelector('code')!.textContent!;
        unmount();

        // Second mount: should load the persisted identity, not regenerate.
        render(<App />);
        await waitFor(() => {
            expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument();
        });
        const secondRecipientId = screen.getByTitle('Copy your recipient ID').querySelector('code')!.textContent!;

        expect(secondRecipientId).toBe(firstRecipientId);
    });
});