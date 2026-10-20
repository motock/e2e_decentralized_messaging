// @vitest-environment jsdom
//
// MD-17b: a LINKED device receives on its own `account:device` mailbox.
//
// CONTRACT pinned here:
//   * `Conversation` takes OPTIONAL props `accountHandle?: string` and
//     `deviceId?: number`. The receive loop polls
//     `${accountHandle}:${deviceId}` when both are supplied and
//     `deviceId >= 1`; otherwise it polls `identity.recipientId` (the bare
//     account handle), which is also what the primary device (id 0) uses.
//   * `App` loads the link record the linking handshake (MD-16) persists under
//     StorageGate store 'identity' id 'account-device-list'
//     (`{ accountHandle, deviceId, signedListBytesBase64 }`), validates it
//     structurally, and passes the two fields to Conversation. A missing or
//     malformed record falls back to the bare id and never breaks render.
//   * Neither the record's signed list bytes nor any key material is written
//     to the console.
//
// The WASM module is mocked (this suite asserts mailbox ADDRESSING, not
// crypto) so it runs without a built pkg/. The transport is a mock whose
// pickup always reports an empty mailbox (NotFound) — the normal "nothing to
// receive" path — so the poll's argument is what we assert.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

// ── WASM mock ───────────────────────────────────────────────────────────────
// Only the surface App/Conversation touch at import time and on the receive
// path is needed: the loop is driven to a NotFound poll, so no crypto runs.
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => {
    class FanoutDeviceInput {
        constructor(
            public deviceId: number,
            public identityKey: Uint8Array,
            public bundleBytes: Uint8Array,
        ) {}
    }
    class SessionHandle {}
    class IdentityHandle {
        constructor(private priv: Uint8Array) {}
        public_bytes() {
            const pub = new Uint8Array(33);
            pub[0] = 5;
            for (let i = 0; i < 32; i++) pub[i + 1] = this.priv[i] ^ 0x5a;
            return pub;
        }
        private_bytes() {
            return this.priv.slice();
        }
    }
    return {
        FanoutDeviceInput,
        SessionHandle,
        IdentityHandle,
        generate_identity: () => new IdentityHandle(new Uint8Array(32).fill(7)),
        identity_from_bytes: (bytes: Uint8Array) => new IdentityHandle(bytes.slice()),
        generate_prekey_bundle: () => new Uint8Array([1, 2, 3]),
        create_receiver_session: () => ({ _mock: 'receiver-session' }),
        publish_bundle_bytes: () => new Uint8Array([1, 2, 3]),
        bundle_identity_key_bytes: () => new Uint8Array(33),
        derive_safety_number: () => '00000 00000',
        establish_session_from_bundle: () => ({ _mock: 'sender-session' }),
        encrypt_message: () => new Uint8Array([9]),
        decrypt_message: () => new Uint8Array([1]),
        fanout_establish: () => ({ _mock: 'fanout' }),
        fanout_encrypt: () => [],
        fanout_remove_device: () => ({ _mock: 'fanout' }),
    };
});
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

// ── Storage mock ────────────────────────────────────────────────────────────
// A tiny in-memory store keyed by `${store}/${id}`. The holder is referenced
// only from the class methods (never at factory-evaluation time), so vitest's
// hoisting of this factory above the `const` below is safe.
const storage: { records: Record<string, unknown>; getCalls: [string, string][] } = {
    records: {},
    getCalls: [],
};

vi.mock('../src/storage', () => {
    class MockStorageGate {
        async open() {}
        async get(store: string, id: string) {
            storage.getCalls.push([store, id]);
            return storage.records[`${store}/${id}`] ?? null;
        }
        async put(store: string, id: string, value: unknown) {
            storage.records[`${store}/${id}`] = value;
        }
    }
    return { StorageGate: MockStorageGate };
});

// ── Transport mock ──────────────────────────────────────────────────────────
const holder: any = {};

vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: (...a: unknown[]) => holder.publishPrekey(...a),
            connect: (...a: unknown[]) => holder.connect(...a),
            close: () => holder.close(),
            lookupPrekey: (...a: unknown[]) => holder.lookupPrekey(...a),
            sendEnvelope: (...a: unknown[]) => holder.sendEnvelope(...a),
            pickupEnvelope: (...a: unknown[]) => holder.pickupEnvelope(...a),
        };
    }),
}));

vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

import { Conversation } from '../src/Conversation';
import App, { parseAccountDeviceLink } from '../src/App';

const RECIPIENT_ID = 'alice-account-handle';
const ACCOUNT_HANDLE = 'alice-account-handle';
const RECORD_KEY = 'identity/account-device-list';

function makeIdentity() {
    return {
        handle: { public_bytes: () => new Uint8Array(33), private_bytes: () => new Uint8Array(32) },
        publicBytes: new Uint8Array(33),
        recipientId: RECIPIENT_ID,
    } as any;
}

/** A receiver session stub: the receive loop only checks it is present. */
const receiverSession = { _mock: 'receiver-session' } as any;

beforeEach(() => {
    storage.records = {};
    storage.getCalls = [];

    holder.pickupEnvelope = vi.fn(async () => {
        throw new Error('NotFound');
    });
    holder.publishPrekey = vi.fn(async () => {});
    holder.connect = vi.fn(async () => {});
    holder.close = vi.fn();
    holder.lookupPrekey = vi.fn(async () => new Uint8Array([1, 2, 3]));
    holder.sendEnvelope = vi.fn(async () => {});
});

afterEach(() => {
    vi.restoreAllMocks();
});

// ── Conversation: which mailbox does the receive loop poll? ─────────────────

/** Render Conversation and wait for its first (immediate) poll. */
async function renderConversation(props: Record<string, unknown>) {
    render(
        <Conversation
            identity={makeIdentity()}
            receiverSession={receiverSession}
            transport={{
                lookupPrekey: async () => new Uint8Array([1]),
                sendEnvelope: async () => {},
                pickupEnvelope: holder.pickupEnvelope,
            }}
            {...props}
        />,
    );
    await waitFor(() => expect(holder.pickupEnvelope).toHaveBeenCalled());
}

describe('Conversation receive mailbox (MD-17b)', () => {
    test('a linked device polls its account:device mailbox', async () => {
        await renderConversation({ accountHandle: ACCOUNT_HANDLE, deviceId: 2 });

        expect(holder.pickupEnvelope).toHaveBeenCalledWith(`${ACCOUNT_HANDLE}:2`);
        expect(holder.pickupEnvelope).not.toHaveBeenCalledWith(RECIPIENT_ID);
    });

    test('without the link props the bare recipient id is polled', async () => {
        await renderConversation({});

        expect(holder.pickupEnvelope).toHaveBeenCalledWith(RECIPIENT_ID);
    });

    test('the primary device (id 0) polls the bare recipient id', async () => {
        await renderConversation({ accountHandle: ACCOUNT_HANDLE, deviceId: 0 });

        expect(holder.pickupEnvelope).toHaveBeenCalledWith(RECIPIENT_ID);
    });

    test('an account handle without a device id polls the bare recipient id', async () => {
        await renderConversation({ accountHandle: ACCOUNT_HANDLE });

        expect(holder.pickupEnvelope).toHaveBeenCalledWith(RECIPIENT_ID);
    });
});

// ── App: the persisted link record selects the mailbox ─────────────────────

describe('parseAccountDeviceLink (MD-17b)', () => {
    test('accepts the record the linking handshake persists', () => {
        expect(
            parseAccountDeviceLink({
                accountHandle: ACCOUNT_HANDLE,
                deviceId: 2,
                signedListBytesBase64: 'c2lnbmVkLWxpc3Q=',
            }),
        ).toEqual({ accountHandle: ACCOUNT_HANDLE, deviceId: 2 });
    });

    test('accepts the primary device (id 0)', () => {
        expect(
            parseAccountDeviceLink({
                accountHandle: ACCOUNT_HANDLE,
                deviceId: 0,
                signedListBytesBase64: 'c2lnbmVkLWxpc3Q=',
            }),
        ).toEqual({ accountHandle: ACCOUNT_HANDLE, deviceId: 0 });
    });

    test.each([
        ['no record', null],
        ['a non-object record', 'not-a-record'],
        ['a missing account handle', { deviceId: 2, signedListBytesBase64: 'eA==' }],
        ['an empty account handle', { accountHandle: '', deviceId: 2, signedListBytesBase64: 'eA==' }],
        ['a non-string account handle', { accountHandle: 7, deviceId: 2, signedListBytesBase64: 'eA==' }],
        ['a string device id', { accountHandle: ACCOUNT_HANDLE, deviceId: '2', signedListBytesBase64: 'eA==' }],
        ['a fractional device id', { accountHandle: ACCOUNT_HANDLE, deviceId: 1.5, signedListBytesBase64: 'eA==' }],
        ['a negative device id', { accountHandle: ACCOUNT_HANDLE, deviceId: -1, signedListBytesBase64: 'eA==' }],
        ['missing list bytes', { accountHandle: ACCOUNT_HANDLE, deviceId: 2 }],
    ])('rejects %s', (_label, raw) => {
        expect(parseAccountDeviceLink(raw)).toBeNull();
    });
});

describe('App account-device link record (MD-17b)', () => {
    // The receive loop's first poll can land before the relay session exists,
    // and the next one is a full poll interval away — hence the generous
    // timeout on these two integration assertions.
    const POLL_TIMEOUT_MS = 8000;

    test('a valid record makes the receive loop poll account:device', async () => {
        const listBytes = 'c2VjcmV0LXNpZ25lZC1saXN0LWJ5dGVz';
        storage.records[RECORD_KEY] = {
            accountHandle: ACCOUNT_HANDLE,
            deviceId: 2,
            signedListBytesBase64: listBytes,
        };

        const log = vi.spyOn(console, 'log').mockImplementation(() => {});
        const info = vi.spyOn(console, 'info').mockImplementation(() => {});
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const error = vi.spyOn(console, 'error').mockImplementation(() => {});
        const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});

        render(<App />);

        await waitFor(
            () => expect(holder.pickupEnvelope).toHaveBeenCalledWith(`${ACCOUNT_HANDLE}:2`),
            { timeout: POLL_TIMEOUT_MS },
        );
        // The record is read from the store/id the linking handshake writes.
        expect(storage.getCalls).toContainEqual(['identity', 'account-device-list']);

        const printed = [log, info, warn, error, debug]
            .flatMap((spy) => spy.mock.calls)
            .map((args) => args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '))
            .join('\n');
        expect(printed).not.toContain(listBytes);
        expect(printed).not.toContain('signedListBytesBase64');
    });

    // A rejected record leaves the props unchanged, so nothing re-triggers the
    // receive effect: the first poll that finds a relay session is the regular
    // interval tick, which is why this case needs a timeout above the poll
    // interval (5s) rather than the default 5s test timeout.
    test('a malformed record falls back to the bare id and does not crash', async () => {
        // deviceId is a string, not a number: structurally invalid.
        storage.records[RECORD_KEY] = {
            accountHandle: ACCOUNT_HANDLE,
            deviceId: '2',
            signedListBytesBase64: 'c2lnbmVkLWxpc3Q=',
        };

        render(<App />);

        await waitFor(() => expect(holder.pickupEnvelope).toHaveBeenCalled(), {
            timeout: POLL_TIMEOUT_MS,
        });

        const polled = holder.pickupEnvelope.mock.calls.map((c: unknown[]) => c[0]);
        // Never the linked mailbox; always a bare id (no `:` separator).
        expect(polled).not.toContain(`${ACCOUNT_HANDLE}:2`);
        for (const address of polled) {
            expect(typeof address).toBe('string');
            expect(address).not.toContain(':');
        }
        // The UI is still rendered — the bad record did not break render.
        expect(screen.getByPlaceholderText('Type a message')).toBeTruthy();
    }, 15000);
});
