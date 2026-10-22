/** @vitest-environment jsdom */
//
// GF-4 — the group receive loop polls THIS device's mailbox.
//
// The unit test (src/group_receive_address.test.ts) pins the address rule and
// the App test (tests/app_group_device_mailbox_wiring.test.tsx) pins the
// render-site props. This test closes the loop: it mounts the REAL
// GroupConversation (real WASM group crypto, mocked transport) and asserts the
// address the receive loop actually hands to `pickupEnvelope`.
//
// Positive: a linked device (deviceId 2) polls `${handle}:2`; the primary
// (deviceId 0) polls the bare handle.
// Negative: absent props keep polling `selfRecipientId`; a null/undefined
// deviceId falls back to `selfRecipientId` instead of crashing.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';

async function flush() {
    await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
    });
}

async function tick(ms: number) {
    await act(async () => {
        await vi.advanceTimersByTimeAsync(ms);
    });
}

// ── Storage mock (external boundary) ───────────────────────────────────────
vi.mock('../src/storage', () => {
    const store = new Map<string, unknown>();
    class MockStorageGate {
        async open() {}
        async get(_store: string, id: string) {
            return store.get(id) ?? null;
        }
        async put(_store: string, id: string, value: unknown) {
            store.set(id, value);
        }
    }
    (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store = store;
    return { StorageGate: MockStorageGate, StoreName: 'string' };
});

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('../src/storage_key', () => ({ getStorageKey: () => new Uint8Array(32) }));

import { GroupConversation } from '../src/GroupConversation';
import { StorageGate as MockStorageGate } from '../src/storage';
import { generate_identity, generate_prekey_bundle } from '../../../core/bindings/wasm/pkg/index.js';

function recipientIdFromPublicBytes(publicBytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < publicBytes.length; i++) binary += String.fromCharCode(publicBytes[i]);
    return btoa(binary);
}

/** Transport whose mailbox is always empty; records every pickup address. */
function makeTransport() {
    return {
        sendEnvelope: vi.fn(async () => {}),
        pickupEnvelope: vi.fn(async () => {
            throw new Error('NotFound');
        }),
        lookupPrekey: vi.fn(async () => new Uint8Array([0])),
    };
}

/** Mount the component, create the group, and add one real peer. */
async function mountWithGroup(
    transport: ReturnType<typeof makeTransport>,
    selfIdentity: ReturnType<typeof generate_identity>,
    selfRecipientId: string,
    extraProps: Record<string, unknown> = {},
) {
    const peerIdentity = generate_identity();
    const peerRecipientId = recipientIdFromPublicBytes(peerIdentity.public_bytes());
    transport.lookupPrekey.mockResolvedValue(
        generate_prekey_bundle(peerIdentity) as unknown as Uint8Array<ArrayBuffer>,
    );

    const view = render(
        <GroupConversation
            transport={transport}
            identity={selfIdentity}
            selfRecipientId={selfRecipientId}
            {...extraProps}
        />,
    );
    await flush();
    fireEvent.click(screen.getByTestId('create-group-button'));
    await flush();
    fireEvent.change(screen.getByTestId('group-peer-id-input'), {
        target: { value: peerRecipientId },
    });
    fireEvent.click(screen.getByTestId('add-peer-button'));
    await flush();
    return view;
}

/** The distinct addresses the receive loop has polled so far. */
function polledAddresses(transport: ReturnType<typeof makeTransport>): string[] {
    return transport.pickupEnvelope.mock.calls.map((c: unknown[]) => c[0] as string);
}

beforeEach(() => {
    vi.useFakeTimers();
    const store = (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store;
    store.clear();
});

afterEach(() => {
    vi.useRealTimers();
});

describe('the group receive loop polls this device\'s mailbox', () => {
    test('a linked device polls the device-qualified address', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId, {
            accountHandle: 'acct-handle',
            deviceId: 2,
        });
        await tick(5000);

        expect(polledAddresses(transport)).toContain('acct-handle:2');
        expect(polledAddresses(transport)).not.toContain('acct-handle');
    });

    test('the primary device polls the bare handle', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId, {
            accountHandle: selfRecipientId,
            deviceId: 0,
        });
        await tick(5000);

        expect(polledAddresses(transport)).toContain(selfRecipientId);
        expect(polledAddresses(transport).some((a) => a.includes(':'))).toBe(false);
    });

    test('absent props keep polling selfRecipientId', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId);
        await tick(5000);

        expect(polledAddresses(transport)).toContain(selfRecipientId);
        expect(polledAddresses(transport).some((a) => a.includes(':'))).toBe(false);
    });

    test('a null deviceId falls back to selfRecipientId without crashing', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId, {
            accountHandle: 'acct-handle',
            deviceId: null,
        });
        await tick(5000);

        expect(polledAddresses(transport)).toContain(selfRecipientId);
        expect(polledAddresses(transport)).not.toContain('acct-handle:null');
    });

    test('an undefined deviceId falls back to selfRecipientId without crashing', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId, {
            accountHandle: 'acct-handle',
            deviceId: undefined,
        });
        await tick(5000);

        expect(polledAddresses(transport)).toContain(selfRecipientId);
        expect(polledAddresses(transport)).not.toContain('acct-handle:undefined');
    });

    test('renders no key material in the DOM', async () => {
        const transport = makeTransport();
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        await mountWithGroup(transport, selfIdentity, selfRecipientId, {
            accountHandle: 'acct-handle',
            deviceId: 2,
        });
        await tick(5000);

        const html = document.body.innerHTML;
        expect(html).not.toMatch(/private_bytes|privateKey|secret/i);
    });
});
