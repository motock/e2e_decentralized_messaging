/** @vitest-environment jsdom */
//
// TDD tests for the out-of-band envelope-kind discriminator on the two receive
// loops (Conversation.tsx = "direct", GroupConversation.tsx = "group").
//
// CONTRACT UNDER TEST (the kind is NEVER inside the ciphertext):
//   * `transport.pickupEnvelope(recipientId)` surfaces the kind that travelled
//     as a SIBLING FIELD of the relay's `pickup_envelope` op. It resolves to
//     `{ envelope: Uint8Array; kind?: string }`. A bare `Uint8Array` (legacy /
//     no tag) means "missing kind".
//   * A loop whose own kind matches decrypts the envelope.
//   * A loop that sees a FOREIGN kind must NOT attempt a decrypt and must NOT
//     surface the tampered/corrupted warning — the envelope belongs to the
//     other loop and is never destroyed by the wrong one.
//   * A MISSING (or unknown) kind FALLS THROUGH to the owning loop's decrypt —
//     it is not silently skipped. Failing closed means "not silently
//     misrouted", not "never reaches the loop that owns it".
//
// Real WASM crypto is used for the happy path; only the network transport
// boundary is mocked, matching conversation_receive.test.tsx.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';

let mockStoredMessages: unknown = null;

vi.mock('../src/storage', () => {
    class MockStorageGate {
        async open() { return Promise.resolve(); }
        async get() { return mockStoredMessages; }
        async put(_store: string, _id: string, value: unknown) { mockStoredMessages = value; }
    }
    return { StorageGate: MockStorageGate };
});

import { Conversation } from '../src/Conversation';
import { GroupConversation } from '../src/GroupConversation';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    establish_session_from_bundle,
    encrypt_message,
} from '../../../core/bindings/wasm/pkg/index.js';

/** Minimal PersistedIdentity-shaped wrapper around a real wasm IdentityHandle. */
function toIdentity(handle: any) {
    return { handle, publicBytes: handle.public_bytes(), recipientId: 'test-recipient' };
}

/** Alice (sender) → Bob (local receiver) real direct-session fixture. */
function setupDirect() {
    const bobIdentity = generate_identity();
    const bobSession = create_receiver_session(bobIdentity);
    const bobBundle = publish_bundle_bytes(bobSession);
    const aliceIdentity = generate_identity();
    const aliceSession = establish_session_from_bundle(aliceIdentity, bobBundle);
    return {
        bob: toIdentity(bobIdentity),
        bobSession,
        encryptToBob: (t: string) => encrypt_message(aliceSession, new TextEncoder().encode(t)),
    };
}

function mockTransport(pickupResult: unknown) {
    return {
        lookupPrekey: vi.fn(),
        sendEnvelope: vi.fn(),
        pickupEnvelope: vi.fn().mockResolvedValue(pickupResult),
    };
}

async function flush() {
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
}
async function tick(ms: number) {
    await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}

beforeEach(() => { mockStoredMessages = null; vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); });

describe('Conversation (direct loop) envelope-kind routing', () => {
    test('a direct-kind envelope is still delivered by the direct loop', async () => {
        const { bob, bobSession, encryptToBob } = setupDirect();
        const transport = mockTransport({ envelope: encryptToBob('hello direct'), kind: 'direct' });

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);
        await tick(5000);

        expect(screen.getByText('hello direct')).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('a group-kind envelope is not decrypted by the direct loop (no false tampered warning)', async () => {
        const { bob, bobSession } = setupDirect();
        // Garbage bytes: if the direct loop wrongly attempted a decrypt it would
        // fail closed and raise the tampered/corrupted alert.
        const transport = mockTransport({ envelope: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), kind: 'group' });

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);
        await tick(5000);

        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('a missing kind falls through to the direct loop decrypt (tampered -> fail closed)', async () => {
        const { bob, bobSession } = setupDirect();
        // Bare Uint8Array == no out-of-band kind at all.
        const transport = mockTransport(new Uint8Array([9, 9, 9, 9]));

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);
        await tick(5000);

        expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    test('an unknown kind falls through to the direct loop decrypt (tampered -> fail closed)', async () => {
        const { bob, bobSession } = setupDirect();
        const transport = mockTransport({ envelope: new Uint8Array([9, 9, 9, 9]), kind: 'not-a-real-kind' });

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);
        await tick(5000);

        expect(screen.getByRole('alert')).toBeInTheDocument();
    });
});

describe('GroupConversation (group loop) envelope-kind routing', () => {
    function groupGate() {
        return {
            open: vi.fn().mockResolvedValue(undefined),
            get: vi.fn().mockResolvedValue(null),
            put: vi.fn().mockResolvedValue(undefined),
        };
    }

    async function mountGroup(transport: ReturnType<typeof mockTransport>) {
        const self = generate_identity();
        render(
            <GroupConversation
                transport={transport}
                storageGate={groupGate() as any}
                identity={self}
                selfRecipientId="self-recipient"
            />,
        );
        await flush();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush();
    }

    test('a group-kind envelope reaches the group loop decrypt (tampered -> fail closed)', async () => {
        const transport = mockTransport({ envelope: new Uint8Array([1, 2, 3]), kind: 'group' });
        await mountGroup(transport);
        await tick(5000);

        expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    test('a direct-kind envelope is not decrypted by the group loop (no false tampered warning)', async () => {
        const transport = mockTransport({ envelope: new Uint8Array([1, 2, 3]), kind: 'direct' });
        await mountGroup(transport);
        await tick(5000);

        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('a missing kind falls through to the group loop decrypt (tampered -> fail closed)', async () => {
        const transport = mockTransport(new Uint8Array([1, 2, 3]));
        await mountGroup(transport);
        await tick(5000);

        expect(screen.getByRole('alert')).toBeInTheDocument();
    });
});
