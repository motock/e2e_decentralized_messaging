/** @vitest-environment jsdom */
//
// TDD tests for group conversation real send/receive with persistence
// (issue b9e64380-eab6-4539-b8ed-47c3586a97df).
//
// These tests use the REAL WASM group crypto (group_create, group_add_member,
// group_encrypt, group_decrypt, generate_identity, bundle_identity_key_bytes)
// — only the network transport boundary (sendEnvelope / pickupEnvelope /
// lookupPrekey) is mocked, matching the repo convention established in
// conversation_receive.test.tsx.
//
// Timer mocks (vi.useFakeTimers) control the polling interval so we can assert
// deterministic poll counts and verify cleanup on unmount.
//
// Success criteria covered:
//   (1) A group message round-trips through real send_envelope/pickup_envelope
//       (mocked transport) and group_encrypt/group_decrypt (real WASM) between
//       two real member identities.
//   (2) Group message history persists across a simulated reload.
//   (3) The receive-loop interval is cleaned up on unmount.
//
// Negative/boundary cases:
//   - Decrypt failure (tampered ciphertext) must never render plaintext and
//     must surface a visible warning (role='alert').
//   - Rapid repeated polls must not leak overlapping timers (dedup + in-flight
//     guard).

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent } from '@testing-library/react';

// ── Microtask flush helper ─────────────────────────────────────────────────
//
// With vi.useFakeTimers, `waitFor` hangs because its internal polling uses
// setTimeout which never fires under fake timers. Instead, we flush pending
// microtasks + timer callbacks with a zero-time advance, which resolves the
// component's async init (ensureWasmInit is mocked to a resolved promise)
// and any state updates that follow. This mirrors the pattern used in
// conversation_receive.test.tsx (act + advanceTimersByTimeAsync).
async function flush() {
    await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
    });
}

/** Advance fake timers by ms and flush microtasks, wrapped in act. */
async function tick(ms: number) {
    await act(async () => {
        await vi.advanceTimersByTimeAsync(ms);
    });
}

// ── Mutable fixtures ───────────────────────────────────────────────────────
//
// vi.mock factories are hoisted and file-scoped, so per-test variation is done
// via module-level variables that the mock reads at call time.

/** Map of recipientId → public key bytes that lookupPrekey will return. */
let prekeyBundles: Record<string, Uint8Array>;
/** Whether lookupPrekey should reject (simulating "peer not found"). */
let prekeyRejections: Record<string, string>;
/** Persisted group state that the mock StorageGate returns on reload. */
let persistedGroupState: unknown;
/** Persisted group message history that the mock StorageGate returns on reload. */
let persistedMessages: unknown;

// ── Storage mock ───────────────────────────────────────────────────────────
//
// Mirrors the real StorageGate API (get/put) with an in-memory store that
// simulates persistence across a "reload" (re-render with fresh component
// instance). Two stores: one for group state, one for messages.

vi.mock('../src/storage', () => {
    const store = new Map<string, unknown>();

    class MockStorageGate {
        async open() { return Promise.resolve(); }
        async get(_store: string, id: string) {
            return store.get(id) ?? null;
        }
        async put(_store: string, id: string, value: unknown) {
            store.set(id, value);
        }
    }
    // Expose the store so tests can reset it between runs.
    (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store = store;
    return { StorageGate: MockStorageGate, StoreName: 'string' };
});

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

import { StorageGate as MockStorageGate } from '../src/storage';
import { GroupConversation } from '../src/GroupConversation';
import {
    generate_identity,
    group_create,
    group_add_member,
    group_encrypt,
    group_decrypt,
    group_to_bytes,
    group_from_bytes,
    bundle_identity_key_bytes,
    IdentityHandle,
    GroupHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Derive a base64 recipient ID from a public key, matching identity.ts. */
function recipientIdFromPublicBytes(publicBytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < publicBytes.length; i++) {
        binary += String.fromCharCode(publicBytes[i]);
    }
    return btoa(binary);
}

/**
 * Set up a full group round-trip fixture with two real member identities:
 *   - "self" (the local GroupConversation component's identity)
 *   - "peer" (a remote member whose prekey bundle is looked up via the relay)
 *
 * Returns both identities, the peer's prekey bundle bytes, and a helper to
 * encrypt a group message from the peer's identity (simulating a remote send
 * that the local component will pick up and decrypt).
 *
 * The peer's group is constructed with BOTH members so group_encrypt produces
 * a ciphertext that the self identity can decrypt.
 */
function setupGroupRoundTrip() {
    const selfIdentity = generate_identity();
    const selfPublic = selfIdentity.public_bytes();
    const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

    const peerIdentity = generate_identity();
    const peerPublic = peerIdentity.public_bytes();
    const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

    // The peer's prekey bundle — in tests we return the public key bytes
    // directly (bundle_identity_key_bytes is a passthrough in the real WASM
    // for this test's purpose, but we use the real binding).
    // For lookupPrekey we need to return something that bundle_identity_key_bytes
    // can extract the identity key from. In the real WASM, this expects a
    // prekey bundle. We'll generate a real prekey bundle for the peer.
    // However, the GroupConversation component calls bundle_identity_key_bytes
    // on the looked-up bytes. Let's check what the real binding expects...
    // Actually, for the test we can use the peer's public bytes directly since
    // bundle_identity_key_bytes in the real WASM expects a serialized prekey
    // bundle. Let's generate a real bundle.
    //
    // But wait — the component's addPeer calls lookupPrekey then
    // bundle_identity_key_bytes. For the test to work with real WASM, we need
    // a real prekey bundle. Let's use generate_prekey_bundle.
    //
    // Actually, looking at the existing group_real_peer.test.tsx, it mocks the
    // WASM and returns public key bytes directly from lookupPrekey. But our
    // tests use REAL WASM. So we need a real prekey bundle.
    //
    // Let's check if generate_prekey_bundle is available...
    // From lib.rs: generate_prekey_bundle(identity_handle) -> Vec<u8>
    // And bundle_identity_key_bytes(bundle) extracts the identity key.
    //
    // We need to import generate_prekey_bundle. But the GroupConversation
    // component imports bundle_identity_key_bytes from the WASM pkg. So we
    // need to provide a real bundle via lookupPrekey.

    // For now, let's just use the peer's public bytes. The real
    // bundle_identity_key_bytes may or may not work with raw public bytes.
    // We'll need to test this. If it doesn't work, we'll generate a real bundle.

    // Actually, let's look at what bundle_identity_key_bytes does in the WASM:
    // It takes a serialized PreKeyBundle and extracts the identity key.
    // Raw public bytes (33 bytes) are NOT a valid PreKeyBundle.
    // So we MUST provide a real prekey bundle.

    // We'll import generate_prekey_bundle dynamically.
    // But it's not imported above... Let's add it.

    return {
        selfIdentity,
        selfPublic,
        selfRecipientId,
        peerIdentity,
        peerPublic,
        peerRecipientId,
    };
}

// ── Transport mock ──────────────────────────────────────────────────────────

/**
 * A mock transport that simulates the relay. It stores envelopes sent via
 * sendEnvelope in per-recipientId mailboxes and returns them via pickupEnvelope.
 * This mirrors the real relay's store-and-forward behavior.
 */
function makeRelayMockTransport() {
    const mailboxes = new Map<string, Uint8Array[]>();

    function ensureMailbox(recipientId: string): Uint8Array[] {
        if (!mailboxes.has(recipientId)) mailboxes.set(recipientId, []);
        return mailboxes.get(recipientId)!;
    }

    return {
        lookupPrekey: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
            const rejection = prekeyRejections[recipientId];
            if (rejection) throw new Error(rejection);
            const bundle = prekeyBundles[recipientId];
            if (!bundle) throw new Error('relay: recipient not found');
            return bundle;
        }),
        sendEnvelope: vi.fn(async (recipientId: string, envelope: Uint8Array): Promise<void> => {
            const mailbox = ensureMailbox(recipientId);
            mailbox.push(new Uint8Array(envelope));
        }),
        pickupEnvelope: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
            const mailbox = ensureMailbox(recipientId);
            if (mailbox.length === 0) throw new Error('NotFound');
            return mailbox.shift()!;
        }),
        // Expose mailboxes for test inspection.
        _mailboxes: mailboxes,
    };
}

// ── Test setup ─────────────────────────────────────────────────────────────

beforeEach(() => {
    prekeyBundles = {};
    prekeyRejections = {};
    persistedGroupState = null;
    persistedMessages = null;
    // Clear the mock storage store.
    (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store.clear();
    vi.useFakeTimers();
});

afterEach(() => {
    vi.useRealTimers();
});

// ── GRP-4 ratchet-persistence helpers ──────────────────────────────────────
//
// The persisted group-state record lives in the mock StorageGate's in-memory
// store, keyed by record id ('group-state'). These helpers read/seed it
// directly so a test can simulate a reload carrying a specific persisted blob.

/** Read the persisted group-state record from the mock StorageGate store. */
function readPersistedGroupState(): { members?: unknown[]; blob?: number[] } | undefined {
    const store = (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store;
    return store.get('group-state') as { members?: unknown[]; blob?: number[] } | undefined;
}

/** Seed the persisted group-state record that the next mount will load. */
function seedPersistedGroupState(value: unknown): void {
    const store = (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store;
    store.set('group-state', value);
}

/** The 12-byte AES-GCM nonce that prefixes a group wire ciphertext. */
function nonceOf(ciphertext: Uint8Array): Uint8Array {
    return ciphertext.slice(0, 12);
}

/** Lowercase hex, for readable nonce/ciphertext inequality assertions. */
function hex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Generate a self identity plus a peer identity whose prekey bundle is
 * registered with the relay mock, so `addPeer` can look the peer up.
 */
async function makePeerFixture() {
    const selfIdentity = generate_identity();
    const selfPublic = selfIdentity.public_bytes();
    const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

    const peerIdentity = generate_identity();
    const peerPublic = peerIdentity.public_bytes();
    const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

    const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
    prekeyBundles[peerRecipientId] = generate_prekey_bundle(peerIdentity);

    return { selfIdentity, selfPublic, selfRecipientId, peerIdentity, peerPublic, peerRecipientId };
}

/** Mount GroupConversation, create the group, and add the real peer. */
async function mountCreateAndAddPeer(
    transport: ReturnType<typeof makeRelayMockTransport>,
    selfIdentity: InstanceType<typeof IdentityHandle>,
    selfRecipientId: string,
    peerRecipientId: string,
) {
    const view = render(
        <GroupConversation
            transport={transport}
            identity={selfIdentity}
            selfRecipientId={selfRecipientId}
        />,
    );
    await flush();
    expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('create-group-button'));
    await flush();
    expect(screen.getByTestId('member-list')).toBeInTheDocument();
    fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
    fireEvent.click(screen.getByTestId('add-peer-button'));
    await flush();
    expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();
    return view;
}

/** Type a message into the group composer and click send, then flush. */
async function sendGroupMessage(text: string) {
    fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: text } });
    fireEvent.click(screen.getByTestId('group-send-button'));
    await flush();
    await flush();
}

/** All ciphertexts delivered to a given recipient, in send order. */
function sentCiphertextsTo(
    transport: ReturnType<typeof makeRelayMockTransport>,
    recipientId: string,
): Uint8Array[] {
    return transport.sendEnvelope.mock.calls
        .filter((c: unknown[]) => c[0] === recipientId)
        .map((c: unknown[]) => c[1] as Uint8Array);
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('GroupConversation real send/receive with persistence', () => {
    test('a group message round-trips through send_envelope/pickup_envelope and group_encrypt/group_decrypt between two real member identities', async () => {
        // ── Setup: two real identities ──────────────────────────────────────
        const selfIdentity = generate_identity();
        const selfPublic = selfIdentity.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const peerIdentity = generate_identity();
        const peerPublic = peerIdentity.public_bytes();
        const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

        // The peer needs a prekey bundle published so the local component can
        // look it up and add the peer to the group. We generate a real bundle.
        // We need generate_prekey_bundle — let's import it.
        const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
        const peerBundle = generate_prekey_bundle(peerIdentity);
        prekeyBundles[peerRecipientId] = peerBundle;

        // ── Simulate a remote peer sending a group message ──────────────────
        // The peer creates their own group with both members, encrypts, and
        // sends the ciphertext to the self identity via sendEnvelope.
        const peerGroup = group_create(peerIdentity);
        const peerGroupWithSelf = group_add_member(peerGroup, selfPublic);
        const plaintext = 'hello group from peer!';
        const ciphertext = group_encrypt(peerGroupWithSelf, peerIdentity, new TextEncoder().encode(plaintext));

        const transport = makeRelayMockTransport();
        // Simulate the peer sending the ciphertext to self's mailbox.
        await transport.sendEnvelope(selfRecipientId, ciphertext);

        // ── Render the component with the self identity ─────────────────────
        // The component needs to know its own identity and recipient ID to
        // poll for messages. We pass the identity via a prop.
        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );

        // Wait for the component to be ready.
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();

        // Create the group and add the peer.
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();

        // Add the peer by recipient ID.
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // ── The receive loop should pick up the envelope and decrypt it ─────
        // Advance timers to trigger at least one poll.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // The decrypted plaintext should appear in the rendered message list.
        expect(screen.getByText('hello group from peer!')).toBeInTheDocument();
    });

    test('group message history persists across a simulated reload', async () => {
        const selfIdentity = generate_identity();
        const selfPublic = selfIdentity.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const peerIdentity = generate_identity();
        const peerPublic = peerIdentity.public_bytes();
        const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

        const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
        const peerBundle = generate_prekey_bundle(peerIdentity);
        prekeyBundles[peerRecipientId] = peerBundle;

        // Peer sends a message to self's mailbox.
        const peerGroup = group_create(peerIdentity);
        const peerGroupWithSelf = group_add_member(peerGroup, selfPublic);
        const ciphertext = group_encrypt(peerGroupWithSelf, peerIdentity, new TextEncoder().encode('persist me!'));

        const transport = makeRelayMockTransport();
        await transport.sendEnvelope(selfRecipientId, ciphertext);

        // First "session": render, create group, add peer, receive message.
        const { unmount } = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // Receive the message.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        expect(screen.getByText('persist me!')).toBeInTheDocument();

        // Simulate a page reload: unmount and re-render a fresh component.
        unmount();
        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );

        // The group and its members should be restored from persisted state.
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // The message history should be restored from persisted storage.
        await flush(); expect(screen.getByText('persist me!')).toBeInTheDocument();
    });

    test('the receive-loop interval is cleaned up on unmount — no further pickup calls after unmount', async () => {
        const selfIdentity = generate_identity();
        const selfRecipientId = recipientIdFromPublicBytes(selfIdentity.public_bytes());

        const transport = makeRelayMockTransport();

        const { unmount } = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();

        // Let one poll happen.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        const callsBeforeUnmount = transport.pickupEnvelope.mock.calls.length;
        expect(callsBeforeUnmount).toBeGreaterThanOrEqual(1);

        unmount();

        // Advance timers significantly — no new polls should fire.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(30000);
        });

        expect(transport.pickupEnvelope.mock.calls.length).toBe(callsBeforeUnmount);
    });

    test('a tampered/corrupted envelope fails closed — decrypt throws, UI surfaces a warning, no plaintext rendered', async () => {
        const selfIdentity = generate_identity();
        const selfPublic = selfIdentity.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const peerIdentity = generate_identity();
        const peerPublic = peerIdentity.public_bytes();
        const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

        const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
        const peerBundle = generate_prekey_bundle(peerIdentity);
        prekeyBundles[peerRecipientId] = peerBundle;

        // Peer encrypts a message.
        const peerGroup = group_create(peerIdentity);
        const peerGroupWithSelf = group_add_member(peerGroup, selfPublic);
        const ciphertext = group_encrypt(peerGroupWithSelf, peerIdentity, new TextEncoder().encode('secret group plaintext'));

        // Tamper with the ciphertext: flip a byte near the end.
        const tampered = new Uint8Array(ciphertext);
        const flipIndex = Math.max(1, tampered.length - 5);
        tampered[flipIndex] ^= 0xff;

        const transport = makeRelayMockTransport();
        await transport.sendEnvelope(selfRecipientId, tampered);

        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // Advance timers to trigger a poll.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // The plaintext must NOT appear anywhere in the rendered output.
        expect(screen.queryByText('secret group plaintext')).not.toBeInTheDocument();

        // A visible warning (role='alert') must be surfaced.
        expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    test('rapid repeated polls do not create overlapping/leaked timers — message appears exactly once', async () => {
        const selfIdentity = generate_identity();
        const selfPublic = selfIdentity.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const peerIdentity = generate_identity();
        const peerPublic = peerIdentity.public_bytes();
        const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

        const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
        const peerBundle = generate_prekey_bundle(peerIdentity);
        prekeyBundles[peerRecipientId] = peerBundle;

        const peerGroup = group_create(peerIdentity);
        const peerGroupWithSelf = group_add_member(peerGroup, selfPublic);
        const ciphertext = group_encrypt(peerGroupWithSelf, peerIdentity, new TextEncoder().encode('rapid poll group test'));

        const transport = makeRelayMockTransport();
        await transport.sendEnvelope(selfRecipientId, ciphertext);

        const { unmount } = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // Rapidly advance timers in small increments to simulate many quick polls.
        for (let i = 0; i < 10; i++) {
            await act(async () => {
                await vi.advanceTimersByTimeAsync(5000);
            });
        }

        // The message should appear exactly once (dedup, not duplicated by overlapping polls).
        const allMsgs = screen.getAllByText('rapid poll group test');
        expect(allMsgs).toHaveLength(1);

        unmount();
    });

    test('on send, ciphertext is delivered to every real group member via sendEnvelope', async () => {
        const selfIdentity = generate_identity();
        const selfPublic = selfIdentity.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const peerIdentity = generate_identity();
        const peerPublic = peerIdentity.public_bytes();
        const peerRecipientId = recipientIdFromPublicBytes(peerPublic);

        const { generate_prekey_bundle } = await import('../../../core/bindings/wasm/pkg/index.js');
        const peerBundle = generate_prekey_bundle(peerIdentity);
        prekeyBundles[peerRecipientId] = peerBundle;

        const transport = makeRelayMockTransport();

        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush(); expect(screen.getByTestId('group-conversation')).toBeInTheDocument();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush(); expect(screen.getByTestId('member-list')).toBeInTheDocument();

        // Add the peer.
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerRecipientId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush(); expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // Type and send a message.
        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'outgoing group msg' } });
        fireEvent.click(screen.getByTestId('group-send-button'));

        // The ciphertext should have been sent to the peer's recipient ID via sendEnvelope.
        await flush();
        expect(transport.sendEnvelope).toHaveBeenCalledWith(peerRecipientId, expect.any(Uint8Array));

        // Verify the sent ciphertext can be decrypted by the peer (real crypto round-trip).
        const sentCall = transport.sendEnvelope.mock.calls.find(
            (c: unknown[]) => c[0] === peerRecipientId,
        );
        expect(sentCall).toBeDefined();
        const sentCiphertext = sentCall![1] as Uint8Array;

        // The peer constructs their own group with both members to decrypt.
        const peerGroup = group_create(peerIdentity);
        const peerGroupWithSelf = group_add_member(peerGroup, selfPublic);
        const decrypted = group_decrypt(peerGroupWithSelf, peerIdentity, sentCiphertext);
        expect(new TextDecoder().decode(decrypted)).toBe('outgoing group msg');
    });

    // ── GRP-4: sender-key ratchet persistence (AUDIT-002 key-reuse class) ───
    //
    // GroupSession::new seeds its chain key from the OS CSPRNG, so rebuilding a
    // session from scratch on reload starts a *different* chain — but the
    // pre-GRP-4 code rebuilt the session and then poked the member roster in,
    // which rewound the ratchet to a chain position already used and re-derived
    // an identical (key, nonce) pair. The fix persists group_to_bytes(group)
    // through the encrypted StorageGate and restores with group_from_bytes.
    //
    // The wire ciphertext is `nonce(12) | payload_len(u32 LE) | AES-GCM payload
    // | wrapper_count(u8) | wrappers`, and the nonce is HKDF-derived from the
    // chain key (core/protocol/src/group.rs). It is therefore NOT a counter, so
    // the invariant is "the nonce changed / matches the deterministic
    // continuation of the persisted state", never "the nonce increased".

    test('after a send, the group ratchet state is persisted as a group_to_bytes blob through the encrypted StorageGate', async () => {
        const { selfIdentity, selfRecipientId, peerIdentity, peerRecipientId } = await makePeerFixture();
        const transport = makeRelayMockTransport();

        // Spy on the encrypted StorageGate's writer: the blob must go through
        // it (never a direct poke at the group handle's members).
        const putSpy = vi.spyOn(MockStorageGate.prototype, 'put');

        await mountCreateAndAddPeer(transport, selfIdentity, selfRecipientId, peerRecipientId);
        await sendGroupMessage('hello');

        const persisted = readPersistedGroupState();
        expect(persisted).toBeDefined();

        // The record carries a non-empty group_to_bytes blob.
        expect(Array.isArray(persisted!.blob)).toBe(true);
        expect(persisted!.blob!.length).toBeGreaterThan(0);
        expect(persisted!.blob!.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)).toBe(true);

        // It is a real group_to_bytes serialization: group_from_bytes accepts it
        // and re-serializing round-trips byte-for-byte.
        const restored = group_from_bytes(new Uint8Array(persisted!.blob!));
        expect(Array.from(group_to_bytes(restored))).toEqual(persisted!.blob);

        // The blob carries the real member roster: the peer can decrypt a
        // message encrypted under the restored session.
        const probe = group_encrypt(restored, selfIdentity, new TextEncoder().encode('probe'));
        expect(new TextDecoder().decode(group_decrypt(restored, peerIdentity, probe))).toBe('probe');

        // A second send advances the ratchet again, so the persisted blob must
        // change even though the member roster is unchanged — proving the blob
        // is the live ratchet state, not a roster-only record.
        await sendGroupMessage('world');
        const persistedAfterSecondSend = readPersistedGroupState();
        expect(persistedAfterSecondSend!.blob).not.toEqual(persisted!.blob);

        // The write went through the encrypted StorageGate.
        expect(putSpy).toHaveBeenCalledWith(
            'session',
            'group-state',
            expect.objectContaining({ blob: expect.any(Array) }),
        );
        // The persisted roster matches the real members the component knows.
        expect(persisted!.members).toEqual([
            expect.objectContaining({ recipientId: peerRecipientId }),
        ]);

        putSpy.mockRestore();
    });

    test('a remount restores the group from the persisted blob, so the ratchet continues instead of rewinding', async () => {
        const { selfIdentity, selfRecipientId, peerRecipientId } = await makePeerFixture();
        const transport = makeRelayMockTransport();

        const firstMount = await mountCreateAndAddPeer(
            transport,
            selfIdentity,
            selfRecipientId,
            peerRecipientId,
        );

        // Call 1: send "hello" -> ciphertext C1, nonce N1.
        await sendGroupMessage('hello');
        const call1 = sentCiphertextsTo(transport, peerRecipientId);
        expect(call1.length).toBe(1);
        const c1 = call1[0];
        const n1 = nonceOf(c1);

        // The blob persisted after call 1 is the post-send ratchet state.
        const b1 = readPersistedGroupState()!.blob!;
        expect(b1.length).toBeGreaterThan(0);

        // Unmount and remount: the fresh component must restore from the blob.
        firstMount.unmount();
        const secondMount = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush();
        await flush();
        expect(screen.getByTestId('member-list')).toBeInTheDocument();
        expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();

        // Call 2: send "world" -> ciphertext C2, nonce N2.
        await sendGroupMessage('world');
        const call2 = sentCiphertextsTo(transport, peerRecipientId);
        expect(call2.length).toBe(2);
        const c2 = call2[1];
        const n2 = nonceOf(c2);

        // The restored session advanced its ratchet: a rewound session would
        // have reused N1, and a freshly rebuilt one would have produced an
        // unrelated (random) nonce.
        expect(hex(n2)).not.toBe(hex(n1));
        expect(hex(c2)).not.toBe(hex(c1));

        // Restore really went through group_from_bytes(b1): the nonce is the
        // deterministic continuation of b1's chain key, which an independently
        // restored session reproduces exactly. A fresh group cannot match this.
        const expectedFromB1 = group_encrypt(
            group_from_bytes(new Uint8Array(b1)),
            selfIdentity,
            new TextEncoder().encode('world'),
        );
        expect(hex(n2)).toBe(hex(nonceOf(expectedFromB1)));

        // Follow-up (state left behind): the blob written AFTER call 2 must
        // itself be the correct post-call-2 state, not merely a value that made
        // call 2 return the right ciphertext.
        const b2 = readPersistedGroupState()!.blob!;
        expect(b2).not.toEqual(b1);
        const expectedB2Group = group_from_bytes(new Uint8Array(b1));
        group_encrypt(expectedB2Group, selfIdentity, new TextEncoder().encode('world'));
        expect(b2).toEqual(Array.from(group_to_bytes(expectedB2Group)));

        // Third mount: restore from b2 and send "again" -> C3, N3.
        secondMount.unmount();
        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush();
        await flush();
        expect(screen.getByTestId('member-list')).toBeInTheDocument();
        await sendGroupMessage('again');
        const call3 = sentCiphertextsTo(transport, peerRecipientId);
        expect(call3.length).toBe(3);
        const c3 = call3[2];
        const n3 = nonceOf(c3);

        // N3 advanced past N2 (changed, and matches the deterministic
        // continuation of b2) and C3 differs from C2.
        expect(hex(n3)).not.toBe(hex(n2));
        expect(hex(c3)).not.toBe(hex(c2));
        const expectedFromB2 = group_encrypt(
            group_from_bytes(new Uint8Array(b2)),
            selfIdentity,
            new TextEncoder().encode('again'),
        );
        expect(hex(n3)).toBe(hex(nonceOf(expectedFromB2)));
    });

    test('an empty, truncated, or corrupt persisted blob fails closed, while a legacy no-blob record still restores', async () => {
        const { selfIdentity, selfRecipientId, peerPublic, peerRecipientId } = await makePeerFixture();
        const transport = makeRelayMockTransport();

        // Build a real, valid persisted record to derive the corrupt variants
        // from. `seedGroup` is ratcheted once, so `validBlob` is the state AFTER
        // one encrypt (i.e. past the initial chain position).
        const seedGroup = group_add_member(group_create(selfIdentity), peerPublic);
        group_encrypt(seedGroup, selfIdentity, new TextEncoder().encode('seed'));
        const validBlob = Array.from(group_to_bytes(seedGroup));
        const validMembers = [
            { recipientId: peerRecipientId, publicBytes: Array.from(peerPublic) },
        ];

        const failClosedCases: Array<{ name: string; blob: number[] }> = [
            { name: 'empty', blob: [] },
            { name: 'truncated', blob: validBlob.slice(0, validBlob.length - 5) },
            {
                name: 'corrupt (flipped version byte)',
                blob: (() => {
                    const b = validBlob.slice();
                    b[0] ^= 0xff;
                    return b;
                })(),
            },
            {
                name: 'corrupt (flipped member count)',
                blob: (() => {
                    const b = validBlob.slice();
                    b[34] ^= 0xff;
                    return b;
                })(),
            },
        ];

        for (const { name, blob } of failClosedCases) {
            seedPersistedGroupState({ members: validMembers, blob });
            const view = render(
                <GroupConversation
                    transport={transport}
                    identity={selfIdentity}
                    selfRecipientId={selfRecipientId}
                />,
            );
            await flush();
            await flush();

            // Fail closed: setError surfaced the failure (the component renders
            // its error state as role='alert') and NO group was restored — no
            // member list, no composer, no send button, so no send can succeed.
            const alert = screen.getByRole('alert');
            expect(alert.textContent).toContain('corrupt');
            expect(screen.queryByTestId('member-list')).not.toBeInTheDocument();
            expect(screen.queryByTestId('group-message-input')).not.toBeInTheDocument();
            expect(screen.queryByTestId('group-send-button')).not.toBeInTheDocument();
            expect(transport.sendEnvelope).not.toHaveBeenCalled();

            view.unmount();
            // Reset the store between sub-cases so a stale record cannot leak.
            (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store.clear();
        }

        // Legacy record (no blob field): the pre-ratchet-persistence path
        // restores by replaying group_create + group_add_member, without error.
        seedPersistedGroupState({ members: validMembers });
        const legacyMount = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush();
        await flush();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.getByTestId('member-list')).toBeInTheDocument();
        expect(screen.getByTestId(`member-${peerRecipientId}`)).toBeInTheDocument();
        await sendGroupMessage('legacy send');
        expect(sentCiphertextsTo(transport, peerRecipientId).length).toBe(1);
        legacyMount.unmount();
        (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store.clear();

        // Follow-up: a fail-closed mount must not poison the next mount. Seed a
        // valid blob and confirm the group restores and the ratchet continues
        // from the persisted position rather than the initial one.
        const initialGroup = group_add_member(group_create(selfIdentity), peerPublic);
        const initialCiphertext = group_encrypt(
            initialGroup,
            selfIdentity,
            new TextEncoder().encode('initial'),
        );
        const initialNonce = nonceOf(initialCiphertext);

        seedPersistedGroupState({ members: validMembers, blob: validBlob });
        const recoveredMount = render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush();
        await flush();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.getByTestId('member-list')).toBeInTheDocument();
        const sendsBeforeRecovery = sentCiphertextsTo(transport, peerRecipientId).length;
        await sendGroupMessage('after recovery');

        const recovered = sentCiphertextsTo(transport, peerRecipientId);
        expect(recovered.length).toBe(sendsBeforeRecovery + 1);
        const recoveredNonce = nonceOf(recovered[recovered.length - 1]);

        // The send used the restored (advanced) chain position, not the initial
        // one, and matches the deterministic continuation of the seeded blob.
        expect(hex(recoveredNonce)).not.toBe(hex(initialNonce));
        const expectedRecovered = group_encrypt(
            group_from_bytes(new Uint8Array(validBlob)),
            selfIdentity,
            new TextEncoder().encode('after recovery'),
        );
        expect(hex(recoveredNonce)).toBe(hex(nonceOf(expectedRecovered)));

        recoveredMount.unmount();
    });
});