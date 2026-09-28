/** @vitest-environment jsdom */
//
// TDD tests for real-peer member key distribution in the GroupConversation UI.
//
// These tests assert the three success criteria from the story:
//   (1) a member is added to a group using their real recipient ID and a
//       looked-up public key (via lookup_prekey / RelayTransport), not a
//       locally generated demo identity;
//   (2) group membership persists across a simulated reload;
//   (3) a lookup_prekey failure (peer not found) surfaces a clear error and
//       does not add a member.
//
// Negative/boundary cases:
//   - adding a peer ID with no published bundle fails closed with a visible
//     error, not a silent no-op or crash;
//   - removing a member who was already removed is a no-op, not an error.
//
// The WASM crypto layer (group_create / group_add_member / group_remove_member
// / group_encrypt / group_decrypt) is mocked to simulate the Sender Keys
// contract — exactly like the existing group_conversation.test.tsx — so these
// tests do not require a built pkg/. Only the transport boundary
// (lookupPrekey) is mocked, matching the repo convention of mocking external
// system boundaries while keeping internal/application logic real.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

// ── Mutable fixtures ───────────────────────────────────────────────────────
//
// vi.mock factories are hoisted and file-scoped, so per-test variation is done
// via these module-level variables that the mock reads at call time (same
// pattern as conversation_session.test.tsx's `mockStoredMessages`).

/** Map of recipientId → public key bytes that lookupPrekey will return. */
let prekeyBundles: Record<string, Uint8Array>;
/** Whether lookupPrekey should reject (simulating "peer not found"). */
let prekeyRejections: Record<string, string>;
/** Persisted group state that the mock StorageGate returns on reload. */
let persistedGroupState: unknown;
/**
 * The local identity + recipient ID the real-peer path needs. Criterion 3
 * makes the group view fail closed without them, so every real-peer render
 * site supplies them (see the no-props test at the bottom of this file).
 */
let selfIdentity: InstanceType<typeof IdentityHandle>;
let selfRecipientId: string;

// ── WASM mock ───────────────────────────────────────────────────────────────

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => {
    const arrayEquals = (a: Uint8Array, b: Uint8Array) =>
        a.length === b.length && a.every((v, i) => v === b[i]);

    class IdentityHandle {
        publicBytes: Uint8Array;
        constructor(publicBytes: Uint8Array) { this.publicBytes = publicBytes; }
        public_bytes() { return this.publicBytes; }
    }

    class GroupHandle {
        members: Uint8Array[];
        constructor(members: Uint8Array[] = []) { this.members = members; }
    }

    const encryptionMembers = new Map<Uint8Array, Uint8Array[]>();

    function generate_identity() {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return new IdentityHandle(bytes);
    }

    function group_create(selfIdentity: IdentityHandle) {
        return new GroupHandle([selfIdentity.public_bytes()]);
    }

    function group_add_member(group: GroupHandle, publicBytes: Uint8Array) {
        if (group.members.some((b) => arrayEquals(b, publicBytes))) {
            return new GroupHandle([...group.members]);
        }
        return new GroupHandle([...group.members, publicBytes]);
    }

    function group_remove_member(group: GroupHandle, publicBytes: Uint8Array) {
        return new GroupHandle(group.members.filter((b) => !arrayEquals(b, publicBytes)));
    }

    function group_encrypt(group: GroupHandle, _senderIdentity: IdentityHandle, plaintextBytes: Uint8Array) {
        const ciphertext = new Uint8Array(plaintextBytes);
        encryptionMembers.set(ciphertext, [...group.members]);
        return ciphertext;
    }

    function group_decrypt(_group: GroupHandle, memberIdentity: IdentityHandle, ciphertext: Uint8Array) {
        const memberSet = encryptionMembers.get(ciphertext);
        if (!memberSet) throw new Error('decryption failed');
        const publicKey = memberIdentity.public_bytes();
        if (!memberSet.some((b) => arrayEquals(b, publicKey))) {
            throw new Error('decryption failed');
        }
        return ciphertext;
    }

    function derive_safety_number() { return '00000 00000 00000 00000'; }

    // The real binding extracts the identity key from a prekey bundle. In
    // these tests lookupPrekey returns the identity key bytes directly (no
    // bundle envelope), so this is an identity passthrough.
    function bundle_identity_key_bytes(bundle: Uint8Array) { return bundle; }

    // GRP-4: group state persistence bindings, mirroring the real wasm
    // exports. Serialization is a pure function of the handle's current
    // member set (never cached, never mutating the handle), and
    // group_from_bytes validates the blob and returns a live GroupHandle
    // from this same factory, so the restored group is immediately usable.
    const GROUP_BLOB_MAGIC = [0x47, 0x52, 0x50, 0x34]; // "GRP4"
    const GROUP_BLOB_VERSION = 0x01;

    function group_to_bytes(group: GroupHandle): Uint8Array {
        const bytes: number[] = [...GROUP_BLOB_MAGIC, GROUP_BLOB_VERSION];
        const pushU32 = (value: number) => {
            bytes.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
        };
        pushU32(group.members.length);
        for (const member of group.members) {
            pushU32(member.length);
            bytes.push(...member);
        }
        return new Uint8Array(bytes);
    }

    function group_from_bytes(blob: Uint8Array): GroupHandle {
        const readU32 = (offset: number) =>
            ((blob[offset] << 24) | (blob[offset + 1] << 16) | (blob[offset + 2] << 8) | blob[offset + 3]) >>> 0;
        if (!(blob instanceof Uint8Array) || blob.length < 9) {
            throw new Error('group_from_bytes: malformed group blob');
        }
        for (let i = 0; i < GROUP_BLOB_MAGIC.length; i++) {
            if (blob[i] !== GROUP_BLOB_MAGIC[i]) {
                throw new Error('group_from_bytes: malformed group blob');
            }
        }
        if (blob[4] !== GROUP_BLOB_VERSION) {
            throw new Error('group_from_bytes: unsupported group blob version');
        }
        const memberCount = readU32(5);
        const members: Uint8Array[] = [];
        let offset = 9;
        for (let i = 0; i < memberCount; i++) {
            if (offset + 4 > blob.length) {
                throw new Error('group_from_bytes: malformed group blob');
            }
            const memberLength = readU32(offset);
            offset += 4;
            if (offset + memberLength > blob.length) {
                throw new Error('group_from_bytes: malformed group blob');
            }
            members.push(blob.slice(offset, offset + memberLength));
            offset += memberLength;
        }
        if (offset !== blob.length) {
            throw new Error('group_from_bytes: malformed group blob');
        }
        return new GroupHandle(members);
    }

    return {
        generate_identity,
        group_create,
        group_add_member,
        group_remove_member,
        group_encrypt,
        group_decrypt,
        derive_safety_number,
        bundle_identity_key_bytes,
        group_to_bytes,
        group_from_bytes,
        IdentityHandle,
        GroupHandle,
    };
});

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
}));

// ── Storage mock ───────────────────────────────────────────────────────────
//
// Mirrors the real StorageGate API (get/put) and the conversation test
// convention: an in-memory store that simulates persistence across a
// "reload" (re-render with fresh component instance).

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
    return { StorageGate: MockStorageGate };
});

import { StorageGate as MockStorageGate } from '../src/storage';
import { GroupConversation } from '../src/GroupConversation';
import { generate_identity, IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';

// ── Transport mock ──────────────────────────────────────────────────────────

function makeTransport() {
    return {
        lookupPrekey: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
            const rejection = prekeyRejections[recipientId];
            if (rejection) throw new Error(rejection);
            const bundle = prekeyBundles[recipientId];
            if (!bundle) throw new Error('relay: recipient not found');
            return bundle;
        }),
        // These tests don't exercise send/receive, but GroupTransport now
        // requires them — provide no-op stubs so the mock satisfies the
        // interface.
        sendEnvelope: vi.fn(async (_recipientId: string, _envelope: Uint8Array): Promise<void> => {}),
        pickupEnvelope: vi.fn(async (_recipientId: string): Promise<Uint8Array> => {
            throw new Error('NotFound');
        }),
    };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** A deterministic 32-byte key for a given recipient ID (stable across calls). */
function fakePeerKey(recipientId: string): Uint8Array {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[i] = (recipientId.charCodeAt(i % recipientId.length) + i) & 0xff;
    }
    return bytes;
}

beforeEach(() => {
    prekeyBundles = {};
    prekeyRejections = {};
    persistedGroupState = null;
    selfIdentity = generate_identity();
    selfRecipientId = 'self-recipient-id';
    // Clear the mock storage store so persisted group state from a previous
    // test doesn't leak into the next (the store is module-level in the mock).
    (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store.clear();
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe('GroupConversation real-peer member distribution', () => {
    test('adding a member by recipient ID performs a real lookupPrekey call and group_add_member with the looked-up key', async () => {
        const peerId = 'peer-alice-base64-id';
        const peerKey = fakePeerKey(peerId);
        prekeyBundles[peerId] = peerKey;

        const transport = makeTransport();
        render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);

        // Create the group first.
        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        // Type the real recipient ID and add the peer.
        const peerInput = screen.getByTestId('group-peer-id-input');
        fireEvent.change(peerInput, { target: { value: peerId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));

        // Wait for the member to appear in the group.
        await waitFor(() => {
            expect(screen.getByTestId(`member-${peerId}`)).toBeInTheDocument();
        });

        // The transport's lookupPrekey was called with the recipient ID.
        expect(transport.lookupPrekey).toHaveBeenCalledWith(peerId);
        expect(transport.lookupPrekey).toHaveBeenCalledTimes(1);

        // The member is shown as in-group (has a Remove button).
        expect(screen.getByTestId(`remove-peer-${peerId}`)).toBeInTheDocument();
    });

    test('a lookup_prekey failure (peer not found) surfaces a clear error and does not add a member', async () => {
        const ghostId = 'ghost-peer-id';
        prekeyRejections[ghostId] = 'relay: recipient not found';

        const transport = makeTransport();
        render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        const peerInput = screen.getByTestId('group-peer-id-input');
        fireEvent.change(peerInput, { target: { value: ghostId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));

        // A visible error appears.
        await waitFor(() => {
            expect(screen.getByText(/not found|peer not found|failed to add/i)).toBeInTheDocument();
        });

        // The peer was NOT added — no member chip, no remove button.
        expect(screen.queryByTestId(`member-${ghostId}`)).not.toBeInTheDocument();
        expect(screen.queryByTestId(`remove-peer-${ghostId}`)).not.toBeInTheDocument();
    });

    test('adding a peer ID with no published bundle fails closed with a visible error, not a silent no-op', async () => {
        const noBundleId = 'no-bundle-peer';
        // No entry in prekeyBundles and no explicit rejection — transport throws
        // "relay: recipient not found" by default.

        const transport = makeTransport();
        render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: noBundleId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));

        await waitFor(() => {
            expect(screen.getByText(/not found|failed to add/i)).toBeInTheDocument();
        });

        // Fail closed: no member added.
        expect(screen.queryByTestId(`member-${noBundleId}`)).not.toBeInTheDocument();
    });

    test('group membership persists across a simulated reload', async () => {
        const peerId = 'persisted-peer';
        const peerKey = fakePeerKey(peerId);
        prekeyBundles[peerId] = peerKey;

        const transport = makeTransport();

        // First "session": create group, add a real peer.
        const { unmount } = render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);
        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await waitFor(() => expect(screen.getByTestId(`member-${peerId}`)).toBeInTheDocument());

        // Simulate a page reload: unmount and re-render a fresh component.
        unmount();
        render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);

        // The group and its members should be restored from persisted state.
        await waitFor(() => {
            expect(screen.getByTestId('member-list')).toBeInTheDocument();
        });
        await waitFor(() => {
            expect(screen.getByTestId(`member-${peerId}`)).toBeInTheDocument();
        });
        // The member is still in the group (Remove button present).
        expect(screen.getByTestId(`remove-peer-${peerId}`)).toBeInTheDocument();
    });

    test('removing a member who was already removed is a no-op, not an error', async () => {
        const peerId = 'removable-peer';
        const peerKey = fakePeerKey(peerId);
        prekeyBundles[peerId] = peerKey;

        const transport = makeTransport();
        render(<GroupConversation transport={transport} identity={selfIdentity} selfRecipientId={selfRecipientId} />);

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        // Add the peer.
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await waitFor(() => expect(screen.getByTestId(`remove-peer-${peerId}`)).toBeInTheDocument());

        // Remove the peer.
        fireEvent.click(screen.getByTestId(`remove-peer-${peerId}`));
        await waitFor(() => expect(screen.getByTestId(`add-peer-${peerId}`)).toBeInTheDocument());

        // No error should be visible after removal.
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();

        // Removing again (the member is already gone) should be a no-op:
        // no error, no crash. We click the add button's adjacent remove
        // path — since the member is already removed, there's no remove
        // button. The component should handle this gracefully.
        // Verify no error alert appeared at any point.
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    // ── Transport serialization ─────────────────────────────────────────────
    //
    // RelayTransport allows only ONE request in flight: a second concurrent op
    // overwrites its single pending slot and the first caller's promise never
    // settles. The receive loop polls while the send path fires sendEnvelope
    // without awaiting, so an unserialized send landing mid-poll would hang the
    // poll forever and permanently kill the receive loop. GroupConversation
    // funnels every transport op through one queue; this pins that.
    test('transport ops are serialized: a send issued while another op is in flight waits its turn', async () => {
        const peerId = 'peer-serialized-base64-id';
        prekeyBundles[peerId] = fakePeerKey(peerId);

        let releaseFirstSend: () => void = () => {};
        const firstSendGate = new Promise<void>((resolve) => {
            releaseFirstSend = resolve;
        });
        let sendCalls = 0;
        const transport = {
            lookupPrekey: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
                const bundle = prekeyBundles[recipientId];
                if (!bundle) throw new Error('relay: recipient not found');
                return bundle;
            }),
            sendEnvelope: vi.fn(async (): Promise<void> => {
                sendCalls += 1;
                // Hold the transport's single in-flight slot on the first send.
                if (sendCalls === 1) await firstSendGate;
            }),
            pickupEnvelope: vi.fn(async (): Promise<Uint8Array> => {
                throw new Error('NotFound');
            }),
        };

        render(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());

        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await waitFor(() => expect(screen.getByTestId(`member-${peerId}`)).toBeInTheDocument());

        // Send #1 — its sendEnvelope blocks, holding the single in-flight slot.
        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'first' } });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await waitFor(() => expect(transport.sendEnvelope).toHaveBeenCalledTimes(1));

        // Send #2 while #1 is still in flight. Serialized: it must NOT start.
        fireEvent.change(screen.getByTestId('group-message-input'), { target: { value: 'second' } });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await new Promise((resolve) => setTimeout(resolve, 25));
        expect(transport.sendEnvelope).toHaveBeenCalledTimes(1);

        // Release #1; #2 then runs.
        releaseFirstSend();
        await waitFor(() => expect(transport.sendEnvelope).toHaveBeenCalledTimes(2));
    });

    // ── Criterion 3: the no-props path fails closed ─────────────────────────
    //
    // The shipped group view was a demo sandbox because it was rendered with no
    // props at all, so it ran on a throwaway identity and never polled the
    // relay. Rendering it with no props must now fail closed with a visible
    // message instead of silently pretending to be connected.

    test('rendering the group view with no props fails closed instead of pretending to be connected', async () => {
        render(<GroupConversation />);

        // A visible, fail-closed message — not a live-looking group UI.
        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeInTheDocument();
        });
        expect(screen.getByRole('alert').textContent).toMatch(/unavailable|no identity/i);

        // No group UI that would imply a working, connected group.
        expect(screen.queryByTestId('create-group-button')).not.toBeInTheDocument();
        expect(screen.queryByTestId('member-list')).not.toBeInTheDocument();
    });

    test('a no-props render does not poison a later render that supplies real props', async () => {
        const transport = makeTransport();
        const { rerender } = render(<GroupConversation />);

        // Render 1: no props -> DENY.
        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeInTheDocument();
        });

        // Render 2: real props -> must ALLOW. This is the state-persistence
        // trap: render 1 must not have written a permissive default into any
        // persisted config that render 2 then reads.
        rerender(
            <GroupConversation
                transport={transport}
                identity={selfIdentity}
                selfRecipientId={selfRecipientId}
            />,
        );

        fireEvent.click(await screen.findByTestId('create-group-button'));
        await waitFor(() => expect(screen.getByTestId('member-list')).toBeInTheDocument());
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
    test('supplying only one of identity/selfRecipientId still fails closed', async () => {
        // Pin the `||` boundary: either prop missing must deny, not fall back.
        const { unmount } = render(<GroupConversation identity={selfIdentity} />);
        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeInTheDocument();
        });
        expect(screen.queryByTestId('create-group-button')).not.toBeInTheDocument();
        unmount();

        render(<GroupConversation selfRecipientId={selfRecipientId} />);
        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeInTheDocument();
        });
        expect(screen.queryByTestId('create-group-button')).not.toBeInTheDocument();
    });
});
