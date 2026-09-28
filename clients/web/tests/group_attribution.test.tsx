/** @vitest-environment jsdom */
//
// TDD tests for GRP-7: attributing received group messages to a sender, and
// surfacing group send failures in the UI.
//
// GAP A — a received group message is appended with no sender identity, so
// every group collapses into one flat, unattributed log. Attribution is
// derived from the wrapper roster that is ALREADY on the wire (no protocol
// change): `GroupSession::new` ignores the sender's own public key and starts
// with an empty member list, so the roster of a received envelope lists exactly
// the members the SENDER addressed — every member except the sender. The sender
// is therefore the one known group member whose public key is absent from the
// roster, and the local user's own key is always present (the sender addressed
// them), which doubles as the "was this envelope addressed to me?" check.
//
// GAP B — the fan-out is fire-and-forget (`void ... .catch(console.warn)`), so a
// relay failure is visible only in the console. These tests pin that the
// fan-out is awaited and its per-member outcome is surfaced honestly: a total
// failure is not rendered as sent, and a partial failure is reported as
// "sent to N of M" rather than as blanket success or blanket failure.
//
// The real WASM group crypto is used (group_create / group_add_member /
// group_encrypt / group_decrypt / generate_prekey_bundle); only the network
// transport boundary is mocked, matching the repo convention established in
// group_send_receive.test.tsx.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, fireEvent, within } from '@testing-library/react';

// ── Mutable fixtures ───────────────────────────────────────────────────────
//
// vi.mock factories are hoisted and file-scoped, so per-test variation is done
// via module-level variables that the mock reads at call time.

/** Map of recipientId → prekey bundle bytes that lookupPrekey will return. */
let prekeyBundles: Record<string, Uint8Array>;
/** Map of recipientId → error message; sendEnvelope rejects for those members. */
let sendRejections: Record<string, string>;
/** Destructive store-and-forward mailboxes, keyed by recipient ID. */
let mailboxes: Map<string, Uint8Array[]>;

vi.mock('../src/storage', () => {
    const store = new Map<string, unknown>();
    class MockStorageGate {
        async open() { return Promise.resolve(); }
        async get(_store: string, id: string) { return store.get(id) ?? null; }
        async put(_store: string, id: string, value: unknown) { store.set(id, value); }
    }
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
    generate_prekey_bundle,
    bundle_identity_key_bytes,
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
 * The short, stable sender label the UI is expected to render: the first four
 * bytes of the sender's public identity key, hex-encoded (8 characters).
 */
function shortLabel(publicBytes: Uint8Array): string {
    return Array.from(publicBytes.slice(0, 4))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** Flush pending microtasks + timer callbacks under fake timers. */
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

function makeTransport() {
    return {
        lookupPrekey: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
            const bundle = prekeyBundles[recipientId];
            if (!bundle) throw new Error('relay: recipient not found');
            return bundle;
        }),
        sendEnvelope: vi.fn(async (recipientId: string, envelope: Uint8Array): Promise<void> => {
            const rejection = sendRejections[recipientId];
            if (rejection) throw new Error(rejection);
            if (!mailboxes.has(recipientId)) mailboxes.set(recipientId, []);
            mailboxes.get(recipientId)!.push(new Uint8Array(envelope));
        }),
        pickupEnvelope: vi.fn(async (recipientId: string): Promise<Uint8Array> => {
            const box = mailboxes.get(recipientId);
            if (!box || box.length === 0) throw new Error('NotFound');
            return box.shift()!;
        }),
    };
}

/** Render the group view, create the group and add each peer by recipient ID. */
async function renderGroupWithPeers(
    selfIdentity: ReturnType<typeof generate_identity>,
    selfRecipientId: string,
    peerIds: string[],
) {
    const transport = makeTransport();
    render(
        <GroupConversation
            transport={transport}
            identity={selfIdentity}
            selfRecipientId={selfRecipientId}
        />,
    );
    await flush();
    fireEvent.click(screen.getByTestId('create-group-button'));
    await flush();
    for (const peerId of peerIds) {
        fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerId } });
        fireEvent.click(screen.getByTestId('add-peer-button'));
        await flush();
    }
    return transport;
}

/** The message row (`.group-msg`) that contains the given plaintext. */
function rowFor(plaintext: string): HTMLElement {
    const el = screen.getByText(plaintext).closest('.group-msg');
    if (!el) throw new Error(`no message row found for ${plaintext}`);
    return el as HTMLElement;
}

beforeEach(() => {
    prekeyBundles = {};
    sendRejections = {};
    mailboxes = new Map();
    (MockStorageGate as unknown as { __store: Map<string, unknown> }).__store.clear();
    vi.useFakeTimers();
});

afterEach(() => {
    vi.useRealTimers();
});

// ── Tests ──────────────────────────────────────────────────────────────────

describe('GRP-7 group message attribution', () => {
    test('the identity key extracted from a prekey bundle is the same 33-byte key as public_bytes()', async () => {
        // The attribution rule compares wrapper-roster public keys against the
        // keys the component learned via lookupPrekey + bundle_identity_key_bytes,
        // so those two encodings must be byte-identical. This pins that
        // invariant rather than assuming it.
        const peer = generate_identity();
        const bundle = generate_prekey_bundle(peer);
        expect(Array.from(bundle_identity_key_bytes(bundle))).toEqual(
            Array.from(peer.public_bytes()),
        );
    });

    test('a received group message renders with its sender label, and two senders are distinguishable', async () => {
        const self = generate_identity();
        const selfPublic = self.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const p1 = generate_identity();
        const p1Public = p1.public_bytes();
        const p1Id = recipientIdFromPublicBytes(p1Public);

        const p2 = generate_identity();
        const p2Public = p2.public_bytes();
        const p2Id = recipientIdFromPublicBytes(p2Public);

        prekeyBundles[p1Id] = generate_prekey_bundle(p1);
        prekeyBundles[p2Id] = generate_prekey_bundle(p2);

        // Each sender's own group session contains the OTHER members (a sender
        // never adds itself), so the roster on the wire is [self, other peer].
        const p1Group = group_add_member(
            group_add_member(group_create(p1), selfPublic),
            p2Public,
        );
        const p2Group = group_add_member(
            group_add_member(group_create(p2), selfPublic),
            p1Public,
        );

        const transport = makeTransport();
        await transport.sendEnvelope(
            selfRecipientId,
            group_encrypt(p1Group, p1, new TextEncoder().encode('hello from p1')),
        );
        await transport.sendEnvelope(
            selfRecipientId,
            group_encrypt(p2Group, p2, new TextEncoder().encode('hello from p2')),
        );
        // A third message from p1 again — its label must match p1's first
        // message (a label derived from the message's index would not).
        await transport.sendEnvelope(
            selfRecipientId,
            group_encrypt(p1Group, p1, new TextEncoder().encode('hello again from p1')),
        );

        render(
            <GroupConversation
                transport={transport}
                identity={self}
                selfRecipientId={selfRecipientId}
            />,
        );
        await flush();
        fireEvent.click(screen.getByTestId('create-group-button'));
        await flush();
        for (const peerId of [p1Id, p2Id]) {
            fireEvent.change(screen.getByTestId('group-peer-id-input'), { target: { value: peerId } });
            fireEvent.click(screen.getByTestId('add-peer-button'));
            await flush();
        }

        // One envelope per poll (the mailbox is destructive).
        await tick(5000);
        await tick(5000);
        await tick(5000);

        const label1 = shortLabel(p1Public);
        const label2 = shortLabel(p2Public);
        expect(label1).not.toEqual(label2);

        expect(screen.getByText('hello from p1')).toBeInTheDocument();
        expect(screen.getByText('hello from p2')).toBeInTheDocument();
        expect(screen.getByText('hello again from p1')).toBeInTheDocument();

        // Each message carries its own sender's label...
        expect(within(rowFor('hello from p1')).getByText(label1)).toBeInTheDocument();
        expect(within(rowFor('hello from p2')).getByText(label2)).toBeInTheDocument();
        // ...and the same sender always gets the same label.
        expect(within(rowFor('hello again from p1')).getByText(label1)).toBeInTheDocument();
        expect(within(rowFor('hello from p2')).queryByText(label1)).not.toBeInTheDocument();

        // Both messages were received into the same group, so they carry the
        // same stable group id (not a per-message index).
        const groupId1 = rowFor('hello from p1').getAttribute('data-group-id');
        expect(groupId1).toBeTruthy();
        expect(rowFor('hello from p2').getAttribute('data-group-id')).toBe(groupId1);
        expect(rowFor('hello again from p1').getAttribute('data-group-id')).toBe(groupId1);
    });
});

describe('GRP-7 group send failures', () => {
    test('a rejected fan-out surfaces an error and does not render the message as sent', async () => {
        const self = generate_identity();
        const selfPublic = self.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const m1 = generate_identity();
        const m1Id = recipientIdFromPublicBytes(m1.public_bytes());
        prekeyBundles[m1Id] = generate_prekey_bundle(m1);

        const transport = await renderGroupWithPeers(self, selfRecipientId, [m1Id]);

        // The relay rejects the only member's send.
        sendRejections[m1Id] = 'relay unavailable';

        fireEvent.change(screen.getByTestId('group-message-input'), {
            target: { value: 'doomed message' },
        });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await flush();

        // The failure is surfaced in the UI (not just the console)...
        expect(screen.getByRole('alert')).toBeInTheDocument();
        // ...and the message is NOT claimed as sent.
        const row = rowFor('doomed message');
        expect(within(row).getByTestId(/^send-status-/)).toHaveTextContent('failed');
        expect(within(row).queryByText('sent')).not.toBeInTheDocument();

        // The send contract still holds: one sendEnvelope call per real member,
        // with the ciphertext as a Uint8Array.
        expect(transport.sendEnvelope).toHaveBeenCalledTimes(1);
        expect(transport.sendEnvelope.mock.calls[0][0]).toBe(m1Id);
        expect(transport.sendEnvelope.mock.calls[0][1]).toBeInstanceOf(Uint8Array);

        // A later successful send must not erase the earlier failure.
        delete sendRejections[m1Id];
        fireEvent.change(screen.getByTestId('group-message-input'), {
            target: { value: 'second message' },
        });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await flush();

        expect(within(rowFor('second message')).getByTestId(/^send-status-/)).toHaveTextContent('sent');
        expect(within(rowFor('doomed message')).getByTestId(/^send-status-/)).toHaveTextContent('failed');
    });
});

describe('GRP-7 boundary cases', () => {
    test('an envelope from a non-member fails closed — no plaintext is rendered', async () => {
        const self = generate_identity();
        const selfPublic = self.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const m1 = generate_identity();
        const m1Id = recipientIdFromPublicBytes(m1.public_bytes());
        prekeyBundles[m1Id] = generate_prekey_bundle(m1);

        // An outsider who is NOT a member of self's group addresses their
        // envelope to a third party instead of self, so the wrapper roster
        // parses cleanly but does not contain self's own key.
        const outsider = generate_identity();
        const victim = generate_identity();
        const outsiderGroup = group_add_member(group_create(outsider), victim.public_bytes());
        const outsiderEnvelope = group_encrypt(
            outsiderGroup,
            outsider,
            new TextEncoder().encode('secret outsider plaintext'),
        );

        const transport = await renderGroupWithPeers(self, selfRecipientId, [m1Id]);
        await transport.sendEnvelope(selfRecipientId, outsiderEnvelope);
        await tick(5000);

        // Fail closed: no plaintext, no message row appended at all, and a
        // visible warning that names the real reason (the envelope was not
        // addressed to this member) — i.e. it was rejected BEFORE decryption,
        // not merely because the AEAD happened to fail.
        expect(screen.queryByText('secret outsider plaintext')).not.toBeInTheDocument();
        expect(screen.queryByTestId(/^message-/)).not.toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent(/not addressed to this member/i);
    });

    test('a partial fan-out is reported honestly, not as blanket success or failure', async () => {
        const self = generate_identity();
        const selfPublic = self.public_bytes();
        const selfRecipientId = recipientIdFromPublicBytes(selfPublic);

        const m1 = generate_identity();
        const m1Id = recipientIdFromPublicBytes(m1.public_bytes());
        const m2 = generate_identity();
        const m2Id = recipientIdFromPublicBytes(m2.public_bytes());
        const m3 = generate_identity();
        const m3Id = recipientIdFromPublicBytes(m3.public_bytes());
        prekeyBundles[m1Id] = generate_prekey_bundle(m1);
        prekeyBundles[m2Id] = generate_prekey_bundle(m2);
        prekeyBundles[m3Id] = generate_prekey_bundle(m3);

        const transport = await renderGroupWithPeers(self, selfRecipientId, [m1Id, m2Id, m3Id]);

        // Only M2's relay leg fails.
        sendRejections[m2Id] = 'relay unavailable';

        fireEvent.change(screen.getByTestId('group-message-input'), {
            target: { value: 'partial message' },
        });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await flush();

        // One call per real member, each with the ciphertext as a Uint8Array.
        expect(transport.sendEnvelope).toHaveBeenCalledTimes(3);
        for (const call of transport.sendEnvelope.mock.calls) {
            expect(call[1]).toBeInstanceOf(Uint8Array);
        }

        const partialRow = rowFor('partial message');
        const partialStatus = within(partialRow).getByTestId(/^send-status-/);
        expect(partialStatus).toHaveTextContent('sent to 2 of 3');
        expect(partialStatus).not.toHaveTextContent('failed');
        expect(partialStatus.textContent).not.toBe('sent');

        // A later fully-successful send is reported as sent, and the earlier
        // partial result is still shown as partial.
        delete sendRejections[m2Id];
        fireEvent.change(screen.getByTestId('group-message-input'), {
            target: { value: 'full message' },
        });
        fireEvent.click(screen.getByTestId('group-send-button'));
        await flush();

        expect(within(rowFor('full message')).getByTestId(/^send-status-/)).toHaveTextContent('sent');
        expect(within(rowFor('partial message')).getByTestId(/^send-status-/)).toHaveTextContent(
            'sent to 2 of 3',
        );
    });
});
