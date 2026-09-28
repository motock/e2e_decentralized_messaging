/** @vitest-environment jsdom */
//
// GRP-6 regression: the out-of-band `kind` filter MUST be sent on the
// `pickup_envelope` op, otherwise a DESTRUCTIVE relay mailbox hands a
// foreign-kind envelope to the wrong receive loop and the message is lost.
//
// Reviewer blocking finding: `RelayTransport.pickupEnvelope` sent
//   roundTrip({ op: 'pickup_envelope', recipient_id: recipientId })
// with NO `kind` field. The relay's foreign-kind re-queue (relay/src/ws.rs)
// only engages when the request carries a filter; with `kind: None` it takes
// the first envelope, sets `accepted = true`, dequeues it destructively and
// returns it. The direct loop then sees `envelopeKind === 'group'` and
// `return`s (Conversation.tsx) — but the envelope is already gone from the
// mailbox, so "leave it for the owning loop" is false and the group message is
// destroyed. GroupConversation.tsx has the mirror-image bug for 'direct'.
//
// The existing envelope_kind_routing.test.tsx cannot catch this: its
// `mockResolvedValue` mock is NON-destructive and returns the same envelope on
// every poll. This file drives a genuinely destructive mailbox — every
// successful pickup REMOVES the envelope — and asserts the brief's test 2:
// "A foreign-kind envelope is not destroyed by the wrong loop — the owning
// loop still receives it afterwards."
//
// CONTRACT UNDER TEST (kind is NEVER inside the ciphertext):
//   * `pickupEnvelope` sends `kind` as a SIBLING JSON field of the
//     `pickup_envelope` op (the same non-content metadata channel as
//     `send_envelope`).
//   * A relay honouring that filter leaves a foreign-kind envelope queued, so
//     the wrong loop does not receive it and the owning loop still does.

import { describe, test, expect, beforeEach } from 'vitest';
import { RelayTransport } from '../src/relay_transport';

function b64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function fromB64(s: string): Uint8Array {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/** A difficulty-0 challenge so the PoW solver succeeds on its first candidate. */
function trivialChallenge(): string {
    const context = new TextEncoder().encode('ws-relay-v1');
    const wire = new Uint8Array(2 + context.length + 16 + 4);
    wire[0] = 0;
    wire[1] = context.length;
    wire.set(context, 2);
    // nonce (16 zero bytes) and difficulty (0) are already zero.
    return b64(wire);
}

interface QueuedEnvelope {
    recipientId: string;
    envelope: Uint8Array;
    kind: string | undefined;
}

/**
 * A mock relay whose mailbox is DESTRUCTIVE, mirroring relay/src/ws.rs:
 * a successful pickup REMOVES the envelope from the queue.
 *
 * `pickup_envelope` honours the out-of-band `kind` filter exactly like the
 * real relay: an envelope is dequeued only when its kind matches the filter or
 * it carries no tag at all (the fall-through case); a foreign-kind envelope
 * STAYS QUEUED and the op answers `ok:false` (mailbox empty for this filter).
 * With NO filter on the request the first envelope is dequeued destructively
 * regardless of kind — precisely the behaviour that loses the other loop's
 * mail.
 */
class DestructiveMailboxWebSocket {
    static OPEN = 1;
    static instances: DestructiveMailboxWebSocket[] = [];
    static mailbox: QueuedEnvelope[] = [];

    readyState = 1;
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: string }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    sent: any[] = [];

    constructor(public url: string) {
        DestructiveMailboxWebSocket.instances.push(this);
        queueMicrotask(() => this.onopen?.());
    }

    send(data: string) {
        const req = JSON.parse(data);
        this.sent.push(req);
        let resp: any;
        if (req.op === 'challenge') {
            resp = { ok: true, challenge: trivialChallenge(), challenge_id: 'cid' };
        } else if (req.op === 'send_envelope') {
            DestructiveMailboxWebSocket.mailbox.push({
                recipientId: req.recipient_id,
                envelope: fromB64(req.envelope),
                kind: typeof req.kind === 'string' ? req.kind : undefined,
            });
            resp = { ok: true };
        } else if (req.op === 'pickup_envelope') {
            const filter: string | undefined =
                typeof req.kind === 'string' ? req.kind : undefined;
            const idx = DestructiveMailboxWebSocket.mailbox.findIndex(
                (e) =>
                    e.recipientId === req.recipient_id &&
                    (filter === undefined || e.kind === undefined || e.kind === filter),
            );
            if (idx === -1) {
                // Destructive semantics: nothing matching was removed.
                resp = { ok: false, error: 'no envelope' };
            } else {
                // DESTRUCTIVE dequeue: the envelope leaves the mailbox here.
                const [picked] = DestructiveMailboxWebSocket.mailbox.splice(idx, 1);
                resp = {
                    ok: true,
                    envelope: b64(picked.envelope),
                    ...(picked.kind !== undefined ? { kind: picked.kind } : {}),
                };
            }
        } else {
            resp = { ok: true };
        }
        queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(resp) }));
    }

    close() {}
}

const DIRECT_BYTES = new Uint8Array([0x0d, 0x0d, 0x0d]);
const GROUP_BYTES = new Uint8Array([0x67, 0x67, 0x67]);
const RECIPIENT = 'shared-recipient';

function queue(kind: 'direct' | 'group'): void {
    DestructiveMailboxWebSocket.mailbox.push({
        recipientId: RECIPIENT,
        envelope: kind === 'direct' ? DIRECT_BYTES : GROUP_BYTES,
        kind,
    });
}

function mailboxKinds(): (string | undefined)[] {
    return DestructiveMailboxWebSocket.mailbox.map((e) => e.kind);
}

beforeEach(() => {
    DestructiveMailboxWebSocket.instances = [];
    DestructiveMailboxWebSocket.mailbox = [];
    (globalThis as any).WebSocket = DestructiveMailboxWebSocket;
});

describe('pickup_envelope requests the out-of-band kind filter', () => {
    test('the pickup op carries kind as a sibling field of the op', async () => {
        queue('direct');
        const transport = new RelayTransport('ws://relay.test', 'direct');
        await transport.pickupEnvelope(RECIPIENT);

        const ws = DestructiveMailboxWebSocket.instances[0];
        const frame = ws.sent.find((r) => r.op === 'pickup_envelope');
        expect(frame).toBeDefined();
        expect(frame.recipient_id).toBe(RECIPIENT);
        expect(frame.kind).toBe('direct');
    });
});

describe('a foreign-kind envelope survives the destructive mailbox', () => {
    test('direct loop polls first: it gets the direct envelope and the group envelope stays queued', async () => {
        // FIFO mailbox: [group, direct] — the group envelope is at the head, so
        // a filterless pickup would destructively hand it to the direct loop.
        queue('group');
        queue('direct');
        expect(mailboxKinds()).toEqual(['group', 'direct']);

        const directTransport = new RelayTransport('ws://relay.test', 'direct');
        const picked = await directTransport.pickupEnvelope(RECIPIENT);

        // The direct loop must receive the DIRECT envelope, not the group one.
        expect((picked as any).kind).toBe('direct');
        // ...and the group envelope must still be in the mailbox for its owner.
        expect(DestructiveMailboxWebSocket.mailbox).toHaveLength(1);
        expect(mailboxKinds()).toEqual(['group']);

        // The owning (group) loop still receives it afterwards.
        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const pickedGroup = await groupTransport.pickupEnvelope(RECIPIENT);
        expect((pickedGroup as any).kind).toBe('group');
        expect(DestructiveMailboxWebSocket.mailbox).toHaveLength(0);
    });

    test('group loop polls first: it gets the group envelope and the direct envelope stays queued', async () => {
        queue('direct');
        queue('group');

        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const picked = await groupTransport.pickupEnvelope(RECIPIENT);
        expect((picked as any).kind).toBe('group');
        expect(mailboxKinds()).toEqual(['direct']);

        const directTransport = new RelayTransport('ws://relay.test', 'direct');
        const pickedDirect = await directTransport.pickupEnvelope(RECIPIENT);
        expect((pickedDirect as any).kind).toBe('direct');
        expect(DestructiveMailboxWebSocket.mailbox).toHaveLength(0);
    });

    test('the loop-side foreign-kind skip is a deferral, not a destructive drop', async () => {
        // Mirror the receive step of Conversation.tsx: pick up, and if the
        // envelope's kind is foreign, `return` (skip it). GroupConversation.tsx
        // does the mirror image for 'direct'.
        queue('group');
        queue('direct');

        const directTransport = new RelayTransport('ws://relay.test', 'direct');
        const directPicked = await directTransport.pickupEnvelope(RECIPIENT);
        const directKind = (directPicked as any).kind;
        const directSkipped = directKind === 'group';
        expect(directSkipped).toBe(false);

        // The group envelope must NOT have been consumed by the direct loop.
        expect(mailboxKinds()).toEqual(['group']);

        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const groupPicked = await groupTransport.pickupEnvelope(RECIPIENT);
        const groupKind = (groupPicked as any).kind;
        const groupSkipped = groupKind === 'direct';
        expect(groupSkipped).toBe(false);
        expect(groupKind).toBe('group');
        expect(DestructiveMailboxWebSocket.mailbox).toHaveLength(0);
    });
});
