/** @vitest-environment jsdom */
//
// GRP-6 regression tests against a DESTRUCTIVE mock relay mailbox.
//
// Why this file exists: the reviewer's blocking finding was that
// `RelayTransport.pickupEnvelope` never sent the out-of-band `kind` filter on
// the `pickup_envelope` op, so the relay's foreign-kind re-queue never engaged
// and the loop-side `return` in Conversation.tsx / GroupConversation.tsx was a
// DESTRUCTIVE skip — the envelope had already been removed from the mailbox by
// the time the loop decided it was foreign, so the message was lost. The
// routing tests in envelope_kind_routing.test.tsx could not catch this because
// their `mockResolvedValue` mock is non-destructive: it returns the same
// envelope on every poll.
//
// These tests drive a mock relay whose mailbox is genuinely destructive —
// every successful pickup REMOVES the envelope from the queue — and assert the
// brief's test 2: "A foreign-kind envelope is not destroyed by the wrong loop —
// the owning loop still receives it afterwards."
//
// CONTRACT UNDER TEST (kind is NEVER inside the ciphertext):
//   * `pickupEnvelope` sends `kind` as a SIBLING JSON field of the
//     `pickup_envelope` op (the same non-content metadata channel as
//     `send_envelope`).
//   * A relay honouring that filter leaves a foreign-kind envelope queued, so
//     the wrong loop gets `ok:false` (mailbox "empty for this filter") and the
//     owning loop still retrieves the envelope afterwards.

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
 * A mock relay whose mailbox is DESTRUCTIVE, mirroring the real relay's
 * `Mailbox::dequeue` semantics: a successful pickup removes the envelope.
 *
 * `pickup_envelope` honours the out-of-band `kind` filter exactly like
 * relay/src/ws.rs: an envelope is dequeued only when its kind matches the
 * filter or it carries no tag at all (the fall-through case); a foreign-kind
 * envelope STAYS QUEUED and the op answers `ok:false` (mailbox empty for this
 * filter). With NO filter on the request the first envelope is dequeued
 * destructively regardless of kind — which is precisely the behaviour that
 * loses the other loop's mail.
 */
class DestructiveRelayWebSocket {
    static OPEN = 1;
    static instances: DestructiveRelayWebSocket[] = [];
    static mailbox: QueuedEnvelope[] = [];

    readyState = 1;
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: string }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    sent: any[] = [];

    constructor(public url: string) {
        DestructiveRelayWebSocket.instances.push(this);
        queueMicrotask(() => this.onopen?.());
    }

    send(data: string) {
        const req = JSON.parse(data);
        this.sent.push(req);
        let resp: any;
        if (req.op === 'challenge') {
            resp = { ok: true, challenge: trivialChallenge(), challenge_id: 'cid' };
        } else if (req.op === 'send_envelope') {
            DestructiveRelayWebSocket.mailbox.push({
                recipientId: req.recipient_id,
                envelope: fromB64(req.envelope),
                kind: typeof req.kind === 'string' ? req.kind : undefined,
            });
            resp = { ok: true };
        } else if (req.op === 'pickup_envelope') {
            const filter: string | undefined =
                typeof req.kind === 'string' ? req.kind : undefined;
            const idx = DestructiveRelayWebSocket.mailbox.findIndex(
                (e) =>
                    e.recipientId === req.recipient_id &&
                    (filter === undefined || e.kind === undefined || e.kind === filter),
            );
            if (idx === -1) {
                // Destructive semantics: nothing matching was removed.
                resp = { ok: false, error: 'no envelope' };
            } else {
                // DESTRUCTIVE dequeue: the envelope leaves the mailbox here.
                const [picked] = DestructiveRelayWebSocket.mailbox.splice(idx, 1);
                resp = { ok: true, envelope: b64(picked.envelope), ...(picked.kind !== undefined ? { kind: picked.kind } : {}) };
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

beforeEach(() => {
    DestructiveRelayWebSocket.instances = [];
    DestructiveRelayWebSocket.mailbox = [];
    (globalThis as any).WebSocket = DestructiveRelayWebSocket;
});

describe('pickup_envelope carries the out-of-band kind filter', () => {
    test('the pickup op sends kind as a sibling field for a kinded transport', async () => {
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'my-recipient',
            envelope: DIRECT_BYTES,
            kind: 'direct',
        });
        const transport = new RelayTransport('ws://relay.test', 'direct');
        await transport.pickupEnvelope('my-recipient');

        const ws = DestructiveRelayWebSocket.instances[0];
        const frame = ws.sent.find((r) => r.op === 'pickup_envelope');
        expect(frame).toBeDefined();
        expect(frame.kind).toBe('direct');
        expect(frame.recipient_id).toBe('my-recipient');
    });

    test('a kindless transport sends no kind field (wire shape unchanged)', async () => {
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'my-recipient',
            envelope: DIRECT_BYTES,
            kind: undefined,
        });
        const transport = new RelayTransport('ws://relay.test');
        await transport.pickupEnvelope('my-recipient');

        const ws = DestructiveRelayWebSocket.instances[0];
        const frame = ws.sent.find((r) => r.op === 'pickup_envelope');
        expect(frame).toBeDefined();
        expect('kind' in frame).toBe(false);
    });
});

describe('foreign envelope survives a destructive mailbox (the blocking regression)', () => {
    test('direct loop polls a group-only mailbox: group envelope is still retrievable by the group loop afterwards', async () => {
        // The group envelope is queued for the shared recipient; the DIRECT
        // loop is the one polling. Without the kind filter on the pickup op
        // the destructive mailbox hands the group envelope to the direct
        // transport and destroys it.
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'shared-recipient',
            envelope: GROUP_BYTES,
            kind: 'group',
        });

        const directTransport = new RelayTransport('ws://relay.test', 'direct');
        await expect(directTransport.pickupEnvelope('shared-recipient')).rejects.toThrow();

        // The foreign envelope was NOT destroyed: it is still queued…
        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(1);
        expect(Array.from(DestructiveRelayWebSocket.mailbox[0].envelope)).toEqual([
            ...GROUP_BYTES,
        ]);
        expect(DestructiveRelayWebSocket.mailbox[0].kind).toBe('group');

        // …and the OWNING loop still receives it afterwards.
        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const picked = await groupTransport.pickupEnvelope('shared-recipient');
        expect(Array.from(picked.envelope)).toEqual([...GROUP_BYTES]);
        expect(picked.kind).toBe('group');
        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(0);
    });

    test('group loop polls a direct-only mailbox: direct envelope is still retrievable by the direct loop afterwards', async () => {
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'shared-recipient',
            envelope: DIRECT_BYTES,
            kind: 'direct',
        });

        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        await expect(groupTransport.pickupEnvelope('shared-recipient')).rejects.toThrow();

        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(1);
        expect(Array.from(DestructiveRelayWebSocket.mailbox[0].envelope)).toEqual([
            ...DIRECT_BYTES,
        ]);
        expect(DestructiveRelayWebSocket.mailbox[0].kind).toBe('direct');

        const directTransport = new RelayTransport('ws://relay.test', 'direct');
        const picked = await directTransport.pickupEnvelope('shared-recipient');
        expect(Array.from(picked.envelope)).toEqual([...DIRECT_BYTES]);
        expect(picked.kind).toBe('direct');
        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(0);
    });

    test('an untagged envelope falls through to any filter and is consumed by the polling loop', async () => {
        // Missing kind = fall-through signal: the relay delivers it to
        // whichever loop polls, matching the relay's untagged-fall-through
        // policy (and the loops' fall-through decrypt policy).
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'shared-recipient',
            envelope: DIRECT_BYTES,
            kind: undefined,
        });

        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const picked = await groupTransport.pickupEnvelope('shared-recipient');
        expect(Array.from(picked.envelope)).toEqual([...DIRECT_BYTES]);
        expect(picked.kind).toBeUndefined();
        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(0);
    });

    test('own-kind envelope is dequeued destructively by the polling loop', async () => {
        DestructiveRelayWebSocket.mailbox.push({
            recipientId: 'shared-recipient',
            envelope: GROUP_BYTES,
            kind: 'group',
        });

        const groupTransport = new RelayTransport('ws://relay.test', 'group');
        const picked = await groupTransport.pickupEnvelope('shared-recipient');
        expect(Array.from(picked.envelope)).toEqual([...GROUP_BYTES]);
        expect(picked.kind).toBe('group');
        // Destructive: consumed, exactly once.
        expect(DestructiveRelayWebSocket.mailbox).toHaveLength(0);
    });
});