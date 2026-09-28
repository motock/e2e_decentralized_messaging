/** @vitest-environment jsdom */
//
// TDD tests for the out-of-band envelope-kind plumbing in relay_transport.ts.
//
// CONTRACT UNDER TEST:
//   * `new RelayTransport(url, kind)` — the transport is told which kind of
//     envelope it owns ("direct" | "group"). The kind is NOT a per-call
//     argument, so `sendEnvelope(recipientId, envelope)` keeps its existing
//     2-argument shape and keeps receiving PURE ciphertext.
//   * `sendEnvelope` puts the kind on the op as a SIBLING JSON FIELD of
//     `envelope` — never inside the ciphertext bytes.
//   * `pickupEnvelope` surfaces the kind that came back on the op, so the
//     receive loop can route before attempting a decrypt. It resolves to
//     `{ envelope: Uint8Array; kind?: string }`.

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

class MockWebSocket {
    static OPEN = 1;
    static instances: MockWebSocket[] = [];
    readyState = 1;
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: string }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    sent: any[] = [];

    constructor(public url: string) {
        MockWebSocket.instances.push(this);
        queueMicrotask(() => this.onopen?.());
    }

    send(data: string) {
        const req = JSON.parse(data);
        this.sent.push(req);
        let resp: any;
        if (req.op === 'challenge') {
            resp = { ok: true, challenge: trivialChallenge(), challenge_id: 'cid' };
        } else if (req.op === 'pickup_envelope') {
            resp = { ok: true, envelope: b64(new Uint8Array([7, 7, 7])), kind: 'group' };
        } else {
            resp = { ok: true };
        }
        queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(resp) }));
    }

    close() {}
}

beforeEach(() => {
    MockWebSocket.instances = [];
    (globalThis as any).WebSocket = MockWebSocket;
});

describe('RelayTransport out-of-band envelope kind', () => {
    test('sendEnvelope carries the kind as a sibling field and keeps the payload pure ciphertext', async () => {
        const transport = new RelayTransport('ws://relay.test', 'group');
        const ciphertext = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

        await transport.sendEnvelope('peer-recipient', ciphertext);

        const ws = MockWebSocket.instances[0];
        const frame = ws.sent.find((r) => r.op === 'send_envelope');
        expect(frame).toBeDefined();
        expect(frame.kind).toBe('group');
        expect(frame.recipient_id).toBe('peer-recipient');
        // The ciphertext is byte-for-byte unchanged: the kind is NOT inside it.
        expect(Array.from(fromB64(frame.envelope))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    });

    test('pickupEnvelope surfaces the out-of-band kind from the op', async () => {
        const transport = new RelayTransport('ws://relay.test', 'group');

        const picked = await transport.pickupEnvelope('my-recipient');

        expect(picked.kind).toBe('group');
        expect(Array.from(picked.envelope)).toEqual([7, 7, 7]);
    });

    test('a relay response with no kind surfaces as a missing kind (fall-through signal)', async () => {
        const transport = new RelayTransport('ws://relay.test', 'direct');
        // Re-point the mock so pickup returns no kind at all.
        const original = MockWebSocket.prototype.send;
        MockWebSocket.prototype.send = function (this: MockWebSocket, data: string) {
            const req = JSON.parse(data);
            this.sent.push(req);
            const resp: any =
                req.op === 'challenge'
                    ? { ok: true, challenge: trivialChallenge(), challenge_id: 'cid' }
                    : { ok: true, envelope: b64(new Uint8Array([5, 5])) };
            queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(resp) }));
        };
        try {
            const picked = await transport.pickupEnvelope('my-recipient');
            expect(picked.kind).toBeUndefined();
            expect(Array.from(picked.envelope)).toEqual([5, 5]);
        } finally {
            MockWebSocket.prototype.send = original;
        }
    });
});
