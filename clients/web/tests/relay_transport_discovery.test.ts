// @vitest-environment jsdom
//! Discovery publish/lookup on the relay transport (MD-8).
//!
//! Covers the two new ops added to `RelayTransport`:
//!   - `publishDiscovery(recipientId, blob)` — challenge + PoW, then
//!     `publish_discovery` with `recipient_id`, `discovery` (base64),
//!     `challenge_id`, `pow_solution`.
//!   - `lookupDiscovery(recipientId)` — `lookup_discovery`, decoding
//!     `resp.bundle`; `null` for the relay's NotFound/Expired errors, any
//!     other relay error rejects, and a missing bundle on an ok response
//!     throws a `RelayError`.
//!
//! The fake WebSocket mirrors the one in `relay_transport.test.ts`: the
//! transport opens its socket lazily on the first op, so each test starts an
//! op, waits for the instance, then opens it.

import '@testing-library/jest-dom';
import { vi, describe, test, expect, beforeEach } from 'vitest';

// ── Mock WebSocket ──────────────────────────────────────────────────────────

interface MockWsInstance {
    url: string;
    readyState: number;
    onopen: ((ev: Event) => void) | null;
    onmessage: ((ev: MessageEvent) => void) | null;
    onerror: ((ev: Event) => void) | null;
    onclose: ((ev: CloseEvent) => void) | null;
    sent: string[];
    send(data: string): void;
    close(): void;
    _open(): void;
    _message(data: string): void;
    _error(): void;
    _close(): void;
}

class MockWebSocket {
    static instances: MockWebSocket[] = [];
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    url: string;
    readyState = 0; // CONNECTING
    onopen: ((ev: Event) => void) | null = null;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    onerror: ((ev: Event) => void) | null = null;
    onclose: ((ev: CloseEvent) => void) | null = null;
    sent: string[] = [];

    static CLEAR() { MockWebSocket.instances = []; }

    constructor(url: string) {
        this.url = url;
        MockWebSocket.instances.push(this);
    }
    send(data: string) { this.sent.push(data); }
    close() { this.readyState = 3; }

    _open() {
        this.readyState = 1;
        if (this.onopen) this.onopen(new Event('open'));
    }
    _message(data: string) {
        if (this.onmessage) this.onmessage(new MessageEvent('message', { data }));
    }
    _error() {
        this.readyState = 3;
        if (this.onerror) this.onerror(new Event('error'));
    }
    _close() {
        this.readyState = 3;
        if (this.onclose) this.onclose(new CloseEvent('close'));
    }
}

function lastWs(): MockWebSocket {
    const inst = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    if (!inst) throw new Error('no WebSocket instance created');
    return inst;
}

/** Wait for the transport to create a WebSocket, then return it and open it. */
async function connectAndOpen(): Promise<MockWebSocket> {
    await vi.waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1));
    const ws = lastWs();
    ws._open();
    return ws;
}

// Install the mock before importing the module under test.
(globalThis as any).WebSocket = MockWebSocket;

import { RelayTransport, RelayError } from '../src/relay_transport';

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Build a valid challenge wire (context_len BE || context || nonce(16) || difficulty BE). */
function makeChallengeWire(context: Uint8Array, nonce: Uint8Array, difficulty: number): Uint8Array {
    const len = context.length;
    const wire = new Uint8Array(2 + len + 16 + 4);
    const dv = new DataView(wire.buffer);
    dv.setUint16(0, len, false);
    wire.set(context, 2);
    wire.set(nonce, 2 + len);
    dv.setUint32(2 + len + 16, difficulty, false);
    return wire;
}

function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Answer the transport's `challenge` op with a low-difficulty challenge so the
 * PoW solve stays fast (the relay's real difficulty is 20 bits).
 */
function answerChallenge(ws: MockWebSocket, challengeId: string, nonceFill = 7): void {
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16).fill(nonceFill);
    const wire = makeChallengeWire(context, nonce, 4);
    ws._message(JSON.stringify({
        ok: true,
        challenge: bytesToBase64(wire),
        challenge_id: challengeId,
    }));
}

// ── publishDiscovery ───────────────────────────────────────────────────────

describe('publishDiscovery', () => {
    beforeEach(() => {
        localStorage.clear();
        MockWebSocket.CLEAR();
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
    });

    test('sends op publish_discovery with the base64 payload and PoW fields', async () => {
        const transport = new RelayTransport();
        const blob = new Uint8Array([0, 1, 2, 250, 255, 42]);
        const publishPromise = transport.publishDiscovery('bob', blob);

        const ws = await connectAndOpen();

        // First frame: the challenge request for the same recipient.
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'challenge', recipient_id: 'bob' });

        answerChallenge(ws, 'challenge-1');

        // Second frame: the publish_discovery op.
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(2));
        const sent = JSON.parse(ws.sent[1]);
        expect(sent.op).toBe('publish_discovery');
        expect(sent.recipient_id).toBe('bob');
        expect(sent.challenge_id).toBe('challenge-1');
        // The blob round-trips byte-for-byte through base64.
        expect(Array.from(base64ToBytes(sent.discovery))).toEqual(Array.from(blob));
        // pow_solution is base64 of the 8-byte u64 LE counter.
        expect(base64ToBytes(sent.pow_solution).length).toBe(8);

        ws._message(JSON.stringify({ ok: true }));
        await expect(publishPromise).resolves.toBeUndefined();
        transport.close();
    }, 15000);

    test('rejects with RelayError when the relay refuses the publish', async () => {
        const transport = new RelayTransport();
        const publishPromise = transport.publishDiscovery('bob', new Uint8Array([9]));

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        answerChallenge(ws, 'challenge-2');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(2));
        ws._message(JSON.stringify({ ok: false, error: 'DiscoveryTooLarge' }));

        await expect(publishPromise).rejects.toBeInstanceOf(RelayError);
        await expect(publishPromise).rejects.toThrow('DiscoveryTooLarge');
        transport.close();
    }, 15000);

    test('rejects when the challenge itself is refused (no publish frame sent)', async () => {
        const transport = new RelayTransport();
        const publishPromise = transport.publishDiscovery('bob', new Uint8Array([1]));

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'RateLimitExceeded' }));

        await expect(publishPromise).rejects.toBeInstanceOf(RelayError);
        await expect(publishPromise).rejects.toThrow('RateLimitExceeded');
        expect(ws.sent.length).toBe(1);
        transport.close();
    }, 15000);
});

// ── lookupDiscovery ────────────────────────────────────────────────────────

describe('lookupDiscovery', () => {
    beforeEach(() => {
        localStorage.clear();
        MockWebSocket.CLEAR();
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
    });

    test('sends op lookup_discovery and decodes the returned bytes', async () => {
        const transport = new RelayTransport();
        const blob = new Uint8Array([7, 0, 128, 255, 3]);
        const lookupPromise = transport.lookupDiscovery('alice');

        const ws = await connectAndOpen();

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'lookup_discovery', recipient_id: 'alice' });

        ws._message(JSON.stringify({ ok: true, bundle: bytesToBase64(blob) }));

        const got = await lookupPromise;
        expect(got).toBeInstanceOf(Uint8Array);
        expect(Array.from(got as Uint8Array)).toEqual(Array.from(blob));
        transport.close();
    }, 15000);

    test('returns null when the relay reports NotFound', async () => {
        const transport = new RelayTransport();
        const lookupPromise = transport.lookupDiscovery('nobody');

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'NotFound' }));

        await expect(lookupPromise).resolves.toBeNull();
        transport.close();
    }, 15000);

    test('returns null when the relay reports Expired', async () => {
        const transport = new RelayTransport();
        const lookupPromise = transport.lookupDiscovery('stale');

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'Expired' }));

        await expect(lookupPromise).resolves.toBeNull();
        transport.close();
    }, 15000);

    test('rejects with RelayError on any other relay error', async () => {
        const transport = new RelayTransport();
        const lookupPromise = transport.lookupDiscovery('alice');

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'RateLimitExceeded' }));

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        await expect(lookupPromise).rejects.toThrow('RateLimitExceeded');
        transport.close();
    }, 15000);

    test('throws RelayError when an ok response carries no bundle', async () => {
        const transport = new RelayTransport();
        const lookupPromise = transport.lookupDiscovery('alice');

        const ws = await connectAndOpen();
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: true }));

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        await expect(lookupPromise).rejects.toThrow(/missing bundle/);
        transport.close();
    }, 15000);
});
