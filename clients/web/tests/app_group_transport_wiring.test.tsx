/** @vitest-environment jsdom */
//
// GRP-6 FIX 1 — the wiring-level test no other test can see.
//
// Every existing envelope_kind_* test constructs `RelayTransport` directly
// with a kind, so they all pass while the SHIPPED APP is still broken:
// App.tsx built the group transport as `new RelayTransport(relayUrl)` with NO
// kind, and injected it into GroupConversation, so the in-component default
// (`transport ?? new RelayTransport(getRelayWsUrl(), 'group')`) never fired.
// In the real app the group loop therefore sent untagged and picked up
// unfiltered — a direct envelope was accepted by the relay's untagged/None
// filter, destructively dequeued, then dropped by the group loop's skip.
// Destroyed, not deferred.
//
// This file renders the REAL <App /> (the real RelayTransport module is NOT
// mocked — only GroupConversation is, as a prop-recording stub, the same seam
// app_identity.test.tsx already uses) and asserts that the transport App
// hands the group view carries kind 'group' on the wire.

import '@testing-library/jest-dom';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';
import { describe, test, expect, vi, beforeEach } from 'vitest';

// App.tsx reads `globalThis.indexedDB` directly, so we must install
// fake-indexeddb on the global before any render.
(globalThis as any).indexedDB = fakeIndexedDB;

// ── WASM mock ───────────────────────────────────────────────────────────────
// The subset App imports transitively (same as app_identity.test.tsx).
const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

function makeKeypair() {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = Math.floor(Math.random() * 256);
    const pub = new Uint8Array(33);
    pub[0] = 5;
    for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
    return { priv, pub };
}

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        const kp = makeKeypair();
        keypairs.push(kp);
        return {
            public_bytes: () => kp.pub.slice(),
            private_bytes: () => kp.priv.slice(),
        };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        const match = keypairs.find((kp) => kp.priv.every((b, i) => b === bytes[i]));
        if (match) {
            return {
                public_bytes: () => match.pub.slice(),
                private_bytes: () => match.priv.slice(),
            };
        }
        const priv = bytes.slice();
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return { public_bytes: () => pub, private_bytes: () => priv };
    },
    generate_prekey_bundle: () => new Uint8Array([1, 2, 3, 4, 5]),
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => new Uint8Array([1, 2, 3, 4, 5]),
    derive_safety_number: () => '00000 00000',
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

// ── GroupConversation mock ──────────────────────────────────────────────────
// Stub that records the props it receives. App only passes the group
// transport when view === 'group', so the test clicks the "Group" nav button.
const groupPropsHolder: { props: any[] } = { props: [] };

vi.mock('../src/GroupConversation', () => ({
    GroupConversation: (props: any) => {
        groupPropsHolder.props.push(props);
        return null;
    },
}));

// ── Storage key mock ────────────────────────────────────────────────────────
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => null,
}));

// NOTE: ../src/relay_transport is deliberately NOT mocked — the whole point
// is to capture the REAL transport instance App constructs and prove it sends
// the 'group' kind on the wire.

import App from '../src/App';

// ── Fake relay WebSocket ────────────────────────────────────────────────────

function b64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
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

/**
 * Fake relay socket: answers `challenge` with a difficulty-0 wire (hash-wasm
 * solves on the first candidate — the same trick
 * envelope_kind_routing_destructive.test.tsx uses) and `pickup_envelope` with
 * NotFound so a poll terminates without delivering anything. Records every
 * sent frame.
 */
class WiringTestWebSocket {
    static instances: WiringTestWebSocket[] = [];
    static sent: any[] = [];

    // jsdom's WebSocket has `OPEN = 1` as a static; the transport compares
    // `this.ws.readyState === WebSocket.OPEN`, so the fake must expose it too.
    static OPEN = 1;

    readyState = 1;
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: string }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;

    constructor(public url: string) {
        WiringTestWebSocket.instances.push(this);
        queueMicrotask(() => this.onopen?.());
    }

    send(data: string) {
        const req = JSON.parse(data);
        WiringTestWebSocket.sent.push(req);
        let resp: any;
        if (req.op === 'challenge') {
            resp = { ok: true, challenge: trivialChallenge(), challenge_id: 'cid' };
        } else if (req.op === 'pickup_envelope') {
            resp = { ok: false, error: 'NotFound' };
        } else {
            resp = { ok: true };
        }
        queueMicrotask(() => this.onmessage?.({ data: JSON.stringify(resp) }));
    }

    close() {}
}

beforeEach(() => {
    keypairs.length = 0;
    groupPropsHolder.props.length = 0;
    WiringTestWebSocket.instances = [];
    WiringTestWebSocket.sent = [];
    (globalThis as any).WebSocket = WiringTestWebSocket;

    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    }
});

describe('App wires the group view a kind-tagged transport', () => {
    test('the transport App hands GroupConversation sends kind "group" on pickup', async () => {
        render(<App />);

        // Wait for the identity to load and the nav to be interactive.
        await waitFor(() => {
            expect(screen.getByRole('button', { name: 'Group' })).toBeInTheDocument();
        });

        // App passes the group transport only when view === 'group'.
        fireEvent.click(screen.getByRole('button', { name: 'Group' }));

        await waitFor(() => {
            expect(groupPropsHolder.props.length).toBeGreaterThan(0);
        });
        const props = groupPropsHolder.props[groupPropsHolder.props.length - 1];
        const transport = props.transport;
        expect(transport).toBeDefined();

        // Drive the REAL transport: a pickup must go out on the wire tagged
        // with the group loop's kind. The fake relay answers NotFound, which
        // the transport surfaces as a rejection — that is fine; the assertion
        // is on the SENT frame, so swallow the error.
        await transport.pickupEnvelope('wiring-recipient').catch(() => {});

        const frame = WiringTestWebSocket.sent.find((r) => r.op === 'pickup_envelope');
        expect(frame).toBeDefined();
        expect(frame.recipient_id).toBe('wiring-recipient');
        expect(frame.kind).toBe('group');
    });
});