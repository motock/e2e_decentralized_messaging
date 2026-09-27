// @vitest-environment jsdom
//
// NS-6B: `useRelayConnection` must forward an optional `StorageGate` to
// `publishPrekeyForIdentity` so the receiver session can be restored/persisted
// at startup. The gate is supplied by App (never constructed inside the hook),
// so the hook must pass it through unchanged — and pass `undefined` when none
// was supplied.
//
// The identity module and the WebSocket transport are mocked at the boundary
// (same harness pattern as tests/relay_connection.test.tsx); the hook itself is
// the code under test.

import '@testing-library/jest-dom';
import { render, screen, act } from '@testing-library/react';
import React from 'react';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Transport + identity boundary mocks ──────────────────────────────────────
//
// `publishPrekeyForIdentity` is the only identity surface the hook calls; a
// holder lets the hoisted vi.mock factory reach a per-test spy.

const publishHolder: { fn: ReturnType<typeof vi.fn<(...args: unknown[]) => unknown>> } = {
    fn: vi.fn(),
};

vi.mock('../src/identity', () => ({
    publishPrekeyForIdentity: (...args: unknown[]) => publishHolder.fn(...args),
}));
vi.mock('../src/relay_transport', () => ({
    RelayTransport: function () {
        return { close() { /* no-op for tests */ } };
    },
    getRelayWsUrl: () => 'ws://localhost:8000',
}));

import { useRelayConnection } from '../src/useRelayConnection';
import type { StorageGate } from '../src/storage';

const fakeIdentity = { recipientId: 'testrecipient' } as any;

/** A stand-in gate: the hook must forward it verbatim, never use it itself. */
const fakeGate = { get: vi.fn(), put: vi.fn() } as unknown as StorageGate;

// ── Hook test harness ────────────────────────────────────────────────────────

function HookHarness({ relayUrl, gate }: { relayUrl: string; gate?: StorageGate }) {
    const conn = useRelayConnection(fakeIdentity, relayUrl, gate);
    return <span data-testid="status">{conn.status}</span>;
}

beforeEach(() => {
    vi.useFakeTimers();
    publishHolder.fn = vi.fn().mockResolvedValue({ _mock: 'session' });
});

afterEach(() => {
    vi.useRealTimers();
});

describe('useRelayConnection session gate forwarding', () => {
    test('passes a supplied gate as the third argument to publishPrekeyForIdentity', async () => {
        render(<HookHarness relayUrl="ws://relay.example:8000" gate={fakeGate} />);

        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        expect(publishHolder.fn).toHaveBeenCalledTimes(1);
        expect(publishHolder.fn.mock.calls[0][2]).toBe(fakeGate);
    });

    test('passes undefined as the third argument when no gate is supplied', async () => {
        render(<HookHarness relayUrl="ws://relay.example:8000" />);

        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        expect(publishHolder.fn).toHaveBeenCalledTimes(1);
        expect(publishHolder.fn.mock.calls[0][2]).toBeUndefined();
    });
});
