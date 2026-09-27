// @vitest-environment jsdom
//
// Relay connection UX: the prekey publish flow now retries with backoff and
// exposes Connecting / Connected / Unreachable states, plus an in-app relay
// URL field. This file tests the `useRelayConnection` hook (retry schedule,
// status transitions, auto-recover, cancel-and-restart on URL/retry change),
// the `isValidRelayUrl` validator, and the `RelayConnectionPanel` UI
// (status text, details toggle, relay URL field + validation, retry button).
//
// The WASM-backed identity work and the WebSocket transport are mocked at the
// boundary — `publishPrekeyForIdentity` is a spy and `RelayTransport` is a
// stub — so no built pkg/ or live relay is required.

import '@testing-library/jest-dom';
import { render, screen, fireEvent, act } from '@testing-library/react';
import React from 'react';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Transport + identity boundary mocks ──────────────────────────────────────
//
// `publishPrekeyForIdentity` is the only identity surface the hook calls; we
// make it a controllable spy via a holder (the vi.mock factory is hoisted).
// `RelayTransport` is a constructor stub that records its URL arg and returns
// an instance with a no-op close().

const publishHolder: { fn: ReturnType<typeof vi.fn> } = { fn: vi.fn() };
const TransportMock = vi.fn().mockImplementation(function (this: any) {
    return { close() { /* no-op for tests */ } };
});

vi.mock('../src/identity', () => ({
    publishPrekeyForIdentity: (...args: unknown[]) => publishHolder.fn(...args),
}));
vi.mock('../src/relay_transport', () => ({
    RelayTransport: function (...args: unknown[]) {
        return TransportMock(...args);
    },
    getRelayWsUrl: () => 'ws://localhost:8000',
}));

import {
    useRelayConnection,
    isValidRelayUrl,
    RelayConnectionPanel,
    INITIAL_BACKOFF_MS,
    PERIODIC_RETRY_MS,
} from '../src/useRelayConnection';

const fakeIdentity = { recipientId: 'testrecipient' } as any;

// ── Hook test harness ────────────────────────────────────────────────────────
//
// Renders the hook's output as plain text so we can assert status / error /
// resolved URL / session without coupling to the panel's markup.

function HookHarness({ relayUrl }: { relayUrl: string }) {
    const conn = useRelayConnection(fakeIdentity, relayUrl);
    return (
        <div>
            <span data-testid="status">{conn.status}</span>
            <span data-testid="error">{conn.error ?? ''}</span>
            <span data-testid="url">{conn.resolvedUrl}</span>
            <span data-testid="session">{conn.receiverSession ? 'yes' : 'no'}</span>
            <button type="button" onClick={() => conn.retry()}>retry</button>
        </div>
    );
}

const status = () => screen.getByTestId('status').textContent;

describe('isValidRelayUrl', () => {
    test.each([
        ['ws://localhost:8000', true],
        ['wss://relay.example.com:8000', true],
        ['  ws://relay.example.com  ', true], // trimmed
        ['http://localhost:8000', false], // not ws/wss
        ['not a url', false],
        ['', false],
        ['ws://', false], // no host
    ])('isValidRelayUrl(%j) === %s', (input, expected) => {
        expect(isValidRelayUrl(input)).toBe(expected);
    });
});

describe('useRelayConnection', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        TransportMock.mockClear();
    });
    afterEach(() => {
        vi.useRealTimers();
    });

    test('success transitions to connected and exposes the receiver session', async () => {
        publishHolder.fn = vi.fn().mockResolvedValue({ _mock: 'session' });
        render(<HookHarness relayUrl="ws://relay.example:8000" />);

        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        expect(status()).toBe('connected');
        expect(screen.getByTestId('session').textContent).toBe('yes');
        expect(screen.getByTestId('error').textContent).toBe('');
        // One attempt only on success — no retry storm.
        expect(publishHolder.fn).toHaveBeenCalledTimes(1);
    });

    test('resolved URL reflects the relay URL in use', async () => {
        publishHolder.fn = vi.fn().mockResolvedValue({});
        render(<HookHarness relayUrl="ws://relay.example:9000" />);

        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        expect(screen.getByTestId('url').textContent).toBe('ws://relay.example:9000');
        // The transport is constructed with that URL.
        expect(TransportMock.mock.calls.at(-1)![0]).toBe('ws://relay.example:9000');
    });

    test('persistent failure exhausts the initial burst then reports unreachable', async () => {
        publishHolder.fn = vi.fn().mockRejectedValue(new Error('relay unreachable'));

        render(<HookHarness relayUrl="ws://relay.example:8000" />);

        // Initial burst = 1 + INITIAL_BACKOFF_MS.length attempts.
        const burstDelay = INITIAL_BACKOFF_MS.reduce((a, b) => a + b, 0);
        await act(async () => { await vi.advanceTimersByTimeAsync(burstDelay + 100); });

        expect(status()).toBe('unreachable');
        expect(screen.getByTestId('error').textContent).toBe('relay unreachable');
        expect(publishHolder.fn).toHaveBeenCalledTimes(1 + INITIAL_BACKOFF_MS.length);
    });

    test('a relay that becomes reachable auto-recovers via periodic retry', async () => {
        // Fail every initial-burst attempt, then succeed on the next periodic retry.
        let calls = 0;
        publishHolder.fn = vi.fn().mockImplementation(() => {
            calls++;
            if (calls <= 1 + INITIAL_BACKOFF_MS.length) {
                return Promise.reject(new Error('relay unreachable'));
            }
            return Promise.resolve({ _mock: 'session' });
        });

        render(<HookHarness relayUrl="ws://relay.example:8000" />);

        const burstDelay = INITIAL_BACKOFF_MS.reduce((a, b) => a + b, 0);
        await act(async () => { await vi.advanceTimersByTimeAsync(burstDelay + 100); });
        expect(status()).toBe('unreachable');

        // Advance one periodic interval — the relay is now reachable.
        await act(async () => { await vi.advanceTimersByTimeAsync(PERIODIC_RETRY_MS); });
        expect(status()).toBe('connected');
        expect(screen.getByTestId('session').textContent).toBe('yes');
    });

    test('retry() forces a fresh burst immediately', async () => {
        publishHolder.fn = vi.fn().mockRejectedValue(new Error('relay unreachable'));
        render(<HookHarness relayUrl="ws://relay.example:8000" />);

        const burstDelay = INITIAL_BACKOFF_MS.reduce((a, b) => a + b, 0);
        await act(async () => { await vi.advanceTimersByTimeAsync(burstDelay + 100); });
        expect(status()).toBe('unreachable');

        // Now make the relay reachable and force a retry.
        publishHolder.fn = vi.fn().mockResolvedValue({ _mock: 'session' });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: 'retry' }));
            await vi.advanceTimersByTimeAsync(0);
        });

        expect(status()).toBe('connected');
    });

    test('changing the relay URL cancels the current loop and restarts with the new URL', async () => {
        publishHolder.fn = vi.fn().mockResolvedValue({});
        const { rerender } = render(<HookHarness relayUrl="ws://one.example:8000" />);
        await act(async () => { await vi.advanceTimersByTimeAsync(0); });
        expect(TransportMock.mock.calls.at(-1)![0]).toBe('ws://one.example:8000');

        rerender(<HookHarness relayUrl="ws://two.example:8000" />);
        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        expect(TransportMock.mock.calls.at(-1)![0]).toBe('ws://two.example:8000');
        // Restarted attempt succeeded against the new URL.
        expect(status()).toBe('connected');
    });

    test('unmount during an in-flight publish does not update state or warn', async () => {
        // Attempt that stays pending so we can unmount mid-flight, then
        // resolve it after unmount to prove the cancelled guard holds.
        let resolvePublish: () => void = () => {};
        publishHolder.fn = vi.fn().mockImplementation(
            () => new Promise((res) => { resolvePublish = res as () => void; }),
        );
        const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const { unmount } = render(<HookHarness relayUrl="ws://relay.example:8000" />);
        await act(async () => { await vi.advanceTimersByTimeAsync(0); });

        unmount();

        // Resolving after unmount must not schedule a state update.
        await act(async () => {
            resolvePublish();
            await vi.advanceTimersByTimeAsync(1000);
        });

        // No React act() warning leaked through console.error.
        const actWarning = spy.mock.calls.find((c) => /act/i.test(String(c[0])));
        expect(actWarning).toBeUndefined();
        // The component is gone — no leftover status node.
        expect(screen.queryByTestId('status')).not.toBeInTheDocument();
        spy.mockRestore();
    });

});

// ── Panel (presentational) ───────────────────────────────────────────────────

describe('RelayConnectionPanel', () => {
    test('connecting state renders a neutral status, not an alert', () => {
        render(
            <RelayConnectionPanel
                status="connecting" error={null} resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={() => {}} onRetry={() => {}}
            />,
        );
        expect(screen.getByText(/connecting to relay/i)).toBeInTheDocument();
        expect(screen.getByRole('status')).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('connected state renders a success indicator', () => {
        render(
            <RelayConnectionPanel
                status="connected" error={null} resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={() => {}} onRetry={() => {}}
            />,
        );
        expect(screen.getByText(/relay connected/i)).toBeInTheDocument();
    });

    test('unreachable state renders an alert, a Retry button, and the raw error behind Details', async () => {
        render(
            <RelayConnectionPanel
                status="unreachable" error="relay unreachable" resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={() => {}} onRetry={() => {}}
            />,
        );
        expect(screen.getByText(/can't reach relay/i)).toBeInTheDocument();
        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();

        // Raw error is not the headline — it is hidden until Details is toggled.
        expect(screen.queryByText('relay unreachable')).not.toBeInTheDocument();
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /details/i }));
        });
        expect(screen.getByText('relay unreachable')).toBeInTheDocument();
    });

    test('applying a valid ws URL calls onRelayUrlChange and shows no validation error', async () => {
        const onRelayUrlChange = vi.fn();
        render(
            <RelayConnectionPanel
                status="connecting" error={null} resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={onRelayUrlChange} onRetry={() => {}}
            />,
        );
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: 'ws://new-relay:8000' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(onRelayUrlChange).toHaveBeenCalledWith('ws://new-relay:8000');
        expect(screen.queryByText(/invalid relay url/i)).not.toBeInTheDocument();
    });

    test('applying an invalid (non-ws) URL shows a validation error and does not call onRelayUrlChange', async () => {
        const onRelayUrlChange = vi.fn();
        render(
            <RelayConnectionPanel
                status="connecting" error={null} resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={onRelayUrlChange} onRetry={() => {}}
            />,
        );
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: 'http://not-ws' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(screen.getByText(/invalid relay url/i)).toBeInTheDocument();
        expect(onRelayUrlChange).not.toHaveBeenCalled();
    });

    test('applying an empty URL resets (calls onRelayUrlChange with "") without a validation error', async () => {
        const onRelayUrlChange = vi.fn();
        render(
            <RelayConnectionPanel
                status="connecting" error={null} resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={onRelayUrlChange} onRetry={() => {}}
            />,
        );
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: '' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(onRelayUrlChange).toHaveBeenCalledWith('');
        expect(screen.queryByText(/invalid relay url/i)).not.toBeInTheDocument();
    });

    test('Retry button calls onRetry', async () => {
        const onRetry = vi.fn();
        render(
            <RelayConnectionPanel
                status="unreachable" error="boom" resolvedUrl="ws://r:8000"
                relayUrl="ws://r:8000" onRelayUrlChange={() => {}} onRetry={onRetry}
            />,
        );
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /^retry$/i }));
        });
        expect(onRetry).toHaveBeenCalledTimes(1);
    });
});
