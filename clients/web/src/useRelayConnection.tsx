import React, { useCallback, useEffect, useState } from 'react';
import { RelayTransport } from './relay_transport';
import { publishPrekeyForIdentity, type PersistedIdentity } from './identity';
import type { StorageGate } from './storage';
import type { SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';

// Relay connection UX for the web client.
//
// Publishing a prekey bundle to the relay is what makes a user addressable:
// until it succeeds, peers cannot reach them. The previous App flow attempted
// the publish exactly once and, on failure, rendered a permanent
// "Prekey publish failed: <raw error>" banner. That was both alarming (a raw
// transport error as the headline) and brittle (a relay started a moment after
// page load left the user unreachable until a full reload).
//
// This module replaces that with a retry-with-backoff loop and three human
// states — Connecting / Connected / Unreachable — plus an in-app relay URL
// field so the endpoint can be changed at runtime without a console.
//
// `publishPrekeyForIdentity` (in identity.ts) is left untouched: it still
// throws on failure. The retry/backoff lives here, around it.

export type RelayStatus = 'connecting' | 'connected' | 'unreachable';

// Backoff schedule for the initial burst of attempts after the first one.
// Small and short: this is about tolerating a relay that is still starting up
// or a brief network blip, not about rate-limiting a hostile endpoint. After
// the burst is exhausted we keep trying on a slower cadence so a relay that
// comes up later is picked up without a reload.
export const INITIAL_BACKOFF_MS: readonly number[] = [100, 200, 400];
export const PERIODIC_RETRY_MS = 2000;
const INITIAL_ATTEMPTS = 1 + INITIAL_BACKOFF_MS.length; // first try + retries

/** A relay URL must be a ws:// or wss:// URL with a non-empty host portion. */
export function isValidRelayUrl(url: string): boolean {
    return /^wss?:\/\/.+/i.test(url.trim());
}

/** Clears the reload-warning flag WarningBanner reads, wherever a session is dropped or never held. */
function clearSessionActiveFlag(): void {
    if (typeof window !== 'undefined') {
        localStorage.removeItem('session_active');
    }
}

export interface UseRelayConnectionResult {
    status: RelayStatus;
    /** Raw technical error from the last failed attempt (for the details toggle). */
    error: string | null;
    /** The relay URL currently in use (what the transport was constructed with). */
    resolvedUrl: string;
    /** Receiver session from a successful publish — handed to Conversation's receive loop. */
    receiverSession: InstanceType<typeof SessionHandle> | null;
    /** Force a fresh burst of attempts immediately. */
    retry: () => void;
}

/**
 * Drives the prekey-publish flow against a relay with retry/backoff and exposes
 * a coarse connection status.
 *
 * Cancels cleanly on unmount or when the relay URL / identity / retry token
 * changes, so there are never overlapping retry loops and no state updates
 * after unmount. Errors from `publishPrekeyForIdentity` are caught here (the
 * loop must not surface an unhandled rejection).
 *
 * An optional `sessionGate` is forwarded to `publishPrekeyForIdentity` so the
 * receiver session is restored from (and re-persisted to) the encrypted store
 * instead of being recreated on every load. The gate is supplied by the caller
 * (App) — this hook never constructs one, so it stays renderable without
 * IndexedDB.
 */
export function useRelayConnection(
    identity: PersistedIdentity | null,
    relayUrl: string,
    sessionGate?: StorageGate,
): UseRelayConnectionResult {
    const [status, setStatus] = useState<RelayStatus>('connecting');
    const [error, setError] = useState<string | null>(null);
    const [receiverSession, setReceiverSession] =
        useState<InstanceType<typeof SessionHandle> | null>(null);
    // Bumped by retry() to retrigger the effect and start a fresh burst.
    const [retryCount, setRetryCount] = useState(0);

    const recipientId = identity?.recipientId ?? null;

    useEffect(() => {
        if (!identity) return;
        // A new effect run means the URL/identity/retry token changed: drop any
        // receiver session from a previous relay so Conversation doesn't keep
        // decrypting with a session whose bundle was published to a different
        // (or now-unreachable) relay. It is repopulated on the next success.
        setReceiverSession(null);
        clearSessionActiveFlag();
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout> | null = null;
        let transport: RelayTransport | null = null;
        let attemptIdx = 0;

        const scheduleNext = (delay: number) => {
            timer = setTimeout(() => {
                void tick();
            }, delay);
        };

        const tick = async () => {
            if (cancelled) return;
            if (!transport) transport = new RelayTransport(relayUrl);

            // Only flip to "connecting" during the initial burst. During the
            // periodic retries we leave an "unreachable" status in place so the
            // UI does not flicker between attempts; it flips to "connected" on
            // the first success.
            if (attemptIdx < INITIAL_ATTEMPTS) setStatus('connecting');

            try {
                const session = await publishPrekeyForIdentity(identity, transport, sessionGate);
                if (cancelled) return;
                setReceiverSession(session);
                // Persist a flag so WarningBanner can warn that reloading loses
                // this session; cleared by clearSessionActiveFlag() wherever the
                // session is dropped (effect re-entry, unreachable, unmount).
                if (typeof window !== 'undefined') {
                    localStorage.setItem('session_active', 'true');
                }
                setStatus('connected');
                setError(null);
                return;
            } catch (err) {
                if (cancelled) return;
                setError(err instanceof Error ? err.message : String(err));
                attemptIdx++;
                if (attemptIdx < INITIAL_ATTEMPTS) {
                    scheduleNext(INITIAL_BACKOFF_MS[attemptIdx - 1] ?? PERIODIC_RETRY_MS);
                } else {
                    setStatus('unreachable');
                    clearSessionActiveFlag();
                    scheduleNext(PERIODIC_RETRY_MS);
                }
            }
        };

        void tick();

        return () => {
            cancelled = true;
            clearSessionActiveFlag();
            if (timer) clearTimeout(timer);
            if (transport) {
                try {
                    transport.close();
                } catch {
                    // Already closed or never connected — nothing to do.
                }
            }
        };
        // identity is included because the effect closes over it; it is set
        // once (null → loaded) and then stable, so this does not cause loops.
        // sessionGate is included so a gate that arrives after the first render
        // (App opens storage asynchronously) is picked up rather than left stale.
    }, [recipientId, relayUrl, retryCount, identity, sessionGate]);

    const retry = useCallback(() => setRetryCount((n) => n + 1), []);

    return { status, error, resolvedUrl: relayUrl, receiverSession, retry };
}

// ── Presentational panel ────────────────────────────────────────────────────

interface RelayConnectionPanelProps {
    status: RelayStatus;
    error: string | null;
    resolvedUrl: string;
    /** Current relay URL (the input's initial value; re-synced when it changes). */
    relayUrl: string;
    onRelayUrlChange: (url: string) => void;
    onRetry: () => void;
}

/**
 * Rail widget: a human relay-connection status, the raw error behind a
 * details toggle, and an editable relay URL field with validation.
 *
 * Pure/presentational — all retry/reconnect logic lives in the hook and is
 * wired through onRetry / onRelayUrlChange by the parent.
 */
export function RelayConnectionPanel({
    status,
    error,
    resolvedUrl,
    relayUrl,
    onRelayUrlChange,
    onRetry,
}: RelayConnectionPanelProps) {
    const [inputValue, setInputValue] = useState(relayUrl);
    const [validationError, setValidationError] = useState<string | null>(null);
    const [warning, setWarning] = useState<string | null>(null);
    const [detailsOpen, setDetailsOpen] = useState(false);

    // Keep the field in sync when the resolved URL changes externally (e.g.
    // after an empty-input reset falls back to the default).
    useEffect(() => {
        setInputValue(relayUrl);
    }, [relayUrl]);

    const apply = (e?: React.FormEvent) => {
        e?.preventDefault();
        const trimmed = inputValue.trim();
        if (trimmed === '') {
            // Empty = reset to the default resolved URL (handled by the parent,
            // which clears the localStorage override).
            setValidationError(null);
            onRelayUrlChange('');
            return;
        }
        if (!isValidRelayUrl(trimmed)) {
            setValidationError('Invalid relay URL — must start with ws:// or wss://');
            return;
        }
        setValidationError(null);
        // Parse URL for advisory warning
        let parsedUrl: URL | null = null;
        if (trimmed !== '' && isValidRelayUrl(trimmed)) {
            try {
                parsedUrl = new URL(trimmed);
            } catch {
                /* should not happen due to validation */
            }
        }

        // Determine warning: unencrypted ws:// to non-localhost host
        if (parsedUrl && parsedUrl.protocol === 'ws:' && !['localhost', '127.0.0.1', '::1'].includes(parsedUrl.hostname.toLowerCase())) {
            setWarning('Unencrypted relay connection to non-localhost host may expose metadata');
        } else {
            setWarning(null);
        }

        onRelayUrlChange(trimmed);
    };

    return (
        <div className="rail-relay">
            <div className={`rail-relay-status rail-relay-status--${status}`}>
                {status === 'connecting' && (
                    <span role="status" className="rail-relay-indicator">
                        Connecting to relay…
                    </span>
                )}
                {status === 'connected' && (
                    <span role="status" className="rail-relay-indicator">
                        <span className="rail-relay-dot" aria-hidden="true" />
                        Relay connected
                    </span>
                )}
                {status === 'unreachable' && (
                    <>
                        <span role="alert" className="rail-relay-indicator">
                            Can&apos;t reach relay
                        </span>
                        <button
                            type="button"
                            className="rail-relay-retry"
                            onClick={onRetry}
                        >
                            Retry
                        </button>
                        {error && (
                            <div className="rail-relay-details">
                                <button
                                    type="button"
                                    className="rail-relay-details-toggle"
                                    aria-expanded={detailsOpen}
                                    onClick={() => setDetailsOpen((v) => !v)}
                                >
                                    Details
                                </button>
                                {detailsOpen && (
                                    <pre className="rail-relay-error-detail">{error}</pre>
                                )}
                            </div>
                        )}
                    </>
                )}
            </div>

            <form className="rail-relay-field" onSubmit={apply}>
                <label className="rail-relay-field-label" htmlFor="rail-relay-url-input">
                    Relay URL
                </label>
                <input
                    id="rail-relay-url-input"
                    aria-label="Relay URL"
                    className="rail-relay-field-input"
                    type="text"
                    spellCheck={false}
                    autoComplete="off"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                />
                <button type="submit" className="rail-relay-field-apply">
                    Apply
                </button>
            </form>
            {validationError && (
                <div className="rail-relay-validation" role="alert">
                    {validationError}
                </div>
            )}
            {warning && (
                <div className="rail-relay-warning" role="status">
                    {warning}
                </div>
            )}
            <div className="rail-relay-resolved" title="Resolved relay URL in use">
                {resolvedUrl}
            </div>
        </div>
    );
}
