import React, { useEffect, useRef, useState } from 'react';
import {
    establish_session_from_bundle,
    encrypt_message,
    decrypt_message,
    bundle_identity_key_bytes,
    fanout_establish,
    fanout_encrypt,
    FanoutDeviceInput,
    SessionHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { StorageGate, StoreName } from './storage';
import { getStorageKey } from './storage_key';
import {
    persistSessionRecord,
    restoreSessionRecord,
    senderRecordId,
    RECEIVER_RECORD_ID,
} from './session_persistence';
import { getRelayWsUrl, RelayTransport } from './relay_transport';
import type { PersistedIdentity } from './identity';
import './Conversation.css';

/**
 * DR-6: the recipient's verified device list, as injected into `App` (spec/v0.md §8.3).
 *
 * `identityKey` is the identity key the PRIMARY vouched for when it learned the
 * device — it is what reaches `fanout_establish` as `expected_identity_key_bytes`
 * and is deliberately independent of the key carried inside `bundleBytes` (the
 * device's published prekey bundle). The binding compares the two and rejects a
 * device whose bundle does not match the vouched-for key, so an
 * attacker-substituted bundle cannot silently redirect ciphertext.
 *
 * Device-list updates are MONOTONIC (spec/v0.md §8.4): an update whose version is
 * not newer than the one already held is ignored. `applyDeviceListUpdate` is pure —
 * it never mutates either argument.
 */

export interface DeviceListEntry {
    /** The recipient device's id, as scoped in the primary's signed device list. */
    deviceId: number;
    /** The identity key the primary vouched for — NOT the bundle's own key. */
    identityKey: Uint8Array;
    /** That device's published prekey bundle bytes. */
    bundleBytes: Uint8Array;
}

export interface DeviceList {
    /** Monotonic version of this list; only a strictly newer version replaces the held one. */
    version: number;
    devices: DeviceListEntry[];
}

/**
 * Monotonic device-list update (spec/v0.md §8.4).
 *
 * Returns `incoming` when no list is held yet, `current` when `incoming`'s
 * version is not newer than the held one, and `incoming` otherwise. The held
 * version only ever moves forward: a rejected update must not advance (or
 * rewind) the stored version, otherwise a later, still-stale update could
 * slip past the guard.
 */
export function applyDeviceListUpdate(
    current: DeviceList | null | undefined,
    incoming: DeviceList,
): DeviceList {
    if (current === null || current === undefined) return incoming;
    if (incoming.version <= current.version) return current;
    return incoming;
}

export interface Message {
    id: string;
    body: string;
    timestamp: number; // epoch ms
    sentByMe: boolean;
}

/**
 * The transport surface `Conversation` needs for session establishment and sending: look up a
 * peer's published prekey bundle, and hand off an encrypted envelope for delivery. `RelayTransport`
 * satisfies this; tests inject a mock that implements only this narrow interface so the crypto
 * boundary stays real while the network boundary is mocked.
 */
export interface ConversationTransport {
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
    sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void>;
    /**
     * Pick up a stored envelope addressed to `recipientId` (the local user's own
     * recipient ID). Returns the raw envelope bytes — a `Uint8Array` carrying
     * the envelope's out-of-band kind tag (GRP-6) as a non-enumerable `kind`
     * property (`"direct"` | `"group"`, or `undefined` when the relay sent no
     * tag: the "missing kind" fall-through signal). Rejects with an error whose
     * message is "NotFound" or "Expired" when the mailbox is empty — the receive
     * loop treats these as a normal empty poll, not an exceptional condition.
     *
     * The declared return type is the union the real transport can produce:
     * the bytes themselves, or a `{ envelope, kind? }` result. Callers
     * normalize with `picked instanceof Uint8Array ? picked : picked.envelope`
     * (the real transport self-aliases `envelope` on the bytes, so both arms
     * yield the same bytes).
     */
    pickupEnvelope(
        recipientId: string,
    ): Promise<Uint8Array | { envelope: Uint8Array; kind?: string }>;
}

export interface ConversationProps {
    /** The local persisted identity. Sending is blocked in the UI until this is available. */
    identity?: PersistedIdentity;
    /** Defaults to a real `RelayTransport`; tests inject a mock here. */
    transport?: ConversationTransport;
    /**
     * Called whenever the active peer's remote identity key becomes known (a session was just
     * established) or becomes unknown again (the peer changed and no session exists yet for the
     * new peer). The caller (App.tsx) uses this to feed the *real* remote key into
     * SafetyNumberVerification instead of a placeholder.
     */
    onRemoteIdentityKeyChange?: (peerId: string, remoteIdentityKey: Uint8Array | null) => void;
    /**
     * The receiver session whose prekey bundle was published to the relay.
     * In production, App.tsx creates this via `publishPrekeyForIdentity`
     * (which calls `create_receiver_session` + `publish_bundle_bytes`) and
     * passes it here so the receive loop decrypts with the same session that
     * published the bundle. Tests inject a session whose published bundle a
     * simulated peer has already encrypted to, mirroring the round-trip test
     * pattern from the prior story. This is NOT a parallel session store —
     * it is the single receiver-side session, supplied externally so the
     * publish and receive paths share key material.
     */
    receiverSession?: InstanceType<typeof SessionHandle>;
    /**
     * DR-6: the recipient's verified device list (spec/v0.md §8.3), injected by
     * App. When supplied and non-empty, a 1:1 send fans out — one envelope per
     * device, each addressed to `${peerId}:${deviceId}`. When absent or empty,
     * the send path is exactly the legacy single-recipient behaviour: one
     * envelope addressed to the bare peer id.
     */
    deviceList?: DeviceList;
}

// StoreName is a type, not a runtime object - 'messages' is a plain string
// literal that satisfies it. HISTORY_ID is the single record id this
// component uses within that store (the whole message history is one blob).
const MESSAGES_STORE: StoreName = 'messages';
const HISTORY_ID = 'history';

interface PeerSession {
    session: InstanceType<typeof SessionHandle>;
    remoteIdentityKey: Uint8Array;
}

/** Extract a WasmError's message, falling back to a generic description for non-WASM errors. */
function describeError(e: unknown): string {
    if (e && typeof e === 'object' && 'message' in e) {
        return String((e as { message: unknown }).message);
    }
    return e instanceof Error ? e.message : String(e);
}

/**
 * Merge the message history just read from storage with whatever is already in
 * memory. The stored ordering is authoritative; any in-memory message whose id
 * is not in the stored history — i.e. one that arrived while the load was in
 * flight — is appended after it. `stored` is null/undefined when the store has
 * never been written, in which case the in-memory messages are the whole history.
 */
function mergeHistory(stored: Message[] | null | undefined, prev: Message[]): Message[] {
    const base = stored ?? [];
    return [...base, ...prev.filter(p => !base.some(m => m.id === p.id))];
}

export const Conversation: React.FC<ConversationProps> = ({
    identity,
    transport,
    onRemoteIdentityKeyChange,
    receiverSession,
    deviceList,
}) => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [peerId, setPeerId] = useState('');
    const [input, setInput] = useState('');
    const [status, setStatus] = useState<string>('');
    const [sending, setSending] = useState(false);
    const [decryptionWarning, setDecryptionWarning] = useState<string>('');
    const [persistenceWarning, setPersistenceWarning] = useState<string | null>(null);
    const loadedRef = React.useRef(false);
    // Live sender-side sessions for the peers this component talks to, keyed by
    // peer id. A SessionHandle is serializable (session_to_bytes/session_from_bytes)
    // and its ratchet state is persisted through StorageGate, so this ref is an
    // in-memory cache over persisted state rather than the only copy of it.
    const sessionsRef = useRef<Map<string, PeerSession>>(new Map());
    // GRP-6: when no transport is injected (the App-level wiring was scoped out
    // of this story), build the default transport tagged with THIS loop's
    // envelope kind so outgoing envelopes carry the out-of-band "direct" tag and
    // the two receive loops stop consuming each other's mail. An injected
    // transport is used as-is (tests inject kindless mocks; a missing kind then
    // falls through to this loop's decrypt, which is the fail-closed policy).
    const transportRef = useRef<ConversationTransport>(
        transport ?? new RelayTransport(getRelayWsUrl(), 'direct'),
    );
    // Receiver-side session for decrypting inbound envelopes. Injected by the
    // caller (App.tsx) via the `receiverSession` prop — this is the SAME session
    // whose prekey bundle was published to the relay, so envelopes encrypted to
    // that bundle can be decrypted here. The component does NOT create its own
    // session, because that would be cryptographically distinct from the published
    // bundle. Its ratchet state is serializable and is persisted through
    // StorageGate after every successful decrypt, so a reload can restore it and
    // keep decrypting.
    const receiverSessionRef = useRef<InstanceType<typeof SessionHandle> | null>(null);
    // Mirror the `receiverSession` prop into a ref so the receive-loop effect (which
    // depends on `[identity]`, not `receiverSession`) always reads the latest value.
    // App.tsx sets `identity` first and `receiverSession` later (after the async prekey
    // publish completes); without this ref, the effect's closure would capture a stale
    // `receiverSession === undefined` and every poll would bail out early.
    const receiverSessionPropRef = useRef<InstanceType<typeof SessionHandle> | undefined>(undefined);
    receiverSessionPropRef.current = receiverSession;
    // Set of envelope byte-strings already processed, to dedup across polls (the relay
    // may return the same envelope on consecutive pickups until it's consumed).
    const seenEnvelopesRef = useRef<Set<string>>(new Set());
    // Guards against overlapping polls: if a pollOnce is still in flight when the
    // interval fires again, skip the new invocation rather than running two
    // concurrent pickups (which could double-process an envelope before dedup
    // sees it, or create unnecessary relay load).
    const pollInFlightRef = useRef<boolean>(false);
    // Lazily-created, single StorageGate used to persist the receiver session.
    // Created once per component instance (and opened) so every successful
    // decrypt reuses the same open gate instead of opening a new one per message.
    const sessionGateRef = useRef<StorageGate | null>(null);

    /**
     * Return this component instance's open StorageGate for session persistence,
     * creating and opening it on first use. Uses the same construction as the
     * message-history effects (global IndexedDB + the derived storage key).
     */
    const getSessionGate = async (): Promise<StorageGate> => {
        if (!sessionGateRef.current) {
            const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: getStorageKey() });
            await gate.open();
            sessionGateRef.current = gate;
        }
        return sessionGateRef.current;
    };

    // Load history from storage on mount. The load MERGES into whatever arrived
    // while it was in flight: the stored ordering is authoritative and any
    // in-memory message whose id is not in storage is appended, so an envelope
    // picked up during the read is neither dropped from the UI nor lost from
    // state. `loadedRef` is set BEFORE the state update so the persist effect can
    // never observe the merged render while its guard is still closed — that
    // render is what flushes the in-flight message to storage.
    useEffect(() => {
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: getStorageKey() });
        gate.open().then(async () => {
            try {
                // StorageGate.get already returns the parsed value (or null).
                const stored = await gate.get(MESSAGES_STORE, HISTORY_ID);
                loadedRef.current = true;
                setMessages(prev => mergeHistory(stored as Message[] | null, prev));
            } catch (e) {
                console.error('storage load error', e);
            }
        }).catch(err => console.error('storage init failed', err));
    }, []);

    // Persist messages whenever they change
    useEffect(() => {
        if (!loadedRef.current) return;
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: getStorageKey() });
        // StorageGate.put already serializes the value - don't stringify twice.
        gate.open().then(() => gate.put(MESSAGES_STORE, HISTORY_ID, messages)).catch(console.error);
    }, [messages]);

    // ── Receive loop ───────────────────────────────────────────────────────
    // Poll the relay for inbound envelopes addressed to the local user (by their own
    // recipient ID) on a fixed interval while the component is mounted. On a successful
    // pickup, decrypt with the receiver-side session and append the plaintext to the
    // message history. NotFound/Expired (empty mailbox) are normal, not errors. A
    // decrypt failure (tampered ciphertext, AEAD auth failure) fails closed: no
    // plaintext is rendered and a visible role='alert' warning is surfaced.
    useEffect(() => {
        if (!identity) return;

        let cancelled = false;
        let timer: ReturnType<typeof setInterval> | null = null;

        const POLL_INTERVAL_MS = 5000;

        async function pollOnce() {
            if (cancelled) return;
            if (pollInFlightRef.current) return; // skip overlapping poll
            pollInFlightRef.current = true;
            try {
                await ensureWasmInit();

                // Use the receiver session injected by the caller (App.tsx).
                // This is the SAME session whose prekey bundle was published to
                // the relay — so envelopes encrypted to that bundle can be
                // decrypted here. The component does NOT create its own session
                // lazily, because that would be a cryptographically distinct
                // session unrelated to the published bundle.
                if (!receiverSessionRef.current) {
                    const propSession = receiverSessionPropRef.current;
                    if (!propSession) return; // session not ready yet
                    receiverSessionRef.current = propSession;
                }

                const picked = await transportRef.current.pickupEnvelope(
                    identity!.recipientId,
                );

                // ── Envelope-kind routing (GRP-6, out-of-band) ──────────────
                // The kind travels as a sibling field of the relay's
                // pickup_envelope op — never inside the ciphertext. Normalize
                // both pickup shapes: a bare Uint8Array (legacy mocks / no tag)
                // or a `{ envelope, kind }` result.
                const envelope: Uint8Array =
                    picked instanceof Uint8Array ? picked : picked.envelope;
                const envelopeKind: string | undefined = (picked as any).kind;
                // This is the DIRECT loop. The transport already sent
                // `kind: 'direct'` on the pickup op, so the relay keeps
                // group-kind envelopes queued for the group loop and this
                // branch should not fire against a filtering relay. It is kept
                // as a DEFENSIVE FALLBACK for a non-filtering peer (legacy
                // relay / mock): a known foreign kind ("group") must not be
                // decrypted here, so we skip it without surfacing the tampered
                // warning. A missing or UNKNOWN kind FALLS THROUGH to this
                // loop's decrypt (fail closed = not silently misrouted, not
                // skipped).
                if (envelopeKind === 'group') {
                    return; // foreign kind: leave for the owning loop
                }

                // Dedup: the relay may return the same envelope on consecutive polls.
                const envelopeKey = Buffer.from(envelope).toString('base64');
                if (seenEnvelopesRef.current.has(envelopeKey)) return;
                seenEnvelopesRef.current.add(envelopeKey);

                // Decrypt — fail closed. A tampered/corrupted envelope throws here;
                // we surface a warning and never render any plaintext.
                let plaintext: Uint8Array;
                try {
                    plaintext = decrypt_message(receiverSessionRef.current, envelope);
                } catch (e) {
                    const msg = describeError(e);
                    console.warn('decrypt failed for picked-up envelope', { error: msg });
                    setDecryptionWarning(
                        'A received message could not be verified and was discarded. ' +
                        'This may indicate a tampered or corrupted message.',
                    );
                    return;
                }

                // Success: clear any prior warning and append the decrypted message.
                setDecryptionWarning('');
                // Persist the advanced ratchet state BEFORE rendering the message:
                // the relay has already consumed the envelope, so if the save fails
                // the message must still be shown (dropping it would lose it) but
                // the user is warned that a reload may not be able to decrypt
                // subsequent messages.
                try {
                    await persistSessionRecord(
                        await getSessionGate(),
                        RECEIVER_RECORD_ID,
                        receiverSessionRef.current,
                    );
                    setPersistenceWarning(null);
                } catch {
                    console.warn('failed to persist receiver session');
                    setPersistenceWarning(
                        'Session state could not be saved. Messages received after a reload may fail to decrypt.',
                    );
                }
                const body = new TextDecoder().decode(plaintext);
                const msg: Message = {
                    id: Math.random().toString(36).substr(2, 9),
                    body,
                    timestamp: Date.now(),
                    sentByMe: false,
                };
                setMessages(prev => [...prev, msg]);
            } catch (e) {
                // NotFound / Expired = empty mailbox, a normal condition. Do not
                // log, do not show a warning, do not crash.
                const msg = describeError(e);
                if (msg === 'NotFound' || msg === 'Expired') return;
                // Unexpected transport errors: log at warn level (not error — the
                // loop retries on the next interval) but do not crash the UI.
                console.warn('pickup_envelope poll failed', { error: msg });
            } finally {
                pollInFlightRef.current = false;
            }
        }

        // Start polling. The interval fires pollOnce on a fixed cadence; the
        // pollInFlightRef guard inside pollOnce skips a tick if the previous
        // poll is still awaiting I/O, preventing overlapping/leaked work.
        timer = setInterval(() => {
            void pollOnce();
        }, POLL_INTERVAL_MS);

        // Also fire one immediate poll so we don't wait a full interval on mount.
        void pollOnce();

        return () => {
            cancelled = true;
            if (timer) clearInterval(timer);
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [identity]);

    // Report the active peer's remote identity key (or null, if no session exists for them
    // yet) whenever the peer id changes, so SafetyNumberVerification always reflects the
    // currently selected conversation rather than a stale or unrelated key.
    useEffect(() => {
        const existing = sessionsRef.current.get(peerId.trim());
        onRemoteIdentityKeyChange?.(peerId, existing ? existing.remoteIdentityKey : null);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [peerId]);

    const send = async (): Promise<void> => {
        const trimmedPeerId = peerId.trim();
        const trimmedInput = input.trim();
        if (!identity || !trimmedPeerId || !trimmedInput || sending) return;

        // DR-6: with a verified device list present, one plaintext fans out to
        // one envelope per device (spec/v0.md §8.3). With no list (or an empty
        // one) the send is exactly the legacy single-recipient behaviour —
        // one envelope to the bare peer id — which is what keeps the
        // single-recipient session semantics (and the tests that pin them)
        // unchanged.
        const devices: DeviceListEntry[] | undefined =
            deviceList && deviceList.devices.length > 0 ? deviceList.devices : undefined;
        if (devices) {
            setSending(true);
            setStatus('');
            try {
                const plaintextBytes = new TextEncoder().encode(trimmedInput);
                const inputs = devices.map(
                    (entry) =>
                        // expected_identity_key_bytes is the key the PRIMARY
                        // vouched for (entry.identityKey), never the bundle's
                        // own key — the binding compares the two and rejects a
                        // device whose bundle does not match the vouched-for
                        // key, so a substituted bundle cannot redirect
                        // ciphertext. An entry with no vouched-for key is
                        // rejected outright rather than trusted from its bundle.
                        new FanoutDeviceInput(
                            entry.deviceId,
                            entry.identityKey,
                            entry.bundleBytes,
                        ),
                );
                const handle = fanout_establish(
                    identity.handle as unknown as Parameters<typeof fanout_establish>[0],
                    inputs,
                );
                const envelopes = fanout_encrypt(handle, plaintextBytes);
                for (const env of envelopes) {
                    await transportRef.current.sendEnvelope(
                        `${trimmedPeerId}:${env.device_id}`,
                        env.envelope,
                    );
                }

                const msg: Message = {
                    id: Math.random().toString(36).substr(2, 9),
                    body: trimmedInput,
                    timestamp: Date.now(),
                    sentByMe: true,
                };
                setMessages(prev => [...prev, msg]);
                setInput('');
                setStatus('Sent');
            } catch (e) {
                // Fail closed: a rejected device (identity-key mismatch,
                // malformed bundle) aborts the whole send — nothing is
                // delivered and the composer keeps its text. Error detail is
                // a structured kind/message, never key or plaintext material.
                setStatus(`Send failed: ${describeError(e)}`);
            } finally {
                setSending(false);
            }
            return;
        }

        await sendSingle();
    };

    const sendSingle = async () => {
        const trimmedPeerId = peerId.trim();
        const trimmedInput = input.trim();
        if (!identity || !trimmedPeerId || !trimmedInput || sending) return;

        setSending(true);
        setStatus('');
        try {
            let peerSession = sessionsRef.current.get(trimmedPeerId);

            // Lazy restore: a previous run may have saved this peer's sender
            // session. Only a record that carries the peer's identity key is
            // usable — without it the safety number cannot be reported, so the
            // record is treated as unusable and a fresh session is established
            // instead. A partially restored session is never used.
            let restoreFailed = false;
            if (!peerSession) {
                // Restoring a session deserializes it in WASM, so make sure the
                // module is ready before the first attempt (the establishment path
                // below needs it too).
                await ensureWasmInit();
                try {
                    const restored = await restoreSessionRecord(
                        await getSessionGate(),
                        senderRecordId(trimmedPeerId),
                        identity.handle,
                    );
                    if (restored && restored.remoteIdentityKey) {
                        peerSession = {
                            session: restored.session,
                            remoteIdentityKey: restored.remoteIdentityKey,
                        };
                        sessionsRef.current.set(trimmedPeerId, peerSession);
                        onRemoteIdentityKeyChange?.(trimmedPeerId, restored.remoteIdentityKey);
                    } else if (restored) {
                        restoreFailed = true;
                    }
                } catch {
                    // Static message only: a record's contents (blob bytes, keys)
                    // must never reach a log, an error message, or the UI.
                    console.warn('failed to restore saved sender session');
                    restoreFailed = true;
                }
            }

            if (!peerSession) {
                setStatus(
                    restoreFailed
                        ? 'Saved session for this peer could not be restored; establishing a new one'
                        : 'Looking up peer…',
                );

                let bundleBytes: Uint8Array;
                try {
                    bundleBytes = await transportRef.current.lookupPrekey(trimmedPeerId);
                } catch {
                    setStatus('Peer not found');
                    return;
                }

                let remoteIdentityKey: Uint8Array;
                try {
                    remoteIdentityKey = bundle_identity_key_bytes(bundleBytes);
                } catch (e) {
                    setStatus(`Invalid prekey bundle: ${describeError(e)}`);
                    return;
                }

                // bundle_identity_key_bytes does NOT verify the bundle's signatures (see its doc
                // comment in core/bindings/wasm/src/lib.rs) - only establish_session_from_bundle
                // does that. So remoteIdentityKey is held locally but not reported upward via
                // onRemoteIdentityKeyChange (and the session is not cached) until establishment
                // below succeeds - the safety number a user compares out-of-band must only ever
                // reflect a signature-verified identity key, never an attacker-supplied one from
                // a tampered bundle.
                let session: InstanceType<typeof SessionHandle>;
                try {
                    session = establish_session_from_bundle(
                        identity.handle as unknown as Parameters<typeof establish_session_from_bundle>[0],
                        bundleBytes,
                    );
                } catch (e) {
                    setStatus(`Could not establish session: ${describeError(e)}`);
                    return;
                }

                peerSession = { session, remoteIdentityKey };
                sessionsRef.current.set(trimmedPeerId, peerSession);
                onRemoteIdentityKeyChange?.(trimmedPeerId, remoteIdentityKey);
            }

            const plaintextBytes = new TextEncoder().encode(trimmedInput);
            let envelope: Uint8Array;
            try {
                envelope = encrypt_message(peerSession.session, plaintextBytes);
            } catch (e) {
                setStatus(`Encrypt failed: ${describeError(e)}`);
                return;
            }

            // Persist the advanced ratchet state BEFORE the envelope leaves the
            // device. A skipped ratchet step is safe; a reused message key is not,
            // so a failed save must abort the send rather than deliver a message
            // whose key material was never recorded.
            try {
                await persistSessionRecord(
                    await getSessionGate(),
                    senderRecordId(trimmedPeerId),
                    peerSession.session,
                    peerSession.remoteIdentityKey,
                );
            } catch {
                console.warn('failed to persist sender session');
                setStatus('Could not save session state; message not sent');
                return;
            }

            await transportRef.current.sendEnvelope(trimmedPeerId, envelope);

            const msg: Message = {
                id: Math.random().toString(36).substr(2, 9),
                body: trimmedInput,
                timestamp: Date.now(),
                sentByMe: true,
            };
            setMessages(prev => [...prev, msg]);
            setInput('');
            setStatus('Sent');
        } catch (e) {
            setStatus(describeError(e) || 'Failed to send');
        } finally {
            setSending(false);
        }
    };

    const canSend = !!identity && !!peerId.trim() && !!input.trim() && !sending;

    return (
        <div className="thread">
            <div className="composer-peer">
                <input
                    id="conversation-peer-id"
                    className="composer-peer-input"
                    type="text"
                    value={peerId}
                    onChange={e => setPeerId(e.target.value)}
                    placeholder="Recipient ID"
                    aria-label="Recipient ID"
                />
            </div>
            <div className="thread-log">
                {messages.length===0 ? (<p className="thread-empty">No messages yet.</p>) : (
                    messages.map(m => (
                        <div key={m.id} className={`msg-row${m.sentByMe ? ' mine' : ''}`}>
                            <div className="msg-bubble">
                                {m.body}
                                <small className="msg-time">
                                    {m.sentByMe ? 'You' : 'Them'} · {new Date(m.timestamp).toLocaleString()}
                                </small>
                            </div>
                        </div>
                    ))
                )}
            </div>
            <div className="composer">
                <input
                    className="composer-input"
                    type="text"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    placeholder="Type a message"
                    disabled={!identity}
                />
                <button className="composer-send" onClick={send} disabled={!canSend}>Send</button>
            </div>
            {decryptionWarning && (
                <p className="thread-warning" role="alert">{decryptionWarning}</p>
            )}
            {persistenceWarning && (
                <p className="thread-warning" role="alert">{persistenceWarning}</p>
            )}
            {status && <p className="thread-status">{status}</p>}
        </div>
    );
}
