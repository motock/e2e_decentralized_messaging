import React, { useEffect, useRef, useState } from 'react';
import { generate_identity, derive_safety_number, group_create, group_add_member, group_remove_member, group_encrypt, group_decrypt, bundle_identity_key_bytes, IdentityHandle, GroupHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { SealGlyph } from './design/SealGlyph';
import { StorageGate } from './storage';
import { getStorageKey } from './storage_key';
import { RelayTransport } from './relay_transport';
import './GroupConversation.css';

// Sender Keys group crypto UI on top of the WASM group bindings
// (group_create/group_add_member/group_remove_member/group_encrypt/
// group_decrypt - core/bindings/wasm/src/lib.rs).
//
// Two member sources coexist:
//
//   1. **Demo members** (Alice, Bob, Eve) — each is a full locally generated
//      identity (private + public key), exactly like
//      core/bindings/wasm/tests/wasm_group_encrypt.rs's own test pattern.
//      These let the component prove the real negative-path contract in the
//      browser UI: after removing a member, decrypting a subsequent message AS
//      that member's own identity genuinely fails (a real WasmError from the
//      actual crypto), not a faked/mocked failure.
//
//   2. **Real peers** — added by recipient ID. The component looks up the
//      peer's published prekey bundle via `lookupPrekey` (RelayTransport,
//      same as direct messaging in Conversation.tsx), extracts the identity
//      key with `bundle_identity_key_bytes`, and passes that real looked-up
//      public key to `group_add_member` — the crypto layer is unchanged, only
//      the source of the member's public key changes from a local demo
//      identity to a real looked-up remote identity.
//
// Group membership (the member list with recipient IDs and public keys) is
// persisted via the existing StorageGate pattern (encrypted IndexedDB), so
// it survives a page reload — matching how identity persistence already works
// in identity.ts. The WASM GroupHandle itself is not serializable (it's an
// opaque WASM-side handle), so on reload the component reconstructs the group
// session from the persisted member list by re-calling group_create +
// group_add_member for each persisted member.

export interface GroupMessageResult {
    ok: boolean;
    error?: string;
}

export interface GroupMessage {
    id: string;
    plaintext: string;
    timestamp: number;
    // Per-member decrypt outcome at send time, keyed by member name - lets
    // the UI (and tests) show/assert who could and could not decrypt each
    // message, including members who were removed before it was sent.
    decryptResults: Record<string, GroupMessageResult>;
    // True for messages sent by the local user; false for received messages
    // decrypted from the relay. Omitted/undefined for backward compat with
    // persisted messages from before this field existed.
    sentByMe?: boolean;
}

/**
 * The transport surface `GroupConversation` needs for looking up a real
 * peer's published prekey bundle. `RelayTransport` satisfies this; tests
 * inject a mock that implements only this narrow interface so the crypto
 * boundary stays real while the network boundary is mocked — the same
 * pattern as Conversation.tsx's `ConversationTransport`.
 */
export interface GroupTransport {
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
    sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void>;
    /**
     * Pick up a stored envelope addressed to `recipientId` (the local user's own
     * recipient ID). Returns the raw envelope bytes. Rejects with an error whose
     * message is "NotFound" or "Expired" when the mailbox is empty — the receive
     * loop treats these as a normal empty poll, not an exceptional condition.
     */
    pickupEnvelope(recipientId: string): Promise<Uint8Array>;
}

export interface GroupConversationProps {
    /** Defaults to a real `RelayTransport`; tests inject a mock here. */
    transport?: GroupTransport;
    /**
     * An opened `StorageGate` for persisting group membership. If omitted,
     * the component creates one from `globalThis.indexedDB` (production path).
     * Tests inject a mock to simulate persistence across reloads.
     */
    storageGate?: StorageGate;
    /**
     * The local persisted identity, used for group_create, group_encrypt and
     * group_decrypt. REQUIRED: there is no demo-identity fallback. Omitting
     * this prop (or `selfRecipientId`) makes the component fail closed — it
     * renders a visible "unavailable" alert, starts no receive loop, and never
     * generates a demo identity.
     */
    identity?: InstanceType<typeof IdentityHandle>;
    /**
     * The local user's own recipient ID (base64 of their public key). REQUIRED
     * alongside `identity` — the receive loop polls the relay for envelopes
     * addressed to this ID. Omitting either prop fails closed.
     */
    selfRecipientId?: string;
}

interface DemoMember {
    name: string;
    identity: InstanceType<typeof IdentityHandle>;
    publicBytes: Uint8Array;
}

/**
 * A real peer added by recipient ID. Unlike a DemoMember, there is no local
 * private key — only the public identity key looked up from the relay. The
 * `recipientId` is the address the user typed; `publicBytes` is the identity
 * key extracted from the looked-up prekey bundle via
 * `bundle_identity_key_bytes`.
 */
interface RealMember {
    recipientId: string;
    publicBytes: Uint8Array;
}

/**
 * The persisted group state record. Stored via StorageGate so membership
 * survives a page reload. Public keys are stored as number arrays (JSON-
 * serializable); on reload the component reconstructs the GroupHandle by
 * re-calling group_create + group_add_member for each member.
 */
interface PersistedGroupState {
    members: Array<{ recipientId: string; publicBytes: number[] }>;
}

const DEMO_MEMBER_NAMES = ['Alice', 'Bob', 'Eve'] as const;
const GROUP_STORE = 'session' as const;
const GROUP_RECORD_ID = 'group-state';
const GROUP_MESSAGES_STORE = 'messages' as const;
const GROUP_MESSAGES_ID = 'group-messages';

export const GroupConversation: React.FC<GroupConversationProps> = ({
    transport,
    storageGate,
    identity: identityProp,
    selfRecipientId,
}) => {
    const [ready, setReady] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selfIdentity, setSelfIdentity] = useState<InstanceType<typeof IdentityHandle> | null>(null);
    const [allMembers, setAllMembers] = useState<DemoMember[]>([]);
    const [group, setGroup] = useState<InstanceType<typeof GroupHandle> | null>(null);
    const [memberNames, setMemberNames] = useState<string[]>([]);
    const [realMembers, setRealMembers] = useState<RealMember[]>([]);
    // Real peers that were removed from the group but kept visible so the
    // user can re-add them (mirrors the demo-member Add/Remove toggle).
    const [removedRealMembers, setRemovedRealMembers] = useState<RealMember[]>([]);
    const [messages, setMessages] = useState<GroupMessage[]>([]);
    const [input, setInput] = useState('');
    const [peerIdInput, setPeerIdInput] = useState('');
    const [addingPeer, setAddingPeer] = useState(false);
    const [peerError, setPeerError] = useState<string | null>(null);
    const [decryptionWarning, setDecryptionWarning] = useState<string>('');

    const transportRef = useRef<GroupTransport>(transport ?? new RelayTransport());

    // RelayTransport allows only ONE request in flight (see its one-in-flight
    // constraint): a second concurrent op overwrites the single pending slot and
    // the first caller's promise never settles. The receive loop polls
    // pickupEnvelope on an interval while the send path fires sendEnvelope
    // without awaiting, so a send landing mid-poll would hang that poll forever
    // — pollInFlightRef would stay true and the receive loop would be dead for
    // the rest of the session. Funnel every transport op through this chain so
    // ops are serialized instead of overlapping.
    const transportQueueRef = useRef<Promise<unknown>>(Promise.resolve());
    const runTransportOp = <T,>(op: () => Promise<T>): Promise<T> => {
        const next = transportQueueRef.current.then(op, op);
        transportQueueRef.current = next.then(
            () => undefined,
            () => undefined,
        );
        return next;
    };
    const gateRef = useRef<StorageGate | undefined>(storageGate);
    // Track whether we've attempted to load persisted state so we don't
    // overwrite it with an empty group on the first render.
    const loadedRef = useRef(false);
    // Track whether persisted messages have been loaded (separate from group
    // state loading because messages have their own store/record).
    const messagesLoadedRef = useRef(false);
    // Dedup set for picked-up envelopes (base64 of envelope bytes) — prevents
    // the relay returning the same envelope on consecutive polls from creating
    // duplicate messages. Mirrors Conversation.tsx's receive-loop dedup.
    const seenEnvelopesRef = useRef<Set<string>>(new Set());
    // In-flight guard: prevents overlapping polls when I/O is slow. Mirrors
    // Conversation.tsx's pollInFlightRef pattern.
    const pollInFlightRef = useRef(false);
    // Mirror group/selfIdentity state into refs so the receive-loop effect
    // (which depends on [identityProp, selfRecipientId], not [group]) always
    // reads the latest values without re-subscribing the interval on every
    // group change.
    const groupRef = useRef<InstanceType<typeof GroupHandle> | null>(null);
    const selfIdentityRef = useRef<InstanceType<typeof IdentityHandle> | null>(null);
    useEffect(() => { groupRef.current = group; }, [group]);
    useEffect(() => { selfIdentityRef.current = selfIdentity; }, [selfIdentity]);

    // Keep the prop-derived refs fresh WITHOUT re-running the one-time init.
    // The init effect below rebuilds the GroupHandle and re-reads persisted
    // state, so it must only re-run when the identity itself changes — not on a
    // relay-URL change, which would silently rebuild the group and drop
    // in-memory ratchet state. Declared before the init effect so it runs first
    // on the render that supplies real props.
    useEffect(() => {
        if (transport) transportRef.current = transport;
        if (storageGate) gateRef.current = storageGate;
    }, [transport, storageGate]);

    useEffect(() => {
        let cancelled = false;
        // Criterion 3 — fail closed. With no identity/selfRecipientId the group
        // view must not silently pretend to be connected: no throwaway demo
        // identity, no receive loop, and crucially no persisted-config ref
        // (gateRef) written from a permissive default. Leaving gateRef untouched
        // is what keeps a LATER render that does supply real props correct.
        if (!identityProp || !selfRecipientId) {
            // The render path already prefixes this with "Group conversation
            // unavailable: ", so keep the message itself free of a second
            // "unavailable" clause.
            setError('no identity supplied.');
            setReady(false);
            return;
        }
        setError(null);
        ensureWasmInit()
            .then(async () => {
                if (cancelled) return;
                const self = identityProp;
                const demoMembers: DemoMember[] = DEMO_MEMBER_NAMES.map((name) => {
                    const identity = generate_identity();
                    return { name, identity, publicBytes: identity.public_bytes() };
                });
                setSelfIdentity(self);
                setAllMembers(demoMembers);

                // Load persisted group state (if any) so membership survives
                // a page reload. The GroupHandle is not serializable, so we
                // reconstruct it from the persisted member list.
                if (!gateRef.current) {
                    gateRef.current = new StorageGate({
                        indexedDB: (globalThis as any).indexedDB,
                        keyBytes: getStorageKey(),
                    });
                }
                const gate = gateRef.current;
                try {
                    await gate.open();
                    const persisted = (await gate.get(GROUP_STORE, GROUP_RECORD_ID)) as
                        | PersistedGroupState
                        | null;
                    if (persisted?.members?.length) {
                        const restoredGroup = group_create(self);
                        const restored: RealMember[] = [];
                        for (const m of persisted.members) {
                            const pubBytes = new Uint8Array(m.publicBytes);
                            const newGroup = group_add_member(restoredGroup, pubBytes);
                            restored.push({ recipientId: m.recipientId, publicBytes: pubBytes });
                            // Update the group handle for each member.
                            // We can't call setGroup inside the loop (React
                            // batches), so we build up the final handle.
                            (restoredGroup as unknown as { members: Uint8Array[] }).members =
                                (newGroup as unknown as { members: Uint8Array[] }).members;
                        }
                        setGroup(restoredGroup);
                        setRealMembers(restored);
                    }
                } catch (e) {
                    console.error('Failed to load persisted group state', e);
                }

                // Load persisted group messages (if any) so history survives
                // a page reload — matching Conversation.tsx's message persistence.
                try {
                    const persistedMsgs = (await gate.get(GROUP_MESSAGES_STORE, GROUP_MESSAGES_ID)) as
                        | GroupMessage[]
                        | null;
                    if (persistedMsgs && persistedMsgs.length) {
                        setMessages(persistedMsgs);
                    }
                } catch (e) {
                    console.error('Failed to load persisted group messages', e);
                }
                messagesLoadedRef.current = true;

                loadedRef.current = true;
                setReady(true);
            })
            .catch((e: unknown) => {
                console.error('Failed to initialize group demo identities', e);
                if (!cancelled) setError(e instanceof Error ? e.message : String(e));
            });
        return () => {
            cancelled = true;
        };
    }, [identityProp, selfRecipientId]);

    // Persist the current real-member list to StorageGate so it survives
    // a page reload. Called after every membership change.
    const persistGroupState = async (members: RealMember[]) => {
        const gate = gateRef.current;
        if (!gate || !loadedRef.current) return;
        try {
            const state: PersistedGroupState = {
                members: members.map((m) => ({
                    recipientId: m.recipientId,
                    publicBytes: Array.from(m.publicBytes),
                })),
            };
            await gate.put(GROUP_STORE, GROUP_RECORD_ID, state);
        } catch (e) {
            console.error('Failed to persist group state', e);
        }
    };

    // Persist group messages whenever they change — matching Conversation.tsx's
    // message persistence pattern. Skipped until the initial load completes so
    // we don't overwrite persisted history with an empty array on mount.
    useEffect(() => {
        if (!messagesLoadedRef.current) return;
        const gate = gateRef.current;
        if (!gate) return;
        gate.open()
            .then(() => gate.put(GROUP_MESSAGES_STORE, GROUP_MESSAGES_ID, messages))
            .catch((e) => console.error('Failed to persist group messages', e));
    }, [messages]);

    // ── Receive loop ───────────────────────────────────────────────────────
    // Poll the relay for inbound group envelopes addressed to the local user
    // (by their own recipient ID) on a fixed interval while the component is
    // mounted. On a successful pickup, decrypt with group_decrypt and append
    // the plaintext to the message history. NotFound/Expired (empty mailbox)
    // are normal, not errors. A decrypt failure (tampered ciphertext, AEAD
    // auth failure) fails closed: no plaintext is rendered and a visible
    // role='alert' warning is surfaced — mirroring Conversation.tsx's
    // receive-loop fail-closed pattern.
    useEffect(() => {
        if (!identityProp || !selfRecipientId) return;

        let cancelled = false;
        let timer: ReturnType<typeof setInterval> | null = null;
        const POLL_INTERVAL_MS = 5000;

        async function pollOnce() {
            if (cancelled) return;
            if (pollInFlightRef.current) return; // skip overlapping poll
            pollInFlightRef.current = true;
            try {
                await ensureWasmInit();

                // Check for the group handle BEFORE picking up. If the group
                // hasn't been created yet (or is being restored from persisted
                // state), we must not pick up envelopes — the relay's store-and-
                // forward mailbox is destructive (pickup removes the envelope),
                // so consuming an envelope we can't yet decrypt would lose it.
                const currentGroup = groupRef.current;
                const currentSelf = selfIdentityRef.current;
                if (!currentGroup || !currentSelf) return;

                const envelope: Uint8Array = await runTransportOp(() =>
                    transportRef.current.pickupEnvelope(selfRecipientId!),
                );

                // Dedup: the relay may return the same envelope on consecutive polls.
                const envelopeKey = Buffer.from(envelope).toString('base64');
                if (seenEnvelopesRef.current.has(envelopeKey)) return;
                seenEnvelopesRef.current.add(envelopeKey);

                // Decrypt — fail closed. A tampered/corrupted envelope throws
                // here; we surface a warning and never render any plaintext.

                let plaintext: Uint8Array;
                try {
                    plaintext = group_decrypt(currentGroup, currentSelf, envelope);
                } catch (e) {
                    const msg = e instanceof Error ? e.message : String(e);
                    console.warn('group_decrypt failed for picked-up envelope', { error: msg });
                    setDecryptionWarning(
                        'A received group message could not be verified and was discarded. ' +
                        'This may indicate a tampered or corrupted message.',
                    );
                    return;
                }

                // Success: clear any prior warning and append the decrypted message.
                setDecryptionWarning('');
                const body = new TextDecoder().decode(plaintext);
                setMessages((prev) => [
                    ...prev,
                    {
                        id: Math.random().toString(36).slice(2),
                        plaintext: body,
                        timestamp: Date.now(),
                        decryptResults: {},
                        sentByMe: false,
                    },
                ]);
            } catch (e) {
                // NotFound / Expired = empty mailbox, a normal condition. Do not
                // log, do not show a warning, do not crash.
                const msg = e instanceof Error ? e.message : String(e);
                if (msg === 'NotFound' || msg === 'Expired') return;
                // Unexpected transport errors: log at warn level (not error — the
                // loop retries on the next interval) but do not crash the UI.
                console.warn('pickup_envelope poll failed', { error: msg });
            } finally {
                pollInFlightRef.current = false;
            }
        }

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
    }, [identityProp, selfRecipientId]);

    const createGroup = () => {
        if (!selfIdentity) return;
        setGroup(group_create(selfIdentity));
        setMemberNames([]);
        setRealMembers([]);
        setMessages([]);
        void persistGroupState([]);
    };

    const addMember = (name: string) => {
        if (!group || memberNames.includes(name)) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(group_add_member(group, member.publicBytes));
        setMemberNames((prev) => [...prev, name]);
    };

    // Add a real peer by recipient ID: look up their prekey bundle via the
    // relay transport, extract the identity key, and pass it to group_add_member.
    // The crypto layer is unchanged — only the source of the public key changes
    // from a local demo identity to a real looked-up remote identity.
    const addPeer = async () => {
        const trimmedId = peerIdInput.trim();
        if (!group || !trimmedId || addingPeer) return;
        // Don't add the same recipient ID twice.
        if (realMembers.some((m) => m.recipientId === trimmedId)) return;

        // If the peer was previously removed, re-add them using the known key
        // (no new lookup needed) and clear them from the removed list.
        const previouslyRemoved = removedRealMembers.find((m) => m.recipientId === trimmedId);
        if (previouslyRemoved) {
            setGroup(group_add_member(group, previouslyRemoved.publicBytes));
            const updatedMembers = [...realMembers, previouslyRemoved];
            setRealMembers(updatedMembers);
            setRemovedRealMembers((prev) => prev.filter((m) => m.recipientId !== trimmedId));
            setPeerIdInput('');
            void persistGroupState(updatedMembers);
            return;
        }

        setAddingPeer(true);
        setPeerError(null);
        try {
            let bundleBytes: Uint8Array;
            try {
                bundleBytes = await runTransportOp(() =>
                    transportRef.current.lookupPrekey(trimmedId),
                );
            } catch {
                setPeerError('Peer not found');
                return;
            }

            let identityKey: Uint8Array;
            try {
                identityKey = bundle_identity_key_bytes(bundleBytes);
            } catch (e) {
                setPeerError(`Invalid prekey bundle: ${e instanceof Error ? e.message : String(e)}`);
                return;
            }

            const newGroup = group_add_member(group, identityKey);
            const newMember: RealMember = { recipientId: trimmedId, publicBytes: identityKey };
            const updatedMembers = [...realMembers, newMember];
            setGroup(newGroup);
            setRealMembers(updatedMembers);
            setPeerIdInput('');
            void persistGroupState(updatedMembers);
        } catch (e) {
            setPeerError(e instanceof Error ? e.message : String(e));
        } finally {
            setAddingPeer(false);
        }
    };

    const removeMember = (name: string) => {
        if (!group) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(group_remove_member(group, member.publicBytes));
        setMemberNames((prev) => prev.filter((n) => n !== name));
    };

    // Remove a real peer by recipient ID. Removing a member who was already
    // removed is a no-op (group_remove_member's core contract is infallible —
    // it simply doesn't match), not an error.
    const removePeer = (recipientId: string) => {
        if (!group) return;
        const member = realMembers.find((m) => m.recipientId === recipientId);
        if (!member) return; // already removed — no-op, not an error
        setGroup(group_remove_member(group, member.publicBytes));
        const updatedMembers = realMembers.filter((m) => m.recipientId !== recipientId);
        setRealMembers(updatedMembers);
        setRemovedRealMembers((prev) =>
            prev.some((m) => m.recipientId === recipientId) ? prev : [...prev, member],
        );
        void persistGroupState(updatedMembers);
    };

    // Re-add a previously-removed real peer. The public key is already known
    // (looked up when first added), so no new lookupPrekey call is needed.
    const reAddPeer = (recipientId: string) => {
        if (!group) return;
        const member = removedRealMembers.find((m) => m.recipientId === recipientId);
        if (!member) return;
        setGroup(group_add_member(group, member.publicBytes));
        const updatedMembers = [...realMembers, member];
        setRealMembers(updatedMembers);
        setRemovedRealMembers((prev) => prev.filter((m) => m.recipientId !== recipientId));
        void persistGroupState(updatedMembers);
    };

    const send = () => {
        if (!group || !selfIdentity || !input.trim()) return;
        const plaintextBytes = new TextEncoder().encode(input);
        let ciphertext: Uint8Array;
        try {
            ciphertext = group_encrypt(group, selfIdentity, plaintextBytes);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            return;
        }
        // Deliver the ciphertext to every real group member via sendEnvelope
        // over the relay, addressed by each member's recipient ID — mirroring
        // Conversation.tsx's send path. Demo members are local-only (no relay
        // address) so they are not sent over the wire.
        for (const member of realMembers) {
            void runTransportOp(() =>
                transportRef.current.sendEnvelope(member.recipientId, new Uint8Array(ciphertext)),
            ).catch((e) => {
                    console.warn('sendEnvelope failed for group member', {
                        recipientId: member.recipientId,
                        error: e instanceof Error ? e.message : String(e),
                    });
                });
        }
        // Every known demo member (whether currently in the group or removed)
        // attempts to decrypt, surfacing the real per-member outcome from the
        // actual crypto - including a removed member's decrypt genuinely
        // failing, not a simulated/faked result.
        const decryptResults: Record<string, GroupMessageResult> = {};
        for (const member of allMembers) {
            try {
                group_decrypt(group, member.identity, ciphertext);
                decryptResults[member.name] = { ok: true };
            } catch (e) {
                decryptResults[member.name] = {
                    ok: false,
                    error: e instanceof Error ? e.message : String(e),
                };
            }
        }
        setMessages((prev) => [
            ...prev,
            {
                id: Math.random().toString(36).slice(2),
                plaintext: input,
                timestamp: Date.now(),
                decryptResults,
                sentByMe: true,
            },
        ]);
        setInput('');
    };

    if (error) {
        return <div role="alert" className="group-error">Group conversation unavailable: {error}</div>;
    }

    if (!ready) {
        return <div className="group-loading">Loading…</div>;
    }

    return (
        <div data-testid="group-conversation" className="group-view">
            {!group ? (
                <button onClick={createGroup} data-testid="create-group-button" className="group-create group-create-button">
                    Create Group
                </button>
            ) : (
                <>
                    <div data-testid="member-list" className="group-members">
                        {allMembers.map((m) => (
                            <div key={m.name} className={`member-chip${memberNames.includes(m.name) ? ' in-group' : ''}`}>
                                <SealGlyph value={m.name} size={20} tone={memberNames.includes(m.name) ? 'verified' : 'neutral'} title={`${m.name}'s seal`} />
                                <span className="member-chip-name">{m.name}</span>
                                {memberNames.includes(m.name) ? (
                                    <button onClick={() => removeMember(m.name)} data-testid={`remove-${m.name}`}>
                                        Remove
                                    </button>
                                ) : (
                                    <button onClick={() => addMember(m.name)} data-testid={`add-${m.name}`}>
                                        Add
                                    </button>
                                )}
                            </div>
                        ))}
                        {realMembers.map((m) => (
                            <div key={m.recipientId} data-testid={`member-${m.recipientId}`} className="member-chip in-group">
                                <SealGlyph value={m.recipientId} size={20} tone="verified" title={`${m.recipientId}'s seal`} />
                                <span className="member-chip-name">{m.recipientId}</span>
                                <button onClick={() => removePeer(m.recipientId)} data-testid={`remove-peer-${m.recipientId}`}>
                                    Remove
                                </button>
                            </div>
                        ))}
                        {removedRealMembers.map((m) => (
                            <div key={m.recipientId} className="member-chip">
                                <SealGlyph value={m.recipientId} size={20} tone="neutral" title={`${m.recipientId}'s seal`} />
                                <span className="member-chip-name">{m.recipientId}</span>
                                <button onClick={() => reAddPeer(m.recipientId)} data-testid={`add-peer-${m.recipientId}`}>
                                    Add
                                </button>
                            </div>
                        ))}
                    </div>
                    <div className="group-peer-add">
                        <input
                            value={peerIdInput}
                            onChange={(e) => setPeerIdInput(e.target.value)}
                            placeholder="Recipient ID"
                            data-testid="group-peer-id-input"
                            className="group-input"
                        />
                        <button onClick={addPeer} disabled={addingPeer} data-testid="add-peer-button" className="group-add-peer">
                            {addingPeer ? 'Adding…' : 'Add Peer'}
                        </button>
                        {peerError && (
                            <div role="alert" className="group-peer-error">{peerError}</div>
                        )}
                    </div>
                    <div data-testid="group-message-list" className="group-log">
                        {messages.length === 0 ? (
                            <p className="group-empty">No messages yet.</p>
                        ) : (
                            messages.map((msg) => (
                                <div key={msg.id} data-testid={`message-${msg.id}`} className="group-msg">
                                    <p className="group-msg-text">{msg.plaintext}</p>
                                    <ul className="group-msg-receipts">
                                        {Object.entries(msg.decryptResults).map(([name, result]) => (
                                            <li
                                                key={name}
                                                data-testid={`decrypt-${msg.id}-${name}`}
                                                className={`receipt ${result.ok ? 'receipt-ok' : 'receipt-fail'}`}
                                            >
                                                {name}: {result.ok ? 'decrypted' : `failed (${result.error})`}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            ))
                        )}
                    </div>
                    <div className="group-composer">
                        <input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Type a group message"
                            data-testid="group-message-input"
                            className="group-input"
                        />
                        <button onClick={send} data-testid="group-send-button" className="group-send">
                            Send
                        </button>
                    </div>
                    {decryptionWarning && (
                        <p className="group-warning" role="alert">{decryptionWarning}</p>
                    )}
                </>
            )}
        </div>
    );
};
