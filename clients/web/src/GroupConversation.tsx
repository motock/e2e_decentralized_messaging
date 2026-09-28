import React, { useEffect, useRef, useState } from 'react';
import { generate_identity, derive_safety_number, group_create, group_add_member, group_remove_member, group_encrypt, group_decrypt, group_to_bytes, group_from_bytes, bundle_identity_key_bytes, IdentityHandle, GroupHandle } from '../../../core/bindings/wasm/pkg/index.js';
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
// in identity.ts.
//
// The group's *sender-key ratchet state* is persisted too, via the real
// serialize/restore bindings (group_to_bytes / group_from_bytes,
// core/bindings/wasm/src/lib.rs). The persisted blob is what lets a reload
// resume the running session instead of starting a new one. Starting a new one
// is not itself a key-reuse hazard: GroupSession::new seeds the chain key from
// a fresh CSPRNG (core/protocol/src/group.rs), not from the sender's public
// key, so a rebuilt session cannot re-derive a (key, nonce) pair the old one
// already used. The reuse hazard is resuming a *stale* blob: a restored chain
// that lags the last ciphertext emitted would encrypt from a position already
// used. The save therefore happens before each send, and a failed save aborts
// the send. The serialized blob is secret ratchet state (the chain key,
// verbatim), so it is stored ONLY through the encrypted StorageGate, never
// plaintext, and never logged. On reload the component restores the session
// with group_from_bytes; only a record that predates ratchet persistence (no
// blob) falls back to replaying group_create + group_add_member, and a record
// whose blob is present but corrupt fails closed (no group is restored).

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
    // ── GRP-7: sender attribution for received messages ─────────────────
    // Stable identity of the sender of a RECEIVED message: the hex-encoded
    // public identity key of the group member the envelope's wrapper roster
    // attributes it to. Undefined for messages sent by the local user, and for
    // a received message whose sender cannot be uniquely identified from the
    // roster (fail closed — no attribution rather than a wrong one).
    senderId?: string;
    // Short, stable, human-readable label derived from `senderId` (the first
    // four bytes of the sender's public key, hex-encoded) — what the UI shows.
    senderLabel?: string;
    // Stable fingerprint of the group membership this message belongs to, so
    // messages can be grouped instead of collapsing into one flat log.
    groupId?: string;
    // ── GRP-7: send outcome ─────────────────────────────────────────────
    // How the fan-out to the group's real members actually went. `sent` only
    // when every member's sendEnvelope resolved; `partial` when some did and
    // some did not; `failed` when none did. Undefined for received messages.
    sendStatus?: 'sent' | 'partial' | 'failed';
    sendFailures?: number;
    sendTotal?: number;
    sendError?: string;
}

/** Byte-wise equality for two public identity keys. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/** Lowercase hex of a byte string. */
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** The short, stable sender label the UI renders (first 4 key bytes, hex). */
function shortSenderLabel(publicBytes: Uint8Array): string {
    return toHex(publicBytes.slice(0, 4));
}

/** A stable fingerprint of a group's membership, so messages can be grouped. */
function groupFingerprint(members: Array<{ recipientId: string }>): string {
    const joined = members
        .map((m) => m.recipientId)
        .sort()
        .join('|');
    let hash = 0x811c9dc5;
    for (let i = 0; i < joined.length; i++) {
        hash ^= joined.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
}

/**
 * Parse the wrapper roster out of a Sender Keys group ciphertext.
 *
 * Wire format (core/protocol/src/group.rs, `encrypt_as`):
 *
 *   nonce(12) | payload_len(u32 LE) | AES-GCM payload | wrapper_count(u8)
 *     | (member_pubkey(33) | sealed_len(u16 LE) | sealed)*
 *
 * Returns the public keys of the members the sender addressed, or `null` when
 * the bytes are not a structurally valid group ciphertext. `null` is a
 * fail-closed signal: the caller must neither attribute nor decrypt it.
 */
function parseWrapperRoster(envelope: Uint8Array): Uint8Array[] | null {
    if (envelope.length < 12 + 4 + 1) return null;
    const view = new DataView(envelope.buffer as ArrayBuffer, envelope.byteOffset, envelope.byteLength);
    const payloadLen = view.getUint32(12, true);
    let pos = 16 + payloadLen;
    if (pos + 1 > envelope.length) return null;
    const count = envelope[pos];
    pos += 1;
    const roster: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
        if (pos + 33 + 2 > envelope.length) return null;
        roster.push(envelope.slice(pos, pos + 33));
        pos += 33;
        const sealedLen = view.getUint16(pos, true);
        pos += 2;
        if (pos + sealedLen > envelope.length) return null;
        pos += sealedLen;
    }
    return roster;
}

/**
 * The sender of a received envelope: the one known real member whose public
 * key is absent from the roster. `GroupSession::new` ignores the sender's own
 * public key and starts with an empty member list, so a sender addresses every
 * member *except itself* — the sender is exactly the member missing from the
 * roster, while the local user's own key is always present.
 *
 * Returns `null` when that member is not unique (an empty roster, or a sender
 * whose view of the group omits more than one member): fail closed rather than
 * attribute a message to the wrong member.
 */
function findSenderFromRoster(
    roster: Uint8Array[],
    selfPublicBytes: Uint8Array,
    knownMembers: Array<{ recipientId: string; publicBytes: Uint8Array }>,
): { recipientId: string; publicBytes: Uint8Array } | null {
    const candidates = knownMembers.filter(
        (m) =>
            !bytesEqual(m.publicBytes, selfPublicBytes) &&
            !roster.some((key) => bytesEqual(key, m.publicBytes)),
    );
    return candidates.length === 1 ? candidates[0] : null;
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
 * The persisted group state record. Stored via StorageGate (AES-256-GCM at
 * rest) so membership AND the sender-key ratchet state survive a page reload.
 * Public keys are stored as number arrays (JSON-serializable).
 *
 * `blob` is the group_to_bytes serialization of the group handle at the time
 * of the last persist — secret ratchet state (chain key + position), stored
 * encrypted, never logged. It is absent only in records written before
 * ratchet persistence existed; such a legacy record is restored by replaying
 * group_create + group_add_member (the pre-GRP-4 behavior).
 */
interface PersistedGroupState {
    members: Array<{ recipientId: string; publicBytes: number[] }>;
    /** group_to_bytes(group) as of the last persist; absent in legacy records. */
    blob?: number[];
}

/** Largest serialized group state accepted on restore (1 MiB). */
const MAX_GROUP_BLOB_LENGTH = 1048576;

/** True for a value that is a valid byte (integer in 0..255). */
function isByte(entry: unknown): entry is number {
    return Number.isInteger(entry) && (entry as number) >= 0 && (entry as number) <= 255;
}

/**
 * Validate a stored group blob before handing any bytes to WASM.
 *
 * Returns the bytes, or `null` when the record simply has no blob (a legacy
 * record from before ratchet persistence). Throws on a blob that is present
 * but structurally invalid — the caller must fail closed rather than build a
 * fresh session: a fresh session starts a different chain, and silently
 * dropping the persisted state is the very failure this persistence prevents.
 */
function validatedGroupBlob(blob: unknown): Uint8Array | null {
    if (blob === undefined || blob === null) return null;
    if (!Array.isArray(blob) || blob.length === 0) {
        throw new Error('invalid persisted group state');
    }
    if (blob.length > MAX_GROUP_BLOB_LENGTH) {
        throw new Error('invalid persisted group state');
    }
    if (!blob.every(isByte)) {
        throw new Error('invalid persisted group state');
    }
    return new Uint8Array(blob);
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
    // GRP-7: the outcome of the most recent group send, surfaced in the UI the
    // way Conversation.tsx surfaces a direct-send failure (its `status` line).
    // Per-message outcomes live on the message itself, so a later successful
    // send never hides an earlier failure.
    const [sendError, setSendError] = useState<string | null>(null);

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
    // GRP-7: the real (on-the-wire) members, mirrored into a ref so the
    // receive-loop effect can attribute a picked-up envelope without
    // re-subscribing the poll interval on every membership change. Demo
    // members are local-only identities with no relay address, so they are
    // never on the wire and are not attribution candidates.
    const knownMembersRef = useRef<RealMember[]>([]);
    useEffect(() => { knownMembersRef.current = realMembers; }, [realMembers]);

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
                let storeOpen = true;
                try {
                    await gate.open();
                } catch (e) {
                    // The store could not be opened (e.g. IndexedDB is
                    // unavailable). There is no store to read from or write to,
                    // so drop the unusable gate: the persist path then treats
                    // this as "no store" and does not block a send on a write
                    // that could never succeed.
                    console.error('Failed to open group state store', e);
                    storeOpen = false;
                    gateRef.current = undefined;
                }
                try {
                    const persisted = storeOpen
                        ? ((await gate.get(GROUP_STORE, GROUP_RECORD_ID)) as
                              | PersistedGroupState
                              | null)
                        : null;
                    if (persisted?.members?.length) {
                        const restored: RealMember[] = persisted.members.map((m) => ({
                            recipientId: m.recipientId,
                            publicBytes: new Uint8Array(m.publicBytes),
                        }));
                        // Restore the ratchet state from the persisted blob when
                        // the record has one. group_from_bytes fails closed on
                        // empty/truncated/corrupt input, and we must NOT fall back
                        // to building a fresh session then: a fresh session starts
                        // a different chain, and silently dropping the persisted
                        // state is the very failure this persistence prevents.
                        let restoredGroup: GroupHandle | null = null;
                        let blobError: unknown = null;
                        try {
                            const blob = validatedGroupBlob(persisted.blob);
                            if (blob) {
                                restoredGroup = group_from_bytes(blob);
                            }
                        } catch (e) {
                            blobError = e;
                            restoredGroup = null;
                        }
                        if (restoredGroup) {
                            // Real restore: the session continues from the
                            // persisted chain-key position.
                            setGroup(restoredGroup);
                            setRealMembers(restored);
                        } else if (blobError) {
                            // Fail closed: corrupt/truncated blob. Surface the
                            // failure and leave the group unset so nothing can
                            // send under a rewound chain.
                            console.error('Failed to restore persisted group ratchet state', blobError);
                            if (!cancelled) {
                                setError(
                                    'Stored group state is corrupt; the group session was not restored. ' +
                                    'Clear this site\'s stored data to start a new group.',
                                );
                            }
                        } else {
                            // Legacy record (no blob — written before ratchet
                            // persistence): replay the old reconstruction path.
                            // This only happens for records that never carried
                            // ratchet state, so there is nothing to resume.
                            let replayed = group_create(self);
                            for (const m of persisted.members) {
                                replayed = group_add_member(replayed, new Uint8Array(m.publicBytes));
                            }
                            setGroup(replayed);
                            setRealMembers(restored);
                        }
                    }
                } catch (e) {
                    console.error('Failed to load persisted group state', e);
                }

                // Load persisted group messages (if any) so history survives
                // a page reload — matching Conversation.tsx's message persistence.
                try {
                    const persistedMsgs = storeOpen
                        ? ((await gate.get(GROUP_MESSAGES_STORE, GROUP_MESSAGES_ID)) as
                              | GroupMessage[]
                              | null)
                        : null;
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

    // Persist the current real-member list AND the group's sender-key ratchet
    // state to StorageGate so both survive a page reload. Called after every
    // membership change and after every send (the ratchet advances on each
    // sent message, so the blob must be re-serialized then too).
    //
    // The blob is secret ratchet state: it goes through the encrypted
    // StorageGate only, and is never logged. A serialization failure is
    // logged without the blob and leaves the previously persisted state
    // untouched.
    const persistGroupState = async (
        members: RealMember[],
        groupHandle?: GroupHandle | null,
    ): Promise<boolean> => {
        const gate = gateRef.current;
        // No store to write to (or the initial load has not finished yet):
        // there is nothing to persist and nothing was lost, so this is not a
        // failure and must not block a send.
        if (!gate || !loadedRef.current) return true;
        const handle = groupHandle !== undefined ? groupHandle : groupRef.current;
        try {
            const state: PersistedGroupState = {
                members: members.map((m) => ({
                    recipientId: m.recipientId,
                    publicBytes: Array.from(m.publicBytes),
                })),
            };
            if (handle) {
                state.blob = Array.from(group_to_bytes(handle));
            }
            await gate.put(GROUP_STORE, GROUP_RECORD_ID, state);
            return true;
        } catch (e) {
            console.error('Failed to persist group state', e);
            return false;
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

                // GRP-7: parse the wrapper roster BEFORE decrypting. The roster
                // is the list of members the sender addressed, so if the local
                // user's own key is not in it this envelope was not addressed to
                // us (a non-member's envelope, or a malformed one) — reject it
                // without producing any plaintext.
                const roster = parseWrapperRoster(envelope);
                const selfPublicBytes = currentSelf.public_bytes();
                if (!roster || !roster.some((key) => bytesEqual(key, selfPublicBytes))) {
                    console.warn('group envelope is not addressed to this member; discarded');
                    setDecryptionWarning(
                        'A received group message was not addressed to this member and was discarded.',
                    );
                    return;
                }
                // Attribute the message to the one known member missing from the
                // roster (the sender never addresses itself). Ambiguous -> no
                // attribution, never a wrong one.
                const sender = findSenderFromRoster(
                    roster,
                    selfPublicBytes,
                    knownMembersRef.current,
                );

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
                        senderId: sender ? toHex(sender.publicBytes) : undefined,
                        senderLabel: sender ? shortSenderLabel(sender.publicBytes) : undefined,
                        groupId: groupFingerprint(knownMembersRef.current),
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
        const newGroup = group_create(selfIdentity);
        setGroup(newGroup);
        setMemberNames([]);
        setRealMembers([]);
        setMessages([]);
        void persistGroupState([], newGroup);
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
            const newGroup = group_add_member(group, previouslyRemoved.publicBytes);
            setGroup(newGroup);
            const updatedMembers = [...realMembers, previouslyRemoved];
            setRealMembers(updatedMembers);
            setRemovedRealMembers((prev) => prev.filter((m) => m.recipientId !== trimmedId));
            setPeerIdInput('');
            void persistGroupState(updatedMembers, newGroup);
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
            void persistGroupState(updatedMembers, newGroup);
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
        const updatedGroup = group_remove_member(group, member.publicBytes);
        setGroup(updatedGroup);
        const updatedMembers = realMembers.filter((m) => m.recipientId !== recipientId);
        setRealMembers(updatedMembers);
        setRemovedRealMembers((prev) =>
            prev.some((m) => m.recipientId === recipientId) ? prev : [...prev, member],
        );
        void persistGroupState(updatedMembers, updatedGroup);
    };

    // Re-add a previously-removed real peer. The public key is already known
    // (looked up when first added), so no new lookupPrekey call is needed.
    const reAddPeer = (recipientId: string) => {
        if (!group) return;
        const member = removedRealMembers.find((m) => m.recipientId === recipientId);
        if (!member) return;
        const newGroup = group_add_member(group, member.publicBytes);
        setGroup(newGroup);
        const updatedMembers = [...realMembers, member];
        setRealMembers(updatedMembers);
        setRemovedRealMembers((prev) => prev.filter((m) => m.recipientId !== recipientId));
        void persistGroupState(updatedMembers, newGroup);
    };

    const send = async () => {
        if (!group || !selfIdentity || !input.trim()) return;
        const plaintextBytes = new TextEncoder().encode(input);
        let ciphertext: Uint8Array;
        try {
            ciphertext = group_encrypt(group, selfIdentity, plaintextBytes);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            return;
        }
        // Persist the advanced ratchet BEFORE the envelope leaves the device. A
        // skipped ratchet step is safe; a reused message key is not -- a failed
        // save must abort the send rather than deliver a message whose key
        // material was never recorded (mirrors Conversation.tsx).
        if (!(await persistGroupState(realMembers, group))) {
            setError('Could not save session state; message not sent');
            return;
        }
        // Deliver the ciphertext to every real group member via sendEnvelope
        // over the relay, addressed by each member's recipient ID — mirroring
        // Conversation.tsx's send path. Demo members are local-only (no relay
        // address) so they are not sent over the wire.
        //
        // GRP-7: this fan-out is AWAITED and its per-member outcome is recorded
        // rather than swallowed by a fire-and-forget `.catch(console.warn)`.
        // `allSettled` (not `all`) is deliberate: one member's relay failure
        // must not be reported as a blanket failure of a send that did reach
        // the others, and a rejected entry must not be silently counted as a
        // success either.
        const sendOutcomes = await Promise.allSettled(
            realMembers.map((member) =>
                runTransportOp(() =>
                    transportRef.current.sendEnvelope(member.recipientId, new Uint8Array(ciphertext)),
                ).catch((e) => {
                    console.warn('sendEnvelope failed for group member', {
                        recipientId: member.recipientId,
                        error: e instanceof Error ? e.message : String(e),
                    });
                    throw e;
                }),
            ),
        );
        const sendTotal = sendOutcomes.length;
        const sendFailures = sendOutcomes.filter((o) => o.status === 'rejected').length;
        const sendStatus: GroupMessage['sendStatus'] =
            sendFailures === 0 ? 'sent' : sendFailures === sendTotal ? 'failed' : 'partial';
        const firstFailure = sendOutcomes.find((o) => o.status === 'rejected') as
            | PromiseRejectedResult
            | undefined;
        const failureMessage = firstFailure
            ? firstFailure.reason instanceof Error
                ? firstFailure.reason.message
                : String(firstFailure.reason)
            : undefined;
        setSendError(
            sendStatus === 'sent'
                ? null
                : sendStatus === 'partial'
                  ? `Sent to ${sendTotal - sendFailures} of ${sendTotal} members.`
                  : `Failed to send: ${failureMessage ?? 'relay unavailable'}`,
        );
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
                groupId: groupFingerprint(realMembers),
                sendStatus,
                sendFailures,
                sendTotal,
                sendError: failureMessage,
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
                                <div
                                    key={msg.id}
                                    data-testid={`message-${msg.id}`}
                                    data-group-id={msg.groupId}
                                    className="group-msg"
                                >
                                    {!msg.sentByMe && msg.senderLabel && (
                                        <span
                                            className="group-msg-sender"
                                            data-testid={`sender-${msg.id}`}
                                            title={msg.senderId}
                                        >
                                            {msg.senderLabel}
                                        </span>
                                    )}
                                    <p className="group-msg-text">{msg.plaintext}</p>
                                    {msg.sentByMe && msg.sendStatus && (
                                        <span
                                            className={`group-msg-status status-${msg.sendStatus}`}
                                            data-testid={`send-status-${msg.id}`}
                                            title={msg.sendError}
                                        >
                                            {msg.sendStatus === 'sent'
                                                ? 'sent'
                                                : msg.sendStatus === 'partial'
                                                  ? `sent to ${(msg.sendTotal ?? 0) - (msg.sendFailures ?? 0)} of ${msg.sendTotal ?? 0}`
                                                  : 'failed'}
                                        </span>
                                    )}
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
                    {sendError && (
                        <p className="group-warning group-send-error" role="alert">{sendError}</p>
                    )}
                </>
            )}
        </div>
    );
};
