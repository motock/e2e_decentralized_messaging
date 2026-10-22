import { useEffect, useRef, useState } from 'react';
import { group_create, group_add_member, group_remove_member, group_encrypt, group_decrypt, group_to_bytes, group_from_bytes, bundle_identity_key_bytes, IdentityHandle, GroupHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { StorageGate } from './storage';
import { getStorageKey } from './storage_key';
import { getRelayWsUrl, RelayTransport } from './relay_transport';
import type { GroupConversationProps, GroupTransport } from './GroupConversation';
import type { DeviceListEntry } from './Conversation';
import type { DiscoveryTransport } from './discovery';
import { resolveGroupRecipients, isWellFormedIdentityKey } from './group_recipients';

// The state machine and side effects behind GroupConversation.tsx: the Sender
// Keys group crypto calls (group_create/group_add_member/group_remove_member/
// group_encrypt/group_decrypt - core/bindings/wasm/src/lib.rs), StorageGate
// persistence/restore of membership AND ratchet state, the receive loop, and
// the send path. Extracted verbatim from the component so the component itself
// is presentation only; behavior, guards and user-facing strings are unchanged.
//
// Members are real peers, added by recipient ID. The hook looks up the peer's
// published prekey bundle via `lookupPrekey` (RelayTransport, same as direct
// messaging in Conversation.tsx), extracts the identity key with
// `bundle_identity_key_bytes`, and passes that real looked-up public key to
// `group_add_member`. There is no demo/local-identity member path: every chip
// in the member list is a relay-reachable peer.
//
// Group membership (the member list with recipient IDs and public keys) is
// persisted via the existing StorageGate pattern (encrypted IndexedDB), so it
// survives a page reload — matching how identity persistence already works in
// identity.ts.
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
// plaintext, and never logged. On reload the hook restores the session with
// group_from_bytes; only a record that predates ratchet persistence (no blob)
// falls back to replaying group_create + group_add_member, and a record whose
// blob is present but corrupt fails closed (no group is restored).

export interface GroupMessageResult {
    ok: boolean;
    error?: string;
}

export interface GroupMessage {
    id: string;
    plaintext: string;
    timestamp: number;
    // Retained-but-unpopulated legacy slot: nothing writes a real value any
    // more. The demo-member decrypt loop that was its only producer was
    // removed, and it cannot be repopulated for real peers - the app holds
    // only their public bundles, so it cannot decrypt as a member. It is kept
    // (rather than deleted) because it is part of the persisted GroupMessage
    // shape, so dropping the key would silently change a stored schema; both
    // writers now set `{}`.
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

/**
 * A real peer added by recipient ID. There is no local private key — only the
 * public identity key looked up from the relay. The `recipientId` is the
 * address the user typed; `publicBytes` is the identity key extracted from the
 * looked-up prekey bundle via `bundle_identity_key_bytes`.
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
    /**
     * Highest device-list version applied per account handle (GF-2).
     *
     * This is the durable monotonic floor for `resolveGroupRecipients`. It has
     * to survive a reload: without it every send starts at `null`, and a relay
     * replaying an older (validly signed) device list would resurrect a device
     * the user has revoked (§8.4). Absent in records written before GF-2.
     *
     * Stored as an array of `[handle, version]` pairs so it is JSON-serializable
     * and keeps its insertion order.
     */
    deviceListVersions?: Array<[string, number]>;
    /**
     * Device identity keys this client added to the group roster, as
     * `[accountHandle, identityKeyBytes]` pairs (GF-2).
     *
     * The roster is a key set with no enumeration API, so a key that is no
     * longer a recipient — a removed member's linked device, or a device the
     * account revoked — can only be evicted if we remember what we put there.
     * This is that record. It has to survive a reload for the same reason the
     * floor does: otherwise a device removed in one session stays in the
     * restored roster for the next one and keeps receiving wrappers.
     *
     * Absent in records written before this tracking existed.
     */
    rosterDeviceKeys?: Array<[string, number[]]>;
}

/** A roster identity key remembered so a later reconciliation can evict it. */
interface TrackedRosterKey {
    accountHandle: string;
    identityKey: Uint8Array;
}

/** Largest serialized group state accepted on restore (1 MiB). */
const MAX_GROUP_BLOB_LENGTH = 1048576;

/**
 * The wire format's cap on wrapper recipients in one group envelope.
 *
 * `GroupSession::encrypt_as` seals the per-message key to every identity key in
 * the roster, and the envelope carries one wrapper per recipient. Past this the
 * envelope cannot be encoded, so a send that would exceed it is refused with a
 * clear error instead of producing an undeliverable message.
 */
const MAX_GROUP_RECIPIENTS = 255;

/**
 * The discovery transport used when the caller injected none.
 *
 * It serves no lists, so every member resolves to its bare handle — the
 * resolver's documented fallback, and the pre-GF-2 addressing. It exists so
 * reconciliation can run unconditionally: the recipient-limit check and the
 * roster/floor persistence must not depend on a transport being supplied.
 */
const NO_DISCOVERY: DiscoveryTransport = {
    publishDiscovery: async () => {},
    lookupDiscovery: async () => null,
};

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

/**
 * Read the persisted device-list version floor, ignoring unusable entries.
 *
 * The floor is security-critical, so the failure modes are asymmetric: a
 * *missing* entry only means "no floor for that handle" (the resolver then
 * accepts whatever the relay serves, which is the pre-GF-2 behaviour), while a
 * *lowered* entry would let a replayed list through. So an unreadable record
 * contributes nothing rather than a guessed value, and a value that is not a
 * non-negative safe integer is dropped instead of being coerced — a `NaN` floor
 * would disable the replay guard entirely.
 *
 * The caller merges the result into the live floor with `Math.max`, so a
 * restored record can never lower a floor already held in memory.
 */
function validatedDeviceListVersions(raw: unknown): Map<string, number> {
    const versions = new Map<string, number>();
    if (!Array.isArray(raw)) return versions;
    for (const entry of raw) {
        if (!Array.isArray(entry) || entry.length !== 2) continue;
        const [handle, version] = entry as [unknown, unknown];
        if (typeof handle !== 'string' || handle.length === 0) continue;
        if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) continue;
        versions.set(handle, version);
    }
    return versions;
}

/**
 * Read the persisted tracked roster keys, dropping unusable entries.
 *
 * The tracked set only ever causes a key to be *removed* from the roster when
 * it is no longer a recipient, so a dropped entry is a missed eviction, not a
 * wrong one. A malformed key would be refused by `group_remove_member` anyway,
 * and passing arbitrary bytes to WASM is not worth the risk: validate the same
 * shape the resolver emits (33-byte, 0x05 Curve25519) and ignore the rest.
 */
function validatedRosterDeviceKeys(raw: unknown): TrackedRosterKey[] {
    const keys: TrackedRosterKey[] = [];
    if (!Array.isArray(raw)) return keys;
    for (const entry of raw) {
        if (!Array.isArray(entry) || entry.length !== 2) continue;
        const [handle, rawBytes] = entry as [unknown, unknown];
        if (typeof handle !== 'string' || handle.length === 0) continue;
        if (!Array.isArray(rawBytes) || !rawBytes.every(isByte)) continue;
        const bytes = new Uint8Array(rawBytes);
        if (!isWellFormedIdentityKey(bytes)) continue;
        keys.push({ accountHandle: handle, identityKey: bytes });
    }
    return keys;
}

const GROUP_STORE = 'session' as const;const GROUP_RECORD_ID = 'group-state';
const GROUP_MESSAGES_STORE = 'messages' as const;
const GROUP_MESSAGES_ID = 'group-messages';

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
 * The state machine and side effects behind `GroupConversation`. Returns the
 * state the component renders plus the handlers its controls call.
 */
/**
 * The arguments `useGroupConversation` accepts.
 *
 * The first four are the component's own props. `ownDevices` and `discovery`
 * are GF-2 additions and are deliberately *optional*: the component does not
 * pass them yet (wiring them through `GroupConversation.tsx` is out of this
 * story's scope), and with neither supplied the send path keeps its pre-GF-2
 * behaviour of addressing the roster as-is.
 */
export interface UseGroupConversationArgs
    extends Pick<GroupConversationProps, 'transport' | 'storageGate' | 'identity' | 'selfRecipientId'> {
    /**
     * The sender's own devices, as published in its own signed device list.
     *
     * Used to fan a group message out to the sender's *other* devices so they
     * can decrypt it too. Defaults to empty: with no list the sender simply
     * does not address itself.
     */
    ownDevices?: DeviceListEntry[];
    /**
     * Transport for signed device-list discovery (MD-9).
     *
     * `RelayTransport` satisfies it. When omitted, the resolver cannot look up
     * any member's device list, so every member falls back to its bare handle
     * and the send addresses the roster exactly as it did before GF-2.
     */
    discovery?: DiscoveryTransport;
    /**
     * The sender's own account handle (the discovery key its signed device list
     * is published under). Defaults to `selfRecipientId`, which is the account
     * handle this app uses (`App.tsx` passes `identity.recipientId` as the
     * account handle when publishing its own list).
     */
    ownAccountHandle?: string;
    /**
     * The device id this client is running as. Defaults to 0 (the primary),
     * which is the only device that can exist before device linking.
     */
    currentDeviceId?: number;
}

export function useGroupConversation({
    transport,
    storageGate,
    identity: identityProp,
    selfRecipientId,
    ownDevices,
    discovery,
    ownAccountHandle,
    currentDeviceId,
}: UseGroupConversationArgs) {
    const [ready, setReady] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selfIdentity, setSelfIdentity] = useState<InstanceType<typeof IdentityHandle> | null>(null);
    const [group, setGroup] = useState<InstanceType<typeof GroupHandle> | null>(null);
    const [realMembers, setRealMembers] = useState<RealMember[]>([]);
    // Real peers that were removed from the group but kept visible so the
    // user can re-add them.
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
    // GF-2: the durable monotonic floor for member device lists — the highest
    // version applied per account handle. Kept in a ref (not state) because it
    // is read and written inside the send path, never rendered, and must not
    // trigger a re-render mid-send. Persisted alongside the group state so a
    // reload cannot reset it to empty and let a replayed list through.
    const deviceListVersionsRef = useRef<Map<string, number>>(new Map());
    // GF-2: every device identity key this client added to the group roster,
    // keyed by hex so the set stays de-duplicated, together with the account it
    // belongs to so `removePeer` can purge that member's keys immediately. The
    // roster itself cannot be enumerated, so this tracked set is the only way
    // to evict a key that stops being a recipient (a removed member's linked
    // device, or a revoked device). Persisted alongside the group state; a
    // reload without it would leave those keys in the restored roster.
    const rosterDeviceKeysRef = useRef<Map<string, TrackedRosterKey>>(new Map());

    // GRP-6: when no transport is injected (the App-level wiring was scoped out
    // of this story), build the default transport tagged with THIS loop's
    // envelope kind so outgoing envelopes carry the out-of-band "group" tag and
    // the two receive loops stop consuming each other's mail. An injected
    // transport is used as-is (tests inject kindless mocks; a missing kind then
    // falls through to this loop's decrypt, which is the fail-closed policy).
    const transportRef = useRef<GroupTransport>(
        transport ?? new RelayTransport(getRelayWsUrl(), 'group'),
    );

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
    // re-subscribing the poll interval on every membership change. Every
    // member is a relay-addressed peer, so all of them are attribution
    // candidates.
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

    // GF-2: the sender's own devices and the discovery transport are read by
    // the send path only, so they live in refs kept fresh per render rather
    // than in the init effect's dependency list (which must stay identity-only).
    const ownDevicesRef = useRef<DeviceListEntry[]>(ownDevices ?? []);
    const discoveryRef = useRef<DiscoveryTransport | undefined>(discovery);
    const ownAccountHandleRef = useRef<string | undefined>(ownAccountHandle);
    const currentDeviceIdRef = useRef<number>(currentDeviceId ?? 0);
    useEffect(() => {
        ownDevicesRef.current = ownDevices ?? [];
        discoveryRef.current = discovery;
        ownAccountHandleRef.current = ownAccountHandle;
        currentDeviceIdRef.current = currentDeviceId ?? 0;
    }, [ownDevices, discovery, ownAccountHandle, currentDeviceId]);

    useEffect(() => {
        let cancelled = false;
        // Criterion 3 — fail closed. With no identity/selfRecipientId the group
        // view must not silently pretend to be connected: no throwaway
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
                setSelfIdentity(self);

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
                    // GF-2: restore the device-list version floor. Merged with
                    // `Math.max` so a restored record can never *lower* a floor
                    // already held in memory (an unreadable or stale record must
                    // not re-open the replay window).
                    const restoredVersions = validatedDeviceListVersions(
                        persisted?.deviceListVersions,
                    );
                    for (const [handle, version] of restoredVersions) {
                        const held = deviceListVersionsRef.current.get(handle);
                        if (held === undefined || version > held) {
                            deviceListVersionsRef.current.set(handle, version);
                        }
                    }
                    // GF-2: restore the tracked roster keys so a device removed
                    // before the reload can still be evicted from the restored
                    // blob. Merged rather than replaced: a key already tracked
                    // in this session is identical, and dropping it would lose
                    // the eviction record for the roster the blob carries.
                    for (const tracked of validatedRosterDeviceKeys(
                        persisted?.rosterDeviceKeys,
                    )) {
                        const hex = toHex(tracked.identityKey);
                        if (!rosterDeviceKeysRef.current.has(hex)) {
                            rosterDeviceKeysRef.current.set(hex, tracked);
                        }
                    }
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
                console.error('Failed to initialize group session', e);
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
            // GF-2: carry the device-list version floor forward. Without this
            // the floor would reset to empty on reload and a replayed older
            // (validly signed) list could resurrect a revoked device.
            if (deviceListVersionsRef.current.size > 0) {
                state.deviceListVersions = Array.from(deviceListVersionsRef.current.entries());
            }
            // GF-2: carry the tracked roster keys forward. Without them a
            // reload cannot tell which roster entries were added for a device
            // that is later removed, and the eviction never happens.
            if (rosterDeviceKeysRef.current.size > 0) {
                state.rosterDeviceKeys = Array.from(rosterDeviceKeysRef.current.values()).map(
                    (tracked) => [tracked.accountHandle, Array.from(tracked.identityKey)],
                );
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

                const picked = await runTransportOp(() =>
                    transportRef.current.pickupEnvelope(selfRecipientId!),
                );

                // ── Envelope-kind routing (GRP-6, out-of-band) ──────────────
                // The kind travels as a sibling field of the relay's
                // pickup_envelope op — never inside the ciphertext. Normalize
                // both pickup shapes: a bare Uint8Array (legacy mocks / no tag)
                // or a `{ envelope, kind }` result.
                const envelope: Uint8Array =
                    picked instanceof Uint8Array ? picked : picked.envelope;
                const envelopeKind: string | undefined = (picked as any).kind;
                // This is the GROUP loop. The transport already sent
                // `kind: 'group'` on the pickup op, so the relay keeps
                // direct-kind envelopes queued for the direct loop and this
                // branch should not fire against a filtering relay. It is kept
                // as a DEFENSIVE FALLBACK for a non-filtering peer (legacy
                // relay / mock): a known foreign kind ("direct") must not be
                // decrypted here, so we skip it without surfacing the tampered
                // warning. A missing or UNKNOWN kind FALLS THROUGH to this
                // loop's decrypt (fail closed = not silently misrouted, not
                // skipped).
                if (envelopeKind === 'direct') {
                    return; // foreign kind: leave for the owning loop
                }

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
        setRealMembers([]);
        setMessages([]);
        void persistGroupState([], newGroup);
    };

    // Add a real peer by recipient ID: look up their prekey bundle via the
    // relay transport, extract the identity key, and pass it to group_add_member.
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

    // Remove a real peer by recipient ID. Removing a member who was already
    // removed is a no-op (group_remove_member's core contract is infallible —
    // it simply doesn't match), not an error.
    const removePeer = (recipientId: string) => {
        if (!group) return;
        const member = realMembers.find((m) => m.recipientId === recipientId);
        if (!member) return; // already removed — no-op, not an error
        let updatedGroup = group_remove_member(group, member.publicBytes);
        // Evict the removed member's tracked device keys now. Leaving them for
        // the next send would keep a removed member's linked devices able to
        // decrypt that message; the send-time sweep is the second line of
        // defence, not the first. The sender's own key is never tracked, but
        // guard it explicitly so a corrupt persisted record cannot remove it.
        const selfPublicBytes = selfIdentity?.public_bytes();
        for (const [hex, tracked] of [...rosterDeviceKeysRef.current]) {
            if (tracked.accountHandle !== recipientId) continue;
            rosterDeviceKeysRef.current.delete(hex);
            if (selfPublicBytes && bytesEqual(tracked.identityKey, selfPublicBytes)) continue;
            updatedGroup = group_remove_member(updatedGroup, tracked.identityKey);
        }
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
        const selfPublicBytes = selfIdentity.public_bytes();

        // ── GF-2: reconcile the roster to the recipient device set ──────────
        // A group message is addressed per device, not per account: the sender
        // seals the per-message key to every identity key in the group roster,
        // so a device that is not in the roster gets no wrapper and cannot
        // decrypt, while a revoked device that is still in the roster keeps
        // receiving wrappers. The roster is therefore reconciled to the
        // resolved recipient set before every send.
        //
        // Reconciliation is UNCONDITIONAL. It must not be skipped just because
        // no discovery transport was injected: the recipient-limit check and
        // the roster/floor persistence are security-relevant regardless, and a
        // transport-less caller simply resolves every member to its bare
        // handle (the resolver's documented fallback).
        const discoveryTransport = discoveryRef.current;
        const ownHandle = ownAccountHandleRef.current ?? selfRecipientId ?? '';

        // A roster key that is not a well-formed 33-byte 0x05 identity key
        // cannot be looked up or addressed. Rather than failing the whole send
        // (which would make one bad roster entry a denial of service), such a
        // member is resolved as "no list available": it keeps its bare handle
        // and is reported in `unresolvedMembers`, exactly as a member with no
        // published list is.
        const resolvableMembers = realMembers.filter((member) =>
            isWellFormedIdentityKey(member.publicBytes),
        );
        const malformedMembers = realMembers.filter(
            (member) => !isWellFormedIdentityKey(member.publicBytes),
        );

        let resolved: Awaited<ReturnType<typeof resolveGroupRecipients>>;
        try {
            resolved = await resolveGroupRecipients({
                members: resolvableMembers.map((member) => ({
                    accountHandle: member.recipientId,
                    identityKey: member.publicBytes,
                })),
                ownDevices: ownDevicesRef.current
                    .filter((device) => isWellFormedIdentityKey(device.identityKey))
                    .map((device) => ({
                        deviceId: device.deviceId,
                        identityKey: device.identityKey,
                    })),
                ownAccountHandle: ownHandle,
                currentDeviceId: currentDeviceIdRef.current,
                ownIdentityKey: selfPublicBytes,
                discovery: discoveryTransport ?? NO_DISCOVERY,
                heldVersions: deviceListVersionsRef.current,
            });
        } catch (e) {
            // A bad held version or an ambiguous duplicate handle: fail closed
            // and send nothing rather than address a half-resolved fan-out.
            setError(
                `Could not resolve group recipients; message not sent: ${
                    e instanceof Error ? e.message : String(e)
                }`,
            );
            return;
        }

        // Members whose roster key is malformed still need an address, and the
        // resolver never saw them, so add their bare handle back here. They are
        // reported as unresolved, matching the resolver's own fallback.
        for (const member of malformedMembers) {
            resolved.recipients.push({
                accountHandle: member.recipientId,
                deviceId: 0,
                identityKey: member.publicBytes,
                address: member.recipientId,
            });
            resolved.unresolvedMembers.push(member.recipientId);
        }

        // The wire format caps a group at 255 wrapper recipients. Exceeding it
        // would produce an envelope the relay (and every recipient) rejects, so
        // refuse before anything is encrypted, persisted, or sent.
        if (resolved.recipients.length > MAX_GROUP_RECIPIENTS) {
            setError(
                `Group has ${resolved.recipients.length} recipient devices, which exceeds the ` +
                    `${MAX_GROUP_RECIPIENTS}-recipient limit; message not sent.`,
            );
            return;
        }

        // ── Merge the applied versions into the durable floor ───────────────
        // Monotonic per handle: keep the greater of the floor already held and
        // the version just applied. A resolution can never lower a floor, and
        // handles this resolution did not touch keep their existing entry.
        const mergedHeldVersions = new Map(deviceListVersionsRef.current);
        for (const [handle, version] of resolved.appliedVersions) {
            const held = mergedHeldVersions.get(handle);
            if (held === undefined || version > held) {
                mergedHeldVersions.set(handle, version);
            }
        }
        // One snapshot for both the in-memory ref and persistence, so the two
        // can never diverge.
        deviceListVersionsRef.current = mergedHeldVersions;

        // ── Reconcile the group handle's roster to those keys ───────────────
        // `group_add_member` appends a key and `group_remove_member` removes one
        // (rotating the chain key), so the handle is brought in line with the
        // recipient set before it encrypts.
        let reconciled = group;
        const rosterKeys: Uint8Array[] = [selfPublicBytes, ...realMembers.map((m) => m.publicBytes)];
        const hasKey = (key: Uint8Array) => rosterKeys.some((existing) => bytesEqual(existing, key));
        const isRecipient = (key: Uint8Array) =>
            resolved.recipients.some((recipient) => bytesEqual(recipient.identityKey, key));

        // Work on a copy of the tracked set and commit it only once the
        // reconciled roster has been persisted. The group handle is pure
        // (`group_add_member`/`group_remove_member` return a clone), so a failed
        // persist leaves the in-memory roster unchanged and still holding the
        // evicted keys; dropping their tracking entries here would leave them
        // in the roster forever, since only a tracked key can ever be evicted.
        const previousTrackedRosterKeys = rosterDeviceKeysRef.current;
        const trackedRosterKeys = new Map(previousTrackedRosterKeys);
        rosterDeviceKeysRef.current = trackedRosterKeys;

        try {
            for (const recipient of resolved.recipients) {
                if (hasKey(recipient.identityKey)) continue;
                reconciled = group_add_member(reconciled, recipient.identityKey);
                rosterKeys.push(recipient.identityKey);
            }

            // Track every recipient device key currently in the roster, so a
            // later send can evict it once it stops being a recipient. The
            // roster has no enumeration API, so an untracked key can never be
            // removed. The sender's own key is deliberately not tracked: it
            // must never be evicted.
            for (const recipient of resolved.recipients) {
                if (bytesEqual(recipient.identityKey, selfPublicBytes)) continue;
                const hex = toHex(recipient.identityKey);
                if (!trackedRosterKeys.has(hex)) {
                    trackedRosterKeys.set(hex, {
                        accountHandle: recipient.accountHandle,
                        identityKey: recipient.identityKey,
                    });
                }
            }

            // Evict every tracked key that is no longer a recipient — a linked
            // device of a removed member, or a device its account revoked.
            // Without this the key stays in the roster and keeps receiving a
            // wrapper for every message, so the device can still decrypt.
            for (const [hex, tracked] of [...trackedRosterKeys]) {
                if (bytesEqual(tracked.identityKey, selfPublicBytes)) {
                    trackedRosterKeys.delete(hex);
                    continue;
                }
                if (isRecipient(tracked.identityKey)) continue;
                reconciled = group_remove_member(reconciled, tracked.identityKey);
                const index = rosterKeys.findIndex((key) =>
                    bytesEqual(key, tracked.identityKey),
                );
                if (index >= 0) rosterKeys.splice(index, 1);
                trackedRosterKeys.delete(hex);
            }

            // Remove every member-account key that is no longer a recipient (a
            // revoked or removed device). The sender's own key is never
            // removed: `group_create(self)` put it there and the sender must
            // stay able to decrypt its own group.
            for (const member of realMembers) {
                if (bytesEqual(member.publicBytes, selfPublicBytes)) continue;
                if (!hasKey(member.publicBytes)) continue;
                if (isRecipient(member.publicBytes)) continue;
                reconciled = group_remove_member(reconciled, member.publicBytes);
                const index = rosterKeys.findIndex((key) => bytesEqual(key, member.publicBytes));
                if (index >= 0) rosterKeys.splice(index, 1);
            }
        } catch (e) {
            // Reconciliation could not be completed: fail closed rather than
            // encrypt against a roster that does not match the recipient set.
            // The handle is unchanged, so keep the tracking that matches it.
            rosterDeviceKeysRef.current = previousTrackedRosterKeys;
            setError(
                `Could not reconcile the group roster; message not sent: ${
                    e instanceof Error ? e.message : String(e)
                }`,
            );
            return;
        }

        // ── Persist the reconciled roster AND the floor BEFORE encrypting ───
        // A skipped ratchet step is safe; a reused message key is not, and a
        // floor that was applied but never saved would let a replayed list
        // through on the next send. A failed save aborts the send.
        if (!(await persistGroupState(realMembers, reconciled))) {
            // The reconcile was not saved either, so `group` still carries the
            // old roster: roll the tracking back with it.
            rosterDeviceKeysRef.current = previousTrackedRosterKeys;
            setError('Could not save session state; message not sent');
            return;
        }

        const plaintextBytes = new TextEncoder().encode(input);
        let ciphertext: Uint8Array;
        try {
            ciphertext = group_encrypt(reconciled, selfIdentity, plaintextBytes);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            return;
        }
        setGroup(reconciled);
        // The ratchet advanced on encrypt, so re-persist the new position. The
        // roster and floor were already written above; this second write keeps
        // the blob in step with the ciphertext that is about to leave.
        if (!(await persistGroupState(realMembers, reconciled))) {
            setError('Could not save session state; message not sent');
            return;
        }
        // Deliver the ciphertext to every real group member via sendEnvelope
        // over the relay, addressed by each member's recipient ID — mirroring
        // Conversation.tsx's send path.
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
        setMessages((prev) => [
            ...prev,
            {
                id: Math.random().toString(36).slice(2),
                plaintext: input,
                timestamp: Date.now(),
                decryptResults: {},
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

    return {
        ready,
        error,
        group,
        realMembers,
        removedRealMembers,
        messages,
        input,
        setInput,
        peerIdInput,
        setPeerIdInput,
        addingPeer,
        peerError,
        decryptionWarning,
        sendError,
        createGroup,
        addPeer,
        removePeer,
        reAddPeer,
        send,
    };
}
