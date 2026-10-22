/**
 * Group member → per-device recipient resolution (GF-1).
 *
 * A group message is addressed to a mailbox per device, not per account: the
 * primary (device 0) is reachable at the bare account handle and each linked
 * device at `${handle}:${deviceId}` (MD-17a/17b). This module turns the group's
 * member list into that flat recipient list, using each member's *verified*
 * signed device list (MD-9) to discover its linked devices.
 *
 * Security properties:
 *  - **Only verified identities are emitted.** A member's devices come from
 *    `lookupDeviceList`, which verifies the signed list against the member's
 *    account identity key and throws on tampered, foreign-signed, or malformed
 *    bytes. Nothing from an unverified blob is ever returned to the caller.
 *  - **Partial coverage is explicit, not silent.** A member with no published
 *    list — and no cached contents — or whose list fails verification or
 *    lookup still gets a single recipient at its bare handle (the primary is
 *    reachable; linked devices are not) and is reported in `unresolvedMembers`
 *    so the caller can surface the gap. One member's failure never fails the
 *    whole send.
 *  - **A cached verified list beats no list.** When `lookupDeviceList` returns
 *    null (no list, a lookup failure, or a version no newer than the floor),
 *    the caller's cached contents for that handle are used instead. The floor
 *    makes every unchanged list "not newer", so without the cache a member's
 *    linked devices would drop out of the fan-out on every send after the
 *    first. Cached keys are shape-checked again before they are emitted; only
 *    unverified bytes are never used, and none are in this path.
 *  - **Fail closed on malformed input.** Every identity key must be exactly 33
 *    bytes with the `0x05` Curve25519 type byte, and every account handle must
 *    pass the shared handle rules (non-empty, ≤64 chars, no C0/C1/bidi/
 *    zero-width characters) *and* must not contain the `:` address separator.
 *    All of it is checked before any lookup is attempted.
 *  - **Unambiguous addresses.** Because a handle can never contain `:`, the
 *    `${handle}:${deviceId}` encoding cannot collide with another account's
 *    bare handle, so a hostile member handle cannot shadow (and thereby
 *    suppress) a real linked-device mailbox in the de-duplication step.
 *  - **Monotonic device lists.** The caller's held versions are passed through
 *    to `lookupDeviceList`, so a replayed stale list cannot resurrect a revoked
 *    device (§8.4). The effective floor for a handle is the *higher* of the
 *    caller's held version and any version already applied in this call, so a
 *    repeated handle can never be walked backwards. The versions actually
 *    applied are returned in `appliedVersions` so the caller can persist a
 *    durable floor: a floor that lives only for one call restarts at `null` on
 *    the next send, and a relay replaying an older (validly signed) list would
 *    then resurrect a device the user has revoked.
 *  - **A floor is never silently disabled.** Every caller-supplied
 *    `heldVersions` value must be a non-negative safe integer. A `NaN` (or
 *    negative, or fractional) value would make every `version <= floor`
 *    comparison false — i.e. accept *any* list, including a replayed one — so
 *    it is rejected outright rather than coerced.
 *  - **List-derived devices are validated too.** A verified list is only as
 *    trustworthy as the codec that decoded it; a device whose identity key is
 *    not a 33-byte `0x05` key, or whose device id is not a u32, makes the whole
 *    list unusable. Such a list is reported (and the member falls back to its
 *    bare handle) rather than emitting a key that could never decrypt.
 *  - **One handle, one account.** A roster that names the same handle twice
 *    with *different* identity keys is ambiguous — the first-wins de-dupe would
 *    silently drop the genuine account — so it fails closed.
 *  - **Canonical handles.** Handles are trimmed before use, so the handles in
 *    the returned recipients are canonical even if the caller's roster is not;
 *    callers matching recipients back to roster entries should compare against
 *    the trimmed form. Trimming happens *before* the duplicate-handle check, so
 *    `"alice"` and `" alice "` are recognised as the same account.
 *  - **The fallback path emits the roster key.** When a member's list is
 *    missing or unusable, the single recipient emitted for it carries the
 *    identity key from the caller's roster — the key the group handle was built
 *    with — not a key taken from any list. That is what keeps the fallback
 *    addressable by the existing roster.
 *  - **No sensitive data in logs.** Only a pseudonymous correlation id for a
 *    handle (a 32-bit FNV-1a digest — stable enough to tie one send's log lines
 *    together, and not a handle), a coarse reason code, and an error *class* are
 *    logged; account handles, identity keys, prekey bundles, and list bytes
 *    never are.
 */

import { lookupDeviceList, type DiscoveryTransport } from './discovery';

/** A group member, identified by its account (device 0) identity key. */
export interface GroupMemberAccount {
    accountHandle: string;
    identityKey: Uint8Array;
}

/** One of the sender's own devices, as published in its own signed list. */
export interface OwnDevice {
    deviceId: number;
    identityKey: Uint8Array;
}

/** A single mailbox recipient: one device of one account. */
export interface GroupDeviceRecipient {
    accountHandle: string;
    deviceId: number;
    identityKey: Uint8Array;
    /** Bare handle for device 0, `${handle}:${deviceId}` for linked devices. */
    address: string;
}

/** The resolved fan-out, plus the members only partially covered. */
export interface ResolvedGroupRecipients {
    recipients: GroupDeviceRecipient[];
    /** Handles that fell back to the bare primary address. */
    unresolvedMembers: string[];
    /**
     * The device-list version applied for each handle in this call.
     *
     * Callers must persist these as a durable monotonic floor and pass them
     * back as `heldVersions` on the next resolution. Without that, every send
     * starts at `null` and a relay replaying an older (validly signed) list can
     * resurrect a device the user has revoked (§8.4).
     *
     * A handle whose list was absent, stale, or unusable has no entry: there is
     * no new version to record, and the caller's existing floor for it must be
     * left exactly as it was.
     */
    appliedVersions: Map<string, number>;
    /**
     * The verified device list contents applied for each handle in this call.
     *
     * Callers should cache these beside the version floor and pass them back as
     * `heldLists`. `lookupDeviceList` returns null for a list no newer than the
     * floor, so without the contents every send after the first would resolve
     * the member to its bare primary and the linked devices would be dropped
     * from the roster even though nothing changed.
     */
    appliedLists: Map<string, HeldDeviceList>;
}

/** A verified device list's usable contents. */
export interface HeldDeviceList {
    version: number;
    devices: Array<{ deviceId: number; identityKey: Uint8Array }>;
}

/** Arguments for {@link resolveGroupRecipients}. */
export interface ResolveGroupRecipientsArgs {
    members: GroupMemberAccount[];
    ownDevices: OwnDevice[];
    ownAccountHandle: string;
    /** The device this client is running as; excluded from the fan-out. */
    currentDeviceId: number;
    /**
     * The sender's own account (device 0) identity key, when known.
     *
     * Used to recognise a roster entry that *is* the sender's own account: a
     * member whose handle equals `ownAccountHandle` **and** whose identity key
     * equals this key. Only such a member has `currentDeviceId` excluded from
     * its devices — otherwise the sender would address a wrapper to the mailbox
     * it is already reading. A roster entry that merely reuses the sender's
     * handle with a different key is a different account and is left untouched.
     */
    ownIdentityKey?: Uint8Array;
    discovery: DiscoveryTransport;
    /**
     * Highest device-list version already applied, per account handle.
     *
     * Passed straight through to `lookupDeviceList` as its monotonic floor, so
     * a relay replaying an older (but validly signed) list cannot resurrect a
     * device the user has revoked. Within one call the effective floor for a
     * handle is the higher of this map's entry and any version already applied
     * for that handle, so a repeated handle can never be walked backwards.
     *
     * The map is never mutated. The versions this call applies are returned in
     * {@link ResolvedGroupRecipients.appliedVersions}; callers persist those to
     * make the floor durable across sends.
     *
     * Every value must be a non-negative safe integer. A `NaN` (or negative, or
     * fractional) value is rejected with a throw: treated as a floor it would
     * make every `version <= floor` comparison false and accept *any* list,
     * silently disabling the replay guard.
     */
    heldVersions?: ReadonlyMap<string, number>;
    /**
     * The last verified device list contents per account handle.
     *
     * Used when `lookupDeviceList` returns null — the relay served no list, the
     * lookup failed, or the served version is no newer than the floor. Those
     * contents are the best known truth for the handle, so the member keeps its
     * linked devices instead of silently falling back to the bare primary on
     * every send after the first. A handle with no cached contents keeps the
     * documented bare-primary fallback and is reported in `unresolvedMembers`.
     */
    heldLists?: ReadonlyMap<string, HeldDeviceList>;
}

/** Length of a serialized identity public key. */
const IDENTITY_KEY_LEN = 33;
/** Type byte of a serialized Curve25519 identity public key (see `link_new_device.ts`). */
const IDENTITY_KEY_TYPE_BYTE = 0x05;
/** Longest account handle accepted; mirrors `link_new_device.ts`. */
const MAX_ACCOUNT_HANDLE_LENGTH = 64;
/** Separator between a handle and a linked device id in a mailbox address. */
const ADDRESS_SEPARATOR = ':';
/**
 * Characters that must never reach a mailbox address or a log line.
 *
 * Mirrors `FORBIDDEN_HANDLE_CHARS` in `link_new_device.ts`: C0/C1 controls
 * (terminal escapes, XSS vectors), bidi marks/embeddings/isolates (which
 * reorder rendered text), zero-width characters (which make distinct handles
 * render identically), line/paragraph separators, and U+FEFF.
 */
const FORBIDDEN_HANDLE_CHARS =
    /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u2029\u202a-\u202e\u2066-\u2069\ufeff]/;

/**
 * Why a member fell back to its bare handle.
 *
 * `no-fresh-list` covers both "the relay holds no list" and "the list it holds
 * is not newer than the floor" — `lookupDeviceList` returns `null` for both and
 * the resolver cannot tell them apart without a second lookup.
 */
type UnresolvedReason = 'no-fresh-list' | 'verification-failed';

/** Mailbox address for one device of `handle` (MD-17a/17b). */
function deviceAddress(handle: string, deviceId: number): string {
    return deviceId === 0 ? handle : `${handle}${ADDRESS_SEPARATOR}${deviceId}`;
}

/**
 * Validate an account handle and return its canonical (trimmed) form.
 *
 * The rules mirror `validateAccountHandle` in `link_new_device.ts` — that
 * helper is module-private, so the rules are restated here rather than
 * duplicated by import — plus one addition: the `:` address separator is
 * rejected outright. Without that, a member registered as `alice:5` would
 * produce the address `alice:5` for its own device 0, which is byte-identical
 * to alice's real device-5 mailbox; the "first wins" de-duplication would then
 * drop alice's genuine recipient and route the attacker's ciphertext to her
 * linked device.
 *
 * The message names only the structural failure — never the handle itself.
 *
 * The returned handle is the trimmed input, so callers see the canonical form.
 */
function assertAccountHandle(value: unknown, role: string): string {
    if (typeof value !== 'string') {
        throw new Error(`group recipients: ${role} account handle must be a string`);
    }
    const handle = value.trim();
    if (handle.length === 0) {
        throw new Error(`group recipients: ${role} account handle must not be empty`);
    }
    if (handle.length > MAX_ACCOUNT_HANDLE_LENGTH) {
        throw new Error(
            `group recipients: ${role} account handle must be at most ${MAX_ACCOUNT_HANDLE_LENGTH} characters`,
        );
    }
    if (FORBIDDEN_HANDLE_CHARS.test(handle)) {
        throw new Error(`group recipients: ${role} account handle contains a forbidden character`);
    }
    if (handle.includes(ADDRESS_SEPARATOR)) {
        throw new Error(
            `group recipients: ${role} account handle must not contain "${ADDRESS_SEPARATOR}"`,
        );
    }
    return handle;
}

/**
 * Reject any identity key that is not a 33-byte, `0x05`-tagged public key.
 *
 * The type-byte check matches `link_new_device.ts` so the boundary behaves the
 * same everywhere; a key that fails it could never verify a device list anyway.
 * The message names only the structural failure — never the key itself.
 */
function assertIdentityKey(identityKey: Uint8Array, role: string): void {
    if (!(identityKey instanceof Uint8Array) || identityKey.length !== IDENTITY_KEY_LEN) {
        throw new Error(`group recipients: ${role} identity key must be ${IDENTITY_KEY_LEN} bytes`);
    }
    if (identityKey[0] !== IDENTITY_KEY_TYPE_BYTE) {
        throw new Error(
            `group recipients: ${role} identity key must be a Curve25519 public key (0x05 prefix)`,
        );
    }
}

/** Reject a device id that is not a u32. */
function assertDeviceId(deviceId: number, role: string): void {
    if (!Number.isInteger(deviceId) || deviceId < 0 || deviceId > 0xffffffff) {
        throw new Error(`group recipients: ${role} device id must be an unsigned 32-bit integer`);
    }
}

/**
 * Reject a held device-list version that is not a non-negative safe integer.
 *
 * A `NaN` floor is the dangerous case: `version <= NaN` is always false, so
 * `lookupDeviceList` would accept *every* list it is served — including a
 * replayed older one — and the replay guard would be silently off. A negative
 * or fractional value is equally meaningless as a version, so all three are
 * rejected rather than coerced to something plausible.
 */
function assertHeldVersion(version: unknown): void {
    if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) {
        throw new Error(
            'group recipients: held device-list version must be a non-negative safe integer',
        );
    }
}

/**
 * True when `identityKey` is a well-formed serialized Curve25519 identity key.
 *
 * Used for keys that come out of a *verified* device list. Verification proves
 * the list was signed by the account, not that every entry decodes to a usable
 * key, so the shape is re-checked here before the key is emitted.
 */
export function isWellFormedIdentityKey(identityKey: unknown): identityKey is Uint8Array {
    return (
        identityKey instanceof Uint8Array &&
        identityKey.length === IDENTITY_KEY_LEN &&
        identityKey[0] === IDENTITY_KEY_TYPE_BYTE
    );
}

/** True when `deviceId` is a u32. */
function isU32(deviceId: unknown): deviceId is number {
    return typeof deviceId === 'number' && Number.isInteger(deviceId) && deviceId >= 0 && deviceId <= 0xffffffff;
}

/** Byte-wise equality for two identity keys. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Non-reversible reference to a handle, for logs.
 *
 * CLAUDE.md forbids PII in logs, and a handle is user-visible identity. A
 * 32-bit FNV-1a digest is enough to correlate the log lines of one send without
 * writing the handle itself.
 */
function handleRef(handle: string): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < handle.length; i += 1) {
        hash ^= handle.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return `h${hash.toString(16).padStart(8, '0')}`;
}

/**
 * Resolve a group's members into per-device mailbox recipients.
 *
 * Members are emitted in input order, each member's devices in the order its
 * signed list carries them, followed by the sender's own other devices. The
 * output is never sorted, and duplicate addresses are dropped (first wins).
 *
 * @throws if any member or own-device identity key is not a 33-byte `0x05`
 *   key, or if any handle is empty, too long, contains a forbidden character,
 *   or contains the `:` address separator. Lookup and verification failures do
 *   not throw: they degrade to the member's bare handle and are reported in
 *   `unresolvedMembers`.
 * @throws if any `heldVersions` value is not a non-negative safe integer, or if
 *   the same (trimmed) handle appears twice with different identity keys.
 */
export async function resolveGroupRecipients({
    members,
    ownDevices,
    ownAccountHandle,
    currentDeviceId,
    ownIdentityKey,
    discovery,
    heldVersions,
    heldLists,
}: ResolveGroupRecipientsArgs): Promise<ResolvedGroupRecipients> {
    // Validate the whole input before doing any I/O: a malformed key or handle
    // must not leave the caller with a half-resolved fan-out, and an ambiguous
    // handle must never reach the address encoder.
    const ownHandle = assertAccountHandle(ownAccountHandle, 'own');
    assertDeviceId(currentDeviceId, 'current');
    const memberHandles = members.map((member) => {
        assertIdentityKey(member.identityKey, 'member');
        return assertAccountHandle(member.accountHandle, 'member');
    });
    for (const device of ownDevices) {
        assertIdentityKey(device.identityKey, 'own-device');
        assertDeviceId(device.deviceId, 'own-device');
    }
    // A floor that is not a non-negative safe integer would disable the replay
    // guard (see `assertHeldVersion`), so it is rejected before any lookup.
    if (heldVersions) {
        for (const version of heldVersions.values()) {
            assertHeldVersion(version);
        }
    }
    // One handle must name one account. Two roster entries with the same
    // (trimmed) handle but different identity keys are ambiguous: the
    // first-wins address de-dupe would silently drop the genuine account and
    // route its ciphertext to whoever was listed first. Fail closed instead.
    const keyByHandle = new Map<string, Uint8Array>();
    for (const [index, handle] of memberHandles.entries()) {
        const previous = keyByHandle.get(handle);
        if (previous === undefined) {
            keyByHandle.set(handle, members[index].identityKey);
            continue;
        }
        if (!bytesEqual(previous, members[index].identityKey)) {
            throw new Error(
                'group recipients: the same member account handle appears with different identity keys',
            );
        }
    }

    const recipients: GroupDeviceRecipient[] = [];
    const unresolvedMembers: string[] = [];
    const seenAddresses = new Set<string>();
    // Versions applied in this call, so a repeated handle cannot be walked
    // backwards within a single resolution.
    const appliedVersions = new Map<string, number>();
    const appliedLists = new Map<string, HeldDeviceList>();

    const emit = (recipient: GroupDeviceRecipient): void => {
        if (seenAddresses.has(recipient.address)) return;
        seenAddresses.add(recipient.address);
        recipients.push(recipient);
    };
    const emitDevices = (
        handle: string,
        member: GroupMemberAccount,
        devices: ReadonlyArray<{ deviceId: number; identityKey: Uint8Array }>,
    ): void => {
        // A member whose handle is the sender's own account handle *and* whose
        // identity key is the sender's own account key is the sender's own
        // account (a self-add, or a roster that lists the sender). Its devices
        // are the sender's devices, so the device this client is running as
        // must be excluded here too — otherwise the sender would address a
        // wrapper to itself at the mailbox it is already reading. A roster
        // entry that merely reuses the sender's handle with a different key is
        // a different account and keeps all of its devices.
        const isOwnAccount =
            handle === ownHandle &&
            ownIdentityKey !== undefined &&
            bytesEqual(ownIdentityKey, member.identityKey);
        for (const device of devices) {
            if (isOwnAccount && device.deviceId === currentDeviceId) continue;
            emit({
                accountHandle: handle,
                deviceId: device.deviceId,
                identityKey: device.identityKey,
                address: deviceAddress(handle, device.deviceId),
            });
        }
    };

    for (const [index, member] of members.entries()) {
        const handle = memberHandles[index];
        // The floor is the *highest* version we know of for this handle: a
        // caller-supplied version must never shadow a higher version already
        // applied in this call, or a replayed older list would be accepted and
        // resurrect a device revoked by the newer one (§8.4).
        const floor = Math.max(
            heldVersions?.get(handle) ?? -1,
            appliedVersions.get(handle) ?? -1,
        );
        const heldVersion = floor < 0 ? null : floor;

        let verified: Awaited<ReturnType<typeof lookupDeviceList>> = null;
        let reason: UnresolvedReason = 'no-fresh-list';
        try {
            verified = await lookupDeviceList(discovery, handle, member.identityKey, heldVersion);
        } catch (error) {
            // Tampered, foreign-signed, or malformed bytes — and relay failures.
            // The error is deliberately not rethrown: the primary is still
            // reachable, and the caller learns about the gap via
            // `unresolvedMembers`. Only the error *class* is logged: a message
            // is not guaranteed to be free of list-derived detail.
            reason = 'verification-failed';
            console.warn('group recipients: member device list failed verification', {
                handleRef: handleRef(handle),
                reason,
                errorClass: error instanceof Error ? error.constructor.name : typeof error,
            });
        }

        if (verified === null) {
            // No list, a list no newer than the floor, or a failed
            // verification. The cached contents are the last list this handle
            // verified, so prefer them: falling back to the bare primary would
            // drop every linked device on each send whose list is unchanged.
            const cached = heldLists?.get(handle);
            const cachedUsable =
                cached !== undefined &&
                cached.devices.length > 0 &&
                cached.devices.every(
                    (device) =>
                        isWellFormedIdentityKey(device.identityKey) && isU32(device.deviceId),
                );
            if (cachedUsable) {
                emitDevices(handle, member, cached.devices);
                continue;
            }

            // Nothing cached either: fall back to the bare handle rather than
            // silently dropping the member. The primary is still reachable; its
            // linked devices are not, and the caller can surface that.
            emit({
                accountHandle: handle,
                deviceId: 0,
                identityKey: member.identityKey,
                address: handle,
            });
            unresolvedMembers.push(handle);
            console.warn('group recipients: member device list unavailable; using primary handle', {
                handleRef: handleRef(handle),
                reason,
            });
            continue;
        }

        appliedVersions.set(handle, verified.version);

        const devices = verified.deviceList.devices;
        if (devices.length === 0) {
            // A verified list that names no devices: fall back to the bare
            // handle rather than silently dropping the member.
            emit({
                accountHandle: handle,
                deviceId: 0,
                identityKey: member.identityKey,
                address: handle,
            });
            unresolvedMembers.push(handle);
            console.warn('group recipients: member device list names no devices; using primary handle', {
                handleRef: handleRef(handle),
                reason: 'no-fresh-list',
            });
            continue;
        }

        // Verification proves the list was signed by the account; it does not
        // prove every entry decodes to a usable key. A single malformed device
        // makes the whole list unusable — emitting a key that is not a 33-byte
        // 0x05 Curve25519 key would put an undecryptable wrapper in the roster
        // and, worse, could displace the genuine device at that address. Report
        // the member as partially covered and fall back to its roster key.
        const malformed = devices.find(
            (device) => !isWellFormedIdentityKey(device.identityKey) || !isU32(device.deviceId),
        );
        if (malformed !== undefined) {
            emit({
                accountHandle: handle,
                deviceId: 0,
                identityKey: member.identityKey,
                address: handle,
            });
            unresolvedMembers.push(handle);
            console.warn('group recipients: member device list contains a malformed device', {
                handleRef: handleRef(handle),
                reason: 'verification-failed',
            });
            continue;
        }

        appliedLists.set(handle, {
            version: verified.version,
            devices: devices.map((device) => ({
                deviceId: device.deviceId,
                identityKey: device.identityKey,
            })),
        });
        emitDevices(handle, member, devices);
    }

    for (const device of ownDevices) {
        if (device.deviceId === currentDeviceId) continue;
        emit({
            accountHandle: ownHandle,
            deviceId: device.deviceId,
            identityKey: device.identityKey,
            address: deviceAddress(ownHandle, device.deviceId),
        });
    }

    return { recipients, unresolvedMembers, appliedVersions, appliedLists };
}

// ── GF-3: fan the one ciphertext out to every recipient device ──────────────

/** One member's device addresses, in the order they were resolved. */
export interface GroupMemberFanout {
    accountHandle: string;
    /** De-duplicated device addresses for this member, primary first. */
    addresses: string[];
}

/** The per-device send plan derived from a resolved recipient set. */
export interface GroupFanoutPlan {
    /**
     * Every distinct device address to deliver to, in first-seen order.
     *
     * A group envelope carries ONE ciphertext: the per-message key is wrapped
     * separately for each roster identity key, so the same bytes are delivered
     * to every device mailbox. The relay keys its tag map by
     * `(recipient_id, envelope hash)`, so N deliveries of identical bytes stay
     * independent.
     */
    addresses: string[];
    /** The same addresses grouped by member, for per-member outcome reporting. */
    members: GroupMemberFanout[];
}

/**
 * Turn a resolved recipient set into the per-device send plan.
 *
 * Addresses are de-duplicated (first wins) because a member can legitimately
 * appear twice — the resolver de-dupes its own output, but a caller that
 * appends a fallback recipient for a malformed roster key does not, and a
 * duplicate delivery would double-count in the outcome. Members are keyed by
 * `accountHandle`, so a member's devices are always reported together.
 */
export function planGroupFanout(
    recipients: ReadonlyArray<GroupDeviceRecipient>,
): GroupFanoutPlan {
    const addresses: string[] = [];
    const seen = new Set<string>();
    const members: GroupMemberFanout[] = [];
    const byHandle = new Map<string, GroupMemberFanout>();

    for (const recipient of recipients) {
        if (seen.has(recipient.address)) continue;
        seen.add(recipient.address);
        addresses.push(recipient.address);

        let member = byHandle.get(recipient.accountHandle);
        if (member === undefined) {
            member = { accountHandle: recipient.accountHandle, addresses: [] };
            byHandle.set(recipient.accountHandle, member);
            members.push(member);
        }
        member.addresses.push(recipient.address);
    }

    return { addresses, members };
}

/** How one member's devices fared: every device, some, or none. */
export type GroupMemberSendStatus = 'sent' | 'partial' | 'failed';

/** The result of one device delivery. */
export interface GroupDeviceSendResult {
    address: string;
    ok: boolean;
    error?: unknown;
}

/** The aggregate outcome of a fan-out, in the shape `GroupMessage` records. */
export interface GroupFanoutOutcome {
    /**
     * `sent` when every device of every real member was delivered to, `failed`
     * when no device of any real member was, `partial` otherwise.
     *
     * This is counted per DEVICE, not per member: a member with two devices and
     * one failure is `partial`, not `sent` (its second device never got the
     * message) and not `failed` (its first device did). The sender's own
     * devices are delivered to but are not members, so they never affect this
     * status.
     */
    sendStatus: GroupMemberSendStatus;
    /** Real members with at least one failed device. */
    sendFailures: number;
    /** Real members addressed, not devices. Excludes the sender's own handle. */
    sendTotal: number;
    /** The first device failure's message, for the user-facing error copy. */
    failureMessage?: string;
    /**
     * Members that were only reachable at their primary device because their
     * signed device list could not be used (`unresolvedMembers`). Their linked
     * devices were not addressed, so the send is not full coverage for them.
     */
    primaryOnlyMembers: string[];
}

/**
 * Deliver one ciphertext to every device address in `plan`, then summarise.
 *
 * The ciphertext is encrypted ONCE by the caller and passed to every device
 * unchanged (a fresh copy per send, so a transport that transfers or mutates
 * its buffer cannot corrupt the others). Nothing here re-encrypts or
 * re-persists: the ratchet advanced once, before the fan-out.
 *
 * Deliveries are awaited together and failures are collected per device rather
 * than thrown: one device's relay failure must not be reported as a blanket
 * failure of a send that did reach the others, and a rejected delivery must
 * not be counted as a success either.
 */
export async function fanOutGroupCiphertext(args: {
    plan: GroupFanoutPlan;
    ciphertext: Uint8Array;
    /** Deliver `ciphertext` to one device mailbox. */
    send: (address: string, ciphertext: Uint8Array) => Promise<void>;
    /** Called once per failed device, for logging. Never receives key bytes. */
    onDeviceFailure?: (result: GroupDeviceSendResult) => void;
    /** Handles reported by the resolver as primary-only. */
    unresolvedMembers?: ReadonlyArray<string>;
    /**
     * The sender's own account handle.
     *
     * The resolver emits the sender's *other* devices as recipients with
     * `accountHandle = ownAccountHandle`, so they are delivery targets but not
     * group members. Excluding them from the member counts keeps `sendTotal`
     * equal to the number of real members (the UI renders "sent to X of Y") and
     * stops a failure of the sender's own second device from being reported as
     * a member failure. Their devices are still delivered to.
     */
    ownAccountHandle?: string;
}): Promise<GroupFanoutOutcome> {
    const { plan, ciphertext, send, onDeviceFailure, unresolvedMembers, ownAccountHandle } = args;

    const settled = await Promise.allSettled(
        plan.addresses.map((address) => send(address, new Uint8Array(ciphertext))),
    );

    const failedAddresses = new Set<string>();
    let failureMessage: string | undefined;
    settled.forEach((outcome, index) => {
        if (outcome.status === 'fulfilled') return;
        const address = plan.addresses[index];
        failedAddresses.add(address);
        if (failureMessage === undefined) {
            failureMessage =
                outcome.reason instanceof Error
                    ? outcome.reason.message
                    : String(outcome.reason);
        }
        onDeviceFailure?.({ address, ok: false, error: outcome.reason });
    });

    // The sender's own devices are delivered to above, but they are not group
    // members: counting them would inflate `sendTotal` by one for every user
    // with a linked device and turn a failure of the user's own second device
    // into a member failure.
    const memberFanouts = plan.members.filter(
        (member) => member.accountHandle !== ownAccountHandle,
    );

    let sendFailures = 0;
    let memberDeviceTotal = 0;
    let memberDeviceFailures = 0;
    for (const member of memberFanouts) {
        const failed = member.addresses.filter((address) => failedAddresses.has(address)).length;
        if (failed > 0) sendFailures += 1;
        memberDeviceTotal += member.addresses.length;
        memberDeviceFailures += failed;
    }

    const sendTotal = memberFanouts.length;
    const sendStatus: GroupMemberSendStatus =
        memberDeviceFailures === 0
            ? 'sent'
            : memberDeviceFailures === memberDeviceTotal
              ? 'failed'
              : 'partial';

    const unresolved = new Set(unresolvedMembers ?? []);
    const primaryOnlyMembers = memberFanouts
        .filter((member) => unresolved.has(member.accountHandle))
        .map((member) => member.accountHandle);

    return {
        sendStatus,
        sendFailures,
        sendTotal,
        failureMessage,
        primaryOnlyMembers,
    };
}
