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
 *    list — or whose list fails verification or lookup — still gets a single
 *    recipient at its bare handle (the primary is reachable; linked devices are
 *    not) and is reported in `unresolvedMembers` so the caller can surface the
 *    gap. One member's failure never fails the whole send.
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
 *    repeated handle can never be walked backwards.
 *  - **Canonical handles.** Handles are trimmed before use, so the handles in
 *    the returned recipients are canonical even if the caller's roster is not;
 *    callers matching recipients back to roster entries should compare against
 *    the trimmed form.
 *  - **No sensitive data in logs.** Only a non-reversible handle reference, a
 *    coarse reason code, and an error *class* are logged; account handles,
 *    identity keys, prekey bundles, and list bytes never are.
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
}

/** Arguments for {@link resolveGroupRecipients}. */
export interface ResolveGroupRecipientsArgs {
    members: GroupMemberAccount[];
    ownDevices: OwnDevice[];
    ownAccountHandle: string;
    /** The device this client is running as; excluded from the fan-out. */
    currentDeviceId: number;
    discovery: DiscoveryTransport;
    /**
     * Highest device-list version already applied, per account handle.
     *
     * Passed straight through to `lookupDeviceList` as its monotonic floor, so
     * a relay replaying an older (but validly signed) list cannot resurrect a
     * device the user has revoked. This is a *per-call* floor: the resolver
     * never mutates the map, and the versions it applies are not returned, so a
     * caller cannot populate it from a previous resolution. Within one call the
     * effective floor for a handle is the higher of this map's entry and any
     * version already applied for that handle, so a repeated handle can never
     * be walked backwards.
     */
    heldVersions?: ReadonlyMap<string, number>;
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
 */
export async function resolveGroupRecipients({
    members,
    ownDevices,
    ownAccountHandle,
    currentDeviceId,
    discovery,
    heldVersions,
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

    const recipients: GroupDeviceRecipient[] = [];
    const unresolvedMembers: string[] = [];
    const seenAddresses = new Set<string>();
    // Versions applied in this call, so a repeated handle cannot be walked
    // backwards within a single resolution.
    const appliedVersions = new Map<string, number>();

    const emit = (recipient: GroupDeviceRecipient): void => {
        if (seenAddresses.has(recipient.address)) return;
        seenAddresses.add(recipient.address);
        recipients.push(recipient);
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
            // verification: fall back to the bare handle rather than silently
            // dropping the member. The primary is still reachable; its linked
            // devices are not, and the caller can surface that.
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

        for (const device of devices) {
            emit({
                accountHandle: handle,
                deviceId: device.deviceId,
                identityKey: device.identityKey,
                address: deviceAddress(handle, device.deviceId),
            });
        }
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

    return { recipients, unresolvedMembers };
}
