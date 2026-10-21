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
 *    bytes; a malformed key throws before any lookup is attempted.
 *  - **No sensitive data in logs.** Account handles and a coarse reason code
 *    are logged; identity keys, prekey bundles, and list bytes never are.
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
}

/** Length of an Ed25519 public identity key. */
const IDENTITY_KEY_LEN = 33;

/** Why a member fell back to its bare handle. */
type UnresolvedReason = 'no-verified-list' | 'verification-failed';

/** Mailbox address for one device of `handle` (MD-17a/17b). */
function deviceAddress(handle: string, deviceId: number): string {
    return deviceId === 0 ? handle : `${handle}:${deviceId}`;
}

/**
 * Reject any identity key that is not exactly 33 bytes.
 *
 * The message names only the structural failure — never the key itself.
 */
function assertIdentityKey(identityKey: Uint8Array, role: string): void {
    if (!(identityKey instanceof Uint8Array) || identityKey.length !== IDENTITY_KEY_LEN) {
        throw new Error(`group recipients: ${role} identity key must be ${IDENTITY_KEY_LEN} bytes`);
    }
}

/**
 * Resolve a group's members into per-device mailbox recipients.
 *
 * Members are emitted in input order, each member's devices in the order its
 * signed list carries them, followed by the sender's own other devices. The
 * output is never sorted, and duplicate addresses are dropped (first wins).
 *
 * @throws if any member or own-device identity key is not 33 bytes. Lookup and
 *   verification failures do not throw: they degrade to the member's bare
 *   handle and are reported in `unresolvedMembers`.
 */
export async function resolveGroupRecipients({
    members,
    ownDevices,
    ownAccountHandle,
    currentDeviceId,
    discovery,
}: ResolveGroupRecipientsArgs): Promise<ResolvedGroupRecipients> {
    // Validate the whole input before doing any I/O: a malformed key must not
    // leave the caller with a half-resolved fan-out.
    for (const member of members) {
        assertIdentityKey(member.identityKey, 'member');
    }
    for (const device of ownDevices) {
        assertIdentityKey(device.identityKey, 'own-device');
    }

    const recipients: GroupDeviceRecipient[] = [];
    const unresolvedMembers: string[] = [];
    const seenAddresses = new Set<string>();

    const emit = (recipient: GroupDeviceRecipient): void => {
        if (seenAddresses.has(recipient.address)) return;
        seenAddresses.add(recipient.address);
        recipients.push(recipient);
    };

    for (const member of members) {
        let verified: Awaited<ReturnType<typeof lookupDeviceList>> = null;
        let reason: UnresolvedReason = 'no-verified-list';
        try {
            verified = await lookupDeviceList(
                discovery,
                member.accountHandle,
                member.identityKey,
                null,
            );
        } catch {
            // Tampered, foreign-signed, or malformed bytes — and relay failures.
            // The error is deliberately not rethrown: the primary is still
            // reachable, and the caller learns about the gap via
            // `unresolvedMembers`. The error object is not logged because its
            // text is not guaranteed to be free of list-derived detail.
            reason = 'verification-failed';
        }

        const devices = verified?.deviceList.devices ?? [];
        if (devices.length === 0) {
            // No list, or a verified list that names no devices: fall back to
            // the bare handle rather than silently dropping the member.
            emit({
                accountHandle: member.accountHandle,
                deviceId: 0,
                identityKey: member.identityKey,
                address: member.accountHandle,
            });
            unresolvedMembers.push(member.accountHandle);
            console.warn('group recipients: member device list unavailable; using primary handle', {
                accountHandle: member.accountHandle,
                reason,
            });
            continue;
        }

        for (const device of devices) {
            emit({
                accountHandle: member.accountHandle,
                deviceId: device.deviceId,
                identityKey: device.identityKey,
                address: deviceAddress(member.accountHandle, device.deviceId),
            });
        }
    }

    for (const device of ownDevices) {
        if (device.deviceId === currentDeviceId) continue;
        emit({
            accountHandle: ownAccountHandle,
            deviceId: device.deviceId,
            identityKey: device.identityKey,
            address: deviceAddress(ownAccountHandle, device.deviceId),
        });
    }

    return { recipients, unresolvedMembers };
}
