/**
 * Group roster reconciliation.
 *
 * A group message seals its per-message key to every identity key in the
 * sender's roster (`GroupSession::encrypt_as`), so a key that is still in the
 * roster keeps receiving a decryptable wrapper. The roster is a key set with no
 * enumeration API, and `group_add_member` does not de-duplicate, so this module
 * keeps its own record of the keys it added (`TrackedRosterKey`) and reconciles
 * the roster against the resolved recipient devices on every send:
 *
 *  - every recipient device key is present exactly once;
 *  - every tracked key that has stopped being a recipient is evicted — a linked
 *    device of a removed member, or a device its account revoked;
 *  - a handle whose device list could not be resolved this round is left
 *    alone. `lookupDeviceList` returns null for a list no newer than the held
 *    floor, so the resolver falls back to the bare primary on every send after
 *    the first; evicting that handle's tracked devices would silently stop
 *    them receiving after exactly one message. A null lookup is not evidence
 *    of revocation — a newer signed list is.
 *
 * The functions are pure: `group_add_member`/`group_remove_member` return a
 * cloned handle, and the tracked set is rebuilt rather than mutated. The caller
 * commits the returned set only once the reconciled roster is persisted.
 */

import {
    group_add_member,
    group_remove_member,
    GroupHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import { isWellFormedIdentityKey, type GroupDeviceRecipient } from './group_recipients';

/** A roster identity key remembered so a later reconciliation can evict it. */
export interface TrackedRosterKey {
    accountHandle: string;
    identityKey: Uint8Array;
}

/** Tracked keys keyed by the lowercase hex of the identity key. */
export type TrackedRosterKeys = Map<string, TrackedRosterKey>;

/** A recipient key and the account it belongs to. */
export interface RosterRecipient {
    accountHandle: string;
    identityKey: Uint8Array;
}

export interface ReconcileRosterArgs {
    group: GroupHandle;
    /** The sender's own identity key; never added, tracked, or evicted here. */
    selfPublicBytes: Uint8Array;
    /** The devices this message must reach. */
    recipients: ReadonlyArray<RosterRecipient>;
    /** The account keys of the current members. */
    memberKeys: ReadonlyArray<Uint8Array>;
    /** Handles whose device list was unavailable or not newer this round. */
    unresolvedHandles: ReadonlySet<string>;
    tracked: TrackedRosterKeys;
}

export interface ReconcileRosterResult {
    group: GroupHandle;
    tracked: TrackedRosterKeys;
}

/** True for a value that is a valid byte (integer in 0..255). */
function isByte(entry: unknown): entry is number {
    return Number.isInteger(entry) && (entry as number) >= 0 && (entry as number) <= 255;
}

/** Lowercase hex of a byte string. */
function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Read persisted tracked roster keys, dropping unusable entries.
 *
 * A dropped entry is a missed eviction, not a wrong one, so an unusable record
 * contributes nothing. Validate the same shape the resolver emits (33-byte,
 * 0x05 Curve25519) before any bytes reach WASM.
 */
export function validatedRosterDeviceKeys(raw: unknown): TrackedRosterKey[] {
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

/**
 * Bring the roster in line with the resolved recipients.
 *
 * Throws if a WASM roster operation fails; the caller must then keep the
 * previous handle and tracked set rather than commit a partial reconcile.
 */
export function reconcileRoster({
    group,
    selfPublicBytes,
    recipients,
    memberKeys,
    unresolvedHandles,
    tracked,
}: ReconcileRosterArgs): ReconcileRosterResult {
    const selfHex = toHex(selfPublicBytes);
    // Keys the roster is believed to hold: the sender, every member account
    // key, and every key tracked from a previous send. `hasKey` must consult
    // the tracked set — the roster itself cannot be enumerated, and
    // `group_add_member` would otherwise append a duplicate on every send that
    // re-lists the same device.
    const knownKeys = new Set<string>([selfHex, ...memberKeys.map(toHex), ...tracked.keys()]);
    const recipientHexes = new Set(recipients.map((recipient) => toHex(recipient.identityKey)));
    const nextTracked = new Map(tracked);
    let reconciled = group;

    for (const recipient of recipients) {
        const hex = toHex(recipient.identityKey);
        if (knownKeys.has(hex)) continue;
        reconciled = group_add_member(reconciled, recipient.identityKey);
        knownKeys.add(hex);
    }

    for (const recipient of recipients) {
        const hex = toHex(recipient.identityKey);
        if (hex === selfHex) continue;
        if (nextTracked.has(hex)) continue;
        nextTracked.set(hex, {
            accountHandle: recipient.accountHandle,
            identityKey: recipient.identityKey,
        });
    }

    for (const [hex, entry] of [...nextTracked]) {
        const entryHex = toHex(entry.identityKey);
        if (entryHex === selfHex) {
            nextTracked.delete(hex);
            continue;
        }
        if (recipientHexes.has(entryHex)) continue;
        // The handle resolved to its bare primary because the list was absent,
        // stale, or unverifiable. That is not evidence that its linked devices
        // were revoked, so keep the last known roster for that handle.
        if (unresolvedHandles.has(entry.accountHandle)) continue;
        reconciled = group_remove_member(reconciled, entry.identityKey);
        knownKeys.delete(hex);
        nextTracked.delete(hex);
    }

    // Member account keys are seeded into `knownKeys`, so they are covered by
    // the tracked sweep once a send has tracked them; this loop still handles a
    // key added by `addPeer` that no send has tracked yet.
    for (const memberKey of memberKeys) {
        const hex = toHex(memberKey);
        if (hex === selfHex) continue;
        if (!knownKeys.has(hex)) continue;
        if (recipientHexes.has(hex)) continue;
        reconciled = group_remove_member(reconciled, memberKey);
        knownKeys.delete(hex);
    }

    return { group: reconciled, tracked: nextTracked };
}
