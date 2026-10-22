/**
 * The persisted group state record and its validators.
 *
 * Everything here crosses the trust boundary at restore: the record comes back
 * from StorageGate (encrypted at rest, but still data this process did not
 * produce in this session) and feeds WASM calls and the roster. Each validator
 * states the failure mode it chooses, because for the floor and the roster the
 * safe direction is not the same as for the cached lists.
 */

import { isWellFormedIdentityKey, type HeldDeviceList } from './group_recipients';

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
export interface PersistedGroupState {
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
    /**
     * The contents of the last verified device list per account handle (GF-2).
     *
     * `lookupDeviceList` returns null for a list no newer than the floor, so
     * this is what lets a member keep its linked devices on every send after
     * the first. Without it the resolver falls back to the bare primary and the
     * roster sweep evicts live devices. Stored as
     * `[handle, { version, devices: [[deviceId, identityKeyBytes], ...] }]` so
     * it is JSON-serializable.
     */
    deviceLists?: Array<[string, { version: number; devices: Array<[number, number[]]> }]>;
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
export function validatedGroupBlob(blob: unknown): Uint8Array | null {
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
export function validatedDeviceListVersions(raw: unknown): Map<string, number> {
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
 * Read the persisted device-list cache, dropping unusable entries.
 *
 * A dropped entry costs availability (the handle falls back to its primary
 * until a newer list arrives), never secrecy: every key is re-validated to the
 * same 33-byte `0x05` shape the resolver emits before it can reach the roster.
 */
export function validatedHeldDeviceLists(raw: unknown): Map<string, HeldDeviceList> {
    const lists = new Map<string, HeldDeviceList>();
    if (!Array.isArray(raw)) return lists;
    for (const entry of raw) {
        if (!Array.isArray(entry) || entry.length !== 2) continue;
        const [handle, record] = entry as [unknown, unknown];
        if (typeof handle !== 'string' || handle.length === 0) continue;
        if (typeof record !== 'object' || record === null) continue;
        const { version, devices } = record as { version?: unknown; devices?: unknown };
        if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) continue;
        if (!Array.isArray(devices) || devices.length === 0) continue;
        const parsed: HeldDeviceList['devices'] = [];
        let usable = true;
        for (const device of devices) {
            if (!Array.isArray(device) || device.length !== 2) {
                usable = false;
                break;
            }
            const [deviceId, rawKey] = device as [unknown, unknown];
            if (
                typeof deviceId !== 'number' ||
                !Number.isInteger(deviceId) ||
                deviceId < 0 ||
                deviceId > 0xffffffff
            ) {
                usable = false;
                break;
            }
            if (!Array.isArray(rawKey) || !rawKey.every(isByte)) {
                usable = false;
                break;
            }
            const identityKey = new Uint8Array(rawKey);
            if (!isWellFormedIdentityKey(identityKey)) {
                usable = false;
                break;
            }
            parsed.push({ deviceId, identityKey });
        }
        if (!usable) continue;
        lists.set(handle, { version, devices: parsed });
    }
    return lists;
}
