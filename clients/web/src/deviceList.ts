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