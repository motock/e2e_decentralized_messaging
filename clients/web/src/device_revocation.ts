/**
 * DR-6b: revocation support for the account's linked devices.
 *
 * App owns the recipient device list (spec/v0.md §8.3) and the live
 * sender-side fan-out session. This module keeps those two concerns in one
 * place so a revoke does both halves of the job:
 *
 *   1. `revokeDeviceOnSession` calls `fanout_remove_device` on the LIVE
 *      handle, mutating the session the handle holds — the removal sticks in
 *      the session rather than only in the UI.
 *   2. `removeDeviceFromList` drops the device from the held list (purely,
 *      bumping the list version so a stale or replayed list can never
 *      resurrect the revoked device — §8.4 monotonicity). Conversation
 *      re-establishes its fan-out session from this list on every send, so a
 *      later 1:1 send produces no envelope for the revoked device while the
 *      survivors still receive.
 *
 * No keys, plaintext or full identifiers are logged here.
 */

import {
    fanout_establish,
    fanout_remove_device,
    FanoutDeviceInput,
    FanoutHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import type { DeviceList, DeviceListEntry } from './Conversation';

/** The live sender-side fan-out session App holds for revocation. */
export type FanoutSessionHandle = FanoutHandle;

/**
 * Establish a live fan-out session over the account's linked devices.
 *
 * `identityHandle` is the WASM identity handle App holds (PersistedIdentity's
 * `handle`); it is cast at this boundary exactly like Conversation does for
 * its own `fanout_establish` call, so App itself never has to import the wasm
 * pkg. Throws when any device's bundle does not match its vouched-for key or
 * is malformed — the caller must fail closed (no live session), never fall
 * back to a partial session.
 */
export function establishFanoutSession(
    identityHandle: unknown,
    devices: DeviceListEntry[],
): FanoutSessionHandle {
    const inputs = devices.map(
        (entry) =>
            // expected_identity_key_bytes is the key the PRIMARY vouched for
            // (entry.identityKey), never the bundle's own key — the binding
            // compares the two and rejects a mismatched bundle.
            new FanoutDeviceInput(entry.deviceId, entry.identityKey, entry.bundleBytes),
    );
    return fanout_establish(
        identityHandle as unknown as Parameters<typeof fanout_establish>[0],
        inputs,
    );
}

/**
 * Drop `deviceId` from the LIVE fan-out session `handle` holds. Mutates the
 * session, so a later `fanout_devices`/`fanout_encrypt` on the same handle
 * reflects the removal.
 */
export function revokeDeviceOnSession(handle: FanoutSessionHandle, deviceId: number): void {
    fanout_remove_device(handle, deviceId);
}

/**
 * Drop `deviceId` from the held device list, purely.
 *
 * The returned list's version is strictly newer than the held one, so the
 * §8.4 monotonic guard ignores any stale or replayed list that still carries
 * the revoked device: a revocation can never be undone by an old update.
 */
export function removeDeviceFromList(held: DeviceList, deviceId: number): DeviceList {
    return {
        version: held.version + 1,
        devices: held.devices.filter((device) => device.deviceId !== deviceId),
    };
}

/** True when `deviceId` is actually in `list` — the revoke guard for unknown ids. */
export function isListedDevice(list: DeviceList | undefined, deviceId: number): boolean {
    return !!list && list.devices.some((device) => device.deviceId === deviceId);
}