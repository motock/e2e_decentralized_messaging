/**
 * Device revocation (web client, MD-18).
 *
 * Revoking a linked device is a *published* act, not just a local one: the
 * account primary re-signs its device list without the revoked device at
 * version+1 and publishes it, so every peer that fetches the list stops
 * fanning out to the revoked device (spec/v0.md §8.3/§8.4).
 *
 * The signing and verification live in the Rust core and are exposed through
 * the WASM bindings (`sign_device_list` / `verify_device_list`). This module is
 * the web-side orchestration: verify the list we hold, drop the device, bump
 * the version, sign, publish.
 *
 * Security properties:
 *  - **Fail closed.** `currentListBytes` is verified against the primary's
 *    public key before any of it is trusted. An unverifiable list throws and
 *    nothing is published — a tampered or foreign list can never be re-signed
 *    into a list peers would accept.
 *  - **The primary cannot be revoked.** Device 0 is the account's own identity;
 *    revoking it would leave a list no device can sign for. It is rejected
 *    before anything is published.
 *  - **Monotonic.** The new list is signed at `heldVersion + 1`, so a peer's
 *    §8.4 guard accepts it and a replayed older list can never resurrect the
 *    revoked device.
 *  - **No sensitive data in logs or errors.** Identity keys, list bytes and
 *    prekey bundles are never logged, and thrown messages name only the
 *    structural failure.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { publishSignedDeviceList, toConversationDeviceList, type DiscoveryTransport } from './discovery';
import type { DeviceList, DeviceListEntry } from './Conversation';

/**
 * The signed-device-list bindings this module uses (MD-3).
 *
 * Declared locally rather than added to `wasm-bindings.d.ts`: that file is the
 * ambient fallback for the unbuilt-WASM case and is outside this module's
 * scope. When `prepare-wasm` has run, wasm-pack's generated `index.d.ts`
 * declares these functions and the cast below is a no-op.
 */
interface DeviceListBindings {
    /** `u64_le(version) || packed entries`. */
    verify_device_list(bytes: Uint8Array, expectedAccount: Uint8Array): Uint8Array;
    /** Sign a versioned list; returns the on-the-wire blob. */
    sign_device_list(
        primaryPrivateBytes: Uint8Array,
        version: number,
        packedEntries: Uint8Array,
    ): Uint8Array;
}

const deviceListWasm = wasm as unknown as DeviceListBindings;

/** The primary identity handle App holds (PersistedIdentity's `handle`). */
export interface PrimaryIdentityHandle {
    /** The account's 33-byte public identity key. */
    public_bytes(): Uint8Array;
    /** The account's private identity bytes, used to sign the list. */
    private_bytes(): Uint8Array;
}

/** Arguments for {@link revokeDevice}. */
export interface RevokeDeviceArgs {
    /** The exact signed list bytes currently held (and published). */
    currentListBytes: Uint8Array;
    /** The account primary's identity handle — verifies and re-signs. */
    primaryIdentityHandle: PrimaryIdentityHandle;
    /** The device to revoke. Device 0 (the primary) is rejected. */
    deviceId: number;
    /** The account handle the list is published under. */
    accountHandle: string;
    /** Discovery transport used to publish the new list. */
    transport: DiscoveryTransport;
}

/** The new signed list and its decoded form. */
export interface RevokeDeviceResult {
    signedListBytes: Uint8Array;
    deviceList: DeviceList;
}

/** Bytes of the `u64_le` version prefix `verify_device_list` prepends. */
const VERSION_PREFIX_LEN = 8;

/** The primary device's id — the account's own identity, never revocable. */
const PRIMARY_DEVICE_ID = 0;

/**
 * Revoke `deviceId` from the account's signed device list.
 *
 * Verifies `currentListBytes` against the primary's public key, drops the
 * device, signs the survivors at version+1, publishes the new blob for
 * `accountHandle`, and returns the new bytes together with the new list.
 *
 * @throws if the list does not verify against the primary, if `deviceId` is
 *   the primary (0), if `deviceId` is not a listed device, or if publishing
 *   fails. Nothing is published on any of those paths.
 */
export async function revokeDevice({
    currentListBytes,
    primaryIdentityHandle,
    deviceId,
    accountHandle,
    transport,
}: RevokeDeviceArgs): Promise<RevokeDeviceResult> {
    if (!Number.isSafeInteger(deviceId) || deviceId < 0 || deviceId > 0xffffffff) {
        throw new Error('device revocation: device id is out of range');
    }
    if (deviceId === PRIMARY_DEVICE_ID) {
        throw new Error('device revocation: the primary device cannot be revoked');
    }

    await ensureWasmInit();

    // Verify BEFORE trusting anything in the blob: an unverifiable list must
    // never be re-signed into a list peers would accept.
    const verified = deviceListWasm.verify_device_list(
        currentListBytes,
        primaryIdentityHandle.public_bytes(),
    );
    const { version, packedEntries } = splitVerified(verified);
    const held = toConversationDeviceList(version, packedEntries);

    if (!held.devices.some((device) => device.deviceId === deviceId)) {
        throw new Error('device revocation: device is not in the list');
    }

    const remaining = held.devices.filter((device) => device.deviceId !== deviceId);
    const nextVersion = version + 1;
    const signedListBytes = deviceListWasm.sign_device_list(
        primaryIdentityHandle.private_bytes(),
        nextVersion,
        packDeviceListEntries(remaining),
    );

    await publishSignedDeviceList(transport, accountHandle, signedListBytes);

    return {
        signedListBytes,
        deviceList: { version: nextVersion, devices: remaining },
    };
}

/**
 * Split the `u64_le(version) || packed entries` buffer `verify_device_list`
 * returns. Mirrors discovery.ts's private splitter so this module does not
 * depend on its internals.
 */
function splitVerified(verified: Uint8Array): { version: number; packedEntries: Uint8Array } {
    if (verified.length < VERSION_PREFIX_LEN) {
        throw new Error('device list: verified buffer is truncated');
    }
    const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
    const raw = view.getBigUint64(0, true);
    if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('device list: version is out of range');
    }
    return { version: Number(raw), packedEntries: verified.subarray(VERSION_PREFIX_LEN) };
}

/**
 * Pack device-list entries for `sign_device_list`:
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`,
 * concatenated with no count prefix (the layout `toConversationDeviceList`
 * parses). Mirrors App.tsx's packer; kept local so this module does not depend
 * on App's internals.
 */
function packDeviceListEntries(entries: DeviceListEntry[]): Uint8Array {
    let size = 0;
    for (const entry of entries) {
        size += 4 + 4 + entry.identityKey.length + 4 + entry.bundleBytes.length;
    }
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const entry of entries) {
        if (
            !Number.isSafeInteger(entry.deviceId) ||
            entry.deviceId < 0 ||
            entry.deviceId > 0xffffffff
        ) {
            throw new Error('device list: device id is out of range');
        }
        // Validate before signing: a malformed entry must never be signed and
        // published, because peers verify the signature and then trust the
        // contents.
        if (entry.identityKey.length !== 33) {
            throw new Error('device list: identity key is not 33 bytes');
        }
        if (entry.bundleBytes.length === 0) {
            throw new Error('device list: bundle is empty');
        }
        view.setUint32(pos, entry.deviceId, true);
        pos += 4;
        view.setUint32(pos, entry.identityKey.length, true);
        pos += 4;
        out.set(entry.identityKey, pos);
        pos += entry.identityKey.length;
        view.setUint32(pos, entry.bundleBytes.length, true);
        pos += 4;
        out.set(entry.bundleBytes, pos);
        pos += entry.bundleBytes.length;
    }
    return out;
}
