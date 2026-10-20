/**
 * Signed device-list discovery (web client, MD-9).
 *
 * The account primary signs a versioned list of its devices (spec/v0.md §8.3)
 * and publishes it as an opaque discovery blob; a peer looks the blob up,
 * verifies it against the account's identity key, and applies it only when its
 * version is strictly newer than the one it already holds (§8.4).
 *
 * The signing and verification live in the Rust core and are exposed through
 * the WASM bindings (`sign_device_list` / `verify_device_list`). This module is
 * the web-side orchestration: publish, verify-then-convert, and the packed-entry
 * codec.
 *
 * This module also owns the canonical codec for the buffer
 * `verify_device_list` returns — `u64_le(version) || packed entries` — as
 * {@link packEntries} and {@link splitVerified}. Every web module that reads or
 * writes that layout imports these two rather than carrying a private copy, so
 * the framing cannot drift between callers.
 *
 * Security properties:
 *  - **Never returns unverified bytes.** `lookupDeviceList` calls
 *    `verify_device_list` on every blob it receives and lets any throw
 *    propagate. There is no fallback path that hands back the relay's bytes.
 *  - **Monotonic.** A verified list whose version is not strictly newer than
 *    `heldVersion` is discarded (`null`), so a replayed stale list cannot
 *    resurrect a revoked device.
 *  - **No sensitive data in logs or errors.** Account keys, identity keys,
 *    list bytes, and prekey bundles are never logged, and thrown messages name
 *    only the structural failure.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
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
}

const deviceListWasm = wasm as unknown as DeviceListBindings;

/** The transport surface discovery needs. `RelayTransport` satisfies it. */
export interface DiscoveryTransport {
    /** Publish (or replace) the discovery blob for `handle`. */
    publishDiscovery(handle: string, blob: Uint8Array): Promise<void>;
    /** Fetch the discovery blob for `handle`, or `null` when none is stored. */
    lookupDiscovery(handle: string): Promise<Uint8Array | null>;
}

/** A verified device list together with the version it was signed at. */
export interface VerifiedDeviceList {
    version: number;
    deviceList: DeviceList;
}

/** Bytes of the `u64_le` version prefix `verify_device_list` prepends. */
const VERSION_PREFIX_LEN = 8;

/**
 * Publish an already-signed device list for `handle`.
 *
 * The bytes are opaque to the relay, which stores them blind. Signing is the
 * caller's job (`sign_device_list`); this wrapper only carries the blob.
 */
export async function publishSignedDeviceList(
    transport: DiscoveryTransport,
    handle: string,
    signedBytes: Uint8Array,
): Promise<void> {
    await transport.publishDiscovery(handle, signedBytes);
}

/**
 * Look up, verify, and convert the device list published for `handle`.
 *
 * Returns `null` when the relay holds no list, or when the verified list's
 * version is not strictly newer than `heldVersion` (monotonic update, §8.4).
 *
 * @param expectedAccount - The account primary's 33-byte public identity key.
 *   The list must be signed by it.
 * @param heldVersion     - The version already applied, or `null` if none.
 * @throws if the blob fails verification (tampered, wrong signer, malformed).
 *   The error propagates unchanged: unverified bytes are never returned.
 */
export async function lookupDeviceList(
    transport: DiscoveryTransport,
    handle: string,
    expectedAccount: Uint8Array,
    heldVersion: number | null,
): Promise<VerifiedDeviceList | null> {
    const signedBytes = await transport.lookupDiscovery(handle);
    if (signedBytes === null) return null;

    await ensureWasmInit();
    // Any verification failure throws out of here — deliberately not caught.
    const verified = deviceListWasm.verify_device_list(signedBytes, expectedAccount);

    const { version, packedEntries } = splitVerified(verified);
    if (heldVersion !== null && version <= heldVersion) return null;

    return { version, deviceList: toConversationDeviceList(version, packedEntries) };
}

/**
 * Convert a packed entry buffer into a `DeviceList`.
 *
 * Layout (no count prefix — parsed until exhaustion):
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`.
 * A partial trailing record throws rather than silently dropping a device.
 */
export function toConversationDeviceList(version: number, packedEntries: Uint8Array): DeviceList {
    const view = new DataView(packedEntries.buffer, packedEntries.byteOffset, packedEntries.byteLength);
    const devices: DeviceListEntry[] = [];
    let pos = 0;

    while (pos < packedEntries.length) {
        const deviceId = readU32(view, packedEntries.length, pos);
        pos += 4;
        const identityLen = readU32(view, packedEntries.length, pos);
        pos += 4;
        const identityKey = readBytes(packedEntries, pos, identityLen);
        pos += identityLen;
        const bundleLen = readU32(view, packedEntries.length, pos);
        pos += 4;
        const bundleBytes = readBytes(packedEntries, pos, bundleLen);
        pos += bundleLen;

        devices.push({ deviceId, identityKey, bundleBytes });
    }

    return { version, devices };
}

// ---------------------------------------------------------------------------
// Shared codec for `u64_le(version) || packed entries`
// ---------------------------------------------------------------------------

/**
 * Encode a versioned device list into the buffer layout `verify_device_list`
 * returns: `u64_le(version) || packed entries`, where the entries are
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`
 * concatenated with no count prefix.
 *
 * The exact inverse of {@link splitVerified}. Callers that need only the entry
 * portion (e.g. `sign_device_list`, which prepends the version itself) take
 * `.subarray(VERSION_PREFIX_LEN)` of the result.
 *
 * @throws if `version` is not a non-negative safe integer, or if any entry is
 *   malformed. Validation happens before anything is encoded, so a rejected
 *   call leaves no partial output behind.
 */
export function packEntries(version: number, entries: DeviceListEntry[]): Uint8Array {
    // `setBigUint64` would happily encode 2^53 and peers would then read a
    // version this side can no longer represent. Reject before encoding, and
    // never fold the version through a 32-bit operator (`version | 0` turns
    // 2^53 into 0).
    if (!Number.isSafeInteger(version) || version < 0) {
        throw new Error('device list: version is out of range');
    }

    let size = VERSION_PREFIX_LEN;
    for (const entry of entries) {
        size += 4 + 4 + entry.identityKey.length + 4 + entry.bundleBytes.length;
    }

    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    view.setBigUint64(0, BigInt(version), true);
    let pos = VERSION_PREFIX_LEN;

    for (const entry of entries) {
        // `setUint32` silently wraps, so an out-of-range id from a hostile list
        // would pack as a different id (2^32 packs as 0, colliding with the
        // primary and failing Rust structural validation). Reject instead.
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

/**
 * Split `verify_device_list`'s output into its version and entry buffer.
 *
 * @throws if the buffer is shorter than the 8-byte version prefix (a truncated
 *   read must not zero-fill) or if the version exceeds `Number.MAX_SAFE_INTEGER`.
 */
export function splitVerified(verified: Uint8Array): { version: number; packedEntries: Uint8Array } {
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Read a little-endian `u32`, bounds-checked against the buffer length. */
function readU32(view: DataView, length: number, pos: number): number {
    if (pos + 4 > length) throw new Error('device list: truncated entry buffer');
    return view.getUint32(pos, true);
}

/** Borrow `len` bytes at `pos`, bounds-checked so a short buffer throws. */
function readBytes(buf: Uint8Array, pos: number, len: number): Uint8Array {
    if (pos + len > buf.length) throw new Error('device list: truncated entry buffer');
    return buf.slice(pos, pos + len);
}
