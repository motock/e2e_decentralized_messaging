/**
 * Primary-side device linking (web client, MD-11).
 *
 * The primary device scans a new device's QR payload, derives the *link key*
 * the new device published its prekey bundle under, fetches that bundle, and —
 * only after confirming the bundle really belongs to the identity key the QR
 * named — appends the device to the account's signed device list and publishes
 * the next version (spec/v0.md §8.3).
 *
 * Security properties:
 *  - **The relay is not trusted for identity binding.** The bundle is looked up
 *    under the derived link key, and its identity key must byte-match the
 *    scanned QR key. A mismatch throws before anything is signed or published,
 *    so a bundle for a *different* identity cannot get a device into the signed
 *    list. This binds the bundle to the scanned identity key; it does **not**
 *    authenticate the bundle's prekeys — `bundle_identity_key_bytes` does not
 *    check signatures, so a relay can still serve a same-identity bundle with
 *    substituted prekeys (a denial of service, not an impersonation). Verifying
 *    the signed-prekey/Kyber signatures before signing is a follow-up.
 *  - **No duplicate identity keys.** The new device's identity key is compared
 *    against every existing entry, device 0 included, and a match rejects before
 *    signing. `FanoutSession::establish_from_bundles` rejects a list carrying one
 *    identity under two device ids (`FanoutError::DuplicateIdentity`), so
 *    publishing one would break every sender's fan-out to the account. This also
 *    stops a re-scan of the same QR from re-adding a device under its old key
 *    (spec/v0.md §8.4). Re-adding a *revoked* device whose key is no longer in
 *    the list needs local revocation state, which this module does not hold —
 *    that is a follow-up, not something this check can cover.
 *  - **No fallback bundle.** A missing bundle (`NotFound`) rejects the whole
 *    request; there is no synthesized or cached bundle path.
 *  - **The current list is verified, never trusted for authenticity.**
 *    `currentListBytes` is run through `verify_device_list` against the primary's
 *    public identity key before its entries or version are used, so a tampered
 *    list cannot seed the next version. Verification proves *authenticity*, not
 *    *freshness*: a relay can serve an older validly-signed list. Callers that
 *    hold a version MUST pass `heldVersion`, so a rollback is rejected before
 *    signing (§8.4); without it this function cannot detect a replay.
 *  - **Device 0 is preserved.** The primary is itself a fan-out recipient, so
 *    every published list contains device 0 exactly once.
 *  - **No sensitive data in logs or errors.** Identity keys, private bytes,
 *    link keys, and prekey bundles are never logged, and thrown messages name
 *    only the structural failure.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import {
    publishSignedDeviceList,
    toConversationDeviceList,
    type DiscoveryTransport,
} from './discovery';

/**
 * The signed-device-list bindings this module needs that the checked-in
 * ambient fallback (`wasm-bindings.d.ts`) does not declare (MD-3).
 *
 * Declared locally and reached through a cast, mirroring `discovery.ts` and
 * `link_new_device.ts` — the ambient declaration file is deliberately left
 * untouched. When `prepare-wasm` has run, wasm-pack's generated `index.d.ts`
 * declares these functions and the cast below is a no-op.
 */
interface DeviceListBindings {
    /** Sign a versioned list; returns the on-the-wire blob. */
    sign_device_list(
        primaryPrivateBytes: Uint8Array,
        version: number,
        packedEntries: Uint8Array,
    ): Uint8Array;
    /** `u64_le(version) || packed entries`, verified against `expectedAccount`. */
    verify_device_list(bytes: Uint8Array, expectedAccount: Uint8Array): Uint8Array;
    /** Derive the relay lookup handle for a device's identity key. */
    derive_link_key(identityKey: Uint8Array): string;
}

const deviceListWasm = wasm as unknown as DeviceListBindings;

/** Bytes of the `u64_le` version prefix `verify_device_list` prepends. */
const VERSION_PREFIX_LEN = 8;

/** The transport surface linking needs. `RelayTransport` satisfies it. */
export interface LinkPrimaryTransport extends DiscoveryTransport {
    /** Fetch the prekey bundle published under `recipientId`. Throws on `NotFound`. */
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
}

/** One device in the account's list, as carried by the packed entry buffer. */
export interface DeviceListEntryInput {
    deviceId: number;
    identityKey: Uint8Array;
    bundleBytes: Uint8Array;
}

/** Arguments to {@link buildAndPublishLinkedList}. */
export interface BuildAndPublishLinkedListArgs {
    /** Relay transport used for the bundle lookup and the list publication. */
    transport: LinkPrimaryTransport;
    /** The scanned QR payload encoding the new device's 33-byte identity key. */
    qrPayload: string;
    /** The account primary's identity handle (signs the list). */
    primaryIdentityHandle: IdentityHandle;
    /** The primary's own prekey bundle, included as device 0. */
    primaryBundleBytes: Uint8Array;
    /** The currently published signed list, or `null` when none exists yet. */
    currentListBytes: Uint8Array | null;
    /**
     * The list version this device already holds, or `null`/omitted when it
     * holds none.
     *
     * `verify_device_list` proves authenticity, not freshness, so a relay can
     * serve an older validly-signed list. When this is supplied the verified
     * version must be `>= heldVersion`, otherwise the request is rejected before
     * signing (spec/v0.md §8.4). Callers that track a version MUST pass it —
     * this function has no other way to detect a rollback.
     */
    heldVersion?: number | null;
    /** Relay handle the signed list is published under. */
    accountHandle: string;
}

/** The outcome of a successful link: the published list and the new device's data. */
export interface BuildAndPublishLinkedListResult {
    /** Version of the list that was published. */
    version: number;
    /** Device id assigned to the new device. */
    deviceId: number;
    /** The signed on-the-wire blob that was published. */
    signedListBytes: Uint8Array;
    /** The new device's 33-byte identity key (from the QR payload). */
    newDeviceIdentityKey: Uint8Array;
    /** Safety number between the primary and the new device. */
    safetyNumber: string;
    /** Relay lookup handle the new device's bundle was published under. */
    linkKey: string;
    /** The new device's prekey bundle, as fetched from the relay. */
    newDeviceBundle: Uint8Array;
}

/**
 * The next device id for a list: `1` when no entry has an id `>= 1`, otherwise
 * the largest such id plus one. Never returns `0` — that id is the primary's.
 *
 * Does not mutate `entries`.
 */
export function nextDeviceId(entries: { deviceId: number }[]): number {
    let max = 0;
    for (const entry of entries) {
        if (entry.deviceId >= 1 && entry.deviceId > max) {
            max = entry.deviceId;
        }
    }
    return max + 1;
}

/**
 * Verify the link request and publish the signed version+1 device list.
 *
 * Steps, in order:
 *  1. decode the QR payload to the new device's 33-byte identity key;
 *  2. derive the link key and fetch the bundle published under it;
 *  3. require the bundle's identity key to byte-match the QR key — throw on any
 *     difference, before signing or publishing;
 *  4. take the entries from the *verified* current list, or seed device 0 from
 *     the primary's own key and bundle when there is no list yet;
 *  5. reject if the new identity key is already in the list (device 0 included);
 *  6. append the new device at `nextDeviceId(entries)`;
 *  7. sign at `(current version or 0) + 1` with the primary's private bytes;
 *  8. publish the signed blob under `accountHandle`.
 *
 * Lookup, verification, and mismatch errors propagate unchanged: nothing is
 * published on any failure path.
 *
 * @throws if the QR payload is malformed, the bundle is missing, the bundle's
 *   identity key differs from the QR key, the new identity key is already in the
 *   list, the current list fails verification or is older than `heldVersion`, or
 *   signing/publishing fails.
 */
export async function buildAndPublishLinkedList(
    args: BuildAndPublishLinkedListArgs,
): Promise<BuildAndPublishLinkedListResult> {
    const {
        transport,
        qrPayload,
        primaryIdentityHandle,
        primaryBundleBytes,
        currentListBytes,
        heldVersion = null,
        accountHandle,
    } = args;

    await ensureWasmInit();

    // 1. The scanned QR names the new device's identity key.
    const newDeviceIdentityKey = wasm.decode_device_qr(qrPayload);

    // 2. The bundle lives under the derived link key, never under the identity key.
    const linkKey = deviceListWasm.derive_link_key(newDeviceIdentityKey);
    const newDeviceBundle = await transport.lookupPrekey(linkKey);

    // 3. The relay's bundle must belong to the identity the QR named. Any
    //    difference rejects the request before anything is signed or published.
    const bundleIdentityKey = wasm.bundle_identity_key_bytes(newDeviceBundle);
    if (!bytesEqual(bundleIdentityKey, newDeviceIdentityKey)) {
        throw new Error('link request: bundle identity key does not match the scanned key');
    }

    const primaryPublicBytes = primaryIdentityHandle.public_bytes();

    // 4. Entries come from the verified current list, or from device 0 alone.
    let entries: DeviceListEntryInput[];
    let currentVersion: number;
    if (currentListBytes === null) {
        entries = [
            {
                deviceId: 0,
                identityKey: primaryPublicBytes,
                bundleBytes: primaryBundleBytes,
            },
        ];
        currentVersion = 0;
    } else {
        const verified = deviceListWasm.verify_device_list(currentListBytes, primaryPublicBytes);
        currentVersion = readVersion(verified);
        // Verification proves the list was signed by the primary; it says nothing
        // about freshness. Reject a rollback before signing, so a relay cannot
        // make us re-sign an older list and resurrect revoked devices (§8.4).
        if (heldVersion !== null && currentVersion < heldVersion) {
            throw new Error('link request: current list is older than the version already held');
        }
        const packedEntries = verified.subarray(VERSION_PREFIX_LEN);
        entries = toConversationDeviceList(currentVersion, packedEntries).devices.map(
            (device) => ({
                deviceId: device.deviceId,
                identityKey: device.identityKey,
                bundleBytes: device.bundleBytes,
            }),
        );
    }

    // 5. The new identity must not already be in the list. A duplicate identity
    //    under two device ids makes `FanoutSession::establish_from_bundles` fail
    //    for every sender, and re-adding a device under its old key is exactly
    //    what §8.4 forbids. Device 0 is included in the comparison.
    for (const entry of entries) {
        if (bytesEqual(entry.identityKey, newDeviceIdentityKey)) {
            throw new Error('link request: identity key is already present in the device list');
        }
    }

    // 6. Append the new device at the next free id.
    const deviceId = nextDeviceId(entries);
    const nextEntries: DeviceListEntryInput[] = [
        ...entries,
        { deviceId, identityKey: newDeviceIdentityKey, bundleBytes: newDeviceBundle },
    ];

    // 7. Sign the complete list at the next version.
    const version = currentVersion + 1;
    const signedListBytes = deviceListWasm.sign_device_list(
        primaryIdentityHandle.private_bytes(),
        version,
        packEntries(nextEntries),
    );

    // 8. Publish the signed blob under the account handle.
    await publishSignedDeviceList(transport, accountHandle, signedListBytes);

    return {
        version,
        deviceId,
        signedListBytes,
        newDeviceIdentityKey,
        safetyNumber: wasm.derive_safety_number(primaryPublicBytes, newDeviceIdentityKey),
        linkKey,
        newDeviceBundle,
    };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Byte equality for two byte arrays. Not constant-time; identity keys are public. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

/** Read the `u64_le` version prefix `verify_device_list` prepends. */
function readVersion(verified: Uint8Array): number {
    if (verified.length < VERSION_PREFIX_LEN) {
        throw new Error('device list: verified buffer is truncated');
    }
    const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
    const raw = view.getBigUint64(0, true);
    if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('device list: version exceeds the safe integer range');
    }
    return Number(raw);
}

/**
 * Pack entries for `sign_device_list`:
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`,
 * concatenated with no count prefix.
 */
function packEntries(entries: DeviceListEntryInput[]): Uint8Array {
    let size = 0;
    for (const entry of entries) {
        size += 4 + 4 + entry.identityKey.length + 4 + entry.bundleBytes.length;
    }

    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
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
