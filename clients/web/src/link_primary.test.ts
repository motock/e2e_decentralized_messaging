/**
 * Tests for `link_primary` (MD-11): the primary device verifies a link request
 * and publishes the signed version+1 device list.
 *
 * The WASM namespace is partially mocked. The checked-in (stale) wasm package
 * does not export `sign_device_list`, `verify_device_list` or `derive_link_key`
 * at all, so those are replaced; `bundle_identity_key_bytes` and
 * `derive_safety_number` are replaced with fixtures so the mismatch path can
 * present a bundle whose identity key differs from the scanned QR key. The real
 * `decode_device_qr` is preserved: it is a pure hex decode, so the QR payload
 * fixtures below are genuine payloads and the 33-byte contract is exercised.
 *
 * Security properties under test:
 *  - the bundle looked up under the derived link key must carry the identity key
 *    the QR payload named; a mismatch rejects and publishes nothing;
 *  - a missing bundle rejects and publishes nothing (no fallback bundle);
 *  - the published list always contains device 0 (the primary) and the new
 *    device, at version `current + 1`;
 *  - a failed attempt leaves no hidden version state behind: an immediate retry
 *    with a matching bundle publishes `current + 1`, not `current + 2`;
 *  - the list is signed with the primary's private bytes and published under the
 *    account handle.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { LinkPrimaryTransport } from './link_primary';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** 33-byte serialized identity key: 0x05 type tag + 32 key bytes. */
function identityKey(fill: number): Uint8Array {
    return new Uint8Array(33).fill(fill);
}

const PRIMARY_PUBLIC = identityKey(0x05);
const PRIMARY_PRIVATE = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const PRIMARY_BUNDLE = new Uint8Array([0xaa, 0xbb, 0xcc]);

/** The new device's identity key as encoded in the QR payload. */
const NEW_KEY = identityKey(0x11);
/** A bundle identity key that does NOT match the QR key. */
const WRONG_KEY = identityKey(0x22);
const NEW_BUNDLE = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

const DEVICE2_KEY = identityKey(0x33);
const DEVICE2_BUNDLE = new Uint8Array([0x02, 0x02]);

const LINK_KEY = 'link-key-fixture';
const SAFETY_NUMBER = 'safety-number-fixture';
const SIGNED_BLOB = new Uint8Array([0x99, 0x88, 0x77]);
const ACCOUNT_HANDLE = 'account-handle-fixture';

/** Hex QR payload for a 33-byte identity key (the real `decode_device_qr` input). */
function qrPayloadFor(key: Uint8Array): string {
    return Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// WASM boundary mock
// ---------------------------------------------------------------------------

const mocks = vi.hoisted(() => ({
    sign_device_list: vi.fn(),
    verify_device_list: vi.fn(),
    derive_link_key: vi.fn(),
    bundle_identity_key_bytes: vi.fn(),
    derive_safety_number: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        sign_device_list: mocks.sign_device_list,
        verify_device_list: mocks.verify_device_list,
        derive_link_key: mocks.derive_link_key,
        bundle_identity_key_bytes: mocks.bundle_identity_key_bytes,
        derive_safety_number: mocks.derive_safety_number,
    };
});

vi.mock('./wasm_init', () => ({
    ensureWasmInit: vi.fn(async () => undefined),
}));

const { nextDeviceId, buildAndPublishLinkedList } = await import('./link_primary');

// ---------------------------------------------------------------------------
// Test-only packing helpers, derived independently from the Rust layout
// ---------------------------------------------------------------------------

interface PackedEntry {
    deviceId: number;
    identityKey: Uint8Array;
    bundleBytes: Uint8Array;
}

/**
 * Pack entries exactly as the WASM boundary expects:
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`,
 * concatenated with no count prefix.
 */
function encodePackedEntries(entries: PackedEntry[]): Uint8Array {
    const parts: number[] = [];
    const pushU32 = (n: number): void => {
        parts.push(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
    };
    for (const entry of entries) {
        pushU32(entry.deviceId);
        pushU32(entry.identityKey.length);
        parts.push(...entry.identityKey);
        pushU32(entry.bundleBytes.length);
        parts.push(...entry.bundleBytes);
    }
    return Uint8Array.from(parts);
}

/** Decode a packed entry buffer, failing loudly on a partial trailing record. */
function decodePackedEntries(buf: Uint8Array): PackedEntry[] {
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const out: PackedEntry[] = [];
    let pos = 0;
    while (pos < buf.length) {
        expect(pos + 4).toBeLessThanOrEqual(buf.length);
        const deviceId = view.getUint32(pos, true);
        pos += 4;
        const identityLen = view.getUint32(pos, true);
        pos += 4;
        const identityKey = buf.slice(pos, pos + identityLen);
        pos += identityLen;
        const bundleLen = view.getUint32(pos, true);
        pos += 4;
        const bundleBytes = buf.slice(pos, pos + bundleLen);
        pos += bundleLen;
        out.push({ deviceId, identityKey, bundleBytes });
    }
    return out;
}

/** `verify_device_list` output: `u64_le(version) || packed entries`. */
function encodeVerifiedList(version: number, entries: PackedEntry[]): Uint8Array {
    const packed = encodePackedEntries(entries);
    const out = new Uint8Array(8 + packed.length);
    new DataView(out.buffer).setBigUint64(0, BigInt(version), true);
    out.set(packed, 8);
    return out;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function makeIdentityHandle(): { handle: IdentityHandle; privateBytes: ReturnType<typeof vi.fn> } {
    const privateBytes = vi.fn(() => PRIMARY_PRIVATE);
    const handle = {
        public_bytes: vi.fn(() => PRIMARY_PUBLIC),
        private_bytes: privateBytes,
    } as unknown as IdentityHandle;
    return { handle, privateBytes };
}

interface MockTransport {
    lookupPrekey: ReturnType<typeof vi.fn>;
    publishDiscovery: ReturnType<typeof vi.fn>;
    lookupDiscovery: ReturnType<typeof vi.fn>;
}

function makeTransport(): MockTransport {
    return {
        lookupPrekey: vi.fn(async () => NEW_BUNDLE),
        publishDiscovery: vi.fn(async () => undefined),
        lookupDiscovery: vi.fn(async () => null),
    };
}

/** The mock transport satisfies the production transport surface structurally. */
function asTransport(transport: MockTransport): LinkPrimaryTransport {
    return transport as unknown as LinkPrimaryTransport;
}

/** The verified version-7 list: device 0 (primary) and device 2. */
function version7ListBytes(): Uint8Array {
    return encodeVerifiedList(7, [
        { deviceId: 0, identityKey: PRIMARY_PUBLIC, bundleBytes: PRIMARY_BUNDLE },
        { deviceId: 2, identityKey: DEVICE2_KEY, bundleBytes: DEVICE2_BUNDLE },
    ]);
}

beforeEach(() => {
    vi.clearAllMocks();
    mocks.derive_link_key.mockReturnValue(LINK_KEY);
    mocks.bundle_identity_key_bytes.mockReturnValue(NEW_KEY);
    mocks.derive_safety_number.mockReturnValue(SAFETY_NUMBER);
    mocks.sign_device_list.mockReturnValue(SIGNED_BLOB);
    mocks.verify_device_list.mockReturnValue(version7ListBytes());
});

// ---------------------------------------------------------------------------
// nextDeviceId
// ---------------------------------------------------------------------------

describe('nextDeviceId', () => {
    it('returns 1 when there are no entries', () => {
        expect(nextDeviceId([])).toBe(1);
    });

    it('returns 1 when only the primary (device 0) exists', () => {
        expect(nextDeviceId([{ deviceId: 0 }])).toBe(1);
    });

    it('returns max(deviceId) + 1 for the highest non-zero id', () => {
        expect(nextDeviceId([{ deviceId: 1 }, { deviceId: 3 }])).toBe(4);
    });

    it('never returns 0, even for a list of only device 0', () => {
        expect(nextDeviceId([{ deviceId: 0 }, { deviceId: 0 }])).toBe(1);
    });

    it('does not mutate its input', () => {
        const entries = [{ deviceId: 1 }, { deviceId: 3 }];
        const snapshot = JSON.parse(JSON.stringify(entries));
        nextDeviceId(entries);
        expect(entries).toEqual(snapshot);
    });
});

// ---------------------------------------------------------------------------
// buildAndPublishLinkedList — positive paths
// ---------------------------------------------------------------------------

describe('buildAndPublishLinkedList with no current list', () => {
    it('publishes version 1 containing device 0 and the new device 1', async () => {
        const transport = makeTransport();
        const { handle, privateBytes } = makeIdentityHandle();

        const result = await buildAndPublishLinkedList({
            transport: asTransport(transport),
            qrPayload: qrPayloadFor(NEW_KEY),
            primaryIdentityHandle: handle,
            primaryBundleBytes: PRIMARY_BUNDLE,
            currentListBytes: null,
            accountHandle: ACCOUNT_HANDLE,
        });

        // The link key is derived from the scanned QR key and used for the lookup.
        expect(mocks.derive_link_key).toHaveBeenCalledWith(NEW_KEY);
        expect(transport.lookupPrekey).toHaveBeenCalledWith(LINK_KEY);

        // Signed with the primary's private bytes at version 1.
        expect(privateBytes).toHaveBeenCalled();
        expect(mocks.sign_device_list).toHaveBeenCalledTimes(1);
        const [signPrivate, signVersion, packed] = mocks.sign_device_list.mock.calls[0];
        expect(signPrivate).toEqual(PRIMARY_PRIVATE);
        expect(signVersion).toBe(1);

        const entries = decodePackedEntries(packed as Uint8Array);
        expect(entries.map((e) => e.deviceId)).toEqual([0, 1]);
        expect(entries[0].identityKey).toEqual(PRIMARY_PUBLIC);
        expect(entries[0].bundleBytes).toEqual(PRIMARY_BUNDLE);
        expect(entries[1].identityKey).toEqual(NEW_KEY);
        expect(entries[1].bundleBytes).toEqual(NEW_BUNDLE);

        // Published exactly once, under the account handle, with the signed bytes.
        expect(transport.publishDiscovery).toHaveBeenCalledTimes(1);
        expect(transport.publishDiscovery).toHaveBeenCalledWith(ACCOUNT_HANDLE, SIGNED_BLOB);

        // Safety number is derived from the primary public key and the new key.
        expect(mocks.derive_safety_number).toHaveBeenCalledWith(PRIMARY_PUBLIC, NEW_KEY);

        expect(result).toEqual({
            version: 1,
            deviceId: 1,
            signedListBytes: SIGNED_BLOB,
            newDeviceIdentityKey: NEW_KEY,
            safetyNumber: SAFETY_NUMBER,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_BUNDLE,
        });
    });
});

describe('buildAndPublishLinkedList with a verified current list', () => {
    it('publishes version 8 preserving device 0 and adding device 3', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        const currentListBytes = version7ListBytes();

        const result = await buildAndPublishLinkedList({
            transport: asTransport(transport),
            qrPayload: qrPayloadFor(NEW_KEY),
            primaryIdentityHandle: handle,
            primaryBundleBytes: PRIMARY_BUNDLE,
            currentListBytes,
            accountHandle: ACCOUNT_HANDLE,
        });

        // The current list is verified against the primary's public key, never trusted.
        expect(mocks.verify_device_list).toHaveBeenCalledWith(currentListBytes, PRIMARY_PUBLIC);

        expect(mocks.sign_device_list).toHaveBeenCalledTimes(1);
        const [, signVersion, packed] = mocks.sign_device_list.mock.calls[0];
        expect(signVersion).toBe(8);

        const entries = decodePackedEntries(packed as Uint8Array);
        expect(entries.map((e) => e.deviceId)).toEqual([0, 2, 3]);
        expect(entries[0].identityKey).toEqual(PRIMARY_PUBLIC);
        expect(entries[0].bundleBytes).toEqual(PRIMARY_BUNDLE);
        expect(entries[1].identityKey).toEqual(DEVICE2_KEY);
        expect(entries[1].bundleBytes).toEqual(DEVICE2_BUNDLE);
        expect(entries[2].identityKey).toEqual(NEW_KEY);
        expect(entries[2].bundleBytes).toEqual(NEW_BUNDLE);

        expect(transport.publishDiscovery).toHaveBeenCalledTimes(1);
        expect(transport.publishDiscovery).toHaveBeenCalledWith(ACCOUNT_HANDLE, SIGNED_BLOB);

        expect(result.version).toBe(8);
        expect(result.deviceId).toBe(3);
        expect(result.signedListBytes).toEqual(SIGNED_BLOB);
        expect(result.newDeviceIdentityKey).toEqual(NEW_KEY);
        expect(result.newDeviceBundle).toEqual(NEW_BUNDLE);
        expect(result.linkKey).toBe(LINK_KEY);
        expect(result.safetyNumber).toBe(SAFETY_NUMBER);
    });
});

// ---------------------------------------------------------------------------
// buildAndPublishLinkedList — negative paths
// ---------------------------------------------------------------------------

describe('buildAndPublishLinkedList identity mismatch', () => {
    it('rejects and publishes nothing when the bundle identity key differs from the QR key', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        mocks.bundle_identity_key_bytes.mockReturnValue(WRONG_KEY);

        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: version7ListBytes(),
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow();

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });

    it('publishes version 8 on an immediate retry with a matching bundle (no hidden version state)', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        const currentListBytes = version7ListBytes();

        // First attempt: the relay hands back a bundle for a different identity.
        mocks.bundle_identity_key_bytes.mockReturnValue(WRONG_KEY);
        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow();
        expect(transport.publishDiscovery).not.toHaveBeenCalled();

        // Second attempt: the bundle now carries the QR key's identity.
        mocks.bundle_identity_key_bytes.mockReturnValue(NEW_KEY);
        const result = await buildAndPublishLinkedList({
            transport: asTransport(transport),
            qrPayload: qrPayloadFor(NEW_KEY),
            primaryIdentityHandle: handle,
            primaryBundleBytes: PRIMARY_BUNDLE,
            currentListBytes,
            accountHandle: ACCOUNT_HANDLE,
        });

        expect(result.version).toBe(8);
        expect(result.deviceId).toBe(3);
        expect(transport.publishDiscovery).toHaveBeenCalledTimes(1);
        expect(transport.publishDiscovery).toHaveBeenCalledWith(ACCOUNT_HANDLE, SIGNED_BLOB);
    });
});

describe('buildAndPublishLinkedList missing bundle', () => {
    it('rejects and publishes nothing when lookupPrekey reports NotFound', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        const notFound = new Error('NotFound');
        transport.lookupPrekey.mockRejectedValue(notFound);

        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: null,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow('NotFound');

        expect(transport.lookupPrekey).toHaveBeenCalledWith(LINK_KEY);
        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// buildAndPublishLinkedList — duplicate identity keys (BLOCKING 1)
// ---------------------------------------------------------------------------

describe('buildAndPublishLinkedList duplicate identity key', () => {
    it('rejects and publishes nothing when the QR key is already in the list', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        // The bundle genuinely belongs to DEVICE2_KEY, so the identity-binding
        // check passes and the duplicate check is what rejects.
        mocks.bundle_identity_key_bytes.mockReturnValue(DEVICE2_KEY);

        // The version-7 list already carries DEVICE2_KEY at device 2.
        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(DEVICE2_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: version7ListBytes(),
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/already present/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });

    it('rejects a QR naming the primary identity key (device 0 is compared too)', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        mocks.bundle_identity_key_bytes.mockReturnValue(PRIMARY_PUBLIC);

        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(PRIMARY_PUBLIC),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: version7ListBytes(),
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/already present/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });

    it('rejects a re-scan of a device that was already linked', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        // A list that already contains NEW_KEY at device 3 (a prior successful link).
        const listWithNewKey = encodeVerifiedList(8, [
            { deviceId: 0, identityKey: PRIMARY_PUBLIC, bundleBytes: PRIMARY_BUNDLE },
            { deviceId: 2, identityKey: DEVICE2_KEY, bundleBytes: DEVICE2_BUNDLE },
            { deviceId: 3, identityKey: NEW_KEY, bundleBytes: NEW_BUNDLE },
        ]);
        mocks.verify_device_list.mockReturnValue(listWithNewKey);

        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: listWithNewKey,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/already present/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// buildAndPublishLinkedList — freshness / rollback (BLOCKING 2)
// ---------------------------------------------------------------------------

describe('buildAndPublishLinkedList held version', () => {
    it('rejects a verified list older than the version already held', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();

        // The relay serves a validly-signed v7 list while this device holds v9.
        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: version7ListBytes(),
                heldVersion: 9,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/older than the version already held/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });

    it('publishes version 8 when the held version matches the verified list', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();

        const result = await buildAndPublishLinkedList({
            transport: asTransport(transport),
            qrPayload: qrPayloadFor(NEW_KEY),
            primaryIdentityHandle: handle,
            primaryBundleBytes: PRIMARY_BUNDLE,
            currentListBytes: version7ListBytes(),
            heldVersion: 7,
            accountHandle: ACCOUNT_HANDLE,
        });

        expect(result.version).toBe(8);
        expect(result.deviceId).toBe(3);
        expect(transport.publishDiscovery).toHaveBeenCalledTimes(1);
    });

    it('rejects a missing list when a version is already held (relay NotFound rollback)', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();

        // The relay answers `NotFound`, so the caller has no list to verify. The
        // effective current version is 0, which is older than the held version:
        // signing here would publish version 1 holding only device 0 + the new
        // device, silently dropping every other device.
        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: null,
                heldVersion: 9,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/older than the version already held/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });

    it('rejects a held version that is not a non-negative safe integer', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();

        // `NaN` compares false against every version, so an unvalidated guard
        // would silently disable rollback protection.
        for (const heldVersion of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
            await expect(
                buildAndPublishLinkedList({
                    transport: asTransport(transport),
                    qrPayload: qrPayloadFor(NEW_KEY),
                    primaryIdentityHandle: handle,
                    primaryBundleBytes: PRIMARY_BUNDLE,
                    currentListBytes: version7ListBytes(),
                    heldVersion,
                    accountHandle: ACCOUNT_HANDLE,
                }),
            ).rejects.toThrow(/held version is not a valid list version/);
        }

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// buildAndPublishLinkedList — hostile device ids (packing range check)
// ---------------------------------------------------------------------------

describe('buildAndPublishLinkedList device id range', () => {
    it('rejects a list whose next device id would overflow u32', async () => {
        const transport = makeTransport();
        const { handle } = makeIdentityHandle();
        const hostile = encodeVerifiedList(7, [
            { deviceId: 0, identityKey: PRIMARY_PUBLIC, bundleBytes: PRIMARY_BUNDLE },
            { deviceId: 0xffffffff, identityKey: DEVICE2_KEY, bundleBytes: DEVICE2_BUNDLE },
        ]);
        mocks.verify_device_list.mockReturnValue(hostile);

        await expect(
            buildAndPublishLinkedList({
                transport: asTransport(transport),
                qrPayload: qrPayloadFor(NEW_KEY),
                primaryIdentityHandle: handle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: hostile,
                accountHandle: ACCOUNT_HANDLE,
            }),
        ).rejects.toThrow(/out of range/);

        expect(transport.publishDiscovery).not.toHaveBeenCalled();
        expect(mocks.sign_device_list).not.toHaveBeenCalled();
    });
});
