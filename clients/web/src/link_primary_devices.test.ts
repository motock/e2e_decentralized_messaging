/**
 * DL-1: the real `buildAndPublishLinkedList` must expose the exact entry set it
 * signed as a required `devices` property.
 *
 * The handshake hook reads `built.devices` to hand the caller the list version
 * it just published. The hook's own suite mocks `link_primary`, so it cannot
 * prove that the real build attaches the field at all.
 * This file exercises the real module without touching `link_primary.test.ts`.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { LinkPrimaryTransport } from './link_primary';

function identityKey(fill: number): Uint8Array {
    return new Uint8Array(33).fill(fill);
}

const PRIMARY_PUBLIC = identityKey(0x05);
const PRIMARY_PRIVATE = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
const PRIMARY_BUNDLE = new Uint8Array([0xaa, 0xbb, 0xcc]);
const NEW_KEY = identityKey(0x11);
const NEW_BUNDLE = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const LINK_KEY = 'link-key-fixture';
const SAFETY_NUMBER = 'safety-number-fixture';
const SIGNED_BLOB = new Uint8Array([0x99, 0x88, 0x77]);
const ACCOUNT_HANDLE = 'account-handle-fixture';

function qrPayloadFor(key: Uint8Array): string {
    return Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('');
}

const mocks = vi.hoisted(() => ({
    sign_device_list: vi.fn(),
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
        derive_link_key: mocks.derive_link_key,
        bundle_identity_key_bytes: mocks.bundle_identity_key_bytes,
        derive_safety_number: mocks.derive_safety_number,
    };
});

vi.mock('./wasm_init', () => ({
    ensureWasmInit: vi.fn(async () => undefined),
}));

const { buildAndPublishLinkedList } = await import('./link_primary');

interface PackedEntry {
    deviceId: number;
    identityKey: Uint8Array;
    bundleBytes: Uint8Array;
}

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

function makeIdentityHandle(): IdentityHandle {
    return {
        public_bytes: vi.fn(() => PRIMARY_PUBLIC),
        private_bytes: vi.fn(() => PRIMARY_PRIVATE),
    } as unknown as IdentityHandle;
}

beforeEach(() => {
    vi.clearAllMocks();
    mocks.derive_link_key.mockReturnValue(LINK_KEY);
    mocks.bundle_identity_key_bytes.mockReturnValue(NEW_KEY);
    mocks.derive_safety_number.mockReturnValue(SAFETY_NUMBER);
    mocks.sign_device_list.mockReturnValue(SIGNED_BLOB);
});

describe('buildAndPublishLinkedList exposes the signed entries (DL-1)', () => {
    it('returns the exact signed set', async () => {
        const transport = makeTransport();

        const result = await buildAndPublishLinkedList({
            transport: transport as unknown as LinkPrimaryTransport,
            qrPayload: qrPayloadFor(NEW_KEY),
            primaryIdentityHandle: makeIdentityHandle(),
            primaryBundleBytes: PRIMARY_BUNDLE,
            currentListBytes: null,
            accountHandle: ACCOUNT_HANDLE,
        });

        // The entries the build actually signed.
        const packed = mocks.sign_device_list.mock.calls[0][2] as Uint8Array;
        const signedEntries = decodePackedEntries(packed);
        expect(signedEntries.map((e) => e.deviceId)).toEqual([0, 1]);
        expect(signedEntries[0].identityKey).toEqual(PRIMARY_PUBLIC);
        expect(signedEntries[1].identityKey).toEqual(NEW_KEY);

        // The hook reads this field; it must be the signed set, not a re-parse.
        expect(result.devices).toEqual(signedEntries);

        // Enumerable: the field is part of the API and survives spreads/clones.
        expect(Object.keys(result)).toContain('devices');
        expect(Object.getOwnPropertyDescriptor(result, 'devices')?.enumerable).toBe(true);
        expect(result).toEqual({
            version: 1,
            deviceId: 1,
            signedListBytes: SIGNED_BLOB,
            newDeviceIdentityKey: NEW_KEY,
            safetyNumber: SAFETY_NUMBER,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_BUNDLE,
            devices: signedEntries,
        });
    });
});
