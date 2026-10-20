/**
 * MF-8: the shared version-prefix splitter and entry packer.
 *
 * `discovery.ts` owns the canonical `u64_le(version) || packed entries` codec
 * for the buffer `verify_device_list` returns. `revocation.ts` used to carry a
 * private copy of both halves; these tests pin the shared exports so the two
 * modules cannot drift apart again.
 *
 * CONTRACT pinned here:
 *   * `packEntries(version, entries)` returns `u64_le(version)` followed by the
 *     packed entry buffer (`u32_le(deviceId) | u32_le(identityLen) | identity |
 *     u32_le(bundleLen) | bundle`, no count prefix).
 *   * `splitVerified(buffer)` is its exact inverse.
 *   * A buffer shorter than the 8-byte prefix throws rather than zero-filling.
 *   * A version above `Number.MAX_SAFE_INTEGER` is rejected on both sides — a
 *     32-bit `| 0` shortcut would silently turn 2^53 into 0 and accept it.
 *   * A rejected call leaves no retained state behind: the next call still
 *     round-trips.
 *
 * The WASM module is mocked because this environment has no wasm32 toolchain
 * to rebuild `core/bindings/wasm/pkg`; nothing here calls into it.
 */
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    sign_device_list: () => {
        throw new Error('not used by the shared codec tests');
    },
    verify_device_list: () => {
        throw new Error('not used by the shared codec tests');
    },
}));
vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { packEntries, splitVerified, toConversationDeviceList } from './discovery';
import type { DeviceListEntry } from './Conversation';

/** A minimal entry the packer accepts: 33-byte identity key, non-empty bundle. */
function entry(deviceId: number, identityFill: number, bundleFill: number): DeviceListEntry {
    return {
        deviceId,
        identityKey: new Uint8Array(33).fill(identityFill),
        bundleBytes: new Uint8Array([bundleFill, bundleFill + 1]),
    };
}

/** The packed entry layout, built independently of the implementation. */
function expectedPackedEntries(entries: DeviceListEntry[]): Uint8Array {
    const parts: Uint8Array[] = [];
    for (const e of entries) {
        const head = new Uint8Array(8);
        const headView = new DataView(head.buffer);
        headView.setUint32(0, e.deviceId, true);
        headView.setUint32(4, e.identityKey.length, true);
        const tail = new Uint8Array(4);
        new DataView(tail.buffer).setUint32(0, e.bundleBytes.length, true);
        parts.push(head, e.identityKey, tail, e.bundleBytes);
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) {
        out.set(p, at);
        at += p.length;
    }
    return out;
}

const ENTRIES: DeviceListEntry[] = [entry(1, 0xde, 0xad), entry(2, 0x01, 0x02)];

describe('shared packEntries / splitVerified codec', () => {
    it('packs u64_le(version) followed by the entries and splits back unchanged', () => {
        const packed = packEntries(7, ENTRIES);

        // The version prefix is little-endian u64: 07 00 00 00 00 00 00 00.
        expect(Array.from(packed.slice(0, 8))).toEqual([7, 0, 0, 0, 0, 0, 0, 0]);
        expect(Array.from(packed.slice(8))).toEqual(Array.from(expectedPackedEntries(ENTRIES)));

        const { version, packedEntries } = splitVerified(packed);
        expect(version).toBe(7);
        expect(Array.from(packedEntries)).toEqual(Array.from(expectedPackedEntries(ENTRIES)));

        // The split entry buffer is the layout `toConversationDeviceList` parses.
        const list = toConversationDeviceList(version, packedEntries);
        expect(list.version).toBe(7);
        expect(list.devices.map((d) => d.deviceId)).toEqual([1, 2]);
        expect(Array.from(list.devices[0].identityKey)).toEqual(Array.from(ENTRIES[0].identityKey));
        expect(Array.from(list.devices[1].bundleBytes)).toEqual(Array.from(ENTRIES[1].bundleBytes));
    });

    it('packs an empty entry list as just the version prefix', () => {
        const packed = packEntries(3, []);
        expect(packed.length).toBe(8);
        const { version, packedEntries } = splitVerified(packed);
        expect(version).toBe(3);
        expect(packedEntries.length).toBe(0);
    });

    it('throws on a buffer shorter than the version prefix instead of zero-filling', () => {
        const truncated = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        expect(() => splitVerified(truncated)).toThrow('device list: verified buffer is truncated');
        expect(() => splitVerified(new Uint8Array(0))).toThrow(
            'device list: verified buffer is truncated',
        );
    });

    it('accepts Number.MAX_SAFE_INTEGER as a version', () => {
        const packed = packEntries(Number.MAX_SAFE_INTEGER, ENTRIES);
        // 9007199254740991 == 0x1f_ffff_ffff_ffff, little-endian.
        expect(Array.from(packed.slice(0, 8))).toEqual([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00]);
        expect(splitVerified(packed).version).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('rejects a version above Number.MAX_SAFE_INTEGER when packing', () => {
        expect(() => packEntries(Number.MAX_SAFE_INTEGER + 1, ENTRIES)).toThrow(
            'device list: version is out of range',
        );
        // 2^53 is exactly the value a `version | 0` shortcut would fold to 0.
        expect(() => packEntries(9007199254740992, ENTRIES)).toThrow(
            'device list: version is out of range',
        );
    });

    it('rejects a negative or non-integer version when packing', () => {
        expect(() => packEntries(-1, ENTRIES)).toThrow('device list: version is out of range');
        expect(() => packEntries(1.5, ENTRIES)).toThrow('device list: version is out of range');
        expect(() => packEntries(Number.NaN, ENTRIES)).toThrow('device list: version is out of range');
    });

    it('rejects a version above Number.MAX_SAFE_INTEGER when splitting', () => {
        const packed = new Uint8Array(8);
        new DataView(packed.buffer).setBigUint64(0, 9007199254740992n, true);
        expect(() => splitVerified(packed)).toThrow('device list: version is out of range');
    });

    it('still round-trips after both rejected cases (no retained state)', () => {
        expect(() => splitVerified(new Uint8Array(7))).toThrow();
        expect(() => packEntries(9007199254740992, ENTRIES)).toThrow();

        const packed = packEntries(7, ENTRIES);
        expect(Array.from(packed.slice(0, 8))).toEqual([7, 0, 0, 0, 0, 0, 0, 0]);
        expect(splitVerified(packed).version).toBe(7);
        expect(Array.from(splitVerified(packed).packedEntries)).toEqual(
            Array.from(expectedPackedEntries(ENTRIES)),
        );
    });

    it('keeps the entry bounds the revocation copy enforced', () => {
        expect(() => packEntries(1, [{ ...entry(1, 0x11, 0x22), identityKey: new Uint8Array(32) }])).toThrow(
            'device list: identity key is not 33 bytes',
        );
        expect(() => packEntries(1, [{ ...entry(1, 0x11, 0x22), bundleBytes: new Uint8Array(0) }])).toThrow(
            'device list: bundle is empty',
        );
        expect(() => packEntries(1, [{ ...entry(1, 0x11, 0x22), deviceId: -1 }])).toThrow(
            'device list: device id is out of range',
        );
        expect(() => packEntries(1, [{ ...entry(1, 0x11, 0x22), deviceId: 0x1_0000_0000 }])).toThrow(
            'device list: device id is out of range',
        );
    });
});
