//
// Real-WASM integration test for the signed device list (spec/v0.md §8.3, MF-9).
//
// This suite runs against the actual wasm32 module produced by
// `npm run prepare-wasm` (see clients/web/package.json) — nothing about the
// bindings is mocked, matching the repo convention established in
// device_linking.test.ts and wasm_session_persistence.test.ts. The functions
// under test are:
//   sign_device_list(primary_private_bytes, version, entries) -> blob
//   verify_device_list(blob, expected_account) -> u64_le(version) || entries
//
// The packed entry layout (see core/bindings/wasm/src/device_list.rs) is a bare
// concatenation of records, parsed until exhaustion:
//   u32_le(device_id) | u32_le(identity_key_len) | identity_key
//                     | u32_le(prekey_bundle_len) | prekey_bundle
//
// NOTE FOR LOCAL RUNS: the generated `core/bindings/wasm/pkg` directory is
// gitignored and may predate sign_device_list/verify_device_list. Running
// `npx vitest run tests/device_list_sign_verify.test.ts` against such a stale
// pkg fails loudly in the beforeAll guard below (it never skips), so a missing
// binding is visible instead of silently green. Run `npm run prepare-wasm`
// first. CI's web job runs `npm test` (= prepare-wasm && vitest run), so this
// file is exercised there with a freshly built pkg.

import { describe, it, expect, beforeAll } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

/** The subset of the generated bindings this suite exercises. */
interface DeviceListBindings {
    sign_device_list(primaryPrivateBytes: Uint8Array, version: bigint, entries: Uint8Array): Uint8Array;
    verify_device_list(bytes: Uint8Array, expectedAccount: Uint8Array): Uint8Array;
}

/**
 * The generated module, viewed through the device-list surface. A namespace import keeps a
 * stale pkg (one built before these bindings existed) from failing at import time, so the
 * beforeAll guard can report the real problem in prose.
 */
const deviceList = wasm as unknown as DeviceListBindings;

/** The `WasmError::kind` every device-list failure carries. */
const KIND = 'DeviceList';

/** One packed device-list record, as the browser client assembles it. */
interface EntrySpec {
    deviceId: number;
    identityKey: Uint8Array;
    prekeyBundle: Uint8Array;
}

beforeAll(async () => {
    await ensureWasmInit();
    const missing = ['sign_device_list', 'verify_device_list'].filter(
        (name) => typeof (wasm as unknown as Record<string, unknown>)[name] !== 'function',
    );
    if (missing.length > 0) {
        throw new Error(
            `The generated WASM package is missing ${missing.join(', ')}. ` +
                'The local pkg is stale: run `npm run prepare-wasm` in clients/web before ' +
                'running this suite (CI does this via `npm test`).',
        );
    }
});

/** Little-endian `u32` bytes, matching the packed entry layout. */
function u32le(value: number): Uint8Array {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, true);
    return out;
}

/** Concatenate byte arrays in order. */
function concat(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/** Pack entries into the bare concatenation `sign_device_list` expects. */
function packEntries(entries: EntrySpec[]): Uint8Array {
    const parts: Uint8Array[] = [];
    for (const entry of entries) {
        parts.push(
            u32le(entry.deviceId),
            u32le(entry.identityKey.length),
            entry.identityKey,
            u32le(entry.prekeyBundle.length),
            entry.prekeyBundle,
        );
    }
    return concat(parts);
}

/** Parse the packed entry layout back into records, failing on a partial trailing record. */
function parseEntries(packed: Uint8Array): EntrySpec[] {
    const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
    const entries: EntrySpec[] = [];
    let pos = 0;
    while (pos < packed.length) {
        const deviceId = view.getUint32(pos, true);
        pos += 4;
        const keyLen = view.getUint32(pos, true);
        pos += 4;
        const identityKey = packed.slice(pos, pos + keyLen);
        pos += keyLen;
        const bundleLen = view.getUint32(pos, true);
        pos += 4;
        const prekeyBundle = packed.slice(pos, pos + bundleLen);
        pos += bundleLen;
        entries.push({ deviceId, identityKey, prekeyBundle });
    }
    return entries;
}

/** Capture either a call's return value or the error it threw. */
function callCapturing(fn: () => unknown): { returned: unknown; error: unknown } {
    try {
        return { returned: fn(), error: null };
    } catch (error) {
        return { returned: undefined, error };
    }
}

/** A primary identity plus a second device identity, and their packed two-entry list. */
function twoEntryList() {
    const primary = wasm.generate_identity();
    const second = wasm.generate_identity();
    const entries: EntrySpec[] = [
        {
            deviceId: 0,
            identityKey: primary.public_bytes(),
            prekeyBundle: wasm.generate_prekey_bundle(primary),
        },
        {
            deviceId: 1,
            identityKey: second.public_bytes(),
            prekeyBundle: wasm.generate_prekey_bundle(second),
        },
    ];
    return { primary, entries, packed: packEntries(entries) };
}

describe('signed device list (real WASM)', () => {
    it('signs a two-entry list and verifies it against the primary public key', () => {
        const { primary, entries, packed } = twoEntryList();

        const blob = deviceList.sign_device_list(primary.private_bytes(), 5n, packed);
        // The blob carries the signature on top of the entries, so it must be longer.
        expect(blob.length).toBeGreaterThan(packed.length);

        const verified = deviceList.verify_device_list(blob, primary.public_bytes());

        // Layout: u64_le(version) || packed entries.
        expect(verified.length).toBe(8 + packed.length);
        const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
        expect(view.getBigUint64(0, true)).toBe(5n);
        expect(Array.from(verified.slice(8))).toEqual(Array.from(packed));

        const parsed = parseEntries(verified.slice(8));
        expect(parsed.map((entry) => entry.deviceId)).toEqual([0, 1]);
        expect(Array.from(parsed[0].identityKey)).toEqual(Array.from(entries[0].identityKey));
        expect(Array.from(parsed[0].prekeyBundle)).toEqual(Array.from(entries[0].prekeyBundle));
        expect(Array.from(parsed[1].identityKey)).toEqual(Array.from(entries[1].identityKey));
        expect(Array.from(parsed[1].prekeyBundle)).toEqual(Array.from(entries[1].prekeyBundle));
    });

    it('rejects a list whose signature byte was flipped', () => {
        const { primary, packed } = twoEntryList();
        const blob = deviceList.sign_device_list(primary.private_bytes(), 5n, packed);

        const tampered = blob.slice();
        tampered[tampered.length - 1] ^= 0x01;

        const { returned, error } = callCapturing(() =>
            deviceList.verify_device_list(tampered, primary.public_bytes()),
        );
        expect(returned).toBeUndefined();
        expect((error as { kind: string }).kind).toBe(KIND);
    });

    it('rejects a list verified against a different account key', () => {
        const { primary, packed } = twoEntryList();
        const blob = deviceList.sign_device_list(primary.private_bytes(), 5n, packed);
        const other = wasm.generate_identity();

        const { returned, error } = callCapturing(() =>
            deviceList.verify_device_list(blob, other.public_bytes()),
        );
        expect(returned).toBeUndefined();
        expect((error as { kind: string }).kind).toBe(KIND);
    });

    it('rejects a truncated entry buffer at sign time', () => {
        const { primary, packed } = twoEntryList();
        // Drop the last byte so the final record ends mid-field.
        const truncated = packed.slice(0, packed.length - 1);

        const { returned, error } = callCapturing(() =>
            deviceList.sign_device_list(primary.private_bytes(), 5n, truncated),
        );
        expect(returned).toBeUndefined();
        expect((error as { kind: string }).kind).toBe(KIND);
    });
});
