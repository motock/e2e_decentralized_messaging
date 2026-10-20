// MD-18: revoking a linked device re-signs and re-publishes the account's
// signed device list at version+1.
//
// CONTRACT pinned here (the implementation must match it):
//   * `revokeDevice({ currentListBytes, primaryIdentityHandle, deviceId,
//     accountHandle, transport })` verifies `currentListBytes` against the
//     primary's public key BEFORE trusting any of it (fail closed), rejects
//     device 0 (the primary can never be revoked), drops the entry, signs the
//     remaining devices at version+1, publishes the new blob for
//     `accountHandle`, and returns both the new bytes and the new DeviceList.
//   * Every rejection path publishes NOTHING — a failed revoke must never
//     replace the relay's list with a partial or unverified one.
//
// The WASM module is mocked here because this environment has no wasm32
// toolchain to rebuild `core/bindings/wasm/pkg` (the checked-in pkg predates
// `sign_device_list` / `verify_device_list`). The fake below models the
// documented contract exactly — `verify_device_list(bytes, expectedAccount)`
// returns `u64_le(version)` followed by the packed entry buffer, and rejects a
// blob signed by another account. The real Rust signer/verifier is covered by
// `core/bindings/wasm/src/device_list.rs`'s own unit tests; these tests grade
// the web-side orchestration in `src/revocation.ts`.

import { describe, test, expect, vi } from 'vitest';

// ── Fake WASM device-list signer/verifier ───────────────────────────────────
// A blob is `pub(33) | u64_le(version) | packed entries | tag(32)`, where the
// tag binds the account key, version and entries. `verify_device_list` checks
// the tag against the expected account and returns `u64_le(version) | packed`.
const fake = vi.hoisted(() => {
    const accounts = new Map<string, Uint8Array>();
    const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    const fnv = (b: Uint8Array) => {
        let h = 0x811c9dc5;
        for (const x of b) { h ^= x; h = Math.imul(h, 0x01000193) >>> 0; }
        return h >>> 0;
    };
    const tagFor = (pub: Uint8Array, version: number, entries: Uint8Array) => {
        const buf = new Uint8Array(33 + 8 + entries.length);
        buf.set(pub, 0);
        new DataView(buf.buffer).setBigUint64(33, BigInt(version), true);
        buf.set(entries, 41);
        const h = fnv(buf);
        const tag = new Uint8Array(32);
        for (let i = 0; i < 32; i++) tag[i] = ((h >>> ((i % 4) * 8)) & 0xff) ^ i;
        return tag;
    };
    const fail = (message: string): never => {
        throw new Error(message);
    };
    return {
        accounts,
        sign_device_list: (privateBytes: Uint8Array, version: number, entries: Uint8Array) => {
            const pub = accounts.get(hex(privateBytes));
            if (!pub) fail('UnknownAccount');
            const out = new Uint8Array(33 + 8 + entries.length + 32);
            out.set(pub!, 0);
            new DataView(out.buffer).setBigUint64(33, BigInt(version), true);
            out.set(entries, 41);
            out.set(tagFor(pub!, version, entries), 41 + entries.length);
            return out;
        },
        verify_device_list: (bytes: Uint8Array, expectedAccount: Uint8Array) => {
            if (bytes.length < 33 + 8 + 32) fail('Truncated');
            const pub = bytes.slice(0, 33);
            if (hex(pub) !== hex(expectedAccount)) fail('WrongAccount');
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            const version = Number(view.getBigUint64(33, true));
            const entries = bytes.slice(41, bytes.length - 32);
            const tag = bytes.slice(bytes.length - 32);
            const expected = tagFor(pub, version, entries);
            if (hex(tag) !== hex(expected)) fail('BadSignature');
            const out = new Uint8Array(8 + entries.length);
            new DataView(out.buffer).setBigUint64(0, BigInt(version), true);
            out.set(entries, 8);
            return out;
        },
    };
});

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    sign_device_list: fake.sign_device_list,
    verify_device_list: fake.verify_device_list,
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { revokeDevice } from '../src/revocation';

interface Entry {
    deviceId: number;
    identityKey: Uint8Array;
    bundleBytes: Uint8Array;
}

const BUNDLE = new Uint8Array([7, 7, 7]);

/** A device entry with a 33-byte identity key (the length every binding requires). */
function device(deviceId: number): Entry {
    return {
        deviceId,
        identityKey: new Uint8Array(33).fill(deviceId + 1),
        bundleBytes: BUNDLE,
    };
}

/** Pack entries exactly as `sign_device_list` expects (no count prefix). */
function pack(entries: Entry[]): Uint8Array {
    let size = 0;
    for (const entry of entries) {
        size += 12 + entry.identityKey.length + entry.bundleBytes.length;
    }
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const entry of entries) {
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

/** Decode a signed blob back to its version and device ids (via the fake verifier). */
function decode(bytes: Uint8Array, account: Uint8Array): { version: number; deviceIds: number[] } {
    const verified = fake.verify_device_list(bytes, account);
    const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
    const version = Number(view.getBigUint64(0, true));
    const packed = verified.subarray(8);
    const packedView = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
    const deviceIds: number[] = [];
    let pos = 0;
    while (pos < packed.length) {
        deviceIds.push(packedView.getUint32(pos, true));
        pos += 4;
        const idLen = packedView.getUint32(pos, true);
        pos += 4 + idLen;
        const bundleLen = packedView.getUint32(pos, true);
        pos += 4 + bundleLen;
    }
    return { version, deviceIds };
}

/** A discovery transport stub that records what was published. */
function makeTransport() {
    const published: { handle: string; bytes: Uint8Array }[] = [];
    return {
        published,
        transport: {
            publishDiscovery: async (handle: string, bytes: Uint8Array) => {
                published.push({ handle, bytes });
            },
            lookupDiscovery: async () => null,
        },
    };
}

/** A primary identity: 32 private bytes registered with the fake signer. */
function makePrimary(seed = 3) {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = (i * 7 + seed) & 0xff;
    const pub = new Uint8Array(33);
    pub[0] = 5;
    for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
    fake.accounts.set(
        Array.from(priv, (x) => x.toString(16).padStart(2, '0')).join(''),
        pub,
    );
    return {
        public_bytes: () => pub.slice(),
        private_bytes: () => priv.slice(),
    };
}

const ACCOUNT_HANDLE = 'alice-account';

describe('revokeDevice (MD-18)', () => {
    test('revoking device 2 from version 1 publishes version 2 without device 2 and with device 0', async () => {
        const primary = makePrimary();
        const currentListBytes = fake.sign_device_list(
            primary.private_bytes(),
            1,
            pack([device(0), device(2)]),
        );
        const { published, transport } = makeTransport();

        const result = await revokeDevice({
            currentListBytes,
            primaryIdentityHandle: primary,
            deviceId: 2,
            accountHandle: ACCOUNT_HANDLE,
            transport,
        });

        // Returned list: version bumped, device 2 gone, device 0 kept.
        expect(result.deviceList.version).toBe(2);
        expect(result.deviceList.devices.map((d) => d.deviceId)).toEqual([0]);

        // Published blob: exactly one publish, for this account, verifying to v2.
        expect(published).toHaveLength(1);
        expect(published[0].handle).toBe(ACCOUNT_HANDLE);
        expect(published[0].bytes).toEqual(result.signedListBytes);
        expect(decode(published[0].bytes, primary.public_bytes())).toEqual({
            version: 2,
            deviceIds: [0],
        });
    });

    test('the primary device (0) cannot be revoked and nothing is published', async () => {
        const primary = makePrimary();
        const currentListBytes = fake.sign_device_list(
            primary.private_bytes(),
            1,
            pack([device(0), device(2)]),
        );
        const { published, transport } = makeTransport();

        await expect(
            revokeDevice({
                currentListBytes,
                primaryIdentityHandle: primary,
                deviceId: 0,
                accountHandle: ACCOUNT_HANDLE,
                transport,
            }),
        ).rejects.toThrow(/primary/i);

        expect(published).toHaveLength(0);
    });

    test('an unverifiable current list is rejected and nothing is published', async () => {
        const primary = makePrimary();
        const impostor = makePrimary(99);
        // Signed by the WRONG key: verification against the primary must fail.
        const currentListBytes = fake.sign_device_list(
            impostor.private_bytes(),
            1,
            pack([device(0), device(2)]),
        );
        const { published, transport } = makeTransport();

        await expect(
            revokeDevice({
                currentListBytes,
                primaryIdentityHandle: primary,
                deviceId: 2,
                accountHandle: ACCOUNT_HANDLE,
                transport,
            }),
        ).rejects.toThrow();

        expect(published).toHaveLength(0);
    });

    test('a tampered current list is rejected and nothing is published', async () => {
        const primary = makePrimary();
        const currentListBytes = fake.sign_device_list(
            primary.private_bytes(),
            1,
            pack([device(0), device(2)]),
        );
        // Flip a byte inside the packed entries: the signature no longer binds.
        currentListBytes[45] ^= 0xff;
        const { published, transport } = makeTransport();

        await expect(
            revokeDevice({
                currentListBytes,
                primaryIdentityHandle: primary,
                deviceId: 2,
                accountHandle: ACCOUNT_HANDLE,
                transport,
            }),
        ).rejects.toThrow();

        expect(published).toHaveLength(0);
    });

    test('a device that is not in the list is rejected and nothing is published', async () => {
        const primary = makePrimary();
        const currentListBytes = fake.sign_device_list(
            primary.private_bytes(),
            1,
            pack([device(0), device(2)]),
        );
        const { published, transport } = makeTransport();

        await expect(
            revokeDevice({
                currentListBytes,
                primaryIdentityHandle: primary,
                deviceId: 5,
                accountHandle: ACCOUNT_HANDLE,
                transport,
            }),
        ).rejects.toThrow(/not in the list/i);

        expect(published).toHaveLength(0);
    });

    test.each([-1, 1.5, Number.NaN])(
        'an out-of-range device id (%s) is rejected and nothing is published',
        async (deviceId) => {
            const primary = makePrimary();
            const currentListBytes = fake.sign_device_list(
                primary.private_bytes(),
                1,
                pack([device(0), device(2)]),
            );
            const { published, transport } = makeTransport();

            await expect(
                revokeDevice({
                    currentListBytes,
                    primaryIdentityHandle: primary,
                    deviceId,
                    accountHandle: ACCOUNT_HANDLE,
                    transport,
                }),
            ).rejects.toThrow(/out of range/i);

            expect(published).toHaveLength(0);
        },
    );
});
