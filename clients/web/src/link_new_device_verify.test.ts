/**
 * Tests for `verifyLinkResponse` (MD-14): the new device re-verifies the
 * primary's signed device list at the public boundary, converts the packed
 * entries into a `DeviceList`, and derives the out-of-band safety number the
 * user compares on both devices before anything is persisted.
 *
 * `awaitLinkResponse` (MD-13) already verified the list once, but
 * `verifyLinkResponse` takes a caller-supplied object, so it must not trust it:
 * these tests pin the *second* verification, the version/entry conversion, and
 * the safety-number derivation. MD-13's own verification table is covered by
 * `link_response.test.ts` and is deliberately not duplicated here.
 *
 * The WASM namespace is partially mocked. `verify_device_list` is replaced by a
 * stand-in that models the real contract — the blob is
 * `payload || sha256(payload || accountKey)` and a foreign key or a flipped byte
 * throws — while `derive_safety_number` is the real binding, so the safety
 * number asserted below is a genuine 12-group fingerprint.
 *
 * Security properties under test:
 *  - the list is re-verified against `response.primaryPublicKey`; a tampered
 *    blob rejects and no `DeviceList` is ever returned from unverified bytes;
 *  - the verified list must contain the assigned device id, and that id must be
 *    the one the response reports — a mismatch or a missing entry rejects;
 *  - device id 0 is never a valid assignment;
 *  - the version prefix is bounds-checked (truncated / out of range rejects);
 *  - nothing is persisted: no `StorageGate` method is touched.
 */

import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ verify_device_list: vi.fn() }));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        verify_device_list: mocks.verify_device_list,
    };
});

const { verifyLinkResponse } = await import('./link_new_device');
const { derive_safety_number } = await import('../../../core/bindings/wasm/pkg/index.js');
const { StorageGate } = await import('./storage');

// ── Fixtures ────────────────────────────────────────────────────────────────

/** The primary's 33-byte identity public key (type-tagged Curve25519, 0x05). */
const PRIMARY_PUBLIC_KEY_HEX =
    '05' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
/** This device's own 33-byte identity public key. */
const LOCAL_PUBLIC_KEY_HEX = '05' + '11'.repeat(32);
/** A different device's identity key. */
const OTHER_DEVICE_KEY_HEX = '05' + '22'.repeat(32);
const ACCOUNT_HANDLE = 'alice';
/** The id the primary assigned to this device. */
const ASSIGNED_DEVICE_ID = 2;

const primaryPublicKey = hexToBytes(PRIMARY_PUBLIC_KEY_HEX);
const localPublicKey = hexToBytes(LOCAL_PUBLIC_KEY_HEX);
const otherDeviceKey = hexToBytes(OTHER_DEVICE_KEY_HEX);

// ── Signed device list stand-in ─────────────────────────────────────────────
//
// The real `verify_device_list` checks a signature over the list, bound to the
// account key, and returns `u64_le(version) || packed entries`. The fake below
// models exactly that contract so a tampered blob or a foreign signer fails
// verification just as it would in the Rust core.

interface FakeEntry {
    deviceId: number;
    identityKey: Uint8Array;
}

function u32le(value: number): number[] {
    return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

function u64le(value: number): number[] {
    return [...u32le(value), 0, 0, 0, 0];
}

/** `u64_le(version) || packed entries`, the layout `verify_device_list` returns. */
function packList(version: number, entries: FakeEntry[]): Uint8Array {
    const out: number[] = u64le(version);
    for (const entry of entries) {
        out.push(...u32le(entry.deviceId));
        out.push(...u32le(entry.identityKey.length), ...entry.identityKey);
        out.push(...u32le(0)); // empty prekey bundle
    }
    return Uint8Array.from(out);
}

function signature(payload: Uint8Array, accountKey: Uint8Array): Uint8Array {
    const hash = createHash('sha256');
    hash.update(payload);
    hash.update(accountKey);
    return new Uint8Array(hash.digest());
}

/** Sign a list with `accountKey`, producing the on-the-wire blob. */
function signList(accountKey: Uint8Array, version: number, entries: FakeEntry[]): Uint8Array {
    const payload = packList(version, entries);
    return Uint8Array.from([...payload, ...signature(payload, accountKey)]);
}

/** The stand-in for the real binding: verify the trailing signature. */
function fakeVerifyDeviceList(bytes: Uint8Array, accountKey: Uint8Array): Uint8Array {
    if (bytes.length < 32) throw new Error('device list: malformed blob');
    const payload = bytes.subarray(0, bytes.length - 32);
    const sig = bytes.subarray(bytes.length - 32);
    const expected = signature(payload, accountKey);
    if (sig.length !== expected.length || !sig.every((byte, i) => byte === expected[i])) {
        throw new Error('device list: signature verification failed');
    }
    return payload;
}

/** The list the primary would send: it contains this device at id 2. */
const SIGNED_LIST_BYTES = signList(primaryPublicKey, 7, [
    { deviceId: 1, identityKey: otherDeviceKey },
    { deviceId: ASSIGNED_DEVICE_ID, identityKey: localPublicKey },
]);

/** The MD-12 response shape, as the primary device serialises it. */
function makeResponse(overrides: Partial<Record<string, unknown>> = {}) {
    return {
        accountHandle: ACCOUNT_HANDLE,
        deviceId: ASSIGNED_DEVICE_ID,
        primaryPublicKey,
        signedListBytes: SIGNED_LIST_BYTES,
        ...overrides,
    } as Parameters<typeof verifyLinkResponse>[0]['response'];
}

function verify(overrides: {
    response?: Parameters<typeof verifyLinkResponse>[0]['response'];
    expectedDeviceId?: number;
    localPublicKey?: Uint8Array;
} = {}) {
    return verifyLinkResponse({
        response: overrides.response ?? makeResponse(),
        expectedDeviceId: overrides.expectedDeviceId ?? ASSIGNED_DEVICE_ID,
        localPublicKey: overrides.localPublicKey ?? localPublicKey,
    });
}

function hexToBytes(hex: string): Uint8Array {
    return Uint8Array.from(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
}

beforeEach(() => {
    mocks.verify_device_list.mockReset();
    mocks.verify_device_list.mockImplementation(fakeVerifyDeviceList);
});

// ── Positive path ───────────────────────────────────────────────────────────

describe('verifyLinkResponse — verified conversion', () => {
    it('returns the account handle, device id, primary key and list version', () => {
        const result = verify();

        expect(result.accountHandle).toBe(ACCOUNT_HANDLE);
        expect(result.deviceId).toBe(ASSIGNED_DEVICE_ID);
        expect(result.primaryKey).toEqual(primaryPublicKey);
        expect(result.version).toBe(7);
    });

    it('converts every packed entry into a DeviceList entry', () => {
        const result = verify();

        expect(result.deviceList.version).toBe(7);
        expect(result.deviceList.devices.map((device) => device.deviceId)).toEqual([1, 2]);
        expect(result.deviceList.devices[0].identityKey).toEqual(otherDeviceKey);
        expect(result.deviceList.devices[1].identityKey).toEqual(localPublicKey);
    });

    it('re-verifies the list against the response primary key at this boundary', () => {
        verify();

        expect(mocks.verify_device_list).toHaveBeenCalledTimes(1);
        expect(mocks.verify_device_list).toHaveBeenCalledWith(
            SIGNED_LIST_BYTES,
            primaryPublicKey,
        );
    });

    it('derives a 12-group safety number from the primary key and this device key', () => {
        const result = verify();

        expect(result.safetyNumber).toBe(derive_safety_number(primaryPublicKey, localPublicKey));
        // The binding returns 60 digits; the UI shows them as 12 groups of 5.
        expect(result.safetyNumber).toMatch(/^\d{60}$/);
        const groups = result.safetyNumber.match(/.{5}/g)!;
        expect(groups).toHaveLength(12);
    });

    it('derives the same safety number whichever key is passed first', () => {
        const result = verify();

        expect(result.safetyNumber).toBe(derive_safety_number(localPublicKey, primaryPublicKey));
    });
});

// ── Negative path ───────────────────────────────────────────────────────────

describe('verifyLinkResponse — rejects unverified or inconsistent responses', () => {
    it('rejects a tampered list and returns no DeviceList', () => {
        const tampered = Uint8Array.from(SIGNED_LIST_BYTES);
        tampered[tampered.length - 1] ^= 0xff;

        let result: unknown;
        expect(() => {
            result = verify({ response: makeResponse({ signedListBytes: tampered }) });
        }).toThrow();
        // Fail closed: no partial result, and certainly no unverified list.
        expect(result).toBeUndefined();
    });

    it('rejects a structurally invalid response before touching the list', () => {
        expect(() =>
            verify({ response: makeResponse({ accountHandle: '' }) }),
        ).toThrow(/accountHandle/);
        expect(() =>
            verify({ response: makeResponse({ primaryPublicKey: new Uint8Array(32) }) }),
        ).toThrow(/primaryPublicKey/);
        expect(() =>
            verify({ response: makeResponse({ signedListBytes: 'not-bytes' }) }),
        ).toThrow(/signedListBytes/);
        expect(() => verify({ localPublicKey: new Uint8Array(10) })).toThrow(/localPublicKey/);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects a list signed by a key other than the response primary key', () => {
        const foreign = signList(otherDeviceKey, 7, [
            { deviceId: ASSIGNED_DEVICE_ID, identityKey: localPublicKey },
        ]);

        expect(() => verify({ response: makeResponse({ signedListBytes: foreign }) })).toThrow();
    });

    it('rejects when the assigned id is absent from the verified list', () => {
        const withoutUs = signList(primaryPublicKey, 7, [
            { deviceId: 1, identityKey: otherDeviceKey },
        ]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: withoutUs }) }),
        ).toThrow();
    });

    it('rejects when the response reports a different id than the caller expects', () => {
        expect(() => verify({ expectedDeviceId: 3 })).toThrow();
    });

    it('rejects device id 0 as the assigned id even when the list contains it', () => {
        const withZero = signList(primaryPublicKey, 7, [
            { deviceId: 0, identityKey: localPublicKey },
        ]);

        expect(() =>
            verify({
                response: makeResponse({ deviceId: 0, signedListBytes: withZero }),
                expectedDeviceId: 0,
            }),
        ).toThrow();
    });

    it('rejects an entry whose identity key is not 33 bytes', () => {
        const shortKey = signList(primaryPublicKey, 7, [
            { deviceId: ASSIGNED_DEVICE_ID, identityKey: Uint8Array.from([0x05, ...new Array(31).fill(0x11)]) },
        ]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: shortKey }) }),
        ).toThrow();
    });

    it('rejects a verified buffer too short to carry the version prefix', () => {
        // A correctly signed blob whose payload is only 4 bytes: verification
        // succeeds, so the rejection must come from the version-prefix check.
        const payload = Uint8Array.from([0x07, 0x00, 0x00, 0x00]);
        const truncated = Uint8Array.from([...payload, ...signature(payload, primaryPublicKey)]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: truncated }) }),
        ).toThrow(/truncated/);
    });

    it('rejects a version that exceeds Number.MAX_SAFE_INTEGER', () => {
        const payload = Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        const huge = Uint8Array.from([...payload, ...signature(payload, primaryPublicKey)]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: huge }) }),
        ).toThrow();
    });

    it('rejects a truncated packed entry rather than dropping the device', () => {
        const payload = Uint8Array.from([...u64le(7), ...u32le(ASSIGNED_DEVICE_ID), 0x21, 0x00, 0x00, 0x00]);
        const truncatedEntry = Uint8Array.from([
            ...payload,
            ...signature(payload, primaryPublicKey),
        ]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: truncatedEntry }) }),
        ).toThrow();
    });
});

// ── Boundary hardening (review round 2) ─────────────────────────────────────
//
// `verifyLinkResponse` is the API MD-16 persists from, so every check
// `parseLinkResponse` performs must hold here too — otherwise the gaps are
// inherited by the persisting caller.

describe('verifyLinkResponse — binds the assigned entry to this device', () => {
    it('rejects a list whose assigned id carries a foreign identity key', () => {
        // The list is validly signed by the primary, but "this device" at the
        // assigned id is bound to an attacker-chosen key. The safety number is
        // still derived from the honest local key, so accepting this would let
        // the out-of-band comparison cover a list entry it does not describe.
        const foreignBinding = signList(primaryPublicKey, 7, [
            { deviceId: 1, identityKey: otherDeviceKey },
            { deviceId: ASSIGNED_DEVICE_ID, identityKey: otherDeviceKey },
        ]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: foreignBinding }) }),
        ).toThrow(/identity key/i);
    });

    it('rejects a foreign key that differs from the local key in one byte', () => {
        const almostLocal = Uint8Array.from(localPublicKey);
        almostLocal[almostLocal.length - 1] ^= 0x01;
        const nearMiss = signList(primaryPublicKey, 7, [
            { deviceId: ASSIGNED_DEVICE_ID, identityKey: almostLocal },
        ]);

        expect(() => verify({ response: makeResponse({ signedListBytes: nearMiss }) })).toThrow();
    });

    it('accepts the honest binding and returns this device key in the list', () => {
        const result = verify();

        const assigned = result.deviceList.devices.find(
            (device) => device.deviceId === ASSIGNED_DEVICE_ID,
        );
        expect(assigned?.identityKey).toEqual(localPublicKey);
    });
});

describe('verifyLinkResponse — validates the display-bound account handle', () => {
    it('rejects a handle longer than 64 characters', () => {
        expect(() =>
            verify({ response: makeResponse({ accountHandle: 'a'.repeat(65) }) }),
        ).toThrow(/accountHandle/);
    });

    it('accepts a handle of exactly 64 characters', () => {
        expect(verify({ response: makeResponse({ accountHandle: 'a'.repeat(64) }) }).accountHandle)
            .toHaveLength(64);
    });

    it('rejects a handle containing bidi overrides or control characters', () => {
        for (const handle of ['al\u202eice', 'al\u2066ice', 'al\u0000ice', 'al\u009bice']) {
            expect(() =>
                verify({ response: makeResponse({ accountHandle: handle }) }),
            ).toThrow(/accountHandle/);
        }
    });

    it('rejects a whitespace-only handle', () => {
        expect(() => verify({ response: makeResponse({ accountHandle: '   ' }) })).toThrow(
            /accountHandle/,
        );
    });

    it('rejects a handle containing a zero-width character', () => {
        // U+200B renders as nothing, so "ali\u200Bce" and "alice" look identical
        // while comparing unequal — a handle-spoofing vector.
        expect(() =>
            verify({ response: makeResponse({ accountHandle: 'ali\u200Bce' }) }),
        ).toThrow(/accountHandle/);
    });

    it('rejects a handle containing a zero-width no-break space', () => {
        expect(() =>
            verify({ response: makeResponse({ accountHandle: 'ali\uFEFFce' }) }),
        ).toThrow(/accountHandle/);
    });

    it('rejects a handle containing an Arabic letter mark', () => {
        expect(() =>
            verify({ response: makeResponse({ accountHandle: 'ali\u061Cce' }) }),
        ).toThrow(/accountHandle/);
    });

    it('rejects a handle containing a line separator', () => {
        expect(() =>
            verify({ response: makeResponse({ accountHandle: 'ali\u2028ce' }) }),
        ).toThrow(/accountHandle/);
    });

    it('returns the handle trimmed so padded and unpadded handles compare equal', () => {
        expect(verify({ response: makeResponse({ accountHandle: '  alice  ' }) }).accountHandle)
            .toBe('alice');
    });
});

describe('verifyLinkResponse — bounds the untrusted inputs', () => {
    it('rejects a signed list larger than 64 KiB before verifying it', () => {
        const payload = new Uint8Array(64 * 1024 + 1);
        const oversized = Uint8Array.from([...payload, ...signature(payload, primaryPublicKey)]);

        expect(() =>
            verify({ response: makeResponse({ signedListBytes: oversized }) }),
        ).toThrow(/signedListBytes/);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects a primary key without the identity-key type byte', () => {
        const wrongType = Uint8Array.from(primaryPublicKey);
        wrongType[0] = 0x02;

        expect(() =>
            verify({ response: makeResponse({ primaryPublicKey: wrongType }) }),
        ).toThrow(/primaryPublicKey/);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects a local key without the identity-key type byte', () => {
        const wrongType = Uint8Array.from(localPublicKey);
        wrongType[0] = 0x04;

        expect(() => verify({ localPublicKey: wrongType })).toThrow(/localPublicKey/);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects an array posing as a response object', () => {
        expect(() =>
            verifyLinkResponse({
                response: [] as unknown as Parameters<typeof verifyLinkResponse>[0]['response'],
                expectedDeviceId: ASSIGNED_DEVICE_ID,
                localPublicKey,
            }),
        ).toThrow(/object/);
    });
});

// ── No persistence ──────────────────────────────────────────────────────────

describe('verifyLinkResponse — persists nothing', () => {
    it('never touches StorageGate, on success or on failure', () => {
        const methods = Object.getOwnPropertyNames(StorageGate.prototype).filter(
            (name) => name !== 'constructor',
        );
        const spies = methods.map((name) =>
            vi.spyOn(StorageGate.prototype as unknown as Record<string, () => unknown>, name),
        );

        try {
            verify();

            const tampered = Uint8Array.from(SIGNED_LIST_BYTES);
            tampered[0] ^= 0xff;
            expect(() =>
                verify({ response: makeResponse({ signedListBytes: tampered }) }),
            ).toThrow();

            for (const spy of spies) expect(spy).not.toHaveBeenCalled();
        } finally {
            for (const spy of spies) spy.mockRestore();
        }
    });
});
