/**
 * Group member → per-device recipient resolution: GF-2 hardening.
 *
 * GF-1 built the resolver; these tests pin the gaps GF-2 closes:
 *
 *  - the versions actually applied are returned (`appliedVersions`) so a caller
 *    can persist a durable monotonic floor instead of restarting at `null` on
 *    every send;
 *  - a `NaN` / negative / fractional held version cannot silently disable the
 *    replay guard — it is rejected;
 *  - a device taken from a *verified* list is still shape-checked (33-byte
 *    `0x05` identity key, u32 device id) before it is emitted;
 *  - the same handle listed twice with different identity keys fails closed
 *    rather than letting the first-wins de-dupe drop the genuine account;
 *  - a member that is the sender's own account does not get a wrapper for the
 *    device the sender is running as.
 *
 * `verify_device_list` is mocked at the WASM boundary (the seam
 * `group_recipients.test.ts` and `discovery.shared.test.ts` use) so the real
 * `lookupDeviceList` orchestration — including its monotonicity guard — runs.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ verify_device_list: vi.fn() }));

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    verify_device_list: mocks.verify_device_list,
}));

vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { packEntries, type DiscoveryTransport } from './discovery';
import { resolveGroupRecipients } from './group_recipients';

/** A deterministic 33-byte identity key with the Curve25519 type tag. */
function key(seed: number): Uint8Array {
    const bytes = new Uint8Array(33).fill(seed);
    bytes[0] = 0x05;
    return bytes;
}

/** A transport that serves `blobs` and records every handle looked up. */
function transportWith(blobs: Record<string, Uint8Array>): DiscoveryTransport & {
    lookedUp: string[];
} {
    const lookedUp: string[] = [];
    return {
        lookedUp,
        publishDiscovery: async () => {},
        lookupDiscovery: async (handle: string) => {
            lookedUp.push(handle);
            return blobs[handle] ?? null;
        },
    };
}

/** The signed blob the relay would hold; its contents are opaque here. */
const SIGNED_BLOB = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

/** A packed `u64_le(version) || entries` buffer, as `verify_device_list` returns. */
function verifiedList(
    version: number,
    entries: Array<{ deviceId: number; identityKey: Uint8Array }>,
): Uint8Array {
    return packEntries(
        version,
        entries.map((entry) => ({ ...entry, bundleBytes: new Uint8Array([0x01, 0x02]) })),
    );
}

describe('resolveGroupRecipients — applied versions', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it('returns the version it applied for each handle', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(5, [
                { deviceId: 0, identityKey: key(0x01) },
                { deviceId: 2, identityKey: key(0x02) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.appliedVersions.get('alice')).toBe(5);
        expect(result.appliedVersions.size).toBe(1);
    });

    it('records no version for a member whose list was unavailable', async () => {
        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({}),
        });

        expect(result.appliedVersions.has('alice')).toBe(false);
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('records no version for a list that is not newer than the floor', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(4, [{ deviceId: 0, identityKey: key(0x01) }]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
            heldVersions: new Map([['alice', 5]]),
        });

        // The replayed v4 list is refused, so there is no new version to record
        // and the caller's existing floor must not be lowered.
        expect(result.appliedVersions.has('alice')).toBe(false);
        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
    });
});

describe('resolveGroupRecipients — held version validation', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it.each([
        ['NaN', Number.NaN],
        ['negative', -1],
        ['fractional', 1.5],
        ['Infinity', Number.POSITIVE_INFINITY],
    ])('rejects a %s held version instead of disabling the floor', async (_label, value) => {
        const discovery = transportWith({ alice: SIGNED_BLOB });

        await expect(
            resolveGroupRecipients({
                members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
                heldVersions: new Map([['alice', value as number]]),
            }),
        ).rejects.toThrow(/non-negative safe integer/);

        // Rejected before any I/O: no lookup, no verification.
        expect(discovery.lookedUp).toEqual([]);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('accepts a zero floor', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(1, [{ deviceId: 0, identityKey: key(0x01) }]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
            heldVersions: new Map([['alice', 0]]),
        });

        expect(result.appliedVersions.get('alice')).toBe(1);
    });
});

describe('resolveGroupRecipients — list-derived device validation', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it('rejects a list whose device identity key is not 33 bytes', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(2, [
                { deviceId: 0, identityKey: key(0x01) },
                { deviceId: 3, identityKey: new Uint8Array(31).fill(0x05) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        // The malformed device is never emitted; the member falls back to the
        // roster key at its bare handle and is reported as partially covered.
        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
        expect(result.recipients[0].identityKey).toStrictEqual(key(0xa1));
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('rejects a list whose device identity key lacks the 0x05 type byte', async () => {
        const wrongType = key(0x07);
        wrongType[0] = 0x04;
        mocks.verify_device_list.mockReturnValue(
            verifiedList(2, [{ deviceId: 0, identityKey: wrongType }]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
        expect(result.recipients[0].identityKey).toStrictEqual(key(0xa1));
        expect(result.unresolvedMembers).toEqual(['alice']);
    });
});

describe('resolveGroupRecipients — duplicate handles', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it('fails closed when one handle names two different identity keys', async () => {
        const discovery = transportWith({ alice: SIGNED_BLOB });

        await expect(
            resolveGroupRecipients({
                members: [
                    { accountHandle: 'alice', identityKey: key(0xa1) },
                    { accountHandle: 'alice', identityKey: key(0xa2) },
                ],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
            }),
        ).rejects.toThrow(/same member account handle/);

        expect(discovery.lookedUp).toEqual([]);
    });

    it('fails closed when the duplicate differs only by surrounding whitespace', async () => {
        await expect(
            resolveGroupRecipients({
                members: [
                    { accountHandle: 'alice', identityKey: key(0xa1) },
                    { accountHandle: '  alice  ', identityKey: key(0xa2) },
                ],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery: transportWith({}),
            }),
        ).rejects.toThrow(/same member account handle/);
    });

    it('accepts the same handle repeated with the same identity key', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(1, [{ deviceId: 0, identityKey: key(0x01) }]),
        );

        const result = await resolveGroupRecipients({
            members: [
                { accountHandle: 'alice', identityKey: key(0xa1) },
                { accountHandle: 'alice', identityKey: key(0xa1) },
            ],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
    });
});

describe('resolveGroupRecipients — the sender’s own account', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it('excludes the current device from a member that is the sender’s own account', async () => {
        const ownAccountKey = key(0x4f);
        mocks.verify_device_list.mockReturnValue(
            verifiedList(3, [
                { deviceId: 0, identityKey: ownAccountKey },
                { deviceId: 1, identityKey: key(0x11) },
                { deviceId: 2, identityKey: key(0x12) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'me', identityKey: ownAccountKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 1,
            ownIdentityKey: ownAccountKey,
            discovery: transportWith({ me: SIGNED_BLOB }),
        });

        // Device 1 is this client: no wrapper for it. Devices 0 and 2 remain.
        expect(result.recipients.map((r) => r.address)).toEqual(['me', 'me:2']);
    });

    it('keeps every device of a member that only reuses the sender’s handle', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList(3, [
                { deviceId: 0, identityKey: key(0x21) },
                { deviceId: 1, identityKey: key(0x22) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'me', identityKey: key(0x2f) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 1,
            ownIdentityKey: key(0x4f),
            discovery: transportWith({ me: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['me', 'me:1']);
    });
});
