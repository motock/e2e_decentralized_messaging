/**
 * Group member → per-device recipient resolution (GF-1).
 *
 * The resolver fans a group's member list out into one mailbox recipient per
 * verified device, so a message reaches a member's linked devices and not just
 * its primary. These tests pin the security-relevant behaviour:
 *
 *  - only identities from a *verified* device list are ever emitted;
 *  - a member whose list is missing, tampered, or foreign-signed degrades to
 *    its bare handle (the primary is still reachable) and is reported as
 *    partially covered instead of failing the whole send;
 *  - a malformed identity key fails closed before any lookup happens;
 *  - no key material, bundle bytes, or list bytes reach the console.
 *
 * `verify_device_list` is mocked at the WASM boundary (the same seam
 * `discovery.shared.test.ts` uses) so the tests exercise the real
 * `lookupDeviceList` orchestration — including its throw-on-tamper contract —
 * without a built WASM package.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ verify_device_list: vi.fn() }));

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    verify_device_list: mocks.verify_device_list,
}));

vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { packEntries, type DiscoveryTransport } from './discovery';
import { resolveGroupRecipients } from './group_recipients';

/** A deterministic 33-byte identity key. */
function key(seed: number): Uint8Array {
    return new Uint8Array(33).fill(seed);
}

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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

/** A transport whose lookups always fail, as a relay outage would. */
function failingTransport(): DiscoveryTransport {
    return {
        publishDiscovery: async () => {},
        lookupDiscovery: async () => {
            throw new Error('relay unavailable');
        },
    };
}

/** The signed blob the relay would hold; its contents are opaque here. */
const SIGNED_BLOB = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

function verifiedList(entries: Array<{ deviceId: number; identityKey: Uint8Array }>): Uint8Array {
    return packEntries(
        1,
        entries.map((entry) => ({ ...entry, bundleBytes: new Uint8Array([0x01, 0x02]) })),
    );
}

describe('resolveGroupRecipients', () => {
    beforeEach(() => {
        mocks.verify_device_list.mockReset();
    });

    it('emits one recipient per verified device, bare handle for device 0', async () => {
        const aliceKey = key(0xa1);
        const aliceDevice0 = key(0x01);
        const aliceDevice2 = key(0x02);
        mocks.verify_device_list.mockReturnValue(
            verifiedList([
                { deviceId: 0, identityKey: aliceDevice0 },
                { deviceId: 2, identityKey: aliceDevice2 },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [{ deviceId: 0, identityKey: key(0x11) }],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.recipients).toEqual([
            {
                accountHandle: 'alice',
                deviceId: 0,
                identityKey: aliceDevice0,
                address: 'alice',
            },
            {
                accountHandle: 'alice',
                deviceId: 2,
                identityKey: aliceDevice2,
                address: 'alice:2',
            },
        ]);
        expect(result.unresolvedMembers).toEqual([]);
    });

    it('verifies the list against the member identity key at version null', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList([{ deviceId: 0, identityKey: key(0x01) }]),
        );
        const aliceKey = key(0xa1);

        await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        const [blob, expectedAccount] = mocks.verify_device_list.mock.calls[0];
        expect(blob).toBe(SIGNED_BLOB);
        expect(expectedAccount).toBe(aliceKey);
    });

    it("includes the sender's other devices and excludes the current one", async () => {
        const ownDevice1 = key(0x21);

        const result = await resolveGroupRecipients({
            members: [],
            ownDevices: [
                { deviceId: 0, identityKey: key(0x20) },
                { deviceId: 1, identityKey: ownDevice1 },
            ],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({}),
        });

        expect(result.recipients).toEqual([
            {
                accountHandle: 'me',
                deviceId: 1,
                identityKey: ownDevice1,
                address: 'me:1',
            },
        ]);
        expect(result.unresolvedMembers).toEqual([]);
    });

    it('addresses the own primary at the bare handle when a linked device is current', async () => {
        const result = await resolveGroupRecipients({
            members: [],
            ownDevices: [
                { deviceId: 0, identityKey: key(0x20) },
                { deviceId: 1, identityKey: key(0x21) },
            ],
            ownAccountHandle: 'me',
            currentDeviceId: 1,
            discovery: transportWith({}),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['me']);
    });

    it('falls back to the bare handle when the member has no published list', async () => {
        const aliceKey = key(0xa1);

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({}),
        });

        expect(result.recipients).toEqual([
            {
                accountHandle: 'alice',
                deviceId: 0,
                identityKey: aliceKey,
                address: 'alice',
            },
        ]);
        expect(result.unresolvedMembers).toEqual(['alice']);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('falls back and records the member when verification throws', async () => {
        const aliceKey = key(0xa1);
        mocks.verify_device_list.mockImplementation(() => {
            throw new Error('device list: signature does not verify');
        });

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.recipients).toEqual([
            {
                accountHandle: 'alice',
                deviceId: 0,
                identityKey: aliceKey,
                address: 'alice',
            },
        ]);
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('falls back and records the member when the lookup itself fails', async () => {
        const aliceKey = key(0xa1);

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: failingTransport(),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('keeps resolving other members when one member fails verification', async () => {
        const bobKey = key(0xb1);
        const bobDevice0 = key(0x31);
        mocks.verify_device_list.mockImplementation((_blob: Uint8Array, expected: Uint8Array) => {
            if (expected === bobKey) {
                return verifiedList([{ deviceId: 0, identityKey: bobDevice0 }]);
            }
            throw new Error('device list: signature does not verify');
        });

        const result = await resolveGroupRecipients({
            members: [
                { accountHandle: 'alice', identityKey: key(0xa1) },
                { accountHandle: 'bob', identityKey: bobKey },
            ],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB, bob: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice', 'bob']);
        expect(result.recipients[1].identityKey).toStrictEqual(bobDevice0);
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('rejects a malformed member identity key before any lookup', async () => {
        const discovery = transportWith({ alice: SIGNED_BLOB });

        await expect(
            resolveGroupRecipients({
                members: [{ accountHandle: 'alice', identityKey: new Uint8Array(32).fill(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
            }),
        ).rejects.toThrow(/33 bytes/);

        expect(discovery.lookedUp).toEqual([]);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects a malformed own-device identity key', async () => {
        await expect(
            resolveGroupRecipients({
                members: [],
                ownDevices: [{ deviceId: 1, identityKey: new Uint8Array(34).fill(0x21) }],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery: transportWith({}),
            }),
        ).rejects.toThrow(/33 bytes/);
    });

    it('de-duplicates recipients by address, first wins', async () => {
        const memberDevice1 = key(0x41);
        const ownDevice1 = key(0x42);
        mocks.verify_device_list.mockReturnValue(
            verifiedList([
                { deviceId: 0, identityKey: key(0x40) },
                { deviceId: 1, identityKey: memberDevice1 },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'me', identityKey: key(0x4f) }],
            ownDevices: [{ deviceId: 1, identityKey: ownDevice1 }],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ me: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['me', 'me:1']);
        expect(result.recipients[1].identityKey).toStrictEqual(memberDevice1);
    });

    it('does not sort the output', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList([
                { deviceId: 3, identityKey: key(0x53) },
                { deviceId: 0, identityKey: key(0x50) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [
                { accountHandle: 'zoe', identityKey: key(0xf1) },
                { accountHandle: 'amy', identityKey: key(0xf2) },
            ],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ zoe: SIGNED_BLOB, amy: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.address)).toEqual([
            'zoe:3',
            'zoe',
            'amy:3',
            'amy',
        ]);
    });

    it('never logs identity keys, bundles, or list bytes', async () => {
        const aliceKey = key(0xa1);
        const aliceDevice0 = key(0x01);
        const aliceDevice2 = key(0x02);
        mocks.verify_device_list.mockImplementation((_blob: Uint8Array, expected: Uint8Array) => {
            if (expected === aliceKey) {
                return verifiedList([
                    { deviceId: 0, identityKey: aliceDevice0 },
                    { deviceId: 2, identityKey: aliceDevice2 },
                ]);
            }
            throw new Error('device list: signature does not verify');
        });

        const calls: unknown[][] = [];
        const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((level) =>
            vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
                calls.push(args);
            }),
        );

        try {
            await resolveGroupRecipients({
                members: [
                    { accountHandle: 'alice', identityKey: aliceKey },
                    { accountHandle: 'bob', identityKey: key(0xb1) },
                ],
                ownDevices: [{ deviceId: 1, identityKey: key(0x21) }],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery: transportWith({ alice: SIGNED_BLOB, bob: SIGNED_BLOB }),
            });
        } finally {
            spies.forEach((spy) => spy.mockRestore());
        }

        const text = calls
            .flat()
            .map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg) ?? ''))
            .join(' ');

        for (const secret of [aliceKey, aliceDevice0, aliceDevice2, SIGNED_BLOB]) {
            expect(text).not.toContain(hex(secret));
        }
        expect(text).not.toContain(Array.from(aliceKey).join(','));
        expect(calls.flat().some((arg) => containsBytes(arg))).toBe(false);
    });
});

/** True when `value` is, or structurally contains, raw bytes. */
function containsBytes(value: unknown): boolean {
    if (value instanceof Uint8Array) return true;
    if (Array.isArray(value)) return value.some(containsBytes);
    if (value !== null && typeof value === 'object') {
        return Object.values(value as Record<string, unknown>).some(containsBytes);
    }
    return false;
}
