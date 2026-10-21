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

/**
 * A deterministic 33-byte identity key.
 *
 * Byte 0 is the Curve25519 type tag (0x05), as a real serialized
 * `IdentityKey` carries; the resolver rejects anything else.
 */
function key(seed: number): Uint8Array {
    const bytes = new Uint8Array(33).fill(seed);
    bytes[0] = 0x05;
    return bytes;
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
    it('rejects a member handle containing the address separator, before any lookup', async () => {
        // `alice:5` would otherwise encode to the same address as alice's real
        // device-5 mailbox, letting the attacker's entry win the de-dupe and
        // suppress alice's linked device.
        const discovery = transportWith({ 'alice:5': SIGNED_BLOB });

        await expect(
            resolveGroupRecipients({
                members: [{ accountHandle: 'alice:5', identityKey: key(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
            }),
        ).rejects.toThrow(/must not contain ":"/);

        expect(discovery.lookedUp).toEqual([]);
        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    it('rejects a member handle with a zero-width character, before any lookup', async () => {
        const discovery = transportWith({});

        await expect(
            resolveGroupRecipients({
                members: [{ accountHandle: 'ali\u200bce', identityKey: key(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
            }),
        ).rejects.toThrow(/forbidden character/);

        expect(discovery.lookedUp).toEqual([]);
    });

    it('rejects empty, over-long, and bidi member handles', async () => {
        const cases = ['', '   ', 'a'.repeat(65), 'ali\u202ece'];
        for (const accountHandle of cases) {
            const discovery = transportWith({});
            await expect(
                resolveGroupRecipients({
                    members: [{ accountHandle, identityKey: key(0xa1) }],
                    ownDevices: [],
                    ownAccountHandle: 'me',
                    currentDeviceId: 0,
                    discovery,
                }),
            ).rejects.toThrow(/account handle/);
            expect(discovery.lookedUp).toEqual([]);
        }
    });

    it('rejects an own account handle containing the address separator', async () => {
        await expect(
            resolveGroupRecipients({
                members: [],
                ownDevices: [{ deviceId: 1, identityKey: key(0x21) }],
                ownAccountHandle: 'me:1',
                currentDeviceId: 0,
                discovery: transportWith({}),
            }),
        ).rejects.toThrow(/must not contain ":"/);
    });

    it('rejects an identity key without the Curve25519 type byte', async () => {
        const discovery = transportWith({ alice: SIGNED_BLOB });
        const untagged = new Uint8Array(33).fill(0xa1);
        untagged[0] = 0x02;

        await expect(
            resolveGroupRecipients({
                members: [{ accountHandle: 'alice', identityKey: untagged }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery,
            }),
        ).rejects.toThrow(/0x05 prefix/);

        expect(discovery.lookedUp).toEqual([]);
    });

    it('does not emit a list whose version is not newer than the held version', async () => {
        const aliceKey = key(0xa1);
        mocks.verify_device_list.mockReturnValue(
            packEntries(3, [
                { deviceId: 0, identityKey: key(0x01), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 4, identityKey: key(0x04), bundleBytes: new Uint8Array([0x01]) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: aliceKey }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
            // The caller already applied version 3: a replayed list at the same
            // version must not resurrect device 4.
            heldVersions: new Map([['alice', 3]]),
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

    it('emits a list strictly newer than the held version', async () => {
        mocks.verify_device_list.mockReturnValue(
            packEntries(4, [
                { deviceId: 0, identityKey: key(0x01), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 4, identityKey: key(0x04), bundleBytes: new Uint8Array([0x01]) },
            ]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
            heldVersions: new Map([['alice', 3]]),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice', 'alice:4']);
        expect(result.unresolvedMembers).toEqual([]);
    });

    it('never lets a held version shadow a higher version applied in the same call', async () => {
        const aliceKey = key(0xa1);
        // First entry: version 5, which has revoked device 7.
        mocks.verify_device_list
            .mockReturnValueOnce(
                packEntries(5, [
                    { deviceId: 0, identityKey: key(0x01), bundleBytes: new Uint8Array([0x01]) },
                ]),
            )
            // Second entry: a replayed version 4 that still lists device 7.
            .mockReturnValueOnce(
                packEntries(4, [
                    { deviceId: 0, identityKey: key(0x01), bundleBytes: new Uint8Array([0x01]) },
                    { deviceId: 7, identityKey: key(0x07), bundleBytes: new Uint8Array([0x01]) },
                ]),
            );

        const result = await resolveGroupRecipients({
            members: [
                { accountHandle: 'alice', identityKey: aliceKey },
                { accountHandle: 'alice', identityKey: aliceKey },
            ],
            ownDevices: [],
            ownAccountHandle: 'me',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
            // The caller's floor (3) is *lower* than the version this call has
            // already applied (5). The higher of the two must win, or the
            // replayed v4 list resurrects the device v5 revoked (§8.4).
            heldVersions: new Map([['alice', 3]]),
        });

        expect(result.recipients.map((r) => r.address)).toEqual(['alice']);
        expect(result.unresolvedMembers).toEqual(['alice']);
    });

    it('does not log the raw account handle', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        try {
            await resolveGroupRecipients({
                members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery: transportWith({}),
            });

            const text = warn.mock.calls
                .flat()
                .map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg) ?? ''))
                .join(' ');
            expect(text).not.toContain('alice');
            expect(text).toContain('handleRef');
        } finally {
            warn.mockRestore();
        }
    });

    it('trims member and own handles to their canonical form', async () => {
        mocks.verify_device_list.mockReturnValue(
            verifiedList([{ deviceId: 0, identityKey: key(0x01) }]),
        );

        const result = await resolveGroupRecipients({
            members: [{ accountHandle: '  alice  ', identityKey: key(0xa1) }],
            ownDevices: [{ deviceId: 1, identityKey: key(0x21) }],
            ownAccountHandle: ' me ',
            currentDeviceId: 0,
            discovery: transportWith({ alice: SIGNED_BLOB }),
        });

        expect(result.recipients.map((r) => r.accountHandle)).toEqual(['alice', 'me']);
        expect(result.recipients.map((r) => r.address)).toEqual(['alice', 'me:1']);
    });

    it('reports a missing list as no-fresh-list, not as a stale list', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        try {
            await resolveGroupRecipients({
                members: [{ accountHandle: 'alice', identityKey: key(0xa1) }],
                ownDevices: [],
                ownAccountHandle: 'me',
                currentDeviceId: 0,
                discovery: transportWith({}),
            });

            const reasons = warn.mock.calls.map(
                (args) => (args[1] as { reason?: string } | undefined)?.reason,
            );
            expect(reasons).toEqual(['no-fresh-list']);
        } finally {
            warn.mockRestore();
        }
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
