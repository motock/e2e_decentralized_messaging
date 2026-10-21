/** @vitest-environment jsdom */
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

const mocks = vi.hoisted(() => ({
    verify_device_list: vi.fn(),
    group_create: vi.fn(),
    group_add_member: vi.fn(),
    group_remove_member: vi.fn(),
    group_encrypt: vi.fn(),
    group_decrypt: vi.fn(),
    group_to_bytes: vi.fn(),
    group_from_bytes: vi.fn(),
    bundle_identity_key_bytes: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    verify_device_list: mocks.verify_device_list,
    group_create: mocks.group_create,
    group_add_member: mocks.group_add_member,
    group_remove_member: mocks.group_remove_member,
    group_encrypt: mocks.group_encrypt,
    group_decrypt: mocks.group_decrypt,
    group_to_bytes: mocks.group_to_bytes,
    group_from_bytes: mocks.group_from_bytes,
    bundle_identity_key_bytes: mocks.bundle_identity_key_bytes,
    IdentityHandle: class {
        constructor(public bytes: Uint8Array) {}
        public_bytes() {
            return this.bytes;
        }
    },
    GroupHandle: class {
        constructor(public members: Uint8Array[]) {}
    },
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

/**
 * Hand-build the same buffer without `packEntries`' validation.
 *
 * `packEntries` refuses to encode a malformed identity key, so the only way to
 * model a *verified* list that still carries a bad key — the case the resolver
 * must defend against — is to write the bytes directly.
 */
function rawVerifiedList(
    version: number,
    entries: Array<{ deviceId: number; identityKey: Uint8Array }>,
): Uint8Array {
    const chunks: number[] = [];
    const pushU32 = (value: number) => {
        chunks.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
    };
    const pushU64 = (value: number) => {
        pushU32(value >>> 0);
        pushU32(Math.floor(value / 0x100000000));
    };
    pushU64(version);
    for (const entry of entries) {
        pushU32(entry.deviceId);
        pushU32(entry.identityKey.length);
        chunks.push(...entry.identityKey);
        pushU32(2);
        chunks.push(0x01, 0x02);
    }
    return new Uint8Array(chunks);
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
            rawVerifiedList(2, [
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

// ---------------------------------------------------------------------------
// Send-path coverage (GF-2)
//
// The resolver is only half the story: the send path must reconcile the group
// handle's roster to the resolved identity keys, persist that roster AND the
// merged device-list version floor BEFORE it encrypts, and carry the floor into
// every subsequent send. These tests drive the real hook with the WASM group
// bindings mocked, so the ordering and the floor are observable.
// ---------------------------------------------------------------------------

import { renderHook, act } from '@testing-library/react';
import { afterEach } from 'vitest';
import { useGroupConversation } from './useGroupConversation';

/** A 33-byte identity key with the Curve25519 type tag. */
function idKey(seed: number): Uint8Array {
    const bytes = new Uint8Array(33).fill(seed & 0xff);
    bytes[0] = 0x05;
    return bytes;
}

function sameKey(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
    return true;
}

/** A StorageGate stand-in that records every write, in order. */
function makeGate() {
    const writes: Array<{ store: string; id: string; value: unknown }> = [];
    const put = vi.fn(async (store: string, id: string, value: unknown) => {
        writes.push({ store, id, value });
    });
    return {
        writes,
        put,
        open: async () => {},
        get: async () => null,
    };
}

/** A discovery transport serving one signed blob per handle. */
function discoveryWith(blobs: Record<string, Uint8Array>) {
    return {
        publishDiscovery: async () => {},
        lookupDiscovery: async (handle: string) => blobs[handle] ?? null,
    };
}

/** A transport that records the envelopes it is asked to send. */
function makeTransport() {
    const sent: Array<{ recipientId: string; envelope: Uint8Array }> = [];
    return {
        sent,
        // The member's published bundle carries a well-formed identity key, so
        // the resolver treats it as a real account rather than a malformed one.
        lookupPrekey: async () => idKey(0x02),
        sendEnvelope: async (recipientId: string, envelope: Uint8Array) => {
            sent.push({ recipientId, envelope });
        },
        pickupEnvelope: async () => {
            throw new Error('NotFound');
        },
    };
}

/** Flush pending microtasks and zero-delay timers inside `act`. */
async function flush() {
    await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
    });
}

describe('useGroupConversation send path — GF-2 reconciliation', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        for (const fn of Object.values(mocks)) fn.mockReset();
        mocks.group_to_bytes.mockReturnValue(new Uint8Array([0x01]));
        mocks.group_encrypt.mockReturnValue(new Uint8Array([0xaa]));
        mocks.group_decrypt.mockReturnValue(new Uint8Array());
        mocks.bundle_identity_key_bytes.mockImplementation((b: Uint8Array) => b);
        mocks.group_create.mockImplementation((self: { public_bytes(): Uint8Array }) => ({
            members: [self.public_bytes()],
        }));
        mocks.group_add_member.mockImplementation((group: { members: Uint8Array[] }, key: Uint8Array) => ({
            members: [...group.members, key],
        }));
        mocks.group_remove_member.mockImplementation((group: { members: Uint8Array[] }, key: Uint8Array) => ({
            members: group.members.filter((m) => !sameKey(m, key)),
        }));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    /** Render the hook, create the group, and add one member. */
    async function setupHook(options: {
        gate: ReturnType<typeof makeGate>;
        transport: ReturnType<typeof makeTransport>;
        discovery?: ReturnType<typeof discoveryWith>;
        ownDevices?: Array<{ deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }>;
    }) {
        const selfBytes = idKey(0x01);
        const identity = { public_bytes: () => selfBytes } as never;

        const view = renderHook(() =>
            useGroupConversation({
                transport: options.transport as never,
                storageGate: options.gate as never,
                identity,
                selfRecipientId: 'group-a',
                discovery: options.discovery as never,
                ownDevices: options.ownDevices as never,
                ownAccountHandle: 'group-a',
                currentDeviceId: 0,
            }),
        );

        await flush();
        await act(async () => {
            view.result.current.createGroup();
        });
        await act(async () => {
            view.result.current.setPeerIdInput('member-b');
        });
        await act(async () => {
            await view.result.current.addPeer();
        });
        await flush();

        return { view, selfBytes };
    }

    it('persists the reconciled roster and applied versions before encrypting', async () => {
        const gate = makeGate();
        const transport = makeTransport();
        const discovery = discoveryWith({ 'member-b': new Uint8Array([0x01]) });

        // The member's verified list names a second device.
        mocks.verify_device_list.mockReturnValue(
            verifiedList(7, [
                { deviceId: 0, identityKey: idKey(0x02) },
                { deviceId: 3, identityKey: idKey(0x03) },
            ]),
        );

        const { view } = await setupHook({ gate, transport, discovery });

        // Ignore the writes made while creating the group and adding the peer.
        gate.writes.length = 0;
        gate.put.mockClear();
        mocks.group_encrypt.mockClear();

        await act(async () => {
            view.result.current.setInput('hello');
        });
        await act(async () => {
            await view.result.current.send();
        });

        // The reconciled roster AND the applied floor were persisted.
        const stateWrite = gate.writes.find((w) => w.id === 'group-state');
        expect(stateWrite).toBeDefined();
        const persisted = stateWrite!.value as {
            deviceListVersions?: Array<[string, number]>;
        };
        expect(persisted.deviceListVersions).toEqual([['member-b', 7]]);

        // ...and that write completed BEFORE the envelope was encrypted.
        expect(mocks.group_encrypt).toHaveBeenCalledTimes(1);
        const persistOrder = gate.put.mock.invocationCallOrder[0];
        const encryptOrder = mocks.group_encrypt.mock.invocationCallOrder[0];
        expect(persistOrder).toBeLessThan(encryptOrder);

        // The member's second device was added to the roster before encrypting.
        const addedKeys = mocks.group_add_member.mock.calls.map((c) => c[1] as Uint8Array);
        expect(addedKeys.some((k) => sameKey(k, idKey(0x03)))).toBe(true);
    });

    it('carries the merged floor into every subsequent send', async () => {
        const gate = makeGate();
        const transport = makeTransport();
        const discovery = discoveryWith({ 'member-b': new Uint8Array([0x01]) });

        mocks.verify_device_list.mockReturnValue(
            verifiedList(7, [
                { deviceId: 0, identityKey: idKey(0x02) },
                { deviceId: 3, identityKey: idKey(0x03) },
            ]),
        );

        const { view } = await setupHook({ gate, transport, discovery });

        await act(async () => {
            view.result.current.setInput('first');
        });
        await act(async () => {
            await view.result.current.send();
        });

        // Second send: the relay now serves a stale (version 6) list that still
        // names a device the newer list revoked.
        mocks.verify_device_list.mockReturnValue(
            verifiedList(6, [
                { deviceId: 0, identityKey: idKey(0x02) },
                { deviceId: 9, identityKey: idKey(0x09) },
            ]),
        );
        mocks.group_add_member.mockClear();

        await act(async () => {
            view.result.current.setInput('second');
        });
        await act(async () => {
            await view.result.current.send();
        });

        // The stale list is refused, so the revoked device is never added.
        const addedKeys = mocks.group_add_member.mock.calls.map((c) => c[1] as Uint8Array);
        expect(addedKeys.some((k) => sameKey(k, idKey(0x09)))).toBe(false);

        // The floor never regresses below 7, in memory or on disk.
        const lastWrite = [...gate.writes].reverse().find((w) => w.id === 'group-state');
        const persisted = lastWrite!.value as { deviceListVersions?: Array<[string, number]> };
        expect(persisted.deviceListVersions).toEqual([['member-b', 7]]);
    });

    it('aborts without encrypting or sending when the roster exceeds 255 recipients', async () => {
        const gate = makeGate();
        const transport = makeTransport();

        // A verified list with 256 devices for the single member.
        const devices = Array.from({ length: 256 }, (_, i) => ({
            deviceId: i,
            identityKey: idKey(i + 10),
        }));
        mocks.verify_device_list.mockReturnValue(verifiedList(1, devices));

        const { view } = await setupHook({
            gate,
            transport,
            discovery: discoveryWith({ 'member-b': new Uint8Array([0x01]) }),
        });

        await act(async () => {
            view.result.current.setInput('too many');
        });
        await act(async () => {
            await view.result.current.send();
        });

        expect(mocks.group_encrypt).not.toHaveBeenCalled();
        expect(transport.sent).toEqual([]);
        expect(view.result.current.error).toMatch(/255/);
    });

    it('enforces the recipient limit even with no discovery transport injected', async () => {
        const gate = makeGate();
        const transport = makeTransport();

        // No discovery transport: reconciliation must still run, so the
        // recipient set is the member's bare handle plus the sender's own
        // devices — 257 recipients, over the wire limit.
        const ownDevices = Array.from({ length: 256 }, (_, i) => ({
            deviceId: i + 1,
            identityKey: idKey(i + 10),
            bundleBytes: new Uint8Array([0x01]),
        }));

        const { view } = await setupHook({ gate, transport, ownDevices });

        await act(async () => {
            view.result.current.setInput('too many');
        });
        await act(async () => {
            await view.result.current.send();
        });

        expect(mocks.group_encrypt).not.toHaveBeenCalled();
        expect(transport.sent).toEqual([]);
        expect(view.result.current.error).toMatch(/255/);
    });

    it('does not send when persisting the reconciled state fails', async () => {
        const gate = makeGate();
        const transport = makeTransport();

        mocks.verify_device_list.mockReturnValue(
            verifiedList(2, [{ deviceId: 0, identityKey: idKey(0x02) }]),
        );

        const { view } = await setupHook({
            gate,
            transport,
            discovery: discoveryWith({ 'member-b': new Uint8Array([0x01]) }),
        });

        // Every write now fails, as an unavailable store would.
        gate.put.mockImplementation(async () => {
            throw new Error('storage unavailable');
        });

        await act(async () => {
            view.result.current.setInput('nope');
        });
        await act(async () => {
            await view.result.current.send();
        });

        expect(transport.sent).toEqual([]);
        expect(view.result.current.error).toMatch(/Could not save session state/);
    });
});
