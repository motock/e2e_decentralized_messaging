/** @vitest-environment jsdom */
/**
 * GF-3: fan the group ciphertext out to every recipient DEVICE address.
 *
 * A group envelope carries one ciphertext whose per-message key is wrapped
 * separately for each roster identity key, so the same bytes must be delivered
 * to every device mailbox — the bare handle for device 0 and
 * `${handle}:${deviceId}` for each linked device. The relay keys its tag map by
 * `(recipient_id, envelope hash)`, so N deliveries of identical bytes stay
 * independent.
 *
 * These tests drive the real hook (`useGroupConversation`) with the WASM
 * bindings, the storage gate and the relay transport mocked at their seams, and
 * pin:
 *
 *  - a two-device member receives two sends (bare + `:2`) with byte-identical
 *    ciphertext;
 *  - the sender's own second device receives exactly one send;
 *  - exactly one `group_encrypt` and one persist per send (no per-device
 *    re-encryption or re-persistence);
 *  - one device failing reports `partial` while the other still receives;
 *  - every device failing reports `failed`;
 *  - no duplicate addresses are ever delivered to;
 *  - no key or device-list bytes are logged.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';

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
        constructor(public members: Uint8Array[] = []) {}
    },
}));

vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('./storage_key', () => ({ getStorageKey: () => new Uint8Array(32).fill(7) }));
vi.mock('./relay_transport', () => ({
    getRelayWsUrl: () => 'ws://relay.test',
    RelayTransport: class {
        sendEnvelope = async () => {};
        lookupPrekey = async () => new Uint8Array();
        pickupEnvelope = async () => {
            throw new Error('NotFound');
        };
    },
}));

import { packEntries, type DiscoveryTransport } from './discovery';
import { useGroupConversation } from './useGroupConversation';
import type { GroupTransport } from './GroupConversation';
import type { DeviceListEntry } from './Conversation';

/** A deterministic 33-byte identity key with the Curve25519 type tag. */
function key(seed: number): Uint8Array {
    const bytes = new Uint8Array(33).fill(seed);
    bytes[0] = 0x05;
    return bytes;
}

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

/** A discovery transport serving `blobs` per handle. */
function discoveryWith(blobs: Record<string, Uint8Array>): DiscoveryTransport {
    return {
        publishDiscovery: async () => {},
        lookupDiscovery: async (handle: string) => blobs[handle] ?? null,
    };
}

/** The ciphertext `group_encrypt` returns; every device must receive these bytes. */
const CIPHERTEXT = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);

interface Harness {
    sent: Array<{ address: string; ciphertext: Uint8Array }>;
    gate: { open: () => Promise<void>; get: () => Promise<null>; put: ReturnType<typeof vi.fn> };
}

/**
 * Render the hook with one real member (`alice`) and, optionally, the sender's
 * own linked device, then run a single send.
 */
async function runSend(options: {
    aliceDevices?: Array<{ deviceId: number; identityKey: Uint8Array }>;
    aliceListAvailable?: boolean;
    ownDevices?: DeviceListEntry[];
    sendEnvelope?: (address: string, ciphertext: Uint8Array) => Promise<void>;
}): Promise<Harness & { result: ReturnType<typeof renderHook<ReturnType<typeof useGroupConversation>, unknown>>['result'] }> {
    const sent: Array<{ address: string; ciphertext: Uint8Array }> = [];
    const gate = {
        open: async () => {},
        get: async () => null,
        put: vi.fn(async () => {}),
    };
    const transport: GroupTransport = {
        lookupPrekey: async () => key(0xa1),
        sendEnvelope: async (address: string, ciphertext: Uint8Array) => {
            sent.push({ address, ciphertext: new Uint8Array(ciphertext) });
            if (options.sendEnvelope) await options.sendEnvelope(address, ciphertext);
        },
        pickupEnvelope: async () => {
            throw new Error('NotFound');
        },
    };

    const blobs: Record<string, Uint8Array> = {};
    if (options.aliceListAvailable !== false) blobs.alice = new Uint8Array([0xde, 0xad]);

    const identity = new (class {
        constructor(public bytes: Uint8Array) {}
        public_bytes() {
            return this.bytes;
        }
    })(key(0x11)) as never;

    const { result } = renderHook(() =>
        useGroupConversation({
            transport,
            storageGate: gate as never,
            identity,
            selfRecipientId: 'me',
            ownDevices: options.ownDevices,
            discovery: discoveryWith(blobs),
            ownAccountHandle: 'me',
            currentDeviceId: 0,
        }),
    );

    await waitFor(() => expect(result.current.ready).toBe(true));

    act(() => result.current.createGroup());
    await waitFor(() => expect(result.current.group).not.toBeNull());

    act(() => result.current.setPeerIdInput('alice'));
    await act(async () => {
        await result.current.addPeer();
    });
    await waitFor(() => expect(result.current.realMembers).toHaveLength(1));

    act(() => result.current.setInput('hello group'));
    // Only the writes the send itself performs are of interest; createGroup and
    // addPeer persist too.
    gate.put.mockClear();
    await act(async () => {
        await result.current.send();
    });

    return { sent, gate, result };
}

describe('GF-3 group device fan-out', () => {
    beforeEach(() => {
        for (const mock of Object.values(mocks)) mock.mockReset();
        mocks.group_create.mockImplementation(() => ({ members: [] }));
        mocks.group_add_member.mockImplementation((group: unknown) => group);
        mocks.group_remove_member.mockImplementation((group: unknown) => group);
        mocks.group_encrypt.mockReturnValue(CIPHERTEXT);
        mocks.group_to_bytes.mockReturnValue(new Uint8Array([0x01]));
        mocks.bundle_identity_key_bytes.mockReturnValue(key(0xa1));
        mocks.verify_device_list.mockReturnValue(
            verifiedList(1, [
                { deviceId: 0, identityKey: key(0xa1) },
                { deviceId: 2, identityKey: key(0xa2) },
            ]),
        );
    });

    it('sends the same ciphertext to every device of a two-device member', async () => {
        const { sent } = await runSend({});

        expect(sent.map((s) => s.address).sort()).toEqual(['alice', 'alice:2']);
        for (const delivery of sent) {
            expect(Array.from(delivery.ciphertext)).toEqual(Array.from(CIPHERTEXT));
        }
    });

    it("sends once to the sender's own second device", async () => {
        const { sent } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
        });

        const ownDeliveries = sent.filter((s) => s.address.startsWith('me'));
        expect(ownDeliveries.map((s) => s.address)).toEqual(['me:3']);
        expect(Array.from(ownDeliveries[0].ciphertext)).toEqual(Array.from(CIPHERTEXT));
    });

    it("does not count the sender's own devices as a member in the outcome", async () => {
        const { result } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
        });

        // One real member (`alice`), so the UI must say "sent to 1 of 1", not
        // "sent to 1 of 2": the sender's own linked device is a delivery
        // target, never a member of the group.
        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('sent');
        expect(message?.sendTotal).toBe(1);
        expect(message?.sendFailures).toBe(0);
        expect(result.current.sendError).toBeNull();
    });

    it("reports sent when only the sender's own second device fails", async () => {
        const { sent, result } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
            sendEnvelope: async (address) => {
                if (address === 'me:3') throw new Error('relay unavailable');
            },
        });

        // The own device was still attempted...
        expect(sent.map((s) => s.address).sort()).toEqual(['alice', 'alice:2', 'me:3']);
        // ...but its failure is not a member failure: every real member got it.
        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('sent');
        expect(message?.sendTotal).toBe(1);
        expect(message?.sendFailures).toBe(0);
        expect(result.current.sendError).toBeNull();
    });

    it("counts a real member's device failure but not the sender's own", async () => {
        const { result } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
            sendEnvelope: async (address) => {
                if (address === 'me:3' || address === 'alice:2') {
                    throw new Error('relay unavailable');
                }
            },
        });

        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('partial');
        expect(message?.sendTotal).toBe(1);
        expect(message?.sendFailures).toBe(1);
        expect(result.current.sendError).toBe('Sent to 0 of 1 members.');
    });

    it('encrypts once and persists the session once per send, not once per device', async () => {
        const { gate } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
        });

        expect(mocks.group_encrypt).toHaveBeenCalledTimes(1);
        // Two session writes per send: the pre-encrypt roster/floor save and the
        // post-encrypt ratchet-position save. Neither is per device.
        const sessionWrites = gate.put.mock.calls.filter((call) => call[1] === 'group-state');
        expect(sessionWrites).toHaveLength(2);
    });

    it('reports partial when one device fails while the other still receives', async () => {
        const { sent, result } = await runSend({
            sendEnvelope: async (address) => {
                if (address === 'alice:2') throw new Error('relay unavailable');
            },
        });

        expect(sent.map((s) => s.address).sort()).toEqual(['alice', 'alice:2']);
        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('partial');
        expect(message?.sendFailures).toBe(1);
        expect(message?.sendTotal).toBe(1);
        expect(result.current.sendError).toBe('Sent to 0 of 1 members.');
    });

    it('reports failed when every device of every member fails', async () => {
        const { result } = await runSend({
            sendEnvelope: async () => {
                throw new Error('relay unavailable');
            },
        });

        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('failed');
        expect(message?.sendFailures).toBe(1);
        expect(result.current.sendError).toBe('Failed to send: relay unavailable');
    });

    it('never delivers to a duplicate address', async () => {
        const { sent } = await runSend({
            ownDevices: [
                { deviceId: 0, identityKey: key(0x11), bundleBytes: new Uint8Array([0x01]) },
                { deviceId: 3, identityKey: key(0x13), bundleBytes: new Uint8Array([0x01]) },
            ],
        });

        const addresses = sent.map((s) => s.address);
        expect(new Set(addresses).size).toBe(addresses.length);
    });

    it('still delivers to a member with no usable device list, noting primary-only coverage', async () => {
        const { sent, result } = await runSend({ aliceListAvailable: false });

        // The bare fallback address is the only one, and it is delivered to.
        expect(sent.map((s) => s.address)).toEqual(['alice']);
        const message = result.current.messages.at(-1);
        expect(message?.sendStatus).toBe('sent');
        expect(result.current.sendError).toBe(
            'Only the primary device of 1 member(s) could be reached.',
        );
    });

    it('does not log key or device-list bytes', async () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const error = vi.spyOn(console, 'error').mockImplementation(() => {});
        const log = vi.spyOn(console, 'log').mockImplementation(() => {});

        try {
            await runSend({
                sendEnvelope: async (address) => {
                    if (address === 'alice:2') throw new Error('relay unavailable');
                },
            });

            const logged = [...warn.mock.calls, ...error.mock.calls, ...log.mock.calls]
                .flat()
                .map((entry) => (typeof entry === 'string' ? entry : JSON.stringify(entry)))
                .join(' ');

            // The identity keys and the signed list blob must never appear.
            expect(logged).not.toContain(Array.from(key(0xa1)).join(','));
            expect(logged).not.toContain(Array.from(key(0xa2)).join(','));
            // The signed device-list blob is `[0xde, 0xad]`; it must not leak as
            // a comma-joined array, as JSON (`{"0":222,"1":173}`) or as hex.
            expect(logged).not.toContain('222,173');
            expect(logged).not.toContain('"0":222');
            expect(logged).not.toContain('dead');
        } finally {
            warn.mockRestore();
            error.mockRestore();
            log.mockRestore();
        }
    });
});
