/** @vitest-environment node */
/**
 * Group roster reconciliation: the pure module behind the send path.
 *
 * These pin the invariants the hook-level tests exercise end to end, plus the
 * negative paths that are awkward to reach through the hook: validation of a
 * persisted tracking record, duplicate prevention, and the rule that an
 * unresolved handle (list absent or not newer) is not evidence of revocation.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
    group_add_member: vi.fn(),
    group_remove_member: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    group_add_member: mocks.group_add_member,
    group_remove_member: mocks.group_remove_member,
    GroupHandle: class {
        constructor(public members: Uint8Array[]) {}
    },
}));

import { reconcileRoster, validatedRosterDeviceKeys } from './group_roster';

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

function tracked(handle: string, key: Uint8Array) {
    return { accountHandle: handle, identityKey: key };
}

const SELF = idKey(0x01);

beforeEach(() => {
    for (const fn of Object.values(mocks)) fn.mockReset();
    mocks.group_add_member.mockImplementation(
        (group: { members: Uint8Array[] }, key: Uint8Array) => ({
            members: [...group.members, key],
        }),
    );
    mocks.group_remove_member.mockImplementation(
        (group: { members: Uint8Array[] }, key: Uint8Array) => ({
            members: group.members.filter((member) => !sameKey(member, key)),
        }),
    );
});

describe('validatedRosterDeviceKeys', () => {
    it('keeps a well-formed handle/key pair', () => {
        const result = validatedRosterDeviceKeys([['member-b', Array.from(idKey(0x03))]]);
        expect(result).toHaveLength(1);
        expect(result[0].accountHandle).toBe('member-b');
        expect(sameKey(result[0].identityKey, idKey(0x03))).toBe(true);
    });

    it('drops an identity key of the wrong length', () => {
        expect(validatedRosterDeviceKeys([['member-b', [0x05, 0x01, 0x02]]])).toEqual([]);
    });

    it('drops an identity key with the wrong type byte', () => {
        const wrongType = Array.from(idKey(0x03));
        wrongType[0] = 0x04;
        expect(validatedRosterDeviceKeys([['member-b', wrongType]])).toEqual([]);
    });

    it('drops an entry whose bytes are not all bytes', () => {
        const bytes = Array.from(idKey(0x03));
        bytes[1] = 256;
        expect(validatedRosterDeviceKeys([['member-b', bytes]])).toEqual([]);
    });

    it('drops an entry with an empty or non-string handle', () => {
        expect(validatedRosterDeviceKeys([['', Array.from(idKey(0x03))]])).toEqual([]);
        expect(validatedRosterDeviceKeys([[7, Array.from(idKey(0x03))]])).toEqual([]);
    });

    it('returns nothing for a non-array record', () => {
        expect(validatedRosterDeviceKeys(undefined)).toEqual([]);
        expect(validatedRosterDeviceKeys({})).toEqual([]);
    });
});

describe('reconcileRoster', () => {
    it('does not re-add a recipient key that is already tracked', () => {
        const group = { members: [] as Uint8Array[] };
        const deviceKey = idKey(0x03);
        const result = reconcileRoster({
            group: group as never,
            selfPublicBytes: SELF,
            recipients: [{ accountHandle: 'member-b', identityKey: deviceKey }],
            memberKeys: [],
            unresolvedHandles: new Set(),
            tracked: new Map([['05' + '03'.repeat(32), tracked('member-b', deviceKey)]]),
        });

        expect(mocks.group_add_member).not.toHaveBeenCalled();
        expect(result.tracked.size).toBe(1);
    });

    it('evicts a tracked device of a resolved handle that is no longer a recipient', () => {
        const deviceKey = idKey(0x03);
        const result = reconcileRoster({
            group: { members: [deviceKey] } as never,
            selfPublicBytes: SELF,
            recipients: [{ accountHandle: 'member-b', identityKey: idKey(0x02) }],
            memberKeys: [idKey(0x02)],
            unresolvedHandles: new Set(),
            tracked: new Map([['key3', tracked('member-b', deviceKey)]]),
        });

        const removed = mocks.group_remove_member.mock.calls.map(
            (call) => call[1] as Uint8Array,
        );
        expect(removed.some((key) => sameKey(key, deviceKey))).toBe(true);
        expect(result.tracked.has('key3')).toBe(false);
    });

    it('keeps a tracked device whose handle could not be resolved', () => {
        const deviceKey = idKey(0x03);
        const result = reconcileRoster({
            group: { members: [deviceKey] } as never,
            selfPublicBytes: SELF,
            recipients: [{ accountHandle: 'member-b', identityKey: idKey(0x02) }],
            memberKeys: [idKey(0x02)],
            unresolvedHandles: new Set(['member-b']),
            tracked: new Map([['key3', tracked('member-b', deviceKey)]]),
        });

        expect(mocks.group_remove_member).not.toHaveBeenCalled();
        expect(result.tracked.has('key3')).toBe(true);
    });

    it('never evicts the sender, even when a persisted record names it', () => {
        const result = reconcileRoster({
            group: { members: [SELF] } as never,
            selfPublicBytes: SELF,
            recipients: [],
            memberKeys: [],
            unresolvedHandles: new Set(),
            tracked: new Map([['self', tracked('group-a', SELF)]]),
        });

        expect(mocks.group_remove_member).not.toHaveBeenCalled();
        expect(result.tracked.has('self')).toBe(false);
    });

    it('evicts a member account key that is no longer a recipient', () => {
        const memberKey = idKey(0x02);
        reconcileRoster({
            group: { members: [memberKey] } as never,
            selfPublicBytes: SELF,
            recipients: [],
            memberKeys: [memberKey],
            unresolvedHandles: new Set(),
            tracked: new Map(),
        });

        const removed = mocks.group_remove_member.mock.calls.map(
            (call) => call[1] as Uint8Array,
        );
        expect(removed.some((key) => sameKey(key, memberKey))).toBe(true);
    });
});
