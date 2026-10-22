/** @vitest-environment node */
/**
 * Persisted group state: validation of the GF-2 device-list cache.
 *
 * The cache is a new restore-time trust boundary — its contents feed the
 * recipient set, and therefore the roster. These pin the negative paths: an
 * unusable entry contributes nothing rather than a guessed device.
 */

import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    verify_device_list: vi.fn(),
}));

vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { validatedHeldDeviceLists } from './group_state';

/** A 33-byte identity key with the Curve25519 type tag. */
function idKey(seed: number): Uint8Array {
    const bytes = new Uint8Array(33).fill(seed & 0xff);
    bytes[0] = 0x05;
    return bytes;
}

function entry(handle: unknown, record: unknown): unknown[] {
    return [handle, record];
}

describe('validatedHeldDeviceLists', () => {
    it('keeps a well-formed list', () => {
        const lists = validatedHeldDeviceLists([
            entry('member-b', {
                version: 7,
                devices: [
                    [0, Array.from(idKey(0x02))],
                    [3, Array.from(idKey(0x03))],
                ],
            }),
        ]);

        const list = lists.get('member-b');
        expect(list?.version).toBe(7);
        expect(list?.devices.map((device) => device.deviceId)).toEqual([0, 3]);
        expect(list?.devices[1].identityKey).toEqual(idKey(0x03));
    });

    it('drops a list whose key is not 33 bytes', () => {
        const lists = validatedHeldDeviceLists([
            entry('member-b', { version: 7, devices: [[0, [0x05, 0x01]]] }),
        ]);
        expect(lists.size).toBe(0);
    });

    it('drops a list whose key has the wrong type byte', () => {
        const wrong = Array.from(idKey(0x03));
        wrong[0] = 0x04;
        const lists = validatedHeldDeviceLists([
            entry('member-b', { version: 7, devices: [[3, wrong]] }),
        ]);
        expect(lists.size).toBe(0);
    });

    it('drops a list with a non-byte key value', () => {
        const bytes = Array.from(idKey(0x03));
        bytes[1] = 256;
        const lists = validatedHeldDeviceLists([
            entry('member-b', { version: 7, devices: [[3, bytes]] }),
        ]);
        expect(lists.size).toBe(0);
    });

    it('drops a non-integer or out-of-range device id', () => {
        expect(
            validatedHeldDeviceLists([
                entry('member-b', { version: 7, devices: [[1.5, Array.from(idKey(0x03))]] }),
            ]).size,
        ).toBe(0);
        expect(
            validatedHeldDeviceLists([
                entry('member-b', {
                    version: 7,
                    devices: [[0x100000000, Array.from(idKey(0x03))]],
                }),
            ]).size,
        ).toBe(0);
    });

    it('drops an entry with no devices', () => {
        const lists = validatedHeldDeviceLists([entry('member-b', { version: 7, devices: [] })]);
        expect(lists.size).toBe(0);
    });

    it('drops an entry with an invalid version', () => {
        for (const version of [-1, 1.5, Number.NaN, '7']) {
            const lists = validatedHeldDeviceLists([
                entry('member-b', { version, devices: [[0, Array.from(idKey(0x02))]] }),
            ]);
            expect(lists.size).toBe(0);
        }
    });

    it('drops an entry with an empty handle or a non-object record', () => {
        expect(
            validatedHeldDeviceLists([
                entry('', { version: 7, devices: [[0, Array.from(idKey(0x02))]] }),
            ]).size,
        ).toBe(0);
        expect(validatedHeldDeviceLists([entry('member-b', null)])).toEqual(new Map());
        expect(validatedHeldDeviceLists([entry('member-b', 'nope')]).size).toBe(0);
    });

    it('returns nothing for a non-array record', () => {
        expect(validatedHeldDeviceLists(undefined).size).toBe(0);
        expect(validatedHeldDeviceLists({ 'member-b': {} }).size).toBe(0);
    });
});
