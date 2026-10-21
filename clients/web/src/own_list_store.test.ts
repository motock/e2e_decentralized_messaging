/**
 * DL-2: the account's own signed device list survives a reload.
 *
 * CONTRACT pinned here:
 *  - `saveOwnDeviceList` persists `{version, signedListBytesBase64}` under its
 *    OWN record (`identity` / `own-device-list`) and never touches the linking
 *    handshake's `account-device-list` record.
 *  - `loadOwnDeviceList` returns the verified version, bytes and devices, and
 *    returns `null` — never unverified bytes — for a missing, malformed,
 *    tampered, foreign-signed or version-inconsistent record.
 *  - `restoreOwnDeviceList` prefers a strictly newer relay list, otherwise
 *    restores the persisted list (NEVER seeding v1), and never re-publishes an
 *    older list over a newer relay blob.
 *
 * The WASM module is mocked at the external boundary with a faithful stand-in:
 * `sign_device_list` tags the blob with a value derived from the signing key and
 * `verify_device_list` recomputes that tag from the expected account key, so a
 * tampered blob or a foreign signer really fails verification.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest';

const h = vi.hoisted(() => {
    const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

    let counter = 0;
    function makeKeypair() {
        const seed = ++counter;
        const priv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) priv[i] = (i * 7 + seed * 31 + 3) & 0xff;
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return { priv, pub };
    }

    /**
     * The 4-byte tag a key signs with / verifies against. Bound to BOTH the key
     * and the payload, so a tampered payload and a foreign signer both fail —
     * exactly the two properties the real binding provides.
     */
    function tagFor(secret: Uint8Array, payload: Uint8Array): number[] {
        let a = 0;
        let b = 0;
        let c = 0;
        let d = 0;
        for (const x of secret) {
            a = (a + x) & 0xff;
            b = (b + a) & 0xff;
        }
        for (const x of payload) {
            c = (c + x) & 0xff;
            d = (d + c) & 0xff;
        }
        return [a ^ c, b ^ d, (a + b) & 0xff, (c + d) & 0xff];
    }

    /** The private half a 33-byte compressed public key was derived from. */
    function privFromPublic(pub: Uint8Array): Uint8Array {
        const priv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) priv[i] = pub[i + 1] ^ 0x5a;
        return priv;
    }

    return { keypairs, makeKeypair, tagFor, privFromPublic };
});

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    sign_device_list: (priv: Uint8Array, version: number, packed: Uint8Array) => {
        const tag = h.tagFor(priv, packed);
        const out = new Uint8Array(1 + packed.length + tag.length);
        out[0] = version;
        out.set(packed, 1);
        out.set(tag, 1 + packed.length);
        return out;
    },
    verify_device_list: (bytes: Uint8Array, expectedAccount: Uint8Array) => {
        const packed = bytes.slice(1, bytes.length - 4);
        const tag = h.tagFor(h.privFromPublic(expectedAccount), packed);
        const actual = Array.from(bytes.slice(bytes.length - 4));
        if (actual.length !== tag.length || actual.some((b, i) => b !== tag[i])) {
            throw new Error('device list: signature verification failed');
        }
        const out = new Uint8Array(8 + packed.length);
        new DataView(out.buffer).setBigUint64(0, BigInt(bytes[0]), true);
        out.set(packed, 8);
        return out;
    },
}));

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

import {
    loadOwnDeviceList,
    OWN_LIST_RECORD_ID,
    OWN_LIST_STORE,
    restoreOwnDeviceList,
    saveOwnDeviceList,
    verifyOwnDeviceList,
} from '../src/own_list_store';
import type { DiscoveryTransport } from '../src/discovery';
import type { StorageGate } from '../src/storage';

// ── Fixtures ────────────────────────────────────────────────────────────────

const BUNDLE = new Uint8Array([9, 9, 9]);

function pack(entries: { deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }[]) {
    let size = 0;
    for (const e of entries) size += 12 + e.identityKey.length + e.bundleBytes.length;
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const e of entries) {
        view.setUint32(pos, e.deviceId, true);
        pos += 4;
        view.setUint32(pos, e.identityKey.length, true);
        pos += 4;
        out.set(e.identityKey, pos);
        pos += e.identityKey.length;
        view.setUint32(pos, e.bundleBytes.length, true);
        pos += 4;
        out.set(e.bundleBytes, pos);
        pos += e.bundleBytes.length;
    }
    return out;
}

const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: BUNDLE };
const dev2 = { deviceId: 2, identityKey: new Uint8Array(33).fill(3), bundleBytes: BUNDLE };
const dev3 = { deviceId: 3, identityKey: new Uint8Array(33).fill(4), bundleBytes: BUNDLE };

/** Sign a list the way the real binding does (the mock tags it with key+payload). */
function sign(priv: Uint8Array, version: number, entries: Parameters<typeof pack>[0]) {
    const packed = pack(entries);
    const tag = h.tagFor(priv, packed);
    const out = new Uint8Array(1 + packed.length + tag.length);
    out[0] = version;
    out.set(packed, 1);
    out.set(tag, 1 + packed.length);
    return out;
}

/** A minimal in-memory StorageGate stand-in, recording every key it touched. */
function fakeGate(seed: Record<string, unknown> = {}) {
    const records = new Map<string, unknown>(Object.entries(seed));
    const touched: string[] = [];
    const gate = {
        async get(store: string, id: string) {
            touched.push(`${store}/${id}`);
            return records.get(`${store}/${id}`) ?? null;
        },
        async put(store: string, id: string, value: unknown) {
            touched.push(`${store}/${id}`);
            records.set(`${store}/${id}`, value);
        },
    };
    return { gate: gate as unknown as StorageGate, records, touched };
}

/** A discovery transport serving one blob for the account handle. */
function fakeTransport(blob: Uint8Array | null) {
    const published: { handle: string; blob: Uint8Array }[] = [];
    const transport: DiscoveryTransport = {
        publishDiscovery: async (handle, bytes) => {
            published.push({ handle, blob: bytes });
        },
        lookupDiscovery: async () => blob,
    };
    return { transport, published };
}

const account = h.makeKeypair();
const otherAccount = h.makeKeypair();

beforeEach(() => {
    h.keypairs.length = 0;
});

// ── save / load ─────────────────────────────────────────────────────────────

describe('DL-2: saveOwnDeviceList / loadOwnDeviceList', () => {
    test('round-trips the version, the exact bytes and the devices', async () => {
        const { gate, records } = fakeGate();
        const bytes = sign(account.priv, 3, [dev0, dev2]);

        await saveOwnDeviceList(gate, { version: 3, bytes });

        const stored = records.get(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`) as {
            version: number;
            signedListBytesBase64: string;
        };
        expect(stored.version).toBe(3);
        expect(typeof stored.signedListBytesBase64).toBe('string');

        const loaded = await loadOwnDeviceList(gate, account.pub);
        expect(loaded).not.toBeNull();
        expect(loaded!.version).toBe(3);
        expect(Array.from(loaded!.bytes)).toEqual(Array.from(bytes));
        expect(loaded!.devices.map((d) => d.deviceId)).toEqual([0, 2]);
    });

    test('never writes the linking handshake record', async () => {
        const { gate, touched } = fakeGate();
        await saveOwnDeviceList(gate, { version: 1, bytes: sign(account.priv, 1, [dev0]) });

        expect(touched).toEqual([`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`]);
        expect(touched).not.toContain('identity/account-device-list');
    });

    test('returns null when nothing is persisted', async () => {
        const { gate } = fakeGate();
        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });

    test('returns null for a malformed record', async () => {
        const cases: unknown[] = [
            'not-an-object',
            null,
            {},
            { version: 3 },
            { version: 3, signedListBytesBase64: '' },
            { version: 0, signedListBytesBase64: 'AAAA' },
            { version: 1.5, signedListBytesBase64: 'AAAA' },
            { version: '3', signedListBytesBase64: 'AAAA' },
        ];
        for (const raw of cases) {
            const { gate } = fakeGate({ [`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`]: raw });
            expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
        }
    });

    test('returns null for tampered bytes instead of handing them back', async () => {
        const { gate, records } = fakeGate();
        const bytes = sign(account.priv, 3, [dev0, dev2]);
        await saveOwnDeviceList(gate, { version: 3, bytes });

        const stored = records.get(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`) as {
            version: number;
            signedListBytesBase64: string;
        };
        const tampered = Uint8Array.from(bytes);
        tampered[1] ^= 0xff; // flip a byte inside the signed payload
        records.set(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`, {
            version: stored.version,
            signedListBytesBase64: Buffer.from(tampered).toString('base64'),
        });

        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });

    test('returns null when the record was signed by another account', async () => {
        const { gate } = fakeGate();
        await saveOwnDeviceList(gate, {
            version: 3,
            bytes: sign(otherAccount.priv, 3, [dev0, dev2]),
        });

        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });

    test('returns null when the stored version disagrees with the signed version', async () => {
        const { gate } = fakeGate();
        await saveOwnDeviceList(gate, { version: 3, bytes: sign(account.priv, 4, [dev0]) });

        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });

    test('returns null when the store read throws', async () => {
        const gate = {
            async get() {
                throw new Error('unreadable record');
            },
            async put() {},
        } as unknown as StorageGate;

        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });

    test('rejects an out-of-range version and empty bytes on save', async () => {
        const { gate } = fakeGate();
        await expect(saveOwnDeviceList(gate, { version: 0, bytes: new Uint8Array([1]) })).rejects.toThrow();
        await expect(saveOwnDeviceList(gate, { version: 1, bytes: new Uint8Array(0) })).rejects.toThrow();
    });

    test('rejects an oversized persisted record without decoding it', async () => {
        const { gate } = fakeGate();
        await gate.put(OWN_LIST_STORE, OWN_LIST_RECORD_ID, {
            version: 1,
            // One base64 group past the 64 KiB protocol cap.
            signedListBytesBase64: 'A'.repeat(4 * Math.ceil((64 * 1024) / 3) + 4),
        });

        expect(await loadOwnDeviceList(gate, account.pub)).toBeNull();
    });
});

// ── verifyOwnDeviceList ─────────────────────────────────────────────────────

describe('DL-2: verifyOwnDeviceList', () => {
    test('derives the devices from the signed bytes, not from a caller array', () => {
        const bytes = sign(account.priv, 5, [dev0, dev2, dev3]);
        const list = verifyOwnDeviceList(bytes, account.pub);

        expect(list.version).toBe(5);
        expect(list.devices.map((d) => d.deviceId)).toEqual([0, 2, 3]);
        expect(Array.from(list.bytes)).toEqual(Array.from(bytes));
    });

    test('throws on a foreign signer', () => {
        const bytes = sign(otherAccount.priv, 5, [dev0]);
        expect(() => verifyOwnDeviceList(bytes, account.pub)).toThrow();
    });
});

// ── restoreOwnDeviceList ────────────────────────────────────────────────────

describe('DL-2: restoreOwnDeviceList', () => {
    test('relay null + persisted v3 restores v3 (never seeds v1) and asks for a re-publish', async () => {
        const { gate } = fakeGate();
        const persistedBytes = sign(account.priv, 3, [dev0, dev2]);
        await saveOwnDeviceList(gate, { version: 3, bytes: persistedBytes });
        const { transport } = fakeTransport(null);

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored).not.toBeNull();
        expect(restored!.list.version).toBe(3);
        expect(restored!.list.devices.map((d) => d.deviceId)).toEqual([0, 2]);
        expect(Array.from(restored!.list.bytes)).toEqual(Array.from(persistedBytes));
        expect(restored!.republish).toBe(true);
    });

    test('relay v4 + persisted v3 restores the relay v4 bytes', async () => {
        const { gate } = fakeGate();
        await saveOwnDeviceList(gate, { version: 3, bytes: sign(account.priv, 3, [dev0, dev2]) });
        const relayBytes = sign(account.priv, 4, [dev0, dev2, dev3]);
        const { transport } = fakeTransport(relayBytes);

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored!.list.version).toBe(4);
        expect(restored!.list.devices.map((d) => d.deviceId)).toEqual([0, 2, 3]);
        expect(Array.from(restored!.list.bytes)).toEqual(Array.from(relayBytes));
        expect(restored!.republish).toBe(true);
    });

    test('an older relay blob never replaces the newer persisted list', async () => {
        const { gate } = fakeGate();
        const persistedBytes = sign(account.priv, 3, [dev0, dev2]);
        await saveOwnDeviceList(gate, { version: 3, bytes: persistedBytes });
        const { transport } = fakeTransport(sign(account.priv, 2, [dev0]));

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored!.list.version).toBe(3);
        expect(Array.from(restored!.list.bytes)).toEqual(Array.from(persistedBytes));
    });

    test('an invalid persisted record is ignored and the relay list still wins', async () => {
        const { gate, records } = fakeGate();
        await saveOwnDeviceList(gate, { version: 3, bytes: sign(account.priv, 3, [dev0, dev2]) });
        // Corrupt the record: the bytes no longer verify.
        const stored = records.get(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`) as {
            version: number;
            signedListBytesBase64: string;
        };
        records.set(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`, {
            version: stored.version,
            signedListBytesBase64: Buffer.from(sign(otherAccount.priv, 3, [dev0])).toString('base64'),
        });
        const relayBytes = sign(account.priv, 4, [dev0, dev3]);
        const { transport } = fakeTransport(relayBytes);

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored!.list.version).toBe(4);
        expect(restored!.list.devices.map((d) => d.deviceId)).toEqual([0, 3]);
    });

    test('an invalid persisted record with no relay blob yields null (caller seeds v1)', async () => {
        const { gate, records } = fakeGate();
        records.set(`${OWN_LIST_STORE}/${OWN_LIST_RECORD_ID}`, {
            version: 3,
            signedListBytesBase64: 'not-base64-at-all!!',
        });
        const { transport } = fakeTransport(null);

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored).toBeNull();
    });

    test('neither persisted nor relay yields null', async () => {
        const { gate } = fakeGate();
        const { transport } = fakeTransport(null);

        expect(
            await restoreOwnDeviceList({
                gate,
                transport,
                handle: 'acct',
                expectedAccount: account.pub,
                heldVersion: null,
            }),
        ).toBeNull();
    });

    test('works without a gate (store not open yet) and takes the relay list', async () => {
        const relayBytes = sign(account.priv, 2, [dev0, dev2]);
        const { transport } = fakeTransport(relayBytes);

        const restored = await restoreOwnDeviceList({
            gate: undefined,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: null,
        });

        expect(restored!.list.version).toBe(2);
        expect(Array.from(restored!.list.bytes)).toEqual(Array.from(relayBytes));
    });

    test('a tampered relay blob throws rather than being held', async () => {
        const { gate } = fakeGate();
        const relayBytes = sign(otherAccount.priv, 4, [dev0]);
        const { transport } = fakeTransport(relayBytes);

        await expect(
            restoreOwnDeviceList({
                gate,
                transport,
                handle: 'acct',
                expectedAccount: account.pub,
                heldVersion: null,
            }),
        ).rejects.toThrow();
    });

    test('the in-memory held version is the baseline when it is newer than the record', async () => {
        const { gate } = fakeGate();
        await saveOwnDeviceList(gate, { version: 3, bytes: sign(account.priv, 3, [dev0, dev2]) });
        // Relay holds v4, but the caller already holds v5 in memory.
        const { transport } = fakeTransport(sign(account.priv, 4, [dev0, dev2, dev3]));

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: 5,
        });

        // v4 is not newer than the held v5, so the persisted v3 is restored
        // rather than downgrading the in-memory list.
        expect(restored!.list.version).toBe(3);
    });

    test('the persisted version is the baseline when it is newer than the in-memory hold', async () => {
        const { gate } = fakeGate();
        const persistedBytes = sign(account.priv, 6, [dev0, dev2]);
        await saveOwnDeviceList(gate, { version: 6, bytes: persistedBytes });
        // The relay holds v5: newer than the in-memory v4 but OLDER than the
        // persisted v6. Using only the in-memory version as the baseline would
        // adopt and re-publish v5, downgrading the store.
        const { transport, published } = fakeTransport(
            sign(account.priv, 5, [dev0, dev2, dev3]),
        );

        const restored = await restoreOwnDeviceList({
            gate,
            transport,
            handle: 'acct',
            expectedAccount: account.pub,
            heldVersion: 4,
        });

        expect(restored!.list.version).toBe(6);
        expect(Array.from(restored!.list.bytes)).toEqual(Array.from(persistedBytes));
        expect(restored!.republish).toBe(true);
        // `restoreOwnDeviceList` never publishes; the caller only does so for
        // the list it returns.
        expect(published).toHaveLength(0);
    });
});
