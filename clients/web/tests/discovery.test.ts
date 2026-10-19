/**
 * Discovery module (MD-9): publish, verify, and apply signed device lists.
 *
 * The WASM module is mocked here because this environment has no wasm32
 * toolchain to rebuild `core/bindings/wasm/pkg` (the checked-in pkg predates
 * `sign_device_list` / `verify_device_list`). The fake below models the
 * documented contract exactly — `verify_device_list(bytes, expectedAccount)`
 * returns `u64_le(version)` followed by the packed entry buffer, and rejects a
 * tampered blob or a list bound to another account. The real Rust verifier is
 * covered by `core/bindings/wasm/src/device_list.rs`'s own unit tests; these
 * tests grade the web-side orchestration in `src/discovery.ts`.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { DeviceList } from '../src/Conversation';

// ── Fake WASM device-list signer/verifier ───────────────────────────────────

const fake = vi.hoisted(() => {
    const accounts = new Map<string, Uint8Array>();
    const verifyCalls: Array<{ bytes: Uint8Array; expectedAccount: Uint8Array }> = [];
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
        const e = new Error(message);
        (e as unknown as { kind: string }).kind = 'DeviceList';
        throw e;
    };
    const sign_device_list = (privateBytes: Uint8Array, version: number, entries: Uint8Array) => {
        const pub = accounts.get(hex(privateBytes));
        if (!pub) fail('UnknownAccount');
        const out = new Uint8Array(33 + 8 + entries.length + 32);
        out.set(pub!, 0);
        new DataView(out.buffer).setBigUint64(33, BigInt(version), true);
        out.set(entries, 41);
        out.set(tagFor(pub!, version, entries), 41 + entries.length);
        return out;
    };
    const verify_device_list = (bytes: Uint8Array, expectedAccount: Uint8Array) => {
        verifyCalls.push({ bytes, expectedAccount });
        if (expectedAccount.length !== 33) fail('BadAccountLength');
        if (bytes.length < 33 + 8 + 32) fail('Truncated');
        const pub = bytes.slice(0, 33);
        if (hex(pub) !== hex(expectedAccount)) fail('WrongAccount');
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const version = Number(view.getBigUint64(33, true));
        const entries = bytes.slice(41, bytes.length - 32);
        if (hex(bytes.slice(bytes.length - 32)) !== hex(tagFor(pub, version, entries))) fail('BadSignature');
        const out = new Uint8Array(8 + entries.length);
        new DataView(out.buffer).setBigUint64(0, BigInt(version), true);
        out.set(entries, 8);
        return out;
    };
    return { accounts, verifyCalls, sign_device_list, verify_device_list };
});

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    sign_device_list: fake.sign_device_list,
    verify_device_list: fake.verify_device_list,
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

import {
    publishSignedDeviceList,
    lookupDeviceList,
    toConversationDeviceList,
    type DiscoveryTransport,
} from '../src/discovery';

// ── Helpers ─────────────────────────────────────────────────────────────────

const bytes = (len: number, seed: number) => Uint8Array.from({ length: len }, (_, i) => (seed + i) & 0xff);

function makeAccount(seed: number) {
    const privateBytes = bytes(32, seed);
    const publicBytes = bytes(33, seed + 0x40);
    fake.accounts.set(
        Array.from(privateBytes, (x) => x.toString(16).padStart(2, '0')).join(''),
        publicBytes,
    );
    return { privateBytes, publicBytes };
}

function packEntries(entries: Array<{ deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }>) {
    const parts: Uint8Array[] = [];
    for (const e of entries) {
        const head = new Uint8Array(8);
        const view = new DataView(head.buffer);
        view.setUint32(0, e.deviceId, true);
        view.setUint32(4, e.identityKey.length, true);
        const tail = new Uint8Array(4);
        new DataView(tail.buffer).setUint32(0, e.bundleBytes.length, true);
        parts.push(head, e.identityKey, tail, e.bundleBytes);
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
}

const ENTRIES = [
    { deviceId: 1, identityKey: bytes(33, 0x11), bundleBytes: bytes(48, 0x21) },
    { deviceId: 2, identityKey: bytes(33, 0x31), bundleBytes: bytes(52, 0x41) },
];

function signList(account: { privateBytes: Uint8Array }, version: number, entries = ENTRIES) {
    return fake.sign_device_list(account.privateBytes, version, packEntries(entries));
}

class FakeTransport implements DiscoveryTransport {
    published: Array<{ handle: string; bytes: Uint8Array }> = [];
    stored: Uint8Array | null = null;
    lookups: string[] = [];
    async publishDiscovery(handle: string, blob: Uint8Array): Promise<void> {
        this.published.push({ handle, bytes: blob });
        this.stored = blob;
    }
    async lookupDiscovery(handle: string): Promise<Uint8Array | null> {
        this.lookups.push(handle);
        return this.stored;
    }
}

let account: ReturnType<typeof makeAccount>;
let transport: FakeTransport;

beforeEach(() => {
    fake.verifyCalls.length = 0;
    account = makeAccount(1);
    transport = new FakeTransport();
});

// ── publishSignedDeviceList ─────────────────────────────────────────────────

describe('publishSignedDeviceList', () => {
    it('hands the signed bytes to the transport unchanged, under the handle', async () => {
        const signed = signList(account, 2);
        await publishSignedDeviceList(transport, 'alice', signed);
        expect(transport.published).toHaveLength(1);
        expect(transport.published[0].handle).toBe('alice');
        expect(transport.published[0].bytes).toBe(signed);
    });

    it('propagates a transport publish failure', async () => {
        const failing: DiscoveryTransport = {
            publishDiscovery: async () => { throw new Error('relay down'); },
            lookupDiscovery: async () => null,
        };
        await expect(publishSignedDeviceList(failing, 'alice', signList(account, 1))).rejects.toThrow('relay down');
    });
});

// ── lookupDeviceList: positive ──────────────────────────────────────────────

describe('lookupDeviceList round-trip', () => {
    it('verifies a signed list and returns the version and device ids', async () => {
        await publishSignedDeviceList(transport, 'alice', signList(account, 2));
        const result = await lookupDeviceList(transport, 'alice', account.publicBytes, null);

        expect(result).not.toBeNull();
        expect(result!.version).toBe(2);
        expect(result!.deviceList.version).toBe(2);
        expect(result!.deviceList.devices.map((d) => d.deviceId)).toEqual([1, 2]);
        expect(result!.deviceList.devices[0].identityKey).toEqual(ENTRIES[0].identityKey);
        expect(result!.deviceList.devices[0].bundleBytes).toEqual(ENTRIES[0].bundleBytes);
        expect(fake.verifyCalls).toHaveLength(1);
        expect(fake.verifyCalls[0].expectedAccount).toEqual(account.publicBytes);
    });

    it('returns a newer list when heldVersion is older', async () => {
        await publishSignedDeviceList(transport, 'alice', signList(account, 2));
        const result = await lookupDeviceList(transport, 'alice', account.publicBytes, 1);
        expect(result!.version).toBe(2);
        expect(result!.deviceList.devices).toHaveLength(2);
    });

    it('returns null when the held version is equal (monotonic)', async () => {
        await publishSignedDeviceList(transport, 'alice', signList(account, 2));
        expect(await lookupDeviceList(transport, 'alice', account.publicBytes, 2)).toBeNull();
    });

    it('returns null when the held version is newer', async () => {
        await publishSignedDeviceList(transport, 'alice', signList(account, 2));
        expect(await lookupDeviceList(transport, 'alice', account.publicBytes, 3)).toBeNull();
    });
});

// ── lookupDeviceList: negative ──────────────────────────────────────────────

describe('lookupDeviceList rejects unverified bytes', () => {
    it('returns null when the relay has no list, without calling verify', async () => {
        expect(await lookupDeviceList(transport, 'alice', account.publicBytes, null)).toBeNull();
        expect(fake.verifyCalls).toHaveLength(0);
    });

    it('rejects (never returns null) when a single byte is flipped', async () => {
        const signed = signList(account, 2);
        const tampered = signed.slice();
        tampered[tampered.length - 1] ^= 0xff; // corrupt the signature
        transport.stored = tampered;

        await expect(lookupDeviceList(transport, 'alice', account.publicBytes, null)).rejects.toThrow();
    });

    it('rejects a list signed by another account key', async () => {
        const other = makeAccount(9);
        transport.stored = signList(other, 2);

        await expect(lookupDeviceList(transport, 'alice', account.publicBytes, null)).rejects.toThrow();
    });

    it('rejects a malformed expected account key', async () => {
        transport.stored = signList(account, 2);
        await expect(lookupDeviceList(transport, 'alice', bytes(32, 7), null)).rejects.toThrow();
    });
});

// ── toConversationDeviceList ────────────────────────────────────────────────

describe('toConversationDeviceList', () => {
    it('parses the packed entry buffer into a DeviceList', () => {
        const list: DeviceList = toConversationDeviceList(7, packEntries(ENTRIES));
        expect(list.version).toBe(7);
        expect(list.devices).toEqual(ENTRIES);
    });

    it('parses an empty entry buffer to an empty device list', () => {
        expect(toConversationDeviceList(1, new Uint8Array(0))).toEqual({ version: 1, devices: [] });
    });

    it('throws on a truncated trailing record instead of dropping it', () => {
        const packed = packEntries(ENTRIES).slice(0, -3);
        expect(() => toConversationDeviceList(1, packed)).toThrow();
    });
});

// ── No sensitive data in logs ───────────────────────────────────────────────

describe('logging', () => {
    it('never logs the account key, identity keys, list bytes, or bundles', async () => {
        const spies = (['log', 'debug', 'info', 'warn', 'error'] as const).map((m) =>
            vi.spyOn(console, m).mockImplementation(() => {}),
        );
        try {
            await publishSignedDeviceList(transport, 'alice', signList(account, 2));
            await lookupDeviceList(transport, 'alice', account.publicBytes, null);

            const other = makeAccount(9);
            transport.stored = signList(other, 2);
            await expect(lookupDeviceList(transport, 'alice', account.publicBytes, null)).rejects.toThrow();

            for (const spy of spies) expect(spy).not.toHaveBeenCalled();
        } finally {
            for (const spy of spies) spy.mockRestore();
        }
    });
});
