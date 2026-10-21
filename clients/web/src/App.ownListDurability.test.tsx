// @vitest-environment jsdom
//
// DL-2: App persists and restores the account's OWN signed device list.
//
// CONTRACT pinned here (the acceptance criteria of DL-2):
//   1. Relay null + a persisted v3 list with linked devices -> App holds v3 and
//      re-publishes those EXACT bytes. It never seeds v1.
//   2. Relay v4 + persisted v3 -> App holds and persists v4, and re-publishes
//      the v4 bytes (TTL refresh).
//   3. A revoke that yields v+2 is persisted, and a reload restores v+2 — the
//      revoked device stays gone.
//   4. Negative: an invalid/tampered persisted record is ignored and never
//      seeds v1 over a newer relay list.
//   5. Negative: a linked device (persisted `deviceId: 2`) neither seeds nor
//      publishes anything under its own recipient id.
//   6. Negative: a persist failure does not crash render and the in-memory list
//      stays usable.
//
// Only the external boundaries are mocked: the WASM module, the encrypted store,
// the relay transport, the storage key, and Conversation (stubbed to null so the
// direct view stays cheap). The real App, discovery.ts and own_list_store.ts run.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react';

// ── Hoisted shared state (referenced from the vi.mock factories) ────────────
const h = vi.hoisted(() => {
    const BUNDLE = new Uint8Array([9, 9, 9]);
    const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

    function makeKeypair() {
        const priv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) priv[i] = (i * 11 + 7) & 0xff;
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return { priv, pub };
    }

    /** The 4-byte tag a key signs with / verifies against (key + payload bound). */
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

    function privFromPublic(pub: Uint8Array): Uint8Array {
        const priv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) priv[i] = pub[i + 1] ^ 0x5a;
        return priv;
    }

    /** The store/id MD-16 persists the account-device link record under. */
    const LINK_KEY = 'identity/account-device-list';
    /** The store/id DL-2 persists the account's own signed list under. */
    const OWN_KEY = 'identity/own-device-list';

    const storage = {
        /** Records keyed by `${store}/${id}`. */
        records: new Map<string, unknown>(),
        /** When true, a `put` of the own-list record rejects (a failing persist). */
        putThrows: false,
        /** Every `put` in call order, as `${store}/${id}`. */
        puts: [] as string[],
    };

    const relay = {
        /** The blob served for the account's OWN handle. */
        ownBlob: null as Uint8Array | null,
        /** Every publish, in call order. */
        published: [] as { handle: string; blob: Uint8Array }[],
    };

    return { BUNDLE, keypairs, makeKeypair, tagFor, privFromPublic, LINK_KEY, OWN_KEY, storage, relay };
});

// ── WASM mock (external boundary: the compiled bindings) ────────────────────
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        const kp = h.makeKeypair();
        h.keypairs.push(kp);
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        const match = h.keypairs.find((kp) => kp.priv.every((b, i) => b === bytes[i]));
        const kp = match ?? h.makeKeypair();
        return { public_bytes: () => kp.pub.slice(), private_bytes: () => kp.priv.slice() };
    },
    create_receiver_session: () => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: () => h.BUNDLE.slice(),
    generate_prekey_bundle: () => h.BUNDLE.slice(),
    derive_safety_number: () => '00000 00000',
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
    fanout_establish: () => ({}),
    fanout_remove_device: () => {},
    FanoutDeviceInput: class {
        constructor(
            public device_id: number,
            public expected_identity_key_bytes: Uint8Array,
            public bundle_bytes: Uint8Array,
        ) {}
    },
    FanoutHandle: class {},
}));

vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));
vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

// ── StorageGate mock (external boundary: the encrypted store) ───────────────
vi.mock('../src/storage', async (importOriginal) => {
    const actual = await importOriginal<any>();
    return {
        ...actual,
        StorageGate: class {
            constructor(_opts: unknown) {}
            async open(): Promise<void> {}
            async put(store: string, id: string, value: unknown): Promise<void> {
                const key = `${store}/${id}`;
                h.storage.puts.push(key);
                // Only the own-list record fails: the identity/session records
                // must still persist, or the app could not even start.
                if (h.storage.putThrows && key === h.OWN_KEY) throw new Error('put failed');
                h.storage.records.set(key, value);
            }
            async get(store: string, id: string): Promise<unknown | null> {
                return h.storage.records.get(`${store}/${id}`) ?? null;
            }
        },
    };
});

// ── Transport mock ──────────────────────────────────────────────────────────
vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: async () => {},
            connect: async () => {},
            close: () => {},
            pickupEnvelope: () => Promise.reject(new Error('NotFound')),
            publishDiscovery: async (handle: string, blob: Uint8Array) => {
                h.relay.published.push({ handle, blob });
            },
            lookupDiscovery: async () => h.relay.ownBlob,
        };
    }),
}));

// Conversation is stubbed to null so the direct view stays cheap.
vi.mock('../src/Conversation', async () => {
    const actual = await vi.importActual<any>('../src/Conversation');
    return { ...actual, Conversation: () => null };
});

import App from '../src/App';

// ── Fixtures ────────────────────────────────────────────────────────────────
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

/** Sign a list with the account key the way the real binding does. */
function sign(version: number, entries: Parameters<typeof pack>[0]) {
    const priv = h.keypairs[0].priv;
    const packed = pack(entries);
    const tag = h.tagFor(priv, packed);
    const out = new Uint8Array(1 + packed.length + tag.length);
    out[0] = version;
    out.set(packed, 1);
    out.set(tag, 1 + packed.length);
    return out;
}

const dev0 = { deviceId: 0, identityKey: new Uint8Array(33).fill(1), bundleBytes: h.BUNDLE };
const dev2 = { deviceId: 2, identityKey: new Uint8Array(33).fill(3), bundleBytes: h.BUNDLE };
const dev3 = { deviceId: 3, identityKey: new Uint8Array(33).fill(4), bundleBytes: h.BUNDLE };

/** The MD-16 link record shape, as persisted by the linking handshake. */
function linkRecord(deviceId: number) {
    return { accountHandle: 'acct-handle', deviceId, signedListBytesBase64: 'AAAA' };
}

/** The DL-2 own-list record shape. */
function ownRecord(version: number, bytes: Uint8Array) {
    return { version, signedListBytesBase64: Buffer.from(bytes).toString('base64') };
}

const lastOwnPublish = () => h.relay.published[h.relay.published.length - 1];

/** Render App and wait for the identity to load. */
async function renderApp() {
    const view = render(<App />);
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    return view;
}

/** Open the Link view and wait for the linked-devices section to show `label`. */
async function openLinkView(label: string) {
    fireEvent.click(screen.getByRole('button', { name: 'Link' }));
    await waitFor(() => expect(screen.getByText(label)).toBeInTheDocument());
}

beforeEach(() => {
    h.keypairs.length = 0;
    h.storage.records.clear();
    h.storage.puts.length = 0;
    h.storage.putThrows = false;
    h.relay.published.length = 0;
    h.relay.ownBlob = null;
    // The identity loader needs a keypair to exist before App signs anything.
    h.keypairs.push(h.makeKeypair());
});

afterEach(() => {
    cleanup();
});

describe('DL-2: restoring the account own list', () => {
    test('relay null + persisted v3 re-publishes v3 (not v1) and holds it', async () => {
        const v3 = sign(3, [dev0, dev2]);
        h.storage.records.set(h.OWN_KEY, ownRecord(3, v3));
        h.relay.ownBlob = null;

        await renderApp();

        await waitFor(() => expect(h.relay.published.length).toBeGreaterThan(0));
        const published = lastOwnPublish();
        expect(Array.from(published.blob)).toEqual(Array.from(v3));
        // Never a v1 seed: the version byte of the published blob is 3.
        expect(published.blob[0]).toBe(3);

        // And the held list is v3 with both devices.
        await openLinkView('Device 2');
        expect(screen.getByText('Device 2')).toBeInTheDocument();
    });

    test('relay v4 + persisted v3 holds and persists v4, and re-publishes v4', async () => {
        const v3 = sign(3, [dev0, dev2]);
        h.storage.records.set(h.OWN_KEY, ownRecord(3, v3));
        const v4 = sign(4, [dev0, dev2, dev3]);
        h.relay.ownBlob = v4;

        await renderApp();

        await waitFor(() => expect(h.relay.published.length).toBeGreaterThan(0));
        expect(Array.from(lastOwnPublish().blob)).toEqual(Array.from(v4));

        // v4 is persisted so a later reload restores it.
        await waitFor(() => {
            const stored = h.storage.records.get(h.OWN_KEY) as { version: number } | undefined;
            expect(stored?.version).toBe(4);
        });

        await openLinkView('Device 3');
        expect(screen.getByText('Device 3')).toBeInTheDocument();
    });

    test('a revoke that yields v+2 is persisted, and a reload restores v+2', async () => {
        // Start from a persisted v3 holding devices 0 and 2.
        const v3 = sign(3, [dev0, dev2]);
        h.storage.records.set(h.OWN_KEY, ownRecord(3, v3));
        h.relay.ownBlob = null;

        const first = await renderApp();
        await waitFor(() => expect(h.relay.published.length).toBeGreaterThan(0));

        // A revoke published v5 (v+2) elsewhere and handed the fresh list back.
        const v5 = sign(5, [dev0]);
        h.relay.ownBlob = v5;
        first.unmount();

        // Reload: the relay now holds v5, which is newer than the persisted v3.
        await renderApp();
        await waitFor(() => {
            const stored = h.storage.records.get(h.OWN_KEY) as { version: number } | undefined;
            expect(stored?.version).toBe(5);
        });

        // The revoked device 2 is gone from the restored list.
        fireEvent.click(screen.getByRole('button', { name: 'Link' }));
        await waitFor(() => expect(screen.getByText('Device 0')).toBeInTheDocument());
        expect(screen.queryByText('Device 2')).not.toBeInTheDocument();
    });

    test('an invalid persisted record is ignored and never seeds v1 over a newer relay list', async () => {
        // A record whose bytes do not verify (signed by a foreign key).
        const foreign = h.makeKeypair();
        const foreignPacked = pack([dev0]);
        const foreignTag = h.tagFor(foreign.priv, foreignPacked);
        const foreignBlob = new Uint8Array(1 + foreignPacked.length + foreignTag.length);
        foreignBlob[0] = 3;
        foreignBlob.set(foreignPacked, 1);
        foreignBlob.set(foreignTag, 1 + foreignPacked.length);
        h.storage.records.set(h.OWN_KEY, ownRecord(3, foreignBlob));

        const v4 = sign(4, [dev0, dev3]);
        h.relay.ownBlob = v4;

        await renderApp();

        await waitFor(() => expect(h.relay.published.length).toBeGreaterThan(0));
        // The relay's v4 wins; no v1 seed was published.
        expect(Array.from(lastOwnPublish().blob)).toEqual(Array.from(v4));
        expect(h.relay.published.every((p) => p.blob[0] !== 1)).toBe(true);
    });

    test('a linked device (deviceId 2) neither seeds nor publishes an own list', async () => {
        h.storage.records.set(h.LINK_KEY, linkRecord(2));
        h.relay.ownBlob = null;

        await renderApp();

        // Give the own-list effect every chance to run before asserting.
        await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
        await new Promise((r) => setTimeout(r, 50));

        expect(h.relay.published).toHaveLength(0);
        // Nothing was persisted under the own-list record either.
        expect(h.storage.puts).not.toContain(h.OWN_KEY);
    });

    test('a persist failure does not crash render and the in-memory list stays usable', async () => {
        h.storage.putThrows = true;
        const v3 = sign(3, [dev0, dev2]);
        h.relay.ownBlob = v3;

        await renderApp();

        // The list is still held in memory: the linked-devices section renders.
        await openLinkView('Device 2');
        expect(screen.getByText('Device 2')).toBeInTheDocument();
        // The app is still interactive.
        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        expect(screen.getByRole('button', { name: 'Link' })).toBeInTheDocument();
    });
});
