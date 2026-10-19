// @vitest-environment jsdom
//
// MD-17a: the PRIMARY device (device_id 0) must be addressed by the BARE peer
// id, because the receive loop polls `identity.recipientId` (bare) — an
// envelope addressed to `${peerId}:0` is never picked up. Nonzero devices keep
// the `peerId:deviceId` addressing.
//
// CONTRACT pinned here (the implementation must match it):
//   * fan-out devices [0, 1] for peer "peer" -> exactly two sends:
//       sendEnvelope("peer",   envelope-for-device-0)
//       sendEnvelope("peer:1", envelope-for-device-1)
//   * no address receives the same envelope twice, and no address is repeated.
//   * an EMPTY device list never reaches the fan-out path: the legacy
//     single-recipient send (one envelope to the bare peer id) is unchanged.
//
// Real WASM crypto + a real StorageGate over fake-indexeddb; only the relay
// transport, the storage key and IndexedDB are mocked — same harness as
// `app_device_fanout.test.tsx`.
//
// The fan-out trio (`FanoutDeviceInput`, `fanout_establish`, `fanout_encrypt`)
// is additionally stubbed here: this suite pins the ADDRESSING of the fan-out
// envelopes, not the crypto, and the locally available wasm pkg predates the
// fan-out bindings. Everything else (identity generation, prekey bundles,
// storage encryption) still runs against the real wasm module.

import '@testing-library/jest-dom';
import type { FC } from 'react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import fakeIndexedDB from 'fake-indexeddb';

(globalThis as any).indexedDB = fakeIndexedDB;

vi.mock('../src/storage_key', () => ({
    getStorageKey: () => new Uint8Array(32),
    getStoragePassword: () => 'test-storage-password',
}));

// App does not inject a transport into Conversation, so Conversation builds the
// default one; every instance the mock class returns shares these spies.
const holder: any = { sent: [] as { recipientId: string; envelope: Uint8Array }[] };

vi.mock('../src/relay_transport', () => ({
    getRelayWsUrl: () => 'ws://localhost:8000',
    RelayTransport: vi.fn().mockImplementation(function () {
        return {
            publishPrekey: (...a: unknown[]) => holder.publishPrekey(...a),
            connect: (...a: unknown[]) => holder.connect(...a),
            close: () => holder.close(),
            lookupPrekey: (...a: unknown[]) => holder.lookupPrekey(...a),
            sendEnvelope: (...a: unknown[]) => holder.sendEnvelope(...a),
            pickupEnvelope: (...a: unknown[]) => holder.pickupEnvelope(...a),
        };
    }),
}));

// Stub ONLY the fan-out bindings; every other export is the real wasm module.
// `fanout_encrypt` returns one envelope per input device, in input order, with
// the device id echoed back — exactly the shape the send loop consumes.
vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<Record<string, unknown>>();
    class FanoutDeviceInput {
        constructor(
            public deviceId: number,
            public identityKey: Uint8Array,
            public bundleBytes: Uint8Array,
        ) {}
    }
    return {
        ...actual,
        FanoutDeviceInput,
        fanout_establish: (_handle: unknown, inputs: FanoutDeviceInput[]) => ({ inputs }),
        fanout_encrypt: (handle: { inputs: FanoutDeviceInput[] }, plaintext: Uint8Array) =>
            handle.inputs.map((input) => ({
                device_id: input.deviceId,
                envelope: Uint8Array.from([input.deviceId, ...plaintext]),
            })),
    };
});

import App from '../src/App';
import { ensureWasmInit } from '../src/wasm_init';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    bundle_identity_key_bytes,
} from '../../../core/bindings/wasm/pkg/index.js';

interface DeviceListEntry {
    deviceId: number;
    identityKey: Uint8Array;
    bundleBytes: Uint8Array;
}
interface DeviceList {
    version: number;
    devices: DeviceListEntry[];
}

const AppWithDeviceList = App as unknown as FC<{ deviceList?: DeviceList }>;

const PEER_ID = 'peer';
const BODY = 'hello from the device-0 fan-out suite';

/** A real device: its own identity, receiver session and published bundle. */
function makeDevice(deviceId: number): DeviceListEntry {
    const identity = generate_identity();
    const bundleBytes = publish_bundle_bytes(create_receiver_session(identity));
    return { deviceId, identityKey: bundle_identity_key_bytes(bundleBytes), bundleBytes };
}

const list = (version: number, devices: DeviceListEntry[]): DeviceList => ({ version, devices });

/** Recipient ids the transport was asked to deliver to, in call order. */
const sentTo = (): string[] => holder.sent.map((s: { recipientId: string }) => s.recipientId);

/** The envelope delivered to `recipientId` (undefined when never addressed). */
const envelopeTo = (recipientId: string): Uint8Array | undefined =>
    holder.sent.find((s: { recipientId: string }) => s.recipientId === recipientId)?.envelope;

async function renderApp(deviceList?: DeviceList) {
    const utils = render(<AppWithDeviceList deviceList={deviceList} />);
    // The direct composer only appears once the persisted identity has loaded,
    // so this is the gate for "App is ready to send".
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    return utils;
}

/** Type and send, then wait until the send completed successfully. */
async function sendAndWait(peerId: string, body: string): Promise<void> {
    fireEvent.change(screen.getByLabelText('Recipient ID'), { target: { value: peerId } });
    fireEvent.change(screen.getByPlaceholderText('Type a message'), { target: { value: body } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    // Success is observable as the delivered message appearing in the thread
    // and the composer being cleared — not as any particular status wording.
    await waitFor(() => expect(screen.getByText(body)).toBeInTheDocument());
    expect((screen.getByPlaceholderText('Type a message') as HTMLInputElement).value).toBe('');
}

beforeEach(async () => {
    holder.sent.length = 0;
    holder.sendEnvelope = vi.fn(async (recipientId: string, envelope: Uint8Array) => {
        holder.sent.push({ recipientId, envelope });
    });
    holder.publishPrekey = vi.fn(async () => {});
    holder.connect = vi.fn(async () => {});
    holder.close = vi.fn();
    holder.pickupEnvelope = vi.fn(async () => {
        throw new Error('NotFound');
    });
    holder.lookupPrekey = vi.fn(async () =>
        publish_bundle_bytes(create_receiver_session(generate_identity())),
    );

    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();

    await ensureWasmInit();
});

describe('MD-17a: the primary device is addressed by the bare peer id', () => {
    test('devices [0, 1] send to "peer" and "peer:1" — exactly two sends', async () => {
        await renderApp(list(1, [makeDevice(0), makeDevice(1)]));
        await sendAndWait(PEER_ID, BODY);

        // The primary (device 0) is reachable only through the bare-id receive
        // loop; device 1 keeps the per-device address.
        expect(sentTo().sort()).toEqual([PEER_ID, `${PEER_ID}:1`]);
        expect(holder.sendEnvelope).toHaveBeenCalledTimes(2);
        expect(holder.sendEnvelope).toHaveBeenCalledWith(PEER_ID, expect.anything());
        expect(holder.sendEnvelope).toHaveBeenCalledWith(`${PEER_ID}:1`, expect.anything());
        // Never the old, unreachable `${peerId}:0` address.
        expect(sentTo()).not.toContain(`${PEER_ID}:0`);
    });

    test('a two-device fan-out produces exactly two sends', async () => {
        await renderApp(list(2, [makeDevice(0), makeDevice(1)]));
        await sendAndWait(PEER_ID, BODY);

        expect(holder.sendEnvelope).toHaveBeenCalledTimes(2);
        expect(holder.sent).toHaveLength(2);
    });

    test('no address receives the same envelope twice', async () => {
        await renderApp(list(3, [makeDevice(0), makeDevice(1)]));
        await sendAndWait(PEER_ID, BODY);

        const addresses = sentTo();
        expect(new Set(addresses).size).toBe(addresses.length);

        const ciphertexts = holder.sent.map((s: { envelope: Uint8Array }) => s.envelope.join(','));
        expect(new Set(ciphertexts).size).toBe(ciphertexts.length);
        for (const s of holder.sent) expect(s.envelope.length).toBeGreaterThan(0);
    });

    test('a later fan-out with devices [0, 2] addresses "peer" then "peer:2"', async () => {
        // No state left behind: the primary is reachable again and device 2
        // gets its own address.
        await renderApp(list(4, [makeDevice(0), makeDevice(2)]));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo().sort()).toEqual([PEER_ID, `${PEER_ID}:2`]);
        expect(holder.sendEnvelope).toHaveBeenCalledTimes(2);
        expect(envelopeTo(PEER_ID)).toBeDefined();
        expect(envelopeTo(`${PEER_ID}:2`)).toBeDefined();
    });

    test('an empty device list never reaches the fan-out path: one send to the bare peer id', async () => {
        await renderApp(list(5, []));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo()).toEqual([PEER_ID]);
        expect(holder.sendEnvelope).toHaveBeenCalledTimes(1);
        expect(holder.lookupPrekey).toHaveBeenCalledWith(PEER_ID);
    });
});
