// @vitest-environment jsdom
//
// DR-6: the 1:1 send must fan out to the recipient's linked devices.
//
// CONTRACT pinned here (the implementation must match it):
//   * `App` takes an OPTIONAL prop `deviceList?: DeviceList`:
//       DeviceList      = { version: number; devices: DeviceListEntry[] }
//       DeviceListEntry = { deviceId: number; identityKey: Uint8Array; bundleBytes: Uint8Array }
//     `identityKey` is the key the PRIMARY vouched for (spec/v0.md §8.3) and is
//     what must reach `fanout_establish` as `expected_identity_key_bytes`;
//     `bundleBytes` is that device's prekey bundle. App owns the list as state
//     and applies prop updates MONOTONICALLY (§8.4): a version that is not
//     newer than the one already held is ignored.
//   * With a list: one plaintext -> one envelope per device, delivered as
//     `sendEnvelope(`${peerId}:${deviceId}`, envelope)`.
//   * With NO list: unchanged, exactly one `sendEnvelope(peerId, envelope)`.
//
// Real WASM crypto + a real StorageGate over fake-indexeddb; only the relay
// transport, the storage key and IndexedDB are mocked.

import '@testing-library/jest-dom';
import type { FC } from 'react';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
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

const PEER_ID = 'bob-recipient';
const BODY = 'hello from the fan-out suite';

/** A real device: its own identity, receiver session and published bundle. */
function makeDevice(deviceId: number): DeviceListEntry {
    const identity = generate_identity();
    const bundleBytes = publish_bundle_bytes(create_receiver_session(identity));
    return { deviceId, identityKey: bundle_identity_key_bytes(bundleBytes), bundleBytes };
}

const list = (version: number, devices: DeviceListEntry[]): DeviceList => ({ version, devices });

/** Recipient ids the transport was asked to deliver to, in call order. */
const sentTo = (): string[] => holder.sent.map((s: { recipientId: string }) => s.recipientId);

async function renderApp(deviceList?: DeviceList) {
    const utils = render(<AppWithDeviceList deviceList={deviceList} />);
    // The direct composer only appears once the persisted identity has loaded,
    // so this is the gate for "App is ready to send".
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    return utils;
}

function typeAndSend(peerId: string, body: string): void {
    fireEvent.change(screen.getByLabelText('Recipient ID'), { target: { value: peerId } });
    fireEvent.change(screen.getByPlaceholderText('Type a message'), { target: { value: body } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
}

/** Type and send, then wait until the send completed successfully. */
async function sendAndWait(peerId: string, body: string): Promise<void> {
    typeAndSend(peerId, body);
    // Success is observable as the delivered message appearing in the thread
    // and the composer being cleared — not as any particular status wording.
    await waitFor(() => expect(screen.getByText(body)).toBeInTheDocument());
    expect((screen.getByPlaceholderText('Type a message') as HTMLInputElement).value).toBe('');
}

/** Let an async send attempt run to completion (success or failure). */
async function settle(): Promise<void> {
    await act(async () => {
        for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));
    });
}

/** Assert the send attempt finished without delivering anything. */
function expectNothingSent(): void {
    expect(holder.sendEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(BODY)).toBeNull();
    // A successful send clears the composer; a rejected one leaves it intact.
    expect((screen.getByPlaceholderText('Type a message') as HTMLInputElement).value).toBe(BODY);
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
    // The peer's published bundle, served by lookupPrekey on the legacy path.
    holder.lookupPrekey = vi.fn(async () =>
        publish_bundle_bytes(create_receiver_session(generate_identity())),
    );

    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();

    await ensureWasmInit();
});

describe('App device fan-out wiring', () => {
    test('a 1:1 send to a recipient with three devices produces one envelope per device', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo().sort()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:2`, `${PEER_ID}:3`]);
        // One plaintext, three distinct ciphertexts — not one envelope reused.
        const ciphertexts = holder.sent.map((s: { envelope: Uint8Array }) => s.envelope.join(','));
        expect(new Set(ciphertexts).size).toBe(3);
        for (const s of holder.sent) expect(s.envelope.length).toBeGreaterThan(0);
    });

    test('a one-device recipient still produces exactly one envelope', async () => {
        await renderApp(list(1, [makeDevice(4)]));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo()).toEqual([`${PEER_ID}:4`]);
    });

    test('with no device list the send is unchanged: one envelope to the bare peer id', async () => {
        await renderApp();
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo()).toEqual([PEER_ID]);
        expect(holder.lookupPrekey).toHaveBeenCalledWith(PEER_ID);
    });

    test('a device whose bundle identity key is not the vouched-for key is rejected', async () => {
        const good = makeDevice(1);
        // Same well-formed key encoding, different key: the bundle's own
        // identity key is NOT what the primary vouched for.
        const tampered: DeviceListEntry = { ...good, identityKey: makeDevice(2).identityKey };

        await renderApp(list(3, [tampered]));
        typeAndSend(PEER_ID, BODY);
        await settle();

        expectNothingSent();
    });

    test('a device with malformed bundle bytes is rejected', async () => {
        const bad: DeviceListEntry = { ...makeDevice(1), bundleBytes: new Uint8Array([1, 2, 3]) };

        await renderApp(list(1, [bad]));
        typeAndSend(PEER_ID, BODY);
        await settle();

        expectNothingSent();
    });

    test('a device entry with no vouched-for key is rejected, never trusted from its bundle', async () => {
        const good = makeDevice(1);
        const missing = { deviceId: 1, bundleBytes: good.bundleBytes } as unknown as DeviceListEntry;

        await renderApp(list(1, [missing]));
        typeAndSend(PEER_ID, BODY);
        await settle();

        expectNothingSent();
    });

    test('an empty device list never addresses a device-scoped recipient', async () => {
        await renderApp(list(1, []));
        typeAndSend(PEER_ID, BODY);
        await settle();

        // Fail-closed or legacy fallback are both acceptable; inventing a
        // device-scoped address for a device that does not exist is not.
        for (const id of sentTo()) expect(id).not.toContain(':');
    });

    test('a newer device-list version replaces the held list', async () => {
        const { rerender } = await renderApp(list(2, [makeDevice(1)]));
        await act(async () => {
            rerender(<AppWithDeviceList deviceList={list(3, [makeDevice(5), makeDevice(6)])} />);
        });

        await sendAndWait(PEER_ID, BODY);
        expect(sentTo().sort()).toEqual([`${PEER_ID}:5`, `${PEER_ID}:6`]);
    });

    test('a stale device-list version is rejected', async () => {
        const { rerender } = await renderApp(list(5, [makeDevice(1), makeDevice(2)]));
        await act(async () => {
            rerender(<AppWithDeviceList deviceList={list(4, [makeDevice(9)])} />);
        });

        await sendAndWait(PEER_ID, BODY);
        expect(sentTo().sort()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:2`]);
    });

    test('an equal device-list version is rejected', async () => {
        const { rerender } = await renderApp(list(5, [makeDevice(1)]));
        await act(async () => {
            rerender(<AppWithDeviceList deviceList={list(5, [makeDevice(9)])} />);
        });

        await sendAndWait(PEER_ID, BODY);
        expect(sentTo()).toEqual([`${PEER_ID}:1`]);
    });

    test('the plaintext message is never logged', async () => {
        const spies = ['log', 'warn', 'error', 'info', 'debug'].map((m) =>
            vi.spyOn(console, m as 'log').mockImplementation(() => {}),
        );
        try {
            await renderApp(list(1, [makeDevice(1)]));
            await sendAndWait(PEER_ID, BODY);

            const logged = spies.flatMap((s) => s.mock.calls.flat()).map(String).join(' ');
            expect(logged).not.toContain(BODY);
        } finally {
            for (const s of spies) s.mockRestore();
        }
    });
});
