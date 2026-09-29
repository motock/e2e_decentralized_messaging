// @vitest-environment jsdom
//
// DR-6b: revoking a linked device must stop later 1:1 sends from reaching it.
//
// CONTRACT pinned here (the implementation must match it):
//   * `DeviceLinking` gains two OPTIONAL props:
//       deviceList?: DeviceList                 (from ./Conversation)
//       onRevokeDevice?: (deviceId: number) => void
//     The linked-devices section and its per-device revoke controls render
//     ONLY when a list is actually supplied, so the existing render sites that
//     pass only `localIdentityKey` are unchanged.
//   * `App` owns revocation: revoking drops the device from the held list AND
//     calls `fanout_remove_device(handle, deviceId)` on the live sender-side
//     fan-out handle, so the removal sticks in the session, not just the UI.
//   * After a revoke, a 1:1 send produces envelopes for the surviving devices
//     and NONE for the revoked id.
//
// Real WASM crypto + a real StorageGate over fake-indexeddb; only the relay
// transport, the storage key and IndexedDB are mocked. The DR-5
// `fanout_remove_device` binding is WRAPPED (not replaced) so the call is
// observable while the real crypto still runs.

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

// Wrap (do not replace) the DR-5 binding so the real crypto still runs while
// the revoke call itself is observable. The spy is parked on globalThis
// because vi.mock factories are hoisted above module-scope declarations.
vi.mock('../../../core/bindings/wasm/pkg/index.js', async () => {
    const actual = await vi.importActual<any>('../../../core/bindings/wasm/pkg/index.js');
    (globalThis as any).__removeDeviceSpy = vi.fn();
    return {
        ...actual,
        fanout_remove_device: (handle: unknown, deviceId: number) => {
            (globalThis as any).__removeDeviceSpy(handle, deviceId);
            return actual.fanout_remove_device(handle, deviceId);
        },
    };
});

import App from '../src/App';
import { DeviceLinking } from '../src/DeviceLinking';
import { ensureWasmInit } from '../src/wasm_init';
import type { DeviceList, DeviceListEntry } from '../src/Conversation';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    bundle_identity_key_bytes,
} from '../../../core/bindings/wasm/pkg/index.js';

const AppWithDeviceList = App as unknown as FC<{ deviceList?: DeviceList }>;
const removeDeviceSpy = (): any => (globalThis as any).__removeDeviceSpy;

const PEER_ID = 'bob-recipient';
const BODY = 'hello after the revoke';

/** A real device: its own identity, receiver session and published bundle. */
function makeDevice(deviceId: number): DeviceListEntry {
    const identity = generate_identity();
    const bundleBytes = publish_bundle_bytes(create_receiver_session(identity));
    return { deviceId, identityKey: bundle_identity_key_bytes(bundleBytes), bundleBytes };
}

const list = (version: number, devices: DeviceListEntry[]): DeviceList => ({ version, devices });

/** Recipient ids the transport was asked to deliver to, in call order. */
const sentTo = (): string[] => holder.sent.map((s: { recipientId: string }) => s.recipientId);

/** Accessible names of the revoke controls currently offered. */
const revokeControls = (): string[] =>
    screen.queryAllByRole('button', { name: /^Revoke device / }).map((b) => b.textContent ?? '');

const goTo = (label: string): void => {
    fireEvent.click(screen.getByRole('button', { name: label }));
};

const revoke = (deviceId: number): void => {
    fireEvent.click(screen.getByRole('button', { name: `Revoke device ${deviceId}` }));
};

async function renderApp(deviceList?: DeviceList) {
    const utils = render(<AppWithDeviceList deviceList={deviceList} />);
    // The direct composer only appears once the persisted identity has loaded,
    // so this is the gate for "App is ready".
    await waitFor(() => expect(screen.getByTitle('Copy your recipient ID')).toBeInTheDocument());
    return utils;
}

async function sendAndWait(peerId: string, body: string): Promise<void> {
    fireEvent.change(screen.getByLabelText('Recipient ID'), { target: { value: peerId } });
    fireEvent.change(screen.getByPlaceholderText('Type a message'), { target: { value: body } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    await waitFor(() => expect(screen.getByText(body)).toBeInTheDocument());
}

/** Let pending async work (list sync, session establishment) settle. */
async function settle(): Promise<void> {
    await act(async () => {
        for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 5));
    });
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
    removeDeviceSpy()?.mockClear();

    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();

    await ensureWasmInit();
});

describe('DeviceLinking revoke control (optional props)', () => {
    /** Render and wait past the async wasm gate so assertions are meaningful. */
    async function renderLinking(props: Record<string, unknown>): Promise<void> {
        render(<DeviceLinking localIdentityKey={generate_identity().publicBytes} {...props} />);
        await screen.findByText('Link a new device to this account.');
    }

    test('with no device list there is no revoke control', async () => {
        await renderLinking({});
        expect(screen.queryByRole('region', { name: 'Linked devices' })).toBeNull();
        expect(revokeControls()).toEqual([]);
    });

    test('a supplied list renders one revoke control per device, reporting its id', async () => {
        const onRevokeDevice = vi.fn();
        await renderLinking({
            deviceList: list(1, [makeDevice(1), makeDevice(2)]),
            onRevokeDevice,
        });
        expect(revokeControls()).toEqual(['Revoke device 1', 'Revoke device 2']);

        revoke(2);
        expect(onRevokeDevice).toHaveBeenCalledTimes(1);
        expect(onRevokeDevice).toHaveBeenCalledWith(2);
    });

    test('an empty device list renders the section but no revoke control', async () => {
        await renderLinking({ deviceList: list(1, []), onRevokeDevice: vi.fn() });
        expect(screen.getByRole('region', { name: 'Linked devices' })).toBeInTheDocument();
        expect(revokeControls()).toEqual([]);
    });
});

describe('App device revocation', () => {
    test('revoking one of three devices: a later send reaches the two survivors only', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        goTo('Link');
        await waitFor(() => expect(revokeControls()).toHaveLength(3));
        revoke(2);
        await waitFor(() =>
            expect(revokeControls()).toEqual(['Revoke device 1', 'Revoke device 3']),
        );

        goTo('Direct');
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
    });

    test('revoking calls fanout_remove_device on the live session handle', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        goTo('Link');
        await waitFor(() => expect(revokeControls()).toHaveLength(3));
        revoke(2);

        await waitFor(() => expect(removeDeviceSpy()).toHaveBeenCalledTimes(1));
        expect(removeDeviceSpy()).toHaveBeenCalledWith(expect.anything(), 2);
    });

    test('a revoked id is no longer offered and the surviving session is undisturbed', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        goTo('Link');
        await waitFor(() => expect(revokeControls()).toHaveLength(3));
        revoke(2);
        await waitFor(() =>
            expect(revokeControls()).toEqual(['Revoke device 1', 'Revoke device 3']),
        );

        // The revoked id is gone from the list, so it cannot be revoked again.
        expect(screen.queryByRole('button', { name: 'Revoke device 2' })).toBeNull();

        goTo('Direct');
        await sendAndWait(PEER_ID, BODY);
        expect(sentTo()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
    });

    test('a replayed stale list cannot resurrect a revoked device', async () => {
        const initial = list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]);
        const { rerender } = await renderApp(initial);
        goTo('Link');
        await waitFor(() => expect(revokeControls()).toHaveLength(3));
        revoke(2);
        await waitFor(() =>
            expect(revokeControls()).toEqual(['Revoke device 1', 'Revoke device 3']),
        );

        // Replay the same (now stale) version as a fresh object, as a
        // reconnecting peer would.
        rerender(<AppWithDeviceList deviceList={list(7, initial.devices)} />);
        await settle();
        expect(revokeControls()).toEqual(['Revoke device 1', 'Revoke device 3']);

        goTo('Direct');
        await sendAndWait(PEER_ID, BODY);
        expect(sentTo()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
    });

    test('revoking every device falls back to the legacy single-recipient send', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2)]));
        goTo('Link');
        await waitFor(() => expect(revokeControls()).toHaveLength(2));
        revoke(1);
        await waitFor(() => expect(revokeControls()).toEqual(['Revoke device 2']));
        revoke(2);
        await waitFor(() => expect(revokeControls()).toEqual([]));

        goTo('Direct');
        await sendAndWait(PEER_ID, BODY);
        expect(sentTo()).toEqual([PEER_ID]);
    });
});
