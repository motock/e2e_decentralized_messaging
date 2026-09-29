// @vitest-environment jsdom
//
// DR-6b: the user gets a revoke control for the account's linked devices, so
// later 1:1 sends stop reaching a revoked device.
//
// CONTRACT pinned here (the implementation must match it):
//   * `DeviceLinking` takes OPTIONAL props `deviceList?: DeviceList` and
//     `onRevokeDevice?: (deviceId: number) => void`. The linked-devices
//     section — and its revoke controls — render only when a list is actually
//     supplied, so the existing `<DeviceLinking localIdentityKey={key} />`
//     render sites keep working unchanged.
//   * App feeds the section from its own device-list state, and revoking a
//     device (a) drops it from that list AND (b) calls `fanout_remove_device`
//     on the live fan-out session, so the removal sticks in the session
//     rather than only in the UI.
//   * After a revoke, a subsequent 1:1 send produces NO envelope for the
//     revoked device while the surviving devices still receive — asserted on
//     the recipient-id SET, never on "a call did not throw".
//   * A device id that is not in the list cannot be revoked: no control is
//     ever offered for it, and the surviving session is undisturbed.
//
// The flow is driven from the REAL entry point (render App) with the same
// mock boundaries as app_device_fanout.test.tsx: real WASM crypto, real
// StorageGate over fake-indexeddb; only the relay transport and the storage
// key are mocked. `fanout_remove_device` is wrapped (call-through) so the
// tests can pin that a revoke hits the live session — and only for listed ids.

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

// Real WASM crypto throughout; only `fanout_remove_device` is wrapped so the
// tests can observe revocations hitting the live session.
vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<Record<string, unknown>>();
    if (typeof actual.fanout_remove_device !== 'function') {
        throw new Error('fanout_remove_device missing from the wasm pkg — DR-5 bindings not built');
    }
    return {
        ...actual,
        fanout_remove_device: vi.fn(actual.fanout_remove_device as (...a: unknown[]) => void),
    };
});

import App from '../src/App';
import { ensureWasmInit } from '../src/wasm_init';
import {
    fanout_remove_device,
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
const BODY = 'hello from the revoke suite';

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

/** Navigate to the Link view and wait for the linked-devices section. */
async function openLinkedDevices(): Promise<void> {
    fireEvent.click(screen.getByRole('button', { name: 'Link' }));
    await waitFor(() => expect(screen.getByText('Linked devices')).toBeInTheDocument());
    await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Revoke device 1' })).toBeInTheDocument(),
    );
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

    vi.mocked(fanout_remove_device).mockClear();

    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') dbs.clear();

    await ensureWasmInit();
});

describe('App device revocation (DR-6b)', () => {
    test('revoking one of three devices stops later sends reaching it; survivors still receive', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        await openLinkedDevices();

        expect(screen.getByRole('button', { name: 'Revoke device 1' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Revoke device 2' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Revoke device 3' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Revoke device 2' }));

        // Device 2 is gone from the list; the survivors remain revocable.
        expect(screen.queryByRole('button', { name: 'Revoke device 2' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Revoke device 1' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Revoke device 3' })).toBeInTheDocument();

        // The removal hit the live fan-out session, not just the UI list.
        expect(vi.mocked(fanout_remove_device)).toHaveBeenCalledTimes(1);
        expect(vi.mocked(fanout_remove_device)).toHaveBeenCalledWith(expect.anything(), 2);

        // Back to Direct: the next 1:1 send reaches only the survivors.
        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo().sort()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
        expect(sentTo()).not.toContain(`${PEER_ID}:2`);
        for (const s of holder.sent) expect(s.envelope.length).toBeGreaterThan(0);
    });

    test('the removal sticks: a replayed stale device list cannot resurrect the revoked device', async () => {
        const stale = list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]);
        const utils = await renderApp(stale);
        await openLinkedDevices();

        fireEvent.click(screen.getByRole('button', { name: 'Revoke device 2' }));
        expect(screen.queryByRole('button', { name: 'Revoke device 2' })).not.toBeInTheDocument();

        // Replay the same-version list as a fresh prop object: the monotonic
        // guard (§8.4) ignores it, so the revoked device stays revoked.
        utils.rerender(<AppWithDeviceList deviceList={{ version: 7, devices: stale.devices }} />);
        await waitFor(() =>
            expect(screen.getByRole('button', { name: 'Revoke device 1' })).toBeInTheDocument(),
        );
        expect(screen.queryByRole('button', { name: 'Revoke device 2' })).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        await sendAndWait(PEER_ID, BODY);

        expect(sentTo().sort()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
        expect(sentTo()).not.toContain(`${PEER_ID}:2`);
    });

    test('revoking an id that is not in the list is a no-op; the surviving session is undisturbed', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2), makeDevice(3)]));
        await openLinkedDevices();

        // No control is ever offered for an id the list does not contain.
        expect(screen.queryByRole('button', { name: 'Revoke device 9' })).not.toBeInTheDocument();

        // Once device 2 is revoked its control is gone, so a second revoke of
        // that (now non-listed) id cannot even be attempted from the UI.
        fireEvent.click(screen.getByRole('button', { name: 'Revoke device 2' }));
        expect(screen.queryByRole('button', { name: 'Revoke device 2' })).not.toBeInTheDocument();

        // Exactly one removal reached the live session — for the listed id
        // only; no stray revocation was forwarded for an unknown id.
        expect(vi.mocked(fanout_remove_device)).toHaveBeenCalledTimes(1);
        expect(vi.mocked(fanout_remove_device)).toHaveBeenCalledWith(expect.anything(), 2);

        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        await sendAndWait(PEER_ID, BODY);

        // The surviving session is undisturbed: both survivors receive.
        expect(sentTo().sort()).toEqual([`${PEER_ID}:1`, `${PEER_ID}:3`]);
    });

    test('revoking every listed device leaves a working send on the legacy single-recipient path', async () => {
        await renderApp(list(7, [makeDevice(1), makeDevice(2)]));
        await openLinkedDevices();

        fireEvent.click(screen.getByRole('button', { name: 'Revoke device 1' }));
        fireEvent.click(screen.getByRole('button', { name: 'Revoke device 2' }));

        expect(screen.getByText('No linked devices.')).toBeInTheDocument();
        expect(vi.mocked(fanout_remove_device)).toHaveBeenCalledTimes(2);

        fireEvent.click(screen.getByRole('button', { name: 'Direct' }));
        await sendAndWait(PEER_ID, BODY);

        // An empty list falls back to exactly the legacy behaviour.
        expect(sentTo()).toEqual([PEER_ID]);
    });
});