/** @vitest-environment jsdom */
/**
 * MF-11: the link-send retry and the pending-device revoke are one-shot, and a
 * successful link does not retain the scanned linking code.
 *
 * MF-3's `handleRetrySend` and MF-10's `handleRevokePending` both guarded with
 * React *state* (`sending`, `revoking`). State is not updated synchronously, so
 * two clicks dispatched in the same tick both passed the guard: the retry sent
 * the link response twice, and the revoke called `revokeDevice` twice — the
 * second time against a list that no longer contains the device. The file
 * already uses a ref (`persistedRef`) for exactly this kind of one-shot
 * guarantee, so both guards get a ref mirror.
 *
 * MF-10 also called `onOwnListPublished` *inside* the try that maps any throw to
 * the static "device list is unchanged" copy. A caller callback that throws
 * after a successful revoke therefore reported a published v+2 as unchanged and
 * left `pendingSend` set.
 *
 * Covered here:
 *  - positive: two retry clicks in the same tick send exactly one response;
 *  - positive: two revoke clicks in the same tick call `revokeDevice` once;
 *  - positive: a callback that throws after a successful revoke neither shows
 *    the "unchanged" copy nor leaves the pending send set;
 *  - positive: after a successful link the scanned linking code is gone;
 *  - negative: a failed retry clears the guard, so a later click retries again;
 *  - negative: a genuine revoke failure still shows the static failure copy and
 *    keeps the pending send.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from '../src/relay_transport';
import type { StorageGate } from '../src/storage';
import type { BuildAndPublishLinkedListResult } from '../src/link_primary';
import type { DeviceListEntry } from '../src/Conversation';

vi.mock('../src/link_primary', () => ({
    buildAndPublishLinkedList: vi.fn(),
    sendLinkResponse: vi.fn(),
}));

vi.mock('../src/link_new_device', () => ({
    beginLinkRequest: vi.fn(),
    awaitLinkResponse: vi.fn(),
    verifyLinkResponse: vi.fn(),
}));

vi.mock('../src/revocation', () => ({
    revokeDevice: vi.fn(),
}));

import { buildAndPublishLinkedList, sendLinkResponse } from '../src/link_primary';
import { revokeDevice } from '../src/revocation';
import { DeviceLinking } from '../src/DeviceLinking';

const buildMock = vi.mocked(buildAndPublishLinkedList);
const sendMock = vi.mocked(sendLinkResponse);
const revokeMock = vi.mocked(revokeDevice);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** This device's 33-byte identity public key (0x05 type tag + 32 bytes). */
const LOCAL_KEY = new Uint8Array(33).fill(0x05);
const PRIVATE_KEY = new Uint8Array(32).fill(0x11);

const QR_PAYLOAD = '05a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f';
const LINK_KEY = 'link-key-fixture';
const ACCOUNT_HANDLE = 'account-handle-fixture';
const PRIMARY_BUNDLE = new Uint8Array([0x01, 0x02, 0x03]);
const CURRENT_LIST = new Uint8Array([0x0a, 0x0b]);
const NEW_DEVICE_BUNDLE = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const NEW_DEVICE_IDENTITY_KEY = new Uint8Array(33).fill(0x07);
const SIGNED_LIST = new Uint8Array([0x99, 0x88, 0x77, 0x66]);
const REVOKED_LIST = new Uint8Array([0x55, 0x44, 0x33, 0x22]);
const HELD_LIST_VERSION = 7;
const ASSIGNED_DEVICE_ID = 3;
const SAFETY_NUMBER = '1234567890';

const identityHandle = {
    public_bytes: () => LOCAL_KEY,
    private_bytes: () => PRIVATE_KEY,
} as unknown as IdentityHandle;

const transport = {
    publishPrekey: vi.fn(),
    lookupPrekey: vi.fn(),
    sendEnvelope: vi.fn(),
    publishDiscovery: vi.fn(),
    lookupDiscovery: vi.fn(),
} as unknown as RelayTransport;

function makeStorageGate(): StorageGate & { put: ReturnType<typeof vi.fn> } {
    return {
        put: vi.fn().mockResolvedValue(undefined),
        get: vi.fn().mockResolvedValue(null),
    } as unknown as StorageGate & { put: ReturnType<typeof vi.fn> };
}

const BUILD_RESULT: BuildAndPublishLinkedListResult = {
    version: HELD_LIST_VERSION + 1,
    deviceId: ASSIGNED_DEVICE_ID,
    signedListBytes: SIGNED_LIST,
    newDeviceIdentityKey: NEW_DEVICE_IDENTITY_KEY,
    safetyNumber: SAFETY_NUMBER,
    linkKey: LINK_KEY,
    newDeviceBundle: NEW_DEVICE_BUNDLE,
    devices: [
        { deviceId: 0, identityKey: LOCAL_KEY, bundleBytes: PRIMARY_BUNDLE },
        {
            deviceId: ASSIGNED_DEVICE_ID,
            identityKey: NEW_DEVICE_IDENTITY_KEY,
            bundleBytes: NEW_DEVICE_BUNDLE,
        },
    ],
};

/** The list the primary holds after the revoke: device 0 only. */
const REVOKED_DEVICES: DeviceListEntry[] = [
    { deviceId: 0, identityKey: LOCAL_KEY, bundleBytes: PRIMARY_BUNDLE },
];

const REVOKE_RESULT = {
    signedListBytes: REVOKED_LIST,
    deviceList: { version: HELD_LIST_VERSION + 2, devices: REVOKED_DEVICES },
};

type PublishCallback = (bytes: Uint8Array, version: number, devices: DeviceListEntry[]) => void;

function renderPrimary(gate: StorageGate, onOwnListPublished?: PublishCallback) {
    return render(
        <DeviceLinking
            localIdentityKey={LOCAL_KEY}
            transport={transport}
            identityHandle={identityHandle}
            storageGate={gate}
            accountHandle={ACCOUNT_HANDLE}
            primaryBundleBytes={PRIMARY_BUNDLE}
            currentListBytes={CURRENT_LIST}
            heldListVersion={HELD_LIST_VERSION}
            onOwnListPublished={onOwnListPublished}
        />,
    );
}

async function enterLinkingCode(): Promise<void> {
    fireEvent.click(await screen.findByText('Enter linking code (from other device)'));
    fireEvent.change(screen.getByLabelText('Linking code input'), {
        target: { value: QR_PAYLOAD },
    });
    fireEvent.click(screen.getByText('Continue'));
}

/** Drive the screen into MF-3's send-failure state. */
async function failTheSend(
    gate: StorageGate,
    onOwnListPublished?: PublishCallback,
): Promise<void> {
    sendMock.mockRejectedValueOnce(new Error('relay: send failed'));
    renderPrimary(gate, onOwnListPublished);
    await enterLinkingCode();
    await screen.findByText('Retry send');
}

beforeEach(() => {
    // reset (not clear): a leftover mockRejectedValueOnce from a prior test
    // must not be consumed by the next test's first send.
    vi.resetAllMocks();
    buildMock.mockResolvedValue(BUILD_RESULT);
    sendMock.mockResolvedValue(undefined);
    revokeMock.mockResolvedValue(REVOKE_RESULT);
});

afterEach(() => {
    cleanup();
});

// ---------------------------------------------------------------------------
// Positive: the retry send is one-shot
// ---------------------------------------------------------------------------

describe('DeviceLinking retry send: one-shot', () => {
    it('sends exactly one link response for two retry clicks in the same tick', async () => {
        const gate = makeStorageGate();
        await failTheSend(gate);
        expect(sendMock).toHaveBeenCalledTimes(1);

        // Hold the retry send open so the second click lands while the first is
        // still in flight — the same tick, before React can re-render the
        // control as disabled.
        let release!: () => void;
        sendMock.mockImplementationOnce(
            () =>
                new Promise<void>((resolve) => {
                    release = resolve;
                }),
        );

        const retry = screen.getByText('Retry send');
        await act(async () => {
            retry.click();
            retry.click();
        });

        // One failed first send plus exactly one retry.
        expect(sendMock).toHaveBeenCalledTimes(2);

        release();
        await waitFor(() => expect(screen.queryByText('Retry send')).toBeNull());
        expect(sendMock).toHaveBeenCalledTimes(2);
        expect(buildMock).toHaveBeenCalledTimes(1);
    });
});

// ---------------------------------------------------------------------------
// Positive: the pending-device revoke is one-shot
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: one-shot', () => {
    it('calls revokeDevice exactly once for two revoke clicks in the same tick', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        await failTheSend(gate, onOwnListPublished);

        let release!: () => void;
        revokeMock.mockImplementationOnce(
            () =>
                new Promise((resolve) => {
                    release = () => resolve(REVOKE_RESULT);
                }),
        );

        const revoke = screen.getByText('Revoke pending device');
        await act(async () => {
            revoke.click();
            revoke.click();
        });

        // A second entry would call revokeDevice against a list that no longer
        // contains the device.
        expect(revokeMock).toHaveBeenCalledTimes(1);

        release();
        await waitFor(() => expect(onOwnListPublished).toHaveBeenCalledTimes(1));
        expect(revokeMock).toHaveBeenCalledTimes(1);
        expect(onOwnListPublished).toHaveBeenCalledWith(
            REVOKED_LIST,
            HELD_LIST_VERSION + 2,
            REVOKED_DEVICES,
        );
    });
});

// ---------------------------------------------------------------------------
// Positive: a throwing publish callback cannot undo a successful revoke
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: throwing publish callback', () => {
    it('does not report the list as unchanged when onOwnListPublished throws', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn(() => {
            throw new Error('caller: state update failed');
        });
        await failTheSend(gate, onOwnListPublished);

        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(onOwnListPublished).toHaveBeenCalledTimes(1));

        // The revoke itself succeeded and v+2 is published: the screen must not
        // claim the device list is unchanged.
        expect(screen.queryByText(/device list is unchanged/i)).toBeNull();
        expect(screen.getByRole('status').textContent).toContain('revoked');
    });

    it('does not leave the pending send set when onOwnListPublished throws', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn(() => {
            throw new Error('caller: state update failed');
        });
        await failTheSend(gate, onOwnListPublished);

        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(onOwnListPublished).toHaveBeenCalledTimes(1));

        // The pending send is gone, so neither recovery control survives.
        expect(screen.queryByText('Retry send')).toBeNull();
        expect(screen.queryByText('Revoke pending device')).toBeNull();
        expect(gate.put).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// Positive: the scanned linking code is not retained after a successful link
// ---------------------------------------------------------------------------

describe('DeviceLinking linking-code retention', () => {
    it('does not retain the scanned linking code after a successful link', async () => {
        const gate = makeStorageGate();
        renderPrimary(gate);
        await enterLinkingCode();

        // The link response went out, so the screen moves to the confirming
        // phase and the scanned code must not survive anywhere in the DOM.
        await waitFor(() => expect(screen.getByTestId('link-safety-number')).toBeTruthy());
        expect(screen.queryByLabelText('Linking code input')).toBeNull();
        expect(document.body.textContent ?? '').not.toContain(QR_PAYLOAD);
    });
});

// ---------------------------------------------------------------------------
// Negative: a failed retry clears the guard so the user can retry again
// ---------------------------------------------------------------------------

describe('DeviceLinking retry send: guard is released on failure', () => {
    it('lets a later click retry again after a failed retry', async () => {
        const gate = makeStorageGate();
        await failTheSend(gate);
        expect(sendMock).toHaveBeenCalledTimes(1);

        // Second attempt fails too: the guard must be released in `finally`.
        sendMock.mockRejectedValueOnce(new Error('relay: send failed again'));
        fireEvent.click(screen.getByText('Retry send'));
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(2));
        expect(await screen.findByText('Retry send')).toBeTruthy();

        // Third attempt succeeds: the guard did not latch shut.
        fireEvent.click(screen.getByText('Retry send'));
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(3));
        await waitFor(() => expect(screen.queryByText('Retry send')).toBeNull());
        expect(screen.getByTestId('link-safety-number')).toBeTruthy();
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(gate.put).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// Negative: a genuine revoke failure still fails closed
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: genuine failure', () => {
    it('keeps the pending send and shows the static failure copy', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        await failTheSend(gate, onOwnListPublished);

        revokeMock.mockRejectedValueOnce(new Error('relay: publish failed'));
        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(1));

        expect(screen.getByRole('alert').textContent).toContain('device list is unchanged');
        // Only the link hand-off (v+1) ran; the failed revoke handed nothing back.
        expect(onOwnListPublished).toHaveBeenCalledTimes(1);
        expect(onOwnListPublished).toHaveBeenCalledWith(
            SIGNED_LIST,
            HELD_LIST_VERSION + 1,
            BUILD_RESULT.devices,
        );
        // The pending send survives so the user can still finish the link.
        expect(screen.getByText('Retry send')).toBeTruthy();
        expect(screen.getByText('Revoke pending device')).toBeTruthy();
        expect(gate.put).not.toHaveBeenCalled();
    });

    it('lets the user retry the revoke after a failed revoke', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        await failTheSend(gate, onOwnListPublished);

        revokeMock.mockRejectedValueOnce(new Error('relay: publish failed'));
        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(1));

        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(2));
        // Link hand-off (v+1), then the successful revoke hand-off (v+2).
        await waitFor(() => expect(onOwnListPublished).toHaveBeenCalledTimes(2));
        expect(onOwnListPublished).toHaveBeenNthCalledWith(
            1,
            SIGNED_LIST,
            HELD_LIST_VERSION + 1,
            BUILD_RESULT.devices,
        );
        expect(onOwnListPublished).toHaveBeenNthCalledWith(
            2,
            REVOKED_LIST,
            HELD_LIST_VERSION + 2,
            REVOKED_DEVICES,
        );
        expect(screen.queryByText('Revoke pending device')).toBeNull();
    });
});
