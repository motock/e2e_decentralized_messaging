/** @vitest-environment jsdom */
/**
 * MF-10: revoking the pending device from the link send-failure state.
 *
 * MF-3 keeps the successful `BuildAndPublishLinkedListResult` in `pendingSend`
 * when `sendLinkResponse` fails, because the list it published (version v+1)
 * already contains the new device. The user's other way out of that state is to
 * revoke the device that never received its response.
 *
 * The revoke MUST build on `pendingSend.signedListBytes` (v+1) and sign v+2.
 * App's own held list is still the PRE-link list (v) — the publish happened
 * inside DeviceLinking — so routing this through App's `handleRevokeDevice`
 * would verify v, re-sign v+1 and collide with the already-published v+1
 * (a rollback / version reuse). The fresh v+2 bytes therefore go back to App
 * through the dedicated `onOwnListPublished` callback.
 *
 * Covered here:
 *  - positive: the revoke control appears beside "Retry send", calls
 *    `revokeDevice` with the built v+1 bytes and the new device's id, publishes
 *    v+2 without the new device, clears `pendingSend` and hands the fresh
 *    bytes/version to the caller;
 *  - negative: a failed revoke keeps `pendingSend` and the v+1 list untouched,
 *    publishes nothing further and shows a static error;
 *  - negative: device 0 (the primary) is never handed to `revokeDevice`;
 *  - negative: without `onOwnListPublished` the screen fails closed — it does
 *    not publish a list App could never learn about;
 *  - the copy is non-sensitive (no key bytes, link key or list bytes in the DOM
 *    or on the console).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
/** The v+1 list the primary published before the send failed. */
const SIGNED_LIST = new Uint8Array([0x99, 0x88, 0x77, 0x66]);
/** The v+2 list `revokeDevice` returns (the new device dropped). */
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

function buildResult(deviceId: number): BuildAndPublishLinkedListResult {
    return {
        version: HELD_LIST_VERSION + 1,
        deviceId,
        signedListBytes: SIGNED_LIST,
        newDeviceIdentityKey: NEW_DEVICE_IDENTITY_KEY,
        safetyNumber: SAFETY_NUMBER,
        linkKey: LINK_KEY,
        newDeviceBundle: NEW_DEVICE_BUNDLE,
    };
}

const BUILD_RESULT = buildResult(ASSIGNED_DEVICE_ID);

/** The list the primary holds after the revoke: device 0 only. */
const REVOKED_DEVICES: DeviceListEntry[] = [
    { deviceId: 0, identityKey: LOCAL_KEY, bundleBytes: PRIMARY_BUNDLE },
];

const REVOKE_RESULT = {
    signedListBytes: REVOKED_LIST,
    deviceList: { version: HELD_LIST_VERSION + 2, devices: REVOKED_DEVICES },
};

/** The exact arguments the screen must hand `revokeDevice`. */
const EXPECTED_REVOKE_ARGS = {
    currentListBytes: SIGNED_LIST,
    primaryIdentityHandle: identityHandle,
    deviceId: ASSIGNED_DEVICE_ID,
    accountHandle: ACCOUNT_HANDLE,
    transport,
};

function renderPrimary(
    gate: StorageGate,
    onOwnListPublished?: (bytes: Uint8Array, version: number, devices: DeviceListEntry[]) => void,
) {
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
    onOwnListPublished?: (bytes: Uint8Array, version: number, devices: DeviceListEntry[]) => void,
): Promise<void> {
    sendMock.mockRejectedValueOnce(new Error('relay: send failed'));
    renderPrimary(gate, onOwnListPublished);
    await enterLinkingCode();
    await screen.findByText('Retry send');
}

beforeEach(() => {
    vi.clearAllMocks();
    buildMock.mockResolvedValue(BUILD_RESULT);
    sendMock.mockResolvedValue(undefined);
    revokeMock.mockResolvedValue(REVOKE_RESULT);
});

afterEach(() => {
    cleanup();
});

// ---------------------------------------------------------------------------
// Positive: revoke the pending device
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: success', () => {
    it('offers the revoke beside the retry and revokes from the published v+1 list', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        await failTheSend(gate, onOwnListPublished);

        // Both ways out of the send-failure state are offered.
        expect(screen.getByText('Retry send')).toBeTruthy();
        const revoke = screen.getByText('Revoke pending device');

        fireEvent.click(revoke);

        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(1));

        // Built on the list the primary actually published (v+1), not App's
        // stale pre-link list, and never on device 0.
        expect(revokeMock.mock.calls[0][0]).toEqual(EXPECTED_REVOKE_ARGS);
        expect(revokeMock.mock.calls[0][0].currentListBytes).toBe(SIGNED_LIST);
        expect(revokeMock.mock.calls[0][0].deviceId).toBe(ASSIGNED_DEVICE_ID);

        // The fresh v+2 bytes/version go back to the caller in one step.
        await waitFor(() => expect(onOwnListPublished).toHaveBeenCalledTimes(1));
        expect(onOwnListPublished).toHaveBeenCalledWith(
            REVOKED_LIST,
            HELD_LIST_VERSION + 2,
            REVOKED_DEVICES,
        );

        // The pending send is gone and the outcome is stated.
        await waitFor(() => expect(screen.queryByText('Retry send')).toBeNull());
        expect(screen.getByRole('status').textContent).toContain('revoked');
        // Nothing was persisted and the link never completed.
        expect(gate.put).not.toHaveBeenCalled();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
        // Exactly one publish: the revoke itself. No re-send, no re-build.
        expect(sendMock).toHaveBeenCalledTimes(1);
        expect(buildMock).toHaveBeenCalledTimes(1);
    });

    it('keeps the revoke copy free of key material and list bytes', async () => {
        const gate = makeStorageGate();
        await failTheSend(gate, vi.fn());

        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(1));

        const text = document.body.textContent ?? '';
        expect(text).not.toContain(LINK_KEY);
        expect(text).not.toContain(QR_PAYLOAD);
        expect(text).not.toContain(SAFETY_NUMBER);
        expect(text).not.toContain('05'.repeat(33));
        expect(text).not.toContain('99887766');
        expect(text).not.toContain('55443322');
    });
});

// ---------------------------------------------------------------------------
// Negative: a failed revoke changes nothing
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: failure', () => {
    it('keeps the pending send and the published list, and shows a static error', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        revokeMock.mockRejectedValueOnce(new Error('relay: publish failed'));

        await failTheSend(gate, onOwnListPublished);

        fireEvent.click(screen.getByText('Revoke pending device'));
        await waitFor(() => expect(revokeMock).toHaveBeenCalledTimes(1));

        // Fail closed: nothing handed back, nothing persisted, no second publish.
        expect(onOwnListPublished).not.toHaveBeenCalled();
        expect(revokeMock).toHaveBeenCalledTimes(1);
        expect(gate.put).not.toHaveBeenCalled();

        // The user can still retry the send: the v+1 list is untouched.
        expect(screen.getByText('Retry send')).toBeTruthy();
        const alert = screen.getByRole('alert');
        expect(alert.textContent).toBeTruthy();
        // The thrown message must never reach the UI.
        expect(alert.textContent).not.toContain('relay: publish failed');
        expect(alert.textContent).not.toContain('99887766');
    });
});

// ---------------------------------------------------------------------------
// Negative: device 0 is never revoked
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: primary is never revoked', () => {
    it('refuses to hand device 0 to revokeDevice', async () => {
        const gate = makeStorageGate();
        const onOwnListPublished = vi.fn();
        buildMock.mockResolvedValue(buildResult(0));

        await failTheSend(gate, onOwnListPublished);

        fireEvent.click(screen.getByText('Revoke pending device'));

        await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
        expect(revokeMock).not.toHaveBeenCalled();
        expect(onOwnListPublished).not.toHaveBeenCalled();
        // The pending send is still there, so the user can retry instead.
        expect(screen.getByText('Retry send')).toBeTruthy();
    });
});

// ---------------------------------------------------------------------------
// Negative: no callback means no publish
// ---------------------------------------------------------------------------

describe('DeviceLinking pending-device revoke: no callback', () => {
    it('fails closed instead of publishing a list the caller cannot learn about', async () => {
        const gate = makeStorageGate();
        await failTheSend(gate, undefined);

        fireEvent.click(screen.getByText('Revoke pending device'));

        await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
        expect(revokeMock).not.toHaveBeenCalled();
        expect(screen.getByText('Retry send')).toBeTruthy();
    });
});
