/** @vitest-environment jsdom */
/**
 * MF-3: recovering when the link response send fails *after* the device list
 * has been published.
 *
 * `handleScan` publishes the next signed list (which already contains the new
 * device) and only then sends the new device its encrypted response. If that
 * send throws, the list is already published: the new device is in it, but it
 * never learns its id or handle, and a re-scan is rejected by
 * `buildAndPublishLinkedList`'s duplicate-identity check. The screen must
 * therefore keep the successful build result and offer a bounded, user-driven
 * "Retry send" that re-sends the SAME result — no re-sign, no re-publish, no
 * new list version.
 *
 * Covered here:
 *  - positive: a send failure shows the retry affordance and a successful
 *    retry sends exactly one more envelope with the same payload, without
 *    calling `buildAndPublishLinkedList` again;
 *  - negative: a second send failure keeps the user pre-confirmation with
 *    nothing persisted and no `linked` state, and retrying never mints a
 *    second list version;
 *  - the failure copy is non-sensitive (no key bytes, link key or list bytes).
 *
 * `link_primary` and `link_new_device` are mocked so the tests can inject a
 * failure at the send step and assert the exact arguments handed to it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from '../src/relay_transport';
import type { StorageGate } from '../src/storage';
import type { BuildAndPublishLinkedListResult } from '../src/link_primary';

vi.mock('../src/link_primary', () => ({
    buildAndPublishLinkedList: vi.fn(),
    sendLinkResponse: vi.fn(),
}));

vi.mock('../src/link_new_device', () => ({
    beginLinkRequest: vi.fn(),
    awaitLinkResponse: vi.fn(),
    verifyLinkResponse: vi.fn(),
}));

import { buildAndPublishLinkedList, sendLinkResponse } from '../src/link_primary';
import { DeviceLinking } from '../src/DeviceLinking';

const buildMock = vi.mocked(buildAndPublishLinkedList);
const sendMock = vi.mocked(sendLinkResponse);

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
const HELD_LIST_VERSION = 7;
const ASSIGNED_DEVICE_ID = 3;
const SAFETY_NUMBER = '1234567890';
const FORMATTED_SAFETY_NUMBER = '12345 67890';

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

/** The exact arguments the screen must hand `sendLinkResponse`, unchanged on retry. */
const EXPECTED_SEND_ARGS = {
    transport,
    linkKey: LINK_KEY,
    newDeviceBundle: NEW_DEVICE_BUNDLE,
    expectedNewDeviceIdentityKey: NEW_DEVICE_IDENTITY_KEY,
    primaryIdentityHandle: identityHandle,
    accountHandle: ACCOUNT_HANDLE,
    deviceId: ASSIGNED_DEVICE_ID,
    signedListBytes: SIGNED_LIST,
};

function renderPrimary(gate: StorageGate) {
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

beforeEach(() => {
    vi.clearAllMocks();
    buildMock.mockResolvedValue(BUILD_RESULT);
    sendMock.mockResolvedValue(undefined);
});

afterEach(() => {
    cleanup();
});

// ---------------------------------------------------------------------------
// Positive: retry after a failed send
// ---------------------------------------------------------------------------

describe('DeviceLinking send recovery: retry after a failed send', () => {
    it('offers a retry and re-sends the same build result without re-publishing', async () => {
        const gate = makeStorageGate();
        sendMock.mockRejectedValueOnce(new Error('relay: send failed'));

        renderPrimary(gate);
        await enterLinkingCode();

        // The failure is surfaced with a retry affordance, not a dead end.
        const retry = await screen.findByText('Retry send');
        expect(screen.getByRole('alert')).toBeTruthy();
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(sendMock).toHaveBeenCalledTimes(1);
        expect(gate.put).not.toHaveBeenCalled();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();

        fireEvent.click(retry);

        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number').textContent).toBe(
                FORMATTED_SAFETY_NUMBER,
            );
        });

        // Exactly one more envelope, byte-identical to the first attempt.
        expect(sendMock).toHaveBeenCalledTimes(2);
        expect(sendMock.mock.calls[1][0]).toEqual(EXPECTED_SEND_ARGS);
        expect(sendMock.mock.calls[1][0]).toEqual(sendMock.mock.calls[0][0]);
        // No re-sign, no re-publish, no second list version.
        expect(buildMock).toHaveBeenCalledTimes(1);
        // Still pre-confirmation: nothing persisted, no `linked`.
        expect(gate.put).not.toHaveBeenCalled();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
    });

    it('keeps the failure copy free of key material and list bytes', async () => {
        const gate = makeStorageGate();
        sendMock.mockRejectedValueOnce(new Error('relay: send failed'));

        renderPrimary(gate);
        await enterLinkingCode();

        const alert = await screen.findByRole('alert');
        const text = alert.textContent ?? '';
        expect(text).not.toContain(LINK_KEY);
        expect(text).not.toContain(QR_PAYLOAD);
        expect(text).not.toContain('99887766');
        expect(text).not.toContain('05'.repeat(33));
    });
});

// ---------------------------------------------------------------------------
// Negative: a second failure keeps the user pre-confirmation
// ---------------------------------------------------------------------------

describe('DeviceLinking send recovery: repeated failure', () => {
    it('stays pre-confirmation with nothing persisted when the retry also fails', async () => {
        const gate = makeStorageGate();
        sendMock.mockRejectedValue(new Error('relay: send failed'));

        renderPrimary(gate);
        await enterLinkingCode();

        fireEvent.click(await screen.findByText('Retry send'));

        await waitFor(() => {
            expect(sendMock).toHaveBeenCalledTimes(2);
        });
        // The affordance survives a second failure so the user can try again.
        expect(await screen.findByText('Retry send')).toBeTruthy();
        expect(screen.getByRole('alert')).toBeTruthy();
        expect(screen.queryByTestId('link-safety-number')).toBeNull();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
        expect(gate.put).not.toHaveBeenCalled();
        // Retrying never mints a second list version.
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(sendMock.mock.calls[1][0]).toEqual(EXPECTED_SEND_ARGS);
    });

    it('does not publish a second list version across many retries', async () => {
        const gate = makeStorageGate();
        sendMock.mockRejectedValue(new Error('relay: send failed'));

        renderPrimary(gate);
        await enterLinkingCode();

        fireEvent.click(await screen.findByText('Retry send'));
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(2));
        fireEvent.click(await screen.findByText('Retry send'));
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(3));

        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(buildMock).toHaveBeenCalledWith(
            expect.objectContaining({ heldVersion: HELD_LIST_VERSION }),
        );
        expect(gate.put).not.toHaveBeenCalled();
    });
});
