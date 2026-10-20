/** @vitest-environment jsdom */
/**
 * MD-16: the device-linking screen wired to the real handshake and to
 * post-confirmation persistence.
 *
 * The screen keeps its legacy local-only behaviour when no handshake props are
 * supplied (covered by `device_linking_ui.test.tsx` and
 * `device_linking_safety_number.test.tsx`, which must keep passing unchanged).
 * These tests cover the wired path:
 *
 *  - display mode (this device is the new device): `beginLinkRequest` publishes
 *    the bundle and yields the QR payload, then the screen polls
 *    `awaitLinkResponse` and re-verifies with `verifyLinkResponse` (MD-14)
 *    before showing the safety number;
 *  - scan mode (this device is the primary): `buildAndPublishLinkedList` is
 *    called with the caller's `heldListVersion` (the §8.4 freshness guard must
 *    never be silently disabled) and `sendLinkResponse` is called exactly once
 *    with the REQUIRED `expectedNewDeviceIdentityKey` from the build result;
 *  - confirmation persists the account device list exactly once through
 *    `StorageGate.put('identity', 'account-device-list', ...)` — never
 *    localStorage, never before the safety number is confirmed;
 *  - negative: a handshake error never persists, a verification mismatch never
 *    reaches `linked`, a missing `heldListVersion` fails closed without
 *    publishing, and no key bytes reach the console or the DOM.
 *
 * `link_primary` and `link_new_device` are mocked so the tests assert the exact
 * arguments the screen hands the handshake, and so a failure can be injected at
 * a precise step. The real `device_linking` state machine and wasm init are
 * left in place.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from '../src/relay_transport';
import type { StorageGate } from '../src/storage';
import type { BuildAndPublishLinkedListResult } from '../src/link_primary';
import type { LinkResponse, VerifiedLinkResponse } from '../src/link_new_device';

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
import { beginLinkRequest, awaitLinkResponse, verifyLinkResponse } from '../src/link_new_device';
import { DeviceLinking } from '../src/DeviceLinking';

const buildMock = vi.mocked(buildAndPublishLinkedList);
const sendMock = vi.mocked(sendLinkResponse);
const beginMock = vi.mocked(beginLinkRequest);
const awaitMock = vi.mocked(awaitLinkResponse);
const verifyMock = vi.mocked(verifyLinkResponse);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** This device's 33-byte identity public key (0x05 type tag + 32 bytes). */
const LOCAL_KEY = new Uint8Array(33).fill(0x05);
/** The primary's private key bytes — must never reach the DOM or the console. */
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

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64');
}

const identityHandle = {
    public_bytes: () => LOCAL_KEY,
    private_bytes: () => PRIVATE_KEY,
} as unknown as IdentityHandle;

const receiverSession = { id: 'receiver-session-fixture' } as unknown as SessionHandle;

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
};

const LINK_RESPONSE: LinkResponse = {
    accountHandle: ACCOUNT_HANDLE,
    deviceId: ASSIGNED_DEVICE_ID,
    primaryPublicKey: new Uint8Array(33).fill(0x09),
    signedListBytes: SIGNED_LIST,
};

const VERIFIED_RESPONSE: VerifiedLinkResponse = {
    accountHandle: ACCOUNT_HANDLE,
    deviceId: ASSIGNED_DEVICE_ID,
    primaryKey: LINK_RESPONSE.primaryPublicKey,
    version: HELD_LIST_VERSION + 1,
    deviceList: { version: HELD_LIST_VERSION + 1, devices: [] },
    safetyNumber: SAFETY_NUMBER,
};

/** A promise the test settles explicitly, so a mid-flow render is observable. */
function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((res) => {
        resolve = res;
    });
    return { promise, resolve };
}

beforeEach(() => {
    vi.clearAllMocks();
    beginMock.mockResolvedValue({
        qrPayload: QR_PAYLOAD,
        linkKey: LINK_KEY,
        receiverSession,
        bundleBytes: NEW_DEVICE_BUNDLE,
    });
    awaitMock.mockResolvedValue(LINK_RESPONSE);
    verifyMock.mockReturnValue(VERIFIED_RESPONSE);
    buildMock.mockResolvedValue(BUILD_RESULT);
    sendMock.mockResolvedValue(undefined);
});

afterEach(() => {
    cleanup();
});

// ---------------------------------------------------------------------------
// Display mode — this device is the new device
// ---------------------------------------------------------------------------

describe('DeviceLinking handshake: display mode (new device)', () => {
    it('publishes the link request and renders the QR code', async () => {
        const gate = makeStorageGate();
        // Hold the response so the QR stays on screen while we assert.
        const pending = deferred<LinkResponse>();
        awaitMock.mockReturnValue(pending.promise);

        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                receiverSession={receiverSession}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
            />,
        );

        fireEvent.click(await screen.findByText('Show QR code (this device)'));

        await waitFor(() => {
            expect(beginMock).toHaveBeenCalledWith(transport, identityHandle);
        });
        await waitFor(() => {
            expect(screen.getByRole('img', { name: 'Device linking QR code' })).toBeTruthy();
        });
        expect(awaitMock).toHaveBeenCalledWith(
            expect.objectContaining({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
                newDevicePublicKey: LOCAL_KEY,
            }),
        );
        // Nothing is persisted before the safety number is confirmed.
        expect(gate.put).not.toHaveBeenCalled();
    });

    it('shows the verified safety number and persists exactly once on confirmation', async () => {
        const gate = makeStorageGate();

        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                receiverSession={receiverSession}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
            />,
        );

        fireEvent.click(await screen.findByText('Show QR code (this device)'));

        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number').textContent).toBe(
                FORMATTED_SAFETY_NUMBER,
            );
        });
        expect(verifyMock).toHaveBeenCalledWith({
            response: LINK_RESPONSE,
            expectedDeviceId: ASSIGNED_DEVICE_ID,
            localPublicKey: LOCAL_KEY,
        });
        expect(gate.put).not.toHaveBeenCalled();

        fireEvent.click(screen.getByLabelText('Safety number matches on both devices'));
        const authorize = screen.getByText('Authorize device');
        fireEvent.click(authorize);
        fireEvent.click(authorize);

        await waitFor(() => {
            expect(screen.getByText('Device linked successfully!')).toBeTruthy();
        });
        expect(gate.put).toHaveBeenCalledTimes(1);
        expect(gate.put).toHaveBeenCalledWith('identity', 'account-device-list', {
            accountHandle: ACCOUNT_HANDLE,
            deviceId: ASSIGNED_DEVICE_ID,
            signedListBytesBase64: toBase64(SIGNED_LIST),
        });
    });
});

// ---------------------------------------------------------------------------
// Scan mode — this device is the primary
// ---------------------------------------------------------------------------

describe('DeviceLinking handshake: scan mode (primary)', () => {
    function renderPrimary(heldListVersion: number | undefined) {
        return render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                storageGate={makeStorageGate()}
                accountHandle={ACCOUNT_HANDLE}
                primaryBundleBytes={PRIMARY_BUNDLE}
                currentListBytes={CURRENT_LIST}
                heldListVersion={heldListVersion}
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

    it('builds with the supplied heldListVersion and sends one bound response', async () => {
        renderPrimary(HELD_LIST_VERSION);
        await enterLinkingCode();

        await waitFor(() => {
            expect(buildMock).toHaveBeenCalledWith({
                transport,
                qrPayload: QR_PAYLOAD,
                primaryIdentityHandle: identityHandle,
                primaryBundleBytes: PRIMARY_BUNDLE,
                currentListBytes: CURRENT_LIST,
                heldVersion: HELD_LIST_VERSION,
                accountHandle: ACCOUNT_HANDLE,
            });
        });

        await waitFor(() => {
            expect(sendMock).toHaveBeenCalledTimes(1);
        });
        expect(sendMock).toHaveBeenCalledWith({
            transport,
            linkKey: BUILD_RESULT.linkKey,
            newDeviceBundle: BUILD_RESULT.newDeviceBundle,
            expectedNewDeviceIdentityKey: BUILD_RESULT.newDeviceIdentityKey,
            primaryIdentityHandle: identityHandle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: BUILD_RESULT.deviceId,
            signedListBytes: BUILD_RESULT.signedListBytes,
        });

        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number').textContent).toBe(
                FORMATTED_SAFETY_NUMBER,
            );
        });
    });

    it('persists the published list exactly once after confirmation', async () => {
        const gate = makeStorageGate();
        render(
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
        await enterLinkingCode();

        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number')).toBeTruthy();
        });
        expect(gate.put).not.toHaveBeenCalled();

        fireEvent.click(screen.getByLabelText('Safety number matches on both devices'));
        const authorize = screen.getByText('Authorize device');
        fireEvent.click(authorize);
        fireEvent.click(authorize);

        await waitFor(() => {
            expect(screen.getByText('Device linked successfully!')).toBeTruthy();
        });
        expect(gate.put).toHaveBeenCalledTimes(1);
        expect(gate.put).toHaveBeenCalledWith('identity', 'account-device-list', {
            accountHandle: ACCOUNT_HANDLE,
            // The primary is device 0 in its own signed list.
            deviceId: 0,
            signedListBytesBase64: toBase64(SIGNED_LIST),
        });
    });

    it('fails closed without publishing when heldListVersion is not supplied', async () => {
        const gate = makeStorageGate();
        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
                primaryBundleBytes={PRIMARY_BUNDLE}
                currentListBytes={CURRENT_LIST}
            />,
        );
        await enterLinkingCode();

        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeTruthy();
        });
        expect(buildMock).not.toHaveBeenCalled();
        expect(sendMock).not.toHaveBeenCalled();
        expect(gate.put).not.toHaveBeenCalled();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
    });

    it('never persists when the freshness guard rejects a stale version', async () => {
        const gate = makeStorageGate();
        buildMock.mockRejectedValue(new Error('device list: version is older than the held version'));
        render(
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
        await enterLinkingCode();

        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeTruthy();
        });
        expect(sendMock).not.toHaveBeenCalled();
        expect(gate.put).not.toHaveBeenCalled();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// Negative: verification mismatch and key hygiene
// ---------------------------------------------------------------------------

describe('DeviceLinking handshake: fail closed', () => {
    it('never reaches linked or persists when verification rejects the response', async () => {
        const gate = makeStorageGate();
        verifyMock.mockImplementation(() => {
            throw new Error('link response: device list does not contain this device');
        });

        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                receiverSession={receiverSession}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
            />,
        );

        fireEvent.click(await screen.findByText('Show QR code (this device)'));

        await waitFor(() => {
            expect(screen.getByRole('alert')).toBeTruthy();
        });
        expect(screen.queryByTestId('link-safety-number')).toBeNull();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
        expect(gate.put).not.toHaveBeenCalled();
    });

    it('ignores a response that arrives after the user cancelled', async () => {
        const gate = makeStorageGate();
        const pending = deferred<LinkResponse>();
        awaitMock.mockReturnValue(pending.promise);

        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                receiverSession={receiverSession}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
            />,
        );

        fireEvent.click(await screen.findByText('Show QR code (this device)'));
        await waitFor(() => {
            expect(screen.getByRole('img', { name: 'Device linking QR code' })).toBeTruthy();
        });

        fireEvent.click(screen.getByText('Cancel'));
        pending.resolve(LINK_RESPONSE);

        await waitFor(() => {
            expect(screen.getByText('Show QR code (this device)')).toBeTruthy();
        });
        expect(screen.queryByTestId('link-safety-number')).toBeNull();
        expect(screen.queryByText('Device linked successfully!')).toBeNull();
        expect(gate.put).not.toHaveBeenCalled();
    });

    it('keeps key bytes out of the console and the DOM', async () => {
        const gate = makeStorageGate();
        const log = vi.spyOn(console, 'log').mockImplementation(() => {});
        const error = vi.spyOn(console, 'error').mockImplementation(() => {});
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

        render(
            <DeviceLinking
                localIdentityKey={LOCAL_KEY}
                transport={transport}
                identityHandle={identityHandle}
                receiverSession={receiverSession}
                storageGate={gate}
                accountHandle={ACCOUNT_HANDLE}
            />,
        );

        fireEvent.click(await screen.findByText('Show QR code (this device)'));
        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number')).toBeTruthy();
        });

        const privateHex = toHex(PRIVATE_KEY);
        const signedListHex = toHex(SIGNED_LIST);
        const html = document.body.innerHTML;
        expect(html).not.toContain(privateHex);
        expect(html).not.toContain(signedListHex);

        const logged = [...log.mock.calls, ...error.mock.calls, ...warn.mock.calls]
            .flat()
            .map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg) ?? ''))
            .join(' ');
        expect(logged).not.toContain(privateHex);
        expect(logged).not.toContain(signedListHex);

        log.mockRestore();
        error.mockRestore();
        warn.mockRestore();
    });
});
