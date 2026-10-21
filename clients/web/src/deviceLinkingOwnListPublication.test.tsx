/** @vitest-environment jsdom */
/**
 * DL-1: every published device-list version is propagated back to the caller.
 *
 * The primary's scan path publishes a new signed list (version+1) from inside
 * the linking screen. Before DL-1 the caller's held own list stayed at the
 * PRE-link version, so the next publish was built on a stale base:
 *
 *   - a second link re-signed version+1 from the stale list and DROPPED the
 *     device linked a moment earlier;
 *   - a revoke after a link likewise signed version+1 from the stale base and
 *     could drop the just-linked device.
 *
 * CONTRACT pinned here. The harness mirrors App.tsx's own-list ownership
 * exactly: one `ownList` state plus an `ownListRef` mirror, `holdOwnList`
 * setting both in one step, `handleOwnListPublished` replacing the held list,
 * and `currentListBytes`/`heldListVersion` fed back from that same state. The
 * link view is a child that can be unmounted and remounted, because that is
 * what navigating away from and back to the linking screen does in the app —
 * App's own-list state survives, the screen's does not.
 *
 *  1. Linking A from a held version 7 `[O]` hands the caller version 8 `[O, A]`.
 *  2. Linking B afterwards builds on the held version-8 bytes and publishes
 *     version 9 `[O, A, B]` — A is not dropped.
 *  3. Linking A then revoking O uses the version-8 bytes as the revoke base and
 *     publishes version 9 `[A]`.
 *  4. A successful build records `build → onOwnListPublished → send`. A failed
 *     send still leaves version 8 held, and a later link of B builds on those
 *     version-8 bytes and publishes version 9 `[O, A, B]`. MF-3's retry does not
 *     rebuild or republish.
 *  5. Backward compatibility: a runtime scan without `onOwnListPublished`
 *     still builds and sends (the previous behaviour); the callback is simply
 *     not invoked, so the caller's held list is unchanged.
 *  6. Negative: a rejected build invokes neither the publication callback nor
 *     send, leaves the held list at version 7, and a later successful link
 *     still publishes version 8.
 *
 * `link_primary`, `link_new_device` and `revocation` are mocked so the exact
 * arguments the screen hands the handshake are observable and a failure can be
 * injected at a precise step. The mocked build is a faithful stand-in: it
 * appends the new device to the base list it is GIVEN and signs version+1, so a
 * stale base is visible as a repeated version and a dropped device.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from './relay_transport';
import type { StorageGate } from './storage';
import type { BuildAndPublishLinkedListResult } from './link_primary';
import type { DeviceListEntry } from './Conversation';

/**
 * The verification binding is the identity by default: the signed list the
 * mocked build returns is already in the `u64_le(version) || packed entries`
 * layout. Real signature checking is covered by the Rust core and by
 * `link_new_device_verify.test.ts`. The indirection lets a test make the
 * post-publish verification throw, which is the failure the scan path must
 * survive without discarding the already-published list.
 */
const verifyState = vi.hoisted(() => ({
    impl: (bytes: Uint8Array) => bytes,
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    verify_device_list: (bytes: Uint8Array) => verifyState.impl(bytes),
    sign_device_list: () => {
        throw new Error('not used by the own-list publication tests');
    },
}));

vi.mock('./wasm_init', () => ({ ensureWasmInit: async () => {} }));

vi.mock('./link_primary', () => ({
    buildAndPublishLinkedList: vi.fn(),
    sendLinkResponse: vi.fn(),
}));

vi.mock('./link_new_device', () => ({
    beginLinkRequest: vi.fn(),
    awaitLinkResponse: vi.fn(),
    verifyLinkResponse: vi.fn(),
}));

vi.mock('./revocation', () => ({ revokeDevice: vi.fn() }));

import { buildAndPublishLinkedList, sendLinkResponse } from './link_primary';
import { revokeDevice } from './revocation';
import { packEntries, splitVerified, toConversationDeviceList } from './discovery';
import { DeviceLinking } from './DeviceLinking';
import type { DeviceLinkingProps } from './useDeviceLinkingHandshake';

const buildMock = vi.mocked(buildAndPublishLinkedList);
const sendMock = vi.mocked(sendLinkResponse);
const revokeMock = vi.mocked(revokeDevice);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** This device's 33-byte identity public key (0x05 type tag + 32 bytes). */
const LOCAL_KEY = new Uint8Array(33).fill(0x05);
const PRIVATE_KEY = new Uint8Array(32).fill(0x11);

const ACCOUNT_HANDLE = 'account-handle-fixture';
const QR_PAYLOAD = '05a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f';
const LINK_KEY = 'link-key-fixture';
const SAFETY_NUMBER = '12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 1234';
const PRIMARY_BUNDLE = new Uint8Array([0x01, 0x02, 0x03]);

/** The version the caller holds before any link. */
const HELD_LIST_VERSION = 7;

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

function makeStorageGate(): StorageGate {
    return {
        put: vi.fn().mockResolvedValue(undefined),
        get: vi.fn().mockResolvedValue(null),
    } as unknown as StorageGate;
}

/** A device entry the packer accepts: 33-byte identity key, non-empty bundle. */
function device(deviceId: number, identityFill: number): DeviceListEntry {
    return {
        deviceId,
        identityKey: new Uint8Array(33).fill(identityFill),
        bundleBytes: new Uint8Array([identityFill, identityFill + 1]),
    };
}

/** Device 0 — the account's own identity, present in every list. */
const OWN_DEVICE = device(0, 0x05);
/** The first device linked in these tests. */
const DEVICE_A = device(1, 0x0a);
/** The second device linked in these tests. */
const DEVICE_B = device(2, 0x0b);

/** The caller's held own list, exactly as App.tsx holds it. */
interface HeldOwnList {
    version: number;
    bytes: Uint8Array;
    devices: DeviceListEntry[];
}

function heldList(version: number, devices: DeviceListEntry[]): HeldOwnList {
    return { version, bytes: packEntries(version, devices), devices };
}

/** Decode a signed list back into its version and devices. */
function decode(bytes: Uint8Array): { version: number; devices: DeviceListEntry[] } {
    const { version, packedEntries } = splitVerified(bytes);
    return { version, devices: toConversationDeviceList(version, packedEntries).devices };
}

function deviceIds(devices: DeviceListEntry[]): number[] {
    return devices.map((entry) => entry.deviceId);
}

// ---------------------------------------------------------------------------
// The caller harness — mirrors App.tsx's own-list ownership
// ---------------------------------------------------------------------------

interface HarnessProps {
    initial: HeldOwnList;
    /** Receives every held list, so assertions read what the caller holds. */
    heldRef: { current: HeldOwnList };
    /** Ordered side-effect log: 'build' | 'publish' | 'send'. */
    events: string[];
    /** False exercises the runtime fail-closed guard for a missing callback. */
    publish?: boolean;
    /** True makes the caller's own state update throw, after the publish. */
    publishThrows?: boolean;
    /** True makes only the FIRST hand-off throw (the retry succeeds). */
    publishThrowsOnce?: boolean;
}

interface LinkViewProps {
    ownList: HeldOwnList;
    onOwnListPublished: (bytes: Uint8Array, version: number, devices: DeviceListEntry[]) => void;
    onRevokeDevice: (deviceId: number) => void;
    publish: boolean;
}

/**
 * The linking screen as App renders it: `currentListBytes` and
 * `heldListVersion` come from the ONE held list, and the publication callback
 * is supplied only when the caller wired it (App: primary device only).
 */
function LinkView({ ownList, onOwnListPublished, onRevokeDevice, publish }: LinkViewProps) {
    const props: DeviceLinkingProps = {
        localIdentityKey: LOCAL_KEY,
        transport,
        identityHandle,
        storageGate: makeStorageGate(),
        accountHandle: ACCOUNT_HANDLE,
        primaryBundleBytes: PRIMARY_BUNDLE,
        currentListBytes: ownList.bytes,
        heldListVersion: ownList.version,
        deviceList: { version: ownList.version, devices: ownList.devices },
        onRevokeDevice,
        ...(publish ? { onOwnListPublished } : {}),
    };

    // Test-only type escape: force the callback to be absent at runtime so the
    // fail-closed guard is exercised. The production prop type is NOT weakened
    // to make this compile.
    const renderedProps = publish
        ? props
        : ({ ...props, onOwnListPublished: undefined } as unknown as DeviceLinkingProps);

    return <DeviceLinking {...renderedProps} />;
}

/**
 * A stand-in for App.tsx's own-list ownership. `ownList`/`ownListRef` are set
 * together by `holdOwnList`, so a publish that never reaches the caller is
 * visible as a stale base on the next build. The link view is keyed so the test
 * can unmount and remount it — App's state survives, the screen's does not.
 */
function Caller({
    initial,
    heldRef,
    events,
    publish = true,
    publishThrows = false,
    publishThrowsOnce = false,
}: HarnessProps) {
    const [ownList, setOwnList] = React.useState<HeldOwnList>(initial);
    const ownListRef = React.useRef<HeldOwnList>(initial);
    const [viewKey, setViewKey] = React.useState(0);
    const threwOnceRef = React.useRef(false);

    const holdOwnList = React.useCallback(
        (next: HeldOwnList) => {
            ownListRef.current = next;
            heldRef.current = next;
            setOwnList(next);
        },
        [heldRef],
    );

    const handleOwnListPublished = React.useCallback(
        (bytes: Uint8Array, version: number, devices: DeviceListEntry[]) => {
            events.push('publish');
            // A caller whose own state update throws must not be able to undo
            // the publish: the scan path keeps the pending send and surfaces a
            // distinct error instead of falling into the build-failure catch.
            if (publishThrows || (publishThrowsOnce && !threwOnceRef.current)) {
                if (publishThrowsOnce) threwOnceRef.current = true;
                throw new Error('caller state update failed');
            }
            holdOwnList({ version, bytes, devices });
        },
        [events, holdOwnList, publishThrows, publishThrowsOnce],
    );

    // App.tsx's `handleRevokeDevice` for a held own list: re-sign and re-publish
    // from the bytes the caller holds, then hold the returned list.
    const handleRevokeDevice = React.useCallback(
        async (deviceId: number) => {
            const held = ownListRef.current;
            const { signedListBytes, deviceList: next } = await revokeDevice({
                currentListBytes: held.bytes,
                primaryIdentityHandle: identityHandle,
                deviceId,
                accountHandle: ACCOUNT_HANDLE,
                transport,
            });
            holdOwnList({ version: next.version, bytes: signedListBytes, devices: next.devices });
        },
        [holdOwnList],
    );

    return (
        <>
            <div data-testid="held-version">{ownList.version}</div>
            <div data-testid="held-devices">{deviceIds(ownList.devices).join(',')}</div>
            <button type="button" onClick={() => setViewKey((key) => key + 1)}>
                Leave link view
            </button>
            <LinkView
                key={viewKey}
                ownList={ownList}
                onOwnListPublished={handleOwnListPublished}
                onRevokeDevice={handleRevokeDevice}
                publish={publish}
            />
        </>
    );
}

// ---------------------------------------------------------------------------
// Driving the scan path
// ---------------------------------------------------------------------------

async function enterLinkingCode(): Promise<void> {
    fireEvent.click(await screen.findByText('Enter linking code (from other device)'));
    fireEvent.change(screen.getByLabelText('Linking code input'), {
        target: { value: QR_PAYLOAD },
    });
    fireEvent.click(screen.getByText('Continue'));
}

/** Navigate away from the linking screen and back: App's held list survives. */
async function leaveLinkView(): Promise<void> {
    fireEvent.click(screen.getByText('Leave link view'));
    await screen.findByText('Enter linking code (from other device)');
}

/** The device the next mocked build will append. */
let nextDevice: DeviceListEntry;

/** The ordered side-effect log, shared with the harness. */
let events: string[] = [];

beforeEach(() => {
    vi.clearAllMocks();
    nextDevice = DEVICE_A;
    events = [];
    verifyState.impl = (bytes: Uint8Array) => bytes;

    // A faithful stand-in for the real build: append the new device to the base
    // list it is GIVEN and sign version+1. A stale base therefore shows up as a
    // repeated version and a dropped device.
    buildMock.mockImplementation(async (args) => {
        events.push('build');
        const base = args.currentListBytes ? decode(args.currentListBytes) : null;
        const version = (base ? base.version : 0) + 1;
        const devices = [...(base ? base.devices : []), nextDevice];
        return {
            version,
            deviceId: nextDevice.deviceId,
            signedListBytes: packEntries(version, devices),
            newDeviceIdentityKey: nextDevice.identityKey,
            safetyNumber: SAFETY_NUMBER,
            linkKey: LINK_KEY,
            newDeviceBundle: nextDevice.bundleBytes,
            devices,
        } satisfies BuildAndPublishLinkedListResult;
    });

    sendMock.mockImplementation(async () => {
        events.push('send');
    });
});

afterEach(() => {
    cleanup();
});

function renderCaller(
    options: { publish?: boolean; publishThrows?: boolean; publishThrowsOnce?: boolean } = {},
) {
    const heldRef = { current: heldList(HELD_LIST_VERSION, [OWN_DEVICE]) };
    render(
        <Caller
            initial={heldRef.current}
            heldRef={heldRef}
            events={events}
            publish={options.publish}
            publishThrows={options.publishThrows}
            publishThrowsOnce={options.publishThrowsOnce}
        />,
    );
    return { heldRef, events };
}

// ---------------------------------------------------------------------------
// 1 + 2: the published version reaches the caller, so the next link builds on it
// ---------------------------------------------------------------------------

describe('DL-1: the caller holds every published version', () => {
    it('hands the caller version 8 containing [O, A] after linking A', async () => {
        const { heldRef } = renderCaller();

        await enterLinkingCode();

        await waitFor(() => {
            expect(heldRef.current.version).toBe(HELD_LIST_VERSION + 1);
        });
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1]);
        expect(decode(heldRef.current.bytes)).toEqual({
            version: HELD_LIST_VERSION + 1,
            devices: heldRef.current.devices,
        });
        expect(screen.getByTestId('held-version').textContent).toBe('8');
        expect(screen.getByTestId('held-devices').textContent).toBe('0,1');
    });

    it('builds the second link on the held version-8 bytes and publishes version 9 [O, A, B]', async () => {
        const { heldRef } = renderCaller();

        await enterLinkingCode();
        await waitFor(() => {
            expect(heldRef.current.version).toBe(8);
        });
        const version8Bytes = heldRef.current.bytes;

        await leaveLinkView();
        nextDevice = DEVICE_B;
        await enterLinkingCode();

        await waitFor(() => {
            expect(heldRef.current.version).toBe(9);
        });
        // The second build was handed the exact bytes the caller holds — not the
        // stale version-7 list.
        expect(buildMock).toHaveBeenCalledTimes(2);
        expect(buildMock.mock.calls[1][0].currentListBytes).toBe(version8Bytes);
        expect(buildMock.mock.calls[1][0].heldVersion).toBe(8);
        // A is still there: the first linked device was not dropped.
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1, 2]);
        expect(screen.getByTestId('held-devices').textContent).toBe('0,1,2');
    });
});

// ---------------------------------------------------------------------------
// 3: a revoke after a link uses the published version as its base
// ---------------------------------------------------------------------------

describe('DL-1: a revoke after a link builds on the published version', () => {
    it('revokes O from the held version-8 bytes and publishes version 9 [A]', async () => {
        const { heldRef } = renderCaller();

        await enterLinkingCode();
        await waitFor(() => {
            expect(heldRef.current.version).toBe(8);
        });
        const version8Bytes = heldRef.current.bytes;

        // `revokeDevice` is mocked: what is under test is the BASE the caller
        // hands it, not the core's own signing.
        revokeMock.mockResolvedValue({
            signedListBytes: packEntries(9, [DEVICE_A]),
            deviceList: { version: 9, devices: [DEVICE_A] },
        });

        fireEvent.click(await screen.findByText('Revoke device 0'));

        await waitFor(() => {
            expect(revokeMock).toHaveBeenCalledTimes(1);
        });
        // The revoke base is the list the link just published, so the device
        // linked a moment earlier survives.
        expect(revokeMock.mock.calls[0][0].currentListBytes).toBe(version8Bytes);
        expect(revokeMock.mock.calls[0][0].deviceId).toBe(0);

        await waitFor(() => {
            expect(heldRef.current.version).toBe(9);
        });
        expect(deviceIds(heldRef.current.devices)).toEqual([1]);
    });
});

// ---------------------------------------------------------------------------
// 4: publication happens after the build and before the send
// ---------------------------------------------------------------------------

describe('DL-1: publication ordering', () => {
    it('records build → onOwnListPublished → send', async () => {
        const { events: log } = renderCaller();

        await enterLinkingCode();

        await waitFor(() => {
            expect(log).toContain('send');
        });
        expect(log).toEqual(['build', 'publish', 'send']);
    });

    it('keeps version 8 held when the send fails, and the next link builds on it', async () => {
        const { heldRef, events: log } = renderCaller();
        sendMock.mockRejectedValueOnce(new Error('relay unavailable'));

        await enterLinkingCode();

        // The send failed, but the list was already published: the caller must
        // hold it, otherwise the next publish re-signs version 8 and drops A.
        await waitFor(() => {
            expect(screen.getByText('Retry send')).toBeTruthy();
        });
        expect(heldRef.current.version).toBe(8);
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1]);
        expect(log).toEqual(['build', 'publish']);

        // MF-3 retry: the same build result is re-sent — no rebuild, no
        // republish, so the caller is not handed a second version.
        fireEvent.click(screen.getByText('Retry send'));
        await waitFor(() => {
            expect(log).toEqual(['build', 'publish', 'send']);
        });
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(heldRef.current.version).toBe(8);

        // A later link of B builds on the held version-8 bytes.
        await leaveLinkView();
        nextDevice = DEVICE_B;
        await enterLinkingCode();

        await waitFor(() => {
            expect(heldRef.current.version).toBe(9);
        });
        expect(buildMock.mock.calls[1][0].heldVersion).toBe(8);
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1, 2]);
    });
});

// ---------------------------------------------------------------------------
// 5 + 6: negative paths publish nothing and leave the held list untouched
// ---------------------------------------------------------------------------

describe('DL-1: nothing is published when the scan path cannot publish safely', () => {
    it('still builds and sends when no callback is wired (backward compatible)', async () => {
        const { heldRef, events: log } = renderCaller({ publish: false });

        await enterLinkingCode();

        await waitFor(() => {
            expect(sendMock).toHaveBeenCalledTimes(1);
        });
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(screen.queryByText(/not configured/)).toBeNull();
        // No callback: the caller's held list is untouched by this screen.
        expect(log).toEqual(['build', 'send']);
        expect(heldRef.current.version).toBe(HELD_LIST_VERSION);
        expect(deviceIds(heldRef.current.devices)).toEqual([0]);
        expect(screen.getByTestId('held-version').textContent).toBe('7');
    });

    it('publishes nothing when the build rejects, and a later link still publishes version 8', async () => {
        const { heldRef, events: log } = renderCaller();
        buildMock.mockRejectedValueOnce(new Error('device list: stale held version'));

        await enterLinkingCode();

        await waitFor(() => {
            expect(buildMock).toHaveBeenCalledTimes(1);
        });
        await waitFor(() => {
            expect(screen.getByText('Enter linking code (from other device)')).toBeTruthy();
        });
        // The rejected build published nothing: no callback, no send.
        expect(log).not.toContain('publish');
        expect(log).not.toContain('send');
        expect(sendMock).not.toHaveBeenCalled();
        expect(heldRef.current.version).toBe(HELD_LIST_VERSION);
        expect(deviceIds(heldRef.current.devices)).toEqual([0]);

        // The failed build left no partial state behind: the next link publishes
        // version 8 from the still-held version-7 list.
        await enterLinkingCode();

        await waitFor(() => {
            expect(heldRef.current.version).toBe(8);
        });
        expect(buildMock.mock.calls[1][0].heldVersion).toBe(HELD_LIST_VERSION);
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1]);
    });

    it('keeps the published list and the pending send when the caller callback throws', async () => {
        const { heldRef, events: log } = renderCaller({ publishThrows: true });

        await enterLinkingCode();

        // The caller's own state update failed, but v+1 is already published:
        // the pending send is retained and the recovery controls stay available.
        await waitFor(() => {
            expect(screen.getByText('Retry send')).toBeTruthy();
        });
        expect(screen.getByText('Revoke pending device')).toBeTruthy();
        expect(screen.getByText(/could not record the new version/)).toBeTruthy();

        // The callback was attempted exactly once, nothing was sent, and the
        // caller still holds the pre-link list.
        expect(log).toEqual(['build', 'publish']);
        expect(sendMock).not.toHaveBeenCalled();
        expect(buildMock).toHaveBeenCalledTimes(1);
        expect(heldRef.current.version).toBe(HELD_LIST_VERSION);
        expect(deviceIds(heldRef.current.devices)).toEqual([0]);
    });

    it('re-attempts the hand-off on retry after a callback throw', async () => {
        const { heldRef, events: log } = renderCaller({ publishThrowsOnce: true });

        await enterLinkingCode();

        // First hand-off throws: v+1 is published but the response was not sent.
        await waitFor(() => {
            expect(screen.getByText('Retry send')).toBeTruthy();
        });
        expect(sendMock).not.toHaveBeenCalled();
        expect(heldRef.current.version).toBe(HELD_LIST_VERSION);

        fireEvent.click(screen.getByText('Retry send'));

        // The retry re-attempts the hand-off BEFORE sending, so the caller ends
        // up holding v+1 and the stale-base bug cannot be reached this way.
        await waitFor(() => {
            expect(screen.getByTestId('link-safety-number')).toBeTruthy();
        });
        expect(sendMock).toHaveBeenCalledTimes(1);
        expect(log.filter((event) => event === 'publish')).toHaveLength(2);
        expect(heldRef.current.version).toBe(HELD_LIST_VERSION + 1);
        expect(deviceIds(heldRef.current.devices)).toEqual([0, 1]);
    });
});
