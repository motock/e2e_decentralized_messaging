/**
 * useDeviceLinkingHandshake — the device-linking state machine and side effects.
 *
 * Split out of `DeviceLinking.tsx` (MF-12) so the screen itself is primarily
 * presentation. Everything here is a verbatim move of the logic that used to
 * live in the component: the same guards, the same ordering, the same copy.
 *
 * What this hook owns:
 *  - the linking state machine (`LinkingState` from `device_linking`),
 *  - the real handshake (MD-16): `beginLinkRequest` / `awaitLinkResponse` /
 *    `verifyLinkResponse` as the new device, `buildAndPublishLinkedList` /
 *    `sendLinkResponse` as the primary,
 *  - the post-confirmation `StorageGate` persistence (MD-16),
 *  - the send-failure retry and pending-device revoke recovery (MF-3, MF-10),
 *  - the one-shot refs and abort invalidation (MF-11).
 *
 * Security properties preserved by the move (see `DeviceLinking.tsx` for the
 * full statement):
 *  - Fail closed: malformed payloads and mismatched safety numbers never reach
 *    the `linked` state; a partial handshake configuration and a missing
 *    `heldListVersion` fail closed rather than defaulting.
 *  - The assigned device id is bound to the verified list, not to the
 *    response's own claim.
 *  - No sensitive data in logs; no raw key bytes in the DOM.
 *  - A handshake that resolves after the user cancelled is dropped.
 *  - Nothing is persisted before the safety number is confirmed.
 */

import { useEffect, useRef, useState } from 'react';
import {
    beginDisplay,
    beginScan,
    confirmLink,
    initialLinkingState,
    type LinkingState,
} from './device_linking';
import type { DeviceList, DeviceListEntry } from './Conversation';
import {
    buildAndPublishLinkedList,
    sendLinkResponse,
    type BuildAndPublishLinkedListResult,
} from './link_primary';
import { beginLinkRequest, awaitLinkResponse, verifyLinkResponse } from './link_new_device';
import { revokeDevice } from './revocation';
import type { RelayTransport } from './relay_transport';
import type { StorageGate } from './storage';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

export interface DeviceLinkingProps {
    localIdentityKey: Uint8Array;
    /**
     * DR-6b: the account's linked devices, injected by App from its own
     * device-list state. OPTIONAL — the linked-devices section (and its
     * revoke controls) render only when a list is actually supplied, so
     * existing render sites that pass only `localIdentityKey` are unchanged.
     */
    deviceList?: DeviceList;
    /**
     * DR-6b: called with the id of the device whose revoke control the user
     * activated. App performs the revocation (list + live fan-out session);
     * this component only reports the intent. OPTIONAL — without it the
     * revoke controls do not render.
     */
    onRevokeDevice?: (deviceId: number) => void;
    /**
     * MF-10: called with the freshly published signed list after this screen
     * revokes a pending device itself, so the caller's held own list (bytes,
     * version and devices) can be replaced in one step.
     *
     * This is deliberately NOT `onRevokeDevice`: the publish that put the new
     * device in the list happened *inside* this screen, so the caller's held
     * list is still the pre-link version. Routing the revoke through
     * `onRevokeDevice` would verify that stale list, re-sign the version this
     * screen already published and collide with it (a rollback / version
     * reuse). OPTIONAL — without it the revoke control fails closed rather than
     * publishing a list the caller could never learn about.
     */
    onOwnListPublished?: (
        bytes: Uint8Array,
        version: number,
        devices: DeviceListEntry[],
    ) => void;
    /**
     * MD-15: the safety number this device must compare out-of-band with the
     * other device before the link is authorised. OPTIONAL — without it no
     * safety-number panel renders, so existing render sites that pass only
     * `localIdentityKey` are unchanged. The value is the already-derived
     * display string; raw key bytes are never accepted or rendered here.
     */
    safetyNumber?: string;
    /**
     * MD-15: called when the user has confirmed the safety number matches and
     * activated the authorize control. The component only reports the intent;
     * the caller performs the authorization. OPTIONAL — without it the
     * authorize control does not render.
     */
    onConfirm?: () => void;
    /**
     * MD-16: relay transport used for the real linking handshake. OPTIONAL —
     * when the handshake props are absent the screen keeps its local-only
     * behaviour (encode/decode the QR payload and derive the safety number
     * locally), so existing render sites are unchanged.
     */
    transport?: RelayTransport;
    /**
     * MD-16: this device's identity handle. Required for either handshake role:
     * the new device creates its receiver session from it, the primary signs
     * the device list with it.
     */
    identityHandle?: IdentityHandle;
    /**
     * MD-16: the storage gate the account device list is persisted through
     * after the safety number is confirmed. Required for either handshake role;
     * nothing is ever written to `localStorage`.
     */
    storageGate?: StorageGate;
    /**
     * MD-16: the account handle the new device joins (display mode) or the
     * handle the signed list is published under (scan mode).
     */
    accountHandle?: string;
    /**
     * MD-16: the primary's own prekey bundle, included as device 0 in the list
     * it signs. Required in scan mode.
     */
    primaryBundleBytes?: Uint8Array;
    /**
     * MD-16: the currently published signed device list, or `null` when the
     * account genuinely has none. Required in scan mode so the primary builds
     * on the list it already holds instead of starting from version 0.
     */
    currentListBytes?: Uint8Array | null;
    /**
     * MD-16: the list version this device already holds (`deviceList.version`
     * in the app), or `0` only when the account genuinely has no list.
     *
     * Required in scan mode. `verify_device_list` proves authenticity, not
     * freshness, so omitting this would silently disable the §8.4 rollback
     * guard — a relay answering `NotFound` could then truncate the device list.
     * The screen therefore fails closed rather than defaulting it.
     */
    heldListVersion?: number;
}

/**
 * MD-16: the handshake result awaiting the safety-number confirmation.
 *
 * Nothing here is written anywhere until the user confirms the number matches
 * on both devices — the signed list is held in memory only.
 */
interface PendingLink {
    /** Account handle the new device joins. */
    accountHandle: string;
    /** This device's id in the signed list (the primary is device 0). */
    deviceId: number;
    /** The signed device list to persist once the number is confirmed. */
    signedListBytes: Uint8Array;
}

/** Store and record id the account device list is persisted under. */
const DEVICE_LIST_STORE = 'identity' as const;
const DEVICE_LIST_RECORD_ID = 'account-device-list';

/** Base64 for the signed list. The list is public; it is not secret material. */
function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    if (typeof btoa === 'function') return btoa(binary);
    return Buffer.from(binary, 'binary').toString('base64');
}

/**
 * A user-facing message for a failed handshake step. The linking modules throw
 * structural messages only (never key bytes, bundles or list contents), so the
 * message is safe to render; anything else collapses to a static string.
 */
function describeError(e: unknown): string {
    return e instanceof Error && e.message ? e.message : 'Device linking failed';
}

/**
 * MF-3: what the user sees when the link response could not be sent *after* the
 * device list was published. Deliberately static — a transport error message
 * could echo payload bytes, and this copy must never carry key material, the
 * link key or list contents. It also states the real situation: the list is
 * already updated, so the user must either retry the send or revoke the device.
 */
const SEND_FAILED_MESSAGE =
    'The device list was updated, but the new device did not receive its link response. ' +
    'Retry the send to finish linking it, or revoke the pending device if it cannot be reached.';

/**
 * MF-10: what the user sees after the pending device was revoked. Static, and
 * it names the outcome rather than the mechanism — no ids, keys or list bytes.
 */
const PENDING_DEVICE_REVOKED_MESSAGE =
    'The pending device was revoked. The device list was updated and the new device is no longer trusted.';

/**
 * MF-10: what the user sees when the revoke could not be published. Static, for
 * the same reason as {@link SEND_FAILED_MESSAGE}: the thrown message names the
 * structural failure and must never reach the UI. The pending send is kept, so
 * the copy points at the remaining way out.
 */
const REVOKE_FAILED_MESSAGE =
    'The pending device could not be revoked. The device list is unchanged and the new device is still listed. ' +
    'Retry the send to finish linking it, or try the revoke again.';

/**
 * MF-10: what the user sees when the revoke cannot be published safely — no
 * `onOwnListPublished` callback to hand the fresh list back to, or a pending
 * device id that is not a revocable device. Fail closed: nothing is published.
 */
const REVOKE_UNAVAILABLE_MESSAGE =
    'The pending device cannot be revoked from this screen. Retry the send to finish linking it.';

/**
 * The device id the verified list binds to this device.
 *
 * The primary assigns the id when it signs the list, so the verified list — not
 * the response's own `deviceId` field — is the authority for it. Requiring
 * exactly one entry to carry this device's identity key is what makes the id
 * unambiguous: a list that names this device twice cannot say which id is ours.
 *
 * @throws if no entry, or more than one entry, carries this device's key.
 */
function deviceIdBoundTo(deviceList: DeviceList, localIdentityKey: Uint8Array): number {
    const matches = deviceList.devices.filter(
        (device) =>
            device.identityKey instanceof Uint8Array &&
            device.identityKey.length === localIdentityKey.length &&
            device.identityKey.every((byte, i) => byte === localIdentityKey[i]),
    );
    if (matches.length !== 1) {
        throw new Error(
            'link response: verified device list does not bind this device exactly once',
        );
    }
    return matches[0].deviceId;
}

/** Everything the presentation layer needs to render the screen. */
export interface DeviceLinkingHandshake {
    state: LinkingState;
    mode: 'display' | 'scan' | null;
    setMode: (mode: 'display' | 'scan' | null) => void;
    scanInput: string;
    setScanInput: (value: string) => void;
    confirmInput: string;
    setConfirmInput: (value: string) => void;
    wasmReady: boolean;
    safetyNumberConfirmed: boolean;
    setSafetyNumberConfirmed: (confirmed: boolean) => void;
    pendingLink: PendingLink | null;
    pendingSend: BuildAndPublishLinkedListResult | null;
    sending: boolean;
    revoking: boolean;
    revokedNotice: string | null;
    /** The number the panel shows: caller-supplied (MD-15) or derived (MD-16). */
    panelSafetyNumber: string | null | undefined;
    handleDisplay: () => Promise<void>;
    handleScan: () => Promise<void>;
    handleRetrySend: () => Promise<void>;
    handleRevokePending: () => Promise<void>;
    handleConfirm: () => void;
    handleAbort: () => void;
    handleAuthorize: () => Promise<void>;
}

/**
 * Drive the device-linking flow for one screen instance.
 *
 * The caller passes the same props it renders with; the hook returns the state
 * and the handlers the presentation layer binds to. No behaviour is decided
 * here that was not decided in the component before the split.
 */
export function useDeviceLinkingHandshake({
    localIdentityKey,
    onOwnListPublished,
    safetyNumber,
    onConfirm,
    transport,
    identityHandle,
    storageGate,
    accountHandle,
    primaryBundleBytes,
    currentListBytes,
    heldListVersion,
}: DeviceLinkingProps): DeviceLinkingHandshake {
    const [state, setState] = useState<LinkingState>(initialLinkingState());
    const [mode, setMode] = useState<'display' | 'scan' | null>(null);
    const [scanInput, setScanInput] = useState('');
    const [confirmInput, setConfirmInput] = useState('');
    const [wasmReady, setWasmReady] = useState(false);
    const [safetyNumberConfirmed, setSafetyNumberConfirmed] = useState(false);
    const [pendingLink, setPendingLink] = useState<PendingLink | null>(null);
    /**
     * MF-3: the successful build result whose link response has not been
     * delivered yet. The list it published already contains the new device, so
     * this is the only way to finish the link without re-signing or
     * re-publishing. Held in memory only — never persisted.
     */
    const [pendingSend, setPendingSend] = useState<BuildAndPublishLinkedListResult | null>(null);
    /** True while a (re)send is in flight, so the retry control cannot double-send. */
    const [sending, setSending] = useState(false);
    /** True while a pending-device revoke is in flight (MF-10). */
    const [revoking, setRevoking] = useState(false);
    /**
     * MF-10: the static confirmation shown after the pending device was
     * revoked. Held separately from `state.error` so the outcome is a status,
     * not an alert, and so it survives the `pendingSend` reset.
     */
    const [revokedNotice, setRevokedNotice] = useState<string | null>(null);
    /**
     * Guards the one-shot write: a double click (or a re-render racing the
     * awaited `put`) must not persist the list twice. Reset on failure so the
     * user can retry.
     */
    const persistedRef = useRef(false);
    /**
     * MF-11: mirrors `sending` for the same-tick guarantee. React state is not
     * updated synchronously, so two clicks dispatched before the re-render both
     * saw `sending === false` and sent the link response twice. The ref is set
     * before the await and cleared in `finally`, so a failed send can still be
     * retried.
     */
    const sendingRef = useRef(false);
    /**
     * MF-11: mirrors `revoking` for the same reason. Two same-tick clicks would
     * otherwise both call `revokeDevice` — the second against a list that no
     * longer contains the device.
     */
    const revokingRef = useRef(false);
    /**
     * Bumped whenever the user aborts. An in-flight handshake captures the
     * value it started with and drops its result if it changed, so a response
     * that arrives after Cancel can never open the confirmation panel.
     */
    const attemptRef = useRef(0);

    // The handshake needs a full prop set per role. When none of the handshake
    // props are supplied the screen keeps its local-only behaviour, so existing
    // render sites are unchanged.
    const handshakePropsSupplied =
        transport !== undefined ||
        identityHandle !== undefined ||
        storageGate !== undefined ||
        accountHandle !== undefined ||
        primaryBundleBytes !== undefined ||
        currentListBytes !== undefined ||
        heldListVersion !== undefined;
    const handshakeDisplayReady = Boolean(
        transport && identityHandle && storageGate && accountHandle,
    );
    const handshakeScanReady = Boolean(
        transport && identityHandle && storageGate && accountHandle && primaryBundleBytes,
    );

    useEffect(() => {
        let cancelled = false;
        ensureWasmInit().then(() => {
            if (!cancelled) setWasmReady(true);
        });
        return () => { cancelled = true; };
    }, []);

    // A new safety number is a new comparison: drop any earlier confirmation
    // so a stale "matches" can never authorise a different key pair.
    useEffect(() => {
        setSafetyNumberConfirmed(false);
    }, [safetyNumber, state.safetyNumber]);

    const handleDisplay = async () => {
        setMode('display');
        if (!handshakePropsSupplied) {
            const newState = await beginDisplay(state, localIdentityKey);
            setState(newState);
            return;
        }
        if (!handshakeDisplayReady) {
            setMode(null);
            setState({
                ...initialLinkingState(),
                error: 'Device linking is not configured for this device',
            });
            return;
        }
        const attempt = attemptRef.current;
        try {
            // 1. Publish this device's bundle and show the QR the primary scans.
            const request = await beginLinkRequest(transport!, identityHandle!);
            if (attempt !== attemptRef.current) return;
            setState({
                phase: 'displaying',
                qrPayload: request.qrPayload,
                remoteKey: null,
                safetyNumber: null,
                error: null,
            });

            // 2. Wait for the primary's encrypted response, then re-verify the
            //    signed list against this device before trusting anything (MD-14).
            //    The session must be the one `beginLinkRequest` created: that is
            //    the session whose bundle was published under the link key, so it
            //    is the only one that can decrypt the primary's response.
            const response = await awaitLinkResponse({
                transport: transport!,
                linkKey: request.linkKey,
                receiverSession: request.receiverSession,
                newDevicePublicKey: localIdentityKey,
            });
            if (attempt !== attemptRef.current) return;
            // The id this device was assigned is only knowable from the verified
            // list: the QR payload carries no id, and the response's `deviceId` is
            // an unsigned claim. `expectedDeviceId` below therefore cannot be the
            // binding guard — it only lets the list be verified and decoded. The
            // guard is the derivation that follows: the id the signer actually
            // bound to this device must be the id the response reports. Without it
            // a response could point at *any* entry in the signed list that happens
            // to carry this device's key, losing the binding between the id
            // assigned to this device and the id reported.
            const verified = verifyLinkResponse({
                response,
                expectedDeviceId: response.deviceId,
                localPublicKey: localIdentityKey,
            });
            if (attempt !== attemptRef.current) return;
            const assignedDeviceId = deviceIdBoundTo(verified.deviceList, localIdentityKey);
            if (verified.deviceId !== assignedDeviceId) {
                throw new Error(
                    'link response: assigned device id is not the id bound to this device',
                );
            }
            if (attempt !== attemptRef.current) return;

            // 3. Hold the list in memory; the safety number gates the write.
            setPendingLink({
                accountHandle: verified.accountHandle,
                deviceId: verified.deviceId,
                // `verifyLinkResponse` re-verifies these bytes but returns the
                // converted list, so the blob to persist is the response's.
                signedListBytes: response.signedListBytes,
            });
            setState({
                phase: 'confirming',
                qrPayload: request.qrPayload,
                remoteKey: verified.primaryKey,
                safetyNumber: verified.safetyNumber,
                error: null,
            });
        } catch (e: unknown) {
            // Fail closed: no pending link, nothing persisted, no `linked`.
            // A failure after the user aborted must not resurrect the flow.
            if (attempt !== attemptRef.current) return;
            setPendingLink(null);
            setMode(null);
            setState({ ...initialLinkingState(), error: describeError(e) });
        }
    };

    const handleScan = async () => {
        if (!scanInput.trim()) {
            setState({ ...state, error: 'Enter a linking code' });
            return;
        }
        if (!handshakePropsSupplied) {
            const newState = await beginScan(state, scanInput.trim(), localIdentityKey);
            setState(newState);
            return;
        }
        if (!handshakeScanReady) {
            setMode(null);
            setState({
                ...initialLinkingState(),
                error: 'Device linking is not configured for this device',
            });
            return;
        }
        if (heldListVersion === undefined) {
            // Never default the freshness guard: without the version this
            // device holds, a relay answering `NotFound` could truncate the
            // device list (§8.4). Refuse to publish instead.
            setMode(null);
            setState({
                ...initialLinkingState(),
                error: 'Device list version unavailable; refusing to publish without a freshness check',
            });
            return;
        }
        const attempt = attemptRef.current;
        try {
            // 1. Verify the scanned key, append the new device and publish the
            //    next signed list — building on the list this device holds.
            const built = await buildAndPublishLinkedList({
                transport: transport!,
                qrPayload: scanInput.trim(),
                primaryIdentityHandle: identityHandle!,
                primaryBundleBytes: primaryBundleBytes!,
                currentListBytes: currentListBytes ?? null,
                heldVersion: heldListVersion,
                accountHandle: accountHandle!,
            });
            if (attempt !== attemptRef.current) return;

            // 2. Send the new device its encrypted response, bound to the
            //    identity the QR named (never to whatever the relay served).
            //    From here on the list is already published, so a send failure
            //    must keep `built` for a retry instead of discarding it.
            setPendingSend(built);
            await deliverResponse(built, attempt);
        } catch (e: unknown) {
            // Fail closed: a rejected build (e.g. a stale held version) publishes
            // nothing and persists nothing. A failure after the user aborted
            // must not resurrect the flow.
            if (attempt !== attemptRef.current) return;
            setPendingLink(null);
            setPendingSend(null);
            setMode(null);
            setState({ ...initialLinkingState(), error: describeError(e) });
        }
    };

    /**
     * MF-3: send the link response for an already-published build result.
     *
     * Split out of `handleScan` so a failed send can be retried with the SAME
     * result: the list is already published, so re-signing or re-publishing
     * would mint a second version and could truncate a concurrent publish.
     * On failure the build result stays in `pendingSend` and the screen shows a
     * static, non-sensitive error plus the retry control; nothing is persisted
     * and the flow stays pre-confirmation.
     */
    const deliverResponse = async (
        built: BuildAndPublishLinkedListResult,
        attempt: number,
    ): Promise<void> => {
        sendingRef.current = true;
        setSending(true);
        try {
            await sendLinkResponse({
                transport: transport!,
                linkKey: built.linkKey,
                newDeviceBundle: built.newDeviceBundle,
                expectedNewDeviceIdentityKey: built.newDeviceIdentityKey,
                primaryIdentityHandle: identityHandle!,
                accountHandle: accountHandle!,
                deviceId: built.deviceId,
                signedListBytes: built.signedListBytes,
            });
        } catch {
            if (attempt !== attemptRef.current) return;
            // The list is already published: keep the build result so the user
            // can retry the send. Static copy only — never the thrown message.
            setState({ ...initialLinkingState(), error: SEND_FAILED_MESSAGE });
            return;
        } finally {
            // Always release the one-shot guard, so a failed send can be retried.
            sendingRef.current = false;
            if (attempt === attemptRef.current) setSending(false);
        }
        if (attempt !== attemptRef.current) return;

        // 3. Hold the list in memory; the safety number gates the write. The
        //    scanned linking code has served its purpose — drop it so it is not
        //    retained past the send.
        setScanInput('');
        setPendingSend(null);
        setPendingLink({
            accountHandle: accountHandle!,
            // The primary is device 0 in its own signed list.
            deviceId: 0,
            signedListBytes: built.signedListBytes,
        });
        setState({
            phase: 'confirming',
            qrPayload: null,
            remoteKey: built.newDeviceIdentityKey,
            safetyNumber: built.safetyNumber,
            error: null,
        });
    };

    /**
     * MF-3: retry the link response for the build result already published.
     * Bounded by the user: no automatic retries, no re-publish.
     */
    const handleRetrySend = async () => {
        // `sending` disables the control on the next render; the ref rejects a
        // second click dispatched in the same tick, before that render.
        if (!pendingSend || sending || sendingRef.current) return;
        await deliverResponse(pendingSend, attemptRef.current);
    };

    /**
     * MF-10: revoke the device whose link response could not be sent.
     *
     * The list to build on is `pendingSend.signedListBytes` — the version this
     * screen already published (v+1), which contains the new device. The
     * caller's own held list is still the pre-link version, so it must never be
     * the base here: re-signing it would reuse v+1 and roll the list back.
     * `revokeDevice` therefore signs v+2 without the new device.
     *
     * Fail closed on every path that cannot leave the caller consistent:
     *  - no `onOwnListPublished` — publishing would leave the caller holding a
     *    stale list, so nothing is published;
     *  - a pending device id that is not a revocable device (device 0 is the
     *    account's own identity and is never handed to `revokeDevice`).
     * A failed revoke keeps `pendingSend` and the published v+1 list untouched.
     */
    const handleRevokePending = async () => {
        // `revoking` disables the control on the next render; the ref rejects a
        // second click dispatched in the same tick, before that render.
        if (!pendingSend || revoking || revokingRef.current) return;
        const { deviceId, signedListBytes } = pendingSend;
        if (!onOwnListPublished || !identityHandle || !accountHandle || !transport) {
            setState({ ...initialLinkingState(), error: REVOKE_UNAVAILABLE_MESSAGE });
            return;
        }
        if (!Number.isSafeInteger(deviceId) || deviceId <= 0) {
            // Device 0 is the primary: revoking it would leave a list no device
            // can sign for. Never publish, never call `revokeDevice`.
            setState({ ...initialLinkingState(), error: REVOKE_UNAVAILABLE_MESSAGE });
            return;
        }

        revokingRef.current = true;
        setRevoking(true);
        let revoked: { signedListBytes: Uint8Array; deviceList: DeviceList };
        try {
            revoked = await revokeDevice({
                currentListBytes: signedListBytes,
                primaryIdentityHandle: identityHandle,
                deviceId,
                accountHandle,
                transport,
            });
        } catch {
            // Fail closed: the v+1 list stays published and `pendingSend` stays
            // so the user can still retry the send. Static copy only.
            setState({ ...initialLinkingState(), error: REVOKE_FAILED_MESSAGE });
            return;
        } finally {
            // Always release the one-shot guard, so a failed revoke can be retried.
            revokingRef.current = false;
            setRevoking(false);
        }

        // The revoke itself succeeded, so v+2 is published. Drop the pending send
        // and state the outcome BEFORE handing the fresh list back: a throwing
        // `onOwnListPublished` must not turn a published revoke into the
        // "device list is unchanged" failure copy, nor leave `pendingSend` set.
        setPendingSend(null);
        setState(initialLinkingState());
        setRevokedNotice(PENDING_DEVICE_REVOKED_MESSAGE);
        try {
            onOwnListPublished(revoked.signedListBytes, revoked.deviceList.version, revoked.deviceList.devices);
        } catch {
            // The caller's own state update failed. This screen is already
            // consistent (v+2 published, pending send dropped), so the failure is
            // not reported as a revoke failure.
        }
    };

    const handleConfirm = () => {
        const newState = confirmLink(state, localIdentityKey, confirmInput);
        setState(newState);
    };

    const handleAbort = () => {
        // Invalidate any in-flight handshake so a late response is dropped.
        attemptRef.current += 1;
        setState(initialLinkingState());
        setMode(null);
        setScanInput('');
        setConfirmInput('');
        setPendingLink(null);
        // MF-3: dropping the build result abandons the retry. The published list
        // still names the new device, so it must be revoked out of band.
        setPendingSend(null);
        setSending(false);
        setRevoking(false);
        setRevokedNotice(null);
        persistedRef.current = false;
    };

    const handleAuthorize = async () => {
        // Fail closed: the control is disabled until confirmed, and a click
        // that somehow reaches it must not authorise an unverified number.
        if (!safetyNumberConfirmed) return;

        if (!pendingLink) {
            // MD-15 prop-driven path: the caller performs the authorization.
            if (!safetyNumber) return;
            onConfirm?.();
            return;
        }

        // MD-16: persist the account device list exactly once, only now that
        // the safety number has been confirmed out of band.
        if (!storageGate || persistedRef.current) return;
        persistedRef.current = true;
        try {
            await storageGate.put(DEVICE_LIST_STORE, DEVICE_LIST_RECORD_ID, {
                accountHandle: pendingLink.accountHandle,
                deviceId: pendingLink.deviceId,
                signedListBytesBase64: bytesToBase64(pendingLink.signedListBytes),
            });
            setPendingLink(null);
            setState({
                phase: 'linked',
                qrPayload: null,
                remoteKey: null,
                safetyNumber: null,
                error: null,
            });
        } catch (e: unknown) {
            // The write failed: stay pre-confirmation so the user can retry.
            persistedRef.current = false;
            setState({ ...state, error: describeError(e) });
        }
    };

    /**
     * The number the panel shows: the caller-supplied MD-15 value when present,
     * otherwise the one the handshake derived (MD-16). Both are already-derived
     * display strings; raw key bytes never reach the panel.
     */
    const panelSafetyNumber = safetyNumber ?? state.safetyNumber;

    return {
        state,
        mode,
        setMode,
        scanInput,
        setScanInput,
        confirmInput,
        setConfirmInput,
        wasmReady,
        safetyNumberConfirmed,
        setSafetyNumberConfirmed,
        pendingLink,
        pendingSend,
        sending,
        revoking,
        revokedNotice,
        panelSafetyNumber,
        handleDisplay,
        handleScan,
        handleRetrySend,
        handleRevokePending,
        handleConfirm,
        handleAbort,
        handleAuthorize,
    };
}
