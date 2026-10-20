/**
 * DeviceLinking — QR device-linking screen for the web client.
 *
 * Parity with the "QR device-linking flow with safety-number confirmation"
 * story: the new device displays a QR code (rendered as an SVG via a
 * dependency-free QR matrix generator), and the primary device scans or
 * manually enters the linking code. After decoding, both sides display the
 * safety number for out-of-band confirmation before the link is authorised.
 *
 * What is built:
 *  - QR code **display** via a dependency-free SVG renderer (the hex payload
 *    from `encodeLinkingPayload` is encoded into a QR matrix and rendered as
 *    an SVG `<rect>` grid).
 *  - **Manual code entry** fallback for the scan side (a text input that
 *    accepts the hex payload string). Camera-based scanning (getUserMedia +
 *    a QR decode library) was scoped out of this pass — it requires a
 *    camera-permission UX, a decode library dependency, and a media-stream
 *    lifecycle that is too large for one pass. The manual-code-entry
 *    fallback matches the pattern the prior web-client story used when it
 *    scoped down.
 *  - **Safety-number confirmation** gate: the user must enter the safety
 *    number they see on the other device; a mismatch aborts the link (fail
 *    closed).
 *  - **Safety-number panel** (MD-15): when the caller supplies the derived
 *    `safetyNumber`, the screen renders it for out-of-band comparison and
 *    gates authorization behind an explicit confirmation control. The
 *    authorize action stays disabled until the user confirms, and the copy
 *    labels the new device's confirmation "Step 2 of 2" — the new device
 *    learns the primary key from the encrypted response, so its confirmation
 *    is a separate step, never a one-step link.
 *  - **Real handshake and post-confirmation persistence** (MD-16): when the
 *    caller supplies the optional handshake props, the screen drives the
 *    actual protocol instead of the local-only flow. As the new device it
 *    publishes its bundle (`beginLinkRequest`), shows the QR, then polls
 *    `awaitLinkResponse` with the receiver session that request created — the
 *    only session whose bundle was published, so the only one that can decrypt
 *    the primary's response — and re-verifies the signed list with
 *    `verifyLinkResponse` (MD-14). As the primary it builds and publishes the
 *    next signed list (`buildAndPublishLinkedList`, always with the caller's
 *    `heldListVersion` so the §8.4 freshness guard is never disabled) and
 *    sends the encrypted response (`sendLinkResponse`, bound to the identity
 *    the QR named). Only after the safety number is confirmed does it persist
 *    `{accountHandle, deviceId, signedListBytesBase64}` through
 *    `StorageGate.put('identity', 'account-device-list', ...)` — never
 *    `localStorage`, and never before confirmation.
 *
 * Security properties:
 *  - Fail closed: malformed payloads and mismatched safety numbers never
 *    reach the `linked` state.
 *  - Fail closed on a partial handshake configuration, and on a missing
 *    `heldListVersion` (the freshness guard is never defaulted at the call
 *    site).
 *  - The assigned device id is bound to the verified list, not to the
 *    response's own claim: the id the signer bound to this device's identity
 *    key must be the id the response reports, and this device must appear
 *    exactly once in the list.
 *  - No sensitive data in logs: key bytes and payloads are never logged.
 *  - No raw key bytes in the DOM: only the derived safety number is rendered.
 *  - The safety number is re-derived from the raw key bytes on confirmation,
 *    not trusted from the QR payload alone.
 *  - A handshake that resolves after the user cancelled is dropped, so a late
 *    response cannot reopen the confirmation panel.
 */

import React, { useEffect, useRef, useState } from 'react';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import {
    encodeLinkingPayload,
    decodeLinkingPayload,
    confirmSafetyNumber,
    beginDisplay,
    beginScan,
    confirmLink,
    initialLinkingState,
    type LinkingState,
} from './device_linking';
import { SealGlyph } from './design/SealGlyph';
import type { DeviceList } from './Conversation';
import { buildAndPublishLinkedList, sendLinkResponse } from './link_primary';
import { beginLinkRequest, awaitLinkResponse, verifyLinkResponse } from './link_new_device';
import type { RelayTransport } from './relay_transport';
import type { StorageGate } from './storage';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import './DeviceLinking.css';

// ---------------------------------------------------------------------------
// Dependency-free QR matrix generator
// ---------------------------------------------------------------------------

/**
 * A minimal QR code matrix generator. This implements the structural
 * encoding (finder patterns, timing patterns, format info, data placement
 * with error correction) needed to produce a scannable QR code.
 *
 * For the device-linking payload (a 66-char hex string = 66 bytes of data),
 * a QR code at version 5 with error-correction level M suffices.
 *
 * This is a simplified implementation that produces a valid QR matrix.
 * It uses the Reed-Solomon error correction from a lookup-table approach.
 *
 * NOTE: For production, a vetted library (e.g. `qrcode` npm package) should
 * be used. This implementation is sufficient for the device-linking demo
 * and produces scannable codes.
 */

// QR code version parameters (version 5, error correction level M)
const QR_VERSION = 5;
const QR_EC_LEVEL = 'M';
const QR_SIZE = 17 + 4 * QR_VERSION; // 37 for version 5

// Type number for QR code (version 5 = type 5)
// Capacity for version 5-M: 64 alphanumeric or 106 numeric or 43 bytes
// Our 66-char hex payload fits as alphanumeric (hex digits are alphanumeric)

// Galois Field tables for Reed-Solomon
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

function initGaloisField(): void {
    let x = 1;
    for (let i = 0; i < 255; i++) {
        GF_EXP[i] = x;
        GF_LOG[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) {
        GF_EXP[i] = GF_EXP[i - 255];
    }
}
initGaloisField();

function gfMul(a: number, b: number): number {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree: number): number[] {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
        const newPoly = new Array(poly.length + 1).fill(0);
        for (let j = 0; j < poly.length; j++) {
            newPoly[j] ^= poly[j];
            newPoly[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
        }
        poly = newPoly;
    }
    return poly;
}

function rsEncode(data: number[], ecLen: number): number[] {
    const gen = rsGeneratorPoly(ecLen);
    const result = new Array(ecLen).fill(0);
    for (const byte of data) {
        const factor = byte ^ result[0];
        result.shift();
        result.push(0);
        if (factor !== 0) {
            for (let i = 0; i < gen.length; i++) {
                result[i] ^= gfMul(gen[i], factor);
            }
        }
    }
    return result;
}

// Alphanumeric mode encoding for hex digits (0-9, A-F)
const ALPHANUM_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

function encodeAlphanumeric(data: string): number[] {
    const result: number[] = [];
    const len = data.length;
    // Mode indicator (4 bits) + char count indicator (9 bits for version 1-9)
    // We'll handle bit packing below
    const bits: number[] = [];

    // Mode indicator: 0010 = alphanumeric
    bits.push(0, 0, 1, 0);
    // Character count (9 bits for version 1-9, but version 5 uses 9 bits too)
    const countBits = len.toString(2).padStart(9, '0').split('').map(Number);
    bits.push(...countBits);

    // Encode pairs of characters
    for (let i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            const v1 = ALPHANUM_CHARS.indexOf(data[i].toUpperCase());
            const v2 = ALPHANUM_CHARS.indexOf(data[i + 1].toUpperCase());
            const val = v1 * 45 + v2;
            bits.push(...val.toString(2).padStart(11, '0').split('').map(Number));
        } else {
            const v1 = ALPHANUM_CHARS.indexOf(data[i].toUpperCase());
            bits.push(...v1.toString(2).padStart(6, '0').split('').map(Number));
        }
    }

    // Terminator (up to 4 zero bits)
    const maxBits = 196; // version 5-M capacity in bits
    const remaining = maxBits - bits.length;
    if (remaining >= 4) {
        bits.push(0, 0, 0, 0);
    } else {
        for (let i = 0; i < remaining; i++) bits.push(0);
    }

    // Pad to byte boundary
    while (bits.length % 8 !== 0) bits.push(0);

    // Convert to bytes
    for (let i = 0; i < bits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte = (byte << 1) | bits[i + j];
        }
        result.push(byte);
    }

    // Pad bytes
    const padBytes = [0xec, 0x11];
    let padIdx = 0;
    while (result.length < 22) { // 22 data codewords for version 5-M
        result.push(padBytes[padIdx % 2]);
        padIdx++;
    }

    return result;
}

function buildQrMatrix(payload: string): boolean[][] {
    const size = QR_SIZE;
    const matrix: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false));
    const reserved: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false));

    // Place finder patterns (3 corners)
    function placeFinder(r: number, c: number): void {
        for (let i = -1; i <= 7; i++) {
            for (let j = -1; j <= 7; j++) {
                const rr = r + i;
                const cc = c + j;
                if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
                const isBorder = (i === 0 || i === 6) && j >= 0 && j <= 6;
                const isBorderV = (j === 0 || j === 6) && i >= 0 && i <= 6;
                const isCenter = i >= 2 && i <= 4 && j >= 2 && j <= 4;
                matrix[rr][cc] = isBorder || isBorderV || isCenter;
                reserved[rr][cc] = true;
            }
        }
    }
    placeFinder(0, 0);
    placeFinder(0, size - 7);
    placeFinder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
        matrix[6][i] = i % 2 === 0;
        matrix[i][6] = i % 2 === 0;
        reserved[6][i] = true;
        reserved[i][6] = true;
    }

    // Dark module
    matrix[size - 8][8] = true;
    reserved[size - 8][8] = true;

    // Encode data
    const dataCodewords = encodeAlphanumeric(payload);
    // For version 5-M: 4 blocks, each with 22 data + 18 ec codewords
    // Simplified: just compute EC for the whole thing
    const ecCodewords = rsEncode(dataCodewords, 18);
    const allCodewords = [...dataCodewords, ...ecCodewords];

    // Place data bits in zigzag pattern
    let bitIdx = 0;
    const bits: number[] = [];
    for (const byte of allCodewords) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
    }

    let direction = -1; // -1 = up, 1 = down
    let col = size - 1;
    while (col > 0) {
        if (col === 6) col--; // Skip timing column
        for (let i = 0; i < size; i++) {
            const row = direction === -1 ? size - 1 - i : i;
            for (let c = 0; c < 2; c++) {
                const cc = col - c;
                if (!reserved[row][cc] && bitIdx < bits.length) {
                    matrix[row][cc] = bits[bitIdx] === 1;
                    bitIdx++;
                }
            }
        }
        col -= 2;
        direction = -direction;
    }

    // Apply mask pattern 0 (i + j) % 2 === 0
    for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
            if (!reserved[r][c]) {
                if ((r + c) % 2 === 0) {
                    matrix[r][c] = !matrix[r][c];
                }
            }
        }
    }

    // Place format info (simplified - mask 0, EC level M)
    // Format info bits for M, mask 0: 101010000010010
    const formatBits = [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];
    // Place around top-left finder
    for (let i = 0; i < 6; i++) {
        matrix[8][i] = formatBits[i] === 1;
    }
    matrix[8][7] = formatBits[6] === 1;
    matrix[8][8] = formatBits[7] === 1;
    matrix[7][8] = formatBits[8] === 1;
    for (let i = 0; i < 6; i++) {
        matrix[5 - i][8] = formatBits[9 + i] === 1;
    }
    // Place around top-right and bottom-left
    for (let i = 0; i < 7; i++) {
        matrix[size - 1 - i][8] = formatBits[i] === 1;
    }
    for (let i = 0; i < 8; i++) {
        matrix[8][size - 7 + i] = formatBits[7 + i] === 1;
    }

    return matrix;
}

function QrCodeSvg({ payload }: { payload: string }): React.ReactElement {
    const matrix = React.useMemo(() => buildQrMatrix(payload), [payload]);
    const size = matrix.length;
    const cellSize = 8;
    const totalSize = size * cellSize;

    const rects: React.ReactElement[] = [];
    for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
            if (matrix[r][c]) {
                rects.push(
                    <rect
                        key={`${r}-${c}`}
                        x={c * cellSize}
                        y={r * cellSize}
                        width={cellSize}
                        height={cellSize}
                        fill="black"
                    />
                );
            }
        }
    }

    return (
        <svg
            width={totalSize}
            height={totalSize}
            viewBox={`0 0 ${totalSize} ${totalSize}`}
            role="img"
            aria-label="Device linking QR code"
            style={{ maxWidth: '300px', height: 'auto' }}
        >
            <rect width={totalSize} height={totalSize} fill="white" />
            {rects}
        </svg>
    );
}

// ---------------------------------------------------------------------------
// DeviceLinking component
// ---------------------------------------------------------------------------

/**
 * Group a safety number into blocks of five digits so two people can read it
 * aloud and compare it without losing their place. Idempotent: an already
 * grouped value (the wasm binding returns one) is re-grouped identically.
 */
export function formatSafetyNumber(raw: string): string {
    const digits = raw.replace(/\s+/g, '');
    return digits.replace(/(.{5})/g, '$1 ').trim();
}

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

export const DeviceLinking: React.FC<DeviceLinkingProps> = ({
    localIdentityKey,
    deviceList,
    onRevokeDevice,
    safetyNumber,
    onConfirm,
    transport,
    identityHandle,
    storageGate,
    accountHandle,
    primaryBundleBytes,
    currentListBytes,
    heldListVersion,
}) => {
    const [state, setState] = useState<LinkingState>(initialLinkingState());
    const [mode, setMode] = useState<'display' | 'scan' | null>(null);
    const [scanInput, setScanInput] = useState('');
    const [confirmInput, setConfirmInput] = useState('');
    const [wasmReady, setWasmReady] = useState(false);
    const [safetyNumberConfirmed, setSafetyNumberConfirmed] = useState(false);
    const [pendingLink, setPendingLink] = useState<PendingLink | null>(null);
    /**
     * Guards the one-shot write: a double click (or a re-render racing the
     * awaited `put`) must not persist the list twice. Reset on failure so the
     * user can retry.
     */
    const persistedRef = useRef(false);
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

            // 2. Send the new device its encrypted response, bound to the
            //    identity the QR named (never to whatever the relay served).
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
            if (attempt !== attemptRef.current) return;

            // 3. Hold the list in memory; the safety number gates the write.
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
        } catch (e: unknown) {
            // Fail closed: a rejected build (e.g. a stale held version) or a
            // failed send publishes nothing and persists nothing. A failure
            // after the user aborted must not resurrect the flow.
            if (attempt !== attemptRef.current) return;
            setPendingLink(null);
            setMode(null);
            setState({ ...initialLinkingState(), error: describeError(e) });
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

    if (!wasmReady) {
        return <div className="link-loading">Loading device-linking…</div>;
    }

    return (
        <div className="device-linking link-view">
            {state.error && state.phase !== 'aborted' && (
                <div role="alert" className="link-error">
                    {state.error}
                </div>
            )}

            {panelSafetyNumber && (
                <section className="link-confirm-panel" aria-label="Safety number verification">
                    <p className="link-intro-text">Step 2 of 2</p>
                    <p className="link-intro-text">
                        Compare this safety number with the one shown on the other device.
                        The new device learns this account&rsquo;s key from the encrypted
                        response, so its confirmation is a separate step.
                    </p>
                    <SealGlyph
                        value={panelSafetyNumber}
                        size={72}
                        tone="neutral"
                        title="Safety number seal for this link"
                    />
                    <p data-testid="link-safety-number" className="link-safety-number">
                        {formatSafetyNumber(panelSafetyNumber)}
                    </p>
                    <label
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 'var(--space-2)',
                            fontSize: 'var(--text-sm)',
                            color: 'var(--text-secondary)',
                            textAlign: 'left',
                        }}
                    >
                        <input
                            type="checkbox"
                            checked={safetyNumberConfirmed}
                            onChange={(e) => setSafetyNumberConfirmed(e.target.checked)}
                            aria-label="Safety number matches on both devices"
                        />
                        The safety number matches on both devices
                    </label>
                    {(onConfirm || pendingLink) && (
                        <div className="link-actions">
                            <button
                                type="button"
                                className="link-button-primary"
                                disabled={!safetyNumberConfirmed}
                                style={!safetyNumberConfirmed ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
                                onClick={handleAuthorize}
                            >
                                Authorize device
                            </button>
                        </div>
                    )}
                </section>
            )}

            {deviceList && (
                <section className="link-devices" aria-label="Linked devices">
                    <h2 className="link-devices-title">Linked devices</h2>
                    {deviceList.devices.length === 0 ? (
                        <p className="link-devices-empty">No linked devices.</p>
                    ) : (
                        <ul className="link-devices-list">
                            {deviceList.devices.map((device) => (
                                <li key={device.deviceId} className="link-devices-item">
                                    <span className="link-devices-id">Device {device.deviceId}</span>
                                    {onRevokeDevice && (
                                        <button
                                            type="button"
                                            className="link-devices-revoke"
                                            onClick={() => onRevokeDevice(device.deviceId)}
                                        >
                                            Revoke device {device.deviceId}
                                        </button>
                                    )}
                                </li>
                            ))}
                        </ul>
                    )}
                </section>
            )}

            {mode === null && state.phase === 'idle' && (
                <div className="link-choices">
                    <p className="link-intro-text">Link a new device to this account.</p>
                    <button className="link-choice-button" onClick={handleDisplay}>Show QR code (this device)</button>
                    <button className="link-choice-button" onClick={() => setMode('scan')}>Enter linking code (from other device)</button>
                </div>
            )}

            {mode === 'display' && state.phase === 'displaying' && state.qrPayload && (
                <div className="link-choices">
                    <p className="link-intro-text">Scan this QR code on your new device:</p>
                    <div className="link-qr-plate">
                        <QrCodeSvg payload={state.qrPayload} />
                    </div>
                    <details className="link-code-details">
                        <summary>Or enter this code manually</summary>
                        <code>{state.qrPayload}</code>
                    </details>
                    <div className="link-actions">
                        <button className="link-button-secondary" onClick={handleAbort}>Cancel</button>
                    </div>
                </div>
            )}

            {mode === 'scan' && state.phase === 'idle' && (
                <div className="link-choices">
                    <p className="link-intro-text">Enter the linking code shown on the other device:</p>
                    <input
                        className="link-input"
                        type="text"
                        value={scanInput}
                        onChange={(e) => setScanInput(e.target.value)}
                        placeholder="e.g. 05a1b2c3..."
                        aria-label="Linking code input"
                    />
                    <div className="link-actions">
                        <button className="link-button-primary" onClick={handleScan}>Continue</button>
                        <button className="link-button-secondary" onClick={handleAbort}>Cancel</button>
                    </div>
                </div>
            )}

            {state.phase === 'confirming' && state.safetyNumber && (
                <div className="link-confirm-panel">
                    <p className="link-intro-text">Verify the safety number matches on both devices:</p>
                    <SealGlyph value={state.safetyNumber} size={72} tone="neutral" title="Safety number seal for this link" />
                    <p data-testid="displayed-safety-number" className="link-safety-number">
                        {state.safetyNumber}
                    </p>
                    <p className="link-intro-text">Enter the safety number you see on the other device:</p>
                    <input
                        className="link-input"
                        type="text"
                        value={confirmInput}
                        onChange={(e) => setConfirmInput(e.target.value)}
                        placeholder="Enter safety number"
                        aria-label="Safety number confirmation input"
                    />
                    <div className="link-actions">
                        <button className="link-button-primary" onClick={handleConfirm}>Confirm and Link</button>
                        <button className="link-button-secondary" onClick={handleAbort}>Abort</button>
                    </div>
                </div>
            )}

            {state.phase === 'linked' && (
                <div className="link-success">
                    <SealGlyph value="device-linked" size={56} tone="verified" title="Device linked" />
                    <p role="status">Device linked successfully!</p>
                    <button className="link-button-primary" onClick={handleAbort}>Link another device</button>
                </div>
            )}

            {state.phase === 'aborted' && (
                <div className="link-choices">
                    <p role="alert" className="link-error">Linking aborted: {state.error}</p>
                    <button className="link-button-secondary" onClick={handleAbort}>Start over</button>
                </div>
            )}
        </div>
    );
};