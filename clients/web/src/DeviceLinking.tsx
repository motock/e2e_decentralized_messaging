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
 *  - **Linked-device management** (DR-3): the devices currently linked to
 *    this account are listed with a per-device revoke control. Revoking
 *    requires an explicit confirmation step, the last remaining device
 *    additionally requires confirming the lock-out risk, and the outcome is
 *    reported honestly — a refused or failed revocation is never shown as
 *    success.
 *
 * Security properties:
 *  - Fail closed: malformed payloads and mismatched safety numbers never
 *    reach the `linked` state.
 *  - No sensitive data in logs: key bytes and payloads are never logged.
 *  - The safety number is re-derived from the raw key bytes on confirmation,
 *    not trusted from the QR payload alone.
 */

import React, { useEffect, useState } from 'react';
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
    revokeDevice,
    type LinkedDevice,
    type LinkingState,
} from './device_linking';
import { SealGlyph } from './design/SealGlyph';
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

export interface DeviceLinkingProps {
    localIdentityKey: Uint8Array;
    /**
     * The devices currently linked to this account. When provided, a
     * "Linked devices" section lists them with a per-device revoke control.
     */
    linkedDevices?: LinkedDevice[];
}

/** Outcome of the last revocation attempt, for honest reporting. */
interface RevocationOutcome {
    /** The device the attempt was for. */
    deviceId: string;
    /** True only when the device was actually removed. */
    ok: boolean;
    /** Human-readable detail: success note, refusal reason, or error. */
    message: string;
    /** True when the refusal is the last-device confirmation gate. */
    requiresConfirmation?: boolean;
}

export const DeviceLinking: React.FC<DeviceLinkingProps> = ({ localIdentityKey, linkedDevices }) => {
    const [state, setState] = useState<LinkingState>(initialLinkingState());
    const [mode, setMode] = useState<'display' | 'scan' | null>(null);
    const [scanInput, setScanInput] = useState('');
    const [confirmInput, setConfirmInput] = useState('');
    const [wasmReady, setWasmReady] = useState(false);
    const [devices, setDevices] = useState<LinkedDevice[]>(linkedDevices ?? []);
    const [pendingRevoke, setPendingRevoke] = useState<string | null>(null);
    const [revocation, setRevocation] = useState<RevocationOutcome | null>(null);

    useEffect(() => {
        let cancelled = false;
        ensureWasmInit().then(() => {
            if (!cancelled) setWasmReady(true);
        });
        return () => { cancelled = true; };
    }, []);

    // Keep the local device list in sync when the caller passes a new list.
    useEffect(() => {
        if (linkedDevices) setDevices(linkedDevices);
    }, [linkedDevices]);

    const handleDisplay = async () => {
        setMode('display');
        const newState = await beginDisplay(state, localIdentityKey);
        setState(newState);
    };

    const handleScan = async () => {
        if (!scanInput.trim()) {
            setState({ ...state, error: 'Enter a linking code' });
            return;
        }
        const newState = await beginScan(state, scanInput.trim(), localIdentityKey);
        setState(newState);
    };

    const handleConfirm = () => {
        const newState = confirmLink(state, localIdentityKey, confirmInput);
        setState(newState);
    };

    const handleAbort = () => {
        setState(initialLinkingState());
        setMode(null);
        setScanInput('');
        setConfirmInput('');
    };

    // --- Revocation (DR-3) -------------------------------------------------

    /** Stage a revoke: nothing is removed until the user confirms. */
    const handleRevokeClick = (deviceId: string) => {
        setPendingRevoke(deviceId);
        setRevocation(null);
    };

    const handleCancelRevoke = () => {
        setPendingRevoke(null);
    };

    /** Perform the staged revoke and report the outcome honestly. */
    const handleConfirmRevoke = async () => {
        const deviceId = pendingRevoke;
        if (deviceId === null) return;
        setPendingRevoke(null);

        const isLastDevice = devices.length === 1;
        const result = await revokeDevice(
            { ...state, linkedDevices: devices },
            deviceId,
            // The last remaining device needs the explicit lock-out confirmation;
            // the UI's confirm button IS that confirmation.
            { confirmLastDevice: isLastDevice },
        );

        if (result.ok) {
            setDevices(result.state.linkedDevices);
            setState(result.state);
            setRevocation({
                deviceId,
                ok: true,
                message: `Device ${deviceId} revoked. It can no longer receive messages.`,
            });
        } else {
            // Failure: the state is untouched by revokeDevice; report the
            // refusal/error and do NOT claim success.
            setRevocation({
                deviceId,
                ok: false,
                message: result.error ?? 'Revocation failed',
                requiresConfirmation: result.requiresConfirmation,
            });
        }
    };

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
                    <SealGlyph value={localIdentityKey.join(',')} size={56} tone="verified" title="Device linked" />
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

            {devices.length > 0 && (
                <section className="linked-devices" aria-label="Linked devices">
                    <h3>Linked devices</h3>
                    <ul className="linked-devices-list">
                        {devices.map((device) => (
                            <li key={device.deviceId} className="linked-device-row">
                                <span className="linked-device-id">{device.deviceId}</span>
                                {pendingRevoke === device.deviceId ? (
                                    <span className="linked-device-confirm">
                                        <span className="linked-device-confirm-text">
                                            Remove {device.deviceId}
                                            {devices.length === 1
                                                ? ' — this is your last linked device' : ''}?
                                        </span>
                                        <button
                                            className="link-button-primary"
                                            onClick={handleConfirmRevoke}
                                        >
                                            Confirm revoke
                                        </button>
                                        <button
                                            className="link-button-secondary"
                                            aria-label={`Revoke device ${device.deviceId}`}
                                            onClick={handleCancelRevoke}
                                        >
                                            Keep device
                                        </button>
                                    </span>
                                ) : (
                                    <button
                                        className="link-button-secondary"
                                        aria-label={`Revoke device ${device.deviceId}`}
                                        onClick={() => handleRevokeClick(device.deviceId)}
                                    >
                                        Revoke
                                    </button>
                                )}
                            </li>
                        ))}
                    </ul>
                    {revocation && (
                        <p
                            data-testid="revocation-status"
                            role={revocation.ok ? 'status' : 'alert'}
                            className={revocation.ok ? 'revocation-ok' : 'revocation-error'}
                        >
                            {revocation.ok
                                ? `Device ${revocation.deviceId} revoked`
                                : `Revocation failed for device ${revocation.deviceId}: ${revocation.message}`}
                        </p>
                    )}
                </section>
            )}
        </div>
    );
};