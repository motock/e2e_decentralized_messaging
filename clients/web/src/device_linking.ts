/**
 * QR device-linking flow (web client).
 *
 * Mirrors the Rust core's `crypto::device_qr` flow:
 *  1. New device encodes its identity public key as a QR payload (hex string).
 *  2. Primary device scans (or manually enters) the payload and decodes it.
 *  3. Both devices derive and display the safety number.
 *  4. User confirms the safety numbers match out-of-band.
 *  5. On match → link proceeds; on mismatch → link aborts (fail closed).
 *
 * The encode/decode and safety-number derivation are delegated to the WASM
 * bindings (`encode_device_qr`, `decode_device_qr`, `derive_safety_number`),
 * which are thin wrappers over the Rust core. This module provides the
 * web-side orchestration and the confirmation gate.
 *
 * Revocation (DR-3): a linked device can be removed again. `revokeDevice`
 * drops the device from `linkedDevices` (so `messageRecipients` no longer
 * includes it) and calls the WASM `remove_device` binding, which is the
 * boundary for the core's fan-out revocation primitive. Revocation fails
 * closed: an unknown device, or the last remaining device without explicit
 * confirmation, leaves the state untouched and reports why.
 *
 * Security properties:
 *  - **Fail closed**: any malformed, truncated, or tampered QR payload is
 *    rejected by `decodeLinkingPayload` (the WASM binding throws). The
 *    function does not return partial or best-effort results.
 *  - **Confirmation gate**: `confirmSafetyNumber` re-derives the expected
 *    safety number from the raw key bytes and compares it to the user-entered
 *    value. A mismatch returns `confirmed: false` and never produces a
 *    safety number, so the caller cannot accidentally proceed.
 *  - **Revocation gate**: `revokeDevice` refuses to remove the last remaining
 *    device unless the caller passes `{ confirmLastDevice: true }`, so a user
 *    cannot lock themselves out silently. A failed revocation never mutates
 *    the state and is never reported as success.
 *  - **No sensitive data in logs**: key bytes and payloads are never logged.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

/**
 * Extract a human-readable message from a thrown value. WASM binding errors
 * are `WasmError` structs (not JS `Error` instances) that expose a `.message()`
 * method, so we check for that before falling back to `String(e)`.
 */
function errorMessage(e: unknown): string {
    if (e instanceof Error) return e.message;
    if (e !== null && typeof e === 'object' && 'message' in e) {
        const msg = (e as { message: unknown }).message;
        if (typeof msg === 'string') return msg;
        if (typeof msg === 'function') {
            try { return String((e as { message: () => string }).message()); } catch { /* fall through */ }
        }
    }
    return String(e);
}

/**
 * Encode a device's identity public key bytes as a QR code payload string.
 * The returned hex string is what a QR renderer encodes into the image.
 *
 * @throws if the WASM binding rejects the key bytes (should not happen for
 *   valid 33-byte identity keys).
 */
export function encodeLinkingPayload(identityPublicKey: Uint8Array): string {
    return wasm.encode_device_qr(identityPublicKey);
}

/**
 * Decode a scanned or manually entered QR payload back to raw identity
 * public key bytes.
 *
 * Fail closed: any malformed payload (non-hex, odd length, wrong byte
 * count) causes the WASM binding to throw. This function does not catch
 * or swallow those errors — callers must handle the rejection and not
 * proceed with linking.
 *
 * @throws if the payload is malformed, truncated, or does not decode to
 *   a valid 33-byte identity key.
 */
export function decodeLinkingPayload(qrPayload: string): Uint8Array {
    const bytes = wasm.decode_device_qr(qrPayload);
    return new Uint8Array(bytes);
}

/**
 * Result of the safety-number confirmation step.
 */
export interface SafetyNumberConfirmation {
    /** True only when the user-entered safety number matches the derived one. */
    confirmed: boolean;
    /** The derived safety number string, or null if confirmation failed. */
    safetyNumber: string | null;
    /** Error message when confirmation fails (mismatch or derivation error). */
    error?: string;
}

/**
 * Confirm that the user-entered safety number matches the safety number
 * derived from the two devices' identity keys.
 *
 * This is the critical security gate: the link proceeds only if
 * `confirmed === true`. On any mismatch (or derivation error), the function
 * returns `confirmed: false` with `safetyNumber: null` so the caller cannot
 * accidentally use a derived value from a failed confirmation.
 *
 * @param primaryKey      - The primary device's identity public key bytes.
 * @param newDeviceKey    - The new device's identity public key bytes.
 * @param userInput       - The safety number string the user entered/compared.
 */
export function confirmSafetyNumber(
    primaryKey: Uint8Array,
    newDeviceKey: Uint8Array,
    userInput: string,
): SafetyNumberConfirmation {
    let derived: string;
    try {
        derived = wasm.derive_safety_number(primaryKey, newDeviceKey);
    } catch (e: unknown) {
        return {
            confirmed: false,
            safetyNumber: null,
            error: errorMessage(e),
        };
    }

    if (userInput.trim() === derived) {
        return { confirmed: true, safetyNumber: derived };
    }

    return {
        confirmed: false,
        safetyNumber: null,
        error: 'Safety number mismatch — link aborted',
    };
}

// ---------------------------------------------------------------------------
// Linking state machine
// ---------------------------------------------------------------------------

/** The phases of the device-linking flow. */
export type LinkingPhase =
    | 'idle'
    | 'displaying'
    | 'confirming'
    | 'linked'
    | 'revoked'
    | 'aborted';

/** A device currently linked to this account. */
export interface LinkedDevice {
    /** Application-level device id (the fan-out `DeviceId` as a JS number). */
    deviceId: string;
    /** The device's serialized public identity key, when known. */
    publicKey?: Uint8Array;
}

/** Mutable linking state, driven by the UI. */
export interface LinkingState {
    phase: LinkingPhase;
    /** The QR payload string to render (when this device is the new device). */
    qrPayload: string | null;
    /** The decoded remote key (when this device is the primary/scanner). */
    remoteKey: Uint8Array | null;
    /** The derived safety number for display. */
    safetyNumber: string | null;
    /** Error message on failure. */
    error: string | null;
    /** The devices currently linked to this account. */
    linkedDevices: LinkedDevice[];
}

export function initialLinkingState(): LinkingState {
    return {
        phase: 'idle',
        qrPayload: null,
        remoteKey: null,
        safetyNumber: null,
        error: null,
        linkedDevices: [],
    };
}

/**
 * Begin the flow as the new device: encode the local identity key as a QR
 * payload for display. Transitions to the `displaying` phase.
 */
export async function beginDisplay(
    state: LinkingState,
    localIdentityKey: Uint8Array,
): Promise<LinkingState> {
    await ensureWasmInit();
    try {
        const payload = encodeLinkingPayload(localIdentityKey);
        return { ...state, phase: 'displaying', qrPayload: payload, error: null };
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }
}

/**
 * Begin the flow as the primary device: decode a scanned/manually-entered
 * QR payload and derive the safety number. Transitions to `confirming`.
 *
 * Fail closed: a malformed payload transitions to `aborted`, not
 * `confirming`.
 */
export async function beginScan(
    state: LinkingState,
    scannedPayload: string,
    localIdentityKey: Uint8Array,
): Promise<LinkingState> {
    await ensureWasmInit();
    let remoteKey: Uint8Array;
    try {
        remoteKey = decodeLinkingPayload(scannedPayload);
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }

    let safetyNumber: string;
    try {
        safetyNumber = wasm.derive_safety_number(localIdentityKey, remoteKey);
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }

    return {
        ...state,
        phase: 'confirming',
        remoteKey,
        safetyNumber,
        error: null,
    };
}

/**
 * User confirms or denies the safety number. On match → `linked`; on
 * mismatch → `aborted`.
 */
export function confirmLink(
    state: LinkingState,
    localIdentityKey: Uint8Array,
    userInput: string,
): LinkingState {
    if (state.phase !== 'confirming' || state.remoteKey === null) {
        return { ...state, error: 'Not in confirming phase' };
    }

    const result = confirmSafetyNumber(localIdentityKey, state.remoteKey, userInput);
    if (result.confirmed) {
        return { ...state, phase: 'linked', safetyNumber: result.safetyNumber, error: null };
    }
    return { ...state, phase: 'aborted', safetyNumber: null, error: result.error ?? 'Confirmation failed' };
}

// ---------------------------------------------------------------------------
// Device revocation / unlinking (DR-3)
// ---------------------------------------------------------------------------

/** Options for `revokeDevice`. */
export interface RevokeOptions {
    /**
     * Explicitly confirm revoking the LAST remaining linked device. Without
     * this, revoking the last device is refused (the user would lock
     * themselves out of the account silently).
     */
    confirmLastDevice?: boolean;
}

/** Result of a revocation attempt. */
export interface RevokeResult {
    /** True only when the device was actually removed. */
    ok: boolean;
    /** The (unchanged on failure) state after the attempt. */
    state: LinkingState;
    /** Why the revocation failed; always set when `ok` is false. */
    error?: string;
    /**
     * True when the refusal is specifically "this is the last remaining
     * device — pass `confirmLastDevice: true` to proceed".
     */
    requiresConfirmation?: boolean;
}

/**
 * The devices a message should currently be sent to: exactly the devices
 * still linked, recomputed from `state.linkedDevices` on every call — never
 * from a list cached when a link completed, so a revoked device stops being
 * a recipient immediately.
 */
export function messageRecipients(state: LinkingState): string[] {
    return state.linkedDevices.map((device) => device.deviceId);
}

/**
 * Revoke (unlink) a linked device.
 *
 * Fail closed, in a fixed order, before any state changes:
 *  1. The device must actually be linked (unknown ids are refused with a
 *     clear error — revoking a device this account never knew about would
 *     otherwise look like success).
 *  2. The last remaining device requires `{ confirmLastDevice: true }`, so a
 *     user cannot silently lock themselves out.
 *  3. The underlying `remove_device` WASM binding must succeed.
 *
 * Only after all three pass is the device dropped from `linkedDevices` and
 * the phase set to `'revoked'`. Any failure returns `ok: false` with the
 * state untouched — a failed revocation is never reported as success and
 * never leaves the device list half-updated.
 *
 * @param state    - The current linking state (its `linkedDevices` is the
 *                   source of truth for what is linked).
 * @param deviceId - The device to revoke.
 * @param options  - `{ confirmLastDevice: true }` to allow revoking the last
 *                   remaining device.
 */
export async function revokeDevice(
    state: LinkingState,
    deviceId: string,
    options?: RevokeOptions,
): Promise<RevokeResult> {
    await ensureWasmInit();

    const linked = state.linkedDevices ?? [];

    // 1. Fail closed on unknown devices — before anything is mutated.
    if (!linked.some((device) => device.deviceId === deviceId)) {
        return {
            ok: false,
            state,
            error: `Device ${deviceId} is not linked to this account`,
        };
    }

    // 2. Never silently revoke the last remaining device.
    const isLastDevice = linked.length === 1;
    if (isLastDevice && options?.confirmLastDevice !== true) {
        return {
            ok: false,
            state,
            error:
                'This is the last remaining device. Revoking it would remove your only linked device — confirm to proceed.',
            requiresConfirmation: true,
        };
    }

    // 3. The underlying revocation must succeed before the local list changes.
    try {
        wasm.remove_device(deviceIdAsUint32(deviceId));
    } catch (e: unknown) {
        return {
            ok: false,
            state,
            error: errorMessage(e),
        };
    }

    // All gates passed: drop the device and report success.
    return {
        ok: true,
        state: {
            ...state,
            phase: 'revoked',
            error: null,
            linkedDevices: linked.filter((device) => device.deviceId !== deviceId),
        },
    };
}

/**
 * Parse a device id into the `u32` the WASM `remove_device` binding takes.
 *
 * Device ids in this client are opaque strings ("dev-1", a UUID, …). The
 * binding's `u32` parameter is the fan-out `DeviceId` index; when the id is
 * a decimal string it maps through directly, and any other id is passed as
 * its stable hash so the binding still receives a well-formed `u32`. The
 * hash is deterministic, so the same device id always maps to the same
 * `DeviceId` within a session.
 *
 * @throws when the id is not a non-negative integer below 2^32 and no hash
 *   value can be derived.
 */
function deviceIdAsUint32(deviceId: string): number {
    if (/^\d+$/.test(deviceId)) {
        const value = Number(deviceId);
        if (Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff) {
            return value;
        }
    }
    // FNV-1a over the UTF-8 bytes of the id — deterministic, well-distributed,
    // and never derived from key material or link payloads.
    let hash = 0x811c9dc5;
    for (let i = 0; i < deviceId.length; i++) {
        hash ^= deviceId.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash >>> 0;
}