/**
 * New-device link request (MD-10, web client).
 *
 * A device that wants to be linked creates a *receiver* session, publishes its
 * prekey bundle to the relay under a **derived link key** (never under its
 * identity public key), and shows a QR payload encoding its identity public
 * key. The primary device scans that QR, derives the same link key from the
 * scanned public key, looks the bundle up, and establishes a sender session
 * against it — so the new device can decrypt the response with the receiver
 * session retained here.
 *
 * Security properties:
 *  - The relay only ever sees the derived link key as the recipient id, so the
 *    identity public key is not exposed to the relay as a lookup handle.
 *  - The receiver session returned by `create_receiver_session` is the exact
 *    session whose bundle is published and the exact session handed back to
 *    the caller. (`generate_prekey_bundle` would produce bundle bytes without
 *    retaining that session, leaving the response undecryptable.)
 *  - The QR payload is produced only after publication succeeds: a failed
 *    publish rejects the whole request and yields no QR.
 *  - No key material is ever logged.
 *
 * ## Picking up the response (MD-13)
 *
 * Once the primary device has processed the QR it sends an encrypted response
 * envelope to the same derived link key. `awaitLinkResponse` polls the relay
 * for that envelope, decrypts it with the retained receiver session, and
 * validates the decoded payload before handing anything back:
 *
 *  - `NotFound` is the *expected* "not sent yet" outcome and is retried up to
 *    `maxAttempts` times, `delayMs` apart. Every other relay error is surfaced
 *    immediately — a broken relay must not be retried into a timeout.
 *  - A decrypt failure (tampered/corrupted ciphertext) or a malformed payload
 *    rejects immediately; nothing is retried and no partial result is
 *    returned, so a bad response can never be mistaken for a good one.
 *  - The plaintext and the key bytes it carries are never logged.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { RelayError, type RelayTransport } from './relay_transport';

/**
 * The one binding this module needs that is not yet present in the checked-in
 * WASM package declarations (`clients/web/src/wasm-bindings.d.ts`). Declared
 * narrowly here and reached through a cast, mirroring how the rest of the web
 * client consumes not-yet-declared exports — the ambient declaration file is
 * deliberately left untouched.
 */
interface LocalBindings {
    derive_link_key(publicKey: Uint8Array): string;
}

const localWasm = wasm as unknown as LocalBindings;

export interface LinkRequest {
    /** Hex QR payload encoding this device's 33-byte identity public key. */
    qrPayload: string;
    /** Relay recipient id the bundle was published under. */
    linkKey: string;
    /** Receiver session that will decrypt the primary device's response. */
    receiverSession: SessionHandle;
    /** The published prekey bundle bytes. */
    bundleBytes: Uint8Array;
}

/**
 * Create a receiver session, publish its bundle under the derived link key,
 * and return the QR payload the primary device scans.
 *
 * @throws if the relay rejects the publication; no QR payload is produced and
 *   no state is retained, so the caller may simply retry.
 */
export async function beginLinkRequest(
    transport: RelayTransport,
    identityHandle: IdentityHandle,
): Promise<LinkRequest> {
    const receiverSession = wasm.create_receiver_session(identityHandle);
    const bundleBytes = wasm.publish_bundle_bytes(receiverSession);

    const publicKeyBytes = identityHandle.public_bytes();
    const linkKey = localWasm.derive_link_key(publicKeyBytes);

    await transport.publishPrekey(linkKey, bundleBytes);

    const qrPayload = wasm.encode_device_qr(publicKeyBytes);

    return { qrPayload, linkKey, receiverSession, bundleBytes };
}

// ── Link response (MD-13) ────────────────────────────────────────────────────

/** The primary device's answer to a link request, decrypted and validated. */
export interface LinkResponse {
    /** Human-readable account handle the new device is being linked into. */
    accountHandle: string;
    /** Id assigned to the new device in the account's device list. */
    deviceId: number;
    /** The primary device's 33-byte identity public key. */
    primaryPublicKey: Uint8Array;
    /** The signed device-list bytes the new device must persist. */
    signedListBytes: Uint8Array;
}

export interface AwaitLinkResponseOptions {
    transport: RelayTransport;
    /** Relay recipient id the response is addressed to (the derived link key). */
    linkKey: string;
    /** Receiver session retained from `beginLinkRequest`. */
    receiverSession: SessionHandle;
    /** Maximum number of pickup attempts before giving up. Default 20. */
    maxAttempts?: number;
    /** Delay between attempts, in milliseconds. Default 250. */
    delayMs?: number;
}

/** Length of a compressed secp256k1 public key, in bytes. */
const PRIMARY_PUBLIC_KEY_BYTES = 33;
const HEX_PATTERN = /^[0-9a-fA-F]+$/;

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/** `NotFound` is the relay's "nothing queued yet" signal — the only retryable one. */
function isNotFound(error: unknown): boolean {
    return error instanceof RelayError && error.message === 'NotFound';
}

/**
 * Decode a hex string field, rejecting anything that is not well-formed hex.
 * `expectedBytes` pins the length when the field has a fixed size.
 */
function requireHex(value: unknown, field: string, expectedBytes?: number): Uint8Array {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length % 2 !== 0 ||
        !HEX_PATTERN.test(value)
    ) {
        throw new Error(`link response field "${field}" must be a non-empty hex string`);
    }
    if (expectedBytes !== undefined && value.length !== expectedBytes * 2) {
        throw new Error(
            `link response field "${field}" must be exactly ${expectedBytes * 2} hex characters`,
        );
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Parse and validate the decrypted response payload.
 *
 * Fail closed: every field is checked before any of it is returned, so a
 * partially-valid payload never escapes as a usable result.
 */
function parseLinkResponse(plaintext: Uint8Array): LinkResponse {
    let parsed: unknown;
    try {
        parsed = JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
        throw new Error('link response is not valid JSON');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('link response must be a JSON object');
    }
    const record = parsed as Record<string, unknown>;

    const accountHandle = record.accountHandle;
    if (typeof accountHandle !== 'string' || accountHandle.trim().length === 0) {
        throw new Error('link response field "accountHandle" must be a non-empty string');
    }

    const deviceId = record.deviceId;
    if (typeof deviceId !== 'number' || !Number.isInteger(deviceId) || deviceId < 1) {
        throw new Error('link response field "deviceId" must be an integer >= 1');
    }

    const primaryPublicKey = requireHex(
        record.primaryPublicKeyHex,
        'primaryPublicKeyHex',
        PRIMARY_PUBLIC_KEY_BYTES,
    );
    const signedListBytes = requireHex(record.signedListBytesHex, 'signedListBytesHex');

    return { accountHandle, deviceId, primaryPublicKey, signedListBytes };
}

/**
 * Poll the relay for the response envelope.
 *
 * Retries only on `NotFound`, at most `maxAttempts` pickups in total (so at
 * most `maxAttempts - 1` waits). Any other error — including `Expired` — is
 * surfaced immediately.
 */
async function pickupWithRetry(
    transport: RelayTransport,
    linkKey: string,
    maxAttempts: number,
    delayMs: number,
): Promise<Uint8Array> {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await transport.pickupEnvelope(linkKey);
        } catch (error) {
            if (!isNotFound(error)) throw error;
            if (attempt < maxAttempts) await sleep(delayMs);
        }
    }
    throw new RelayError(`no link response after ${maxAttempts} attempts`);
}

/**
 * Wait for the primary device's link response, decrypt it with the receiver
 * session retained from `beginLinkRequest`, and return the validated payload.
 *
 * @throws {RelayError} if no response arrives within `maxAttempts` pickups, or
 *   if the relay reports any error other than `NotFound`.
 * @throws if the envelope cannot be decrypted (tampered or corrupted
 *   ciphertext) or the decrypted payload is malformed. Neither is retried.
 */
export async function awaitLinkResponse({
    transport,
    linkKey,
    receiverSession,
    maxAttempts = 20,
    delayMs = 250,
}: AwaitLinkResponseOptions): Promise<LinkResponse> {
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
        throw new Error('maxAttempts must be an integer >= 1');
    }
    if (!Number.isFinite(delayMs) || delayMs < 0) {
        throw new Error('delayMs must be a finite number >= 0');
    }

    const envelope = await pickupWithRetry(transport, linkKey, maxAttempts, delayMs);
    const plaintext = wasm.decrypt_message(receiverSession, envelope);
    return parseLinkResponse(plaintext);
}
