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
 *
 * ## Trust model of the response — read before persisting anything
 *
 * Decrypting the envelope only proves that *someone who could read the QR*
 * produced it: the link key is derived from the new device's own identity
 * public key, which the QR carries in the clear. Anyone who can read the QR
 * (shoulder-surfing, a screenshot, a malicious app on the new device, or the
 * relay itself) can derive the same link key, look up the published bundle,
 * and send a perfectly decryptable response. **The response is therefore NOT
 * authenticated to the legitimate primary device** — the QR carries no primary
 * key to compare against.
 *
 * Two checks narrow that gap but do not close it:
 *
 *  - the device list must carry a valid signature by the key the response
 *    itself names (`verify_device_list`), so a list signed by a *different*
 *    key can never escape; and
 *  - the verified list must contain this device's own identity key, so the
 *    response cannot link the device into an account it is not part of.
 *
 * An attacker who answers first with their own key and a list they signed
 * still passes both checks. A caller must not treat the result as trusted
 * without an out-of-band confirmation (a short code the user compares on both
 * devices) before persisting the device list or showing the account handle.
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
    /**
     * Verify a signed device list against the account key that must have signed
     * it (`core/bindings/wasm/src/device_list.rs`). Returns
     * `u64_le(version) || packed entries`; throws on a bad signature, a list
     * bound to another account, or a malformed blob.
     */
    verify_device_list(bytes: Uint8Array, expectedAccount: Uint8Array): Uint8Array;
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

/**
 * The primary device's answer to a link request, decrypted and validated.
 *
 * **Not authenticated to the legitimate primary device.** The QR payload
 * carries no primary key, so anyone who can read it can produce a response
 * that decrypts and passes every check here (see the module header). Treat the
 * result as untrusted until the user has confirmed an out-of-band code on both
 * devices.
 */
export interface LinkResponse {
    /**
     * Human-readable account handle the new device is being linked into.
     * Display-bound: bounded in length and free of control/bidi characters,
     * but still attacker-chosen until the response is confirmed out of band.
     */
    accountHandle: string;
    /** Id assigned to the new device in the account's device list. */
    deviceId: number;
    /**
     * The 33-byte compressed identity public key that signed
     * `signedListBytes`. Verified to have produced the list's signature, but
     * *not* proven to be the legitimate primary's key.
     */
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
    /**
     * This device's own 33-byte identity public key — the one encoded in the
     * QR payload. The verified device list must contain it, so a response can
     * never link this device into an account it is not part of.
     */
    newDevicePublicKey: Uint8Array;
    /** Maximum number of pickup attempts before giving up. Default 20. */
    maxAttempts?: number;
    /** Delay between attempts, in milliseconds. Default 250. */
    delayMs?: number;
    /**
     * Optional abort signal. Aborting rejects the wait instead of leaving the
     * caller hanging on a relay that accepts the socket and never answers.
     */
    signal?: AbortSignal;
}

/** Length of a compressed secp256k1 public key, in bytes. */
const PRIMARY_PUBLIC_KEY_BYTES = 33;
/** Length of a serialized (type-tagged) identity public key, in bytes. */
const IDENTITY_KEY_BYTES = 33;
/**
 * Type byte of a serialized Curve25519 identity public key.
 *
 * The review asked for a compressed-secp256k1 prefix check (0x02/0x03). That
 * would reject *every* legitimate response: the account/primary identity key
 * this protocol uses is a libsignal `IdentityKey`, serialized as a 33-byte
 * type-tagged Curve25519 key whose first byte is 0x05
 * (`core/bindings/wasm/src/device_list.rs`, `IDENTITY_KEY_LEN`). The intent —
 * fail here rather than in downstream crypto — is kept, with the correct
 * prefix.
 */
const IDENTITY_KEY_TYPE_BYTE = 0x05;
/** Longest account handle accepted: it is rendered in the linking UI. */
const MAX_ACCOUNT_HANDLE_LENGTH = 64;
/** Upper bound on a signed device list, so a hostile sender cannot amplify memory. */
const MAX_SIGNED_LIST_BYTES = 64 * 1024;
/** Bytes of the `u64_le` version prefix `verify_device_list` prepends. */
const VERSION_PREFIX_LEN = 8;
const HEX_PATTERN = /^[0-9a-fA-F]+$/;
/** C0/C1 control characters and bidi overrides: handle-spoofing and XSS vectors. */
const FORBIDDEN_HANDLE_CHARS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/;

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * `NotFound` is the relay's "nothing queued yet" signal — the only retryable
 * one.
 *
 * The relay is untrusted and `RelayError.message` is populated straight from
 * its `error` field, so this string match is only a *hint*: a hostile relay can
 * keep the client polling by answering `NotFound` forever, and a genuine
 * failure whose text happens to be `NotFound` is retried and then reported as
 * "no link response". A structured code set at the transport boundary would
 * remove the ambiguity; until then the match is deliberately narrow (exact
 * string, `RelayError` only) and bounded by `maxAttempts`.
 */
function isNotFound(error: unknown): boolean {
    return error instanceof RelayError && error.message === 'NotFound';
}

/**
 * Decode a hex string field, rejecting anything that is not well-formed hex.
 * `expectedBytes` pins the length when the field has a fixed size; `maxBytes`
 * caps it, and is checked *before* the bytes are materialized so an oversized
 * field cannot amplify memory.
 */
function requireHex(
    value: unknown,
    field: string,
    limits: { expectedBytes?: number; maxBytes?: number } = {},
): Uint8Array {
    const { expectedBytes, maxBytes } = limits;
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
    if (maxBytes !== undefined && value.length > maxBytes * 2) {
        throw new Error(`link response field "${field}" must be at most ${maxBytes} bytes`);
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Verify the device list's signature against the key the response names.
 *
 * Without this the response is only *decryptable*, not *authenticated*: a
 * device list signed by any other key would be persisted as if the primary had
 * issued it. The underlying error is not forwarded — its text is not needed by
 * the caller and the message must not carry list bytes.
 */
function verifySignedList(
    signedListBytes: Uint8Array,
    primaryPublicKey: Uint8Array,
): Uint8Array {
    try {
        return localWasm.verify_device_list(signedListBytes, primaryPublicKey);
    } catch {
        throw new Error('link response device list failed signature verification');
    }
}

/**
 * Whether the verified device list (`u64_le(version) || packed entries`) holds
 * an entry pairing `deviceId` with `identityKey`.
 *
 * Entry layout: `u32_le(device_id) | u32_le(identity_key_len) | identity_key |
 * u32_le(prekey_bundle_len) | prekey_bundle`. Bounds-checked: a truncated
 * buffer is an error, never a silent "not found".
 */
function listContainsDevice(
    verified: Uint8Array,
    deviceId: number,
    identityKey: Uint8Array,
): boolean {
    if (verified.length < VERSION_PREFIX_LEN) {
        throw new Error('link response device list is truncated');
    }
    const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
    let pos = VERSION_PREFIX_LEN;
    const readU32 = (): number => {
        if (pos + 4 > verified.length) throw new Error('link response device list is truncated');
        const value = view.getUint32(pos, true);
        pos += 4;
        return value;
    };
    const readBytes = (len: number): Uint8Array => {
        if (pos + len > verified.length) {
            throw new Error('link response device list is truncated');
        }
        const slice = verified.subarray(pos, pos + len);
        pos += len;
        return slice;
    };

    while (pos < verified.length) {
        const entryDeviceId = readU32();
        const entryKey = readBytes(readU32());
        readBytes(readU32()); // prekey bundle — not needed here
        if (
            entryDeviceId === deviceId &&
            entryKey.length === identityKey.length &&
            entryKey.every((byte, i) => byte === identityKey[i])
        ) {
            return true;
        }
    }
    return false;
}

/**
 * Parse and validate the decrypted response payload.
 *
 * Fail closed: every field is checked — including the device list's signature
 * and its binding to this device — before any of it is returned, so a
 * partially-valid payload never escapes as a usable result.
 */
function parseLinkResponse(plaintext: Uint8Array, newDevicePublicKey: Uint8Array): LinkResponse {
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
    if (accountHandle.length > MAX_ACCOUNT_HANDLE_LENGTH) {
        throw new Error(
            `link response field "accountHandle" must be at most ${MAX_ACCOUNT_HANDLE_LENGTH} characters`,
        );
    }
    if (FORBIDDEN_HANDLE_CHARS.test(accountHandle)) {
        throw new Error(
            'link response field "accountHandle" must not contain control or bidi characters',
        );
    }

    const deviceId = record.deviceId;
    if (typeof deviceId !== 'number' || !Number.isInteger(deviceId) || deviceId < 1) {
        throw new Error('link response field "deviceId" must be an integer >= 1');
    }

    const primaryPublicKey = requireHex(record.primaryPublicKeyHex, 'primaryPublicKeyHex', {
        expectedBytes: PRIMARY_PUBLIC_KEY_BYTES,
    });
    if (primaryPublicKey[0] !== IDENTITY_KEY_TYPE_BYTE) {
        throw new Error(
            'link response field "primaryPublicKeyHex" must be a type-tagged Curve25519 identity key (0x05)',
        );
    }

    const signedListBytes = requireHex(record.signedListBytesHex, 'signedListBytesHex', {
        maxBytes: MAX_SIGNED_LIST_BYTES,
    });

    const verifiedList = verifySignedList(signedListBytes, primaryPublicKey);
    if (!listContainsDevice(verifiedList, deviceId, newDevicePublicKey)) {
        throw new Error(
            'link response device list does not contain this device at the reported deviceId',
        );
    }

    return { accountHandle, deviceId, primaryPublicKey, signedListBytes };
}

/** Rejection reason used when the caller aborts the wait. */
const ABORT_MESSAGE = 'link response wait aborted';

function throwIfAborted(signal: AbortSignal | undefined): void {
    if (signal?.aborted) throw new Error(ABORT_MESSAGE);
}

/**
 * Settle with `promise`, or reject as soon as `signal` aborts.
 *
 * `pickupEnvelope` has no timeout of its own, so a relay that accepts the
 * socket and never answers would otherwise hang the linking flow forever.
 */
function withAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
    if (!signal) return promise;
    if (signal.aborted) return Promise.reject(new Error(ABORT_MESSAGE));
    return new Promise<T>((resolve, reject) => {
        const onAbort = () => reject(new Error(ABORT_MESSAGE));
        signal.addEventListener('abort', onAbort, { once: true });
        promise.then(
            (value) => {
                signal.removeEventListener('abort', onAbort);
                resolve(value);
            },
            (error: unknown) => {
                signal.removeEventListener('abort', onAbort);
                reject(error);
            },
        );
    });
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
    signal: AbortSignal | undefined,
): Promise<Uint8Array> {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        throwIfAborted(signal);
        try {
            return await withAbort(transport.pickupEnvelope(linkKey), signal);
        } catch (error) {
            if (!isNotFound(error)) throw error;
            if (attempt < maxAttempts) {
                await sleep(delayMs);
                throwIfAborted(signal);
            }
        }
    }
    throw new RelayError(`no link response after ${maxAttempts} attempts`);
}

/**
 * Wait for the primary device's link response, decrypt it with the receiver
 * session retained from `beginLinkRequest`, and return the validated payload.
 *
 * The result is **not authenticated to the legitimate primary device** — see
 * the module header. Confirm an out-of-band code before persisting anything.
 *
 * @throws {RelayError} if no response arrives within `maxAttempts` pickups, or
 *   if the relay reports any error other than `NotFound`.
 * @throws if the envelope cannot be decrypted (tampered or corrupted
 *   ciphertext), the decrypted payload is malformed, the device list's
 *   signature does not verify against `primaryPublicKey`, or the verified list
 *   does not contain `newDevicePublicKey`. None of these is retried.
 * @throws if `signal` aborts the wait.
 */
export async function awaitLinkResponse({
    transport,
    linkKey,
    receiverSession,
    newDevicePublicKey,
    maxAttempts = 20,
    delayMs = 250,
    signal,
}: AwaitLinkResponseOptions): Promise<LinkResponse> {
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
        throw new Error('maxAttempts must be an integer >= 1');
    }
    if (!Number.isFinite(delayMs) || delayMs < 0) {
        throw new Error('delayMs must be a finite number >= 0');
    }
    if (!(newDevicePublicKey instanceof Uint8Array) || newDevicePublicKey.length !== IDENTITY_KEY_BYTES) {
        throw new Error(`newDevicePublicKey must be a ${IDENTITY_KEY_BYTES}-byte Uint8Array`);
    }

    const envelope = await pickupWithRetry(transport, linkKey, maxAttempts, delayMs, signal);
    const plaintext = wasm.decrypt_message(receiverSession, envelope);
    return parseLinkResponse(plaintext, newDevicePublicKey);
}
