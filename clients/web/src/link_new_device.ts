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
 *
 * ## Verifying before persisting (MD-14)
 *
 * `verifyLinkResponse` is the boundary that turns a `LinkResponse` into the
 * version, `DeviceList`, and safety number a caller can act on. It re-runs
 * `verify_device_list` rather than trusting the object it is handed, converts
 * the packed entries with the shared decoder, requires the assigned device id
 * to be present in the verified list **and bound to this device's own identity
 * key**, and derives the safety number from `primaryPublicKey` and that same
 * local key. It **persists nothing**: the caller shows the safety number for
 * the out-of-band comparison and only persists after the user confirms it
 * (MD-16).
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { RelayError, type RelayTransport } from './relay_transport';
import { toConversationDeviceList } from './discovery';
import type { DeviceList } from './Conversation';

/**
 * The bindings this module needs that are not yet present in the checked-in
 * WASM package declarations (`clients/web/src/wasm-bindings.d.ts`). Declared
 * narrowly here and reached through a cast, mirroring how the rest of the web
 * client consumes not-yet-declared exports — the ambient declaration file is
 * deliberately left untouched. `derive_safety_number` is *not* listed: it is
 * already declared there (and in the generated package declarations), so it is
 * called through the ambient type to avoid a duplicate declaration drifting.
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
/**
 * Characters that must never reach the handle the user reads.
 *
 *  - C0/C1 controls: terminal escapes and XSS vectors.
 *  - U+061C (Arabic letter mark), U+200E/U+200F (LRM/RLM), U+202A-U+202E and
 *    U+2066-U+2069 (bidi embeddings/overrides/isolates): reorder the rendered
 *    text so the handle can read as something other than what it is.
 *  - U+200B-U+200D (zero-width space/joiners): invisible, so they let two
 *    distinct handles render identically.
 *  - U+2028/U+2029 (line/paragraph separators) and U+FEFF (zero-width no-break
 *    space): line breaks and invisible padding in a single-line label.
 */
const FORBIDDEN_HANDLE_CHARS =
    /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u2029\u202a-\u202e\u2066-\u2069\ufeff]/;

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
 * Validate the display-bound account handle.
 *
 * Shared by both response paths (`parseLinkResponse` and `verifyLinkResponse`)
 * so the checks cannot drift: the handle is rendered in the linking UI, so it
 * is bounded in length and free of control/bidi/zero-width characters that
 * would let an attacker spoof what the user reads while confirming the safety
 * number.
 *
 * The returned handle is **trimmed**: surrounding whitespace is never part of
 * the label, and returning it verbatim would let `" alice"` and `"alice"` — which
 * render identically — compare unequal downstream. The forbidden-character
 * check runs on the raw value first, so a forbidden character at either edge is
 * rejected rather than silently trimmed away.
 */
function validateAccountHandle(value: unknown): string {
    if (typeof value !== 'string') {
        throw new Error('link response field "accountHandle" must be a non-empty string');
    }
    if (FORBIDDEN_HANDLE_CHARS.test(value)) {
        throw new Error(
            'link response field "accountHandle" must not contain control or bidi characters',
        );
    }
    const handle = value.trim();
    if (handle.length === 0) {
        throw new Error('link response field "accountHandle" must be a non-empty string');
    }
    if (handle.length > MAX_ACCOUNT_HANDLE_LENGTH) {
        throw new Error(
            `link response field "accountHandle" must be at most ${MAX_ACCOUNT_HANDLE_LENGTH} characters`,
        );
    }
    return handle;
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

    const accountHandle = validateAccountHandle(record.accountHandle);

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

// ---------------------------------------------------------------------------
// Verifying the response before anything is persisted (MD-14)
// ---------------------------------------------------------------------------

export interface VerifyLinkResponseOptions {
    /** The response `awaitLinkResponse` returned. Treated as untrusted input. */
    response: LinkResponse;
    /**
     * The device id this device was assigned. Must be a positive integer and
     * must match the id the response reports.
     */
    expectedDeviceId: number;
    /** This device's own 33-byte identity public key. */
    localPublicKey: Uint8Array;
}

/** A link response whose device list has been re-verified and converted. */
export interface VerifiedLinkResponse {
    accountHandle: string;
    deviceId: number;
    /** The key that signed the list — *not* proven to be the legitimate primary. */
    primaryKey: Uint8Array;
    /** Version the verified list was signed at. */
    version: number;
    /** The verified, converted device list. */
    deviceList: DeviceList;
    /**
     * Out-of-band code the user compares on both devices. Until it matches,
     * nothing here may be persisted (MD-16).
     */
    safetyNumber: string;
}

/**
 * Re-verify a link response's signed device list and convert it for display.
 *
 * `awaitLinkResponse` already verified the list, but this is a public boundary
 * that accepts a caller-supplied object, so it verifies again rather than
 * trusting the caller: `signedListBytes` must carry a valid signature by
 * `response.primaryPublicKey`, and the verified list must contain the assigned
 * device id bound to `localPublicKey` (byte-for-byte) with a well-formed
 * identity key. The account handle is re-validated with the same display-bound
 * rules as `parseLinkResponse`. Any failure throws — no partial result and no
 * unverified `DeviceList` is ever returned.
 *
 * **This function persists nothing.** The response is not authenticated to the
 * legitimate primary device (the QR carries no primary key), so the caller must
 * show `safetyNumber` for an out-of-band comparison and only persist after the
 * user confirms it (MD-16).
 *
 * **Version monotonicity is the caller's job.** `version` is returned as-is and
 * is not compared against a held version (there is none at link bootstrap). The
 * persisting caller (MD-16) must seed its held version from this value;
 * otherwise a later rollback to an older signed list would be accepted as an
 * update (spec/v0.md §8.4, cf. `discovery.ts`).
 *
 * @throws if the response is structurally invalid, the list fails verification,
 *   the version prefix is truncated or out of range, the packed entries are
 *   malformed, the assigned id is missing from the list or bound to another
 *   key, or the safety number cannot be derived.
 */
export function verifyLinkResponse({
    response,
    expectedDeviceId,
    localPublicKey,
}: VerifyLinkResponseOptions): VerifiedLinkResponse {
    if (response === null || typeof response !== 'object' || Array.isArray(response)) {
        throw new Error('link response must be an object');
    }
    const { accountHandle, deviceId, primaryPublicKey, signedListBytes } = response;

    // Same display-bound validation as `parseLinkResponse`: the handle is shown
    // to the user while they confirm the safety number. The validated value is
    // the trimmed one, so it is what gets returned below.
    const validatedHandle = validateAccountHandle(accountHandle);
    if (!Number.isSafeInteger(deviceId) || deviceId < 1) {
        throw new Error('link response field "deviceId" must be a positive integer');
    }
    if (!Number.isSafeInteger(expectedDeviceId) || expectedDeviceId < 1) {
        throw new Error('expectedDeviceId must be a positive integer');
    }
    if (!(primaryPublicKey instanceof Uint8Array) || primaryPublicKey.length !== IDENTITY_KEY_BYTES) {
        throw new Error(`link response field "primaryPublicKey" must be a ${IDENTITY_KEY_BYTES}-byte Uint8Array`);
    }
    if (primaryPublicKey[0] !== IDENTITY_KEY_TYPE_BYTE) {
        throw new Error(
            'link response field "primaryPublicKey" must be a type-tagged Curve25519 identity key (0x05)',
        );
    }
    if (!(signedListBytes instanceof Uint8Array)) {
        throw new Error('link response field "signedListBytes" must be a Uint8Array');
    }
    // Cap before the bytes reach WASM: an unbounded caller-supplied buffer is
    // copied into the module, so a hostile caller could amplify memory.
    if (signedListBytes.length > MAX_SIGNED_LIST_BYTES) {
        throw new Error(
            `link response field "signedListBytes" must be at most ${MAX_SIGNED_LIST_BYTES} bytes`,
        );
    }
    if (!(localPublicKey instanceof Uint8Array) || localPublicKey.length !== IDENTITY_KEY_BYTES) {
        throw new Error(`localPublicKey must be a ${IDENTITY_KEY_BYTES}-byte Uint8Array`);
    }
    // Fail here rather than in downstream crypto: a key that is not a
    // type-tagged Curve25519 identity key cannot be this device's own key, so
    // the binding check below would be comparing against garbage.
    if (localPublicKey[0] !== IDENTITY_KEY_TYPE_BYTE) {
        throw new Error(
            'localPublicKey must be a type-tagged Curve25519 identity key (0x05)',
        );
    }

    // 1. Re-verify. Any throw propagates: unverified bytes never become a list.
    const verified = localWasm.verify_device_list(signedListBytes, primaryPublicKey);

    // 2. Read the `u64_le` version prefix, bounds-checked.
    if (!(verified instanceof Uint8Array) || verified.length < VERSION_PREFIX_LEN) {
        throw new Error('link response: verified device list is truncated');
    }
    const view = new DataView(verified.buffer, verified.byteOffset, verified.byteLength);
    const rawVersion = view.getBigUint64(0, true);
    if (rawVersion > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('link response: device list version is out of range');
    }
    const version = Number(rawVersion);

    // 3. Convert the packed entries with the shared decoder.
    const deviceList = toConversationDeviceList(version, verified.subarray(VERSION_PREFIX_LEN));

    // 4. The list must contain the id the response reports *and* the id the
    //    caller expects; a disagreement means the response is not for us.
    if (deviceId !== expectedDeviceId) {
        throw new Error('link response: assigned device id does not match the expected id');
    }
    const assigned = deviceList.devices.find((device) => device.deviceId === expectedDeviceId);
    if (assigned === undefined) {
        throw new Error('link response: verified device list does not contain the assigned device id');
    }
    if (!(assigned.identityKey instanceof Uint8Array) || assigned.identityKey.length !== IDENTITY_KEY_BYTES) {
        throw new Error('link response: assigned device entry has a malformed identity key');
    }
    // Bind the entry to *this* device. Without this, a validly-signed list could
    // pair the assigned id with an attacker-chosen key: the caller would persist
    // a list in which "this device" is the attacker's, while the safety number
    // is still derived from the honest local key — so the out-of-band comparison
    // would not cover the list entry it is supposed to vouch for.
    if (!assigned.identityKey.every((byte, i) => byte === localPublicKey[i])) {
        throw new Error(
            'link response: assigned device entry identity key does not match this device',
        );
    }

    // 5. The out-of-band code the user compares before anything is persisted.
    //    Symmetric in its arguments; derived from the honest local key, which is
    //    why step 4 must bind the list entry to that same key.
    const safetyNumber = wasm.derive_safety_number(primaryPublicKey, localPublicKey);

    return {
        accountHandle: validatedHandle,
        deviceId,
        primaryKey: primaryPublicKey,
        version,
        deviceList,
        safetyNumber,
    };
}
