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
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from './relay_transport';

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
