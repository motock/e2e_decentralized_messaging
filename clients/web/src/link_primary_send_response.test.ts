/**
 * Tests for `sendLinkResponse` (MD-12): the primary device sends the new device
 * the encrypted link response — the account handle, the assigned device id, the
 * primary's identity public key, and the signed device list.
 *
 * The WASM namespace is partially mocked. `establish_session_from_bundle` and
 * `encrypt_message` are replaced so the test can (a) prove the sender session is
 * established from the *new device's bundle* with the *primary's* identity
 * handle, and (b) capture the exact plaintext handed to the ratchet. The real
 * `derive_link_key` is not needed here — the link key is an input.
 *
 * Security properties under test:
 *  - the response is sent to the derived link key, exactly once;
 *  - what goes on the wire is the ratchet's ciphertext, never the JSON plaintext;
 *  - the plaintext is UTF-8 JSON carrying the account handle, device id, the
 *    primary's identity public key as hex, and the signed list as hex — the
 *    primary key is what the new device verifies the list against and derives
 *    the safety number from;
 *  - a malformed bundle rejects and nothing is sent;
 *  - neither the plaintext JSON nor any key bytes reach the console.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { LinkResponseTransport } from './link_primary';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** 33-byte serialized identity key: 0x05 type tag + 32 key bytes. */
function identityKey(fill: number): Uint8Array {
    return new Uint8Array(33).fill(fill);
}

const PRIMARY_PUBLIC = identityKey(0x05);
const PRIMARY_PUBLIC_HEX = Array.from(PRIMARY_PUBLIC, (b) => b.toString(16).padStart(2, '0')).join(
    '',
);

const NEW_DEVICE_BUNDLE = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const SIGNED_LIST_BYTES = new Uint8Array([0x99, 0x88, 0x77, 0x66]);
const SIGNED_LIST_HEX = '99887766';

const LINK_KEY = 'link-key-fixture';
const ACCOUNT_HANDLE = 'account-handle-fixture';
const DEVICE_ID = 3;

/** Ciphertext the mocked ratchet returns; deliberately not the plaintext. */
const CIPHERTEXT = new Uint8Array([0xc1, 0xfe, 0x00, 0x42]);

// ---------------------------------------------------------------------------
// WASM boundary mock
// ---------------------------------------------------------------------------

const mocks = vi.hoisted(() => ({
    establish_session_from_bundle: vi.fn(),
    encrypt_message: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        establish_session_from_bundle: mocks.establish_session_from_bundle,
        encrypt_message: mocks.encrypt_message,
    };
});

vi.mock('./wasm_init', () => ({
    ensureWasmInit: vi.fn(async () => undefined),
}));

const { sendLinkResponse } = await import('./link_primary');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePrimaryIdentityHandle(): {
    handle: IdentityHandle;
    publicBytes: ReturnType<typeof vi.fn>;
} {
    const publicBytes = vi.fn(() => new Uint8Array(PRIMARY_PUBLIC));
    const handle = { public_bytes: publicBytes } as unknown as IdentityHandle;
    return { handle, publicBytes };
}

function makeTransport(): {
    transport: LinkResponseTransport;
    sendEnvelope: ReturnType<typeof vi.fn>;
} {
    const sendEnvelope = vi.fn(async () => undefined);
    const transport = { sendEnvelope } as unknown as LinkResponseTransport;
    return { transport, sendEnvelope };
}

/** Decode the plaintext the mocked ratchet was handed. */
function capturedPlaintext(): Uint8Array {
    expect(mocks.encrypt_message).toHaveBeenCalledTimes(1);
    return mocks.encrypt_message.mock.calls[0][1] as Uint8Array;
}

/** Flatten every console spy's recorded arguments into one searchable string. */
function loggedText(spies: ReturnType<typeof vi.spyOn>[]): string {
    return spies
        .flatMap((spy) => spy.mock.calls as unknown[][])
        .map((args) => args.map((arg) => (typeof arg === 'string' ? arg : String(arg))).join(' '))
        .join('\n');
}

beforeEach(() => {
    mocks.establish_session_from_bundle.mockReset();
    mocks.encrypt_message.mockReset();
    mocks.establish_session_from_bundle.mockReturnValue({} as SessionHandle);
    mocks.encrypt_message.mockReturnValue(new Uint8Array(CIPHERTEXT));
});

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

describe('sendLinkResponse', () => {
    it('sends the ratchet ciphertext to the link key exactly once', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport, sendEnvelope } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        expect(sendEnvelope).toHaveBeenCalledTimes(1);
        const [recipientId, envelope] = sendEnvelope.mock.calls[0];
        expect(recipientId).toBe(LINK_KEY);
        expect(envelope).toEqual(CIPHERTEXT);
    });

    it('never puts the JSON plaintext on the wire', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport, sendEnvelope } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        const [, envelope] = sendEnvelope.mock.calls[0];
        const plaintext = capturedPlaintext();
        expect(envelope).not.toEqual(plaintext);
        // The plaintext is JSON text; the envelope must not contain it verbatim.
        expect(Buffer.from(envelope as Uint8Array).includes(Buffer.from(plaintext))).toBe(false);
    });

    it('establishes the sender session from the new bundle with the primary identity', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        expect(mocks.establish_session_from_bundle).toHaveBeenCalledTimes(1);
        const [identityArg, bundleArg] = mocks.establish_session_from_bundle.mock.calls[0];
        expect(identityArg).toBe(handle);
        expect(bundleArg).toEqual(NEW_DEVICE_BUNDLE);
    });

    it('encrypts a UTF-8 JSON payload with the account handle, device id and hex keys', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        const plaintext = capturedPlaintext();
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
        expect(JSON.parse(decoded)).toEqual({
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            primaryPublicKeyHex: PRIMARY_PUBLIC_HEX,
            signedListBytesHex: SIGNED_LIST_HEX,
        });
    });

    it('encrypts with the session it just established', async () => {
        const session = { id: 'sender-session' } as unknown as SessionHandle;
        mocks.establish_session_from_bundle.mockReturnValue(session);
        const { handle } = makePrimaryIdentityHandle();
        const { transport } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        expect(mocks.encrypt_message).toHaveBeenCalledTimes(1);
        expect(mocks.encrypt_message.mock.calls[0][0]).toBe(session);
    });

    it('propagates a send failure', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport, sendEnvelope } = makeTransport();
        sendEnvelope.mockRejectedValueOnce(new Error('relay unavailable'));

        await expect(
            sendLinkResponse({
                transport,
                linkKey: LINK_KEY,
                newDeviceBundle: NEW_DEVICE_BUNDLE,
                primaryIdentityHandle: handle,
                accountHandle: ACCOUNT_HANDLE,
                deviceId: DEVICE_ID,
                signedListBytes: SIGNED_LIST_BYTES,
            }),
        ).rejects.toThrow('relay unavailable');
    });
});

// ---------------------------------------------------------------------------
// Negative path
// ---------------------------------------------------------------------------

describe('sendLinkResponse (negative)', () => {
    it('rejects a malformed bundle and sends nothing', async () => {
        mocks.establish_session_from_bundle.mockImplementation(() => {
            throw new Error('malformed or truncated prekey bundle bytes');
        });
        const { handle } = makePrimaryIdentityHandle();
        const { transport, sendEnvelope } = makeTransport();

        await expect(
            sendLinkResponse({
                transport,
                linkKey: LINK_KEY,
                newDeviceBundle: new Uint8Array([0x00]),
                primaryIdentityHandle: handle,
                accountHandle: ACCOUNT_HANDLE,
                deviceId: DEVICE_ID,
                signedListBytes: SIGNED_LIST_BYTES,
            }),
        ).rejects.toThrow('malformed or truncated prekey bundle bytes');

        expect(sendEnvelope).not.toHaveBeenCalled();
        expect(mocks.encrypt_message).not.toHaveBeenCalled();
    });

    it('sends nothing when encryption fails', async () => {
        mocks.encrypt_message.mockImplementation(() => {
            throw new Error('session is receiver-only');
        });
        const { handle } = makePrimaryIdentityHandle();
        const { transport, sendEnvelope } = makeTransport();

        await expect(
            sendLinkResponse({
                transport,
                linkKey: LINK_KEY,
                newDeviceBundle: NEW_DEVICE_BUNDLE,
                primaryIdentityHandle: handle,
                accountHandle: ACCOUNT_HANDLE,
                deviceId: DEVICE_ID,
                signedListBytes: SIGNED_LIST_BYTES,
            }),
        ).rejects.toThrow('session is receiver-only');

        expect(sendEnvelope).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// No sensitive data in logs
// ---------------------------------------------------------------------------

describe('sendLinkResponse (logging)', () => {
    const spies: ReturnType<typeof vi.spyOn>[] = [];

    beforeEach(() => {
        for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
            spies.push(vi.spyOn(console, method).mockImplementation(() => undefined));
        }
    });

    afterEach(() => {
        for (const spy of spies.splice(0)) {
            spy.mockRestore();
        }
    });

    it('never logs the plaintext JSON or the key bytes', async () => {
        const { handle } = makePrimaryIdentityHandle();
        const { transport } = makeTransport();

        await sendLinkResponse({
            transport,
            linkKey: LINK_KEY,
            newDeviceBundle: NEW_DEVICE_BUNDLE,
            primaryIdentityHandle: handle,
            accountHandle: ACCOUNT_HANDLE,
            deviceId: DEVICE_ID,
            signedListBytes: SIGNED_LIST_BYTES,
        });

        const plaintext = new TextDecoder().decode(capturedPlaintext());
        const logged = loggedText(spies);

        expect(logged).not.toContain(plaintext);
        expect(logged).not.toContain(PRIMARY_PUBLIC_HEX);
        expect(logged).not.toContain(SIGNED_LIST_HEX);
        expect(logged).not.toContain(LINK_KEY);
    });

    it('never logs the plaintext JSON on the failure path', async () => {
        mocks.establish_session_from_bundle.mockImplementation(() => {
            throw new Error('malformed or truncated prekey bundle bytes');
        });
        const { handle } = makePrimaryIdentityHandle();
        const { transport } = makeTransport();

        await expect(
            sendLinkResponse({
                transport,
                linkKey: LINK_KEY,
                newDeviceBundle: new Uint8Array([0x00]),
                primaryIdentityHandle: handle,
                accountHandle: ACCOUNT_HANDLE,
                deviceId: DEVICE_ID,
                signedListBytes: SIGNED_LIST_BYTES,
            }),
        ).rejects.toThrow();

        const logged = loggedText(spies);

        expect(logged).not.toContain(ACCOUNT_HANDLE);
        expect(logged).not.toContain(PRIMARY_PUBLIC_HEX);
        expect(logged).not.toContain(LINK_KEY);
    });
});
