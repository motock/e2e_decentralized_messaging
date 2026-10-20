/**
 * Tests for `beginLinkRequest` (MD-10): a new device publishes its prekey
 * bundle under a *derived link key* and shows a QR payload that encodes its
 * identity public key.
 *
 * The WASM namespace is partially mocked: `create_receiver_session`,
 * `publish_bundle_bytes` and `derive_link_key` are replaced (the checked-in
 * stale pkg does not export `derive_link_key` at all), while the real
 * `encode_device_qr` / `decode_device_qr` are preserved behind thin spies so
 * the QR round-trip is exercised for real.
 *
 * Security properties under test:
 *  - the bundle is published under `derive_link_key(public_bytes())`, never
 *    under the identity public key itself;
 *  - the receiver session returned by `create_receiver_session` is the one
 *    whose bundle is published AND the one handed back to the caller (using
 *    `generate_prekey_bundle` would lose it and make the response
 *    undecryptable);
 *  - the QR payload is only produced after publication succeeds, and a
 *    rejected publication rejects the whole request;
 *  - a failed attempt does not corrupt a later attempt;
 *  - neither the link key nor the identity key bytes ever reach the console.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import type { IdentityHandle, SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { RelayTransport } from './relay_transport';

/** Valid 33-byte compressed secp256k1 key (the generator point). */
const PUBLIC_KEY_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const PUBLIC_KEY_BYTES = Uint8Array.from(
    PUBLIC_KEY_HEX.match(/../g)!.map((pair) => parseInt(pair, 16)),
);
const DERIVED_LINK_KEY = '0123456789abcdef0123456789abcdef';
const BUNDLE_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

const mocks = vi.hoisted(() => ({
    create_receiver_session: vi.fn(),
    publish_bundle_bytes: vi.fn(),
    derive_link_key: vi.fn(),
    encode_device_qr: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        create_receiver_session: mocks.create_receiver_session,
        publish_bundle_bytes: mocks.publish_bundle_bytes,
        derive_link_key: mocks.derive_link_key,
        // Preserve the real QR encoder, but record calls so tests can prove
        // the payload is not computed before publication succeeds.
        encode_device_qr: (bytes: Uint8Array): string => {
            mocks.encode_device_qr(bytes);
            return actual.encode_device_qr(bytes);
        },
    };
});

const { beginLinkRequest } = await import('./link_new_device');

function makeIdentityHandle(): { handle: IdentityHandle; publicBytes: ReturnType<typeof vi.fn> } {
    const publicBytes = vi.fn(() => new Uint8Array(PUBLIC_KEY_BYTES));
    const handle = { public_bytes: publicBytes } as unknown as IdentityHandle;
    return { handle, publicBytes };
}

function makeTransport(publishPrekey: ReturnType<typeof vi.fn>): RelayTransport {
    return { publishPrekey } as unknown as RelayTransport;
}

/** Every textual form of the secret material that must never be logged. */
function forbiddenNeedles(): string[] {
    const decimal = Array.from(PUBLIC_KEY_BYTES);
    return [
        DERIVED_LINK_KEY,
        PUBLIC_KEY_HEX,
        PUBLIC_KEY_HEX.toUpperCase(),
        Buffer.from(PUBLIC_KEY_BYTES).toString('base64'),
        Buffer.from(DERIVED_LINK_KEY).toString('base64'),
        decimal.join(','),
        decimal.join(', '),
        JSON.stringify(decimal),
    ];
}

function consoleOutput(spies: ReturnType<typeof vi.fn>[]): string {
    return spies
        .flatMap((spy) => spy.mock.calls)
        .flat()
        .map((arg) => {
            if (typeof arg === 'string') return arg;
            try {
                return JSON.stringify(arg);
            } catch {
                return String(arg);
            }
        })
        .join('\n');
}

let consoleSpies: ReturnType<typeof vi.fn>[];

beforeEach(() => {
    mocks.create_receiver_session.mockReset();
    mocks.publish_bundle_bytes.mockReset();
    mocks.derive_link_key.mockReset();
    mocks.encode_device_qr.mockReset();

    mocks.derive_link_key.mockReturnValue(DERIVED_LINK_KEY);
    mocks.publish_bundle_bytes.mockReturnValue(BUNDLE_BYTES);

    consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => {}),
    );
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('beginLinkRequest', () => {
    it('publishes the bundle under the derived link key and returns a QR for the identity key', async () => {
        const receiverSession = { id: 'receiver-session-1' } as unknown as SessionHandle;
        mocks.create_receiver_session.mockReturnValue(receiverSession);

        const publishPrekey = vi.fn().mockResolvedValue(undefined);
        const transport = makeTransport(publishPrekey);
        const { handle, publicBytes } = makeIdentityHandle();

        const result = await beginLinkRequest(transport, handle);

        // The receiver session is created from the identity handle and is the
        // one whose bundle gets published.
        expect(mocks.create_receiver_session).toHaveBeenCalledTimes(1);
        expect(mocks.create_receiver_session).toHaveBeenCalledWith(handle);
        expect(mocks.publish_bundle_bytes).toHaveBeenCalledTimes(1);
        expect(mocks.publish_bundle_bytes).toHaveBeenCalledWith(receiverSession);

        // The link key is derived from the 33-byte identity public key, and it
        // (not the public key) is the relay's recipient id.
        expect(publicBytes).toHaveBeenCalledTimes(1);
        expect(mocks.derive_link_key).toHaveBeenCalledTimes(1);
        expect(mocks.derive_link_key).toHaveBeenCalledWith(PUBLIC_KEY_BYTES);

        expect(publishPrekey).toHaveBeenCalledTimes(1);
        expect(publishPrekey).toHaveBeenCalledWith(DERIVED_LINK_KEY, BUNDLE_BYTES);
        expect(BUNDLE_BYTES.length).toBeGreaterThan(0);

        // Publication happens before the QR payload is produced.
        expect(mocks.publish_bundle_bytes.mock.invocationCallOrder[0]).toBeLessThan(
            publishPrekey.mock.invocationCallOrder[0],
        );
        expect(publishPrekey.mock.invocationCallOrder[0]).toBeLessThan(
            mocks.encode_device_qr.mock.invocationCallOrder[0],
        );

        // The retained receiver session and bundle are handed back unchanged.
        expect(result.receiverSession).toBe(receiverSession);
        expect(result.bundleBytes).toBe(BUNDLE_BYTES);
        expect(result.linkKey).toBe(DERIVED_LINK_KEY);
        expect(typeof result.qrPayload).toBe('string');

        // The QR payload round-trips to the same 33-byte identity key.
        const decoded = wasm.decode_device_qr(result.qrPayload);
        expect(decoded.length).toBe(33);
        expect(Array.from(decoded)).toEqual(Array.from(PUBLIC_KEY_BYTES));

        const output = consoleOutput(consoleSpies);
        for (const needle of forbiddenNeedles()) {
            expect(output).not.toContain(needle);
        }
    });

    it('rejects when publication fails, emits no QR, and does not corrupt a later attempt', async () => {
        const failedSession = { id: 'receiver-session-failed' } as unknown as SessionHandle;
        mocks.create_receiver_session.mockReturnValueOnce(failedSession);

        const publishPrekey = vi
            .fn()
            .mockRejectedValueOnce(new Error('relay unavailable'))
            .mockResolvedValueOnce(undefined);
        const transport = makeTransport(publishPrekey);
        const { handle } = makeIdentityHandle();

        // No fulfilled result exists: the promise rejects with the exact error.
        const outcome = await beginLinkRequest(transport, handle).then(
            (value) => ({ fulfilled: true as const, value }),
            (error: unknown) => ({ fulfilled: false as const, error }),
        );
        expect(outcome.fulfilled).toBe(false);
        if (outcome.fulfilled) throw new Error('unreachable');
        expect(outcome.error).toBeInstanceOf(Error);
        expect((outcome.error as Error).message).toBe('relay unavailable');
        expect(outcome).not.toHaveProperty('value.qrPayload');

        // The QR payload is not computed before publication succeeds.
        expect(mocks.encode_device_qr).not.toHaveBeenCalled();
        expect(publishPrekey).toHaveBeenCalledTimes(1);
        expect(publishPrekey).toHaveBeenCalledWith(DERIVED_LINK_KEY, BUNDLE_BYTES);

        // A follow-up attempt with a fresh session succeeds independently.
        const freshSession = { id: 'receiver-session-2' } as unknown as SessionHandle;
        const freshBundle = new Uint8Array([0x01, 0x02, 0x03]);
        mocks.create_receiver_session.mockReturnValueOnce(freshSession);
        mocks.publish_bundle_bytes.mockReturnValueOnce(freshBundle);

        const result = await beginLinkRequest(transport, handle);

        expect(publishPrekey).toHaveBeenCalledTimes(2);
        expect(publishPrekey).toHaveBeenLastCalledWith(DERIVED_LINK_KEY, freshBundle);
        expect(result.receiverSession).toBe(freshSession);
        expect(result.receiverSession).not.toBe(failedSession);
        expect(result.bundleBytes).toBe(freshBundle);
        expect(result.linkKey).toBe(DERIVED_LINK_KEY);

        const decoded = wasm.decode_device_qr(result.qrPayload);
        expect(decoded.length).toBe(33);
        expect(Array.from(decoded)).toEqual(Array.from(PUBLIC_KEY_BYTES));

        const output = consoleOutput(consoleSpies);
        for (const needle of forbiddenNeedles()) {
            expect(output).not.toContain(needle);
        }
    });
});
