/**
 * Tests for `awaitLinkResponse` (MD-13): the new device polls the relay for the
 * primary device's link response, decrypts it with the receiver session it
 * retained from `beginLinkRequest`, and validates the payload.
 *
 * The WASM namespace is partially mocked. `decrypt_message` is replaced by a
 * stand-in that behaves like an authenticated cipher: the envelope carries a
 * one-byte authentication tag ahead of the plaintext, and a wrong tag throws —
 * exactly how a real AEAD rejects tampered ciphertext. Everything else comes
 * from the real package.
 *
 * Security properties under test:
 *  - only `NotFound` is retried; every other relay error is surfaced at once;
 *  - a corrupted ciphertext or a malformed payload rejects immediately, with
 *    no retry and no partial result;
 *  - a response that never arrives rejects after exactly `maxAttempts`
 *    pickups (and `maxAttempts - 1` waits);
 *  - neither the decrypted plaintext nor the key bytes it carries are logged.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { RelayError, type RelayTransport } from './relay_transport';

/** Valid 33-byte compressed secp256k1 key (the generator point). */
const PRIMARY_PUBLIC_KEY_HEX =
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SIGNED_LIST_BYTES_HEX = '0a0b0c0d';
const LINK_KEY = '0123456789abcdef0123456789abcdef';
const ACCOUNT_HANDLE = 'alice';

/** Authentication tag the stand-in cipher requires on every envelope. */
const CIPHERTEXT_TAG = 0xa5;

const mocks = vi.hoisted(() => ({
    decrypt_message: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        decrypt_message: mocks.decrypt_message,
    };
});

const { awaitLinkResponse } = await import('./link_new_device');

const encoder = new TextEncoder();

/** The MD-12 response shape, as the primary device serialises it. */
function responsePayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        accountHandle: ACCOUNT_HANDLE,
        deviceId: 2,
        primaryPublicKeyHex: PRIMARY_PUBLIC_KEY_HEX,
        signedListBytesHex: SIGNED_LIST_BYTES_HEX,
        ...overrides,
    };
}

/** Wrap plaintext bytes in the stand-in cipher's authenticated envelope. */
function seal(plaintext: Uint8Array): Uint8Array {
    return Uint8Array.from([CIPHERTEXT_TAG, ...plaintext]);
}

function sealJson(payload: unknown): Uint8Array {
    return seal(encoder.encode(JSON.stringify(payload)));
}

function hexToBytes(hex: string): Uint8Array {
    return Uint8Array.from(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
}

function makeTransport(pickupEnvelope: ReturnType<typeof vi.fn>): RelayTransport {
    return { pickupEnvelope } as unknown as RelayTransport;
}

const receiverSession = { id: 'receiver-session-1' } as unknown as SessionHandle;

/** Every textual form of the secret material that must never be logged. */
function forbiddenNeedles(): string[] {
    const keyBytes = hexToBytes(PRIMARY_PUBLIC_KEY_HEX);
    const signedListBytes = hexToBytes(SIGNED_LIST_BYTES_HEX);
    return [
        PRIMARY_PUBLIC_KEY_HEX,
        PRIMARY_PUBLIC_KEY_HEX.toUpperCase(),
        SIGNED_LIST_BYTES_HEX,
        Buffer.from(keyBytes).toString('base64'),
        Buffer.from(signedListBytes).toString('base64'),
        Array.from(keyBytes).join(','),
        Array.from(keyBytes).join(', '),
        JSON.stringify(Array.from(keyBytes)),
        JSON.stringify(Array.from(signedListBytes)),
        LINK_KEY,
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
    mocks.decrypt_message.mockReset();
    // Stand-in authenticated decrypt: verify the tag, then strip it.
    mocks.decrypt_message.mockImplementation((_session: SessionHandle, envelope: Uint8Array) => {
        if (envelope.length === 0 || envelope[0] !== CIPHERTEXT_TAG) {
            throw new Error('decrypt failed: authentication tag mismatch');
        }
        return envelope.slice(1);
    });

    consoleSpies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
        vi.spyOn(console, method).mockImplementation(() => {}),
    );
});

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe('awaitLinkResponse', () => {
    it('decrypts and parses a response produced with the MD-12 shape', async () => {
        const envelope = sealJson(responsePayload());
        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const transport = makeTransport(pickupEnvelope);

        const result = await awaitLinkResponse({
            transport,
            linkKey: LINK_KEY,
            receiverSession,
        });

        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        expect(pickupEnvelope).toHaveBeenCalledWith(LINK_KEY);

        // The retained receiver session decrypts the envelope it was built for.
        expect(mocks.decrypt_message).toHaveBeenCalledTimes(1);
        expect(mocks.decrypt_message).toHaveBeenCalledWith(receiverSession, envelope);

        expect(result.accountHandle).toBe(ACCOUNT_HANDLE);
        expect(result.deviceId).toBe(2);
        expect(Array.from(result.primaryPublicKey)).toEqual(
            Array.from(hexToBytes(PRIMARY_PUBLIC_KEY_HEX)),
        );
        expect(result.primaryPublicKey.length).toBe(33);
        expect(Array.from(result.signedListBytes)).toEqual(
            Array.from(hexToBytes(SIGNED_LIST_BYTES_HEX)),
        );

        const output = consoleOutput(consoleSpies);
        for (const needle of forbiddenNeedles()) {
            expect(output).not.toContain(needle);
        }
    });

    it('retries on NotFound and succeeds once the response arrives', async () => {
        vi.useFakeTimers();
        const envelope = sealJson(responsePayload());
        const pickupEnvelope = vi
            .fn()
            .mockRejectedValueOnce(new RelayError('NotFound'))
            .mockRejectedValueOnce(new RelayError('NotFound'))
            .mockResolvedValueOnce(envelope);
        const transport = makeTransport(pickupEnvelope);

        const outcome = awaitLinkResponse({
            transport,
            linkKey: LINK_KEY,
            receiverSession,
            maxAttempts: 5,
            delayMs: 100,
        }).then(
            (value) => ({ fulfilled: true as const, value }),
            (error: unknown) => ({ fulfilled: false as const, error }),
        );

        // Nothing is picked up again before the delay has elapsed.
        await vi.advanceTimersByTimeAsync(99);
        expect(pickupEnvelope).toHaveBeenCalledTimes(1);

        await vi.advanceTimersByTimeAsync(1);
        expect(pickupEnvelope).toHaveBeenCalledTimes(2);

        await vi.advanceTimersByTimeAsync(1000);
        const settled = await outcome;

        expect(settled.fulfilled).toBe(true);
        if (!settled.fulfilled) throw new Error('unreachable');
        expect(settled.value.accountHandle).toBe(ACCOUNT_HANDLE);
        expect(pickupEnvelope).toHaveBeenCalledTimes(3);
        expect(pickupEnvelope).toHaveBeenNthCalledWith(1, LINK_KEY);
        expect(pickupEnvelope).toHaveBeenNthCalledWith(2, LINK_KEY);
        expect(pickupEnvelope).toHaveBeenNthCalledWith(3, LINK_KEY);
    });

    it('rejects immediately on a corrupted ciphertext, without retrying', async () => {
        const envelope = sealJson(responsePayload());
        // Flip the authentication tag: the ciphertext no longer authenticates.
        envelope[0] = 0x00;
        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow(/authentication tag mismatch/);

        // A decrypt failure is not a "not sent yet" signal: exactly one pickup.
        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        expect(mocks.decrypt_message).toHaveBeenCalledTimes(1);
    });

    it('rejects immediately on a payload that is not valid JSON', async () => {
        const pickupEnvelope = vi.fn().mockResolvedValue(seal(encoder.encode('not json at all')));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow(/not valid JSON/);

        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
    });

    it('rejects immediately on a non-object JSON payload', async () => {
        const pickupEnvelope = vi.fn().mockResolvedValue(sealJson([1, 2, 3]));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow(/must be a JSON object/);

        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
    });

    it('rejects after exactly maxAttempts pickups when the response never arrives', async () => {
        vi.useFakeTimers();
        const pickupEnvelope = vi.fn().mockRejectedValue(new RelayError('NotFound'));
        const transport = makeTransport(pickupEnvelope);

        const outcome = awaitLinkResponse({
            transport,
            linkKey: LINK_KEY,
            receiverSession,
            maxAttempts: 3,
            delayMs: 100,
        }).then(
            (value) => ({ fulfilled: true as const, value }),
            (error: unknown) => ({ fulfilled: false as const, error }),
        );

        // Two waits of 100ms separate the three attempts; 199ms is not enough.
        await vi.advanceTimersByTimeAsync(199);
        expect(pickupEnvelope).toHaveBeenCalledTimes(2);

        await vi.advanceTimersByTimeAsync(1);
        const settled = await outcome;

        expect(settled.fulfilled).toBe(false);
        if (settled.fulfilled) throw new Error('unreachable');
        expect(settled.error).toBeInstanceOf(RelayError);
        expect((settled.error as Error).message).toBe('no link response after 3 attempts');
        expect(pickupEnvelope).toHaveBeenCalledTimes(3);
        // The exhausted poll never decrypts anything.
        expect(mocks.decrypt_message).not.toHaveBeenCalled();
    });

    it('surfaces a non-NotFound relay error immediately, without retrying', async () => {
        vi.useFakeTimers();
        const pickupEnvelope = vi.fn().mockRejectedValue(new RelayError('Expired'));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
                maxAttempts: 5,
                delayMs: 100,
            }),
        ).rejects.toThrow('Expired');

        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        expect(vi.getTimerCount()).toBe(0);
    });

    it('surfaces a non-relay transport error immediately, without retrying', async () => {
        const pickupEnvelope = vi.fn().mockRejectedValue(new Error('socket closed'));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow('socket closed');

        expect(pickupEnvelope).toHaveBeenCalledTimes(1);
    });

    describe('payload validation', () => {
        const cases: Array<[string, Record<string, unknown>, RegExp]> = [
            ['a missing accountHandle', { accountHandle: undefined }, /accountHandle/],
            ['an empty accountHandle', { accountHandle: '' }, /accountHandle/],
            ['a whitespace-only accountHandle', { accountHandle: '   ' }, /accountHandle/],
            ['a non-string accountHandle', { accountHandle: 42 }, /accountHandle/],
            ['a missing deviceId', { deviceId: undefined }, /deviceId/],
            ['a zero deviceId', { deviceId: 0 }, /deviceId/],
            ['a negative deviceId', { deviceId: -1 }, /deviceId/],
            ['a fractional deviceId', { deviceId: 1.5 }, /deviceId/],
            ['a string deviceId', { deviceId: '2' }, /deviceId/],
            [
                'a primaryPublicKeyHex that is too short',
                { primaryPublicKeyHex: PRIMARY_PUBLIC_KEY_HEX.slice(2) },
                /primaryPublicKeyHex/,
            ],
            [
                'a primaryPublicKeyHex that is too long',
                { primaryPublicKeyHex: `${PRIMARY_PUBLIC_KEY_HEX}00` },
                /primaryPublicKeyHex/,
            ],
            [
                'a non-hex primaryPublicKeyHex',
                { primaryPublicKeyHex: 'z'.repeat(66) },
                /primaryPublicKeyHex/,
            ],
            ['a missing primaryPublicKeyHex', { primaryPublicKeyHex: undefined }, /primaryPublicKeyHex/],
            ['a missing signedListBytesHex', { signedListBytesHex: undefined }, /signedListBytesHex/],
            ['an odd-length signedListBytesHex', { signedListBytesHex: 'abc' }, /signedListBytesHex/],
            ['a non-hex signedListBytesHex', { signedListBytesHex: 'zz' }, /signedListBytesHex/],
        ];

        it.each(cases)('rejects %s', async (_label, overrides, expected) => {
            const pickupEnvelope = vi
                .fn()
                .mockResolvedValue(sealJson(responsePayload(overrides)));
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(expected);

            // A malformed payload is never retried.
            expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        });

        it('accepts a deviceId of exactly 1 and an empty signed-list payload', async () => {
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(responsePayload({ deviceId: 1, signedListBytesHex: '00' })),
            );
            const transport = makeTransport(pickupEnvelope);

            const result = await awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
            });

            expect(result.deviceId).toBe(1);
            expect(Array.from(result.signedListBytes)).toEqual([0x00]);
        });

        it('accepts uppercase hex', async () => {
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        primaryPublicKeyHex: PRIMARY_PUBLIC_KEY_HEX.toUpperCase(),
                        signedListBytesHex: SIGNED_LIST_BYTES_HEX.toUpperCase(),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            const result = await awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
            });

            expect(Array.from(result.primaryPublicKey)).toEqual(
                Array.from(hexToBytes(PRIMARY_PUBLIC_KEY_HEX)),
            );
            expect(Array.from(result.signedListBytes)).toEqual(
                Array.from(hexToBytes(SIGNED_LIST_BYTES_HEX)),
            );
        });
    });

    describe('option validation', () => {
        it.each([
            ['maxAttempts of 0', { maxAttempts: 0 }, /maxAttempts/],
            ['a negative maxAttempts', { maxAttempts: -1 }, /maxAttempts/],
            ['a fractional maxAttempts', { maxAttempts: 1.5 }, /maxAttempts/],
            ['a negative delayMs', { delayMs: -1 }, /delayMs/],
            ['a non-finite delayMs', { delayMs: Number.POSITIVE_INFINITY }, /delayMs/],
        ])('rejects %s without touching the relay', async (_label, overrides, expected) => {
            const pickupEnvelope = vi.fn();
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({
                    transport,
                    linkKey: LINK_KEY,
                    receiverSession,
                    ...overrides,
                }),
            ).rejects.toThrow(expected);

            expect(pickupEnvelope).not.toHaveBeenCalled();
        });
    });

    it('never logs the plaintext or the key bytes on a rejected payload', async () => {
        const pickupEnvelope = vi
            .fn()
            .mockResolvedValue(sealJson(responsePayload({ deviceId: 0 })));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow(/deviceId/);

        const output = consoleOutput(consoleSpies);
        for (const needle of forbiddenNeedles()) {
            expect(output).not.toContain(needle);
        }
    });
});
