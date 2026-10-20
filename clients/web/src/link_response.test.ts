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
import { createHash } from 'node:crypto';
import type { SessionHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { RelayError, type RelayTransport } from './relay_transport';

/**
 * The primary's 33-byte identity public key: a libsignal `IdentityKey`
 * serialized as a type-tagged Curve25519 key (0x05 prefix), which is what the
 * protocol actually puts on the wire.
 */
const PRIMARY_PUBLIC_KEY_HEX = '05' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
/** This device's own 33-byte identity public key (type-tagged Curve25519). */
const NEW_DEVICE_KEY_HEX = '05' + '11'.repeat(32);
/** A different device's identity key, used to build lists that omit ours. */
const OTHER_DEVICE_KEY_HEX = '05' + '22'.repeat(32);
const LINK_KEY = '0123456789abcdef0123456789abcdef';
const ACCOUNT_HANDLE = 'alice';

/** Authentication tag the stand-in cipher requires on every envelope. */
const CIPHERTEXT_TAG = 0xa5;

const mocks = vi.hoisted(() => ({
    decrypt_message: vi.fn(),
    verify_device_list: vi.fn(),
}));

vi.mock('../../../core/bindings/wasm/pkg/index.js', async (importOriginal) => {
    const actual = await importOriginal<
        typeof import('../../../core/bindings/wasm/pkg/index.js')
    >();
    return {
        ...actual,
        decrypt_message: mocks.decrypt_message,
        verify_device_list: mocks.verify_device_list,
    };
});

const { awaitLinkResponse: awaitLinkResponseRaw } = await import('./link_new_device');

const encoder = new TextEncoder();
const newDevicePublicKey = hexToBytes(NEW_DEVICE_KEY_HEX);

/**
 * Test-local wrapper: every call supplies this device's identity key, which the
 * verified device list must contain. A test may still override it explicitly.
 */
function awaitLinkResponse(
    options: Omit<Parameters<typeof awaitLinkResponseRaw>[0], 'newDevicePublicKey'> & {
        newDevicePublicKey?: Uint8Array;
    },
) {
    return awaitLinkResponseRaw({ newDevicePublicKey, ...options });
}

// ── Signed device list stand-in ──────────────────────────────────────────────
//
// The real `verify_device_list` checks a signature over the list, bound to the
// account key, and returns `u64_le(version) || packed entries`. The fake below
// models exactly that contract: the blob is `payload || sha256(payload ||
// accountKey)`, so a list signed by a foreign key fails verification just as it
// would in the Rust core.

interface FakeEntry {
    deviceId: number;
    identityKey: Uint8Array;
}

function u32le(value: number): number[] {
    return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

function u64le(value: number): number[] {
    return [...u32le(value), 0, 0, 0, 0];
}

/** `u64_le(version) || packed entries`, the layout `verify_device_list` returns. */
function packList(version: number, entries: FakeEntry[]): Uint8Array {
    const out: number[] = u64le(version);
    for (const entry of entries) {
        out.push(...u32le(entry.deviceId));
        out.push(...u32le(entry.identityKey.length), ...entry.identityKey);
        out.push(...u32le(0)); // empty prekey bundle
    }
    return Uint8Array.from(out);
}

function signature(payload: Uint8Array, accountKey: Uint8Array): Uint8Array {
    const hash = createHash('sha256');
    hash.update(payload);
    hash.update(accountKey);
    return new Uint8Array(hash.digest());
}

/** Sign a list with `accountKey`, producing the on-the-wire blob. */
function signList(
    accountKey: Uint8Array,
    version: number,
    entries: FakeEntry[],
): Uint8Array {
    const payload = packList(version, entries);
    const sig = signature(payload, accountKey);
    return Uint8Array.from([...payload, ...sig]);
}

/** The list the primary device would send: it contains this new device. */
const SIGNED_LIST_BYTES = signList(hexToBytes(PRIMARY_PUBLIC_KEY_HEX), 7, [
    { deviceId: 1, identityKey: hexToBytes(OTHER_DEVICE_KEY_HEX) },
    { deviceId: 2, identityKey: newDevicePublicKey },
]);
const SIGNED_LIST_BYTES_HEX = Buffer.from(SIGNED_LIST_BYTES).toString('hex');

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

    mocks.verify_device_list.mockReset();
    // Stand-in signature check: the blob must carry a signature by the account
    // key the caller expects, and the payload is returned as the verified list.
    mocks.verify_device_list.mockImplementation(
        (bytes: Uint8Array, expectedAccount: Uint8Array) => {
            if (expectedAccount.length !== 33) {
                throw new Error('DeviceList: BadAccountLength');
            }
            if (bytes.length < 32) {
                throw new Error('DeviceList: Truncated');
            }
            const payload = bytes.subarray(0, bytes.length - 32);
            const sig = bytes.subarray(bytes.length - 32);
            const expected = signature(payload, expectedAccount);
            if (!sig.every((byte, i) => byte === expected[i])) {
                throw new Error('DeviceList: WrongAccount');
            }
            return payload;
        },
    );

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

        it('accepts a deviceId of exactly 1', async () => {
            const list = signList(hexToBytes(PRIMARY_PUBLIC_KEY_HEX), 1, [
                { deviceId: 1, identityKey: newDevicePublicKey },
            ]);
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        deviceId: 1,
                        signedListBytesHex: Buffer.from(list).toString('hex'),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            const result = await awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
            });

            expect(result.deviceId).toBe(1);
            expect(Array.from(result.signedListBytes)).toEqual(Array.from(list));
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

    describe('device-list authentication', () => {
        it('verifies the list against the key the response names', async () => {
            const pickupEnvelope = vi.fn().mockResolvedValue(sealJson(responsePayload()));
            const transport = makeTransport(pickupEnvelope);

            await awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession });

            expect(mocks.verify_device_list).toHaveBeenCalledTimes(1);
            expect(mocks.verify_device_list).toHaveBeenCalledWith(
                SIGNED_LIST_BYTES,
                hexToBytes(PRIMARY_PUBLIC_KEY_HEX),
            );
        });

        it('rejects a device list signed by a foreign key', async () => {
            // The attacker's list: signed by a key that is not the one the
            // response claims, so it must never escape as trusted material.
            const foreignList = signList(hexToBytes(OTHER_DEVICE_KEY_HEX), 9, [
                { deviceId: 1, identityKey: newDevicePublicKey },
            ]);
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        signedListBytesHex: Buffer.from(foreignList).toString('hex'),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/signature verification/);

            // A bad signature is not retried and yields no partial result.
            expect(pickupEnvelope).toHaveBeenCalledTimes(1);
            expect(mocks.decrypt_message).toHaveBeenCalledTimes(1);
        });

        it('rejects a device list that does not contain this device', async () => {
            const listWithoutUs = signList(hexToBytes(PRIMARY_PUBLIC_KEY_HEX), 7, [
                { deviceId: 1, identityKey: hexToBytes(OTHER_DEVICE_KEY_HEX) },
            ]);
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        signedListBytesHex: Buffer.from(listWithoutUs).toString('hex'),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/does not contain this device/);

            expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        });

        it('rejects a list that holds this device under a different deviceId', async () => {
            // The response claims deviceId 9, but the signed list assigns this
            // device id 2 — the reported id must come from the signed list.
            const list = signList(hexToBytes(PRIMARY_PUBLIC_KEY_HEX), 7, [
                { deviceId: 2, identityKey: newDevicePublicKey },
            ]);
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        deviceId: 9,
                        signedListBytesHex: Buffer.from(list).toString('hex'),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/does not contain this device/);
        });

        it('rejects a truncated verified list rather than treating it as a miss', async () => {
            // A binding that returns a short buffer must fail closed.
            mocks.verify_device_list.mockReturnValue(Uint8Array.from([1, 2, 3]));
            const pickupEnvelope = vi.fn().mockResolvedValue(sealJson(responsePayload()));
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/truncated/);
        });

        it('surfaces a verification failure without leaking the list bytes', async () => {
            mocks.verify_device_list.mockImplementation(() => {
                throw new Error('DeviceList: BadSignature');
            });
            const pickupEnvelope = vi.fn().mockResolvedValue(sealJson(responsePayload()));
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/signature verification/);

            const output = consoleOutput(consoleSpies);
            for (const needle of forbiddenNeedles()) {
                expect(output).not.toContain(needle);
            }
        });
    });

    describe('accountHandle hardening', () => {
        it.each([
            ['a handle longer than 64 characters', 'a'.repeat(65), /at most 64/],
            ['a handle with a C0 control character', 'ali\u0007ce', /control or bidi/],
            ['a handle with a C1 control character', 'ali\u0085ce', /control or bidi/],
            ['a handle with a bidi override', 'ali\u202ece', /control or bidi/],
            ['a handle with a bidi isolate', 'ali\u2066ce', /control or bidi/],
        ])('rejects %s', async (_label, accountHandle, expected) => {
            const pickupEnvelope = vi
                .fn()
                .mockResolvedValue(sealJson(responsePayload({ accountHandle })));
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(expected);

            expect(pickupEnvelope).toHaveBeenCalledTimes(1);
        });

        it('accepts a handle of exactly 64 characters', async () => {
            const accountHandle = 'a'.repeat(64);
            const pickupEnvelope = vi
                .fn()
                .mockResolvedValue(sealJson(responsePayload({ accountHandle })));
            const transport = makeTransport(pickupEnvelope);

            const result = await awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
            });

            expect(result.accountHandle).toBe(accountHandle);
        });
    });

    describe('primaryPublicKeyHex format', () => {
        it.each([
            ['a compressed secp256k1 prefix', '02'],
            ['an uncompressed-point prefix', '04'],
            ['a zero prefix', '00'],
        ])('rejects %s', async (_label, prefix) => {
            const keyHex = `${prefix}${PRIMARY_PUBLIC_KEY_HEX.slice(2)}`;
            const pickupEnvelope = vi
                .fn()
                .mockResolvedValue(sealJson(responsePayload({ primaryPublicKeyHex: keyHex })));
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
            ).rejects.toThrow(/type-tagged Curve25519/);

            // Rejected before any signature work is attempted.
            expect(mocks.verify_device_list).not.toHaveBeenCalled();
        });

        it('accepts a type-tagged key that signed the list', async () => {
            const keyHex = `05${PRIMARY_PUBLIC_KEY_HEX.slice(2)}`;
            const list = signList(hexToBytes(keyHex), 3, [
                { deviceId: 2, identityKey: newDevicePublicKey },
            ]);
            const pickupEnvelope = vi.fn().mockResolvedValue(
                sealJson(
                    responsePayload({
                        primaryPublicKeyHex: keyHex,
                        signedListBytesHex: Buffer.from(list).toString('hex'),
                    }),
                ),
            );
            const transport = makeTransport(pickupEnvelope);

            const result = await awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
            });

            expect(result.primaryPublicKey[0]).toBe(0x05);
        });
    });

    it('rejects an oversized signed list before materializing it', async () => {
        const oversized = 'ab'.repeat(64 * 1024 + 1);
        const pickupEnvelope = vi
            .fn()
            .mockResolvedValue(sealJson(responsePayload({ signedListBytesHex: oversized })));
        const transport = makeTransport(pickupEnvelope);

        await expect(
            awaitLinkResponse({ transport, linkKey: LINK_KEY, receiverSession }),
        ).rejects.toThrow(/at most 65536 bytes/);

        expect(mocks.verify_device_list).not.toHaveBeenCalled();
    });

    describe('newDevicePublicKey validation', () => {
        it.each([
            ['a 32-byte key', new Uint8Array(32)],
            ['a 34-byte key', new Uint8Array(34)],
            ['a non-Uint8Array value', 'not-a-key'],
        ])('rejects %s without touching the relay', async (_label, key) => {
            const pickupEnvelope = vi.fn();
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({
                    transport,
                    linkKey: LINK_KEY,
                    receiverSession,
                    newDevicePublicKey: key as unknown as Uint8Array,
                }),
            ).rejects.toThrow(/newDevicePublicKey/);

            expect(pickupEnvelope).not.toHaveBeenCalled();
        });
    });

    describe('abort signal', () => {
        it('rejects without touching the relay when already aborted', async () => {
            const controller = new AbortController();
            controller.abort();
            const pickupEnvelope = vi.fn();
            const transport = makeTransport(pickupEnvelope);

            await expect(
                awaitLinkResponse({
                    transport,
                    linkKey: LINK_KEY,
                    receiverSession,
                    signal: controller.signal,
                }),
            ).rejects.toThrow(/aborted/);

            expect(pickupEnvelope).not.toHaveBeenCalled();
        });

        it('rejects a pending pickup when aborted, instead of hanging', async () => {
            const controller = new AbortController();
            // A relay that accepts the socket and never answers.
            const pickupEnvelope = vi.fn().mockReturnValue(new Promise<Uint8Array>(() => {}));
            const transport = makeTransport(pickupEnvelope);

            const outcome = awaitLinkResponse({
                transport,
                linkKey: LINK_KEY,
                receiverSession,
                signal: controller.signal,
            }).then(
                (value) => ({ fulfilled: true as const, value }),
                (error: unknown) => ({ fulfilled: false as const, error }),
            );

            controller.abort();
            const settled = await outcome;

            expect(settled.fulfilled).toBe(false);
            if (settled.fulfilled) throw new Error('unreachable');
            expect(String(settled.error)).toMatch(/aborted/);
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
