/** @vitest-environment jsdom */
//
// TDD tests for session/group serialize + restore in the web client (NS-5D).
//
// These tests run against the REAL wasm32 module built by `npm run prepare-wasm`
// (see clients/web/package.json) — nothing about the WASM bindings is mocked,
// matching the repo convention established in conversation_session.test.tsx and
// device_linking.test.ts. The functions under test are:
//   session_to_bytes / session_from_bytes / group_to_bytes / group_from_bytes
//
// Positive cases prove a restored session/group continues the conversation.
// Negative/boundary cases prove the restore boundary fails closed: empty,
// truncated, unknown-version, and wrong-identity inputs all throw a WasmError
// with kind === 'Session' (or 'Group' for group blobs) and never return a handle.

import { describe, it, expect, beforeAll } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

beforeAll(async () => {
    await ensureWasmInit();
});

/** The outcome of calling a fallible binding: either a returned value or a thrown error. */
interface CallOutcome {
    returned: unknown;
    error: unknown;
}

/**
 * Call `fn`, capturing either its return value or the error it threw. Kept outside the test
 * bodies so each test stays a straight-line sequence of assertions with no conditionals.
 */
function callCapturing(fn: () => unknown): CallOutcome {
    try {
        return { returned: fn(), error: null };
    } catch (error) {
        return { returned: undefined, error };
    }
}

/** The `kind` tag of a captured WasmError, read through the public getter. */
function errorKind(error: unknown): string {
    return (error as { kind: string }).kind;
}

/** Build a sender (Alice) session and its matching receiver (Bob) session. */
function establishedPair() {
    const bobIdentity = wasm.generate_identity();
    const bobSession = wasm.create_receiver_session(bobIdentity);
    const bundleBytes = wasm.publish_bundle_bytes(bobSession);
    const aliceIdentity = wasm.generate_identity();
    const aliceSession = wasm.establish_session_from_bundle(aliceIdentity, bundleBytes);
    return { aliceIdentity, aliceSession, bobIdentity, bobSession };
}

/** Build a sender session whose bundle came from a throwaway receiver session. */
function senderSessionWithBlob() {
    const bobIdentity = wasm.generate_identity();
    const bundleBytes = wasm.generate_prekey_bundle(bobIdentity);
    const aliceIdentity = wasm.generate_identity();
    const aliceSession = wasm.establish_session_from_bundle(aliceIdentity, bundleBytes);
    return { aliceIdentity, aliceSession };
}

/** Build a one-member group plus the sender/member identities that own it. */
function oneMemberGroup() {
    const sender = wasm.generate_identity();
    const member = wasm.generate_identity();
    const group = wasm.group_add_member(wasm.group_create(sender), member.public_bytes());
    return { sender, member, group };
}

// ---------------------------------------------------------------------------
// Positive path: sender session round-trip
// ---------------------------------------------------------------------------

describe('session serialize/restore round-trip', () => {
    it('restores a sender session that still encrypts a message the receiver decrypts', () => {
        const { aliceIdentity, aliceSession, bobSession } = establishedPair();

        const first = wasm.encrypt_message(aliceSession, new TextEncoder().encode('first'));
        expect(new TextDecoder().decode(wasm.decrypt_message(bobSession, first))).toBe('first');

        const blob = wasm.session_to_bytes(aliceSession);
        const restored = wasm.session_from_bytes(aliceIdentity, blob);

        const second = wasm.encrypt_message(restored, new TextEncoder().encode('second'));
        expect(new TextDecoder().decode(wasm.decrypt_message(bobSession, second))).toBe('second');
    });

    it('restores a receiver session that decrypts a further message after a decrypted one', () => {
        const { aliceSession, bobIdentity, bobSession } = establishedPair();

        const first = wasm.encrypt_message(aliceSession, new TextEncoder().encode('first'));
        expect(new TextDecoder().decode(wasm.decrypt_message(bobSession, first))).toBe('first');

        const blob = wasm.session_to_bytes(bobSession);
        const restored = wasm.session_from_bytes(bobIdentity, blob);

        const second = wasm.encrypt_message(aliceSession, new TextEncoder().encode('second'));
        expect(new TextDecoder().decode(wasm.decrypt_message(restored, second))).toBe('second');
    });

    it('continues the conversation after a simulated reload from the bytes alone', () => {
        const { aliceIdentity, aliceSession, bobIdentity, bobSession } = establishedPair();

        const first = wasm.encrypt_message(aliceSession, new TextEncoder().encode('before reload'));
        expect(new TextDecoder().decode(wasm.decrypt_message(bobSession, first))).toBe(
            'before reload',
        );

        const aliceBlob = wasm.session_to_bytes(aliceSession);
        const bobBlob = wasm.session_to_bytes(bobSession);

        // Drop every session-scoped handle: only the blobs and the identity handles survive.
        aliceSession.free();
        bobSession.free();

        const restoredAlice = wasm.session_from_bytes(aliceIdentity, aliceBlob);
        const restoredBob = wasm.session_from_bytes(bobIdentity, bobBlob);

        const second = wasm.encrypt_message(restoredAlice, new TextEncoder().encode('after reload'));
        expect(new TextDecoder().decode(wasm.decrypt_message(restoredBob, second))).toBe(
            'after reload',
        );
    });
});

// ---------------------------------------------------------------------------
// Positive path: group round-trip
// ---------------------------------------------------------------------------

describe('group serialize/restore round-trip', () => {
    it('restores a group that encrypts a message a member decrypts', () => {
        const { sender, member, group } = oneMemberGroup();

        const restored = wasm.group_from_bytes(wasm.group_to_bytes(group));

        const ciphertext = wasm.group_encrypt(restored, sender, new TextEncoder().encode('hello'));
        expect(new TextDecoder().decode(wasm.group_decrypt(restored, member, ciphertext))).toBe(
            'hello',
        );
    });

    it('restores a group whose next message differs from the previous one', () => {
        const { sender, group } = oneMemberGroup();
        const restored = wasm.group_from_bytes(wasm.group_to_bytes(group));

        const first = wasm.group_encrypt(restored, sender, new TextEncoder().encode('same'));
        const second = wasm.group_encrypt(restored, sender, new TextEncoder().encode('same'));

        expect(Array.from(second)).not.toEqual(Array.from(first));
    });
});

// ---------------------------------------------------------------------------
// Negative / boundary: session restore fails closed
// ---------------------------------------------------------------------------

describe('session_from_bytes fails closed', () => {
    it('rejects empty bytes with a Session error and no session object', () => {
        const { aliceIdentity } = senderSessionWithBlob();

        const outcome = callCapturing(() => wasm.session_from_bytes(aliceIdentity, new Uint8Array(0)));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Session');
    });

    it('rejects truncated bytes with a Session error and no session object', () => {
        const { aliceIdentity, aliceSession } = senderSessionWithBlob();
        const blob = wasm.session_to_bytes(aliceSession);

        const outcome = callCapturing(() =>
            wasm.session_from_bytes(aliceIdentity, blob.slice(0, blob.length - 1)),
        );

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Session');
    });

    it('rejects an unknown version byte with a Session error and no session object', () => {
        const { aliceIdentity, aliceSession } = senderSessionWithBlob();
        const blob = wasm.session_to_bytes(aliceSession);
        const tampered = new Uint8Array(blob);
        tampered[0] = 0xff;

        const outcome = callCapturing(() => wasm.session_from_bytes(aliceIdentity, tampered));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Session');
    });

    it('rejects a blob restored under a different identity with a Session error', () => {
        const { aliceSession } = senderSessionWithBlob();
        const blob = wasm.session_to_bytes(aliceSession);
        const otherIdentity = wasm.generate_identity();

        const outcome = callCapturing(() => wasm.session_from_bytes(otherIdentity, blob));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Session');
    });

    it('rejects a receiver blob restored under a different identity with a Session error', () => {
        const { aliceSession, bobSession } = establishedPair();
        const first = wasm.encrypt_message(aliceSession, new TextEncoder().encode('first'));
        wasm.decrypt_message(bobSession, first);
        const blob = wasm.session_to_bytes(bobSession);
        const otherIdentity = wasm.generate_identity();

        const outcome = callCapturing(() => wasm.session_from_bytes(otherIdentity, blob));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Session');
    });

    it('leaves the identity usable so the intact blob still restores after a failed attempt', () => {
        const { aliceSession, bobIdentity, bobSession } = establishedPair();
        const first = wasm.encrypt_message(aliceSession, new TextEncoder().encode('first'));
        wasm.decrypt_message(bobSession, first);
        const blob = wasm.session_to_bytes(bobSession);

        const failed = callCapturing(() =>
            wasm.session_from_bytes(bobIdentity, blob.slice(0, blob.length - 1)),
        );
        expect(errorKind(failed.error)).toBe('Session');

        const restored = wasm.session_from_bytes(bobIdentity, blob);
        const second = wasm.encrypt_message(aliceSession, new TextEncoder().encode('second'));
        expect(new TextDecoder().decode(wasm.decrypt_message(restored, second))).toBe('second');
    });
});

// ---------------------------------------------------------------------------
// Negative / boundary: group restore fails closed
// ---------------------------------------------------------------------------

describe('group_from_bytes fails closed', () => {
    it('rejects empty bytes with a Group error and no group object', () => {
        const outcome = callCapturing(() => wasm.group_from_bytes(new Uint8Array(0)));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Group');
    });

    it('rejects truncated bytes with a Group error and no group object', () => {
        const { group } = oneMemberGroup();
        const blob = wasm.group_to_bytes(group);

        const outcome = callCapturing(() => wasm.group_from_bytes(blob.slice(0, blob.length - 1)));

        expect(outcome.returned).toBeUndefined();
        expect(outcome.error).toBeInstanceOf(wasm.WasmError);
        expect(errorKind(outcome.error)).toBe('Group');
    });
});
