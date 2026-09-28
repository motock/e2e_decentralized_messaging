/**
 * DR-3: device revocation / unlinking (web client).
 *
 * The linking flow could add a device but had no way to remove one. These tests
 * pin the revocation contract through the public surface only; the names below
 * are the contract:
 *
 *  - `src/device_linking.ts`: `LinkingState.linkedDevices` (empty from
 *    `initialLinkingState()`), `revokeDevice(state, deviceId, options?)` and
 *    `messageRecipients(state)`.
 *  - `revokeDevice` returns `{ ok, state, error?, requiresConfirmation? }` and
 *    fails closed: an unknown device, or the last remaining device without
 *    `{ confirmLastDevice: true }`, gives `ok: false` with a clear error and an
 *    untouched state. Success drops the device from `linkedDevices` and
 *    `messageRecipients` and sets phase `'revoked'`.
 *  - `DeviceLinking.tsx`: a `Linked devices` section, a per-device control
 *    labelled `Revoke device <deviceId>`, a `Confirm revoke` button, and a
 *    `data-testid="revocation-status"` element reporting the outcome.
 *  - `clients/web/README.md` documents revocation.
 *  - The committed ambient declaration `src/wasm-bindings.d.ts` declares the
 *    new `remove_device` WASM binding (the gitignored `pkg/` is not rebuilt by
 *    the test run, so the declaration is the only observable surface for it).
 *
 * The existing linking tests are untouched and must keep passing.
 */
/** @vitest-environment jsdom */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ensureWasmInit } from '../src/wasm_init';
import {
    initialLinkingState,
    revokeDevice,
    messageRecipients,
    type LinkingState,
} from '../src/device_linking';

afterEach(() => {
    cleanup();
});

beforeAll(async () => {
    await ensureWasmInit();
});

/** A linking state that already has `ids` linked, in order. */
function stateWithDevices(...ids: string[]): LinkingState {
    return { ...initialLinkingState(), linkedDevices: ids.map((deviceId) => ({ deviceId })) };
}

function deviceIds(state: LinkingState): string[] {
    return (state.linkedDevices ?? []).map((d) => d.deviceId);
}

// ---------------------------------------------------------------------------
// State shape
// ---------------------------------------------------------------------------

describe('initial linking state', () => {
    it('starts with no linked devices', () => {
        expect(initialLinkingState().linkedDevices).toEqual([]);
    });
});

// ---------------------------------------------------------------------------
// Happy path: revoke a linked device
// ---------------------------------------------------------------------------

describe('revoking a linked device', () => {
    it('removes the device from the list and reports success', async () => {
        const result = await revokeDevice(stateWithDevices('dev-1', 'dev-2'), 'dev-1');

        expect(result.ok).toBe(true);
        expect(result.error ?? null).toBeNull();
        expect(deviceIds(result.state)).toEqual(['dev-2']);
        expect(result.state.phase).toBe('revoked');
    });

    it('drops the revoked device from the message recipients', async () => {
        const before = stateWithDevices('dev-1', 'dev-2');
        expect(await messageRecipients(before)).toContain('dev-1');

        const after = await messageRecipients((await revokeDevice(before, 'dev-1')).state);
        expect(after).not.toContain('dev-1');
        expect(after).toContain('dev-2');
    });
});

// ---------------------------------------------------------------------------
// Negative / boundary: fail closed, never silently lock the user out
// ---------------------------------------------------------------------------

describe('revocation fails closed', () => {
    it('refuses an unknown device with a clear error and no state change', async () => {
        const result = await revokeDevice(stateWithDevices('dev-1', 'dev-2'), 'ghost');

        expect(result.ok).toBe(false);
        expect((result.error ?? '').length).toBeGreaterThan(0);
        expect(deviceIds(result.state)).toEqual(['dev-1', 'dev-2']);
    });

    it('does not silently revoke the last remaining device', async () => {
        const result = await revokeDevice(stateWithDevices('only'), 'only');

        expect(result.ok).toBe(false);
        expect(result.requiresConfirmation).toBe(true);
        expect((result.error ?? '').length).toBeGreaterThan(0);
        expect(deviceIds(result.state)).toEqual(['only']);
    });

    it('revokes the last remaining device only when explicitly confirmed', async () => {
        const result = await revokeDevice(stateWithDevices('only'), 'only', {
            confirmLastDevice: true,
        });

        expect(result.ok).toBe(true);
        expect(deviceIds(result.state)).toEqual([]);
        expect(await messageRecipients(result.state)).toEqual([]);
    });

    it('never reports a failed revocation as success', async () => {
        const before = stateWithDevices('dev-1');
        const unknown = await revokeDevice(before, 'ghost');
        const last = await revokeDevice(before, 'dev-1');

        expect(unknown.ok).not.toBe(true);
        expect(last.ok).not.toBe(true);
        expect(deviceIds(unknown.state)).toContain('dev-1');
        expect(deviceIds(last.state)).toContain('dev-1');
    });
});

// ---------------------------------------------------------------------------
// UI: list, revoke, confirm, report
// ---------------------------------------------------------------------------

describe('DeviceLinking revocation UI', () => {
    async function renderWithDevices(...ids: string[]) {
        const { render, screen, waitFor, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        render(
            <DeviceLinking
                localIdentityKey={new Uint8Array(33)}
                linkedDevices={ids.map((deviceId) => ({ deviceId }))}
            />,
        );
        await waitFor(() => screen.getByText('Linked devices'));
        return { screen, waitFor, fireEvent };
    }

    it('lists the linked devices with a revoke control each', async () => {
        const { screen } = await renderWithDevices('dev-1', 'dev-2');

        expect(screen.getByLabelText('Revoke device dev-1')).toBeTruthy();
        expect(screen.getByLabelText('Revoke device dev-2')).toBeTruthy();
    });

    it('requires an explicit confirmation before removing a device', async () => {
        const { screen, waitFor, fireEvent } = await renderWithDevices('dev-1', 'dev-2');

        fireEvent.click(screen.getByLabelText('Revoke device dev-1'));

        await waitFor(() => expect(screen.getByText('Confirm revoke')).toBeTruthy());
        // Nothing is removed until the user confirms.
        expect(screen.getByLabelText('Revoke device dev-1')).toBeTruthy();
    });

    it('removes the device and reports the revocation after confirming', async () => {
        const { screen, waitFor, fireEvent } = await renderWithDevices('dev-1', 'dev-2');

        fireEvent.click(screen.getByLabelText('Revoke device dev-1'));
        await waitFor(() => screen.getByText('Confirm revoke'));
        fireEvent.click(screen.getByText('Confirm revoke'));

        await waitFor(() => {
            expect(screen.queryByLabelText('Revoke device dev-1')).toBeNull();
            expect(screen.getByLabelText('Revoke device dev-2')).toBeTruthy();
            expect(screen.getByTestId('revocation-status').textContent ?? '').toMatch(/revoked/i);
        });
    });
});

// ---------------------------------------------------------------------------
// Documentation and the committed WASM declaration
// ---------------------------------------------------------------------------

describe('documentation', () => {
    it('documents revocation in the web client README', () => {
        const readme = readFileSync(path.resolve(__dirname, '..', 'README.md'), 'utf8');
        expect(readme).toMatch(/revok|unlink/i);
    });
});

describe('wasm-bindings.d.ts declares the revocation binding', () => {
    it('declares remove_device so a fresh checkout type-checks its consumers', () => {
        const webRoot = path.resolve(__dirname, '..');
        const dir = mkdtempSync(path.join(os.tmpdir(), 'dr3-'));
        const fixture = path.join(dir, 'revoke.ts');
        writeFileSync(
            fixture,
            `import { remove_device } from '../../../core/bindings/wasm/pkg/index.js';\nvoid remove_device;\n`,
        );

        let output = '';
        try {
            output = execFileSync(
                path.join(webRoot, 'node_modules', '.bin', 'tsc'),
                [
                    '--noEmit', '--strict', '--target', 'ES2022', '--module', 'ESNext',
                    '--moduleResolution', 'Bundler', '--skipLibCheck', '--pretty', 'false',
                    path.join(webRoot, 'src', 'wasm-bindings.d.ts'), fixture,
                ],
                { cwd: dir, encoding: 'utf8' },
            );
        } catch (error) {
            const e = error as { stdout?: string; stderr?: string; message?: string };
            output = `${e.stdout ?? ''}${e.stderr ?? ''}` || (e.message ?? '');
        }

        expect(output).toBe('');
    });
});
