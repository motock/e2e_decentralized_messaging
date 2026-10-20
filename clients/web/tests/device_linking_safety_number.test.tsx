/** @vitest-environment jsdom */
/**
 * MD-15: safety-number panel and authorization gate on the device-linking
 * screen.
 *
 * The panel is driven entirely by two OPTIONAL props — `safetyNumber` and
 * `onConfirm` — so the legacy render path (only `localIdentityKey`) keeps
 * working. These tests cover:
 *
 *  - positive: the same key pair renders the identical formatted number, and
 *    the authorize action stays disabled until the user confirms;
 *  - negative: different key pairs render different numbers, and the DOM never
 *    contains either key's raw bytes (hex or decimal dump).
 *
 * The safety number is derived with the real wasm binding rather than a
 * fixture so the tests exercise the same value the app would display.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

afterEach(() => {
    cleanup();
});

beforeAll(async () => {
    await ensureWasmInit();
});

async function genPublicBytes(): Promise<Uint8Array> {
    return wasm.generate_identity().public_bytes();
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** The displayed number must be the derived digits, grouped for reading. */
function digitsOnly(value: string): string {
    return value.replace(/\s+/g, '');
}

describe('DeviceLinking safety-number panel (MD-15)', () => {
    it('renders the identical formatted safety number for the same key pair', async () => {
        const { render, screen } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const safetyNumber = wasm.derive_safety_number(primaryKey, newDeviceKey);

        const first = render(
            <DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumber} />,
        );
        const firstText = (await screen.findByTestId('link-safety-number')).textContent ?? '';
        first.unmount();

        render(<DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumber} />);
        const secondText = (await screen.findByTestId('link-safety-number')).textContent ?? '';

        expect(firstText).not.toBe('');
        expect(secondText).toBe(firstText);
        // Same digits as the derived value, grouped into blocks of five.
        expect(digitsOnly(firstText)).toBe(digitsOnly(safetyNumber));
        expect(firstText).not.toMatch(/\d{6,}/);
    });

    it('disables the authorize action until the safety number is confirmed', async () => {
        const { render, screen, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const safetyNumber = wasm.derive_safety_number(primaryKey, newDeviceKey);
        const onConfirm = vi.fn();

        render(
            <DeviceLinking
                localIdentityKey={primaryKey}
                safetyNumber={safetyNumber}
                onConfirm={onConfirm}
            />,
        );

        const authorize = (await screen.findByRole('button', {
            name: /authorize/i,
        })) as HTMLButtonElement;
        expect(authorize.disabled).toBe(true);

        // A disabled control must not authorize, even if a click reaches it.
        fireEvent.click(authorize);
        expect(onConfirm).not.toHaveBeenCalled();

        fireEvent.click(screen.getByLabelText('Safety number matches on both devices'));
        expect(authorize.disabled).toBe(false);

        fireEvent.click(authorize);
        expect(onConfirm).toHaveBeenCalledTimes(1);
    });

    it('renders different numbers for different key pairs', async () => {
        const { render, screen } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        const newDeviceA = await genPublicBytes();
        const newDeviceB = await genPublicBytes();
        const safetyNumberA = wasm.derive_safety_number(primaryKey, newDeviceA);
        const safetyNumberB = wasm.derive_safety_number(primaryKey, newDeviceB);
        expect(safetyNumberA).not.toBe(safetyNumberB);

        const first = render(
            <DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumberA} />,
        );
        const textA = (await screen.findByTestId('link-safety-number')).textContent ?? '';
        first.unmount();

        render(<DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumberB} />);
        const textB = (await screen.findByTestId('link-safety-number')).textContent ?? '';

        expect(textA).not.toBe('');
        expect(textB).not.toBe('');
        expect(textA).not.toBe(textB);
    });

    it('never renders raw key bytes in the panel', async () => {
        const { render, screen } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const safetyNumber = wasm.derive_safety_number(primaryKey, newDeviceKey);

        const { container } = render(
            <DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumber} />,
        );
        await screen.findByTestId('link-safety-number');

        const html = container.innerHTML.toLowerCase();
        expect(html).not.toContain(toHex(primaryKey));
        expect(html).not.toContain(toHex(newDeviceKey));
        // The decimal byte dump the success screen used to expose.
        expect(html).not.toContain(Array.from(primaryKey).join(','));
        expect(html).not.toContain(Array.from(newDeviceKey).join(','));
    });

    it('never renders raw key bytes on the linked screen', async () => {
        const { render, screen, fireEvent } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');
        const { encodeLinkingPayload } = await import('../src/device_linking');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const payload = encodeLinkingPayload(newDeviceKey);
        const expectedSn = wasm.derive_safety_number(primaryKey, newDeviceKey);

        const { container } = render(<DeviceLinking localIdentityKey={primaryKey} />);

        await screen.findByText('Enter linking code (from other device)');
        fireEvent.click(screen.getByText('Enter linking code (from other device)'));
        fireEvent.change(screen.getByLabelText('Linking code input'), {
            target: { value: payload },
        });
        fireEvent.click(screen.getByText('Continue'));

        await screen.findByTestId('displayed-safety-number');
        fireEvent.change(screen.getByLabelText('Safety number confirmation input'), {
            target: { value: expectedSn },
        });
        fireEvent.click(screen.getByText('Confirm and Link'));

        await screen.findByText('Device linked successfully!');

        const html = container.innerHTML.toLowerCase();
        expect(html).not.toContain(toHex(primaryKey));
        expect(html).not.toContain(toHex(newDeviceKey));
        expect(html).not.toContain(Array.from(primaryKey).join(','));
        expect(html).not.toContain(Array.from(newDeviceKey).join(','));
    });

    it('renders no safety-number panel when the prop is absent (legacy path)', async () => {
        const { render, screen } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        render(<DeviceLinking localIdentityKey={primaryKey} />);

        await screen.findByText('Show QR code (this device)');
        expect(screen.queryByTestId('link-safety-number')).toBeNull();
        expect(screen.queryByRole('button', { name: /authorize/i })).toBeNull();
    });

    it('labels the new-device confirmation as step 2 of 2, never one-step', async () => {
        const { render, screen } = await import('@testing-library/react');
        const { DeviceLinking } = await import('../src/DeviceLinking.tsx');

        const primaryKey = await genPublicBytes();
        const newDeviceKey = await genPublicBytes();
        const safetyNumber = wasm.derive_safety_number(primaryKey, newDeviceKey);

        const { container } = render(
            <DeviceLinking localIdentityKey={primaryKey} safetyNumber={safetyNumber} />,
        );
        await screen.findByTestId('link-safety-number');

        expect(screen.getByText(/Step 2 of 2/)).toBeTruthy();
        expect(container.textContent ?? '').not.toMatch(/one[- ]step|single[- ]step|1 of 1/i);
    });
});
