import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// HY-1: the web client must be on Vite 8 (^8.0.0) in BOTH places package.json
// pins it — devDependencies AND overrides (a stale override silently forces
// the old major back in after install) — and vite.config.ts must not carry a
// build.target override whose comment still describes it as a Vite 7-era
// workaround.

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
const viteConfig = readFileSync(new URL('./vite.config.ts', import.meta.url), 'utf8');

const TARGET_RANGE = '^8.0.0';

describe('vite version pins (HY-1: Vite 7 -> Vite 8)', () => {
  it('pins vite ^8.0.0 in devDependencies', () => {
    const pin = pkg.devDependencies?.vite ?? pkg.dependencies?.vite;
    expect(pin, 'package.json must pin vite in devDependencies (or dependencies)').toBeDefined();
    expect(pin).toBe(TARGET_RANGE);
  });

  it('pins vite ^8.0.0 in overrides too', () => {
    expect(pkg.overrides?.vite, 'package.json overrides.vite must exist').toBeDefined();
    expect(pkg.overrides.vite).toBe(TARGET_RANGE);
  });

  it('has no stale Vite 7 workaround comment on the es2022 build target', () => {
    const hasEs2022Override = /target:\s*['"]es2022['"]/.test(viteConfig);
    if (!hasEs2022Override) {
      // No override at all is fine.
      return;
    }
    const comment = viteConfig.slice(0, viteConfig.indexOf('target:'));
    expect(
      /vite 7/i.test(comment),
      'vite.config.ts keeps build.target es2022 but its comment still calls it a Vite 7 workaround; rewrite the comment for the current Vite major or drop the override',
    ).toBe(false);
  });
});