import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

// vite-plugin-top-level-await@1.6.0 requires rollup (dist/index.js:41) and
// esbuild (dist/esbuild.js, resolved from vite's directory) at load time
// but declares neither, so a lockfile regeneration that prunes vite's
// auto-installed optional peers makes vitest.config.ts unloadable.
describe('vite-plugin-top-level-await dependencies', () => {
  it('loads the plugin, which requires rollup and esbuild', () => {
    const require = createRequire(import.meta.url);
    expect(() => require('vite-plugin-top-level-await')).not.toThrow();
  });
});