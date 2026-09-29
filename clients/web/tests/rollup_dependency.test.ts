import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

describe('rollup dependency', () => {
  it('resolves rollup from the web client package', () => {
    const require = createRequire(import.meta.url);
    expect(() => require.resolve('rollup')).not.toThrow();
  });
});