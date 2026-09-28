/**
 * GRP-3: the committed ambient WASM type declaration
 * (clients/web/src/wasm-bindings.d.ts) must declare the group state
 * persistence bindings `group_to_bytes` / `group_from_bytes`, so a fresh
 * checkout that has not run `prepare-wasm` still type-checks consumers of
 * them.
 *
 * These tests grade the declaration the way a consumer uses it: they compile
 * small TypeScript fixtures against the ambient module and assert the
 * compiler accepts the correct calls and rejects wrong ones. The fixtures are
 * written to a temp directory outside the repo, so the relative import can
 * only resolve through the committed declaration - never through a generated
 * wasm-pack `pkg/index.d.ts`, even when `prepare-wasm` has run.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const WEB_ROOT = path.resolve(__dirname, '..');
const DTS = path.join(WEB_ROOT, 'src', 'wasm-bindings.d.ts');
const TSC = path.join(WEB_ROOT, 'node_modules', '.bin', 'tsc');
const MODULE = '../../../core/bindings/wasm/pkg/index.js';

const FIXTURES: Record<string, string> = {
  // Happy path: a GroupHandle round-trips through the two new bindings.
  'roundtrip.ts': [
    `import { group_to_bytes, group_from_bytes, GroupHandle } from '${MODULE}';`,
    'declare const group: GroupHandle;',
    'const blob: Uint8Array = group_to_bytes(group);',
    'const restored: GroupHandle = group_from_bytes(blob);',
    'void restored;',
  ].join('\n'),
  // Additive change: every pre-existing export is still declared.
  'existing.ts': [
    `import { IdentityHandle, GroupHandle, SessionHandle, WasmError, generate_identity,`,
    `  identity_from_bytes, generate_prekey_bundle, create_receiver_session, publish_bundle_bytes,`,
    `  establish_session_from_bundle, bundle_identity_key_bytes, encrypt_message, decrypt_message,`,
    `  group_create, group_add_member, group_remove_member, group_encrypt, group_decrypt,`,
    `  derive_safety_number } from '${MODULE}';`,
    'void 0;',
  ].join('\n'),
  // Negative: group_from_bytes takes bytes, not a string.
  'bad_arg.ts': [
    `import { group_from_bytes } from '${MODULE}';`,
    `group_from_bytes('not-bytes');`,
  ].join('\n'),
  // Negative: group_to_bytes returns bytes, not a string.
  'bad_return.ts': [
    `import { group_to_bytes, GroupHandle } from '${MODULE}';`,
    'declare const group: GroupHandle;',
    'const wrong: string = group_to_bytes(group);',
    'void wrong;',
  ].join('\n'),
  // Negative: group_from_bytes returns a GroupHandle, not a number.
  'bad_return2.ts': [
    `import { group_from_bytes } from '${MODULE}';`,
    'const wrong: number = group_from_bytes(new Uint8Array(0));',
    'void wrong;',
  ].join('\n'),
};

/** Compile every fixture plus the committed declaration; group diagnostics by file. */
function compileFixtures(): Map<string, string[]> {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'grp3-'));
  const files = Object.entries(FIXTURES).map(([name, source]) => {
    const file = path.join(dir, name);
    writeFileSync(file, source);
    return file;
  });

  let output = '';
  try {
    output = execFileSync(
      TSC,
      [
        '--noEmit',
        '--strict',
        '--target',
        'ES2022',
        '--module',
        'ESNext',
        '--moduleResolution',
        'Bundler',
        '--skipLibCheck',
        '--pretty',
        'false',
        DTS,
        ...files,
      ],
      // cwd is the temp dir so no tsconfig.json is picked up.
      { cwd: dir, encoding: 'utf8' },
    );
  } catch (error) {
    const e = error as { stdout?: string; stderr?: string; message?: string };
    output = `${e.stdout ?? ''}${e.stderr ?? ''}${e.stdout || e.stderr ? '' : e.message ?? ''}`;
  }

  const byFile = new Map<string, string[]>();
  for (const line of output.split('\n')) {
    const match = line.match(/^(.*?)\(\d+,\d+\): (error TS\d+): (.*)$/);
    if (!match) continue;
    const name = path.basename(match[1]);
    byFile.set(name, [...(byFile.get(name) ?? []), `${match[2]}: ${match[3]}`]);
  }
  return byFile;
}

const diagnostics = compileFixtures();
const forFile = (name: string) => diagnostics.get(name) ?? [];

describe('wasm-bindings.d.ts declares the group state persistence bindings', () => {
  test('a consumer can round-trip a GroupHandle through group_to_bytes/group_from_bytes', () => {
    expect(forFile('roundtrip.ts')).toEqual([]);
  });

  test('the change is additive: the pre-existing declarations are still exported', () => {
    expect(forFile('existing.ts')).toEqual([]);
  });

  test('group_from_bytes is declared to take bytes, not an implicit any', () => {
    // TS2345 = argument type mismatch. A missing export would be TS2305 instead.
    expect(forFile('bad_arg.ts').join('\n')).toContain('TS2345');
  });

  test('group_to_bytes is declared to return bytes, not an implicit any', () => {
    // TS2322 = assignment type mismatch. A missing export would be TS2305 instead.
    expect(forFile('bad_return.ts').join('\n')).toContain('TS2322');
  });

  test('group_from_bytes is declared to return a GroupHandle, not an implicit any', () => {
    expect(forFile('bad_return2.ts').join('\n')).toContain('TS2322');
  });
});
