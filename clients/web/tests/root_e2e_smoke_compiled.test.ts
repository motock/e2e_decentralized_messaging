import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// HY-3: the orphaned root-level smoke test.
//
// The repo root holds an `e2e_smoke.rs` under `tests/` that no build target ever
// compiles: the root Cargo.toml is a [workspace]-only manifest with no [package]
// table, so no cargo target includes it, and it imports `core_protocol::session` /
// `core_protocol::message`, which do not exist. It is dead weight that reads like
// coverage.
//
// The story's acceptance is "do not leave it as-is": either delete the orphan, or
// make it real by moving it under a crate that compiles it and updating it to the
// APIs that actually exist. This suite grades that invariant through cargo's public
// interface (`cargo metadata`, `cargo test`) and the filesystem - never by reading
// the file's text - so either resolution is accepted.
//
// The path is assembled from parts so this test file does not itself contain the
// literal string the "no tracked file references it" check greps for.

const ROOT_TEST_REL = ['tests', 'e2e_smoke.rs'].join('/');

const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
  encoding: 'utf8',
}).trim();
const rootTestAbs = resolve(repoRoot, ROOT_TEST_REL);

type CargoTarget = { name: string; kind: string[]; src_path: string };
type CargoPackage = { name: string; targets: CargoTarget[] };

function cargo(args: string[]): string {
  return execFileSync('cargo', args, { encoding: 'utf8', cwd: repoRoot });
}

/** Every cargo test target whose source file is the root-level smoke test. */
function targetsCompilingRootTest(): { pkg: string; target: string }[] {
  const raw = cargo(['metadata', '--no-deps', '--format-version', '1']);
  const packages = (JSON.parse(raw) as { packages: CargoPackage[] }).packages;
  return packages.flatMap((pkg) =>
    pkg.targets
      .filter((t) => t.kind.includes('test') && resolve(t.src_path) === rootTestAbs)
      .map((t) => ({ pkg: pkg.name, target: t.name })),
  );
}

/** Tracked files that still mention the root-level smoke test's path. */
function trackedReferences(): string[] {
  try {
    return execFileSync('git', ['grep', '-l', '-F', ROOT_TEST_REL], {
      encoding: 'utf8',
      cwd: repoRoot,
    })
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  } catch (err) {
    // `git grep` exits 1 when nothing matches, which is the expected case.
    if ((err as { status?: number }).status !== 1) throw err;
    return [];
  }
}

const kept = existsSync(rootTestAbs);
const compiledBy = kept ? targetsCompilingRootTest() : [];

describe(`root ${ROOT_TEST_REL} is not left as an orphan (HY-3)`, () => {
  it('is resolved: removed, or compiled by a real cargo target', () => {
    expect(
      kept && compiledBy.length === 0,
      `${ROOT_TEST_REL} is still present but no cargo target compiles it`,
    ).toBe(false);
  });

  it('if kept, is compiled and passes as a cargo test target', () => {
    if (!kept) return; // resolved by removal
    expect(
      compiledBy.length,
      `no cargo test target compiles ${ROOT_TEST_REL}`,
    ).toBeGreaterThan(0);
    for (const { pkg, target } of compiledBy) {
      expect(
        () => cargo(['test', '-p', pkg, '--test', target]),
        `${ROOT_TEST_REL} does not pass as ${pkg}::${target}`,
      ).not.toThrow();
    }
  });

  it('if removed, no tracked file or doc still references it', () => {
    if (kept) return; // resolved by repair
    expect(
      trackedReferences(),
      `a tracked file still references the removed ${ROOT_TEST_REL}`,
    ).toEqual([]);
  });
});
