import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

// HY-2: the git `origin` remote must point at the canonical repository URL.
//
// The repository was renamed; the pre-rename owner path still answers with a
// 301 redirect, so a clone that keeps the old URL depends on that redirect
// (and on GitHub continuing to serve it) for every fetch and push. The change
// lives in the shared .git/config rather than in a tracked file, so it is
// graded through git's public interface (`git remote get-url`) instead of by
// reading a file.

const CANONICAL = 'https://github.com/motock/e2e_decentralized_messaging';
// Assembled from parts so this test file does not itself contain the literal
// string that the "no tracked file references it" check greps for.
const OLD_OWNER = 'fico-jessecarroll';
const OLD_URL = ['https://github.com', OLD_OWNER, 'e2e_decentralized_messaging.git'].join('/');

function git(args: string[]): string {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function normalize(url: string): string {
  return url.replace(/\.git$/, '');
}

const repoRoot = git(['rev-parse', '--show-toplevel']);

describe('git origin remote (HY-2: point origin at the canonical URL)', () => {
  it('still exists (the remote is repointed, not removed)', () => {
    const remotes = git(['remote']).split('\n').map((r) => r.trim());
    expect(remotes).toContain('origin');
  });

  it('fetches from the canonical URL', () => {
    const url = git(['remote', 'get-url', 'origin']);
    expect(normalize(url), `origin fetch URL is ${url}`).toBe(CANONICAL);
  });

  it('pushes to the canonical URL', () => {
    const url = git(['remote', 'get-url', '--push', 'origin']);
    expect(normalize(url), `origin push URL is ${url}`).toBe(CANONICAL);
  });

  it('no longer points at the pre-rename owner path', () => {
    const url = git(['remote', 'get-url', 'origin']);
    expect(url).not.toContain(OLD_OWNER);
    expect(url).not.toBe(OLD_URL);
  });

  it('is not hardcoded in any tracked file', () => {
    let out = '';
    try {
      out = execFileSync('git', ['-C', repoRoot, 'grep', '-l', '-F', OLD_URL], {
        encoding: 'utf8',
      });
    } catch (err) {
      // `git grep` exits 1 when nothing matches, which is the expected case.
      if ((err as { status?: number }).status !== 1) throw err;
    }
    expect(out.trim(), 'a tracked file still hardcodes the old origin URL').toBe('');
  });
});
