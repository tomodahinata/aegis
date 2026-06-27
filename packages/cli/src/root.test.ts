import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveRoot } from './root';

describe('resolveRoot', () => {
  const PROC = '/home/user/project';

  it('uses the process cwd when nothing is given', () => {
    expect(resolveRoot(undefined, undefined, PROC)).toBe(PROC);
  });

  it('honors a positional path, resolved against the process cwd', () => {
    // The regression guard: `aegis scan apps/dashboard` must target apps/dashboard,
    // not silently fall back to the current directory.
    expect(resolveRoot('apps/dashboard', undefined, PROC)).toBe(resolve(PROC, 'apps/dashboard'));
  });

  it('uses --cwd when no positional is given', () => {
    expect(resolveRoot(undefined, '/srv/app', PROC)).toBe('/srv/app');
  });

  it('resolves a positional against the --cwd base when both are given', () => {
    expect(resolveRoot('packages/core', '/srv/app', PROC)).toBe(
      resolve('/srv/app', 'packages/core'),
    );
  });

  it('treats an absolute positional as the target verbatim', () => {
    expect(resolveRoot('/abs/target', '/srv/app', PROC)).toBe('/abs/target');
  });
});
