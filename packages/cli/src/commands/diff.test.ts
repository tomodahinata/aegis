import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UsageError } from '../errors';
import { EXIT } from '../exit';
import { runDiff } from './diff';

const git = (cwd: string, ...args: string[]): void => {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
};

/** A throwaway git repo whose supabase/migrations we can commit to and then mutate. */
function makeRepo(): {
  root: string;
  write: (name: string, sql: string) => void;
  commit: (msg: string) => void;
} {
  const root = mkdtempSync(join(tmpdir(), 'aegis-diff-'));
  git(root, 'init', '--initial-branch=main');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'test');
  mkdirSync(join(root, 'supabase', 'migrations'), { recursive: true });
  return {
    root,
    write: (name, sql) => writeFileSync(join(root, 'supabase', 'migrations', name), sql),
    commit: (msg) => {
      git(root, 'add', '-A');
      git(root, 'commit', '-m', msg, '--no-gpg-sign');
    },
  };
}

const BASE_SQL = `
create table public.docs (id uuid primary key, user_id uuid);
alter table public.docs enable row level security;
create policy p on public.docs for select to authenticated using (auth.uid() = user_id);
`;

describe('aegis diff (end-to-end against a real git repo)', () => {
  let repo: ReturnType<typeof makeRepo>;
  let stdout: string[];

  beforeEach(() => {
    repo = makeRepo();
    stdout = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      stdout.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(repo.root, { recursive: true, force: true });
  });

  it('flags a widening between the base ref and the WORKING TREE, and exits 1', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    repo.write('0002_widen.sql', 'alter policy p on public.docs using (auth.uid() is not null);\n');
    const code = runDiff({
      cwd: repo.root,
      base: 'main',
      format: 'pretty',
      trust: [],
      strict: false,
    });
    expect(code).toBe(EXIT.FINDINGS);
    const out = stdout.join('');
    expect(out).toContain('WIDENING');
    expect(out).toContain('docs');
    expect(out).toContain('ALL rows');
  });

  it('compares two COMMITTED refs when --head is given, without touching the worktree', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    repo.write('0002_disable.sql', 'alter table public.docs disable row level security;\n');
    repo.commit('disable rls');
    // The worktree now holds an unrelated dirty file that must NOT leak into a ref-to-ref diff.
    repo.write('9999_dirty.sql', 'create table public.dirty (id uuid);');
    const code = runDiff({
      cwd: repo.root,
      base: 'main~1',
      head: 'main',
      format: 'json',
      trust: [],
      strict: false,
    });
    expect(code).toBe(EXIT.FINDINGS);
    const parsed = JSON.parse(stdout.join(''));
    expect(parsed.summary.conclusion).toBe('action-required');
    expect(parsed.deltas).toEqual([
      expect.objectContaining({ kind: 'widening', change: { type: 'rls-disabled' } }),
    ]);
    expect(JSON.stringify(parsed)).not.toContain('dirty');
  });

  it('exits 0 with "no access-relevant change" on a no-op change', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    repo.write('0002_index.sql', 'create index docs_idx on public.docs (user_id);\n');
    const code = runDiff({
      cwd: repo.root,
      base: 'main',
      format: 'pretty',
      trust: [],
      strict: false,
    });
    expect(code).toBe(EXIT.CLEAN);
    expect(stdout.join('')).toContain('No access-relevant change');
  });

  it('notice-level widenings pass by default and fail with --strict', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    repo.write(
      '0002_new_owner_policy.sql',
      'create policy p2 on public.docs for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);\n',
    );
    const args = { cwd: repo.root, base: 'main', format: 'pretty' as const, trust: [] };
    expect(runDiff({ ...args, strict: false })).toBe(EXIT.CLEAN);
    stdout.length = 0;
    expect(runDiff({ ...args, strict: true })).toBe(EXIT.FINDINGS);
  });

  it('honors --trust: an allowlisted helper is a notice widening, not review', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    repo.write(
      '0002_member.sql',
      'create policy m on public.docs for select to authenticated using (public.is_member(user_id));\n',
    );
    const args = { cwd: repo.root, base: 'main', format: 'json' as const, strict: false };
    runDiff({ ...args, trust: [] });
    expect(JSON.parse(stdout.join('')).deltas[0].kind).toBe('requires-review');
    stdout.length = 0;
    runDiff({ ...args, trust: ['public.is_member'] });
    expect(JSON.parse(stdout.join('')).deltas[0].kind).toBe('widening');
  });

  it('emits the sticky-comment marker and scope footer in markdown mode', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    runDiff({ cwd: repo.root, base: 'main', format: 'markdown', trust: [], strict: false });
    const out = stdout.join('');
    expect(out).toContain('<!-- aegis-policy-diff -->');
    expect(out).toContain('**Scope.**');
  });

  it('rejects an invalid ref with a usage error (exit-2 path), not a stack trace', () => {
    repo.write('0001_init.sql', BASE_SQL);
    repo.commit('init');
    expect(() =>
      runDiff({ cwd: repo.root, base: 'no-such-ref', format: 'pretty', trust: [], strict: false }),
    ).toThrow(UsageError);
  });
});
