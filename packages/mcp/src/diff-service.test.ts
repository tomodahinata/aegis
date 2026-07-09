import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { explainPolicyDiff } from './diff-service';

const git = (cwd: string, ...args: string[]): void => {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
};

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aegis-mcp-diff-'));
  git(root, 'init', '--initial-branch=main');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'test');
  mkdirSync(join(root, 'supabase', 'migrations'), { recursive: true });
  writeFileSync(
    join(root, 'supabase', 'migrations', '0001_init.sql'),
    `create table public.docs (id uuid primary key, user_id uuid);
     alter table public.docs enable row level security;
     create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
  );
  git(root, 'add', '-A');
  git(root, 'commit', '-m', 'init', '--no-gpg-sign');
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('explainPolicyDiff', () => {
  it('returns the markdown delta and an action-required summary for a widening', () => {
    writeFileSync(
      join(root, 'supabase', 'migrations', '0002_widen.sql'),
      'alter policy p on public.docs using (auth.uid() is not null);',
    );
    const result = explainPolicyDiff(root, 'main');
    expect(result.summary.conclusion).toBe('action-required');
    expect(result.markdown).toContain('**WIDENING**');
    expect(result.markdown).toContain('ALL rows');
    expect(result.markdown).toContain('**Scope.**'); // honest-scope footer survives the MCP path
  });

  it('reports no-change when the worktree matches the base ref', () => {
    const result = explainPolicyDiff(root, 'main');
    expect(result.summary.conclusion).toBe('no-change');
    expect(result.markdown).toContain('No access-relevant change');
  });

  it('throws (fail-closed) when the base ref does not exist — never a silent empty result', () => {
    // An MCP tool that swallowed a bad ref into "no change" would tell an agent a migration is clean
    // when the diff never ran. The git rev-parse guard must surface as an error instead.
    expect(() => explainPolicyDiff(root, 'no-such-ref-xyz')).toThrow();
  });

  it('honors trustedFunctions', () => {
    writeFileSync(
      join(root, 'supabase', 'migrations', '0002_member.sql'),
      'create policy m on public.docs for select to authenticated using (public.is_member(user_id));',
    );
    expect(explainPolicyDiff(root, 'main').summary.requiresReview).toBe(1);
    const trusted = explainPolicyDiff(root, 'main', ['public.is_member']);
    expect(trusted.summary.requiresReview).toBe(0);
    expect(trusted.summary.widening).toBe(1);
  });
});
