import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ANALYSIS_ERROR_RULE } from './internal/analysis-error';
import { scanSql } from './scan-sql';

const SQL_FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'sql');
const sqlFilesIn = (dir: string): string[] =>
  readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => join(dir, f));

function ruleIds(sql: string): string[] {
  return scanSql({ files: ['/m/001.sql'], readFile: () => sql }).findings.map((f) => f.ruleId);
}

describe('scanSql — the zero-false-positive gate (exemplary RLS)', () => {
  it('produces ZERO findings on a correct, production-grade RLS design', () => {
    const sql = `
      create table public.profiles (id uuid primary key, user_id uuid, email text);
      alter table public.profiles enable row level security;
      create policy "own profile" on public.profiles for all to authenticated
        using (auth.uid() = user_id) with check (auth.uid() = user_id);

      create table public.regions (code text primary key, name text);
      alter table public.regions enable row level security;
      create policy "regions readable" on public.regions for select to authenticated using (true);

      create function public.is_member(t uuid) returns boolean
        language sql stable security definer set search_path = public
        as $$ select exists (select 1 from public.members m where m.team = t); $$;

      grant select on public.regions to authenticated;
    `;
    expect(scanSql({ files: ['/m/init.sql'], readFile: () => sql }).findings).toEqual([]);
  });
});

describe('scanSql — per-file isolation (fail secure)', () => {
  it('skips an unreadable migration with a LOW finding instead of aborting the SQL scan', () => {
    const bad = '/m/bad.sql';
    const good = '/m/good.sql';
    const readFile = (path: string): string => {
      if (path === bad) {
        throw new Error('EACCES: permission denied');
      }
      return 'create table public.orders (id uuid, total int);';
    };

    const result = scanSql({ files: [bad, good], readFile });
    // The readable migration was still analyzed (table-without-rls fires) — not aborted.
    expect(result.findings.map((f) => f.ruleId)).toContain('rls/table-without-rls');
    // The unreadable file is surfaced, not silently dropped.
    const err = result.findings.find((f) => f.ruleId === ANALYSIS_ERROR_RULE);
    expect(err?.file).toBe(bad);
    expect(err?.severity).toBe('LOW');
  });
});

describe('scanSql — RLS rules detect their inverse', () => {
  it('flags a public table without RLS', () => {
    expect(ruleIds('create table public.orders (id uuid, total int);')).toContain(
      'rls/table-without-rls',
    );
  });

  it('respects RLS enabled in a LATER migration file (cross-file aggregation)', () => {
    const result = scanSql({
      files: ['/m/1.sql', '/m/2.sql'],
      readFile: (p) =>
        p.endsWith('1.sql')
          ? 'create table public.orders (id uuid);'
          : 'alter table public.orders enable row level security;',
    });
    expect(result.findings).toEqual([]);
  });

  it('ignores non-public schema tables', () => {
    expect(ruleIds('create table auth.sessions (id uuid);')).toEqual([]);
  });

  it('flags SECURITY DEFINER without a pinned search_path', () => {
    expect(
      ruleIds(
        'create function public.f() returns void language sql security definer as $$ select 1; $$;',
      ),
    ).toContain('rls/security-definer-search-path');
  });

  it('does not flag SECURITY DEFINER WITH a pinned search_path', () => {
    expect(
      ruleIds(
        "create function public.f() returns void language sql security definer set search_path = '' as $$ select 1; $$;",
      ),
    ).not.toContain('rls/security-definer-search-path');
  });

  it('recognizes the pg_dump quoted form `SET "search_path" TO …` as pinned', () => {
    expect(
      ruleIds(
        "create function public.f() returns void language sql security definer set \"search_path\" to 'public', 'auth' as $$ select 1; $$;",
      ),
    ).not.toContain('rls/security-definer-search-path');
  });

  it('flags an INSERT policy without WITH CHECK', () => {
    expect(ruleIds('create policy p on public.t for insert to authenticated;')).toContain(
      'rls/write-policy-without-check',
    );
  });

  it('does NOT flag an UPDATE policy without WITH CHECK (PostgreSQL reuses USING as the check)', () => {
    expect(
      ruleIds(
        'create policy p on public.t for update to authenticated using (auth.uid() = owner);',
      ),
    ).not.toContain('rls/write-policy-without-check');
  });

  it('flags a permissive write policy, but not a read-only using(true)', () => {
    expect(
      ruleIds(
        'create policy p on public.t for all to authenticated using (true) with check (true);',
      ),
    ).toContain('rls/permissive-write-policy');
    expect(
      ruleIds('create policy p on public.t for select to authenticated using (true);'),
    ).not.toContain('rls/permissive-write-policy');
  });

  it('does not flag a RESTRICTIVE true policy (deny refinement)', () => {
    expect(
      ruleIds('create policy p on public.t as restrictive for all to authenticated using (true);'),
    ).not.toContain('rls/permissive-write-policy');
  });

  it('flags an anon grant on a NON-RLS table, but not on an RLS-protected one (the Supabase norm)', () => {
    expect(
      ruleIds('create table public.orders (id uuid); grant select on public.orders to anon;'),
    ).toContain('rls/anon-table-grant');
    // anon grant + RLS enabled is the standard row-scoped Supabase pattern → not flagged.
    expect(
      ruleIds(
        'create table public.docs (id uuid); alter table public.docs enable row level security; grant select on public.docs to anon;',
      ),
    ).not.toContain('rls/anon-table-grant');
  });

  it('does not flag a function grant to authenticated', () => {
    expect(ruleIds('grant execute on function public.f() to authenticated;')).not.toContain(
      'rls/anon-table-grant',
    );
  });

  it('ignores temporary tables (session-local, RLS N/A)', () => {
    expect(ruleIds('create temporary table scratch on commit drop as select 1;')).toEqual([]);
  });
});

describe('scanSql — disk fixtures', () => {
  it('exemplary good migration yields ZERO findings', () => {
    expect(scanSql({ files: sqlFilesIn(join(SQL_FIXTURES, 'good')) }).findings).toEqual([]);
  });

  it('the vuln migration fires every RLS rule', () => {
    const ids = new Set(
      scanSql({ files: sqlFilesIn(join(SQL_FIXTURES, 'vuln')) }).findings.map((f) => f.ruleId),
    );
    for (const id of [
      'rls/table-without-rls',
      'rls/security-definer-search-path',
      'rls/write-policy-without-check',
      'rls/permissive-write-policy',
      'rls/anon-table-grant',
    ]) {
      expect([...ids]).toContain(id);
    }
  });
});
