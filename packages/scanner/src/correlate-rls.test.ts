import { describe, expect, it } from 'vitest';
import { correlateRls } from './correlate-rls';
import type { Finding } from './types';

function run(sql: string, ts: string): string[] {
  return findingsOf(sql, ts).map((f) => f.ruleId);
}

function findingsOf(sql: string, ts: string): Finding[] {
  const files: Record<string, string> = { '/m/1.sql': sql, '/app/data.ts': ts };
  return correlateRls({
    sqlFiles: ['/m/1.sql'],
    tsFiles: ['/app/data.ts'],
    readFile: (p) => files[p] ?? '',
  });
}

describe('correlateRls', () => {
  it('confirms exposure: a table without RLS queried via a non-admin client', () => {
    expect(
      run(
        'create table public.orders (id uuid);',
        "import { supabase } from './c'; export const all = () => supabase.from('orders').select('*');",
      ),
    ).toEqual(['rls/exposed-table-access']);
  });

  // SEC-02: a high-confidence (no-RLS) exposure keeps the firm "confirmed exposure" wording.
  it('uses the firm "confirmed exposure" copy for a high-confidence no-RLS table', () => {
    const finding = findingsOf(
      'create table public.orders (id uuid);',
      "export const all = () => supabase.from('orders').select('*');",
    )[0];
    expect(finding?.confidence).toBe('high');
    expect(finding?.message).toContain('confirmed exposure');
  });

  it('does not flag access via the service-role admin client (RLS bypassed by design)', () => {
    expect(
      run(
        'create table public.orders (id uuid);',
        "import { createAdminClient } from './c'; export const all = () => createAdminClient().from('orders').select('*');",
      ),
    ).toEqual([]);
  });

  it('does not flag when the table has RLS enabled (no weak table → no TS parsed)', () => {
    expect(
      run(
        'create table public.orders (id uuid); alter table public.orders enable row level security;',
        "export const all = () => supabase.from('orders').select('*');",
      ),
    ).toEqual([]);
  });

  it('does not flag a query against a different, safe table', () => {
    expect(
      run(
        'create table public.orders (id uuid);',
        "export const all = () => supabase.from('profiles').select('*');",
      ),
    ).toEqual([]);
  });

  // Parity with the rls/* rules' precision gates — the correlator re-derives the same verdicts, so it
  // must apply the same suppressions or it resurrects, at HIGH confidence with "confirmed exposure"
  // phrasing, the exact false positives the rules learned to skip.
  describe('suppression parity with the rls/* rules', () => {
    it('does not flag a table whose RLS is enabled procedurally (DO-block / dynamic EXECUTE)', () => {
      expect(
        run(
          `create table public.orders (id uuid);
           do $$ begin execute 'alter table public.orders enable row level security'; end $$;`,
          "export const all = () => supabase.from('orders').select('*');",
        ),
      ).toEqual([]);
    });

    it('does not flag an unconditional write policy scoped only to service_role (unreachable by the querying client)', () => {
      expect(
        run(
          `create table public.jobs (id uuid primary key, user_id uuid not null);
           alter table public.jobs enable row level security;
           create policy jobs_owner on public.jobs for select using (auth.uid() = user_id);
           create policy jobs_svc on public.jobs for all to service_role using (true) with check (true);`,
          "export const all = () => supabase.from('jobs').select('*');",
        ),
      ).toEqual([]);
    });

    it('does not flag an authenticated-only policy scoped only to service_role', () => {
      expect(
        run(
          `create table public.docs (id uuid primary key, user_id uuid not null);
           alter table public.docs enable row level security;
           create policy docs_svc on public.docs for select to service_role using (auth.role() = 'authenticated');`,
          "export const all = () => supabase.from('docs').select('*');",
        ),
      ).toEqual([]);
    });
  });

  describe('authenticated-only policy (RLS exists but does not scope to the caller)', () => {
    const ownedAuthOnly = `create table public.docs (id uuid primary key, user_id uuid not null);
       alter table public.docs enable row level security;
       create policy "p" on public.docs for select to authenticated using (auth.role() = 'authenticated');`;

    const findings = findingsOf;

    it('confirms a MEDIUM-confidence exposure at the non-admin query site', () => {
      const result = findings(
        ownedAuthOnly,
        "export const all = () => supabase.from('docs').select('*');",
      );
      expect(result.map((f) => f.ruleId)).toEqual(['rls/exposed-table-access']);
      expect(result[0]?.confidence).toBe('medium'); // intent-dependent read exposure → non-blocking
    });

    // SEC-02: the medium path must NOT claim "confirmed exposure" or any absolute-protection phrasing.
    it('uses softer, non-absolute copy for the medium authenticated-only path', () => {
      const finding = findings(
        ownedAuthOnly,
        "export const all = () => supabase.from('docs').select('*');",
      )[0];
      expect(finding?.message).not.toContain('confirmed exposure');
      expect(finding?.message).not.toMatch(/completely protect|fully protect/i);
      expect(finding?.message).toMatch(/flagged for review/i);
    });

    it('does not flag access via the service-role admin client', () => {
      expect(
        findings(
          ownedAuthOnly,
          "import { createAdminClient } from './c'; export const all = () => createAdminClient().from('docs').select('*');",
        ),
      ).toEqual([]);
    });

    it('does not treat an owner-bound or role-delegated policy as weak', () => {
      const ownerBound = `create table public.docs (id uuid, user_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated using (auth.uid() = user_id);`;
      expect(
        findings(ownerBound, "export const all = () => supabase.from('docs').select('*');"),
      ).toEqual([]);
    });
  });
});
