import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { SQL_LABELS } from '../fixtures/labels';
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

describe('scanSql — rls/policy-not-owner-scoped (RLS exists but does not scope to the caller)', () => {
  const RULE = 'rls/policy-not-owner-scoped';
  const scan1 = (sql: string) => scanSql({ files: ['/m/1.sql'], readFile: () => sql });
  const idsOf = (sql: string): string[] => scan1(sql).findings.map((f) => f.ruleId);

  it('fires at MEDIUM confidence on an authenticated-only SELECT over a table with an ownership column', () => {
    const finding = scan1(
      `create table public.docs (id uuid primary key, user_id uuid not null, body text);
       alter table public.docs enable row level security;
       create policy "p" on public.docs for select to authenticated using (auth.role() = 'authenticated');`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('medium'); // non-blocking: surfaced for review, never fails CI
    expect(finding?.severity).toBe('HIGH');
  });

  it('fires on `auth.uid() IS NOT NULL`', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid, tenant_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated using (auth.uid() is not null);`,
      ),
    ).toContain(RULE);
  });

  it('carries a structured explanation + an owner-scoped suggested policy bound to the real column', () => {
    const finding = scan1(
      `create table public.invoices (id uuid primary key, tenant_id uuid not null, total int);
       alter table public.invoices enable row level security;
       create policy "p" on public.invoices for select to authenticated using (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding?.explanation?.kind).toBe('authenticated-only');
    // The suggestion binds to the table's actual ownership column (tenant_id), not a generic placeholder.
    expect(finding?.explanation?.suggestedFix).toBe(
      'create policy "invoices_select_owner" on public.invoices\n' +
        '  for select to authenticated\n' +
        '  using (auth.uid() = tenant_id);',
    );
    expect(finding?.explanation?.detail).toContain('tenant_id');
  });

  it('labels the write-check gap distinctly and suggests a both-clause policy', () => {
    const finding = scan1(
      `create table public.docs (id uuid primary key, user_id uuid not null);
       alter table public.docs enable row level security;
       create policy "p" on public.docs for all to authenticated
         using (auth.uid() = user_id) with check (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding?.explanation?.kind).toBe('authenticated-only-write-check');
    expect(finding?.explanation?.suggestedFix).toContain('using (auth.uid() = user_id)');
    expect(finding?.explanation?.suggestedFix).toContain('with check (auth.uid() = user_id)');
  });

  it('binds the suggested fix to an ownership column introduced by ALTER TABLE ADD COLUMN', () => {
    const finding = scan1(
      `create table public.docs (id uuid primary key, body text);
       alter table public.docs add column org_id uuid not null;
       alter table public.docs enable row level security;
       create policy "p" on public.docs for select to authenticated
         using (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding?.explanation?.suggestedFix).toContain('using (auth.uid() = org_id);');
    expect(finding?.explanation?.detail).toContain('org_id');
  });

  it('prefers a CREATE-TABLE ownership column over a later ALTER-added one', () => {
    const finding = scan1(
      `create table public.docs (id uuid primary key, user_id uuid not null);
       alter table public.docs add column tenant_id uuid;
       alter table public.docs enable row level security;
       create policy "p" on public.docs for select to authenticated
         using (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding?.explanation?.suggestedFix).toContain('auth.uid() = user_id');
  });

  it('binds to a column the table declares, not one named only in a FOREIGN KEY reference', () => {
    // `user_id` appears only inside `references ...(user_id)`; the table's own ownership column is tenant_id.
    const finding = scan1(
      `create table public.audit_log (
         id uuid primary key,
         actor uuid references public.profiles(user_id),
         tenant_id uuid not null
       );
       alter table public.audit_log enable row level security;
       create policy "p" on public.audit_log for select to authenticated
         using (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding?.explanation?.suggestedFix).toContain('auth.uid() = tenant_id');
    expect(finding?.explanation?.suggestedFix).not.toContain('user_id');
  });

  it('does NOT fire on an owner-bound policy (auth.uid() = user_id)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid, user_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated using (auth.uid() = user_id);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire when the table has no ownership column (shared/reference data)', () => {
    expect(
      idsOf(
        `create table public.regions (code text primary key, name text);
         alter table public.regions enable row level security;
         create policy "p" on public.regions for select to authenticated using (auth.uid() is not null);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire on a membership subquery (role-delegated) or a custom function (function-delegated)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid, team_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated
           using (team_id in (select team_id from public.members where user_id = auth.uid()));`,
      ),
    ).not.toContain(RULE);
    expect(
      idsOf(
        `create table public.docs (id uuid, user_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for all to authenticated using (public.has_access(id)) with check (public.has_access(id));`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire on a RESTRICTIVE authenticated-only policy (deny refinement)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid, user_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs as restrictive for all to authenticated using (auth.uid() is not null);`,
      ),
    ).not.toContain(RULE);
  });

  // Field-validated false positives (a 450-repo public-corpus study): the rule fired on policies that are
  // restrictive, or owner-bound written a way the matcher missed. Each must now stay silent.
  it('does NOT fire on a service_role policy (backend-only, not "every authenticated user")', () => {
    // The dominant real-world FP: a correctly owner-scoped table that ALSO grants the backend full access.
    expect(
      idsOf(
        `create table public.tickets (id uuid primary key, user_id uuid not null, body text);
         alter table public.tickets enable row level security;
         create policy "own" on public.tickets for select using (auth.uid() = user_id);
         create policy "svc" on public.tickets for all using (auth.role() = 'service_role');`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire on a JWT admin-claim gate (authorizes by claim, not "every authenticated user")', () => {
    expect(
      idsOf(
        `create table public.conversations (id uuid primary key, user_id uuid not null, body text);
         alter table public.conversations enable row level security;
         create policy "admins" on public.conversations for select
           using ((auth.jwt() -> 'app_metadata' ->> 'claims_admin')::boolean = true);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire on owner-bound predicates written with casts or the Supabase `(select … as uid)` wrapper', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid primary key, user_id uuid not null);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select using (auth.uid()::text = user_id::text);`,
      ),
    ).not.toContain(RULE);
    expect(
      idsOf(
        `create table public.sessions (id uuid primary key, user_id uuid not null);
         alter table public.sessions enable row level security;
         create policy "p" on public.sessions for insert to authenticated
           with check (( select auth.uid() as uid) = user_id);`,
      ),
    ).not.toContain(RULE);
  });

  // Cross-rule regression: a service_role gate must classify as `role-delegated`, not `unknown`, or the
  // sibling `rls/anon-writable` rule wrongly fires on an anon-reachable `FOR ALL` policy an anon caller can
  // never satisfy. (This surfaced as 59 anon-writable false positives on a real public corpus.)
  it('does NOT make anon-writable fire on a service_role FOR ALL policy with no TO clause', () => {
    const ids = idsOf(
      `create table public.audit (id uuid primary key, user_id uuid not null, action text);
       alter table public.audit enable row level security;
       create policy "owner_read" on public.audit for select to authenticated using (auth.uid() = user_id);
       create policy "backend" on public.audit for all
         using (auth.role() = 'service_role') with check (auth.role() = 'service_role');`,
    );
    expect(ids).not.toContain('rls/anon-writable');
    expect(ids).not.toContain(RULE);
  });

  // Per-shape recall lock for the real-world gap forms in `fixtures/sql/vuln/rls-real-world-gaps.sql`. The
  // disk-fixture test only asserts the rule fires SOMEWHERE across the vuln corpus, so each shape is pinned
  // here individually — the precision hardening must not silently suppress any of them.
  it('still fires on the quoted (declarative-schema) authenticated-only gap', () => {
    expect(
      idsOf(
        `create table public.quoted_docs (id uuid primary key, user_id uuid not null, body text);
         alter table public.quoted_docs enable row level security;
         create policy "p" on public.quoted_docs for select to authenticated
           using (("auth"."role"() = 'authenticated'::"text"));`,
      ),
    ).toContain(RULE);
  });

  it('still fires on the (select auth.uid()) IS NOT NULL session-proof gap', () => {
    expect(
      idsOf(
        `create table public.wrapped_docs (id uuid primary key, owner_id uuid not null, body text);
         alter table public.wrapped_docs enable row level security;
         create policy "p" on public.wrapped_docs for select to authenticated
           using ((select auth.uid()) is not null);`,
      ),
    ).toContain(RULE);
  });

  it('still fires on an OR-disjunction that re-widens past a service_role arm to every authenticated user', () => {
    expect(
      idsOf(
        `create table public.mixed_docs (id uuid primary key, user_id uuid not null, body text);
         alter table public.mixed_docs enable row level security;
         create policy "p" on public.mixed_docs for select to authenticated
           using (auth.role() = 'service_role' or auth.uid() is not null);`,
      ),
    ).toContain(RULE);
  });

  it('resolves the ownership column across files (table in one migration, policy in another)', () => {
    const result = scanSql({
      files: ['/m/1.sql', '/m/2.sql'],
      readFile: (p) =>
        p.endsWith('1.sql')
          ? 'create table public.docs (id uuid primary key, user_id uuid not null);'
          : `alter table public.docs enable row level security;
             create policy "p" on public.docs for select to authenticated using (auth.role() = 'authenticated');`,
    });
    expect(result.findings.map((f) => f.ruleId)).toContain(RULE);
  });

  it('resolves an ownership column added later via ALTER TABLE ADD COLUMN', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid primary key, body text);
         alter table public.docs add column user_id uuid not null;
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated using (auth.uid() is not null);`,
      ),
    ).toContain(RULE);
  });

  // COR-01: an `auth.*` token inside a comment or a string literal must NOT manufacture this finding.
  it('does NOT fire when auth.uid() appears only inside a SQL comment (no false positive)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid primary key, user_id uuid not null, status text);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated
           using (status = 'published' /* auth.uid() = user_id */);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT fire when auth.role() appears only inside a string literal (no false positive)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid primary key, user_id uuid not null, note text);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for select to authenticated using (note = 'see auth.role()');`,
      ),
    ).not.toContain(RULE);
  });

  // SEC-01: a correct USING with a weak WITH CHECK on a write-capable command is the IDOR-write gap.
  it('fires on FOR ALL with an owner-bound USING but an authenticated-only WITH CHECK (write-check gap)', () => {
    const finding = scan1(
      `create table public.docs (id uuid primary key, user_id uuid not null, body text);
       alter table public.docs enable row level security;
       create policy "p" on public.docs for all to authenticated
         using (auth.uid() = user_id) with check (auth.uid() is not null);`,
    ).findings.find((f) => f.ruleId === RULE);
    expect(finding).toBeDefined();
    expect(finding?.confidence).toBe('medium');
    // The message and evidence are attributed to the write path (WITH CHECK), not the (correct) USING.
    expect(finding?.message).toMatch(/WITH CHECK/i);
    expect(finding?.evidence).toContain('is not null');
  });

  it('does NOT fire on FOR ALL when BOTH USING and WITH CHECK are owner-bound (correct write policy)', () => {
    expect(
      idsOf(
        `create table public.docs (id uuid primary key, user_id uuid not null, body text);
         alter table public.docs enable row level security;
         create policy "p" on public.docs for all to authenticated
           using (auth.uid() = user_id) with check (auth.uid() = user_id);`,
      ),
    ).not.toContain(RULE);
  });
});

describe('scanSql — rls/anon-writable (anon can modify/delete existing rows)', () => {
  const RULE = 'rls/anon-writable';
  const table = `create table public.jobs (id uuid primary key, user_id uuid, is_public boolean, share_slug text);
                 alter table public.jobs enable row level security;`;

  it('flags an anon UPDATE policy whose predicate only checks row state (the row-state-only gap)', () => {
    expect(
      ruleIds(
        `${table}
         create policy "public bump" on public.jobs for update to anon, authenticated
           using (is_public = true and share_slug is not null)
           with check (is_public = true and share_slug is not null);`,
      ),
    ).toContain(RULE);
  });

  it('flags an anon DELETE gated only on row state', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for delete to anon using (is_public = true);`,
      ),
    ).toContain(RULE);
  });

  it('does NOT flag an anon INSERT (a public submission form is a legitimate pattern)', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for insert to anon with check (is_public = true);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT flag an anon UPDATE whose predicate is owner-bound (anon matches no row)', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for update to anon using (auth.uid() = user_id);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT flag a write policy with the same predicate when anon is NOT a grantee', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for update to authenticated using (is_public = true);`,
      ),
    ).not.toContain(RULE);
  });

  it('leaves the unconditional-USING case to rls/permissive-write-policy (no double report)', () => {
    const ids = ruleIds(
      `${table}
       create policy "p" on public.jobs for update to anon using (true);`,
    );
    expect(ids).toContain('rls/permissive-write-policy');
    expect(ids).not.toContain(RULE);
  });

  it('flags a no-TO-clause UPDATE (Postgres applies it to PUBLIC, which includes anon)', () => {
    // The most common Supabase form: no `TO` clause + a row-state predicate. Postgres defaults the
    // policy to PUBLIC, so an unauthenticated visitor can modify published rows — must not be missed.
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for update using (is_public = true);`,
      ),
    ).toContain(RULE);
  });

  it('does NOT flag a no-TO-clause UPDATE whose predicate is owner-bound', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for update using (auth.uid() = user_id);`,
      ),
    ).not.toContain(RULE);
  });

  it('flags an explicit `to public` DELETE gated only on row state', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for delete to public using (is_public = true);`,
      ),
    ).toContain(RULE);
  });

  it('flags a FOR ALL policy to anon with a row-state USING predicate', () => {
    expect(
      ruleIds(
        `${table}
         create policy "p" on public.jobs for all to anon
           using (is_public = true) with check (is_public = true);`,
      ),
    ).toContain(RULE);
  });

  it('reports BOTH rules for FOR ALL USING (row-state) WITH CHECK (true) — complementary defects', () => {
    // USING row-state lets anon target existing rows (anon-writable); WITH CHECK true leaves the
    // resulting state unconstrained (permissive-write). Two distinct gaps → two findings, by design.
    const ids = ruleIds(
      `${table}
       create policy "p" on public.jobs for all to anon using (is_public = true) with check (true);`,
    );
    expect(ids).toContain(RULE);
    expect(ids).toContain('rls/permissive-write-policy');
  });

  // Regression: a `USING (false)` deny-all policy is the append-only/immutable idiom — satisfiable by no
  // caller, so it is the SAFEST design, not a row-state gap. It was false-flagged HIGH on real audit-log
  // tables (`for update using(false)`) until `classifyPredicate` learned the `'deny'` class.
  it('does NOT flag a deny-all UPDATE policy (USING (false) — immutable table)', () => {
    expect(
      ruleIds(
        `${table}
         create policy "no_update" on public.jobs for update using (false) with check (false);`,
      ),
    ).not.toContain(RULE);
  });

  it('does NOT flag a deny-all DELETE policy (USING (false) — append-only table)', () => {
    expect(
      ruleIds(
        `${table}
         create policy "no_delete" on public.jobs for delete using (false);`,
      ),
    ).not.toContain(RULE);
  });
});

describe('scanSql — final-state migration semantics (DROP/ALTER supersede, no stale FPs)', () => {
  const ids = (sql: string): string[] =>
    scanSql({ files: ['/m/1.sql'], readFile: () => sql }).findings.map((f) => f.ruleId);

  it('DROP POLICY removes a permissive policy that was later recreated safely (no stale FP)', () => {
    const sql = `create table public.t (id uuid primary key, user_id uuid not null);
      alter table public.t enable row level security;
      create policy p on public.t for all to authenticated using (true) with check (true);
      drop policy p on public.t;
      create policy p on public.t for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);`;
    expect(ids(sql)).not.toContain('rls/permissive-write-policy');
    expect(ids(sql)).not.toContain('rls/policy-not-owner-scoped');
  });

  it('DROP POLICY IF EXISTS lets a weak policy be fixed by recreation (no policy-not-owner-scoped FP)', () => {
    const sql = `create table public.docs (id uuid primary key, user_id uuid not null);
      alter table public.docs enable row level security;
      create policy d on public.docs for select to authenticated using (auth.uid() is not null);
      drop policy if exists d on public.docs;
      create policy d on public.docs for select to authenticated using (auth.uid() = user_id);`;
    expect(ids(sql)).not.toContain('rls/policy-not-owner-scoped');
  });

  it('ALTER POLICY updates the predicate (a weakening ALTER is detected)', () => {
    const sql = `create table public.docs (id uuid primary key, user_id uuid not null);
      alter table public.docs enable row level security;
      create policy d on public.docs for select to authenticated using (auth.uid() = user_id);
      alter policy d on public.docs using (auth.uid() is not null);`;
    expect(ids(sql)).toContain('rls/policy-not-owner-scoped');
  });

  it('ALTER POLICY that strengthens the predicate clears the finding (no FP)', () => {
    const sql = `create table public.docs (id uuid primary key, user_id uuid not null);
      alter table public.docs enable row level security;
      create policy d on public.docs for select to authenticated using (auth.uid() is not null);
      alter policy d on public.docs using (auth.uid() = user_id);`;
    expect(ids(sql)).not.toContain('rls/policy-not-owner-scoped');
  });

  it('CREATE OR REPLACE FUNCTION with a pinned search_path supersedes an earlier unpinned one (no FP)', () => {
    const sql = `create function public.f() returns void language sql security definer as $$ select 1; $$;
      create or replace function public.f() returns void language sql security definer set search_path = '' as $$ select 1; $$;`;
    expect(ids(sql)).not.toContain('rls/security-definer-search-path');
  });

  it('DROP FUNCTION removes a since-deleted unpinned SECURITY DEFINER function (no FP)', () => {
    const sql = `create function public.f() returns void language sql security definer as $$ select 1; $$;
      drop function public.f();`;
    expect(ids(sql)).not.toContain('rls/security-definer-search-path');
  });

  it('still flags a live unpinned SECURITY DEFINER function (recall preserved)', () => {
    const sql = `create function public.f() returns void language sql security definer as $$ select 1; $$;`;
    expect(ids(sql)).toContain('rls/security-definer-search-path');
  });
});

describe('scanSql — procedural RLS enable suppresses the CI-blocking table-without-rls false positive', () => {
  it('a DO-block loop that dynamically enables RLS on all public tables → no table-without-rls', () => {
    const sql = `
      create table public.t1 (id uuid, user_id uuid);
      create table public.t2 (id uuid, user_id uuid);
      do $$ declare r record; begin
        for r in select tablename from pg_tables where schemaname = 'public' loop
          execute format('alter table %I enable row level security', r.tablename);
        end loop; end $$;`;
    expect(ruleIds(sql)).not.toContain('rls/table-without-rls');
  });

  it('regression: a genuinely unprotected table (no procedural enable) still fires', () => {
    expect(ruleIds('create table public.t (id uuid, user_id uuid);')).toContain(
      'rls/table-without-rls',
    );
  });

  it("regression: a string literal mentioning 'enable row level security' is NOT a procedural enable — the rule still fires", () => {
    const sql = `
      create table public.t (id uuid, user_id uuid);
      comment on table public.t is 'TODO: enable row level security';`;
    expect(ruleIds(sql)).toContain('rls/table-without-rls');
  });

  it('a grant to anon on a procedurally-enabled table → no anon-table-grant (same suppression as table-without-rls)', () => {
    const sql = `
      create table public.t (id uuid, user_id uuid);
      grant select, update on public.t to anon;
      do $$ begin execute 'alter table public.t enable row level security'; end $$;`;
    expect(ruleIds(sql)).not.toContain('rls/anon-table-grant');
  });

  it('a schema-wide grant to anon still fires under a procedural enable (wildcard is flagged regardless of RLS state, by design)', () => {
    const sql = `
      create table public.t (id uuid, user_id uuid);
      grant select on all tables in schema public to anon;
      do $$ begin execute 'alter table public.t enable row level security'; end $$;`;
    expect(ruleIds(sql)).toContain('rls/anon-table-grant');
  });
});

describe('scanSql — a policy scoped only to service_role/admin is trusted backend access, not a gap', () => {
  const svc = (clause: string): string =>
    `create table public.t (id uuid, user_id uuid);
     alter table public.t enable row level security;
     create policy p on public.t ${clause};`;
  it('service_role permissive write (USING/WITH CHECK true) → silent', () => {
    expect(ruleIds(svc('for all to service_role using (true) with check (true)'))).toEqual([]);
  });
  it('service_role authenticated-only on an owner table → no policy-not-owner-scoped', () => {
    expect(ruleIds(svc('for select to service_role using (auth.uid() is not null)'))).toEqual([]);
  });
  it('service_role INSERT without WITH CHECK → no write-policy-without-check', () => {
    expect(ruleIds(svc('for insert to service_role'))).toEqual([]);
  });
  it('regression: the SAME unconditional write to authenticated DOES fire', () => {
    expect(ruleIds(svc('for all to authenticated using (true) with check (true)'))).toContain(
      'rls/permissive-write-policy',
    );
  });

  // The boundary `appliesOnlyToPrivilegedRoles` documents: a policy that ALSO names an unprivileged role
  // stays fully in scope. If `.every()` ever regressed to `.some()`, all three rules would silently
  // suppress real findings — these are the only tests that would catch it.
  it('a MIXED role list (service_role, authenticated) stays in scope — permissive write fires', () => {
    expect(
      ruleIds(svc('for all to service_role, authenticated using (true) with check (true)')),
    ).toContain('rls/permissive-write-policy');
  });
  it('mixed role list: INSERT without WITH CHECK fires write-policy-without-check', () => {
    expect(ruleIds(svc('for insert to service_role, authenticated'))).toContain(
      'rls/write-policy-without-check',
    );
  });
  it('mixed role list: authenticated-only predicate on an owner table fires policy-not-owner-scoped', () => {
    expect(
      ruleIds(svc('for select to service_role, authenticated using (auth.uid() is not null)')),
    ).toContain('rls/policy-not-owner-scoped');
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
    const expected = SQL_LABELS.find((l) => l.dir === 'vuln')?.expect ?? [];
    expect(expected.length).toBeGreaterThan(0);
    for (const id of expected) {
      expect([...ids]).toContain(id);
    }
  });
});
