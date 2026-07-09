/**
 * Golden suite: curated base/head migration pairs covering every delta class and every
 * predicate-class transition the engine claims to understand. This is the launch gate — a wrong
 * verdict here is the product's worst failure (a false "neutral"/"narrowing" on a real widening
 * destroys the precision asset), so every case asserts the exact verdict, not just "some delta".
 */

import { buildRlsModel } from '@aegiskit/scanner';
import { describe, expect, it } from 'vitest';
import { type DeltaKind, type DeltaSeverity, type DiffOptions, diffAccess } from './diff';

const model = (sql: string) =>
  buildRlsModel([{ path: '/supabase/migrations/0001.sql', text: sql }]);

interface Golden {
  readonly name: string;
  readonly base: string;
  readonly head: string;
  /** Expected deltas, matched exhaustively (order-independent). */
  readonly expect: readonly { kind: DeltaKind; severity?: DeltaSeverity; table?: string }[];
  readonly options?: DiffOptions;
}

const T = (columns = 'id uuid primary key, user_id uuid, status text') => `
  create table public.docs (${columns});
  alter table public.docs enable row level security;
`;

const CASES: readonly Golden[] = [
  // ── WIDENING: the headline class transitions ────────────────────────────────────────────────
  {
    name: 'owner-bound → authenticated-only (the flagship widening)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() is not null);`,
    expect: [{ kind: 'widening', severity: 'high', table: 'docs' }],
  },
  {
    name: 'owner-bound → unconditional',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'deny → unconditional on a write (immutable table opened up)',
    base: `${T()} create policy p on public.docs for update using (false);`,
    head: `${T()} create policy p on public.docs for update using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'RLS disabled via ALTER TABLE … DISABLE (the fail-open the model must now see)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);
           alter table public.docs disable row level security;`,
    expect: [{ kind: 'widening', severity: 'high', table: 'docs' }],
  },
  {
    name: 'RESTRICTIVE policy removed (deny-refinement lifted)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);
           create policy lock on public.docs as restrictive for select using (status = 'active');`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'roles broadened: TO authenticated → TO public (anon gains rows)',
    base: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    head: `${T()} create policy p on public.docs for select using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'new table shipped without RLS',
    base: `create table public.a (id uuid);
           alter table public.a enable row level security;`,
    head: `create table public.a (id uuid);
           alter table public.a enable row level security;
           create table public.leaky (id uuid, user_id uuid);`,
    expect: [{ kind: 'widening', severity: 'high', table: 'leaky' }],
  },
  {
    name: 'grant to anon added on a table WITHOUT RLS',
    base: `create table public.stats (id uuid);`,
    head: `create table public.stats (id uuid);
           grant select on public.stats to anon;`,
    // The base table without RLS predates the diff; only the grant is new.
    expect: [{ kind: 'widening', severity: 'high', table: 'stats' }],
  },
  {
    name: 'grant to authenticated added on an RLS-protected table (standard pattern → notice)',
    base: `${T()}`,
    head: `${T()} grant select on public.docs to authenticated;`,
    expect: [{ kind: 'widening', severity: 'notice', table: 'docs' }],
  },
  {
    // COR-02: a schema-wide grant to anon is BROADER than any single-table one, so when any modeled
    // table lacks RLS it must rank `high` — never below its single-table form.
    name: 'grant to anon on ALL tables in schema, some table without RLS → high (broadest exposure)',
    base: `create table public.secret (id uuid);`,
    head: `create table public.secret (id uuid);
           grant select on all tables in schema public to anon;`,
    expect: [{ kind: 'widening', severity: 'high', table: '*' }],
  },
  {
    // COR-01: a per-table grant already implied by GRANT … ON ALL TABLES did not widen anything — anon
    // (here: authenticated) already had access via the schema-wide grant, so this must be an empty diff.
    name: 'redundant per-table grant already covered by GRANT … ON ALL TABLES → no false widening',
    base: `${T()} grant select on all tables in schema public to authenticated;`,
    head: `${T()} grant select on all tables in schema public to authenticated;
           grant select on public.docs to authenticated;`,
    expect: [],
  },
  {
    name: 'command widened: FOR SELECT → FOR ALL (writes gained)',
    base: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() is not null);`,
    head: `${T()} create policy p on public.docs for all to authenticated using (auth.uid() is not null);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'SEC-01: WITH CHECK weakened while USING stays owner-bound (IDOR-write)',
    base: `${T()} create policy p on public.docs for update to authenticated
             using (auth.uid() = user_id) with check (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for update to authenticated
             using (auth.uid() = user_id) with check (auth.uid() is not null);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'storage.objects: bucket-scoped read → unconditional read',
    base: `create policy b on storage.objects for select using (bucket_id = 'avatars');`,
    head: `create policy b on storage.objects for select using (true);`,
    expect: [{ kind: 'widening', severity: 'high', table: 'objects' }],
  },
  {
    name: 'policy added: owner-scoped (normal feature work → notice)',
    base: `${T()}`,
    head: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    expect: [{ kind: 'widening', severity: 'notice' }],
  },
  {
    name: 'policy added: unconditional TO anon',
    base: `${T()}`,
    head: `${T()} create policy p on public.docs for select to anon using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'policy added: trusted delegated check (allowlist) → widening notice, not review',
    base: `${T()}`,
    head: `${T()} create policy p on public.docs for select to authenticated using (public.is_member(user_id));`,
    options: { trustedFunctions: ['public.is_member'] },
    expect: [{ kind: 'widening', severity: 'notice' }],
  },
  {
    name: 'row-state read → unconditional read (state ⊂ all)',
    base: `${T()} create policy p on public.docs for select to authenticated using (status = 'published');`,
    head: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'authenticated-only → unconditional with NO role list (anon side widens)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() is not null);`,
    head: `${T()} create policy p on public.docs for select using (true);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },
  {
    name: 'policy dropped and recreated wider in the same migration (final state wins)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);
           drop policy p on public.docs;
           create policy p on public.docs for select using (auth.uid() is not null);`,
    expect: [{ kind: 'widening', severity: 'high' }],
  },

  // ── NARROWING: subset-or-equal claims only ──────────────────────────────────────────────────
  {
    name: 'authenticated-only → owner-bound (the fix direction)',
    base: `${T()} create policy p on public.docs for select using (auth.uid() is not null);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'permissive policy removed',
    base: `${T()} create policy p on public.docs for select using (auth.uid() is not null);`,
    head: `${T()}`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'RLS enabled on a previously unprotected table',
    base: `create table public.stats (id uuid);`,
    head: `create table public.stats (id uuid);
           alter table public.stats enable row level security;`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'unconditional → row-state (all → state)',
    base: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    head: `${T()} create policy p on public.docs for select to authenticated using (status = 'published');`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'unconditional → delegated check (all → delegated is subset-or-equal)',
    base: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    head: `${T()} create policy p on public.docs for select to authenticated
             using (id in (select doc_id from public.members where user_id = auth.uid()));`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'grant revoked (REVOKE ALL — final-state grant removal)',
    base: `create table public.stats (id uuid);
           grant select on public.stats to anon;`,
    head: `create table public.stats (id uuid);
           grant select on public.stats to anon;
           revoke all on public.stats from anon;`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'roles narrowed: TO public → TO authenticated (anon loses)',
    base: `${T()} create policy p on public.docs for select using (true);`,
    head: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'table dropped',
    base: `create table public.old (id uuid); alter table public.old enable row level security;`,
    head: ``,
    expect: [{ kind: 'narrowing', table: 'old' }],
  },
  {
    name: 'RESTRICTIVE policy added',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);
           create policy lock on public.docs as restrictive for select using (status = 'active');`,
    expect: [{ kind: 'narrowing' }],
  },
  {
    name: 'command narrowed: FOR ALL → FOR SELECT (writes lost)',
    base: `${T()} create policy p on public.docs for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    expect: [{ kind: 'narrowing' }],
  },

  // ── REQUIRES-REVIEW: fail-safe on everything unverifiable or incomparable ───────────────────
  {
    name: 'owner-bound → untrusted custom function',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (public.has_access(id));`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'untrusted custom function → owner-bound (still review: before-side unverifiable)',
    base: `${T()} create policy p on public.docs for select using (public.has_access(id));`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'owner-bound → row-state (incomparable)',
    base: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select to authenticated using (status = 'published');`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'row-state → owner-bound (incomparable)',
    base: `${T()} create policy p on public.docs for select to authenticated using (status = 'published');`,
    head: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'membership subquery → owner-bound (delegated ↔ own incomparable)',
    base: `${T()} create policy p on public.docs for select to authenticated
             using (id in (select doc_id from public.members where user_id = auth.uid()));`,
    head: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'owner column changed (same class, different predicate)',
    base: `${T('id uuid, user_id uuid, org_id uuid')} create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    head: `${T('id uuid, user_id uuid, org_id uuid')} create policy p on public.docs for select to authenticated using (auth.uid() = org_id);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'trusted function swapped for another trusted function (same breadth, expr changed)',
    base: `${T()} create policy p on public.docs for select to authenticated using (public.is_member(user_id));`,
    head: `${T()} create policy p on public.docs for select to authenticated using (public.is_org_admin(user_id));`,
    options: { trustedFunctions: ['public.is_member', 'public.is_org_admin'] },
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'NO FORCE ROW LEVEL SECURITY (unparseable RLS statement → fail-closed review, high)',
    base: `${T()}`,
    head: `${T()} alter table public.docs no force row level security;`,
    expect: [{ kind: 'requires-review', severity: 'high' }],
  },
  {
    name: 'ALTER POLICY targeting a policy the model never saw',
    base: `${T()}`,
    head: `${T()} alter policy ghost on public.docs using (true);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'policy added on an unmodeled schema (auth.users)',
    base: ``,
    head: `create policy p on auth.users for select using (true);`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'partial REVOKE (privilege state not modeled → review, grant retained)',
    base: `create table public.stats (id uuid);
           grant select, update on public.stats to authenticated;`,
    head: `create table public.stats (id uuid);
           grant select, update on public.stats to authenticated;
           revoke update on public.stats from authenticated;`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'RESTRICTIVE policy predicate changed',
    base: `${T()} create policy lock on public.docs as restrictive for select using (status = 'active');`,
    head: `${T()} create policy lock on public.docs as restrictive for select using (status = 'archived');`,
    expect: [{ kind: 'requires-review' }],
  },
  {
    name: 'row-state predicate changed (state → state, expr changed)',
    base: `${T()} create policy p on public.docs for select to authenticated using (status = 'published');`,
    head: `${T()} create policy p on public.docs for select to authenticated using (status is not null);`,
    expect: [{ kind: 'requires-review' }],
  },

  // ── NEUTRAL / empty: no false alarms on non-changes ─────────────────────────────────────────
  {
    name: 'identical SQL → empty diff',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    expect: [],
  },
  {
    name: 'formatting-only predicate change → empty diff',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using ( auth.uid()   =  user_id );`,
    expect: [],
  },
  {
    name: 'authenticated-only → unconditional on a TO-authenticated policy (semantically identical) → empty',
    base: `${T()} create policy p on public.docs for select to authenticated using (auth.uid() is not null);`,
    head: `${T()} create policy p on public.docs for select to authenticated using (true);`,
    expect: [],
  },
  {
    name: 'policy renamed (identity preserved via ALTER … RENAME) → empty diff',
    base: `${T()} create policy old_name on public.docs for select to authenticated using (auth.uid() = user_id);`,
    head: `${T()} create policy old_name on public.docs for select to authenticated using (auth.uid() = user_id);
           alter policy old_name on public.docs rename to new_name;`,
    // A rename changes identity keys between refs; the engine sees remove+add of the SAME shape.
    // Both sides are owner-bound with the same predicate — remove(own→none) + add(none→own) is
    // reported (rename detection across keys is future work), but must NEVER be review/high.
    expect: [{ kind: 'narrowing' }, { kind: 'widening', severity: 'notice' }],
  },
  {
    name: 'unrelated non-access DDL (indexes, columns) → empty diff',
    base: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`,
    head: `${T()} create policy p on public.docs for select using (auth.uid() = user_id);
           create index docs_status_idx on public.docs (status);
           alter table public.docs add column note text;`,
    expect: [],
  },
];

describe('policy-diff golden suite (launch gate: exact verdicts on every pair)', () => {
  it.each(CASES.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const deltas = diffAccess(model(c.base), model(c.head), c.options);
    const got = deltas
      .map((d) => ({ kind: d.kind, severity: d.severity, table: d.table }))
      .sort((a, b) => a.kind.localeCompare(b.kind) || a.table.localeCompare(b.table));
    const want = [...c.expect].sort(
      (a, b) => a.kind.localeCompare(b.kind) || (a.table ?? '').localeCompare(b.table ?? ''),
    );
    expect(
      got.length,
      JSON.stringify(
        deltas.map((d) => d.summary),
        null,
        2,
      ),
    ).toBe(want.length);
    want.forEach((w, i) => {
      const g = got[i] as (typeof got)[number];
      expect(g.kind).toBe(w.kind);
      if (w.severity) {
        expect(g.severity).toBe(w.severity);
      }
      if (w.table) {
        expect(g.table).toBe(w.table);
      }
    });
  });

  it('never claims a false "safe" verdict: a widening pair is NEVER neutral/narrowing-only', () => {
    const wideningCases = CASES.filter((c) => c.expect.some((e) => e.kind === 'widening'));
    expect(wideningCases.length).toBeGreaterThanOrEqual(15);
    for (const c of wideningCases) {
      const deltas = diffAccess(model(c.base), model(c.head), c.options);
      expect(
        deltas.some((d) => d.kind === 'widening' || d.kind === 'requires-review'),
        c.name,
      ).toBe(true);
    }
  });

  it('fingerprints are stable across file paths and line positions', () => {
    const base = `${T()} create policy p on public.docs for select using (auth.uid() = user_id);`;
    const head = `${T()} create policy p on public.docs for select using (auth.uid() is not null);`;
    const a = diffAccess(model(base), model(head));
    const shifted = buildRlsModel([
      { path: '/supabase/migrations/9999_other_name.sql', text: `\n\n\n-- shifted\n${head}` },
    ]);
    const b = diffAccess(model(base), shifted);
    expect(a.map((d) => d.fingerprint)).toEqual(b.map((d) => d.fingerprint));
  });
});
