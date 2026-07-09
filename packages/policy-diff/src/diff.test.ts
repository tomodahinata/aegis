import { buildRlsModel } from '@aegiskit/scanner';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { diffAccess, summarizeDeltas } from './diff';

const model = (sql: string) =>
  buildRlsModel([{ path: '/supabase/migrations/0001.sql', text: sql }]);

// ── Generators: small random-but-realistic RLS schemas from a template alphabet ──────────────────

const PREDICATES = [
  'auth.uid() = user_id', // owner-bound
  'auth.uid() is not null', // authenticated-only
  'true', // unconditional
  'false', // deny
  "status = 'published'", // unknown (row-state)
  'public.is_member(user_id)', // function-delegated
  "auth.role() = 'service_role'", // role-delegated
] as const;
const COMMANDS = ['all', 'select', 'update'] as const;
const ROLE_LISTS = ['', ' to authenticated', ' to anon'] as const;

const policyArb = fc.record({
  table: fc.constantFrom('docs', 'posts'),
  name: fc.constantFrom('p1', 'p2', 'p3'),
  command: fc.constantFrom(...COMMANDS),
  roles: fc.constantFrom(...ROLE_LISTS),
  predicate: fc.constantFrom(...PREDICATES),
});

type PolicySpec = typeof policyArb extends fc.Arbitrary<infer T> ? T : never;

/** Policy names are unique per table (PostgreSQL invariant) — keep the FIRST of each identity. */
function dedupe(policies: readonly PolicySpec[]): PolicySpec[] {
  const seen = new Set<string>();
  return policies.filter((p) => {
    const key = `${p.table}/${p.name}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Both tables always exist (with RLS) in every generated schema, so the properties test PURE policy
 * semantics: table add/remove is deliberately asymmetric in the engine (added WITH RLS = silence,
 * removed = narrowing) and would trivially break duality.
 */
function toSql(policies: readonly PolicySpec[]): string {
  const lines = ['docs', 'posts'].flatMap((t) => [
    `create table public.${t} (id uuid primary key, user_id uuid, status text);`,
    `alter table public.${t} enable row level security;`,
  ]);
  for (const p of dedupe(policies)) {
    lines.push(
      `create policy ${p.name} on public.${p.table} for ${p.command}${p.roles} using (${p.predicate});`,
    );
  }
  return lines.join('\n');
}

const schemaArb = fc.array(policyArb, { minLength: 0, maxLength: 5 }).map(toSql);

describe('diffAccess — invariants (fast-check)', () => {
  it('reflexivity: a model diffed against itself is always empty', () => {
    fc.assert(
      fc.property(schemaArb, (sql) => {
        expect(diffAccess(model(sql), model(sql))).toEqual([]);
      }),
    );
  });

  it('duality (transition level): every forward widening is a backward narrowing; review is symmetric', () => {
    // The invariant lives on TRANSITIONS, not aggregated delta verdicts: a command swap (e.g.
    // FOR UPDATE → FOR SELECT) is simultaneously a widening (select gained) and a narrowing
    // (update lost), and the per-policy verdict deliberately reports the WORST of the two.
    const transitionCounts = (baseSql: string, headSql: string) => {
      const all = diffAccess(model(baseSql), model(headSql)).flatMap((d) => d.transitions);
      return {
        widening: all.filter((t) => t.kind === 'widening').length,
        narrowing: all.filter((t) => t.kind === 'narrowing').length,
        review: all.filter((t) => t.kind === 'requires-review').length,
      };
    };
    fc.assert(
      fc.property(schemaArb, schemaArb, (baseSql, headSql) => {
        const fwd = transitionCounts(baseSql, headSql);
        const rev = transitionCounts(headSql, baseSql);
        expect(fwd.widening).toBe(rev.narrowing);
        expect(fwd.narrowing).toBe(rev.widening);
        expect(fwd.review).toBe(rev.review);
      }),
    );
  });

  it('fail-safe: an unparseable RLS statement new in head ALWAYS yields at least a review', () => {
    fc.assert(
      fc.property(schemaArb, (sql) => {
        const head = `${sql}\ncreate table public.z (id uuid);\nalter table public.z no force row level security;`;
        const deltas = diffAccess(model(sql), model(head));
        expect(deltas.some((d) => d.kind === 'requires-review')).toBe(true);
      }),
    );
  });

  it('monotone claim safety: removing ONE permissive policy never produces a widening', () => {
    fc.assert(
      fc.property(fc.array(policyArb, { minLength: 1, maxLength: 5 }), (raw) => {
        // Dedupe FIRST so the head really is "base minus one policy", not a shadowed redefinition.
        const policies = dedupe(raw);
        const baseSql = toSql(policies);
        const headSql = toSql(policies.slice(1));
        const deltas = diffAccess(model(baseSql), model(headSql));
        // Fewer OR-branches can only shrink permissive access: widening here would be a false alarm.
        expect(deltas.every((d) => d.kind !== 'widening')).toBe(true);
      }),
    );
  });
});

describe('diffAccess — behavioral details', () => {
  it('carries per-(role, command) transitions as evidence on policy deltas', () => {
    const base = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;
       create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
    );
    const head = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;
       create policy p on public.docs for select to authenticated using (auth.uid() is not null);`,
    );
    const [delta] = diffAccess(base, head);
    expect(delta?.transitions).toEqual([
      expect.objectContaining({
        role: 'authenticated',
        command: 'select',
        before: 'own',
        after: 'all',
        kind: 'widening',
        severity: 'high',
      }),
    ]);
    expect(delta?.summary).toContain('docs');
    expect(delta?.summary).toContain('ALL rows');
  });

  it('trustedFunctions: an untrusted helper is review; the SAME diff with trust is widening-notice', () => {
    const base = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;`,
    );
    const head = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;
       create policy p on public.docs for select to authenticated using (public.is_member(user_id));`,
    );
    expect(diffAccess(base, head).map((d) => d.kind)).toEqual(['requires-review']);
    expect(
      diffAccess(base, head, { trustedFunctions: ['public.is_member'] }).map((d) => [
        d.kind,
        d.severity,
      ]),
    ).toEqual([['widening', 'notice']]);
  });

  it('a mixed trusted+unknown call stays untrusted (fail secure)', () => {
    const base = model('create table public.docs (id uuid, user_id uuid);');
    const head = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;
       create policy p on public.docs for select using (public.is_member(user_id) and public.mystery(id));`,
    );
    const deltas = diffAccess(base, head, { trustedFunctions: ['public.is_member'] });
    expect(deltas.some((d) => d.kind === 'requires-review')).toBe(true);
  });

  it('summarizeDeltas conclusions: no-change / attention / action-required', () => {
    expect(summarizeDeltas([]).conclusion).toBe('no-change');
    const base = model(
      `create table public.docs (id uuid, user_id uuid);
       alter table public.docs enable row level security;`,
    );
    const notice = diffAccess(
      base,
      model(
        `create table public.docs (id uuid, user_id uuid);
         alter table public.docs enable row level security;
         create policy p on public.docs for select to authenticated using (auth.uid() = user_id);`,
      ),
    );
    expect(summarizeDeltas(notice).conclusion).toBe('attention');
    const high = diffAccess(
      base,
      model(
        `create table public.docs (id uuid, user_id uuid);
         alter table public.docs enable row level security;
         create policy p on public.docs for select using (true);`,
      ),
    );
    expect(summarizeDeltas(high).conclusion).toBe('action-required');
  });
});
