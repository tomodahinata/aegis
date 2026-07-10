import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { scanSql } from '../../scan-sql';
import { buildRlsModel, type RlsModel } from './model';

const model = (sql: string): RlsModel => buildRlsModel([{ path: '/m/0001.sql', text: sql }]);

describe('buildRlsModel — RLS enable/disable final-state semantics', () => {
  it('DISABLE ROW LEVEL SECURITY turns rlsEnabled off (the fail-open a diff must see)', () => {
    const m = model(`
      create table public.orders (id uuid, user_id uuid);
      alter table public.orders enable row level security;
      alter table public.orders disable row level security;
    `);
    expect(m.tables.get('orders')?.rlsEnabled).toBe(false);
  });

  it('a later ENABLE supersedes an earlier DISABLE (migration order wins)', () => {
    const m = model(`
      create table public.orders (id uuid);
      alter table public.orders disable row level security;
      alter table public.orders enable row level security;
    `);
    expect(m.tables.get('orders')?.rlsEnabled).toBe(true);
  });

  it('NO FORCE is not a disable — it is recorded uninterpreted, never flipped to rlsEnabled=false', () => {
    const m = model(`
      create table public.orders (id uuid);
      alter table public.orders enable row level security;
      alter table public.orders no force row level security;
    `);
    expect(m.tables.get('orders')?.rlsEnabled).toBe(true);
    expect(m.uninterpreted).toEqual([expect.objectContaining({ kind: 'rls-statement' })]);
  });

  it('DROP TABLE on another schema does not delete the public table of the same name', () => {
    const m = model(`
      create table public.objects (id uuid);
      drop table storage.objects;
    `);
    expect(m.tables.has('objects')).toBe(true);
  });
});

// `ALTER TABLE IF EXISTS …` is a common defensive migration idiom. It must be parsed identically to the
// bare form for every ALTER TABLE handler — historically only the CREATE/DROP paths honored the existence
// clause, so `IF EXISTS` on ENABLE produced a CI-breaking false `table-without-rls`, on DISABLE was missed
// (fail OPEN), and on ADD COLUMN dropped the ownership column (silencing the owner-scope rule).
describe('buildRlsModel — ALTER TABLE IF EXISTS modifier (regression)', () => {
  it('ENABLE via ALTER TABLE IF EXISTS turns rlsEnabled ON (was a false table-without-rls)', () => {
    const m = model(`
      create table public.docs (id uuid, user_id uuid);
      alter table if exists public.docs enable row level security;
    `);
    expect(m.tables.get('docs')?.rlsEnabled).toBe(true);
  });

  it('DISABLE via ALTER TABLE IF EXISTS turns rlsEnabled OFF (was fail-open — a missed disable)', () => {
    const m = model(`
      create table public.docs (id uuid, user_id uuid);
      alter table public.docs enable row level security;
      alter table if exists public.docs disable row level security;
    `);
    expect(m.tables.get('docs')?.rlsEnabled).toBe(false);
  });

  it('honors IF EXISTS and ONLY together, in PostgreSQL order (ALTER TABLE IF EXISTS ONLY t …)', () => {
    const m = model(`
      create table public.docs (id uuid);
      alter table if exists only public.docs enable row level security;
    `);
    expect(m.tables.get('docs')?.rlsEnabled).toBe(true);
  });

  it('ADD COLUMN via ALTER TABLE IF EXISTS records the ownership column (was a fail-open miss)', () => {
    const m = model(`
      create table public.docs (id uuid);
      alter table if exists public.docs add column user_id uuid;
    `);
    expect(m.tables.get('docs')?.hasOwnershipColumn).toBe(true);
    expect(m.tables.get('docs')?.ownershipColumn).toBe('user_id');
  });

  it('NO FORCE with IF EXISTS is still not a disable — recorded uninterpreted, RLS stays on', () => {
    const m = model(`
      create table public.docs (id uuid);
      alter table if exists public.docs enable row level security;
      alter table if exists public.docs no force row level security;
    `);
    expect(m.tables.get('docs')?.rlsEnabled).toBe(true);
    expect(m.uninterpreted).toEqual([expect.objectContaining({ kind: 'rls-statement' })]);
  });
});

// Procedural / dynamic `ENABLE ROW LEVEL SECURITY` (a DO block, a function body, or a dynamic EXECUTE loop
// over pg_tables) is invisible to per-table tracking. The model flags it so `rls/table-without-rls` can fail
// secure instead of flagging tables whose RLS was enabled through a construct it cannot statically attribute.
describe('buildRlsModel — procedural RLS enablement detection', () => {
  it('flags a DO-block loop that dynamically enables RLS on all public tables', () => {
    const m = model(`
      create table public.t1 (id uuid);
      create table public.t2 (id uuid);
      do $$ declare r record; begin
        for r in select tablename from pg_tables where schemaname = 'public' loop
          execute format('alter table %I enable row level security', r.tablename);
        end loop; end $$;
    `);
    expect(m.proceduralRlsEnable).toBe(true);
  });

  it('flags a dynamic EXECUTE string that enables RLS', () => {
    const m = model(`
      create table public.t (id uuid);
      do $$ begin execute 'alter table public.t enable row level security'; end $$;
    `);
    expect(m.proceduralRlsEnable).toBe(true);
  });

  it('does NOT flag a schema that only enables RLS via static top-level ALTER statements', () => {
    const m = model(`
      create table public.t (id uuid);
      alter table public.t enable row level security;
    `);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('does NOT flag an IN-statement comment mentioning the enable (exercises the comment strip — an inter-statement comment never even reaches the model)', () => {
    const m = model(`
      do $$ begin -- enable row level security for all tables (someday)
        perform pg_notify('migrations', 'done');
      end $$;
      create table public.t (id uuid);
    `);
    expect(m.proceduralRlsEnable).toBe(false);
    expect(m.tables.get('t')?.rlsEnabled).toBe(false);
  });

  it('does NOT flag a string literal that merely MENTIONS enabling RLS (COMMENT ON / seed data — was fail-open: one such literal silenced table-without-rls scan-wide)', () => {
    const m = model(`
      create table public.t (id uuid);
      comment on table public.t is 'TODO: enable row level security before launch';
      insert into public.notes (body) values ('remember to enable row level security');
    `);
    expect(m.proceduralRlsEnable).toBe(false);
    expect(m.tables.get('t')?.rlsEnabled).toBe(false);
  });

  it('does NOT flag a column default containing the phrase (the CREATE TABLE statement itself must not poison the flag)', () => {
    const m = model(`
      create table public.audit (id uuid, note text default 'enable row level security later');
    `);
    expect(m.proceduralRlsEnable).toBe(false);
    expect(m.tables.get('audit')?.rlsEnabled).toBe(false);
  });

  it('does NOT flag a plain seed literal carrying the full phrase — no procedural context, no suppression', () => {
    const m = model(`
      create table public.snippets (id uuid);
      insert into public.snippets (body) values ('alter table public.x enable row level security');
    `);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('does NOT flag an unrelated ALTER TABLE whose literal mentions the phrase (real ALTER code + innocent default)', () => {
    const m = model(`
      create table public.audit (id uuid, note text);
      alter table public.audit alter column note set default 'remember to enable row level security';
    `);
    expect(m.proceduralRlsEnable).toBe(false);
    expect(m.tables.get('audit')?.rlsEnabled).toBe(false);
  });

  it('does NOT flag the phrase split across two literals in one DML statement', () => {
    const m = model(`
      create table public.audit_log (id uuid);
      insert into public.audit_log (action, detail) values ('ran alter table cmd', 'enable row level security');
    `);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('flags a bare plpgsql FUNCTION body enable (no EXECUTE keyword — caught by the create-function context)', () => {
    const m = model(`
      create table public.t (id uuid);
      create or replace function public.harden() returns void language plpgsql as $$
        begin alter table public.t enable row level security; end $$;
    `);
    expect(m.proceduralRlsEnable).toBe(true);
  });

  it('flags the psql \\gexec idiom (SELECT format(…) — no do/create prefix, caught by the format( context)', () => {
    const m = model(`
      create table public.t (id uuid);
      select format('alter table %I enable row level security', tablename) from pg_tables where schemaname = 'public' \\gexec
    `);
    expect(m.proceduralRlsEnable).toBe(true);
  });

  it('a block-comment-interleaved ENABLE is attributed to its table, never misfiled as procedural', () => {
    const m = model(`
      create table public.a (id uuid);
      create table public.b (id uuid);
      alter table public.a /* migration step 1 */ enable row level security;
    `);
    expect(m.tables.get('a')?.rlsEnabled).toBe(true);
    expect(m.tables.get('b')?.rlsEnabled).toBe(false);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('a comment whose body is itself comment-like (/* -- */) does not corrupt the strip (approximation edge)', () => {
    const m = model(`
      create table public.a (id uuid);
      alter table public.a /* -- */ enable row level security;
    `);
    expect(m.tables.get('a')?.rlsEnabled).toBe(true);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('a comment-interleaved ADD COLUMN still records the ownership column (same fallback as ENABLE/DISABLE)', () => {
    const m = model(`
      create table public.docs (id uuid);
      alter table public.docs /* fk to auth.users */ add column user_id uuid;
    `);
    expect(m.tables.get('docs')?.hasOwnershipColumn).toBe(true);
    expect(m.tables.get('docs')?.ownershipColumn).toBe('user_id');
  });

  it('a comment/string SPLICE cannot fabricate a static ENABLE (string-aware strip — stays fail-closed)', () => {
    // Adversarial shape: `-- x /*` opens nothing (it is a line comment) and `'*/ … enable row level
    // security'` is a literal. A string-naive strip would splice them and expose the literal tail as
    // code, fabricating rlsEnabled=true for a statement that never touches RLS.
    const m = model(`
      create table public.users (id uuid);
      alter table public.users -- x /*
        alter column note set default '*/
        enable row level security';
    `);
    expect(m.tables.get('users')?.rlsEnabled).toBe(false);
    expect(m.proceduralRlsEnable).toBe(false);
    expect(m.uninterpreted).toEqual([expect.objectContaining({ kind: 'rls-statement' })]);
  });

  it('a procedural enable inside CREATE FUNCTION leaves the fail-closed rls-statement breadcrumb (the one container consumed before the nets)', () => {
    const m = model(`
      create table public.t (id uuid);
      create or replace function public.harden() returns void language plpgsql as $$
        begin alter table public.t enable row level security; end $$;
    `);
    expect(m.proceduralRlsEnable).toBe(true);
    expect(m.uninterpreted).toEqual([expect.objectContaining({ kind: 'rls-statement' })]);
  });

  it('a static ENABLE interleaved with an inline comment is attributed to its table, never misfiled as procedural', () => {
    const m = model(`
      create table public.a (id uuid);
      create table public.b (id uuid);
      alter table public.a
        -- see security docs for why
        enable row level security;
    `);
    expect(m.tables.get('a')?.rlsEnabled).toBe(true);
    expect(m.tables.get('b')?.rlsEnabled).toBe(false);
    expect(m.proceduralRlsEnable).toBe(false);
  });

  it('a comment-interleaved DISABLE is likewise attributed (was fail-open: the model kept claiming RLS on)', () => {
    const m = model(`
      create table public.a (id uuid);
      alter table public.a enable row level security;
      alter table public.a /* audit trail */ disable row level security;
    `);
    expect(m.tables.get('a')?.rlsEnabled).toBe(false);
  });
});

describe('buildRlsModel — REVOKE final-state semantics (fail-secure)', () => {
  it('REVOKE ALL removes the granted role; a fully-revoked grant is dropped from the model', () => {
    const m = model(`
      create table public.stats (id uuid);
      grant select, update on public.stats to anon;
      revoke all privileges on public.stats from anon;
    `);
    expect(m.grants).toEqual([]);
    expect(m.uninterpreted).toEqual([]);
  });

  it('REVOKE ALL removes only the named role, keeping the others granted', () => {
    const m = model(`
      create table public.stats (id uuid);
      grant select on public.stats to anon, authenticated;
      revoke all on table public.stats from anon;
    `);
    expect(m.grants).toEqual([expect.objectContaining({ roles: ['authenticated'] })]);
  });

  it('a PARTIAL revoke keeps the grant (privilege state is not modeled) and records uninterpreted', () => {
    const m = model(`
      create table public.stats (id uuid);
      grant select, update on public.stats to anon;
      revoke update on public.stats from anon;
    `);
    expect(m.grants).toEqual([expect.objectContaining({ table: 'stats', roles: ['anon'] })]);
    expect(m.uninterpreted).toEqual([
      expect.objectContaining({ kind: 'revoke-partial', table: 'stats' }),
    ]);
  });

  it('a schema-wide REVOKE ALL strips the role from per-table AND schema-wide grants', () => {
    const m = model(`
      create table public.stats (id uuid);
      grant select on public.stats to anon;
      grant select on all tables in schema public to anon;
      revoke all on all tables in schema public from anon;
    `);
    expect(m.grants).toEqual([]);
  });

  it('a single-table REVOKE ALL never touches a schema-wide grant (fail-secure over-approximation)', () => {
    const m = model(`
      create table public.stats (id uuid);
      grant select on all tables in schema public to anon;
      revoke all on public.stats from anon;
    `);
    expect(m.grants).toEqual([expect.objectContaining({ table: '*', roles: ['anon'] })]);
  });

  it('REVOKE on functions/sequences is out of scope and records nothing', () => {
    const m = model(`
      create table public.stats (id uuid);
      revoke all on all functions in schema public from anon;
    `);
    expect(m.grants).toEqual([]);
    expect(m.uninterpreted).toEqual([]);
  });
});

describe('buildRlsModel — fail-secure on pathological predicates (REL-01 length guard)', () => {
  it('an over-long predicate suppresses to "unknown", never a safe class', () => {
    // > MAX_CLASSIFY_LEN (8192): the length guard must fail CLOSED. "unknown" is row-state — a diff
    // treats it as potentially anon-satisfiable and surfaces it, rather than owner-bound/deny/
    // authenticated-only, which would silently hide a real access change.
    const huge = `auth.uid() = user_id or ${'x'.repeat(9000)} = '1'`;
    const m = model(`
      create table public.docs (id uuid, user_id uuid);
      alter table public.docs enable row level security;
      create policy p on public.docs for select to authenticated using (${huge});
    `);
    expect(m.policies.find((p) => p.name === 'p')?.usingClass).toBe('unknown');
  });
});

describe('buildRlsModel — ALTER POLICY RENAME identity', () => {
  it('re-keys the policy so a later DROP by the NEW name removes it (no stale duplicate)', () => {
    const m = model(`
      create table public.docs (id uuid, user_id uuid);
      alter table public.docs enable row level security;
      create policy "old name" on public.docs for select using (auth.uid() = user_id);
      alter policy "old name" on public.docs rename to "new name";
      drop policy "new name" on public.docs;
    `);
    expect(m.policies).toEqual([]);
  });

  it('preserves roles across a rename (regression: RENAME TO used to be misread as a TO roles list)', () => {
    const m = model(`
      create table public.docs (id uuid, user_id uuid);
      create policy p on public.docs for select to authenticated using (auth.uid() = user_id);
      alter policy p on public.docs rename to q;
    `);
    expect(m.policies).toEqual([
      expect.objectContaining({ name: 'q', roles: ['authenticated'], usingClass: 'owner-bound' }),
    ]);
  });

  it('a rename of an unknown policy is recorded uninterpreted (fail closed for a differ)', () => {
    const m = model(`alter policy ghost on public.docs rename to ghost2;`);
    expect(m.uninterpreted).toEqual([
      expect.objectContaining({ kind: 'alter-policy-unknown-target', table: 'docs' }),
    ]);
  });

  it('an ALTER POLICY on an unknown policy is recorded uninterpreted', () => {
    const m = model(`alter policy ghost on public.docs using (true);`);
    expect(m.uninterpreted).toEqual([
      expect.objectContaining({ kind: 'alter-policy-unknown-target', table: 'docs' }),
    ]);
  });

  it('rename is equivalent to creating under the new name (identity invariant, property)', () => {
    const ident = fc
      .string({ minLength: 1, maxLength: 12, unit: fc.constantFrom(...'abcdefgh_') })
      .filter((s) => /^[a-z_]/.test(s));
    fc.assert(
      fc.property(ident, ident, (oldName, newName) => {
        fc.pre(oldName !== newName);
        const renamed = model(`
          create table public.t (id uuid, user_id uuid);
          create policy ${oldName} on public.t for select using (auth.uid() = user_id);
          alter policy ${oldName} on public.t rename to ${newName};
        `);
        const direct = model(`
          create table public.t (id uuid, user_id uuid);
          create policy ${newName} on public.t for select using (auth.uid() = user_id);
        `);
        expect(renamed.policies.map((p) => [p.name, p.table, p.usingClass, p.roles])).toEqual(
          direct.policies.map((p) => [p.name, p.table, p.usingClass, p.roles]),
        );
      }),
    );
  });
});

describe('buildRlsModel — storage-schema policies', () => {
  it('models storage.objects policies with schema identity, distinct from a public table named objects', () => {
    const m = model(`
      create table public.objects (id uuid, user_id uuid);
      alter table public.objects enable row level security;
      create policy app on public.objects for select using (auth.uid() = user_id);
      create policy "avatars are public" on storage.objects for select using (bucket_id = 'avatars');
    `);
    expect(m.policies).toHaveLength(2);
    const storagePolicy = m.policies.find((p) => p.schema === 'storage');
    expect(storagePolicy).toMatchObject({ table: 'objects', name: 'avatars are public' });
    // The storage policy must not inherit the PUBLIC objects table's ownership column.
    expect(storagePolicy?.tableHasOwnershipColumn).toBe(false);
    expect(m.policies.find((p) => p.schema === 'public')?.tableHasOwnershipColumn).toBe(true);
  });

  it('DROP POLICY on storage removes the storage policy, not a same-named public one', () => {
    const m = model(`
      create table public.objects (id uuid);
      create policy p on public.objects for select using (true);
      create policy p on storage.objects for select using (true);
      drop policy p on storage.objects;
    `);
    expect(m.policies).toEqual([expect.objectContaining({ schema: 'public', table: 'objects' })]);
  });

  it('a policy on any OTHER schema is recorded uninterpreted, never silently dropped', () => {
    const m = model(`create policy p on auth.users for select using (true);`);
    expect(m.policies).toEqual([]);
    expect(m.uninterpreted).toEqual([
      expect.objectContaining({ kind: 'policy-on-unmodeled-schema', table: 'users' }),
    ]);
  });
});

describe('scanSql — behavior freeze: storage policies produce ZERO rule findings', () => {
  it('idiomatic storage policies (public-upload WITH CHECK (true), anon-readable bucket) stay silent', () => {
    const sql = `
      create policy "anyone can upload" on storage.objects for insert with check (true);
      create policy "anyone can update own folder" on storage.objects for update
        using (bucket_id = 'avatars');
      create policy "authenticated read" on storage.objects for select
        using (auth.role() = 'authenticated');
    `;
    expect(scanSql({ files: ['/m/0001.sql'], readFile: () => sql }).findings).toEqual([]);
  });
});
