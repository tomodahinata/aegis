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
