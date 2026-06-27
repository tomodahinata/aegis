import { describe, expect, it } from 'vitest';
import { correlateRls } from './correlate-rls';

function run(sql: string, ts: string): string[] {
  const files: Record<string, string> = { '/m/1.sql': sql, '/app/data.ts': ts };
  return correlateRls({
    sqlFiles: ['/m/1.sql'],
    tsFiles: ['/app/data.ts'],
    readFile: (p) => files[p] ?? '',
  }).map((f) => f.ruleId);
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
});
