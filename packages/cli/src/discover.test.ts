import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { discoverFiles, discoverSqlFiles } from './discover';

const SRC = dirname(fileURLToPath(import.meta.url));

describe('discoverFiles', () => {
  it('finds source files and excludes test files', () => {
    const files = discoverFiles(SRC);
    expect(files.some((file) => file.endsWith('main.ts'))).toBe(true);
    expect(files.every((file) => !/\.test\.ts$/.test(file))).toBe(true);
  });

  it('excludes machine-generated/vendored output (`generated/`)', () => {
    const root = mkdtempSync(join(tmpdir(), 'aegis-discover-gen-'));
    try {
      mkdirSync(join(root, 'src'), { recursive: true });
      writeFileSync(join(root, 'src', 'app.ts'), 'export const x = 1;\n');
      mkdirSync(join(root, 'generated', 'client'), { recursive: true });
      writeFileSync(join(root, 'generated', 'client', 'runtime.js'), 'export const y = 2;\n');

      const files = discoverFiles(root);
      expect(files.some((f) => f.endsWith('app.ts'))).toBe(true);
      expect(files.some((f) => f.endsWith('runtime.js'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('discoverSqlFiles — scoped to Supabase schema (the RLS threat model)', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aegis-discover-sql-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  const write = (rel: string, body = 'create table public.t (id uuid);\n'): void => {
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  };

  it('discovers Supabase migrations and declarative schemas', () => {
    write('supabase/migrations/001_init.sql');
    write('supabase/schemas/public.sql');
    const found = discoverSqlFiles(root);
    expect(found.some((f) => f.endsWith('001_init.sql'))).toBe(true);
    expect(found.some((f) => f.endsWith('public.sql'))).toBe(true);
  });

  it('ignores non-Supabase ORM migrations (Prisma/Drizzle) — no PostgREST boundary, so RLS is N/A', () => {
    write('prisma/migrations/20260115_init/migration.sql');
    write('drizzle/0000_init.sql');
    expect(discoverSqlFiles(root)).toEqual([]);
  });

  it('still excludes non-authority SQL even under supabase/ (tests, seeds)', () => {
    write('supabase/migrations/001_real.sql');
    write('supabase/migrations/policies.test.sql');
    write('supabase/seed.sql');
    const found = discoverSqlFiles(root);
    expect(found.some((f) => f.endsWith('001_real.sql'))).toBe(true);
    expect(found.some((f) => f.includes('.test.sql'))).toBe(false);
    expect(found.some((f) => f.endsWith('seed.sql'))).toBe(false);
  });
});
