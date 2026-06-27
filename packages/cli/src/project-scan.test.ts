import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanProject } from './project-scan';

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aegis-project-scan-'));
  // A route handler that queries a weak-RLS table via a non-admin client: yields a TS finding
  // (authz) AND a SQL↔code correlation finding (exposed-table-access).
  mkdirSync(join(root, 'app', 'api', 'orders'), { recursive: true });
  writeFileSync(
    join(root, 'app', 'api', 'orders', 'route.ts'),
    "import { supabase } from '@/lib/supabase';\nexport async function GET() {\n  return supabase.from('orders').select('*');\n}\n",
  );
  // A migration that ships a table without RLS: a SQL finding, and makes `orders` a weak table.
  mkdirSync(join(root, 'supabase', 'migrations'), { recursive: true });
  writeFileSync(
    join(root, 'supabase', 'migrations', '001_init.sql'),
    'create table public.orders (id uuid primary key, total int);\n',
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('scanProject — merges the TS, SQL, and RLS-correlation layers', () => {
  it('reports findings from all three layers in one result', () => {
    const ruleIds = new Set(scanProject(root).findings.map((f) => f.ruleId));
    expect(ruleIds).toContain('authz/missing-access-filter'); // TS layer
    expect(ruleIds).toContain('rls/table-without-rls'); // SQL layer
    expect(ruleIds).toContain('rls/exposed-table-access'); // SQL↔code correlation
  });

  it('orders the merged findings by file → line → column → ruleId', () => {
    const findings = scanProject(root).findings;
    const sorted = [...findings].sort(
      (a, b) =>
        a.file.localeCompare(b.file) ||
        a.range.startLine - b.range.startLine ||
        a.range.startColumn - b.range.startColumn ||
        a.ruleId.localeCompare(b.ruleId),
    );
    expect(findings).toEqual(sorted);
  });

  it('sums the per-layer counters across TS + SQL', () => {
    const result = scanProject(root);
    expect(result.scannedFiles).toBe(2); // 1 TS file + 1 SQL migration
    const summaryTotal = Object.values(result.summary).reduce((a, b) => a + b, 0);
    expect(summaryTotal).toBe(result.findings.length);
    expect(result.suppressedCount).toBe(0);
  });

  it('returns the TS result unchanged when the project has no SQL schema', () => {
    const tsOnly = mkdtempSync(join(tmpdir(), 'aegis-ts-only-'));
    try {
      mkdirSync(join(tsOnly, 'app', 'api', 'x'), { recursive: true });
      writeFileSync(
        join(tsOnly, 'app', 'api', 'x', 'route.ts'),
        "export async function GET() {\n  return supabase.from('orders').select('*');\n}\n",
      );
      const result = scanProject(tsOnly);
      expect(result.scannedFiles).toBe(1);
      expect(result.findings.every((f) => !f.ruleId.startsWith('rls/'))).toBe(true);
    } finally {
      rmSync(tsOnly, { recursive: true, force: true });
    }
  });
});
