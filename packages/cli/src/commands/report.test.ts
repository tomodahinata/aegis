import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { UsageError } from '../errors';
import { EXIT } from '../exit';
import { parseFramework, parseReportFormat, type ReportArgs, runReport } from './report';

// A migration with the flagship "authenticates but doesn't authorize" gap — maps to A01,
// i.e. SOC 2 CC6.1 / ISO 27001 A.8.3, giving the report a real gap to render.
const RLS_GAP_SQL = `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "read" on public.notes
  for select to authenticated
  using (auth.role() = 'authenticated');
`;

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tmpProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'aegis-report-'));
  created.push(root);
  for (const [name, content] of Object.entries(files)) {
    const path = join(root, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}

function baseArgs(cwd: string): ReportArgs {
  return { cwd, framework: 'soc2', format: 'md' };
}

function run(args: ReportArgs): { code: number; out: string } {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += String(chunk);
      return true;
    });
  try {
    const code = runReport(args);
    return { code, out };
  } finally {
    spy.mockRestore();
  }
}

describe('runReport', () => {
  it('renders SOC 2 markdown with the RLS gap mapped to CC6.1, and exits clean', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const { code, out } = run(baseArgs(root));
    expect(code).toBe(EXIT.CLEAN); // a report is evidence, never a gate
    expect(out).toContain('SOC 2');
    expect(out).toContain('not a certification');
    expect(out).toContain('CC6.1');
    expect(out).toContain('Gap(s) found');
    expect(out).toContain('rls/policy-not-owner-scoped');
    expect(out).not.toMatch(/\bcompliant\b/i);
  });

  it('emits machine-readable JSON with a gap control when --format json', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const { out } = run({ ...baseArgs(root), format: 'json' });
    const report = JSON.parse(out);
    expect(report.framework).toBe('soc2');
    expect(report.controls.some((c: { status: string }) => c.status === 'gap')).toBe(true);
  });

  it('maps to ISO 27001 Annex A controls when framework=iso27001', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const { out } = run({ ...baseArgs(root), framework: 'iso27001' });
    expect(out).toContain('ISO/IEC 27001');
    expect(out).toContain('A.8.3');
  });

  it('reports no gaps on a clean project', () => {
    const root = tmpProject({
      'page.tsx': 'export default function Page() {\n  return null;\n}\n',
    });
    const { code, out } = run(baseArgs(root));
    expect(code).toBe(EXIT.CLEAN);
    expect(out).toContain('No gaps detected');
    expect(out).not.toContain('Gaps — findings to remediate');
  });

  it('writes the report to a file with --out and confirms on stdout', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const outPath = join(root, 'evidence.md');
    const { code, out } = run({ ...baseArgs(root), out: outPath });
    expect(code).toBe(EXIT.CLEAN);
    expect(existsSync(outPath)).toBe(true);
    expect(readFileSync(outPath, 'utf8')).toContain('CC6.1');
    expect(out).toMatch(/wrote soc2 evidence to/);
  });

  it('renders a self-contained HTML evidence document with --format html', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const { code, out } = run({ ...baseArgs(root), format: 'html' });
    expect(code).toBe(EXIT.CLEAN);
    expect(out.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(out).toContain('<html lang="en">');
    expect(out).toContain('CC6.1');
    expect(out).not.toMatch(/\bcompliant\b/i);
  });

  it('appends to the history ledger with --record and shows remediation once history exists', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const ledger = join(root, '.aegis/history.jsonl');

    // First recorded scan: the gap is open, but one scan is a point, not a trend — the remediation-over-
    // time section needs ≥2 scans, so it must NOT render yet, even though the ledger now holds one record.
    const first = run({
      ...baseArgs(root),
      format: 'html',
      record: true,
      now: '2026-07-01T00:00:00Z',
    });
    expect(existsSync(ledger)).toBe(true);
    expect(readFileSync(ledger, 'utf8').trim().split('\n')).toHaveLength(1);
    expect(first.out).not.toContain('Remediation tracking');

    // Second recorded scan a week later: history now spans two scans, so remediation tracking renders.
    const second = run({
      ...baseArgs(root),
      format: 'html',
      record: true,
      now: '2026-07-08T00:00:00Z',
    });
    expect(readFileSync(ledger, 'utf8').trim().split('\n')).toHaveLength(2);
    expect(second.out).toContain('Remediation tracking');
    expect(second.out).toContain('open');
  });

  it('honours a custom --history path', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const ledger = join(root, 'audit/ledger.jsonl');
    run({ ...baseArgs(root), record: true, history: ledger, now: '2026-07-01T00:00:00Z' });
    expect(existsSync(ledger)).toBe(true);
  });

  it('stamps the recorded scan with --commit for CI provenance', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    const ledger = join(root, '.aegis/history.jsonl');
    run({ ...baseArgs(root), record: true, commit: 'abc123', now: '2026-07-01T00:00:00Z' });
    const line = readFileSync(ledger, 'utf8').trim().split('\n')[0] as string;
    expect(JSON.parse(line).commit).toBe('abc123');
  });

  it('still renders the report when the history ledger cannot be written (advisory degrades)', () => {
    const root = tmpProject({ 'supabase/migrations/0001_init.sql': RLS_GAP_SQL });
    // A file where a directory is expected makes mkdirSync/appendFileSync throw for the ledger.
    const wall = join(root, 'not-a-dir');
    writeFileSync(wall, 'x');
    const { code, out } = run({
      ...baseArgs(root),
      format: 'html',
      record: true,
      history: join(wall, 'ledger.jsonl'),
      now: '2026-07-01T00:00:00Z',
    });
    expect(code).toBe(EXIT.CLEAN); // the report (primary deliverable) is still produced
    expect(out).toContain('CC6.1');
  });
});

describe('report arg parsing', () => {
  it('accepts the supported frameworks', () => {
    expect(parseFramework('soc2')).toBe('soc2');
    expect(parseFramework('iso27001')).toBe('iso27001');
  });

  it('rejects a missing or unknown framework with a UsageError', () => {
    expect(() => parseFramework(undefined)).toThrow(UsageError);
    expect(() => parseFramework('pci-dss')).toThrow(UsageError);
  });

  it('defaults the report format to md and accepts json/html', () => {
    expect(parseReportFormat(undefined)).toBe('md');
    expect(parseReportFormat('md')).toBe('md');
    expect(parseReportFormat('json')).toBe('json');
    expect(parseReportFormat('html')).toBe('html');
  });

  it('rejects an unsupported report format with a UsageError', () => {
    expect(() => parseReportFormat('sarif')).toThrow(UsageError);
  });
});
