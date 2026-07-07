import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { explainFinding, scanAndSummarize } from './scan-service';

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

// The exact fake used by the committed scanner fixture — triggers secrets/committed-literal and is safe
// under GitHub push protection (fake sub-24-char body).
const COMMITTED_SECRET = "export const stripe = 'sk_live_FAKEnotReal9';\n";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tmpProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'aegis-mcp-'));
  created.push(root);
  for (const [name, content] of Object.entries(files)) {
    const path = join(root, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return root;
}

describe('scanAndSummarize', () => {
  it('returns a prioritized summary with a fingerprint per finding', () => {
    const root = tmpProject({ 'supabase/migrations/0001.sql': RLS_GAP_SQL });
    const summary = scanAndSummarize(root);
    expect(summary.total).toBeGreaterThan(0);
    const rls = summary.findings.find((f) => f.ruleId === 'rls/policy-not-owner-scoped');
    expect(rls).toBeDefined();
    expect(rls?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(summary.counts.HIGH).toBeGreaterThanOrEqual(1);
  });

  it('caps results at `limit` and flags truncation', () => {
    const root = tmpProject({
      'supabase/migrations/0001.sql': RLS_GAP_SQL,
      'app/secret.ts': COMMITTED_SECRET,
    });
    const summary = scanAndSummarize(root, 1);
    expect(summary.findings).toHaveLength(1);
    expect(summary.truncated).toBe(summary.total > 1);
  });

  it('reports zero findings on a clean project without claiming safety', () => {
    const root = tmpProject({ 'page.tsx': 'export default function P(){return null}\n' });
    const summary = scanAndSummarize(root);
    expect(summary.total).toBe(0);
    expect(summary.findings).toEqual([]);
  });
});

describe('explainFinding', () => {
  it('returns the F1 explanation and an owner-scoped suggested policy', () => {
    const root = tmpProject({ 'supabase/migrations/0001.sql': RLS_GAP_SQL });
    const fingerprint = scanAndSummarize(root).findings.find(
      (f) => f.ruleId === 'rls/policy-not-owner-scoped',
    )?.fingerprint;
    expect(fingerprint).toBeDefined();
    const detail = explainFinding(root, fingerprint as string);
    expect(detail?.explanation?.kind).toBe('authenticated-only');
    expect(detail?.explanation?.suggestedFix).toContain('auth.uid() = user_id');
  });

  it('redacts evidence for secret-bearing findings (never leaks a matched key to the agent)', () => {
    const root = tmpProject({ 'app/secret.ts': COMMITTED_SECRET });
    const secret = scanAndSummarize(root).findings.find(
      (f) => f.ruleId === 'secrets/committed-literal',
    );
    expect(secret).toBeDefined();
    const detail = explainFinding(root, secret?.fingerprint as string);
    expect(detail?.evidence).toBe('[redacted]');
    expect(JSON.stringify(detail)).not.toContain('sk_live_FAKEnotReal9');
  });

  it('returns undefined for an unknown fingerprint', () => {
    const root = tmpProject({ 'supabase/migrations/0001.sql': RLS_GAP_SQL });
    expect(explainFinding(root, 'deadbeef')).toBeUndefined();
  });

  it('passes non-secret evidence through unredacted (redaction is targeted, not blanket)', () => {
    const root = tmpProject({ 'supabase/migrations/0001.sql': RLS_GAP_SQL });
    const rls = scanAndSummarize(root).findings.find(
      (f) => f.ruleId === 'rls/policy-not-owner-scoped',
    );
    expect(rls).toBeDefined();
    const detail = explainFinding(root, rls?.fingerprint as string);
    expect(detail?.evidence).toBeDefined();
    expect(detail?.evidence).not.toBe('[redacted]');
  });
});
