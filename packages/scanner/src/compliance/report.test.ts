import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { toComplianceJson } from '../reporters/compliance-json';
import { toComplianceMd } from '../reporters/compliance-md';
import { ALL_RULES } from '../rules';
import { ALL_SQL_RULES } from '../sql-rules';
import { emptySummary, type Finding, type ScanResult } from '../types';
import type { ComplianceReport } from './report';
import { buildComplianceReport } from './report';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'authz/idor-tainted-scope',
    severity: 'HIGH',
    confidence: 'high',
    message: 'route param reaches a query without an ownership filter',
    file: '/repo/app/api/invoices/[id]/route.ts',
    range: { startLine: 12, startColumn: 3, endLine: 12, endColumn: 40 },
    docsUrl: 'https://example.test/rule',
    remediation: 'scope the query to the caller, e.g. .eq("user_id", user.id)',
    owasp: 'A01:2021 Broken Access Control',
    ...overrides,
  };
}

function result(findings: readonly Finding[], scannedFiles = 5): ScanResult {
  return {
    findings,
    passes: [],
    summary: emptySummary(),
    scannedFiles,
    durationMs: 0,
    suppressedCount: 0,
  };
}

const gapIds = (report: ComplianceReport): ReadonlySet<string> =>
  new Set(report.controls.filter((c) => c.status === 'gap').map((c) => c.controlId));

describe('buildComplianceReport', () => {
  it('marks the mapped control a gap and attaches the finding as evidence', () => {
    const report = buildComplianceReport(result([finding()]), 'soc2');
    const cc61 = report.controls.find((c) => c.controlId === 'CC6.1'); // A01 → CC6.1
    expect(cc61?.status).toBe('gap');
    expect(cc61?.findings).toHaveLength(1);

    const cc67 = report.controls.find((c) => c.controlId === 'CC6.7'); // A02 only — no finding
    expect(cc67?.status).toBe('covered');
    expect(cc67?.findings).toHaveLength(0);
  });

  it('marks every control covered on a clean scan', () => {
    const report = buildComplianceReport(result([]), 'iso27001');
    expect(report.controls.every((c) => c.status === 'covered')).toBe(true);
    expect(report.summary.gap).toBe(0);
    expect(report.summary.covered).toBe(report.controls.length);
  });

  it('marks controls not-assessed when nothing was scanned (fail-safe, no false "covered")', () => {
    const report = buildComplianceReport(result([], 0), 'soc2');
    expect(report.controls.every((c) => c.status === 'not-assessed')).toBe(true);
    expect(report.summary.covered).toBe(0);
  });

  it('records the scanned-file count and the rule count', () => {
    const report = buildComplianceReport(result([finding()], 7), 'soc2');
    expect(report.generatedFrom.scannedFiles).toBe(7);
    expect(report.generatedFrom.ruleCount).toBe(ALL_RULES.length + ALL_SQL_RULES.length);
  });

  it('is deterministic (byte-identical output for identical input)', () => {
    const r = result([
      finding(),
      finding({ owasp: 'A03:2021 Injection', ruleId: 'injection/sql', severity: 'BLOCKER' }),
    ]);
    expect(toComplianceJson(buildComplianceReport(r, 'soc2'))).toBe(
      toComplianceJson(buildComplianceReport(r, 'soc2')),
    );
  });

  it('gap controls only ever grow as findings are added (monotonicity)', () => {
    const owaspArb = fc.constantFrom(
      'A01:2021 x',
      'A02:2021 x',
      'A03:2021 x',
      'A04:2021 x',
      'A05:2021 x',
      'A06:2021 x',
      'A08:2021 x',
      'A10:2021 x',
    );
    fc.assert(
      fc.property(fc.array(owaspArb), fc.array(owaspArb), (base, extra) => {
        const baseFindings = base.map((owasp) => finding({ owasp }));
        const superset = [...baseFindings, ...extra.map((owasp) => finding({ owasp }))];
        const gapsBase = gapIds(buildComplianceReport(result(baseFindings), 'soc2'));
        const gapsSuper = gapIds(buildComplianceReport(result(superset), 'soc2'));
        return [...gapsBase].every((id) => gapsSuper.has(id));
      }),
    );
  });
});

describe('compliance renderers never overclaim', () => {
  it('MD renders the scope disclaimer, the framework, and the gap evidence', () => {
    const md = toComplianceMd(buildComplianceReport(result([finding()]), 'soc2'));
    expect(md).toContain('not a certification');
    expect(md).toContain('SOC 2');
    expect(md).toContain('authz/idor-tainted-scope');
    expect(md).not.toMatch(/\bcompliant\b/i);
    expect(md).not.toMatch(/\bcertified\b/i);
  });

  it('JSON carries the disclaimer and claims neither compliance nor certification', () => {
    const json = toComplianceJson(buildComplianceReport(result([]), 'iso27001'));
    expect(json).toContain('not a certification');
    expect(json).not.toMatch(/\bcompliant\b/i);
    expect(json).not.toMatch(/\bcertified\b/i);
  });
});
