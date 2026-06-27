import type { Finding, ScanResult } from '@aegiskit/scanner';
import { describe, expect, it } from 'vitest';
import { correlate } from './correlate';
import type { DynamicFinding } from './probes/types';

const staticFinding: Finding = {
  ruleId: 'injection/sql',
  severity: 'BLOCKER',
  confidence: 'medium',
  message: 'Untrusted input may reach a SQL query.',
  file: '/proj/app/api/search/route.ts',
  range: { startLine: 9, startColumn: 1, endLine: 9, endColumn: 1 },
  docsUrl: 'https://aegis.dev/rules/injection-sql',
  remediation: 'Parameterize.',
};

const staticResult: ScanResult = {
  findings: [staticFinding],
  passes: [],
  summary: { BLOCKER: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  scannedFiles: 1,
  durationMs: 0,
  suppressedCount: 0,
};

const dynamic: DynamicFinding = {
  probeId: 'dast/sql-injection',
  severity: 'BLOCKER',
  confidence: 'high',
  message: 'SQL injection confirmed.',
  owasp: 'A03:2021 Injection',
  docsUrl: 'https://aegis.dev/rules/dast-sql-injection',
  remediation: 'Parameterize.',
  routePath: '/api/search',
  evidence: 'boolean differential (reproduced)',
  target: { kind: 'http-request', method: 'GET', path: '/api/search?id=1' },
};

describe('correlate', () => {
  it('upgrades a static finding confirmed at runtime to high confidence with proof', () => {
    const { findings, correlations } = correlate(staticResult, [dynamic], 'http://localhost:3000');
    const upgraded = findings.find((f) => f.ruleId === 'injection/sql');
    expect(upgraded?.confidence).toBe('high');
    expect(upgraded?.message).toMatch(/^Confirmed exploitable at runtime —/);
    expect(upgraded?.target?.method).toBe('GET');
    expect(correlations).toEqual([
      {
        routePath: '/api/search',
        staticRuleId: 'injection/sql',
        dynamicProbeId: 'dast/sql-injection',
      },
    ]);
  });

  it('also keeps the dynamic finding so the URL view stays navigable', () => {
    const { findings } = correlate(staticResult, [dynamic], 'http://localhost:3000');
    expect(findings.some((f) => f.ruleId === 'dast/sql-injection')).toBe(true);
  });

  it('does not upgrade on a sub-high-confidence dynamic finding', () => {
    const { correlations } = correlate(
      staticResult,
      [{ ...dynamic, confidence: 'medium' }],
      'http://localhost:3000',
    );
    expect(correlations).toHaveLength(0);
  });

  it('returns dynamic findings standalone when there is no static result', () => {
    const { findings } = correlate(undefined, [dynamic], 'http://localhost:3000');
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('dast/sql-injection');
  });
});
