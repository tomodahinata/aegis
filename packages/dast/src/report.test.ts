import { describe, expect, it } from 'vitest';
import type { DynamicFinding } from './probes/types';
import { summarize, toFinding, toScanResult } from './report';

function dynamicFinding(overrides: Partial<DynamicFinding> = {}): DynamicFinding {
  return {
    probeId: 'dast/open-redirect',
    severity: 'HIGH',
    confidence: 'high',
    message: 'open redirect',
    owasp: 'A01:2021 Broken Access Control',
    docsUrl: 'https://github.com/tomodahinata/aegis/rules/dast-open-redirect',
    remediation: 'validate the redirect target',
    routePath: '/api/y',
    evidence: 'Location: //evil.com',
    target: { kind: 'http-request', method: 'GET', path: '/api/y?next=//evil.com' },
    ...overrides,
  };
}

describe('toFinding', () => {
  it('joins origin + routePath without a double slash when the origin has a trailing slash', () => {
    expect(toFinding(dynamicFinding(), 'http://localhost:3000/').file).toBe(
      'http://localhost:3000/api/y',
    );
    expect(toFinding(dynamicFinding(), 'http://localhost:3000').file).toBe(
      'http://localhost:3000/api/y',
    );
  });

  it('maps probeId → ruleId and carries owasp + target through', () => {
    const f = toFinding(dynamicFinding(), 'http://localhost:3000');
    expect(f.ruleId).toBe('dast/open-redirect');
    expect(f.owasp).toBe('A01:2021 Broken Access Control');
    expect(f.target?.method).toBe('GET');
  });
});

describe('summarize', () => {
  it('counts findings per severity', () => {
    const findings = [
      toFinding(dynamicFinding({ severity: 'HIGH' }), 'http://x'),
      toFinding(dynamicFinding({ severity: 'HIGH' }), 'http://x'),
      toFinding(dynamicFinding({ severity: 'MEDIUM' }), 'http://x'),
    ];
    const s = summarize(findings);
    expect(s.HIGH).toBe(2);
    expect(s.MEDIUM).toBe(1);
    expect(s.LOW).toBe(0);
  });
});

describe('toScanResult', () => {
  it('wraps dynamic findings with zero scannedFiles and a passed-through duration', () => {
    const result = toScanResult([toFinding(dynamicFinding(), 'http://x')], 1234);
    expect(result.scannedFiles).toBe(0);
    expect(result.durationMs).toBe(1234);
    expect(result.suppressedCount).toBe(0);
    expect(result.summary.HIGH).toBe(1);
    expect(result.passes).toEqual([]);
  });
});
