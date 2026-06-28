import type { Confidence, Finding, ScanResult, Severity } from '@aegiskit/scanner';
import { describe, expect, it } from 'vitest';
import { exitCodeFor } from './exit';

function finding(severity: Severity, confidence: Confidence): Finding {
  return {
    ruleId: 'x/y',
    severity,
    confidence,
    message: 'm',
    file: '/a.ts',
    range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
    docsUrl: 'https://github.com/tomodahinata/aegis',
    remediation: 'r',
  };
}

function resultWith(findings: Finding[]): ScanResult {
  return {
    findings,
    passes: [],
    summary: { BLOCKER: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    scannedFiles: 1,
    suppressedCount: 0,
    durationMs: 0,
  };
}

describe('exitCodeFor', () => {
  it('fails (1) on a high-confidence finding at/above threshold', () => {
    expect(
      exitCodeFor(resultWith([finding('HIGH', 'high')]), { threshold: 'HIGH', strict: false }),
    ).toBe(1);
  });

  it('passes (0) when only lower-confidence findings exist (the FP guard)', () => {
    expect(
      exitCodeFor(resultWith([finding('HIGH', 'medium')]), { threshold: 'HIGH', strict: false }),
    ).toBe(0);
  });

  it('fails on lower-confidence findings when --strict', () => {
    expect(
      exitCodeFor(resultWith([finding('HIGH', 'medium')]), { threshold: 'HIGH', strict: true }),
    ).toBe(1);
  });

  it('ignores findings below the severity threshold', () => {
    expect(
      exitCodeFor(resultWith([finding('LOW', 'high')]), { threshold: 'HIGH', strict: false }),
    ).toBe(0);
  });

  it('returns 0 with no findings', () => {
    expect(exitCodeFor(resultWith([]), { threshold: 'HIGH', strict: false })).toBe(0);
  });
});
