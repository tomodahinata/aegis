import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import type { Finding, ScanResult } from '../types';
import {
  computeRemediation,
  parseHistory,
  type ScanRecord,
  serializeScanRecord,
  toScanRecord,
} from './history';

function finding(ruleId: string, evidence: string): Finding {
  return {
    ruleId,
    severity: 'HIGH',
    confidence: 'medium',
    message: 'm',
    file: '/repo/a.sql',
    range: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    docsUrl: 'x',
    remediation: 'r',
    evidence,
  };
}

function result(findings: readonly Finding[]): ScanResult {
  return {
    findings,
    passes: [],
    summary: { BLOCKER: 0, HIGH: findings.length, MEDIUM: 0, LOW: 0, INFO: 0 },
    scannedFiles: 1,
    durationMs: 0,
    suppressedCount: 0,
  };
}

const record = (scannedAt: string, ...openFingerprints: string[]): ScanRecord => ({
  scannedAt,
  openFingerprints,
});

describe('toScanRecord', () => {
  it('dedupes and sorts fingerprints and carries the commit when given', () => {
    const rec = toScanRecord(
      result([finding('r/a', 'e1'), finding('r/b', 'e2')]),
      '/repo',
      '2026-07-01T00:00:00Z',
      'abc123',
    );
    expect(rec.commit).toBe('abc123');
    expect(rec.openFingerprints).toHaveLength(2);
    expect([...rec.openFingerprints]).toEqual([...rec.openFingerprints].sort());
  });

  it('omits commit when not provided', () => {
    const rec = toScanRecord(result([]), '/repo', '2026-07-01T00:00:00Z');
    expect('commit' in rec).toBe(false);
  });
});

describe('parseHistory', () => {
  it('round-trips serialized records and sorts by scannedAt', () => {
    const jsonl = [
      serializeScanRecord(record('2026-07-03T00:00:00Z', 'b')),
      serializeScanRecord(record('2026-07-01T00:00:00Z', 'a')),
    ].join('\n');
    const parsed = parseHistory(jsonl);
    expect(parsed.map((r) => r.scannedAt)).toEqual([
      '2026-07-01T00:00:00Z',
      '2026-07-03T00:00:00Z',
    ]);
  });

  it('skips blank and corrupt lines instead of throwing', () => {
    const jsonl = [
      '',
      'not json',
      '{"scannedAt":123}',
      serializeScanRecord(record('2026-07-01T00:00:00Z', 'a')),
    ].join('\n');
    const parsed = parseHistory(jsonl);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.openFingerprints).toEqual(['a']);
  });
});

describe('computeRemediation', () => {
  const NOW = '2026-07-10T00:00:00Z';

  it('reports zeros for empty history', () => {
    const summary = computeRemediation([], NOW);
    expect(summary).toMatchObject({
      scans: 0,
      totalTracked: 0,
      open: 0,
      resolved: 0,
      meanTimeToRemediateDays: null,
      oldestOpenAgeDays: null,
    });
  });

  it('classifies a persistent finding as open and ages it from firstSeen to now', () => {
    const history = [record('2026-07-01T00:00:00Z', 'x'), record('2026-07-05T00:00:00Z', 'x')];
    const summary = computeRemediation(history, NOW);
    expect(summary.open).toBe(1);
    expect(summary.resolved).toBe(0);
    const life = summary.lifecycles[0];
    expect(life?.status).toBe('open');
    expect(life?.ageDays).toBe(9); // 2026-07-01 → 2026-07-10
    expect(summary.oldestOpenAgeDays).toBe(9);
  });

  it('classifies a disappeared finding as resolved with MTTR from firstSeen to the fixed scan', () => {
    const history = [
      record('2026-07-01T00:00:00Z', 'x'),
      record('2026-07-04T00:00:00Z', 'x'),
      record('2026-07-06T00:00:00Z'), // x gone here → resolvedAt
    ];
    const summary = computeRemediation(history, NOW);
    expect(summary.resolved).toBe(1);
    expect(summary.open).toBe(0);
    const life = summary.lifecycles[0];
    expect(life?.status).toBe('resolved');
    expect(life?.resolvedAt).toBe('2026-07-06T00:00:00Z');
    expect(life?.ageDays).toBe(5); // 07-01 → 07-06
    expect(summary.meanTimeToRemediateDays).toBe(5);
  });

  it('averages MTTR across resolved findings and tracks the oldest open one', () => {
    const history = [
      record('2026-07-01T00:00:00Z', 'a', 'b', 'openOld'),
      record('2026-07-03T00:00:00Z', 'b', 'openOld'), // a resolved on 07-03 (age 2)
      record('2026-07-07T00:00:00Z', 'openOld'), // b resolved on 07-07 (age 6)
    ];
    const summary = computeRemediation(history, NOW);
    expect(summary.resolved).toBe(2);
    expect(summary.meanTimeToRemediateDays).toBe(4); // (2 + 6) / 2
    expect(summary.open).toBe(1);
    expect(summary.oldestOpenAgeDays).toBe(9); // openOld since 07-01
  });

  it('treats a flapping finding (disappears then reappears) as one open lifecycle from first sight', () => {
    const history = [
      record('2026-07-01T00:00:00Z', 'x'),
      record('2026-07-05T00:00:00Z'), // gone
      record('2026-07-10T00:00:00Z', 'x'), // back — still open at the latest scan
    ];
    const summary = computeRemediation(history, NOW); // NOW = 2026-07-10
    expect(summary.totalTracked).toBe(1); // one lifecycle, not two
    expect(summary.open).toBe(1);
    expect(summary.resolved).toBe(0); // never over-claims a fix that did not hold
    const life = summary.lifecycles[0];
    expect(life?.status).toBe('open');
    expect(life?.firstSeen).toBe('2026-07-01T00:00:00Z'); // earliest appearance, not the reappearance
    expect(life?.resolvedAt).toBeUndefined();
    expect(life?.ageDays).toBe(9); // 07-01 → NOW
  });

  it('never yields NaN or a negative age when a record carries a non-ISO timestamp', () => {
    const summary = computeRemediation([{ scannedAt: 'not-a-date', openFingerprints: ['x'] }], NOW);
    const life = summary.lifecycles[0];
    expect(life?.ageDays).toBe(0);
    expect(Number.isNaN(life?.ageDays)).toBe(false);
    expect(summary.oldestOpenAgeDays).toBe(0);
  });

  it('INVARIANT: open + resolved === totalTracked, and no age is negative', () => {
    const fp = fc.constantFrom('a', 'b', 'c', 'd');
    const day = fc
      .integer({ min: 1, max: 28 })
      .map((d) => `2026-06-${String(d).padStart(2, '0')}T00:00:00Z`);
    const scan = fc.record({ scannedAt: day, openFingerprints: fc.uniqueArray(fp) });
    fc.assert(
      fc.property(fc.array(scan, { maxLength: 8 }), (scans) => {
        const summary = computeRemediation(scans, '2026-07-15T00:00:00Z');
        expect(summary.open + summary.resolved).toBe(summary.totalTracked);
        for (const life of summary.lifecycles) {
          expect(life.ageDays).toBeGreaterThanOrEqual(0);
        }
      }),
    );
  });
});
