import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  applyBaseline,
  buildBaseline,
  fingerprintFinding,
  parseBaseline,
  serializeBaseline,
} from './baseline';
import { scan } from './engine';
import { emptySummary, type Finding } from './types';

const CWD = '/proj';
const PATH = '/proj/src/env.ts';
const VULN = 'export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n';

function firstFinding(source: string): Finding {
  const [finding] = scan({ files: [PATH], readFile: () => source }).findings;
  if (!finding) {
    throw new Error('expected at least one finding');
  }
  return finding;
}

describe('fingerprintFinding', () => {
  it('is stable under prepended blank lines (the line-shift invariant)', () => {
    const a = firstFinding(VULN);
    const b = firstFinding(`\n\n\n\n${VULN}`);
    expect(fingerprintFinding(a, CWD)).toBe(fingerprintFinding(b, CWD));
    expect(a.range.startLine).not.toBe(b.range.startLine); // the lines really differ
  });

  it('property: unchanged for any number of prepended newlines', () => {
    const base = fingerprintFinding(firstFinding(VULN), CWD);
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 500 }), (k) => {
        expect(fingerprintFinding(firstFinding('\n'.repeat(k) + VULN), CWD)).toBe(base);
      }),
      { numRuns: 30 },
    );
  });

  it('differs across rule / file / evidence', () => {
    const a = firstFinding(VULN);
    expect(fingerprintFinding(a, CWD)).not.toBe(
      fingerprintFinding({ ...a, ruleId: 'other/rule' }, CWD),
    );
    expect(fingerprintFinding(a, CWD)).not.toBe(
      fingerprintFinding({ ...a, file: '/proj/src/other.ts' }, CWD),
    );
  });
});

describe('applyBaseline', () => {
  it('mutes baselined findings and surfaces new ones', () => {
    const result = scan({ files: [PATH], readFile: () => VULN });
    const baseline = buildBaseline(result, CWD, '2026-01-01T00:00:00.000Z');
    const applied = applyBaseline(result, baseline, CWD);
    expect(applied.newCount).toBe(0);
    expect(applied.baselinedCount).toBeGreaterThan(0);
  });

  it('surfaces a finding absent from the baseline', () => {
    const empty = buildBaseline(
      {
        findings: [],
        passes: [],
        summary: emptySummary(),
        scannedFiles: 0,
        suppressedCount: 0,
        durationMs: 0,
      },
      CWD,
      'x',
    );
    const result = scan({ files: [PATH], readFile: () => VULN });
    expect(applyBaseline(result, empty, CWD).newCount).toBe(result.findings.length);
  });
});

describe('buildBaseline / serializeBaseline / parseBaseline', () => {
  it('is deterministic for the same input + timestamp (stable bytes)', () => {
    const result = scan({ files: [PATH], readFile: () => VULN });
    const a = serializeBaseline(buildBaseline(result, CWD, 'T'));
    const b = serializeBaseline(buildBaseline(result, CWD, 'T'));
    expect(a).toBe(b);
  });

  it('round-trips through parseBaseline', () => {
    const result = scan({ files: [PATH], readFile: () => VULN });
    const baseline = buildBaseline(result, CWD, 'T');
    expect(parseBaseline(serializeBaseline(baseline))).toEqual(baseline);
  });

  it('rejects a malformed baseline file', () => {
    expect(() => parseBaseline('{"version":2}')).toThrow();
    expect(() => parseBaseline('not json')).toThrow();
  });
});
