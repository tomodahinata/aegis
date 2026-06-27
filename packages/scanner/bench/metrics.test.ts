import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { type CorpusObservations, computeMetrics } from './metrics';

describe('computeMetrics', () => {
  it('a perfect corpus scores precision/recall/f1 = 1 with no FP/FN', () => {
    const obs: CorpusObservations = {
      vuln: [{ corpus: 'ts', dir: 'a', expect: ['r1'], allow: [], fired: ['r1'] }],
      good: [{ corpus: 'ts', dir: 'g', fired: [] }],
    };
    const m = computeMetrics(obs);
    expect(m.overall).toMatchObject({ precision: 1, recall: 1, f1: 1 });
    expect(m.falsePositives).toEqual([]);
    expect(m.falseNegatives).toEqual([]);
  });

  it('a missed expectation is a false negative (recall < 1)', () => {
    const m = computeMetrics({
      vuln: [{ corpus: 'ts', dir: 'a', expect: ['r1'], allow: [], fired: [] }],
      good: [],
    });
    expect(m.overall.recall).toBe(0);
    expect(m.falseNegatives).toEqual([{ corpus: 'ts', dir: 'a', ruleId: 'r1' }]);
  });

  it('a good-fixture firing is a false positive (precision < 1)', () => {
    const m = computeMetrics({
      vuln: [{ corpus: 'ts', dir: 'a', expect: ['r1'], allow: [], fired: ['r1'] }],
      good: [{ corpus: 'ts', dir: 'g', fired: ['r1'] }],
    });
    expect(m.overall.precision).toBeLessThan(1);
    expect(m.falsePositives).toEqual([{ corpus: 'ts', dir: 'g', ruleId: 'r1' }]);
  });

  it('an allowed incidental firing is not unexpected; an unsanctioned one is', () => {
    const m = computeMetrics({
      vuln: [{ corpus: 'ts', dir: 'a', expect: ['r1'], allow: ['r2'], fired: ['r1', 'r2', 'r3'] }],
      good: [],
    });
    expect(m.unexpected).toEqual([{ corpus: 'ts', dir: 'a', ruleId: 'r3' }]);
  });

  it('invariants hold for arbitrary corpora', () => {
    const ruleArb = fc.constantFrom('r1', 'r2', 'r3');
    const vulnArb = fc.record({
      corpus: fc.constant('ts' as const),
      dir: fc.string(),
      expect: fc.array(ruleArb, { minLength: 1 }),
      allow: fc.array(ruleArb),
      fired: fc.array(ruleArb),
    });
    const goodArb = fc.record({
      corpus: fc.constant('ts' as const),
      dir: fc.string(),
      fired: fc.array(ruleArb),
    });
    fc.assert(
      fc.property(fc.array(vulnArb), fc.array(goodArb), (vuln, good) => {
        const m = computeMetrics({ vuln, good });
        const inUnit = (x: number): boolean => x >= 0 && x <= 1;
        expect(inUnit(m.overall.precision)).toBe(true);
        expect(inUnit(m.overall.recall)).toBe(true);
        expect(m.overall.f1).toBeLessThanOrEqual(
          Math.max(m.overall.precision, m.overall.recall) + 1e-4,
        );
      }),
    );
  });
});
