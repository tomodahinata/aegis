/**
 * The benchmark regression gate, run as part of `pnpm test` (and thus CI). It recomputes precision/
 * recall over the real fixture corpus and enforces the committed `baseline.json`: precision must stay a
 * perfect 1.0 (the zero-false-positive wedge), recall may not regress, the corpus may not shrink, and no
 * rule may vanish. To intentionally move the bar, run `pnpm --filter @aegiskit/scanner bench:update` and
 * review the `baseline.json` diff in the PR.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { collectObservations } from './corpus';
import type { BaselineSnapshot } from './format';
import { evaluateGate } from './gate';
import { type BenchMetrics, computeMetrics, type RuleMetric } from './metrics';

const baseline = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'baseline.json'), 'utf8'),
) as BaselineSnapshot;

describe('scanner benchmark — regression gate', () => {
  const metrics = computeMetrics(collectObservations());

  it('holds precision at a perfect 1.0 and does not regress versus baseline', () => {
    const { ok, failures } = evaluateGate(metrics, baseline);
    expect(failures).toEqual([]);
    expect(ok).toBe(true);
  });

  it('keeps overall precision === 1 (the zero-false-positive wedge)', () => {
    expect(metrics.overall.precision).toBe(1);
    expect(metrics.falsePositives).toEqual([]);
  });

  it('covers the whole corpus with no analysis errors (all fixtures parse and run)', () => {
    expect(metrics.corpus.vulnDirs).toBeGreaterThanOrEqual(baseline.corpus.vulnDirs);
    expect(metrics.corpus.goodDirs).toBeGreaterThanOrEqual(baseline.corpus.goodDirs);
  });
});

/**
 * Synthetic-input coverage: the real-corpus case above passes by construction, so it cannot catch an
 * inverted comparison or a wrong field in any individual failure branch. These build minimal current/
 * baseline shapes that violate exactly one branch and assert the SPECIFIC message — so flipping a `<` to
 * `>`, reading `precision` where `recall` is meant, or comparing the wrong corpus counter all turn red.
 */
describe('evaluateGate — each failure branch (synthetic inputs)', () => {
  const ruleMetric = (over: Partial<RuleMetric> = {}): RuleMetric => ({
    tp: 1,
    fp: 0,
    fn: 0,
    precision: 1,
    recall: 1,
    f1: 1,
    ...over,
  });

  const metrics = (over: Partial<BenchMetrics> = {}): BenchMetrics => ({
    overall: ruleMetric(),
    macro: { precision: 1, recall: 1, f1: 1 },
    rules: {},
    falseNegatives: [],
    falsePositives: [],
    unexpected: [],
    corpus: { vulnDirs: 10, goodDirs: 10 },
    ...over,
  });

  const snapshot = (over: Partial<BaselineSnapshot> = {}): BaselineSnapshot => ({
    schema: 1,
    overall: ruleMetric(),
    macro: { precision: 1, recall: 1, f1: 1 },
    rules: {},
    falseNegatives: [],
    falsePositives: [],
    corpus: { vulnDirs: 10, goodDirs: 10 },
    ...over,
  });

  it('passes cleanly when current matches the baseline', () => {
    const { ok, failures } = evaluateGate(metrics(), snapshot());
    expect(failures).toEqual([]);
    expect(ok).toBe(true);
  });

  it('fails when overall precision dips below the 1.0 hard floor', () => {
    const { ok, failures } = evaluateGate(
      metrics({ overall: ruleMetric({ precision: 0.9 }) }),
      snapshot(),
    );
    expect(ok).toBe(false);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('below the hard floor');
    expect(failures[0]).toContain('0.9');
  });

  it('fails and names each false positive on a good fixture', () => {
    const { ok, failures } = evaluateGate(
      metrics({ falsePositives: [{ corpus: 'ts', dir: 'safe-route', ruleId: 'authz/idor' }] }),
      snapshot(),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('false positive:');
    expect(failures[0]).toContain('safe-route');
    expect(failures[0]).toContain('authz/idor');
  });

  it('fails when overall recall regresses below baseline', () => {
    const { ok, failures } = evaluateGate(
      metrics({ overall: ruleMetric({ recall: 0.7 }) }),
      snapshot({ overall: ruleMetric({ recall: 0.9 }) }),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('overall recall regressed');
    expect(failures[0]).toContain('0.7');
    expect(failures[0]).toContain('0.9');
  });

  it('fails when a baseline rule disappears from the current corpus', () => {
    const { ok, failures } = evaluateGate(
      metrics({ rules: {} }),
      snapshot({ rules: { 'crypto/weak-hash': ruleMetric() } }),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('crypto/weak-hash');
    expect(failures[0]).toContain('disappeared');
  });

  it('fails when a per-rule recall regresses below baseline', () => {
    const { ok, failures } = evaluateGate(
      metrics({ rules: { 'crypto/weak-hash': ruleMetric({ recall: 0.5 }) } }),
      snapshot({ rules: { 'crypto/weak-hash': ruleMetric({ recall: 0.8 }) } }),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('crypto/weak-hash');
    expect(failures[0]).toContain('recall regressed');
    expect(failures[0]).toContain('0.5');
    expect(failures[0]).toContain('0.8');
  });

  it('fails when the vuln corpus shrinks below baseline', () => {
    const { ok, failures } = evaluateGate(
      metrics({ corpus: { vulnDirs: 8, goodDirs: 10 } }),
      snapshot({ corpus: { vulnDirs: 10, goodDirs: 10 } }),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('vuln corpus shrank');
    expect(failures[0]).toContain('8');
  });

  it('fails when the good corpus shrinks below baseline', () => {
    const { ok, failures } = evaluateGate(
      metrics({ corpus: { vulnDirs: 10, goodDirs: 7 } }),
      snapshot({ corpus: { vulnDirs: 10, goodDirs: 10 } }),
    );
    expect(ok).toBe(false);
    expect(failures[0]).toContain('good corpus shrank');
    expect(failures[0]).toContain('7');
  });
});
