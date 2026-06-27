/**
 * The regression gate, shared by `run.ts --check` and `gate.test.ts` so the CLI and the test enforce
 * exactly the same contract. Two complementary guarantees: an absolute floor (precision MUST stay 1.0 —
 * the zero-false-positive wedge) and a no-regression check against the committed baseline (recall may
 * not drop, the corpus may not silently shrink, a rule may not vanish).
 */

import type { BaselineSnapshot } from './format';
import type { BenchMetrics } from './metrics';

export function evaluateGate(
  current: BenchMetrics,
  baseline: BaselineSnapshot,
): { readonly ok: boolean; readonly failures: readonly string[] } {
  const failures: string[] = [];

  // Absolute floor — independent of the snapshot.
  if (current.overall.precision < 1) {
    failures.push(
      `overall precision is ${current.overall.precision}, below the hard floor of 1.0 (zero false positives is the trust wedge)`,
    );
  }
  for (const fp of current.falsePositives) {
    failures.push(
      `false positive: ${fp.corpus}/${fp.dir} fired ${fp.ruleId} (good fixtures must be silent)`,
    );
  }

  // No regression versus the committed baseline.
  if (current.overall.recall < baseline.overall.recall) {
    failures.push(
      `overall recall regressed: ${current.overall.recall} < baseline ${baseline.overall.recall}`,
    );
  }
  for (const [ruleId, base] of Object.entries(baseline.rules)) {
    const now = current.rules[ruleId];
    if (!now) {
      failures.push(`rule ${ruleId} disappeared from the corpus (baseline expected it)`);
      continue;
    }
    if (now.recall < base.recall) {
      failures.push(`rule ${ruleId} recall regressed: ${now.recall} < baseline ${base.recall}`);
    }
  }
  if (current.corpus.vulnDirs < baseline.corpus.vulnDirs) {
    failures.push(
      `vuln corpus shrank: ${current.corpus.vulnDirs} < baseline ${baseline.corpus.vulnDirs}`,
    );
  }
  if (current.corpus.goodDirs < baseline.corpus.goodDirs) {
    failures.push(
      `good corpus shrank: ${current.corpus.goodDirs} < baseline ${baseline.corpus.goodDirs}`,
    );
  }

  return { ok: failures.length === 0, failures };
}
