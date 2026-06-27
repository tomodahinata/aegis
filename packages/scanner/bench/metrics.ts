/**
 * Pure precision/recall math for the scanner benchmark — no filesystem, no scanner. The unit of truth
 * is a (fixture, ruleId) pair, not a raw finding:
 *
 *   • TP = an EXPECTED (vuln-fixture, ruleId) pair that fired.
 *   • FN = an EXPECTED pair that did NOT fire           → drives RECALL.
 *   • FP = a GOOD-fixture rule firing                   → drives PRECISION (the zero-FP trust wedge).
 *
 * A rule that fires inside a vuln fixture but is neither expected nor explicitly allowed is recorded as
 * `unexpected` (informational) — NOT a false positive, because a vuln file may legitimately contain a
 * second real flaw. Precision is anchored to the good corpus, exactly where the team's trust gate lives.
 */

export interface RuleMetric {
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
}

export interface CorpusRef {
  readonly corpus: 'ts' | 'sql';
  readonly dir: string;
  readonly ruleId: string;
}

export interface BenchMetrics {
  /** Micro-averaged over all (fixture, ruleId) pairs — reflects real corpus behavior. */
  readonly overall: RuleMetric;
  /** Macro = unweighted mean of per-rule precision/recall/f1 (shown for transparency). */
  readonly macro: { readonly precision: number; readonly recall: number; readonly f1: number };
  readonly rules: Readonly<Record<string, RuleMetric>>;
  readonly falseNegatives: readonly CorpusRef[];
  readonly falsePositives: readonly CorpusRef[];
  readonly unexpected: readonly CorpusRef[];
  readonly corpus: { readonly vulnDirs: number; readonly goodDirs: number };
}

export interface VulnObservation {
  readonly corpus: 'ts' | 'sql';
  readonly dir: string;
  readonly expect: readonly string[];
  readonly allow: readonly string[];
  /** ruleIds that actually fired when this vuln fixture was scanned (synthetic rules excluded). */
  readonly fired: readonly string[];
}

export interface GoodObservation {
  readonly corpus: 'ts' | 'sql';
  readonly dir: string;
  /** ruleIds that fired — every one is a false positive (good fixtures must be silent). */
  readonly fired: readonly string[];
}

export interface CorpusObservations {
  readonly vuln: readonly VulnObservation[];
  readonly good: readonly GoodObservation[];
}

/** Round to 4 decimals so metric values are stable across platforms (and snapshot-comparable). */
function round4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

function ratio(numerator: number, denominator: number): number {
  // No opportunity to be wrong (denominator 0) ⇒ a perfect 1, by convention.
  return denominator === 0 ? 1 : round4(numerator / denominator);
}

function f1Of(precision: number, recall: number): number {
  return precision + recall === 0 ? 0 : round4((2 * precision * recall) / (precision + recall));
}

/** Increment a counter, treating a missing key as 0 (keeps the strict index types honest). */
function bump(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

export function computeMetrics(obs: CorpusObservations): BenchMetrics {
  const tp: Record<string, number> = {};
  const fp: Record<string, number> = {};
  const fn: Record<string, number> = {};
  const falseNegatives: CorpusRef[] = [];
  const falsePositives: CorpusRef[] = [];
  const unexpected: CorpusRef[] = [];
  const ensure = (rule: string): void => {
    tp[rule] ??= 0;
    fp[rule] ??= 0;
    fn[rule] ??= 0;
  };

  for (const observation of obs.vuln) {
    const fired = new Set(observation.fired);
    const sanctioned = new Set([...observation.expect, ...observation.allow]);
    for (const rule of observation.expect) {
      ensure(rule);
      if (fired.has(rule)) {
        bump(tp, rule);
      } else {
        bump(fn, rule);
        falseNegatives.push({ corpus: observation.corpus, dir: observation.dir, ruleId: rule });
      }
    }
    for (const rule of observation.fired) {
      if (!sanctioned.has(rule)) {
        unexpected.push({ corpus: observation.corpus, dir: observation.dir, ruleId: rule });
      }
    }
  }

  for (const observation of obs.good) {
    for (const rule of observation.fired) {
      ensure(rule);
      bump(fp, rule);
      falsePositives.push({ corpus: observation.corpus, dir: observation.dir, ruleId: rule });
    }
  }

  const rules: Record<string, RuleMetric> = {};
  let sumTp = 0;
  let sumFp = 0;
  let sumFn = 0;
  let macroP = 0;
  let macroR = 0;
  let macroF = 0;
  const ruleIds = Object.keys(tp).sort();
  for (const rule of ruleIds) {
    const t = tp[rule] ?? 0;
    const f = fp[rule] ?? 0;
    const n = fn[rule] ?? 0;
    const precision = ratio(t, t + f);
    const recall = ratio(t, t + n);
    rules[rule] = { tp: t, fp: f, fn: n, precision, recall, f1: f1Of(precision, recall) };
    sumTp += t;
    sumFp += f;
    sumFn += n;
    macroP += precision;
    macroR += recall;
    macroF += f1Of(precision, recall);
  }

  const overallP = ratio(sumTp, sumTp + sumFp);
  const overallR = ratio(sumTp, sumTp + sumFn);
  const count = ruleIds.length || 1;
  const sortRef = (a: CorpusRef, b: CorpusRef): number =>
    a.corpus.localeCompare(b.corpus) ||
    a.dir.localeCompare(b.dir) ||
    a.ruleId.localeCompare(b.ruleId);

  return {
    overall: {
      tp: sumTp,
      fp: sumFp,
      fn: sumFn,
      precision: overallP,
      recall: overallR,
      f1: f1Of(overallP, overallR),
    },
    macro: {
      precision: round4(macroP / count),
      recall: round4(macroR / count),
      f1: round4(macroF / count),
    },
    rules,
    falseNegatives: falseNegatives.sort(sortRef),
    falsePositives: falsePositives.sort(sortRef),
    unexpected: unexpected.sort(sortRef),
    corpus: { vulnDirs: obs.vuln.length, goodDirs: obs.good.length },
  };
}
