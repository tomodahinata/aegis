/**
 * Deterministic renderers for the benchmark: a plain-ASCII table (a developer/CI artifact, no color, so
 * it is trivially stable) and the canonical machine JSON that becomes `baseline.json`. The JSON carries
 * NO timing and NO absolute paths, with sorted keys — so it is byte-stable and the committed snapshot is
 * a reproducible, citable artifact.
 */

import type { BenchMetrics, CorpusRef } from './metrics';

/** The gate-relevant projection of the metrics — what `baseline.json` stores (no `unexpected`). */
export interface BaselineSnapshot {
  readonly schema: 1;
  readonly overall: BenchMetrics['overall'];
  readonly macro: BenchMetrics['macro'];
  readonly rules: BenchMetrics['rules'];
  readonly falseNegatives: readonly CorpusRef[];
  readonly falsePositives: readonly CorpusRef[];
  readonly corpus: BenchMetrics['corpus'];
}

export function toSnapshot(metrics: BenchMetrics): BaselineSnapshot {
  return {
    schema: 1,
    overall: metrics.overall,
    macro: metrics.macro,
    rules: metrics.rules,
    falseNegatives: metrics.falseNegatives,
    falsePositives: metrics.falsePositives,
    corpus: metrics.corpus,
  };
}

export function toJson(metrics: BenchMetrics): string {
  return `${JSON.stringify(toSnapshot(metrics), null, 2)}\n`;
}

function pad(text: string, width: number): string {
  return text.padEnd(width);
}

function num(value: number): string {
  return value.toFixed(3).padStart(9);
}

function refLine(ref: CorpusRef): string {
  return `  ${ref.corpus}/${ref.dir}  ${ref.ruleId}`;
}

export function toTable(metrics: BenchMetrics): string {
  const ruleIds = Object.keys(metrics.rules);
  const nameWidth = Math.max(30, ...ruleIds.map((r) => r.length));
  const lines: string[] = [];
  lines.push(
    `Aegis scanner benchmark — corpus: ${metrics.corpus.vulnDirs} vuln dirs, ${metrics.corpus.goodDirs} good dirs`,
  );
  lines.push('');
  lines.push(`${pad('rule', nameWidth)}  TP  FP  FN  precision    recall        F1`);
  const rule = (id: string): string => {
    const m = metrics.rules[id];
    if (!m) {
      return '';
    }
    return `${pad(id, nameWidth)}  ${String(m.tp).padStart(2)}  ${String(m.fp).padStart(2)}  ${String(m.fn).padStart(2)}  ${num(m.precision)} ${num(m.recall)} ${num(m.f1)}`;
  };
  // Divider spans the full data-row width so it underlines every column. The width mirrors the row
  // rendered by `rule()` above: the rule name (nameWidth), then the three width-2 integer count
  // columns (TP/FP/FN) interleaved with width-2 gutters — three gutters + three count columns = six
  // width-2 fields — and finally the numeric block (precision/recall/F1 with their spacing) of 30.
  const FIELD = 2; // a count column OR a gutter — both are width 2
  const COUNT_FIELDS = 6; // 3 count columns + 3 gutters before/between them
  const NUMERIC_BLOCK = 30; // precision + recall + F1 columns, with their inter-column spaces
  const divider = '-'.repeat(nameWidth + FIELD * COUNT_FIELDS + NUMERIC_BLOCK);
  lines.push(divider);
  for (const id of ruleIds) {
    lines.push(rule(id));
  }
  lines.push(divider);
  const o = metrics.overall;
  lines.push(
    `${pad('MICRO (overall)', nameWidth)}  ${String(o.tp).padStart(2)}  ${String(o.fp).padStart(2)}  ${String(o.fn).padStart(2)}  ${num(o.precision)} ${num(o.recall)} ${num(o.f1)}`,
  );
  lines.push(
    `${pad('MACRO (mean of rules)', nameWidth)}   —   —   —  ${num(metrics.macro.precision)} ${num(metrics.macro.recall)} ${num(metrics.macro.f1)}`,
  );
  lines.push('');
  lines.push(`False negatives (${metrics.falseNegatives.length}):`);
  for (const ref of metrics.falseNegatives) {
    lines.push(refLine(ref));
  }
  lines.push(`False positives (${metrics.falsePositives.length}):`);
  for (const ref of metrics.falsePositives) {
    lines.push(refLine(ref));
  }
  lines.push(`Unexpected-but-unscored (${metrics.unexpected.length}):`);
  for (const ref of metrics.unexpected) {
    lines.push(refLine(ref));
  }
  return `${lines.join('\n')}\n`;
}
