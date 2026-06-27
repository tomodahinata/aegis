/**
 * Benchmark CLI. `pnpm bench` prints the table; `--json` emits the canonical snapshot; `--check` runs the
 * regression gate (exit 1 on failure); `--update` rewrites the committed baseline (a deliberate, reviewed
 * act). The committed `baseline.json` is the citable, reproducible "we measured our own precision/recall"
 * artifact.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectObservations } from './corpus';
import { type BaselineSnapshot, toJson, toTable } from './format';
import { evaluateGate } from './gate';
import { computeMetrics } from './metrics';

const BASELINE = join(dirname(fileURLToPath(import.meta.url)), 'baseline.json');

function readBaseline(): BaselineSnapshot {
  return JSON.parse(readFileSync(BASELINE, 'utf8')) as BaselineSnapshot;
}

function main(): void {
  const args = new Set(process.argv.slice(2));
  const metrics = computeMetrics(collectObservations());

  if (args.has('--update')) {
    writeFileSync(BASELINE, toJson(metrics));
    process.stdout.write(`Updated ${BASELINE}\n`);
    return;
  }
  if (args.has('--json')) {
    process.stdout.write(toJson(metrics));
    return;
  }
  process.stdout.write(toTable(metrics));
  if (args.has('--check')) {
    const { ok, failures } = evaluateGate(metrics, readBaseline());
    if (!ok) {
      process.stderr.write(
        `\nBenchmark gate FAILED:\n${failures.map((f) => `  • ${f}`).join('\n')}\n`,
      );
      process.exit(1);
    }
    process.stdout.write('\nBenchmark gate passed.\n');
  }
}

main();
