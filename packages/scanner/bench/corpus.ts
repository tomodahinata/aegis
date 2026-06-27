/**
 * Run the scanner over the labeled fixture corpus and turn it into the observations the metrics module
 * scores. Each fixture directory is scanned IN ISOLATION (exactly as `scan.test.ts` does), so a firing
 * is always attributable to one fixture. A fixture that fails to analyze (parse error) is a corpus bug
 * and aborts the run loudly — silent gaps would inflate the scores.
 */

import { readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SQL_LABELS, TS_LABELS } from '../fixtures/labels';
import { scan } from '../src/engine';
import { ANALYSIS_ERROR_RULE } from '../src/internal/analysis-error';
import { scanSql } from '../src/scan-sql';
import type { Finding } from '../src/types';
import type { CorpusObservations, GoodObservation, VulnObservation } from './metrics';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

function filesIn(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...filesIn(full));
    } else if (/\.(?:ts|tsx|js|jsx)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

function sqlFilesIn(dir: string): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => join(dir, f));
}

function subDirs(dir: string): string[] {
  return readdirSync(dir).filter((d) => statSync(join(dir, d)).isDirectory());
}

/** Distinct ruleIds that fired, excluding the synthetic analysis-error rule (whose presence is fatal). */
function firedRules(findings: readonly Finding[], where: string): string[] {
  const ids = new Set<string>();
  for (const finding of findings) {
    if (finding.ruleId === ANALYSIS_ERROR_RULE) {
      throw new Error(`Benchmark corpus fixture failed to analyze (${where}): ${finding.message}`);
    }
    ids.add(finding.ruleId);
  }
  return [...ids];
}

export function collectObservations(): CorpusObservations {
  const vuln: VulnObservation[] = [];
  const good: GoodObservation[] = [];

  for (const label of TS_LABELS) {
    const result = scan({ files: filesIn(join(FIXTURES, 'vuln', label.dir)) });
    vuln.push({
      corpus: 'ts',
      dir: label.dir,
      expect: label.expect,
      allow: label.allow ?? [],
      fired: firedRules(result.findings, `vuln/${label.dir}`),
    });
  }
  for (const dir of subDirs(join(FIXTURES, 'good'))) {
    const result = scan({ files: filesIn(join(FIXTURES, 'good', dir)) });
    good.push({ corpus: 'ts', dir, fired: firedRules(result.findings, `good/${dir}`) });
  }

  for (const label of SQL_LABELS) {
    const result = scanSql({ files: sqlFilesIn(join(FIXTURES, 'sql', label.dir)) });
    vuln.push({
      corpus: 'sql',
      dir: label.dir,
      expect: label.expect,
      allow: label.allow ?? [],
      fired: firedRules(result.findings, `sql/${label.dir}`),
    });
  }
  const sqlGood = scanSql({ files: sqlFilesIn(join(FIXTURES, 'sql', 'good')) });
  good.push({ corpus: 'sql', dir: 'good', fired: firedRules(sqlGood.findings, 'sql/good') });

  return { vuln, good };
}
