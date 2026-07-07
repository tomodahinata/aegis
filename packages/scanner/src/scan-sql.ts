/**
 * `scanSql` — the SQL-analysis entry, parallel to `scan` (SRP: the TS engine builds scope/taint/
 * reachability; this builds a cross-file RLS model). It returns the SAME `ScanResult`, so every
 * reporter, the baseline, and the CLI exit code work unchanged — the two analyses pool at the output.
 */

import { readFileSync } from 'node:fs';
import { analysisErrorFinding } from './internal/analysis-error';
import { buildRlsModel, type SqlSource } from './internal/sql/model';
import type { SqlRule, SqlRuleContext } from './sql-rule';
import { ALL_SQL_RULES } from './sql-rules';
import { emptySummary, type Finding, type ScanResult } from './types';

export interface ScanSqlOptions {
  readonly files: readonly string[];
  /** Rules to run. Default: all built-in SQL rules. */
  readonly rules?: readonly SqlRule[];
  /** File reader (for tests/virtual FS). Default: `fs.readFileSync`. */
  readonly readFile?: (path: string) => string;
}

export function scanSql(options: ScanSqlOptions): ScanResult {
  const started = Date.now();
  const read = options.readFile ?? ((path: string) => readFileSync(path, 'utf8'));
  const rules = options.rules ?? ALL_SQL_RULES;

  // Isolate each read: one unreadable migration must not abort the whole SQL/RLS analysis (fail
  // secure) — it is skipped and surfaced as a LOW finding so the coverage gap is never silent.
  const sources: SqlSource[] = [];
  const findings: Finding[] = [];
  for (const path of options.files) {
    try {
      sources.push({ path, text: read(path) });
    } catch (error) {
      findings.push(analysisErrorFinding(path, error));
    }
  }
  const model = buildRlsModel(sources);
  for (const rule of rules) {
    const ctx: SqlRuleContext = {
      model,
      report: (input) => {
        findings.push({
          ruleId: rule.meta.id,
          severity: input.severity ?? rule.meta.severity,
          confidence: input.confidence,
          message: input.message,
          file: input.loc.file,
          range: {
            startLine: input.loc.line,
            startColumn: input.loc.column,
            endLine: input.loc.line,
            endColumn: input.loc.column,
          },
          docsUrl: rule.meta.docsUrl,
          remediation: input.remediation,
          ...(rule.meta.owasp !== undefined ? { owasp: rule.meta.owasp } : {}),
          ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
          ...(input.explanation !== undefined ? { explanation: input.explanation } : {}),
        });
      },
    };
    rule.check(ctx);
  }

  findings.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.range.startLine - b.range.startLine ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return {
    findings,
    passes: [],
    summary,
    scannedFiles: sources.length,
    suppressedCount: 0,
    durationMs: Date.now() - started,
  };
}
