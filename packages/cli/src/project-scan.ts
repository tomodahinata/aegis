/**
 * The full-project scan: TypeScript rules (`scan`) + Supabase SQL/RLS rules (`scanSql`) + RLS↔code
 * correlation, merged into one `ScanResult`. Shared by `scan`/`ci`/`doctor` (DRY) so every command
 * sees the same findings — application-layer and database-layer together. Also consumed across the
 * package boundary by `@aegiskit/mcp`, so treat `scanProject`'s signature as a cross-package contract.
 */

import { readFileSync } from 'node:fs';
import {
  correlateRls,
  emptySummary,
  type Finding,
  type ScanResult,
  scan,
  scanSql,
} from '@aegiskit/scanner';
import { defaultAliases, discoverFiles, discoverSqlFiles } from './discover';

export interface ProjectScanOptions {
  readonly showSuppressed?: boolean;
}

function combine(ts: ScanResult, sql: ScanResult, extra: readonly Finding[]): ScanResult {
  const findings = [...ts.findings, ...sql.findings, ...extra].sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.range.startLine - b.range.startLine ||
      a.range.startColumn - b.range.startColumn ||
      a.ruleId.localeCompare(b.ruleId),
  );
  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return {
    findings,
    passes: ts.passes,
    summary,
    scannedFiles: ts.scannedFiles + sql.scannedFiles,
    durationMs: ts.durationMs + sql.durationMs,
    suppressedCount: ts.suppressedCount,
  };
}

export function scanProject(cwd: string, options: ProjectScanOptions = {}): ScanResult {
  const files = discoverFiles(cwd);
  const aliases = defaultAliases(cwd);

  // Read each file from disk at most once. `scan` and `correlateRls` both consume the TS files'
  // text, so without a shared reader a project with a weak-RLS table reads the whole TS corpus
  // twice. (The parse in `correlateRls` is still separate — sharing it would mean exposing the
  // scanner's parsed AST across the package boundary, a public-surface cost we deliberately avoid.)
  const textCache = new Map<string, string>();
  const readFile = (path: string): string => {
    const cached = textCache.get(path);
    if (cached !== undefined) {
      return cached;
    }
    const text = readFileSync(path, 'utf8');
    textCache.set(path, text);
    return text;
  };

  const tsResult = scan({
    files,
    readFile,
    ...(aliases ? { aliases } : {}),
    ...(options.showSuppressed ? { showSuppressed: true } : {}),
  });

  const sqlFiles = discoverSqlFiles(cwd);
  if (sqlFiles.length === 0) {
    return tsResult;
  }
  const sqlResult = scanSql({ files: sqlFiles, readFile });
  // Correlate weak-RLS tables with the code that queries them (parses TS only if a weak table exists).
  const exposures = correlateRls({ sqlFiles, tsFiles: files, readFile });
  return combine(tsResult, sqlResult, exposures);
}
