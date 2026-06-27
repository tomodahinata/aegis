import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  applyBaseline,
  buildBaseline,
  parseBaseline,
  type ScanResult,
  type Severity,
  serializeBaseline,
  toJson,
  toSarif,
} from '@aegiskit/scanner';
import { EXIT, exitCodeFor } from '../exit';
import { colorEnabled } from '../internal/colors';
import { scanProject } from '../project-scan';
import { renderReport } from '../reporters/pretty';

export type OutputFormat = 'pretty' | 'json' | 'sarif';

export interface ScanArgs {
  readonly cwd: string;
  readonly format: OutputFormat;
  readonly severity: Severity;
  readonly strict: boolean;
  readonly noColor: boolean;
  readonly plain: boolean;
  readonly showSuppressed: boolean;
  /** Explicit baseline path. Otherwise `aegis-baseline.json` is auto-detected in `cwd`. */
  readonly baseline?: string;
  readonly updateBaseline: boolean;
}

const DEFAULT_BASELINE = 'aegis-baseline.json';

export function runScan(args: ScanArgs): number {
  const result = scanProject(args.cwd, { showSuppressed: args.showSuppressed });

  // Write a fresh baseline of the current findings, then exit clean.
  if (args.updateBaseline) {
    const path = args.baseline ?? join(args.cwd, DEFAULT_BASELINE);
    const baseline = buildBaseline(result, args.cwd, new Date().toISOString());
    writeFileSync(path, serializeBaseline(baseline));
    process.stdout.write(
      `aegis: wrote ${baseline.entries.length} baseline entries to ${relative(args.cwd, path) || path}\n`,
    );
    return EXIT.CLEAN;
  }

  // Apply an explicit baseline, or an auto-detected one in cwd.
  const defaultPath = join(args.cwd, DEFAULT_BASELINE);
  const baselinePath = args.baseline ?? (existsSync(defaultPath) ? defaultPath : undefined);
  let displayed: ScanResult = result;
  let baselinedCount = 0;
  if (baselinePath !== undefined) {
    const applied = applyBaseline(
      result,
      parseBaseline(readFileSync(baselinePath, 'utf8')),
      args.cwd,
    );
    displayed = { ...result, findings: applied.findings };
    baselinedCount = applied.baselinedCount;
  }

  if (args.format === 'json') {
    process.stdout.write(`${toJson(displayed)}\n`);
  } else if (args.format === 'sarif') {
    process.stdout.write(`${toSarif(displayed)}\n`);
  } else {
    process.stdout.write(
      renderReport(displayed, {
        color: colorEnabled(args.noColor),
        plain: args.plain,
        cwd: args.cwd,
      }),
    );
    if (baselinedCount > 0) {
      process.stdout.write(`${baselinedCount} finding(s) muted by baseline.\n`);
    }
  }

  return exitCodeFor(displayed, { threshold: args.severity, strict: args.strict });
}
