import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import {
  buildComplianceReport,
  type ComplianceFramework,
  computeRemediation,
  parseHistory,
  type RemediationSummary,
  SUPPORTED_FRAMEWORKS,
  serializeScanRecord,
  toComplianceHtml,
  toComplianceJson,
  toComplianceMd,
  toScanRecord,
} from '@aegiskit/scanner';
import { UsageError } from '../errors';
import { EXIT } from '../exit';
import { scanProject } from '../project-scan';

export type ReportFormat = 'md' | 'json' | 'html';

const REPORT_FORMATS: readonly string[] = ['md', 'json', 'html'];

/** Default location of the append-only scan-history ledger (relative to the scanned project root). */
export const DEFAULT_HISTORY_PATH = '.aegis/history.jsonl';

export interface ReportArgs {
  readonly cwd: string;
  readonly framework: ComplianceFramework;
  readonly format: ReportFormat;
  /** Write the report to this file instead of stdout. */
  readonly out?: string;
  /** Scan-history ledger path (default `.aegis/history.jsonl`); relative paths resolve against `cwd`. */
  readonly history?: string;
  /** Append this run's open findings to the history ledger before rendering (build remediation evidence). */
  readonly record?: boolean;
  /** Commit SHA to stamp on the recorded scan (CI passes `--commit ${{ github.sha }}`). Optional. */
  readonly commit?: string;
  /** Injected wall clock (ISO-8601) so the command is deterministic under test. Defaults to now. */
  readonly now?: string;
}

/**
 * Validate `--framework` (report-only, so it lives with the command rather than the shared
 * arg layer). Throws `UsageError`, which the entrypoint maps to EXIT.USAGE.
 */
export function parseFramework(value: string | undefined): ComplianceFramework {
  if (value === undefined) {
    throw new UsageError('report requires --framework <soc2|iso27001>');
  }
  if ((SUPPORTED_FRAMEWORKS as readonly string[]).includes(value)) {
    return value as ComplianceFramework;
  }
  throw new UsageError(`invalid --framework "${value}" (use soc2|iso27001)`);
}

/** Validate `--format` for `report` (md|json|html — distinct from scan's pretty|json|sarif). */
export function parseReportFormat(value: string | undefined): ReportFormat {
  if (value === undefined) {
    return 'md';
  }
  if (REPORT_FORMATS.includes(value)) {
    return value as ReportFormat;
  }
  throw new UsageError(`invalid --format "${value}" for report (use md|json|html)`);
}

function resolveHistoryPath(cwd: string, history: string | undefined): string {
  const path = history ?? DEFAULT_HISTORY_PATH;
  return isAbsolute(path) ? path : join(cwd, path);
}

/** Read the ledger and compute remediation stats, or `undefined` when there is no usable history yet. */
function loadRemediation(historyPath: string, now: string): RemediationSummary | undefined {
  if (!existsSync(historyPath)) {
    return undefined;
  }
  try {
    const summary = computeRemediation(parseHistory(readFileSync(historyPath, 'utf8')), now);
    // Remediation is an OVER-TIME story: one scan is a point, not a trend, so require ≥2 scans before
    // rendering the section (matches history.ts's "a single scan is not evidence").
    return summary.scans > 1 ? summary : undefined;
  } catch {
    // Advisory evidence: an unreadable ledger degrades to a point-in-time report, never a crash.
    return undefined;
  }
}

/**
 * `aegis report` — map a scan into SOC 2 / ISO 27001 control evidence. A report is *evidence*, not a gate,
 * so it always exits clean; gating stays with `scan`/`ci`. With `--record` it also appends this run to the
 * scan-history ledger, and (for `--format html`) renders the remediation-over-time section auditors ask for.
 */
export function runReport(args: ReportArgs): number {
  const now = args.now ?? new Date().toISOString();
  const result = scanProject(args.cwd);
  const historyPath = resolveHistoryPath(args.cwd, args.history);

  if (args.record === true) {
    try {
      const record = toScanRecord(result, args.cwd, now, args.commit);
      mkdirSync(dirname(historyPath), { recursive: true });
      appendFileSync(historyPath, `${serializeScanRecord(record)}\n`);
    } catch (error) {
      // The ledger is advisory remediation evidence — a write failure (unwritable dir, bad --history path)
      // must not sink the report itself, which is the primary deliverable. Warn on stderr and continue.
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(
        `aegis: could not record scan history to ${historyPath}: ${message} (continuing)\n`,
      );
    }
  }

  const report = buildComplianceReport(result, args.framework);
  let rendered: string;
  if (args.format === 'html') {
    // Remediation tracking is HTML-only (the print-ready evidence packet); md/json stay point-in-time.
    rendered = toComplianceHtml(report, loadRemediation(historyPath, now));
  } else if (args.format === 'json') {
    rendered = toComplianceJson(report);
  } else {
    rendered = toComplianceMd(report);
  }

  if (args.out !== undefined) {
    // HTML is already a complete document; md/json get a trailing newline for clean concatenation.
    writeFileSync(args.out, args.format === 'html' ? rendered : `${rendered}\n`);
    process.stdout.write(
      `aegis: wrote ${args.framework} evidence to ${relative(args.cwd, args.out) || args.out}\n`,
    );
  } else {
    process.stdout.write(args.format === 'html' ? rendered : `${rendered}\n`);
  }

  return EXIT.CLEAN;
}
