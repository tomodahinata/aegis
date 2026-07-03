import { writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import {
  buildComplianceReport,
  type ComplianceFramework,
  SUPPORTED_FRAMEWORKS,
  toComplianceJson,
  toComplianceMd,
} from '@aegiskit/scanner';
import { UsageError } from '../errors';
import { EXIT } from '../exit';
import { scanProject } from '../project-scan';

export type ReportFormat = 'md' | 'json';

const REPORT_FORMATS: readonly string[] = ['md', 'json'];

export interface ReportArgs {
  readonly cwd: string;
  readonly framework: ComplianceFramework;
  readonly format: ReportFormat;
  /** Write the report to this file instead of stdout. */
  readonly out?: string;
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

/** Validate `--format` for `report` (md|json — distinct from scan's pretty|json|sarif). */
export function parseReportFormat(value: string | undefined): ReportFormat {
  if (value === undefined) {
    return 'md';
  }
  if (REPORT_FORMATS.includes(value)) {
    return value as ReportFormat;
  }
  throw new UsageError(`invalid --format "${value}" for report (use md|json)`);
}

/**
 * `aegis report` — map a scan into SOC 2 / ISO 27001 control evidence. A report is
 * *evidence*, not a gate, so it always exits clean; gating stays with `scan`/`ci`.
 */
export function runReport(args: ReportArgs): number {
  const result = scanProject(args.cwd);
  const report = buildComplianceReport(result, args.framework);
  const rendered = args.format === 'json' ? toComplianceJson(report) : toComplianceMd(report);

  if (args.out !== undefined) {
    writeFileSync(args.out, `${rendered}\n`);
    process.stdout.write(
      `aegis: wrote ${args.framework} evidence to ${relative(args.cwd, args.out) || args.out}\n`,
    );
  } else {
    process.stdout.write(`${rendered}\n`);
  }

  return EXIT.CLEAN;
}
