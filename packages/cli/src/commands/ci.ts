import { writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { type Severity, toSarif } from '@aegiskit/scanner';
import { exitCodeFor } from '../exit';
import { scanProject } from '../project-scan';

export interface CiArgs {
  readonly cwd: string;
  readonly sarifOut?: string;
  readonly annotations: boolean;
  readonly severity: Severity;
  readonly strict: boolean;
}

export function runCi(args: CiArgs): number {
  const result = scanProject(args.cwd);

  if (args.sarifOut !== undefined) {
    writeFileSync(args.sarifOut, toSarif(result));
  }

  if (args.annotations) {
    for (const finding of result.findings) {
      const level =
        finding.severity === 'BLOCKER' || finding.severity === 'HIGH' ? 'error' : 'warning';
      const file = relative(args.cwd, finding.file);
      process.stdout.write(
        `::${level} file=${file},line=${finding.range.startLine},col=${finding.range.startColumn}::[${finding.ruleId}] ${finding.message}\n`,
      );
    }
  }

  const code = exitCodeFor(result, { threshold: args.severity, strict: args.strict });
  const s = result.summary;
  process.stdout.write(
    `aegis: ${result.findings.length} findings (BLOCKER ${s.BLOCKER}, HIGH ${s.HIGH}, MEDIUM ${s.MEDIUM}) — exit ${code}\n`,
  );
  return code;
}
