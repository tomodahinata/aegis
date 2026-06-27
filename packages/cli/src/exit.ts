import { meetsThreshold, type ScanResult, type Severity } from '@aegiskit/scanner';

/** Exit codes (stable, machine-readable): 0 clean · 1 findings · 2 usage error · 3 internal error. */
export const EXIT = {
  CLEAN: 0,
  FINDINGS: 1,
  USAGE: 2,
  INTERNAL: 3,
} as const;

export interface ExitOptions {
  /** Severity at/above which a finding can fail the run. */
  readonly threshold: Severity;
  /** When false (default), only `high`-confidence findings fail — the false-positive guard. */
  readonly strict: boolean;
}

/** 1 if any finding meets the threshold (and confidence gate), else 0. */
export function exitCodeFor(result: ScanResult, options: ExitOptions): number {
  const blocking = result.findings.filter(
    (finding) =>
      meetsThreshold(finding.severity, options.threshold) &&
      (options.strict || finding.confidence === 'high'),
  );
  return blocking.length > 0 ? EXIT.FINDINGS : EXIT.CLEAN;
}
