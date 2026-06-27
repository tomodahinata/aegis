/**
 * Adapt dynamic findings into the shared scanner `Finding`/`ScanResult` shapes, so DAST output flows
 * through the existing reporters (`toSarif`, `toJson`, the CLI `renderReport`) unchanged — one output
 * pipeline, no DAST-specific format (DRY).
 */

import { emptySummary, type Finding, type ScanResult, type Summary } from '@aegiskit/scanner';
import type { DynamicFinding } from './probes/types';

// A dynamic finding has no source line; SARIF/pretty branch on `target` and ignore this.
const SYNTHETIC_RANGE = { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 } as const;

/** Convert a `DynamicFinding` to the shared `Finding` (URL as `file`, the HTTP exchange as `target`). */
export function toFinding(finding: DynamicFinding, origin: string): Finding {
  return {
    ruleId: finding.probeId,
    severity: finding.severity,
    confidence: finding.confidence,
    message: finding.message,
    // Canonical URL (route pattern, no volatile marker) → stable fingerprint + correlation key.
    file: `${origin.replace(/\/$/, '')}${finding.routePath}`,
    range: SYNTHETIC_RANGE,
    docsUrl: finding.docsUrl,
    remediation: finding.remediation,
    owasp: finding.owasp,
    evidence: finding.evidence,
    target: finding.target,
  };
}

export function summarize(findings: readonly Finding[]): Summary {
  const summary = emptySummary();
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

/** Wrap findings as a `ScanResult` so the existing reporters render them with zero new code. */
export function toScanResult(findings: readonly Finding[], durationMs: number): ScanResult {
  return {
    findings,
    passes: [],
    summary: summarize(findings),
    scannedFiles: 0,
    durationMs,
    suppressedCount: 0,
  };
}
