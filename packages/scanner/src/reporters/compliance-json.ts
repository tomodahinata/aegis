import type { ComplianceReport } from '../compliance/report';

/** Machine-readable compliance evidence: the `ComplianceReport` verbatim, for GRC ingest. */
export function toComplianceJson(report: ComplianceReport): string {
  return JSON.stringify(report, null, 2);
}
