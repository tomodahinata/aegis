/**
 * The SDK-agnostic core of the Aegis MCP server: run a project scan and shape it into token-efficient,
 * deterministic, agent-safe payloads. Kept separate from the MCP glue (`server.ts`) so the real logic —
 * summarization, fingerprint lookup, secret redaction — is unit-testable without a transport (SRP).
 *
 * Reuses `scanProject` (the same orchestration `aegis scan`/`ci` use) and `fingerprintFinding` (the
 * baseline's line-independent identity), so a fingerprint an agent sees here is the SAME id everywhere.
 *
 * Intentionally stateless: every call re-runs `scanProject` from disk rather than caching a prior result,
 * so an explanation never goes stale against code the agent may have edited mid-session. The cost is a
 * repeated scan per `explain_finding` — acceptable for correctness; add an mtime-keyed cache only if a
 * large monorepo makes it a measured problem.
 */

import { relative } from 'node:path';
import { scanProject } from '@aegiskit/cli';
import {
  type Finding,
  type FindingExplanation,
  fingerprintFinding,
  SEVERITY_ORDER,
  type Severity,
  type Summary,
} from '@aegiskit/scanner';

/**
 * Rules whose `evidence` is (or is adjacent to) a real secret. Their evidence is redacted before it can
 * reach the agent's context — an MCP payload flows straight into an LLM, so a matched key must never ride
 * along. Fail-secure: match by prefix so a future `secrets/*` rule is redacted by default.
 */
const SECRET_BEARING =
  /^(?:secrets\/|env\/(?:public-secret|secret-in-client)|supabase\/service-role)/;

/** Default number of findings `scan_project` returns (highest-severity first). */
export const DEFAULT_SCAN_LIMIT = 20;
/** Hard cap on findings `scan_project` returns in one call — a token budget for the agent's context. */
export const MAX_SCAN_LIMIT = 200;

function safeEvidence(finding: Finding): string | undefined {
  if (finding.evidence === undefined) {
    return undefined;
  }
  return SECRET_BEARING.test(finding.ruleId) ? '[redacted]' : finding.evidence;
}

/** A compact finding row for the scan summary — enough to triage and to drill in via `explain_finding`. */
export interface FindingRow {
  readonly fingerprint: string;
  readonly ruleId: string;
  readonly severity: Severity;
  readonly confidence: string;
  /** `relative/path.sql:line`, or the HTTP target for a dynamic finding. */
  readonly location: string;
  readonly message: string;
}

export interface ScanSummary {
  readonly scannedFiles: number;
  readonly total: number;
  readonly counts: Summary;
  /** Highest-priority findings first, capped at the requested limit. */
  readonly findings: readonly FindingRow[];
  /** True when `total` exceeds the returned rows — the agent knows results were capped (no silent truncation). */
  readonly truncated: boolean;
}

/** Full detail for one finding, including the F1 explanation (why + advisory suggested policy). */
export interface FindingDetail extends FindingRow {
  readonly remediation: string;
  readonly docsUrl: string;
  readonly owasp?: string;
  readonly evidence?: string;
  readonly explanation?: FindingExplanation;
}

const CONFIDENCE_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };

// Total order for the summary: severity, then confidence (high→low; an unrecognized confidence sorts
// last via the `?? 9` sentinel), then file, then line.
function byPriority(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    (CONFIDENCE_RANK[a.confidence] ?? 9) - (CONFIDENCE_RANK[b.confidence] ?? 9) ||
    a.file.localeCompare(b.file) ||
    a.range.startLine - b.range.startLine
  );
}

function locationOf(finding: Finding, cwd: string): string {
  if (finding.target) {
    return `${finding.target.method} ${finding.target.path}`;
  }
  return `${relative(cwd, finding.file) || finding.file}:${finding.range.startLine}`;
}

function toRow(finding: Finding, cwd: string): FindingRow {
  return {
    fingerprint: fingerprintFinding(finding, cwd),
    ruleId: finding.ruleId,
    severity: finding.severity,
    confidence: finding.confidence,
    location: locationOf(finding, cwd),
    message: finding.message,
  };
}

/** Scan `cwd` and return a prioritized, capped summary safe to hand an agent. */
export function scanAndSummarize(cwd: string, limit = DEFAULT_SCAN_LIMIT): ScanSummary {
  const result = scanProject(cwd);
  const ordered = [...result.findings].sort(byPriority);
  return {
    scannedFiles: result.scannedFiles,
    total: result.findings.length,
    counts: result.summary,
    findings: ordered.slice(0, Math.max(0, limit)).map((finding) => toRow(finding, cwd)),
    truncated: result.findings.length > Math.max(0, limit),
  };
}

/** Scan `cwd` and return full detail for the finding with `fingerprint`, or `undefined` if none matches. */
export function explainFinding(cwd: string, fingerprint: string): FindingDetail | undefined {
  const result = scanProject(cwd);
  const finding = result.findings.find((f) => fingerprintFinding(f, cwd) === fingerprint);
  if (finding === undefined) {
    return undefined;
  }
  const evidence = safeEvidence(finding);
  return {
    ...toRow(finding, cwd),
    remediation: finding.remediation,
    docsUrl: finding.docsUrl,
    ...(finding.owasp !== undefined ? { owasp: finding.owasp } : {}),
    ...(evidence !== undefined ? { evidence } : {}),
    ...(finding.explanation !== undefined ? { explanation: finding.explanation } : {}),
  };
}
