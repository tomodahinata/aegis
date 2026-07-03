/**
 * Turn a `ScanResult` into per-control compliance evidence — a pure, deterministic
 * transform with no I/O (the CLI does file output; renderers turn this into MD/JSON).
 *
 * Coverage semantics, chosen to never overclaim (see CLAUDE.md non-negotiable framing):
 *   - `gap`          — a mapped rule fired: concrete evidence a control is not met.
 *   - `covered`      — the scan ran and no mapped rule fired: evidence the *common*
 *                      technical gaps are ABSENT. Never "the control is effective".
 *   - `not-assessed` — nothing was scanned, so the control could not be evaluated.
 */

import { ALL_RULES } from '../rules';
import { ALL_SQL_RULES } from '../sql-rules';
import type { Finding, ScanResult } from '../types';
import {
  type ComplianceFramework,
  type ControlDef,
  frameworkControls,
  owaspCategory,
} from './controls';

export type ControlStatus = 'covered' | 'gap' | 'not-assessed';

/** Evidence for one control: its status and the findings (if any) behind that status. */
export interface ControlEvidence {
  readonly controlId: string;
  readonly title: string;
  readonly status: ControlStatus;
  /** Findings that make this control a gap; empty for covered/not-assessed. */
  readonly findings: readonly Finding[];
  /** What the status is based on, in one sentence. */
  readonly note: string;
}

export interface ComplianceReport {
  readonly framework: ComplianceFramework;
  readonly generatedFrom: {
    readonly scannedFiles: number;
    /** Number of Aegis rules that could contribute evidence. */
    readonly ruleCount: number;
  };
  readonly controls: readonly ControlEvidence[];
  readonly summary: Record<ControlStatus, number>;
  /** The fixed non-negotiable scope statement; always present in every rendering. */
  readonly scopeDisclaimer: string;
}

/**
 * The scope statement that must appear, verbatim and unedited, in every report. Deliberately
 * avoids the words "compliant"/"certified" — this artifact makes no such claim.
 */
export const SCOPE_DISCLAIMER =
  'This is machine-generated technical evidence for a subset of application-layer controls — ' +
  'not a certification, an attestation, or a substitute for an audit. Aegis reasons about the ' +
  'shape of your code and SQL, not the correctness of your business rules; a "no gaps detected" ' +
  'result means the common technical gaps are absent, never that a control is effective. This is ' +
  'a reference mapping — confirm every control association with your auditor.';

/** Total number of built-in rules that can contribute evidence to a report. */
const RULE_COUNT = ALL_RULES.length + ALL_SQL_RULES.length;

function noteFor(status: ControlStatus, gapCount: number): string {
  switch (status) {
    case 'gap':
      return `${gapCount} finding${gapCount === 1 ? '' : 's'} in scope indicate a gap for this control.`;
    case 'covered':
      return 'No Aegis-detectable gap in the scanned scope — evidence of absence of common gaps, not proof of control effectiveness.';
    case 'not-assessed':
      return 'Nothing was scanned, so this control could not be assessed.';
  }
}

function evidenceFor(
  control: ControlDef,
  findingsByCategory: ReadonlyMap<string, readonly Finding[]>,
  scannedFiles: number,
): ControlEvidence {
  const findings = control.owasp.flatMap((category) => findingsByCategory.get(category) ?? []);
  const status: ControlStatus =
    findings.length > 0 ? 'gap' : scannedFiles > 0 ? 'covered' : 'not-assessed';
  return {
    controlId: control.id,
    title: control.title,
    status,
    findings,
    note: noteFor(status, findings.length),
  };
}

/**
 * Build the compliance report for `framework`. Deterministic: the same `ScanResult`
 * always yields byte-identical output (controls in declaration order, findings in scan order).
 */
export function buildComplianceReport(
  result: ScanResult,
  framework: ComplianceFramework,
): ComplianceReport {
  const findingsByCategory = groupByOwaspCategory(result.findings);
  const controls = frameworkControls(framework).map((control) =>
    evidenceFor(control, findingsByCategory, result.scannedFiles),
  );
  const summary: Record<ControlStatus, number> = { covered: 0, gap: 0, 'not-assessed': 0 };
  for (const control of controls) {
    summary[control.status] += 1;
  }
  return {
    framework,
    generatedFrom: { scannedFiles: result.scannedFiles, ruleCount: RULE_COUNT },
    controls,
    summary,
    scopeDisclaimer: SCOPE_DISCLAIMER,
  };
}

function groupByOwaspCategory(
  findings: readonly Finding[],
): ReadonlyMap<string, readonly Finding[]> {
  const byCategory = new Map<string, Finding[]>();
  for (const finding of findings) {
    const category = owaspCategory(finding.owasp);
    if (category === undefined) {
      continue; // A finding with no OWASP category (e.g. a parse error) maps to no control.
    }
    const bucket = byCategory.get(category);
    if (bucket === undefined) {
      byCategory.set(category, [finding]);
    } else {
      bucket.push(finding);
    }
  }
  return byCategory;
}
