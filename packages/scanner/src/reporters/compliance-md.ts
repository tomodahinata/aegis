import { FRAMEWORK_LABEL } from '../compliance/controls';
import type { ComplianceReport, ControlEvidence, ControlStatus } from '../compliance/report';
import type { Finding } from '../types';

/**
 * Print-ready Markdown compliance evidence — the artifact you hand to an auditor or paste
 * into a customer security questionnaire. Pure and zero-dependency (mirrors `toJson`/`toSarif`).
 * Deliberately never uses the words "compliant"/"certified": this is evidence, not a claim.
 */
export function toComplianceMd(report: ComplianceReport): string {
  const label = FRAMEWORK_LABEL[report.framework];
  const { scannedFiles, ruleCount } = report.generatedFrom;
  const s = report.summary;

  const lines: string[] = [
    `# ${label} — application-layer control evidence`,
    '',
    `> ${report.scopeDisclaimer}`,
    '',
    `**Scanned files:** ${scannedFiles} · **Rules applied:** ${ruleCount} · ` +
      `**No gaps detected:** ${s.covered} · **Gaps found:** ${s.gap} · **Not assessed:** ${s['not-assessed']}`,
    '',
    '## Control coverage',
    '',
    '| Control | Title | Status | Evidence |',
    '| --- | --- | --- | --- |',
    ...report.controls.map(controlRow),
    '',
  ];

  const gaps = report.controls.filter((control) => control.status === 'gap');
  if (gaps.length > 0) {
    lines.push('## Gaps — findings to remediate', '');
    for (const control of gaps) {
      lines.push(`### ${control.controlId} — ${control.title}`, '');
      for (const finding of control.findings) {
        lines.push(...findingLines(finding));
      }
    }
  }

  return `${lines.join('\n').trimEnd()}\n`;
}

const STATUS_LABEL: Record<ControlStatus, string> = {
  covered: 'No gaps detected',
  gap: 'Gap(s) found',
  'not-assessed': 'Not assessed',
};

function controlRow(control: ControlEvidence): string {
  const evidence =
    control.status === 'gap'
      ? `${control.findings.length} finding${control.findings.length === 1 ? '' : 's'}`
      : '—';
  return `| ${control.controlId} | ${control.title} | ${STATUS_LABEL[control.status]} | ${evidence} |`;
}

function findingLines(finding: Finding): string[] {
  return [
    `- **${finding.ruleId}** (${finding.severity}) — ${finding.file}:${finding.range.startLine}`,
    `  - ${finding.message}`,
    `  - Fix: ${finding.remediation}`,
    '',
  ];
}
