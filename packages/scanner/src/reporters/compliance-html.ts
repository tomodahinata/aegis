/**
 * Print-ready, fully self-contained HTML compliance evidence — the artifact you hand an auditor or attach
 * to a customer security questionnaire. Zero external assets (inline CSS, no scripts, no fonts, no images),
 * so it renders identically offline and prints cleanly; theme-aware (light/dark via `prefers-color-scheme`)
 * and WCAG 2.2 AA (semantic headings, a captioned table with `scope`d headers, status by text label — never
 * color alone, sufficient contrast in both themes).
 *
 * Like the Markdown/JSON reporters this is pure and deliberately never says "compliant"/"certified": it is
 * evidence for a subset of application-layer controls, not a certification (see `SCOPE_DISCLAIMER`). Every
 * dynamic value is HTML-escaped — a finding message or SQL snippet can contain `<`, `&`, quotes.
 */

import { FRAMEWORK_LABEL } from '../compliance/controls';
import type { RemediationSummary } from '../compliance/history';
import type { ComplianceReport, ControlEvidence, ControlStatus } from '../compliance/report';
import type { Finding } from '../types';

/** Escape the five HTML-significant characters so untrusted finding text cannot break out of the markup. */
function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STATUS_LABEL: Record<ControlStatus, string> = {
  covered: 'No gaps detected',
  gap: 'Gap(s) found',
  'not-assessed': 'Not assessed',
};

/**
 * A coarse technical-posture grade from the ratio of assessed controls with no detected gaps. Explicitly a
 * heuristic over Aegis-detectable gaps only — labelled as such in the UI so it is never read as an audit
 * outcome. `N/A` when nothing was assessed.
 */
function postureGrade(report: ComplianceReport): string {
  const assessed = report.summary.covered + report.summary.gap;
  if (assessed === 0) {
    return 'N/A';
  }
  const score = report.summary.covered / assessed;
  if (score >= 0.95) return 'A';
  if (score >= 0.85) return 'B';
  if (score >= 0.7) return 'C';
  if (score >= 0.5) return 'D';
  return 'F';
}

function controlRowHtml(control: ControlEvidence): string {
  const evidence =
    control.status === 'gap'
      ? `${control.findings.length} finding${control.findings.length === 1 ? '' : 's'}`
      : '—';
  // The status carries a text label AND a data attribute the CSS colours — meaning never rests on colour alone.
  return (
    `<tr>` +
    `<th scope="row"><code>${esc(control.controlId)}</code></th>` +
    `<td>${esc(control.title)}</td>` +
    `<td><span class="status" data-status="${control.status}">${STATUS_LABEL[control.status]}</span></td>` +
    `<td>${esc(evidence)}</td>` +
    `</tr>`
  );
}

function findingHtml(finding: Finding): string {
  const loc = `${esc(finding.file)}:${finding.range.startLine}`;
  const parts = [
    `<div class="finding">`,
    `<p class="finding-head"><code>${esc(finding.ruleId)}</code> <span class="sev">${esc(finding.severity)}</span> <span class="loc">${loc}</span></p>`,
    `<p>${esc(finding.message)}</p>`,
    `<p class="fix"><strong>Fix:</strong> ${esc(finding.remediation)}</p>`,
  ];
  if (finding.explanation?.suggestedFix) {
    parts.push(
      `<p class="fix"><strong>Suggested policy (advisory — review before applying):</strong></p>`,
      `<pre><code>${esc(finding.explanation.suggestedFix)}</code></pre>`,
    );
  }
  parts.push(`</div>`);
  return parts.join('');
}

function remediationHtml(remediation: RemediationSummary): string {
  const mttr =
    remediation.meanTimeToRemediateDays === null
      ? '—'
      : `${remediation.meanTimeToRemediateDays} day${remediation.meanTimeToRemediateDays === 1 ? '' : 's'}`;
  const oldest =
    remediation.oldestOpenAgeDays === null
      ? '—'
      : `${remediation.oldestOpenAgeDays} day${remediation.oldestOpenAgeDays === 1 ? '' : 's'}`;
  const rows = remediation.lifecycles
    .map(
      (life) =>
        `<tr>` +
        `<th scope="row"><code>${esc(life.fingerprint.slice(0, 12))}</code></th>` +
        `<td><span class="status" data-status="${life.status === 'open' ? 'gap' : 'covered'}">${life.status}</span></td>` +
        `<td>${esc(life.firstSeen)}</td>` +
        `<td>${life.status === 'resolved' ? esc(life.resolvedAt ?? '—') : '—'}</td>` +
        `<td>${life.ageDays}</td>` +
        `</tr>`,
    )
    .join('');
  return [
    `<section aria-labelledby="remediation-h">`,
    `<h2 id="remediation-h">Remediation tracking</h2>`,
    `<p class="muted">Lifecycle of Aegis-detectable findings across ${remediation.scans} scan${remediation.scans === 1 ? '' : 's'} — evidence that detected gaps are being closed (SOC 2 CC7.1 asks for remediation, not just detection).</p>`,
    `<ul class="stats">`,
    `<li><span class="stat-n">${remediation.open}</span> open</li>`,
    `<li><span class="stat-n">${remediation.resolved}</span> resolved</li>`,
    `<li><span class="stat-n">${esc(mttr)}</span> mean time to remediate</li>`,
    `<li><span class="stat-n">${esc(oldest)}</span> oldest open</li>`,
    `</ul>`,
    rows.length > 0
      ? `<table><caption>Finding lifecycles (oldest first)</caption><thead><tr><th scope="col">Finding</th><th scope="col">Status</th><th scope="col">First seen</th><th scope="col">Resolved</th><th scope="col">Age (days)</th></tr></thead><tbody>${rows}</tbody></table>`
      : '',
    `</section>`,
  ].join('');
}

const STYLE = `
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5a5a5a;--border:#d8d8d8;--card:#f6f6f7;--ok:#0a7d33;--gap:#b42318;--na:#6b6b6b;--accent:#1a4fd6}
@media(prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececed;--muted:#a2a2a6;--border:#2c2c30;--card:#1d1d20;--ok:#3ecf72;--gap:#ff6b5e;--na:#9a9a9e;--accent:#7aa2ff}}
*{box-sizing:border-box}
body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:60rem;margin-inline:auto}
h1{font-size:1.7rem;margin:0 0 .25rem}h2{font-size:1.25rem;margin:2rem 0 .75rem;border-top:1px solid var(--border);padding-top:1.25rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
.muted,.loc{color:var(--muted)}
.cover{display:flex;align-items:center;gap:1.25rem;margin-bottom:1rem}
.grade{display:grid;place-items:center;width:4.5rem;height:4.5rem;border-radius:.75rem;background:var(--card);border:1px solid var(--border);font-size:2rem;font-weight:700;color:var(--accent)}
.disclaimer{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:.85rem 1rem;color:var(--muted);font-size:.9rem}
ul.stats{list-style:none;display:flex;flex-wrap:wrap;gap:1.5rem;padding:0;margin:.5rem 0}
ul.stats .stat-n{display:block;font-size:1.5rem;font-weight:700}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.95rem}
caption{text-align:left;color:var(--muted);font-size:.85rem;margin-bottom:.35rem}
th,td{border:1px solid var(--border);padding:.45rem .6rem;text-align:left;vertical-align:top}
thead th{background:var(--card)}
.status{font-weight:600}
.status[data-status="covered"]{color:var(--ok)}
.status[data-status="gap"]{color:var(--gap)}
.status[data-status="not-assessed"]{color:var(--na)}
.finding{border:1px solid var(--border);border-left:3px solid var(--gap);border-radius:.4rem;padding:.5rem .85rem;margin:.6rem 0}
.finding-head .sev{color:var(--gap);font-weight:700}
.finding p{margin:.35rem 0}
pre{background:var(--card);border:1px solid var(--border);border-radius:.4rem;padding:.6rem .8rem;overflow-x:auto}
footer{margin-top:2.5rem;color:var(--muted);font-size:.82rem;border-top:1px solid var(--border);padding-top:1rem}
@media print{body{padding:0;max-width:none}h2{break-before:auto}.finding,table{break-inside:avoid}}
`;

/**
 * Render a self-contained HTML compliance-evidence document. Pass `remediation` (from the scan-history
 * ledger) to include the remediation-tracking section auditors ask for; omit it for a point-in-time report.
 */
export function toComplianceHtml(
  report: ComplianceReport,
  remediation?: RemediationSummary,
): string {
  const label = FRAMEWORK_LABEL[report.framework];
  const { scannedFiles, ruleCount } = report.generatedFrom;
  const s = report.summary;
  const gaps = report.controls.filter((control) => control.status === 'gap');

  const body = [
    `<header>`,
    `<div class="cover">`,
    `<div class="grade" role="img" aria-label="Aegis technical posture grade ${postureGrade(report)}">${postureGrade(report)}</div>`,
    `<div><h1>${esc(label)} — application-layer control evidence</h1>`,
    `<p class="muted">Aegis technical posture grade (detectable gaps only) · ${scannedFiles} files scanned · ${ruleCount} rules applied</p></div>`,
    `</div>`,
    `<p class="disclaimer">${esc(report.scopeDisclaimer)}</p>`,
    `</header>`,
    `<section aria-labelledby="coverage-h">`,
    `<h2 id="coverage-h">Control coverage</h2>`,
    `<ul class="stats"><li><span class="stat-n">${s.covered}</span> no gaps detected</li><li><span class="stat-n">${s.gap}</span> gaps found</li><li><span class="stat-n">${s['not-assessed']}</span> not assessed</li></ul>`,
    `<table><caption>Mapped controls for ${esc(label)}</caption><thead><tr><th scope="col">Control</th><th scope="col">Title</th><th scope="col">Status</th><th scope="col">Evidence</th></tr></thead><tbody>${report.controls.map(controlRowHtml).join('')}</tbody></table>`,
    `</section>`,
    remediation !== undefined ? remediationHtml(remediation) : '',
    gaps.length > 0
      ? `<section aria-labelledby="gaps-h"><h2 id="gaps-h">Gaps — findings to remediate</h2>${gaps
          .map(
            (control) =>
              `<h3>${esc(control.controlId)} — ${esc(control.title)}</h3>${control.findings.map(findingHtml).join('')}`,
          )
          .join('')}</section>`
      : '',
    `<footer>Generated by Aegis — machine-generated technical evidence, not a certification or a substitute for an audit. Confirm every control association with your auditor.</footer>`,
  ].join('');

  return (
    `<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">\n` +
    `<title>${esc(label)} — Aegis control evidence</title>\n<style>${STYLE}</style>\n</head>\n<body>\n${body}\n</body>\n</html>\n`
  );
}
