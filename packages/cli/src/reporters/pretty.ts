import { relative } from 'node:path';
import {
  type Confidence,
  type Finding,
  type ScanResult,
  SEVERITY_ORDER,
  type Severity,
  type Summary,
} from '@aegiskit/scanner';
import { type Palette, palette } from '../internal/colors';

interface SeverityStyle {
  readonly label: string;
  readonly symbol: string;
  readonly color: keyof Palette;
}

// Every severity is distinguished by a TEXT label AND an ASCII glyph — never color alone — so
// meaning survives in grayscale, for colorblind users, and through screen readers.
const STYLES: Record<Severity, SeverityStyle> = {
  BLOCKER: { label: 'BLOCKER', symbol: '✖', color: 'red' },
  HIGH: { label: 'HIGH', symbol: '▲', color: 'red' },
  MEDIUM: { label: 'MEDIUM', symbol: '▲', color: 'yellow' },
  LOW: { label: 'LOW', symbol: '•', color: 'blue' },
  INFO: { label: 'INFO', symbol: '◦', color: 'gray' },
};

export interface RenderOptions {
  readonly color: boolean;
  /** Screen-reader-friendly: label-prefixed fields, no glyphs or box-drawing. */
  readonly plain: boolean;
  readonly cwd?: string;
}

// Display order, most urgent first. `SEVERITY_ORDER` is the scanner's canonical ranking, reused here
// as the priority ranks for the sort below. The scanner exposes no confidence order, so it stays local.
const CONFIDENCE_ORDER: readonly Confidence[] = ['high', 'medium', 'low'];

function rankOf<T>(order: readonly T[], value: T): number {
  return order.indexOf(value);
}

/**
 * Total order so the most important finding renders first and output is byte-stable for snapshots:
 * severity → confidence → file → line → column → ruleId. Sorting is display-only and runs on a COPY —
 * the engine's canonical `result.findings` order (consumed by JSON/SARIF/baseline) is never mutated.
 */
function byPriority(a: Finding, b: Finding): number {
  return (
    rankOf(SEVERITY_ORDER, a.severity) - rankOf(SEVERITY_ORDER, b.severity) ||
    rankOf(CONFIDENCE_ORDER, a.confidence) - rankOf(CONFIDENCE_ORDER, b.confidence) ||
    a.file.localeCompare(b.file) ||
    a.range.startLine - b.range.startLine ||
    a.range.startColumn - b.range.startColumn ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/** Compact "fix first" location: a source `file:line`, or the HTTP target for a dynamic finding. */
function headlineLocation(finding: Finding, rel: (file: string) => string): string {
  return finding.target
    ? `${finding.target.method} ${finding.target.path}`
    : `${rel(finding.file)}:${finding.range.startLine}`;
}

/**
 * A prioritized headline: total count, file count, severity breakdown, and the single highest-priority
 * finding to "fix first" — the actionable next step. Carries meaning by label + glyph (never color
 * alone); the plain branch is glyph-free and label-prefixed for screen readers. Assumes `ordered` is
 * non-empty (only called when there are findings).
 */
function appendHeadline(
  lines: string[],
  ordered: readonly Finding[],
  summary: Summary,
  c: Palette,
  rel: (file: string) => string,
  plain: boolean,
): void {
  const first = ordered[0];
  if (!first) {
    return;
  }
  const files = new Set(ordered.map((finding) => finding.file)).size;
  const count = `${ordered.length} finding${ordered.length === 1 ? '' : 's'} across ${files} file${files === 1 ? '' : 's'}`;
  const where = headlineLocation(first, rel);

  if (plain) {
    lines.push(`Summary: ${count}`);
    lines.push(`Severity counts: ${SEVERITY_ORDER.map((s) => `${s} ${summary[s]}`).join(', ')}`);
    lines.push(`Fix first: ${first.ruleId}, severity ${first.severity}, ${where}`);
    lines.push('');
    return;
  }

  const breakdown = SEVERITY_ORDER.filter((s) => summary[s] > 0)
    .map((s) => `${summary[s]} ${s.toLowerCase()}`)
    .join(', ');
  const style = STYLES[first.severity];
  lines.push(`${c.bold('Aegis')}  ${count}  ·  ${breakdown}`);
  lines.push(
    `${c.dim('Fix first:')} ${c.bold(first.ruleId)}  ${c[style.color](`(${style.label} ${style.symbol})`)}  ${c.dim(where)}`,
  );
  lines.push('');
}

/** Longest `[kind]` tag, so step locations align in a column — alignment is a non-color visual cue. */
const KIND_WIDTH = '[propagation]'.length;

/**
 * Render a finding's source→sink dataflow path. Meaning is carried by the ordinal, the bracketed kind
 * tag, and indentation — never by color alone — so it survives grayscale and screen readers. In plain
 * mode every step announces "step N of M" so a screen-reader user hears the path length and position.
 */
function renderTrace(
  finding: Finding,
  c: Palette,
  loc: (line: number, column: number) => string,
  plain: boolean,
): string[] {
  const trace = finding.trace;
  if (!trace?.length) {
    return [];
  }
  const out: string[] = [];
  if (plain) {
    trace.forEach((stepItem, i) => {
      out.push(
        `Trace step ${i + 1} of ${trace.length}: ${stepItem.kind} - ${stepItem.label} - ${loc(stepItem.range.startLine, stepItem.range.startColumn)}`,
      );
    });
    return out;
  }
  out.push(`  ${c.dim('Dataflow (source → sink):')}`);
  trace.forEach((stepItem, i) => {
    const tag = `[${stepItem.kind}]`.padEnd(KIND_WIDTH);
    const where = c.dim(loc(stepItem.range.startLine, stepItem.range.startColumn));
    out.push(`    ${i + 1}. ${tag} ${stepItem.label}  ${where}`);
  });
  return out;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * Render the HTTP exchange that confirmed a dynamic (DAST) finding. Meaning is carried by the
 * `Request:`/`Response:` labels, never by color alone (WCAG); plain mode is label-prefixed.
 */
function renderHttpEvidence(finding: Finding, c: Palette, plain: boolean): string[] {
  const target = finding.target;
  if (!target) {
    return [];
  }
  const reqBody = target.request?.body ? `  body: ${clip(target.request.body, 100)}` : '';
  const status = target.response ? `HTTP ${target.response.status}` : '(no response)';
  const contentType = target.response?.headers?.['content-type'];
  const ctype = contentType ? `  ${contentType}` : '';
  if (plain) {
    return [`Request: ${target.method} ${target.path}${reqBody}`, `Response: ${status}${ctype}`];
  }
  return [
    `  ${c.dim('Request: ')}${target.method} ${target.path}${reqBody}`,
    `  ${c.dim('Response:')} ${status}${c.dim(ctype)}`,
  ];
}

export function renderReport(result: ScanResult, options: RenderOptions): string {
  const c = palette(options.color);
  const rel = (file: string): string => (options.cwd ? relative(options.cwd, file) : file);
  const lines: string[] = [];
  // Display-only ordering on a COPY — never mutate the engine's canonical finding order.
  const ordered = [...result.findings].sort(byPriority);

  if (ordered.length === 0) {
    lines.push(c.green('✓ No security findings.'));
  } else {
    appendHeadline(lines, ordered, result.summary, c, rel, options.plain);
  }

  for (const finding of ordered) {
    const style = STYLES[finding.severity];
    // A dynamic (DAST) finding is located by its HTTP request, not a source line.
    const location = finding.target
      ? `${finding.target.method} ${finding.target.path}${
          finding.target.response ? `  (HTTP ${finding.target.response.status})` : ''
        }`
      : `${rel(finding.file)}:${finding.range.startLine}:${finding.range.startColumn}`;
    const owasp = finding.owasp ? `  OWASP: ${finding.owasp}` : '';

    const traceLoc = (line: number, column: number): string =>
      `${rel(finding.file)}:${line}:${column}`;

    if (options.plain) {
      lines.push(
        `Severity: ${style.label} | Rule: ${finding.ruleId} | Confidence: ${finding.confidence}`,
      );
      lines.push(`${finding.target ? 'Target' : 'File'}: ${location}`);
      lines.push(`Issue: ${finding.message}`);
      lines.push(...renderTrace(finding, c, traceLoc, true));
      lines.push(...renderHttpEvidence(finding, c, true));
      lines.push(`Fix: ${finding.remediation}`);
      lines.push(`Docs: ${finding.docsUrl}${owasp}`);
      lines.push('');
    } else {
      const tag = c[style.color](`${style.label} ${style.symbol}`);
      lines.push(
        `${tag} ${c.bold(finding.ruleId)} ${c.dim(`[confidence: ${finding.confidence}]`)}`,
      );
      lines.push(`  ${c.dim(location)}`);
      lines.push(`  ${finding.message}`);
      lines.push(...renderTrace(finding, c, traceLoc, false));
      lines.push(...renderHttpEvidence(finding, c, false));
      lines.push(`  ${c.cyan('→ Fix:')} ${finding.remediation}`);
      lines.push(`  ${c.dim(`Docs: ${finding.docsUrl}${owasp}`)}`);
      lines.push('');
    }
  }

  const passDetails = [...new Set(result.passes.map((pass) => pass.detail))];
  for (const detail of passDetails) {
    lines.push(`${c.green('PASS ✓')} ${c.dim(detail)}`);
  }
  if (passDetails.length > 0) {
    lines.push('');
  }

  const s = result.summary;
  const suppressed = result.suppressedCount > 0 ? `, ${result.suppressedCount} suppressed` : '';
  lines.push(
    `${c.bold('Summary')}  BLOCKER ${s.BLOCKER}  HIGH ${s.HIGH}  MEDIUM ${s.MEDIUM}  LOW ${s.LOW}  INFO ${s.INFO}   ${c.dim(`(scanned ${result.scannedFiles} files${suppressed})`)}`,
  );

  return `${lines.join('\n')}\n`;
}
