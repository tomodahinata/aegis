import { relative } from 'node:path';
import type { Finding, ScanResult, Severity } from '@aegiskit/scanner';
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

  if (result.findings.length === 0) {
    lines.push(c.green('✓ No security findings.'));
  }

  for (const finding of result.findings) {
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
