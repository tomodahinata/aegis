import type { Finding, ScanResult } from '@aegiskit/scanner';
import { describe, expect, it } from 'vitest';
import { renderReport } from './pretty';

const aiFinding: Finding = {
  ruleId: 'ratelimit/missing-on-ai-route',
  severity: 'HIGH',
  confidence: 'high',
  message: 'no rate limit',
  file: '/project/app/api/ai/route.ts',
  range: { startLine: 5, startColumn: 3, endLine: 5, endColumn: 9 },
  docsUrl: 'https://github.com/tomodahinata/aegis/rules/ratelimit-missing-on-ai-route',
  remediation: 'add a limiter',
  owasp: 'A04:2021',
};

const result: ScanResult = {
  findings: [aiFinding],
  passes: [{ ruleId: 'csrf/missing-origin-check', title: 't', detail: 'Route uses bearer auth.' }],
  summary: { BLOCKER: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
  scannedFiles: 3,
  suppressedCount: 0,
  durationMs: 1,
};

// Every ANSI color sequence begins with the ESC byte; its absence proves color is off.
const ESC = String.fromCodePoint(0x1b);

describe('renderReport', () => {
  it('labels severity with a text label AND a glyph (never color alone)', () => {
    const out = renderReport(result, { color: false, plain: false });
    expect(out).toContain('HIGH ▲');
    expect(out).toContain('ratelimit/missing-on-ai-route');
    expect(out).toContain('→ Fix: add a limiter');
    expect(out).toContain('OWASP: A04:2021');
    expect(out).toContain('Summary');
  });

  it('emits no ANSI escapes when color is disabled', () => {
    expect(renderReport(result, { color: false, plain: false }).includes(ESC)).toBe(false);
  });

  it('plain mode is label-prefixed and glyph-free (screen-reader friendly)', () => {
    const out = renderReport(result, { color: false, plain: true });
    expect(out).toContain('Severity: HIGH');
    expect(out).toContain('Fix: add a limiter');
    expect(out).not.toContain('▲');
  });

  const traced: ScanResult = {
    ...result,
    findings: [
      {
        ...aiFinding,
        ruleId: 'injection/sql',
        severity: 'BLOCKER',
        trace: [
          {
            kind: 'source',
            label: 'tainted by request body',
            range: { startLine: 4, startColumn: 18, endLine: 4, endColumn: 30 },
          },
          {
            kind: 'propagation',
            label: 'concatenated into a string',
            range: { startLine: 7, startColumn: 17, endLine: 7, endColumn: 40 },
          },
          {
            kind: 'sink',
            label: 'reaches supabase.rpc()',
            range: { startLine: 9, startColumn: 10, endLine: 9, endColumn: 40 },
          },
        ],
      },
    ],
  };

  it('renders an ordered, accessible dataflow trace (rich mode)', () => {
    const out = renderReport(traced, { color: false, plain: false });
    expect(out).toContain('Dataflow (source → sink):');
    expect(out).toContain('1. [source]');
    expect(out).toContain('3. [sink]');
    expect(out).toContain('tainted by request body');
  });

  it('announces "step N of M" in plain mode (screen-reader friendly)', () => {
    const out = renderReport(traced, { color: false, plain: true });
    expect(out).toContain('Trace step 1 of 3: source - tainted by request body');
    expect(out).toContain('Trace step 3 of 3: sink');
  });

  it('renders no trace block for a finding without a trace (backward compatible)', () => {
    expect(renderReport(result, { color: false, plain: false })).not.toContain('Dataflow');
  });

  const dynamicResult: ScanResult = {
    ...result,
    findings: [
      {
        ...aiFinding,
        ruleId: 'dast/security-headers',
        file: 'http://localhost:3000/api/x',
        target: {
          kind: 'http-request',
          method: 'GET',
          path: '/api/x',
          response: { status: 200, headers: { 'content-type': 'text/html' } },
        },
      },
    ],
  };

  it('locates a dynamic finding by METHOD/path with an HTTP evidence block', () => {
    const out = renderReport(dynamicResult, { color: false, plain: false });
    expect(out).toContain('GET /api/x  (HTTP 200)');
    expect(out).toContain('Response: HTTP 200');
  });

  it('uses a "Target:" label for dynamic findings in plain mode', () => {
    const out = renderReport(dynamicResult, { color: false, plain: true });
    expect(out).toContain('Target: GET /api/x');
  });

  it('reports a clean result when there are no findings', () => {
    const clean: ScanResult = {
      findings: [],
      passes: [],
      summary: { BLOCKER: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      scannedFiles: 0,
      suppressedCount: 0,
      durationMs: 0,
    };
    const out = renderReport(clean, { color: false, plain: false });
    expect(out).toContain('No security findings');
    expect(out).not.toContain('Fix first'); // no headline when there is nothing to fix
  });
});

describe('renderReport — advisory suggested policy (RLS explainability)', () => {
  const explained: ScanResult = {
    ...result,
    findings: [
      {
        ...aiFinding,
        ruleId: 'rls/policy-not-owner-scoped',
        explanation: {
          kind: 'authenticated-only',
          detail: 'proves a session exists but never binds the row to the caller',
          suggestedFix:
            'create policy "notes_select_owner" on public.notes\n' +
            '  for select to authenticated\n' +
            '  using (auth.uid() = user_id);',
        },
      },
    ],
  };

  it('renders the advisory suggested policy after the fix, labelled advisory (rich mode)', () => {
    const out = renderReport(explained, { color: false, plain: false });
    expect(out).toContain('→ Suggested policy (advisory — review before applying):');
    expect(out).toContain('using (auth.uid() = user_id);');
    // Ordered after the Fix line and before the Docs line.
    expect(out.indexOf('→ Fix:')).toBeLessThan(out.indexOf('→ Suggested policy'));
    expect(out.indexOf('→ Suggested policy')).toBeLessThan(out.indexOf('Docs:'));
  });

  it('renders the suggested policy as a labelled block for screen readers (plain mode)', () => {
    const out = renderReport(explained, { color: false, plain: true });
    expect(out).toContain('Suggested fix (advisory — review before applying):');
    expect(out).toContain('create policy "notes_select_owner" on public.notes');
    expect(out).not.toContain('▲');
  });

  it('omits the suggested-policy block for a finding without an explanation (backward compatible)', () => {
    expect(renderReport(result, { color: false, plain: false })).not.toContain('Suggested policy');
  });
});

describe('renderReport — prioritized headline & ordering', () => {
  const mk = (
    ruleId: string,
    severity: Finding['severity'],
    confidence: Finding['confidence'] = 'high',
    line = 1,
  ): Finding => ({
    ...aiFinding,
    ruleId,
    severity,
    confidence,
    range: { startLine: line, startColumn: 1, endLine: line, endColumn: 2 },
  });

  it('renders a rich headline with counts, severity breakdown, and "Fix first"', () => {
    const out = renderReport(result, { color: false, plain: false });
    expect(out).toContain('Aegis');
    expect(out).toContain('1 finding across 1 file');
    expect(out).toContain('1 high');
    expect(out).toContain('Fix first: ratelimit/missing-on-ai-route');
  });

  it('orders findings by severity (BLOCKER → HIGH → MEDIUM) regardless of scan order', () => {
    const mixed: ScanResult = {
      ...result,
      findings: [mk('r-med', 'MEDIUM'), mk('r-block', 'BLOCKER'), mk('r-high', 'HIGH')],
      summary: { BLOCKER: 1, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
    };
    const out = renderReport(mixed, { color: false, plain: false });
    expect(out.indexOf('r-block')).toBeLessThan(out.indexOf('r-high'));
    expect(out.indexOf('r-high')).toBeLessThan(out.indexOf('r-med'));
    expect(out).toContain('Fix first: r-block');
  });

  it('breaks ties below severity+confidence by file, then column, then ruleId', () => {
    // All four share severity HIGH, confidence high, and startLine 1, so only the
    // file → startColumn → ruleId tie-breakers decide order.
    const at = (file: string, startColumn: number, ruleId: string): Finding => ({
      ...aiFinding,
      ruleId,
      severity: 'HIGH',
      confidence: 'high',
      file,
      range: { startLine: 1, startColumn, endLine: 1, endColumn: startColumn + 1 },
    });
    const findings = [
      at('/p/b.ts', 9, 'z/late'),
      at('/p/b.ts', 9, 'z/early'),
      at('/p/b.ts', 3, 'm/mid'),
      at('/p/a.ts', 50, 'a/first'),
    ];
    const tied: ScanResult = {
      ...result,
      findings,
      summary: { BLOCKER: 0, HIGH: 4, MEDIUM: 0, LOW: 0, INFO: 0 },
    };
    const out = renderReport(tied, { color: false, plain: false });
    // file 'a.ts' before 'b.ts'; lower startColumn first; then ruleId lexical order.
    expect(out.indexOf('a/first')).toBeLessThan(out.indexOf('m/mid'));
    expect(out.indexOf('m/mid')).toBeLessThan(out.indexOf('z/early'));
    expect(out.indexOf('z/early')).toBeLessThan(out.indexOf('z/late'));
  });

  it('breaks severity ties by confidence (high before medium)', () => {
    const tied: ScanResult = {
      ...result,
      findings: [mk('r-medium-conf', 'HIGH', 'medium'), mk('r-high-conf', 'HIGH', 'high')],
      summary: { BLOCKER: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
    };
    const out = renderReport(tied, { color: false, plain: false });
    expect(out.indexOf('r-high-conf')).toBeLessThan(out.indexOf('r-medium-conf'));
  });

  it('does not mutate the input findings array (display-only sort)', () => {
    const input = [mk('a', 'MEDIUM'), mk('b', 'BLOCKER')];
    const res: ScanResult = {
      ...result,
      findings: input,
      summary: { BLOCKER: 1, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 },
    };
    renderReport(res, { color: false, plain: false });
    expect(input.map((f) => f.ruleId)).toEqual(['a', 'b']);
  });

  it('renders a glyph-free, label-prefixed headline in plain mode', () => {
    const out = renderReport(result, { color: false, plain: true });
    expect(out).toContain('Summary: 1 finding across 1 file');
    expect(out).toContain('Severity counts: BLOCKER 0, HIGH 1, MEDIUM 0, LOW 0, INFO 0');
    expect(out).toContain('Fix first: ratelimit/missing-on-ai-route, severity HIGH');
  });

  it('emits no ANSI escapes for a multi-finding report when color is disabled', () => {
    const mixed: ScanResult = {
      ...result,
      findings: [mk('r-med', 'MEDIUM'), mk('r-block', 'BLOCKER')],
      summary: { BLOCKER: 1, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 },
    };
    expect(renderReport(mixed, { color: false, plain: false }).includes(ESC)).toBe(false);
  });
});
