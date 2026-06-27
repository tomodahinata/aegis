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
  docsUrl: 'https://aegis.dev/rules/ratelimit-missing-on-ai-route',
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
    expect(renderReport(clean, { color: false, plain: false })).toContain('No security findings');
  });
});
