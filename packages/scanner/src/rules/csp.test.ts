import { describe, expect, it } from 'vitest';
import { scan } from '../engine';
import type { Confidence, Severity } from '../types';

/** csp/unsafe-inline findings for a synthetic source, newest rule plumbing, no disk I/O. */
function cspFindings(source: string) {
  return scan({ files: ['/policy.ts'], readFile: () => source }).findings.filter(
    (f) => f.ruleId === 'csp/unsafe-inline',
  );
}

function grade(source: string): ReadonlyArray<readonly [Severity, Confidence]> {
  return cspFindings(source).map((f) => [f.severity, f.confidence] as const);
}

describe('csp/unsafe-inline — context-aware severity', () => {
  it("scores script-src 'unsafe-inline' HIGH / high (real XSS bypass)", () => {
    expect(grade(`const v = "script-src 'self' 'unsafe-inline'";`)).toEqual([['HIGH', 'high']]);
  });

  it("scores style-src 'unsafe-inline' MEDIUM / high (no script execution)", () => {
    expect(grade(`const v = "style-src 'self' 'unsafe-inline'";`)).toEqual([['MEDIUM', 'high']]);
  });

  it("scores script-src 'unsafe-eval' HIGH / medium (needs an eval sink)", () => {
    expect(grade(`const v = "script-src 'self' 'unsafe-eval'";`)).toEqual([['HIGH', 'medium']]);
  });

  it("scores style-src 'unsafe-eval' LOW / low (inert for styles)", () => {
    expect(grade(`const v = "style-src 'self' 'unsafe-eval'";`)).toEqual([['LOW', 'low']]);
  });

  it('scores an array-split fragment fail-secure as HIGH (worst case)', () => {
    const src = `const v = ["script-src 'self'", "'unsafe-inline'"].join(' ');`;
    expect(grade(src)).toEqual([['HIGH', 'high']]);
  });

  it('emits BOTH a script (HIGH) and a style (MEDIUM) finding from one policy string', () => {
    const src = `const v = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'";`;
    expect(grade(src)).toEqual([
      ['HIGH', 'high'],
      ['MEDIUM', 'high'],
    ]);
  });

  it('does NOT flag a keyword under an inert directive (img-src) — false positive eliminated', () => {
    const src = `const v = "default-src 'self'; script-src 'self'; img-src 'unsafe-inline'";`;
    expect(cspFindings(src)).toHaveLength(0);
  });

  it('scores a dev-only unsafe-eval in a template literal as script-src (HIGH / medium)', () => {
    // Mirrors the real SpoLove builder: 'unsafe-eval' lives in a backtick template's script-src.
    const src = "const v = `script-src 'self' 'nonce-abc' 'strict-dynamic' 'unsafe-eval'`;";
    expect(grade(src)).toEqual([['HIGH', 'medium']]);
  });

  it('carries directive-qualified evidence so script vs style stay distinguishable', () => {
    const f = cspFindings(`const v = "style-src 'self' 'unsafe-inline'";`)[0];
    expect(f?.evidence).toBe("style-src 'unsafe-inline'");
  });

  it('suppresses an unsafe directive gated to development only (the SpoLove `isDev ? …` pattern)', () => {
    const src =
      "const isDev = true; const v = isDev ? `script-src 'self' 'unsafe-eval'` : `script-src 'self'`;";
    expect(cspFindings(src)).toHaveLength(0);
  });

  it('does NOT over-suppress: an unsafe directive in the PRODUCTION branch of a NODE_ENV check still flags', () => {
    const src =
      "const v = process.env.NODE_ENV === 'production' ? `script-src 'unsafe-inline'` : `script-src 'self'`;";
    expect(grade(src)).toEqual([['HIGH', 'high']]);
  });
});
