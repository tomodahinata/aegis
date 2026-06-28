import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

const RULE = 'redos/super-linear-regex';

/** Scan one virtual route module and return the rule ids it produces. */
function ruleIds(src: string): string[] {
  const path = '/app/api/x/route.ts';
  return scan({ files: [path], readFile: () => src }).findings.map((f) => f.ruleId);
}

// A NextRequest query param is an untrusted source the engine recognizes.
const taint = "const q = req.nextUrl.searchParams.get('q') ?? '';";
const route = (body: string): string =>
  `import { NextRequest } from 'next/server';\nexport async function GET(req: NextRequest) {\n  ${taint}\n  ${body}\n}\n`;

describe('redos/super-linear-regex — flags untrusted input into a catastrophic regex', () => {
  it('flags an inline catastrophic literal on the regex receiver (.test)', () => {
    expect(ruleIds(route('return Response.json({ ok: /^(a+)+$/.test(q) });'))).toContain(RULE);
  });

  it('flags catastrophic .exec on the subject argument', () => {
    expect(ruleIds(route('const m = /(\\w+)*$/.exec(q); return Response.json({ m });'))).toContain(
      RULE,
    );
  });

  it('flags a subject-method call (.match) with the catastrophic regex as the argument', () => {
    expect(ruleIds(route('return Response.json({ m: q.match(/(\\d+)+$/) });'))).toContain(RULE);
  });

  it('flags .replace / .split when the subject is tainted and the regex is catastrophic', () => {
    expect(ruleIds(route('return Response.json({ s: q.replace(/(a+)+/g, "") });'))).toContain(RULE);
    expect(ruleIds(route('return Response.json({ s: q.split(/(a+)+/) });'))).toContain(RULE);
  });

  it('resolves a const-bound catastrophic regex (the common idiom)', () => {
    const src = `import { NextRequest } from 'next/server';\nconst RE = /^(a+)+$/;\nexport async function GET(req: NextRequest) {\n  ${taint}\n  return Response.json({ ok: RE.test(q) });\n}\n`;
    expect(ruleIds(src)).toContain(RULE);
  });

  it('flags a catastrophic pattern built via new RegExp(stringLiteral)', () => {
    expect(ruleIds(route('return Response.json({ ok: new RegExp("(a+)+$").test(q) });'))).toContain(
      RULE,
    );
  });

  it('flags alternation overlap under a repeat (also exponential)', () => {
    expect(ruleIds(route('return Response.json({ ok: /^(\\w|\\d)*$/.test(q) });'))).toContain(RULE);
  });
});

const QUAD = 'redos/quadratic-regex';

describe('redos/quadratic-regex — flags untrusted input into a quadratic regex', () => {
  it('flags two overlapping adjacent unbounded quantifiers pinned by an end anchor', () => {
    expect(ruleIds(route('return Response.json({ ok: /^\\d+\\d+$/.test(q) });'))).toContain(QUAD);
  });

  it('resolves a const-bound quadratic regex (shared operand resolution, mirrors the exponential path)', () => {
    const src = `import { NextRequest } from 'next/server';\nconst RE = /^\\d+\\d+$/;\nexport async function GET(req: NextRequest) {\n  ${taint}\n  return Response.json({ ok: RE.test(q) });\n}\n`;
    expect(ruleIds(src)).toContain(QUAD);
  });

  it('does NOT report the exponential rule for a merely-quadratic pattern', () => {
    expect(ruleIds(route('return Response.json({ ok: /^\\d+\\d+$/.test(q) });'))).not.toContain(
      RULE,
    );
  });

  it('does NOT flag a quadratic pattern on a CONSTANT (untainted) subject', () => {
    expect(ruleIds(route('return Response.json({ ok: /^\\d+\\d+$/.test("123") });'))).not.toContain(
      QUAD,
    );
  });

  it('does NOT flag when the overlapping pair has no end anchor (not quadratic)', () => {
    expect(ruleIds(route('return Response.json({ m: q.match(/\\d+\\d+/) });'))).not.toContain(QUAD);
  });
});

describe('redos/super-linear-regex — zero false positives', () => {
  it('does NOT flag a LINEAR regex on tainted input', () => {
    expect(ruleIds(route('return Response.json({ ok: /^\\w+$/.test(q) });'))).not.toContain(RULE);
  });

  it('does NOT flag a catastrophic regex on a CONSTANT (untainted) subject', () => {
    expect(
      ruleIds(route('return Response.json({ ok: /^(a+)+$/.test("constant") });')),
    ).not.toContain(RULE);
  });

  it('does NOT flag when input is numeric-cast before matching (sanitized)', () => {
    expect(
      ruleIds(route('return Response.json({ ok: /^(a+)+$/.test(String(Number(q))) });')),
    ).not.toContain(RULE);
  });

  it('does NOT resolve a reassignable `let` regex binding — fail-secure', () => {
    // A `let` can be reassigned to a safe pattern, so its declaration value is not authoritative.
    const src = `import { NextRequest } from 'next/server';\nlet RE = /^(a+)+$/;\nRE = /^\\w+$/;\nexport async function GET(req: NextRequest) {\n  ${taint}\n  return Response.json({ ok: RE.test(q) });\n}\n`;
    expect(ruleIds(src)).not.toContain(RULE);
  });
});
