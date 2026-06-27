import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { scan } from './engine';
import { applyTextEdits, planFileFixes } from './fix';
import { parseSource } from './internal/ast';
import { wrapRouteHandlersWithSecureRoute } from './internal/wrap-route';
import type { AutoFix, TextEdit } from './types';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const CSRF = 'csrf/missing-origin-check';

/** Scan a single virtual `route.ts` with fixes resolved. */
function scanRoute(text: string) {
  return scan({ files: ['route.ts'], readFile: () => text, computeFixes: true });
}
function csrfFinding(text: string) {
  return scanRoute(text).findings.find((f) => f.ruleId === CSRF);
}

/** Assert a value is present (instead of a `!` non-null assertion), with a legible failure. */
function must<T>(value: T | undefined | null): T {
  if (value == null) {
    throw new Error('expected a defined value');
  }
  return value;
}

describe('applyTextEdits', () => {
  it('replaces a single interval', () => {
    expect(applyTextEdits('hello world', [{ start: 6, end: 11, newText: 'there' }])).toBe(
      'hello there',
    );
  });

  it('is order-independent over disjoint edits and matches the expected splice', () => {
    const segment = fc.oneof(
      fc.record({ kind: fc.constant<'keep'>('keep'), text: fc.string() }),
      fc.record({
        kind: fc.constant<'repl'>('repl'),
        text: fc.string({ minLength: 1 }), // non-empty ⇒ no zero-length, same-offset ambiguity
        to: fc.string(),
      }),
    );
    fc.assert(
      fc.property(fc.array(segment, { maxLength: 12 }), (segments) => {
        let text = '';
        let expected = '';
        const edits: TextEdit[] = [];
        for (const seg of segments) {
          const start = text.length;
          text += seg.text;
          if (seg.kind === 'repl') {
            edits.push({ start, end: text.length, newText: seg.to });
            expected += seg.to;
          } else {
            expected += seg.text;
          }
        }
        const reversed = [...edits].reverse();
        expect(applyTextEdits(text, edits)).toBe(expected);
        expect(applyTextEdits(text, reversed)).toBe(expected);
        return true;
      }),
    );
  });

  it('throws on overlapping edits rather than silently corrupting', () => {
    expect(() =>
      applyTextEdits('abcdef', [
        { start: 0, end: 3, newText: 'X' },
        { start: 2, end: 5, newText: 'Y' },
      ]),
    ).toThrow(/overlap/i);
  });
});

describe('planFileFixes', () => {
  const fixAt = (start: number, end: number, newText: string): AutoFix => ({
    kind: 'auto',
    title: 't',
    edits: [{ start, end, newText }],
  });

  it('applies non-overlapping fixes and defers conflicting ones to a re-run', () => {
    const plan = planFileFixes('f.ts', 'abcdefgh', [
      fixAt(0, 2, 'X'),
      fixAt(1, 3, 'Y'), // overlaps the first ⇒ deferred
      fixAt(4, 6, 'Z'),
    ]);
    expect(plan.applied).toHaveLength(2);
    expect(plan.deferred).toHaveLength(1);
    expect(plan.newText).toBe('Xcd' + 'Z' + 'gh');
  });

  it('returns the original text when there are no fixes', () => {
    const plan = planFileFixes('f.ts', 'unchanged', []);
    expect(plan.newText).toBe('unchanged');
    expect(plan.applied).toHaveLength(0);
  });
});

describe('wrapRouteHandlersWithSecureRoute — golden transform', () => {
  const input = readFileSync(join(FIXTURES, 'fix/wrap-simple/input.ts'), 'utf8');
  const expected = readFileSync(join(FIXTURES, 'fix/wrap-simple/expected.ts'), 'utf8');

  it('the rule emits a fix that produces exactly the expected output', () => {
    const finding = csrfFinding(input);
    expect(finding?.fix).toBeDefined();
    expect(applyTextEdits(input, must(finding?.fix).edits)).toBe(expected);
  });

  it('the fix actually resolves the finding (re-scan is clean for this rule)', () => {
    expect(csrfFinding(input)).toBeDefined();
    expect(csrfFinding(expected)).toBeUndefined();
  });

  it('is idempotent — the fixed output offers no further fix', () => {
    const finding = csrfFinding(expected);
    expect(finding).toBeUndefined();
  });
});

describe('wrapRouteHandlersWithSecureRoute — shape handling', () => {
  const parse = (text: string) => parseSource('route.ts', text);

  it('preserves a non-`req` parameter name via a renamed binding', () => {
    const src = `import { cookies } from 'next/headers';
export async function POST(request: Request) {
  await cookies();
  return Response.json(await request.json());
}
`;
    const fix = wrapRouteHandlersWithSecureRoute(parse(src), ['POST']);
    expect(fix).toBeDefined();
    const out = applyTextEdits(src, must(fix).edits);
    expect(out).toContain('secureRoute({ origin: true }, async ({ req: request }) =>');
    expect(out).toContain('await request.json()'); // body untouched
  });

  it('wraps multiple mutating handlers with a single shared import', () => {
    const src = `import { cookies } from 'next/headers';
export async function POST(req: Request) { await cookies(); return Response.json({}); }
export async function DELETE(req: Request) { await cookies(); return Response.json({}); }
`;
    const fix = wrapRouteHandlersWithSecureRoute(parse(src), ['POST', 'DELETE']);
    expect(fix).toBeDefined();
    const out = applyTextEdits(src, must(fix).edits);
    expect(out.match(/import \{ secureRoute \}/g)).toHaveLength(1);
    expect(out).toContain('export const POST = secureRoute(');
    expect(out).toContain('export const DELETE = secureRoute(');
  });

  it('handles a zero-parameter handler', () => {
    const src = `export async function POST() { return Response.json({}); }\n`;
    const fix = wrapRouteHandlersWithSecureRoute(parse(src), ['POST']);
    const out = applyTextEdits(src, must(fix).edits);
    expect(out).toContain('secureRoute({ origin: true }, async () =>');
  });

  it('skips the import when secureRoute is already imported', () => {
    const src = `import { secureRoute } from '@aegiskit/next';
export async function POST(req: Request) { return Response.json({}); }
`;
    const fix = wrapRouteHandlersWithSecureRoute(parse(src), ['POST']);
    const out = applyTextEdits(src, must(fix).edits);
    expect(out.match(/import \{ secureRoute \}/g)).toHaveLength(1);
  });

  it('fails closed (→ guided) on shapes it cannot transform safely', () => {
    const dynamicRoute = `export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) { return Response.json({}); }`;
    const arrowForm = `export const POST = async (req: Request) => Response.json({});`;
    const destructured = `export async function POST({ method }: Request) { return Response.json({ method }); }`;
    const defaultExport = `export default async function POST(req: Request) { return Response.json({}); }`;
    for (const src of [dynamicRoute, arrowForm, destructured, defaultExport]) {
      expect(wrapRouteHandlersWithSecureRoute(parse(src), ['POST'])).toBeUndefined();
    }
  });

  it('does not compute fixes unless asked (zero hot-path cost)', () => {
    const input = readFileSync(join(FIXTURES, 'fix/wrap-simple/input.ts'), 'utf8');
    const noFix = scan({ files: ['route.ts'], readFile: () => input }); // computeFixes off
    expect(noFix.findings.find((f) => f.ruleId === CSRF)?.fix).toBeUndefined();
  });
});
