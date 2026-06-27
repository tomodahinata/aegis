import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { classifyFile } from '../classify';
import type { FileInfo } from '../rule';
import type { Confidence } from '../types';
import { collectImports, parseSource, ts } from './ast';
import { findTaintFlows, traceOf } from './dataflow';
import type { SinkCategory, TaintFlow, TaintSink, TaintSpec } from './taint-descriptors';

function fileInfo(source: string, path = '/proj/app/api/route.ts'): FileInfo {
  const sourceFile = parseSource(path, source);
  return {
    path,
    text: source,
    sourceFile,
    classification: classifyFile(path, sourceFile),
    imports: collectImports(sourceFile),
    reachableFromClient: false,
  };
}

/** A test sink: `sink(<args>)` (or a renamed callee), of a chosen category. */
function namedSink(category: SinkCategory, callee = 'sink'): TaintSink {
  return {
    id: `test.${category}`,
    category,
    label: `reaches ${callee}()`,
    match: (node) =>
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === callee
        ? node.arguments
        : [],
  };
}

const SQL: TaintSpec = { sinks: [namedSink('sql')] };
const URL_SPEC: TaintSpec = { sinks: [namedSink('url')] };

/** Flows for a snippet, wrapped in a route-handler scope (the engine analyzes function scopes). */
function flows(body: string, spec: TaintSpec = SQL): readonly TaintFlow[] {
  return findTaintFlows(
    fileInfo(`export async function POST(req, { params }) {\n${body}\n}\n`),
    spec,
  );
}

/** Unsanitized flows only (what a rule actually reports). */
function reported(body: string, spec: TaintSpec = SQL): readonly TaintFlow[] {
  return flows(body, spec).filter((f) => !f.sanitized);
}

const Q = "req.nextUrl.searchParams.get('q')";

describe('dataflow — propagation rules', () => {
  it('direct source → sink (no intermediate variable)', () => {
    expect(reported(`sink(${Q});`)).toHaveLength(1);
  });

  it('does not flag a constant reaching a sink', () => {
    expect(reported(`sink('constant');`)).toHaveLength(0);
    expect(reported('const x = "lit"; sink(x);')).toHaveLength(0);
  });

  it('tracks through a variable declaration', () => {
    expect(reported(`const x = ${Q}; sink(x);`)).toHaveLength(1);
  });

  it('tracks through a template literal', () => {
    expect(reported(`sink(\`prefix \${${Q}}\`);`)).toHaveLength(1);
    expect(reported(`sink(\`prefix \${42}\`);`)).toHaveLength(0);
  });

  it('tracks through string concatenation', () => {
    expect(reported(`sink('SELECT ' + ${Q});`)).toHaveLength(1);
  });

  it('tracks through a property access on a tainted object', () => {
    expect(reported(`const u = await req.json(); sink(u.name);`)).toHaveLength(1);
  });

  it('tracks through object destructuring', () => {
    expect(reported(`const { tenant } = await req.json(); sink(tenant);`)).toHaveLength(1);
  });

  it('tracks a route parameter seeded from the scope', () => {
    expect(reported('sink(params.id);')).toHaveLength(1);
  });

  it('tracks through a benign string transform (pass-through)', () => {
    expect(reported(`sink(String(${Q}));`)).toHaveLength(1);
    expect(reported(`sink(${Q}.trim());`)).toHaveLength(1);
  });

  it('seeds cookies(), headers() and request bodies as sources', () => {
    expect(reported(`sink(cookies().get('s'));`)).toHaveLength(1);
    expect(reported(`sink(headers().get('x-id'));`)).toHaveLength(1);
    expect(reported(`const b = await req.text(); sink(b);`)).toHaveLength(1);
  });

  it('does not leak taint across a nested function scope (intraprocedural)', () => {
    expect(reported(`const x = ${Q}; const run = () => sink(x); run();`)).toHaveLength(0);
  });
});

describe('dataflow — sanitizers (sink-category specific)', () => {
  it('a numeric cast neutralizes every category', () => {
    expect(reported(`const n = Number(${Q}); sink(n);`)).toHaveLength(0);
    expect(reported(`sink(parseInt(${Q}, 10));`)).toHaveLength(0);
  });

  it('a constraining schema parse neutralizes SQL; a plain string parse does not', () => {
    expect(reported(`const n = z.coerce.number().parse(${Q}); sink(n);`)).toHaveLength(0);
    // z.string() validates shape but a string can still carry SQL metacharacters → still reported.
    expect(reported(`const s = z.string().parse(${Q}); sink(s);`)).toHaveLength(1);
  });

  it('encodeURIComponent neutralizes a URL sink but NOT a SQL sink', () => {
    expect(reported(`sink(encodeURIComponent(${Q}));`, URL_SPEC)).toHaveLength(0);
    expect(reported(`sink(encodeURIComponent(${Q}));`, SQL)).toHaveLength(1);
  });

  it('decoding undoes URL-encoding (decode is not a sanitizer)', () => {
    expect(reported(`sink(decodeURIComponent(encodeURIComponent(${Q})));`, URL_SPEC)).toHaveLength(
      1,
    );
  });

  it('a numeric value interpolated into SQL stays safe', () => {
    expect(reported(`sink(\`WHERE id = \${Number(${Q})}\`);`)).toHaveLength(0);
  });

  it('returns sanitized flows too (so a rule can record a pass)', () => {
    const all = flows(`const n = Number(${Q}); sink(n);`);
    expect(all).toHaveLength(1);
    expect(all[0]?.sanitized).toBe(true);
  });
});

describe('dataflow — confidence', () => {
  it('a clean single-assignment flow is high confidence', () => {
    expect(reported(`const x = ${Q}; sink(x);`)[0]?.confidence).toBe<Confidence>('high');
  });

  it('a reassigned carrier caps confidence to medium', () => {
    const f = reported(`let id = ${Q}; id = ${Q}; sink(id);`);
    expect(f[0]?.confidence).toBe<Confidence>('medium');
  });
});

describe('dataflow — trace', () => {
  it('produces an ordered source → … → sink trace', () => {
    const [flow] = reported(`const x = ${Q}; sink(x);`);
    expect(flow).toBeDefined();
    if (!flow) {
      return;
    }
    const trace = traceOf(
      fileInfo(`export async function POST(req, { params }) {\nconst x = ${Q}; sink(x);\n}\n`),
      flow,
    );
    expect(trace[0]?.kind).toBe('source');
    expect(trace.at(-1)?.kind).toBe('sink');
    expect(trace.every((s) => s.range.startLine >= 1)).toBe(true);
  });
});

describe('dataflow — bounds', () => {
  it('skips a pathologically large scope without throwing', () => {
    const filler = Array.from({ length: 1500 }, (_, i) => `const a${i} = ${i};`).join('\n');
    expect(() => reported(`${filler}\nsink(${Q});`)).not.toThrow();
  });
});

describe('dataflow — invariants (fast-check)', () => {
  const PADDING = fc
    .nat({ max: 12 })
    .map((n) => Array.from({ length: n }, (_, i) => `const z${i} = ${i};`).join('\n'));

  it('a numeric-cast flow is never reported, however much unrelated code surrounds it', () => {
    fc.assert(
      fc.property(PADDING, PADDING, (before, after) => {
        expect(reported(`${before}\nconst n = Number(${Q});\n${after}\nsink(n);`)).toHaveLength(0);
      }),
      { numRuns: 25 },
    );
  });

  it('wrapping the sink argument in a sanitizer flips report → no-report', () => {
    fc.assert(
      fc.property(fc.constantFrom('Number', 'parseInt', 'parseFloat'), (cast) => {
        expect(reported(`sink(${Q});`)).toHaveLength(1);
        expect(reported(`sink(${cast}(${Q}));`)).toHaveLength(0);
      }),
      { numRuns: 10 },
    );
  });

  it('alpha-renaming the carrier variable does not change the verdict', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z][a-zA-Z0-9]{0,8}$/).filter((n) => n !== 'req' && n !== 'params'),
        (name) => {
          expect(reported(`const ${name} = ${Q}; sink(${name});`)).toHaveLength(1);
        },
      ),
      { numRuns: 25 },
    );
  });
});
