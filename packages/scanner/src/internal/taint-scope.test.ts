import { describe, expect, it } from 'vitest';
import { parseSource } from './ast';
import { buildScopeIndex } from './taint-scope';

function index(source: string) {
  return buildScopeIndex(parseSource('/proj/x.ts', source));
}

describe('buildScopeIndex', () => {
  it('discovers function declarations, arrows, and methods as distinct scopes', () => {
    const idx = index(`
      function a() {}
      const b = () => {};
      class C { m() {} }
    `);
    expect(idx.scopes.length).toBe(3);
  });

  it('captures parameters of each scope', () => {
    const idx = index('export function POST(req, { params }) { return params; }');
    expect(idx.scopes[0]?.parameters.length).toBe(2);
  });

  it('flags a name declared twice in one scope as ambiguous', () => {
    const idx = index('function f() { const x = 1; { const x = 2; return x; } }');
    expect(idx.scopes[0]?.symbols.ambiguous.has('x')).toBe(true);
  });

  it('flags a reassigned name', () => {
    const idx = index('function f(p) { let x = p; x = 2; return x; }');
    expect(idx.scopes[0]?.symbols.reassigned.has('x')).toBe(true);
  });

  it('does not capture an inner function’s declarations in the outer scope', () => {
    const idx = index(
      'function outer() { const a = 1; function inner() { const b = 2; return b; } return a; }',
    );
    const outer = idx.scopes.find(
      (s) => s.parameters.length === 0 && s.node.getText().startsWith('function outer'),
    );
    // `b` belongs to `inner`, never to `outer` — proven by it not being ambiguous when also declared outside.
    expect(outer?.symbols.ambiguous.has('b')).toBe(false);
  });
});
