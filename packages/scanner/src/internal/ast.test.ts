import { describe, expect, it } from 'vitest';
import { codeOnlyText, importsServerOnly, parseSource } from './ast';

function detect(source: string): boolean {
  return importsServerOnly(parseSource('/m.ts', source));
}

describe('codeOnlyText', () => {
  const strip = (src: string): string => codeOnlyText(parseSource('/m.ts', src));

  it('blanks line and block comments but keeps code and string literals', () => {
    const out = strip(
      "import { x } from '@supabase/ssr'; // see @supabase/ssr docs\n/* @supabase/ssr */ const y = 1;",
    );
    // The real import specifier (a string) survives; both comment mentions are gone.
    expect(out).toContain("'@supabase/ssr'");
    expect(out).not.toContain('// see');
    expect(out).not.toContain('/* @supabase/ssr */');
    expect(out.match(/@supabase\/ssr/g)).toHaveLength(1); // only the import string remains
  });

  it('preserves line numbers (newlines kept) so finding locations are unchanged', () => {
    const out = strip('// comment line one\nconst a = 1;\n/* two\nthree */\nconst b = 2;');
    expect(out.split('\n')).toHaveLength(5);
  });

  it('keeps comment markers that live INSIDE string and template literals (lexer, not regex)', () => {
    const out = strip('const s = "// not a comment"; const t = `keep /* this */`;');
    expect(out).toContain('"// not a comment"');
    expect(out).toContain('`keep /* this */`');
  });

  it('output has the same length as the input (only ever replaces chars with spaces, never drops)', () => {
    const src = 'const a = 1; // tail\n/* block */ const b = 2;';
    expect(strip(src)).toHaveLength(src.length);
  });
});

describe('importsServerOnly', () => {
  it('detects the canonical side-effect guard', () => {
    expect(detect("import 'server-only';\nexport const x = 1;")).toBe(true);
  });

  it('detects non-side-effect import forms of the package', () => {
    expect(detect("import marker from 'server-only';")).toBe(true);
    expect(detect("import {} from 'server-only';")).toBe(true);
  });

  it('matches regardless of position among imports', () => {
    expect(detect("import { z } from 'zod';\nimport 'server-only';")).toBe(true);
  });

  it('does not match a local module that merely looks similar', () => {
    expect(detect("import './server-only';")).toBe(false);
    expect(detect("import 'server-only-utils';")).toBe(false);
  });

  it('does not match a mention in a comment or string', () => {
    expect(detect("// import 'server-only'\nconst note = 'server-only';")).toBe(false);
  });

  it('returns false when there is no import at all', () => {
    expect(detect('export const x = 1;')).toBe(false);
  });
});
