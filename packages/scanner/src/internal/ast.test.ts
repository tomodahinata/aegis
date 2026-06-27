import { describe, expect, it } from 'vitest';
import { importsServerOnly, parseSource } from './ast';

function detect(source: string): boolean {
  return importsServerOnly(parseSource('/m.ts', source));
}

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
