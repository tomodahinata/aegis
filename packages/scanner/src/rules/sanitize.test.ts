import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

const RULE = 'sanitize/incomplete-escape';
const P = '/lib/escape.ts';
const has = (src: string): boolean =>
  scan({ files: [P], readFile: () => src }).findings.some((f) => f.ruleId === RULE);
const wrap = (expr: string): string => `export const f = (s: string) => ${expr};`;

describe('sanitize/incomplete-escape', () => {
  it('flags escaping a quote with a backslash when the backslash is never escaped', () => {
    expect(has(wrap(`s.replace(/'/g, "\\\\'")`))).toBe(true);
  });

  it('flags escaping a double-quote with a backslash and no backslash-escape', () => {
    expect(has(wrap(`s.replace(/"/g, '\\\\"')`))).toBe(true);
  });

  it('flags when the backslash is escaped AFTER the quote (wrong order)', () => {
    expect(has(wrap(`s.replace(/'/g, "\\\\'").replace(/\\\\/g, "\\\\\\\\")`))).toBe(true);
  });

  it('does NOT flag when the backslash is escaped FIRST (correct order)', () => {
    expect(has(wrap(`s.replace(/\\\\/g, "\\\\\\\\").replace(/'/g, "\\\\'")`))).toBe(false);
  });

  it('does NOT flag when a non-replace call (.trim) is interposed after the backslash-escape', () => {
    // Regression: the chain walk must STEP THROUGH `.trim()` to still see the `\`-first escape,
    // otherwise this correct sanitizer is falsely flagged.
    expect(has(wrap(`s.replace(/\\\\/g, '\\\\\\\\').trim().replace(/'/g, "\\\\'")`))).toBe(false);
  });

  it('does NOT flag when the backslash-escape receiver is parenthesized', () => {
    // Regression: a grouped receiver `(s.replace(/\\/…)).replace(/'/…)` must be unwrapped, else the
    // backslash link is dropped and the correct sanitizer falsely flagged.
    expect(has(wrap(`(s.replace(/\\\\/g, '\\\\\\\\')).replace(/'/g, "\\\\'")`))).toBe(false);
  });

  it('does NOT flag HTML-entity escaping (no backslash involved)', () => {
    expect(has(wrap(`s.replace(/&/g, "&amp;").replace(/</g, "&lt;")`))).toBe(false);
  });

  it('does NOT flag a non-escaping replace (formatting)', () => {
    expect(has(wrap(`s.replace(/\\s+/g, " ").trim()`))).toBe(false);
  });

  it('does NOT flag escaping only a non-quote control char', () => {
    expect(has(wrap(`s.replace(/\\n/g, "\\\\n")`))).toBe(false);
  });
});
