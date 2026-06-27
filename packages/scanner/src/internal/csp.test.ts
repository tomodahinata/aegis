import { describe, expect, it } from 'vitest';
import { type CspUnsafeUse, findCspUnsafeUses } from './csp';

describe('findCspUnsafeUses', () => {
  it('attributes a keyword to its script-src directive', () => {
    expect(findCspUnsafeUses("script-src 'self' 'unsafe-inline'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'script' },
    ]);
  });

  it('attributes a keyword to its style-src directive', () => {
    expect(findCspUnsafeUses("style-src 'self' 'unsafe-inline'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'style' },
    ]);
  });

  it('scores default-src fail-secure as script context', () => {
    expect(findCspUnsafeUses("default-src 'unsafe-inline'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'script' },
    ]);
  });

  it('treats a bare fragment with no directive name as unknown (caller fails secure)', () => {
    expect(findCspUnsafeUses("'unsafe-inline'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'unknown' },
    ]);
  });

  it('does NOT report a keyword under an inert directive (no false positive)', () => {
    // `img-src` ignores 'unsafe-inline'; the script-src segment carries no unsafe keyword.
    expect(
      findCspUnsafeUses("default-src 'self'; script-src 'self'; img-src 'unsafe-inline'"),
    ).toEqual([]);
  });

  it('splits a multi-directive policy and scores each segment independently', () => {
    expect(
      findCspUnsafeUses(
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
      ),
    ).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'script' },
      { keyword: 'unsafe-inline', context: 'style' },
    ]);
  });

  it('de-duplicates the same (keyword, context) pair within one string', () => {
    expect(
      findCspUnsafeUses("script-src 'unsafe-inline'; script-src-elem 'unsafe-inline'"),
    ).toEqual<CspUnsafeUse[]>([{ keyword: 'unsafe-inline', context: 'script' }]);
  });

  it('detects unsafe-eval distinctly from unsafe-inline', () => {
    expect(findCspUnsafeUses("script-src 'self' 'unsafe-eval'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-eval', context: 'script' },
    ]);
  });

  it('tolerates surrounding JS delimiters from getText() (leading quote)', () => {
    expect(findCspUnsafeUses(`"style-src 'self' 'unsafe-inline'"`)).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'style' },
    ]);
  });

  it('is case-insensitive for directive names', () => {
    expect(findCspUnsafeUses("SCRIPT-SRC 'unsafe-inline'")).toEqual<CspUnsafeUse[]>([
      { keyword: 'unsafe-inline', context: 'script' },
    ]);
  });

  it('returns nothing for a policy with no unsafe keywords', () => {
    expect(findCspUnsafeUses("default-src 'self'; script-src 'self' 'strict-dynamic'")).toEqual([]);
  });
});
