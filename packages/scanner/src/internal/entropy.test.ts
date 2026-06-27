import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { looksLikeCharsetAlphabet, shannonEntropy } from './entropy';

describe('shannonEntropy', () => {
  it('is 0 for empty or single-symbol strings', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaaaa')).toBe(0);
  });

  it('rises with character variety', () => {
    expect(shannonEntropy('abcdef')).toBeGreaterThan(shannonEntropy('aaaaab'));
  });

  it('property: 0 ≤ H ≤ log2(unique chars)', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), (s) => {
        const h = shannonEntropy(s);
        expect(h).toBeGreaterThanOrEqual(0);
        expect(h).toBeLessThanOrEqual(Math.log2(new Set(s).size) + 1e-9);
      }),
    );
  });
});

describe('looksLikeCharsetAlphabet', () => {
  const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  it('recognizes base62 / base64url encoder alphabets', () => {
    expect(looksLikeCharsetAlphabet(BASE62)).toBe(true);
    expect(looksLikeCharsetAlphabet(BASE64URL)).toBe(true);
  });

  it('does NOT classify a random high-entropy secret as an alphabet', () => {
    // A 40-char mixed token (the shape of a real key) — adjacent pairs are consecutive only by chance.
    expect(looksLikeCharsetAlphabet('Xk92Lm4Qz8Rv1Tn6Wp3Yb7Hd5Fg0JsAa3Cc7Ee9')).toBe(false);
    // A prefixed credential shape too. The body is deliberately a fake, sub-pattern-length placeholder so
    // this repo never commits a literal that matches a real provider's secret format (push protection).
    expect(looksLikeCharsetAlphabet('sk_live_FAKEnotARealStripeKey0')).toBe(false);
  });

  it('does not over-trigger on short strings', () => {
    expect(looksLikeCharsetAlphabet('abc')).toBe(false);
  });

  it('applies the 16-char minimum at the exact boundary', () => {
    expect(looksLikeCharsetAlphabet('abcdefghijklmno')).toBe(false); // 15 chars → below the cutoff
    expect(looksLikeCharsetAlphabet('abcdefghijklmnop')).toBe(true); // 16 chars → just over
  });

  it('recognizes the 16-char hex table (consecutive across all but the 9→a gap)', () => {
    // 14/15 adjacent pairs are consecutive (only `9`→`a` breaks the run), well above the 0.5 threshold.
    expect(looksLikeCharsetAlphabet('0123456789abcdef')).toBe(true);
  });

  it('property: any string ending in a long ascending run is treated as an alphabet', () => {
    const az = 'abcdefghijklmnopqrstuvwxyz';
    fc.assert(
      fc.property(fc.string({ maxLength: 8 }), (prefix) => {
        // The 26-char ascending run dominates the ≤8-char random prefix, so the consecutive ratio
        // stays above the 0.5 threshold — an encoder table is recognized regardless of any preamble.
        expect(looksLikeCharsetAlphabet(prefix + az + az)).toBe(true);
      }),
    );
  });
});
