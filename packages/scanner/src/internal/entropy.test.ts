import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { shannonEntropy } from './entropy';

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
