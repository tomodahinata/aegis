import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { bytesToBase64Url, constantTimeEqual, randomBase64Url } from './encoding';

describe('constantTimeEqual', () => {
  it('returns true for identical strings', () => {
    expect(constantTimeEqual('abc123', 'abc123')).toBe(true);
  });

  it('returns false for same-length but different strings', () => {
    expect(constantTimeEqual('abc123', 'abc124')).toBe(false);
  });

  it('returns false for different-length strings', () => {
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
  });

  it('returns true for two empty strings', () => {
    expect(constantTimeEqual('', '')).toBe(true);
  });

  it('property: equal strings always match', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(constantTimeEqual(s, s)).toBe(true);
      }),
    );
  });

  it('property: any single-character mutation never matches', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }),
        fc.nat(),
        fc.integer({ min: 1, max: 0xff }),
        (s, index, delta) => {
          const i = index % s.length;
          const mutatedCode = (s.charCodeAt(i) + delta) % 0x10000;
          // Skip the no-op case where the modular bump lands back on the original char.
          fc.pre(mutatedCode !== s.charCodeAt(i));
          const mutated = s.slice(0, i) + String.fromCharCode(mutatedCode) + s.slice(i + 1);
          expect(constantTimeEqual(s, mutated)).toBe(false);
        },
      ),
    );
  });
});

describe('bytesToBase64Url', () => {
  it('emits a URL-safe charset with no padding', () => {
    // 0xfb 0xff 0xfe encodes to "+/+" in standard base64 (-> "-_-" URL-safe), exercising
    // both substitutions; a length not divisible by 3 would otherwise produce padding.
    const encoded = bytesToBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]));
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });

  it('property: output is always URL-safe and unpadded for any bytes', () => {
    fc.assert(
      fc.property(fc.uint8Array(), (bytes) => {
        expect(bytesToBase64Url(bytes)).toMatch(/^[A-Za-z0-9_-]*$/);
      }),
    );
  });
});

describe('randomBase64Url', () => {
  it('produces a URL-safe, unpadded token for the requested byte length', () => {
    // 16 bytes -> ceil(16 * 4 / 3) = 22 base64 chars once padding is stripped.
    expect(randomBase64Url(16)).toMatch(/^[A-Za-z0-9_-]{22}$/);
    // 32 bytes -> 43 chars.
    expect(randomBase64Url(32)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('returns distinct values across calls (CSPRNG-backed)', () => {
    expect(randomBase64Url(16)).not.toBe(randomBase64Url(16));
  });
});
