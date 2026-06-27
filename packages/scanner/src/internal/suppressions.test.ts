import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { isSuppressed, parseSuppressions } from './suppressions';

describe('parseSuppressions', () => {
  it('targets the next line for a standalone directive', () => {
    const s = parseSuppressions(
      '// aegis-disable-next-line env/public-secret -- demo key\nconst x = 1;',
    );
    expect(isSuppressed(s, 'env/public-secret', 2)).toBe(true);
    expect(isSuppressed(s, 'env/public-secret', 1)).toBe(false);
  });

  it('targets its own line for a trailing directive', () => {
    const s = parseSuppressions(
      'const x = secret; // aegis-disable-next-line secrets/committed-literal -- ok',
    );
    expect(isSuppressed(s, 'secrets/committed-literal', 1)).toBe(true);
  });

  it('suppresses a whole file with disable-file', () => {
    const s = parseSuppressions(
      '// aegis-disable-file csrf/missing-origin-check -- legacy\nexport function POST() {}',
    );
    expect(isSuppressed(s, 'csrf/missing-origin-check', 99)).toBe(true);
  });

  it('supports the * wildcard', () => {
    const s = parseSuppressions('// aegis-disable-next-line * -- everything\nconst x = 1;');
    expect(isSuppressed(s, 'any/rule', 2)).toBe(true);
  });

  it('does not suppress a different rule', () => {
    const s = parseSuppressions('// aegis-disable-next-line env/public-secret -- x\nconst y = 1;');
    expect(isSuppressed(s, 'csrf/missing-origin-check', 2)).toBe(false);
  });

  it('records a missing reason as undefined', () => {
    const s = parseSuppressions('// aegis-disable-next-line env/public-secret\nconst x = 1;');
    expect(s.all[0]?.reason).toBeUndefined();
  });

  it('captures the reason text when present', () => {
    const s = parseSuppressions(
      '// aegis-disable-file csrf/missing-origin-check -- bearer auth only',
    );
    expect(s.all[0]?.reason).toBe('bearer auth only');
  });

  it('ignores non-directive comments and // inside strings', () => {
    const s = parseSuppressions(
      "const url = 'https://example.com'; // a normal comment\nconst x = 1;",
    );
    expect(s.all).toHaveLength(0);
  });

  it('property: any reason string round-trips (trimmed)', () => {
    const reasonArb = fc
      .string({ minLength: 1 })
      .map((s) => s.replace(/[^a-zA-Z0-9 ]/g, 'x'))
      .filter((r) => r.trim().length > 0);
    fc.assert(
      fc.property(reasonArb, (reason) => {
        const s = parseSuppressions(`// aegis-disable-next-line some/rule -- ${reason}\nx;`);
        expect(s.all[0]?.reason).toBe(reason.trim());
      }),
    );
  });
});
