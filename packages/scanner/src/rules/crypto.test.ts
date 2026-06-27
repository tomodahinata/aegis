import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

function has(path: string, source: string, ruleId: string): boolean {
  return scan({ files: [path], readFile: () => source }).findings.some((f) => f.ruleId === ruleId);
}

const P = '/lib/x.ts';

describe('crypto/insecure-randomness', () => {
  it('flags Math.random() bound to a security-named value', () => {
    expect(
      has(
        P,
        'export const f = () => { const sessionToken = Math.random(); return sessionToken; };',
        'crypto/insecure-randomness',
      ),
    ).toBe(true);
  });

  it('does NOT flag Math.random() used for non-security purposes', () => {
    expect(
      has(
        P,
        'export const f = () => { const jitter = Math.random() * 100; return jitter; };',
        'crypto/insecure-randomness',
      ),
    ).toBe(false);
  });
});

describe('crypto/weak-hash', () => {
  it('flags MD5/SHA-1 in either imported or namespaced form', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const h = (s: string) => createHash('md5').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(true);
    expect(
      has(
        P,
        "import crypto from 'node:crypto'; export const h = (s: string) => crypto.createHash('sha1').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(true);
  });

  it('does NOT flag SHA-256', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const h = (s: string) => createHash('sha256').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(false);
  });

  it('does NOT flag SHA-1 in an RFC-4122 v5 UUID builder (spec mandates SHA-1) — the SpoLove case', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export function deterministicUuid(name: string) { const bytes = createHash('sha1').update(name).digest().subarray(0, 16); const b = Buffer.from(bytes); b[6] = (b[6] & 0x0f) | 0x50; b[8] = (b[8] & 0x3f) | 0x80; return b.toString('hex'); }",
        'crypto/weak-hash',
      ),
    ).toBe(false);
  });

  it('does NOT flag a weak hash used for a non-security cache key / ETag', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const cacheKey = (s: string) => createHash('md5').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(false);
  });

  it('does NOT flag a weak hash used for an asset/build fingerprint (cache busting)', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const assetFingerprint = (s: string) => createHash('md5').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(false);
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const buildFingerprint = (s: string) => createHash('sha1').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(false);
  });

  it('STILL flags a weak hash caching auth material — bare `cache` must not suppress (recall preserved)', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const cacheSessionToken = (pw: string) => createHash('md5').update(pw).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(true);
  });

  it('STILL flags a weak hash for a deviceFingerprint used for auth/fraud (recall preserved)', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const deviceFingerprint = (s: string) => createHash('sha1').update(s).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(true);
  });

  it('STILL flags a weak hash in a security context (recall preserved)', () => {
    expect(
      has(
        P,
        "import { createHash } from 'node:crypto'; export const hashPassword = (pw: string) => createHash('sha1').update(pw).digest('hex');",
        'crypto/weak-hash',
      ),
    ).toBe(true);
  });
});

describe('crypto/non-constant-time-compare', () => {
  it('flags === on a secret/signature value', () => {
    expect(
      has(
        P,
        'export const v = (apiKey: string, expected: string) => apiKey === expected;',
        'crypto/non-constant-time-compare',
      ),
    ).toBe(true);
  });

  it('does NOT flag a presence check against null/undefined', () => {
    expect(
      has(
        P,
        'export const v = (token?: string) => token === undefined;',
        'crypto/non-constant-time-compare',
      ),
    ).toBe(false);
  });
});

describe('crypto — severity and confidence are pinned (not just the rule id)', () => {
  const find = (source: string, ruleId: string) =>
    scan({ files: [P], readFile: () => source }).findings.find((f) => f.ruleId === ruleId);

  it('weak-hash reports HIGH severity at medium confidence (may be a non-security checksum)', () => {
    const f = find(
      "import { createHash } from 'node:crypto'; export const h = (s: string) => createHash('md5').update(s).digest('hex');",
      'crypto/weak-hash',
    );
    expect(f?.severity).toBe('HIGH');
    expect(f?.confidence).toBe('medium');
  });

  it('insecure-randomness reports HIGH severity at high confidence (a named security token)', () => {
    const f = find(
      'export const f = () => { const sessionToken = Math.random(); return sessionToken; };',
      'crypto/insecure-randomness',
    );
    expect(f?.severity).toBe('HIGH');
    expect(f?.confidence).toBe('high');
  });
});
