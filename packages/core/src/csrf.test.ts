import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  generateCsrfToken,
  signCsrfToken,
  verifyDoubleSubmitToken,
  verifyOrigin,
  verifySignedCsrfToken,
} from './csrf';

describe('verifyOrigin', () => {
  it('accepts a same-origin request via the Origin host', () => {
    expect(verifyOrigin({ origin: 'https://app.example.com', host: 'app.example.com' })).toEqual({
      ok: true,
    });
  });

  it('rejects a cross-origin host', () => {
    expect(verifyOrigin({ origin: 'https://evil.com', host: 'app.example.com' })).toEqual({
      ok: false,
      reason: 'host-mismatch',
    });
  });

  it('is fail-closed on a missing Origin, with an opt-in escape hatch', () => {
    expect(verifyOrigin({ origin: null, host: 'app.example.com' })).toEqual({
      ok: false,
      reason: 'missing-origin',
    });
    expect(
      verifyOrigin({ origin: null, host: 'app.example.com' }, { allowNullOrigin: true }),
    ).toEqual({ ok: true });
  });

  it('rejects an unparseable Origin', () => {
    expect(verifyOrigin({ origin: 'http://%%%', host: 'x' }).ok).toBe(false);
  });

  it('honours a multi-host allowlist (preview deploys, multi-domain)', () => {
    const config = { allowedHosts: ['app.example.com', 'staging.example.com'] };
    expect(
      verifyOrigin({ origin: 'https://staging.example.com', host: 'app.example.com' }, config).ok,
    ).toBe(true);
    expect(verifyOrigin({ origin: 'https://other.com', host: 'app.example.com' }, config).ok).toBe(
      false,
    );
  });

  it('uses Sec-Fetch-Site as a fast-path', () => {
    expect(
      verifyOrigin({
        origin: 'https://whatever.com',
        secFetchSite: 'same-origin',
        host: 'app.example.com',
      }),
    ).toEqual({ ok: true });
    expect(
      verifyOrigin({ origin: null, secFetchSite: 'cross-site', host: 'app.example.com' }),
    ).toEqual({ ok: false, reason: 'cross-site' });
    expect(verifyOrigin({ origin: null, secFetchSite: 'none', host: 'app.example.com' })).toEqual({
      ok: true,
    });
  });

  it('falls through to the host check on Sec-Fetch-Site: same-site', () => {
    // `same-site` is not the same as `same-origin` (e.g. a sibling subdomain), so it must NOT
    // fast-path; the Origin host check decides.
    expect(
      verifyOrigin({
        origin: 'https://evil.example.com',
        secFetchSite: 'same-site',
        host: 'app.example.com',
      }),
    ).toEqual({ ok: false, reason: 'host-mismatch' });
    expect(
      verifyOrigin({
        origin: 'https://app.example.com',
        secFetchSite: 'same-site',
        host: 'app.example.com',
      }),
    ).toEqual({ ok: true });
  });

  it('reports bad-origin-url explicitly for an unparseable Origin', () => {
    expect(verifyOrigin({ origin: 'http://%%%', host: 'app.example.com' })).toEqual({
      ok: false,
      reason: 'bad-origin-url',
    });
  });

  it('property: any Origin whose host is not allowlisted is rejected', () => {
    const hostArb = fc.domain();
    fc.assert(
      fc.property(hostArb, hostArb, (allowed, other) => {
        // Hosts are case-insensitive and the URL parser lowercases them, so only treat
        // genuinely different hosts as the cross-origin case.
        fc.pre(allowed.toLowerCase() !== other.toLowerCase());
        const verdict = verifyOrigin(
          { origin: `https://${other}`, host: allowed },
          { allowedHosts: [allowed] },
        );
        expect(verdict.ok).toBe(false);
      }),
    );
  });
});

describe('double-submit token', () => {
  it('generates URL-safe tokens', () => {
    expect(generateCsrfToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('accepts matching tokens and rejects mismatches/absences', () => {
    const token = generateCsrfToken();
    expect(verifyDoubleSubmitToken(token, token)).toBe(true);
    expect(verifyDoubleSubmitToken(token, generateCsrfToken())).toBe(false);
    expect(verifyDoubleSubmitToken(null, token)).toBe(false);
    expect(verifyDoubleSubmitToken(token, undefined)).toBe(false);
  });

  it('property: distinct tokens never validate against each other', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), fc.string({ minLength: 1 }), (a, b) => {
        fc.pre(a !== b);
        expect(verifyDoubleSubmitToken(a, b)).toBe(false);
      }),
    );
  });
});

describe('signed token', () => {
  it('round-trips with the right secret', async () => {
    const signed = await signCsrfToken('token-123', 'super-secret');
    expect(await verifySignedCsrfToken(signed, 'super-secret')).toBe(true);
  });

  it('rejects a wrong secret or a tampered signature', async () => {
    const signed = await signCsrfToken('token-123', 'super-secret');
    expect(await verifySignedCsrfToken(signed, 'other-secret')).toBe(false);
    expect(await verifySignedCsrfToken(`${signed}x`, 'super-secret')).toBe(false);
    expect(await verifySignedCsrfToken('no-dot', 'super-secret')).toBe(false);
  });
});
